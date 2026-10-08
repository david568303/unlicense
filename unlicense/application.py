import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import fire  # type: ignore

from . import frida_exec, winlicense2, winlicense3
from .dump_utils import dump_dotnet_assembly, dump_pe, get_section_ranges, interpreter_can_dump_pe, probe_text_sections
from .logger import setup_logger
from .process_control import MemoryRange, ProcessController
from .version_detection import detect_winlicense_version

# Supported Themida/WinLicense major versions
SUPPORTED_VERSIONS = [2, 3]
LOG = logging.getLogger("unlicense")


def main() -> None:
    fire.Fire(run_unlicense)


def _normalize_cli_bool(value: Any, option_name: str) -> bool:
    """Normalize booleans because Fire 0.4 treats lowercase values as text."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off"}:
            return False
    raise ValueError(
        f"--{option_name} expects true/false, yes/no, on/off, or 1/0; "
        f"received {value!r}")


def run_unlicense(
    pe_to_dump: str,
    verbose: bool = False,
    pause_on_oep: bool = False,
    no_imports: bool = False,
    force_oep: Optional[int] = None,
    target_version: Optional[int] = None,
    timeout: int = 10,
    oep_startup_retries: int = 1,
    diagnostic_output: Optional[str] = None,
    native_trace_timeout: int = 0,
    active_wrapper_probe: bool = False,
    active_probe_timeout: int = 5000,
    active_probe_startup_retries: int = 2,
) -> None:
    """
    Unpack executables protected with Themida/WinLicense 2.x and 3.x
    """
    # Python Fire 0.4 only recognizes title-cased boolean literals.  Values
    # such as `--active_wrapper_probe=false` otherwise arrive as the non-empty
    # string "false" and are truthy, which silently enables the option.  Parse
    # every CLI boolean explicitly before it can affect control flow.
    verbose = _normalize_cli_bool(verbose, "verbose")
    pause_on_oep = _normalize_cli_bool(pause_on_oep, "pause_on_oep")
    no_imports = _normalize_cli_bool(no_imports, "no_imports")
    active_wrapper_probe = _normalize_cli_bool(active_wrapper_probe,
                                               "active_wrapper_probe")
    setup_logger(LOG, verbose)
    LOG.info(
        "Trace configuration: native=%d ms, sacrificial=%s, "
        "sacrificial_window=%d ms", native_trace_timeout,
        "enabled" if active_wrapper_probe else "disabled",
        active_probe_timeout)

    # Make sure child processes won't try to run as administrator
    _force_run_as_invoker()

    pe_path = Path(pe_to_dump)
    if not pe_path.is_file():
        LOG.error("'%s' isn't a file or doesn't exist", pe_path)
        sys.exit(1)

    # Detect Themida/Winlicense version if needed
    if target_version is None:
        target_version = detect_winlicense_version(pe_to_dump)
        if target_version is None:
            LOG.error("Failed to automatically detect packer version")
            sys.exit(2)
    elif target_version not in SUPPORTED_VERSIONS:
        LOG.error("Target version '%d' is not supported", target_version)
        sys.exit(2)
    LOG.info("Detected packer version: %d.x", target_version)

    # Check PE architecture and bitness
    if not interpreter_can_dump_pe(pe_to_dump):
        LOG.error("Target PE cannot be dumped with this interpreter. "
                  "This is most likely a 32 vs 64 bit mismatch.")
        sys.exit(3)

    section_ranges = get_section_ranges(pe_to_dump)
    text_section_ranges = probe_text_sections(pe_to_dump)
    if text_section_ranges is None:
        LOG.error("Failed to automatically detect .text section")
        sys.exit(4)

    process_controller, dumped_image_base, dumped_oep, is_dotnet = \
        _create_primary_process(pe_path, text_section_ranges, float(timeout),
                                oep_startup_retries)
    if process_controller is None:
        LOG.error("Original entry point wasn't reached after all attempts")
        sys.exit(4)
    try:
        LOG.info("OEP reached: OEP=%s BASE=%s DOTNET=%r", hex(dumped_oep),
                 hex(dumped_image_base), is_dotnet)
        if pause_on_oep:
            input("Thread blocked, press ENTER to proceed with the dumping.")

        if force_oep is not None:
            dumped_oep = dumped_image_base + force_oep
            LOG.info("Using given OEP RVA value instead (%s)", hex(force_oep))

        # Pick the range that contains the OEP
        text_section_range = text_section_ranges[0]
        for section_range in text_section_ranges:
            if section_range.contains(dumped_oep - dumped_image_base):
                text_section_range = section_range

        # .NET assembly dumping works the same way regardless of the version
        if is_dotnet:
            LOG.info("Dumping .NET assembly ...")
            if not dump_dotnet_assembly(process_controller, dumped_image_base):
                LOG.error(".NET assembly dump failed")
        # Do not bother recovering imports and start dumping if requested
        elif no_imports:
            dump_pe(process_controller, pe_to_dump, dumped_image_base,
                    dumped_oep, 0, 0, True)
        # Fix imports and dump the executable
        elif target_version == 2:
            assert text_section_ranges is not None
            probe_ranges = text_section_ranges

            def create_probe_process(
            ) -> Tuple[Optional[ProcessController], Optional[int]]:
                return _create_probe_process(
                    pe_path, probe_ranges, max(10.0, float(timeout)),
                    max(15000, min(60000, active_probe_timeout * 2)),
                    active_probe_startup_retries)

            winlicense2.fix_and_dump_pe(
                process_controller, pe_to_dump, dumped_image_base, dumped_oep,
                text_section_range, diagnostic_output, native_trace_timeout,
                active_wrapper_probe, active_probe_timeout,
                create_probe_process if active_wrapper_probe else None,
                image_section_ranges=section_ranges)
        elif target_version == 3:
            if diagnostic_output is not None:
                LOG.warning(
                    "Diagnostic reports currently cover Themida 2.x only")
            winlicense3.fix_and_dump_pe(process_controller, pe_to_dump,
                                        dumped_image_base, dumped_oep,
                                        section_ranges, text_section_range)
    finally:
        # Try to kill the process on exit
        process_controller.terminate_process()


def _force_run_as_invoker() -> None:
    os.environ["__COMPAT_LAYER"] = "RUNASINVOKER"


def _wait_for_event_with_progress(event: threading.Event,
                                  timeout_seconds: float,
                                  description: str,
                                  progress_interval: float = 5.0) -> bool:
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    started = time.monotonic()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return event.is_set()
        if event.wait(min(max(0.1, progress_interval), remaining)):
            return True
        elapsed = time.monotonic() - started
        LOG.info("Waiting for %s: %.0f/%.0f seconds", description, elapsed,
                 timeout_seconds)


def _create_primary_process(
    pe_path: Path,
    text_section_ranges: List[MemoryRange],
    startup_wait_seconds: float,
    startup_retries: int,
) -> Tuple[Optional[ProcessController], int, int, bool]:
    attempts = max(1, min(5, startup_retries + 1))
    for attempt in range(1, attempts + 1):
        oep_reached = threading.Event()
        controller: Optional[ProcessController] = None
        state: Dict[str, Any] = {
            "image_base": 0,
            "oep": 0,
            "dotnet": False,
        }

        def notify_oep(image_base: int,
                       oep: int,
                       dotnet: bool,
                       event: threading.Event = oep_reached,
                       attempt_state: Dict[str, Any] = state) -> None:
            attempt_state["image_base"] = image_base
            attempt_state["oep"] = oep
            attempt_state["dotnet"] = dotnet
            event.set()

        LOG.info("Starting primary target attempt %d/%d", attempt, attempts)
        try:
            controller = frida_exec.spawn_and_instrument(
                pe_path, text_section_ranges, notify_oep)
            if _wait_for_event_with_progress(
                    oep_reached, max(0.1, startup_wait_seconds),
                    f"primary target attempt {attempt}/{attempts}"):
                return (controller, int(state["image_base"]),
                        int(state["oep"]), bool(state["dotnet"]))
            LOG.warning(
                "Primary target attempt %d/%d did not reach its OEP before "
                "%.0f seconds", attempt, attempts, startup_wait_seconds)
        except Exception as error:
            LOG.warning("Primary target attempt %d/%d failed: %s", attempt,
                        attempts, error)
        if controller is not None:
            controller.terminate_process()
    return None, 0, 0, False


def _create_probe_process(
    pe_path: Path,
    text_section_ranges: List[MemoryRange],
    startup_wait_seconds: float,
    setup_timeout_ms: int,
    startup_retries: int,
    known_oep_rva: Optional[int] = None,
    known_oep_bytes: Optional[bytes] = None,
) -> Tuple[Optional[ProcessController], Optional[int]]:
    attempts = max(1, min(5, startup_retries + 1))
    for attempt in range(1, attempts + 1):
        oep_reached = threading.Event()
        controller: Optional[ProcessController] = None
        state: Dict[str, Any] = {
            "image_base": None,
            "dotnet": False,
        }

        def notify_oep(image_base: int,
                       _oep: int,
                       dotnet: bool,
                       event: threading.Event = oep_reached,
                       attempt_state: Dict[str, Any] = state) -> None:
            attempt_state["image_base"] = image_base
            attempt_state["dotnet"] = dotnet
            event.set()

        LOG.warning(
            "Starting sacrificial target attempt %d/%d for active wrapper "
            "probing; the dump target remains blocked", attempt, attempts)
        try:
            controller = frida_exec.spawn_and_instrument(
                pe_path,
                text_section_ranges,
                notify_oep,
                setup_timeout_ms,
                # Passive tracing must install Stalker while the clone is
                # blocked at its real OEP. Adopting an already-open process is
                # too late because its startup wrappers have already run.
                post_protect_oep_rearm=False)
            reached, verified_base = _wait_for_probe_ready(
                controller, pe_path.name, oep_reached, startup_wait_seconds,
                attempt, attempts, known_oep_rva, known_oep_bytes)
            if verified_base is not None:
                assert known_oep_rva is not None
                controller.adopt_ready_target(verified_base + known_oep_rva)
                LOG.warning(
                    "Sacrificial target missed its OEP notification but its "
                    "known OEP bytes match at BASE=%s; adopting the already "
                    "unpacked live process", hex(verified_base))
                return controller, verified_base
            if not reached:
                LOG.warning(
                    "Sacrificial target attempt %d/%d did not reach its OEP "
                    "before %.0f seconds", attempt, attempts,
                    startup_wait_seconds)
            elif state["dotnet"]:
                LOG.warning("Sacrificial target was detected as .NET; active "
                            "probing is disabled")
                controller.terminate_process()
                return None, None
            else:
                image_base = state["image_base"]
                LOG.info("Sacrificial target reached OEP: PID=%d BASE=%s",
                         controller.pid, hex(image_base or 0))
                return controller, image_base
        except Exception as error:
            LOG.warning("Sacrificial target attempt %d/%d failed: %s", attempt,
                        attempts, error)
        if controller is not None:
            controller.terminate_process()
    return None, None


def _wait_for_probe_ready(
    controller: ProcessController,
    module_name: str,
    oep_reached: threading.Event,
    timeout_seconds: float,
    attempt: int,
    attempts: int,
    known_oep_rva: Optional[int],
    known_oep_bytes: Optional[bytes],
    progress_interval: float = 5.0,
) -> Tuple[bool, Optional[int]]:
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    started = time.monotonic()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return oep_reached.is_set(), None
        if oep_reached.wait(min(max(0.1, progress_interval), remaining)):
            return True, None

        if known_oep_rva is not None and known_oep_bytes:
            try:
                module = controller.find_module_by_name(module_name)
                if module is not None:
                    raw_base = module.get("base")
                    if isinstance(raw_base, str):
                        image_base = int(raw_base, 16)
                    elif isinstance(raw_base, int):
                        image_base = raw_base
                    else:
                        raise ValueError("sacrificial module base unavailable")
                    candidate = controller.read_process_memory(
                        image_base + known_oep_rva, len(known_oep_bytes))
                    if candidate == known_oep_bytes:
                        return False, image_base
            except Exception as error:
                LOG.debug("Sacrificial readiness check failed: %s", error)

        elapsed = time.monotonic() - started
        LOG.info(
            "Waiting for sacrificial target attempt %d/%d: %.0f/%.0f "
            "seconds", attempt, attempts, elapsed, timeout_seconds)
