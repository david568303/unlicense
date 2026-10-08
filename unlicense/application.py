import logging
import os
import sys
import threading
from pathlib import Path
from typing import List, Optional

import fire  # type: ignore

from . import frida_exec, winlicense2, winlicense3
from .dump_utils import dump_dotnet_assembly, dump_pe, get_section_ranges, interpreter_can_dump_pe, probe_text_sections
from .logger import setup_logger
from .version_detection import detect_winlicense_version

# Supported Themida/WinLicense major versions
SUPPORTED_VERSIONS = [2, 3]
LOG = logging.getLogger("unlicense")


def main() -> None:
    fire.Fire(run_unlicense)


def run_unlicense(
    pe_to_dump: str,
    verbose: bool = False,
    pause_on_oep: bool = False,
    no_imports: bool = False,
    force_oep: Optional[int] = None,
    target_version: Optional[int] = None,
    timeout: int = 30,
    aggressive_imports: bool = False,
    runtime_imports: bool = False,
) -> None:
    """
    Unpack executables protected with Themida/WinLicense 2.x and 3.x

    `aggressive_imports` (Themida/WinLicense 2.x only) makes the emulation-based
    import resolver map missing memory as zero instead of giving up, which can
    recover imports whose wrappers use anti-emulation tricks (e.g. calling real
    helper APIs during resolution). It's a best-effort heuristic: resolutions
    are validated against the known exports, so it won't add bogus imports, but
    it may still resolve a wrapper incorrectly. Use it when a default run leaves
    import wrappers unresolved and the dumped binary crashes.

    `runtime_imports` (Themida/WinLicense 2.x only) resolves import wrappers
    that can't be resolved statically but point inside a loaded module (imports
    the packer redirected a few bytes into the real API). Each such target is
    resolved to the entry of the export whose function contains it. This handles
    wrappers that defeat emulation, without executing any wrapper code.
    """
    setup_logger(LOG, verbose)

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

    dumped_image_base = 0
    dumped_oep = 0
    is_dotnet = False
    oep_reached = False
    # Signaled when the OEP is reached or when the target process goes away.
    instrumentation_done = threading.Event()
    detach_reason: List[str] = []

    def notify_oep_reached(image_base: int, oep: int, dotnet: bool) -> None:
        nonlocal dumped_image_base
        nonlocal dumped_oep
        nonlocal is_dotnet
        nonlocal oep_reached
        dumped_image_base = image_base
        dumped_oep = oep
        is_dotnet = dotnet
        oep_reached = True
        instrumentation_done.set()

    def notify_process_detached(reason: str, *_args: object) -> None:
        # Called by Frida when the session detaches (e.g. the target exited or
        # crashed). Unblock the wait so we don't sit until the timeout.
        detach_reason.append(reason)
        instrumentation_done.set()

    # Spawn the packed executable and instrument it to find its OEP
    process_controller = frida_exec.spawn_and_instrument(
        pe_path, text_section_ranges, notify_oep_reached,
        notify_process_detached)
    try:
        # Block until the OEP is reached or the process goes away
        if not instrumentation_done.wait(float(timeout)):
            LOG.error(
                "Original entry point wasn't reached before timeout (%ds). "
                "The target might need more time to unpack: try increasing "
                "the timeout with '--timeout <seconds>'.", timeout)
            sys.exit(4)

        # The process died (crashed or exited) before the OEP was reached
        if not oep_reached:
            LOG.error(
                "The target process exited before the original entry point was "
                "reached (reason: %s). This is typically caused by the packer's "
                "anti-debugging/anti-tampering detecting the instrumentation. "
                "Unpacking can be non-deterministic, so retrying may succeed.",
                detach_reason[0] if detach_reason else "unknown")
            sys.exit(4)

        LOG.info("OEP reached: OEP=%s BASE=%s DOTNET=%r", hex(dumped_oep),
                 hex(dumped_image_base), is_dotnet)
        if pause_on_oep:
            input("Thread blocked, press ENTER to proceed with the dumping.")

        if force_oep is not None:
            dumped_oep = dumped_image_base + force_oep
            LOG.info("Using given OEP RVA value instead (%s)", hex(force_oep))

        # Pick the range that contains the OEP
        text_section_range = text_section_ranges[0]
        for range in text_section_ranges:
            if range.contains(dumped_oep - dumped_image_base):
                text_section_range = range

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
            winlicense2.fix_and_dump_pe(process_controller, pe_to_dump,
                                        dumped_image_base, dumped_oep,
                                        text_section_range, aggressive_imports,
                                        runtime_imports)
        elif target_version == 3:
            winlicense3.fix_and_dump_pe(process_controller, pe_to_dump,
                                        dumped_image_base, dumped_oep,
                                        section_ranges, text_section_range)
    finally:
        # Try to kill the process on exit
        process_controller.terminate_process()


def _force_run_as_invoker() -> None:
    os.environ["__COMPAT_LAYER"] = "RUNASINVOKER"
