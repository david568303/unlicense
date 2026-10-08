import json
import logging
import struct
from pathlib import Path
from typing import Callable, Dict, List, Tuple, Any, Optional

from capstone import (  # type: ignore
    Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64)
from capstone.x86 import X86_OP_IMM, X86_OP_MEM  # type: ignore

from .imports import ImportToCallSiteDict, WrapperSet, find_wrapped_imports
from .dump_utils import dump_pe, pointer_size_to_fmt
from .emulation import resolve_wrapped_api
from .function_hashing import compute_function_hash, EMPTY_FUNCTION_HASH
from .process_control import (ProcessController, Architecture, MemoryRange,
                              ReadProcessMemoryError)

LOG = logging.getLogger(__name__)
NON_IMPORT_RESOLUTION_METHODS = {"internal_call", "external_code_target"}
ExportHashCandidates = Dict[int, List[int]]


def fix_and_dump_pe(
    process_controller: ProcessController,
    pe_file_path: str,
    image_base: int,
    oep: int,
    text_section_range: MemoryRange,
    diagnostic_output: Optional[str] = None,
    native_trace_timeout: int = 0,
    active_wrapper_probe: bool = False,
    active_probe_timeout: int = 5000,
    probe_process_factory: Optional[Callable[[],
                                             Tuple[Optional[ProcessController],
                                                   Optional[int]]]] = None
) -> None:
    """
    Main dumping routine for Themida/WinLicense 2.x.
    """
    # Convert RVA range to VA range
    section_virtual_addr = image_base + text_section_range.base
    text_section_range = MemoryRange(
        section_virtual_addr, text_section_range.size, "r-x",
        process_controller.read_process_memory(section_virtual_addr,
                                               text_section_range.size))
    assert text_section_range.data is not None
    LOG.debug(".text section: %s", str(text_section_range))

    arch = process_controller.architecture
    exports_dict = process_controller.enumerate_exported_functions()

    # Instanciate the disassembler
    if arch == Architecture.X86_32:
        cs_mode = CS_MODE_32
    elif arch == Architecture.X86_64:
        cs_mode = CS_MODE_64
    else:
        raise NotImplementedError(f"Unsupported architecture: {arch}")
    md = Cs(CS_ARCH_X86, cs_mode)
    md.detail = True

    LOG.info("Looking for wrapped imports ...")
    api_to_calls, wrapper_set, runtime_wrapper_set = find_wrapped_imports(
        text_section_range, exports_dict, md, process_controller)

    LOG.info("Potential import wrappers found: %d", len(wrapper_set))
    LOG.info("In-section wrapper candidates reserved for native tracing: %d",
             len(runtime_wrapper_set))
    direct_import_count = len(api_to_calls)
    export_hashes = None
    # Hash-matching strategy is only needed for 32-bit PEs
    if arch == Architecture.X86_32:
        LOG.info("Generating exports' hashes, this might take some time ...")
        export_hashes = _generate_export_hashes(md, exports_dict,
                                                process_controller)

    LOG.info("Resolving imports ...")
    wrapper_diagnostics = _resolve_imports(
        api_to_calls, wrapper_set, export_hashes, exports_dict, md,
        process_controller, native_trace_timeout, active_wrapper_probe,
        active_probe_timeout, image_base, probe_process_factory,
        runtime_wrapper_set)
    LOG.info("Imports resolved: %d", len(api_to_calls))

    preserved_external_count = sum(
        1 for wrapper in wrapper_diagnostics
        if wrapper.get("resolution_method") == "external_code_target")
    if preserved_external_count:
        LOG.info("Preserved external code targets: %d",
                 preserved_external_count)

    unresolved_count = sum(
        1 for wrapper in wrapper_diagnostics
        if wrapper.get("resolved_address") is None and wrapper.get(
            "resolution_method") not in NON_IMPORT_RESOLUTION_METHODS)
    if unresolved_count > 0:
        LOG.warning(
            "Unresolved suspected wrappers preserved unchanged: %d/%d. "
            "If one is executed on a later code path, the dump may not run.",
            unresolved_count, len(wrapper_diagnostics))

    if diagnostic_output is not None:
        _write_diagnostic_report(diagnostic_output, pe_file_path, image_base,
                                 oep, text_section_range, direct_import_count,
                                 api_to_calls, wrapper_diagnostics,
                                 process_controller)

    try:
        iat_addr, iat_size = _generate_new_iat_in_process(
            api_to_calls, text_section_range.base, process_controller)
        if iat_size:
            LOG.info("Generated the fake IAT at %s, size=%s", hex(iat_addr),
                     hex(iat_size))
            # Replace detected references to wrappers or imports
            LOG.info("Patching call and jmp sites ...")
            _fix_import_references_in_process(api_to_calls, iat_addr,
                                              process_controller)
        else:
            LOG.warning("No reliable imports were resolved; preserving all "
                        "original call sites and rebuilding without a fake "
                        "IAT")

        LOG.info("Dumping PE with OEP=%s ...", hex(oep))
        dump_pe(process_controller, pe_file_path, image_base, oep, iat_addr,
                iat_size, True)
    except Exception as error:
        LOG.error(
            "Dump target became unavailable before PE reconstruction: "
            "%s", error)


def _generate_export_hashes(
        md: Cs, exports_dict: Dict[int, Dict[str, Any]],
        process_controller: ProcessController) -> ExportHashCandidates:
    """
    Go through the given export dictionary and produce a hash for each function
    listed in it.
    """
    result: ExportHashCandidates = {}
    modules = process_controller.enumerate_modules()
    LOG.debug("Hashing exports for %s", str(modules))
    ranges = []
    for module_name in modules:
        if module_name != process_controller.main_module_name:
            ranges += process_controller.enumerate_module_ranges(
                module_name, include_data=True)
    ranges = list(
        filter(lambda mem_range: mem_range.protection[2] == 'x', ranges))

    def get_data(addr: int, size: int) -> bytes:
        for mem_range in ranges:
            if mem_range.data is None:
                continue
            if mem_range.contains(addr):
                offset = addr - mem_range.base
                return mem_range.data[offset:offset + size]
        return bytes()

    exports_count = len(exports_dict)
    empty_hash_count = 0
    loop_hash_count = 0
    for i, (export_addr, _) in enumerate(exports_dict.items()):
        hash_diagnostic: Dict[str, Any] = {}
        export_hash = compute_function_hash(md, export_addr, get_data,
                                            process_controller,
                                            hash_diagnostic)
        if hash_diagnostic.get("loop_edges", 0):
            loop_hash_count += 1
        if export_hash != EMPTY_FUNCTION_HASH:
            # More than one export can legitimately have identical code, and
            # the mutation-resistant fingerprint is intentionally lossy.  A
            # single-address dictionary used to overwrite earlier candidates,
            # making the selected API depend on module/export enumeration
            # order.  Keep every candidate and require another resolver to
            # disambiguate collisions.
            result.setdefault(export_hash, []).append(export_addr)
        else:
            empty_hash_count += 1
        completed = i + 1
        if completed == exports_count or completed % 250 == 0:
            LOG.debug("Exports hashed: %d/%d", completed, exports_count)

    ambiguous_groups = [
        addresses for addresses in result.values() if len(addresses) > 1
    ]
    LOG.info(
        "Export fingerprints generated: %d unique, %d ambiguous groups "
        "covering %d exports, %d empty, %d containing loops", len(result),
        len(ambiguous_groups),
        sum(len(addresses) for addresses in ambiguous_groups),
        empty_hash_count, loop_hash_count)

    return result


def _resolve_imports(
    api_to_calls: ImportToCallSiteDict,
    wrapper_set: WrapperSet,
    export_hashes: Optional[ExportHashCandidates],
    exports_dict: Dict[int, Dict[str, Any]],
    md: Cs,
    process_controller: ProcessController,
    native_trace_timeout: int = 0,
    active_wrapper_probe: bool = False,
    active_probe_timeout: int = 5000,
    image_base: Optional[int] = None,
    probe_process_factory: Optional[Callable[[],
                                             Tuple[Optional[ProcessController],
                                                   Optional[int]]]] = None,
    runtime_wrapper_set: Optional[WrapperSet] = None,
) -> List[Dict[str, Any]]:
    """
    Resolve potential import wrappers by hash-matching or emulation.
    """
    arch = process_controller.architecture
    page_size = process_controller.page_size

    def get_data(addr: int, size: int) -> bytes:
        try:
            return process_controller.read_process_memory(addr, size)
        except ReadProcessMemoryError:
            # In case we crossed a page boundary and tried to read an invalid
            # page, reduce size to stop at page boundary, and try again.
            size = page_size - (addr % page_size)
        return process_controller.read_process_memory(addr, size)

    def diagnostic_bytes(addr: int, size: int) -> Optional[str]:
        try:
            return get_data(addr, size).hex()
        except ReadProcessMemoryError:
            return None

    def record_resolution(record: Dict[str, Any], method: str,
                          resolved_addr: int) -> None:
        record["resolution_method"] = method
        record["resolved_address"] = hex(resolved_addr)
        export = exports_dict.get(resolved_addr)
        if export is not None:
            record["resolved_export"] = export

    # Iterate over the set of potential import wrappers and try to resolve them
    resolved_wrappers: Dict[int, int] = {}
    problematic_wrappers = set()
    diagnostics: List[Dict[str, Any]] = []
    for call_addr, call_size, instr_was_jmp, wrapper_addr, ptr_addr in sorted(
            wrapper_set, key=lambda wrapper: (wrapper[3], wrapper[0])):
        record: Dict[str, Any] = {
            "call_address": hex(call_addr),
            "call_size": call_size,
            "is_jump": instr_was_jmp,
            "wrapper_address": hex(wrapper_addr),
            "pointer_address": None if ptr_addr is None else hex(ptr_addr),
            "call_site_bytes": diagnostic_bytes(call_addr, 16),
            "wrapper_bytes": diagnostic_bytes(wrapper_addr, 256),
            "resolved_address": None,
        }
        try:
            wrapper_module = process_controller.find_module_by_address(
                wrapper_addr)
            record["wrapper_module"] = wrapper_module
        except Exception as error:
            record["wrapper_module_error"] = str(error)
        diagnostics.append(record)

        wrapper_module = record.get("wrapper_module")
        wrapper_module_name = (wrapper_module.get("name") if isinstance(
            wrapper_module, dict) else None)
        if (isinstance(wrapper_module_name, str)
                and wrapper_module_name.lower() !=
                process_controller.main_module_name.lower()):
            # Exact exports were already classified by find_wrapped_imports.
            # A non-export address inside a system/embedded DLL is executable
            # external code, not a Themida wrapper owned by the main image.
            # Hashing such code can collide with an unrelated short export
            # (observed as msvcrt code being rewritten to WLDAP32), corrupting
            # an otherwise valid call site.
            record["resolution_method"] = "external_code_target"
            LOG.debug("Preserving external code target: %s -> %s!%s",
                      hex(call_addr), wrapper_module_name, hex(wrapper_addr))
            continue

        resolved_addr = resolved_wrappers.get(wrapper_addr)
        if resolved_addr is not None:
            LOG.debug("Already resolved wrapper: %s -> %s", hex(wrapper_addr),
                      hex(resolved_addr))
            api_to_calls[resolved_addr].append(
                (call_addr, call_size, instr_was_jmp))
            record_resolution(record, "cached", resolved_addr)
            continue

        if wrapper_addr in problematic_wrappers:
            # Already failed to resolve this one, ignore
            LOG.debug("Skipping unresolved wrapper")
            record["resolution_method"] = "previous_failure"
            continue

        # If 32-bit executable, try hash-matching
        if export_hashes is not None and arch == Architecture.X86_32:
            hash_diagnostic: Dict[str, Any] = {}
            try:
                import_hash = compute_function_hash(md, wrapper_addr, get_data,
                                                    process_controller,
                                                    hash_diagnostic)
            except Exception as ex:
                LOG.debug("Failure for wrapper at %s: %s", hex(wrapper_addr),
                          str(ex))
                record["hash_error"] = str(ex)
                import_hash = EMPTY_FUNCTION_HASH
            if hash_diagnostic:
                record["hash_diagnostic"] = hash_diagnostic
            if import_hash != EMPTY_FUNCTION_HASH:
                LOG.debug("Hash: %s", hex(import_hash))
                record["function_hash"] = hex(import_hash)
                hash_candidates = export_hashes.get(import_hash, [])
                if len(hash_candidates) == 1:
                    resolved_addr = hash_candidates[0]
                    LOG.debug("Hash matched")
                    LOG.debug("Resolved API: %s -> %s", hex(wrapper_addr),
                              hex(resolved_addr))
                    resolved_wrappers[wrapper_addr] = resolved_addr
                    api_to_calls[resolved_addr].append(
                        (call_addr, call_size, instr_was_jmp))
                    record_resolution(record, "hash", resolved_addr)
                    continue
                if len(hash_candidates) > 1:
                    record["hash_candidates"] = [{
                        "address":
                        hex(candidate),
                        "export":
                        exports_dict.get(candidate),
                    } for candidate in hash_candidates]
                    record["hash_ambiguous"] = True
                    LOG.debug(
                        "Ambiguous hash %s matched %d exports; deferring to "
                        "emulation/native tracing", hex(import_hash),
                        len(hash_candidates))

        # Try to resolve the destination address by emulating the wrapper
        emulation_diagnostic: Dict[str, Any] = {}
        resolved_addr = resolve_wrapped_api(call_addr, process_controller,
                                            call_addr + call_size,
                                            emulation_diagnostic)
        record["emulation"] = emulation_diagnostic
        if resolved_addr is not None:
            LOG.debug("Resolved API: %s -> %s", hex(wrapper_addr),
                      hex(resolved_addr))
            resolved_wrappers[wrapper_addr] = resolved_addr
            api_to_calls[resolved_addr].append(
                (call_addr, call_size, instr_was_jmp))
            record_resolution(record, "emulation", resolved_addr)
        else:
            if (emulation_diagnostic.get("returned_without_export")
                    and isinstance(wrapper_module_name, str)
                    and wrapper_module_name.lower()
                    == process_controller.main_module_name.lower()):
                LOG.debug(
                    "Ignoring internal call misidentified as wrapper: "
                    "%s -> %s", hex(call_addr), hex(wrapper_addr))
                record["resolution_method"] = "internal_call"
            else:
                record["resolution_method"] = "unresolved"
                problematic_wrappers.add(wrapper_addr)

    def apply_traced_imports(records: List[Dict[str, Any]],
                             traced_imports: Dict[int,
                                                  int], method: str) -> None:
        for record in records:
            call_addr = int(record["call_address"], 16)
            resolved_addr = traced_imports.get(call_addr)
            if resolved_addr is None:
                continue
            LOG.debug("%s resolved API: %s -> %s", method,
                      record["wrapper_address"], hex(resolved_addr))
            api_to_calls[resolved_addr].append(
                (call_addr, int(record["call_size"]), bool(record["is_jump"])))
            record_resolution(record, method, resolved_addr)

    def merge_observed_imports(observations: List[Dict[str, Any]]) -> int:
        """Merge dynamically observed, safely patchable import call sites."""
        existing_by_call: Dict[int, int] = {}
        for import_addr, call_sites in api_to_calls.items():
            for existing_call, _, _ in call_sites:
                existing_by_call[existing_call] = import_addr

        accepted = 0
        for observation in observations:
            observation["accepted"] = False
            try:
                call_addr = int(str(observation["callAddress"]), 16)
                resolved_addr = int(str(observation["address"]), 16)
                call_size = int(observation["callSize"])
                instr_was_jmp = bool(observation["isJump"])
            except (KeyError, TypeError, ValueError) as error:
                observation["rejection_reason"] = f"invalid trace record: {error}"
                continue

            if resolved_addr not in exports_dict:
                observation["rejection_reason"] = \
                    "destination is not a currently loaded export"
                continue

            try:
                call_bytes = get_data(call_addr, 7)
            except ReadProcessMemoryError as error:
                observation["rejection_reason"] = \
                    f"call site is no longer readable: {error}"
                continue

            # Revalidate the exact six-byte patch window on the host. Plain
            # five-byte E8 calls are intentionally rejected because replacing
            # them with FF15/FF25 would overwrite the next instruction.
            expected_size = 0
            if call_bytes[:2] == b"\x90\xe8" and len(call_bytes) >= 7:
                expected_size = 5
            elif call_bytes[:2] == b"\xff\x15" and len(call_bytes) >= 7:
                expected_size = 6
            elif (len(call_bytes) >= 7 and call_bytes[0] == 0xff
                  and ((call_bytes[1] >> 3) & 7) == 2
                  and (call_bytes[1] & 0xc0) == 0x80):
                # CALL r/m32 with a disp32 operand (for example FF 95 for
                # CALL [EBP+disp32]) has the six-byte window required for an
                # in-place FF 15 [absolute IAT] replacement.
                expected_size = 6
            elif (call_bytes[:1] == b"\xe8" and len(call_bytes) >= 6
                  and call_bytes[5] in (0x90, 0xcc)):
                expected_size = 5
            if expected_size == 0 or call_size != expected_size:
                observation["rejection_reason"] = \
                    "call site no longer has a safe Themida patch window"
                continue

            existing_addr = existing_by_call.get(call_addr)
            if existing_addr is not None:
                if existing_addr == resolved_addr:
                    observation["accepted"] = True
                    observation["duplicate"] = True
                else:
                    observation["rejection_reason"] = (
                        "call site conflicts with an existing resolution to "
                        f"{hex(existing_addr)}")
                continue

            api_to_calls[resolved_addr].append(
                (call_addr, call_size, instr_was_jmp))
            existing_by_call[call_addr] = resolved_addr
            observation["accepted"] = True
            accepted += 1
        return accepted

    unresolved_records = sorted(
        (record for record in diagnostics
         if record.get("resolved_address") is None and record.get(
             "resolution_method") not in NON_IMPORT_RESOLUTION_METHODS),
        key=lambda record: int(record["call_address"], 16))
    if native_trace_timeout > 0:
        runtime_records: List[Dict[str, Any]] = []
        for (call_addr, call_size, instr_was_jmp, wrapper_addr,
             _ptr_addr) in sorted(runtime_wrapper_set or set()):
            runtime_records.append({
                "call_address": hex(call_addr),
                "call_size": call_size,
                "is_jump": instr_was_jmp,
                "wrapper_address": hex(wrapper_addr),
                "call_site_bytes": diagnostic_bytes(call_addr, 16),
            })
        trace_requests = _build_trace_requests(unresolved_records +
                                               runtime_records)
        LOG.warning(
            "Running the dump target for %d ms to trace %d suspected "
            "wrappers (%d in-section) and discover executed imports",
            native_trace_timeout, len(trace_requests), len(runtime_records))
        try:
            traced_imports = process_controller.trace_wrapped_imports(
                trace_requests, native_trace_timeout, False)
            for record in unresolved_records:
                record["native_trace_stats"] = \
                    process_controller.last_wrapper_trace_stats
        except Exception as error:
            LOG.warning("Passive native wrapper tracing failed: %s", error)
            traced_imports = {}
        apply_traced_imports(unresolved_records, traced_imports,
                             "native_trace")
        existing_calls = {
            call_addr: import_addr
            for import_addr, call_sites in api_to_calls.items()
            for call_addr, _, _ in call_sites
        }
        runtime_resolved = 0
        runtime_by_call = {
            int(record["call_address"], 16): record
            for record in runtime_records
        }
        for call_addr, resolved_addr in traced_imports.items():
            runtime_record = runtime_by_call.get(call_addr)
            if runtime_record is None or resolved_addr not in exports_dict:
                continue
            existing_addr = existing_calls.get(call_addr)
            if existing_addr is not None:
                if existing_addr != resolved_addr:
                    LOG.debug(
                        "Ignoring conflicting runtime wrapper resolution at "
                        "%s: %s vs %s", hex(call_addr), hex(existing_addr),
                        hex(resolved_addr))
                continue
            api_to_calls[resolved_addr].append(
                (call_addr, int(runtime_record["call_size"]),
                 bool(runtime_record["is_jump"])))
            existing_calls[call_addr] = resolved_addr
            runtime_resolved += 1
        if process_controller.last_wrapper_trace_stats is not None:
            process_controller.last_wrapper_trace_stats[
                "runtimeCandidates"] = len(runtime_records)
            process_controller.last_wrapper_trace_stats[
                "runtimeCandidateResolutions"] = runtime_resolved
        LOG.info("Resolved %d in-section wrappers through native execution",
                 runtime_resolved)
        observed_count = merge_observed_imports(
            process_controller.last_observed_imports)
        LOG.info("Accepted %d dynamically observed import call sites",
                 observed_count)

    unresolved_records = sorted(
        (record for record in diagnostics
         if record.get("resolved_address") is None and record.get(
             "resolution_method") not in NON_IMPORT_RESOLUTION_METHODS),
        key=lambda record: int(record["call_address"], 16))
    if (active_wrapper_probe and unresolved_records
            and arch != Architecture.X86_32):
        LOG.warning("Active wrapper probing currently supports 32-bit targets "
                    "only; the dump target will not be probed")
    elif active_wrapper_probe and unresolved_records:
        if probe_process_factory is None or image_base is None:
            LOG.warning("Active wrapper probing was requested, but no "
                        "sacrificial process factory is available; the dump "
                        "target will not be probed")
        else:
            probe_timeout = max(100, min(60000, active_probe_timeout))
            probe_controller: Optional[ProcessController] = None
            try:
                probe_controller, probe_image_base = probe_process_factory()
                if probe_controller is None or probe_image_base is None:
                    for record in unresolved_records:
                        record["probe_error"] = \
                            "sacrificial target unavailable"
                    LOG.warning("No sacrificial target is available for "
                                "natural wrapper tracing")
                else:
                    for record in unresolved_records:
                        record["probe_pid"] = probe_controller.pid
                    probe_requests, probe_to_main_calls = \
                        _build_probe_trace_requests(
                            unresolved_records, image_base, probe_image_base,
                            md, probe_controller)
                    LOG.warning(
                        "Tracing %d unresolved wrapper(s) during %d ms of "
                        "natural execution in one sacrificial target PID=%d; "
                        "the dump target remains blocked", len(probe_requests),
                        probe_timeout, probe_controller.pid)
                    probe_results = probe_controller.trace_wrapped_imports(
                        probe_requests, probe_timeout, False)
                    stats = probe_controller.last_wrapper_trace_stats
                    for record in unresolved_records:
                        record["probe_trace_stats"] = stats
                    traced_imports = _translate_probe_results(
                        probe_results, probe_to_main_calls, probe_controller,
                        process_controller)
                    apply_traced_imports(unresolved_records, traced_imports,
                                         "sacrificial_natural_trace")
                    for record in unresolved_records:
                        if record.get("resolved_address") is None:
                            record["probe_error"] = (
                                "wrapper was not resolved during natural "
                                f"execution ({probe_timeout} ms)")
                        else:
                            record.pop("probe_error", None)
            except Exception as error:
                for record in unresolved_records:
                    if record.get("resolved_address") is None:
                        record["probe_error"] = str(error)
                LOG.warning("Sacrificial natural wrapper tracing failed: %s",
                            error)
            finally:
                if probe_controller is not None:
                    probe_controller.terminate_process()

    return diagnostics


def _build_trace_requests(
        records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    requests = []
    for record in records:
        prefix_size = 1 if str(record.get("call_site_bytes",
                                          "")).startswith("90") else 0
        call_address = int(record["call_address"], 16)
        requests.append({
            "callAddress":
            record["call_address"],
            "wrapperAddress":
            record["wrapper_address"],
            "returnAddress":
            hex(call_address + int(record["call_size"]) + prefix_size),
            "isJump":
            bool(record["is_jump"]),
        })
    return requests


def _build_probe_trace_requests(
    records: List[Dict[str, Any]],
    image_base: int,
    probe_image_base: int,
    md: Cs,
    probe_controller: ProcessController,
) -> Tuple[List[Dict[str, Any]], Dict[int, int]]:
    requests = []
    probe_to_main_calls = {}
    pointer_format = pointer_size_to_fmt(probe_controller.pointer_size)

    for record in records:
        main_call = int(record["call_address"], 16)
        probe_call = probe_image_base + main_call - image_base
        try:
            call_bytes = probe_controller.read_process_memory(probe_call, 16)
            prefix_size = 1 if call_bytes[0] == 0x90 else 0
            instruction_address = probe_call + prefix_size
            instruction = next(
                md.disasm(call_bytes[prefix_size:], instruction_address), None)
            if instruction is None or instruction.mnemonic not in ("call",
                                                                   "jmp"):
                raise ValueError("translated call site is not a CALL/JMP")
            operand = instruction.operands[0]
            if operand.type == X86_OP_IMM:
                wrapper_address = operand.value.imm
            elif operand.type == X86_OP_MEM:
                pointer_address = operand.value.mem.disp & 0xffffffff
                pointer_data = probe_controller.read_process_memory(
                    pointer_address, probe_controller.pointer_size)
                wrapper_address = struct.unpack(pointer_format,
                                                pointer_data)[0]
            else:
                raise ValueError("unsupported translated call operand")

            record["probe_call_address"] = hex(probe_call)
            record["probe_wrapper_address"] = hex(wrapper_address)
            requests.append({
                "callAddress":
                hex(probe_call),
                "wrapperAddress":
                hex(wrapper_address),
                "returnAddress":
                hex(instruction.address + instruction.size),
                "isJump":
                bool(record["is_jump"]),
            })
            probe_to_main_calls[probe_call] = main_call
        except Exception as error:
            record["probe_error"] = str(error)
            LOG.debug("Failed to translate call site %s to probe: %s",
                      record["call_address"], error)

    return requests, probe_to_main_calls


def _translate_probe_results(
    probe_results: Dict[int, int],
    probe_to_main_calls: Dict[int, int],
    probe_controller: ProcessController,
    process_controller: ProcessController,
) -> Dict[int, int]:
    translated = {}
    probe_exports = probe_controller.enumerate_exported_functions()
    main_exports = process_controller.enumerate_exported_functions()

    for probe_call, probe_export_address in probe_results.items():
        main_call = probe_to_main_calls.get(probe_call)
        export = probe_exports.get(probe_export_address)
        if main_call is None or export is None:
            continue

        main_export_address = None
        module_name = export.get("module")
        export_name = export.get("name")
        if module_name is not None and export_name is not None:
            main_export_address = process_controller.find_export_by_name(
                str(module_name), str(export_name))
        if main_export_address is None and probe_export_address in main_exports:
            main_export_address = probe_export_address
        if main_export_address is None:
            LOG.debug("Failed to translate probe export %s!%s at %s",
                      module_name, export_name, hex(probe_export_address))
            continue
        translated[main_call] = main_export_address

    return translated


def _write_diagnostic_report(output_path: str, pe_file_path: str,
                             image_base: int, oep: int,
                             text_section_range: MemoryRange,
                             direct_import_count: int,
                             api_to_calls: ImportToCallSiteDict,
                             wrapper_diagnostics: List[Dict[str, Any]],
                             process_controller: ProcessController) -> None:
    exports_dict = process_controller.enumerate_exported_functions()
    collection_errors = []
    try:
        loaded_modules = process_controller.enumerate_modules()
    except Exception as error:  # Diagnostics must not abort the dump.
        loaded_modules = []
        collection_errors.append(f"loaded_modules: {error}")
    try:
        pe_memory_candidates = process_controller.enumerate_pe_candidates()
    except Exception as error:  # Diagnostics must not abort the dump.
        pe_memory_candidates = []
        collection_errors.append(f"pe_memory_candidates: {error}")

    resolved_imports = []
    for address, call_sites in api_to_calls.items():
        resolved_imports.append({
            "address":
            hex(address),
            "export":
            exports_dict.get(address),
            "call_sites": [{
                "address": hex(call_address),
                "size": call_size,
                "is_jump": is_jump,
            } for call_address, call_size, is_jump in call_sites],
        })

    report = {
        "format_version": 1,
        "target_name": Path(pe_file_path).name,
        "architecture": process_controller.architecture.name,
        "image_base": hex(image_base),
        "oep": hex(oep),
        "text_section": {
            "base": hex(text_section_range.base),
            "size": hex(text_section_range.size),
            "protection": text_section_range.protection,
        },
        "loaded_modules": loaded_modules,
        "pe_memory_candidates": pe_memory_candidates,
        "collection_errors": collection_errors,
        "direct_import_count": direct_import_count,
        "native_observed_import_count": sum(
            1 for observation in process_controller.last_observed_imports
            if observation.get("accepted")),
        "native_observed_imports": process_controller.last_observed_imports,
        "native_trace_stats": process_controller.last_wrapper_trace_stats,
        "potential_wrapper_count": len(wrapper_diagnostics),
        "resolved_import_count": len(api_to_calls),
        "resolved_imports": resolved_imports,
        "wrappers": wrapper_diagnostics,
    }

    destination = Path(output_path)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
        LOG.info("Diagnostic report saved at '%s'", destination)
    except OSError as error:
        LOG.error("Failed to write diagnostic report '%s': %s", destination,
                  error)


def _generate_new_iat_in_process(
        imports_dict: ImportToCallSiteDict, near_to_ptr: int,
        process_controller: ProcessController) -> Tuple[int, int]:
    """
    Generate a new IAT from a list of imported function addresses and write
    it into a new buffer into the target process. `near_to_ptr` is used to
    allocate the new IAT near the unpacked module (which is needed for 64-bit
    processes).
    """
    ptr_size = process_controller.pointer_size
    ptr_format = pointer_size_to_fmt(ptr_size)
    iat_size = len(imports_dict) * ptr_size
    if iat_size == 0:
        return 0, 0
    # Allocate a new buffer in the target process
    iat_addr = process_controller.allocate_process_memory(
        iat_size, near_to_ptr)

    # Generate the new IAT and write it into the buffer
    new_iat_data = bytearray()
    for import_addr in imports_dict:
        new_iat_data += struct.pack(ptr_format, import_addr)
    process_controller.write_process_memory(iat_addr, list(new_iat_data))

    return iat_addr, iat_size


def _fix_import_references_in_process(
        api_to_calls: ImportToCallSiteDict, iat_addr: int,
        process_controller: ProcessController) -> None:
    """
    Replace resolved wrapper call sites with call/jmp to the new IAT (that
    contains resolved imports).
    """
    arch = process_controller.architecture
    ptr_size = process_controller.pointer_size
    changed_pages: Dict[int, str] = {}
    checked_pages = set()
    try:
        for i, call_addrs in enumerate(api_to_calls.values()):
            for call_addr, _, instr_was_jmp in call_addrs:
                page_base = call_addr - call_addr % process_controller.page_size
                if page_base not in checked_pages:
                    protection = process_controller.query_memory_protection(
                        call_addr)
                    checked_pages.add(page_base)
                    if len(protection) < 2 or protection[1] != "w":
                        if not process_controller.set_memory_protection(
                                page_base, process_controller.page_size,
                                "rwx"):
                            raise RuntimeError(
                                "failed to make import call page writable at "
                                f"{hex(page_base)}")
                        changed_pages[page_base] = protection

                if arch == Architecture.X86_32:
                    # Absolute
                    operand = iat_addr + i * ptr_size
                    fmt = "<I"
                elif arch == Architecture.X86_64:
                    # RIP-relative
                    operand = iat_addr + i * ptr_size - (call_addr + 6)
                    fmt = "<i"
                else:
                    raise NotImplementedError(
                        f"Unsupported architecture: {arch}")

                if instr_was_jmp:
                    # jmp [iat_addr + i * ptr_size]
                    new_instr = bytes([0xFF, 0x25]) + struct.pack(fmt, operand)
                else:
                    # call [iat_addr + i * ptr_size]
                    new_instr = bytes([0xFF, 0x15]) + struct.pack(fmt, operand)
                process_controller.write_process_memory(call_addr,
                                                        list(new_instr))
    finally:
        for page_base, protection in changed_pages.items():
            if not process_controller.set_memory_protection(
                    page_base, process_controller.page_size, protection):
                LOG.warning("Failed to restore memory protection %s at %s",
                            protection, hex(page_base))
