import gc
import json
import logging
import os
import platform
import re
import shutil
import struct
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Optional, Tuple

import lief
import pyscylla  # type: ignore

from unlicense.lief_utils import lief_pe_data_directories, lief_pe_sections

from .process_control import MemoryRange, ProcessController

LOG = logging.getLogger(__name__)

SectionFileMapping = Tuple[int, int, int, int]

# Themida 2.x emits this position-independent integrity guard in one of its
# executable runtime sections.  The guard reads a pointer from a private,
# process-only allocation and returns 0 when no state/mismatch is present or 1
# when tampering is detected.  A standalone PE cannot serialize that private
# allocation, so the captured pointer becomes stale on the next launch.  The
# full control-flow signature is deliberately strict; only the success return
# at the function entry is patched.
_VM_POINTER_GUARD_PATTERN = re.compile(
    b"\x60\xe8\x00\x00\x00\x00\x5a\x81\xea.{4}"
    b"\x8b\xb2.{4}\x85\xf6\x0f\x85\x07\x00\x00\x00"
    b"\x61\xb8\x00\x00\x00\x00\xc3\x8b\x06\x39\x82.{4}"
    b"\x0f\x85\x0b\x00\x00\x00\x61\xb8\x00\x00\x00\x00"
    b"\xe9\x06\x00\x00\x00\x61\xb8\x01\x00\x00\x00\xc3",
    re.DOTALL)


def _materialize_iat_input(process_controller: ProcessController,
                           image_base: int, iat_addr: int, iat_size: int,
                           add_new_iat: bool, dumped_path: str,
                           output_path: str) -> bool:
    """Fix a real IAT, or preserve the dump byte-for-byte when none exists."""
    if iat_size == 0:
        shutil.copyfile(dumped_path, output_path)
        return False
    pyscylla.fix_iat(process_controller.pid, image_base, iat_addr, iat_size,
                     add_new_iat, dumped_path, output_path)
    return True


def _mapped_file_slices(section_mappings: List[SectionFileMapping], rva: int,
                        size: int) -> List[Tuple[int, int, int]]:
    """Map an RVA range to (file offset, source offset, size) slices."""
    slices: List[Tuple[int, int, int]] = []
    range_end = rva + size
    for section_rva, virtual_size, raw_offset, raw_size in section_mappings:
        section_end = section_rva + min(virtual_size, raw_size)
        overlap_start = max(rva, section_rva)
        overlap_end = min(range_end, section_end)
        if overlap_start >= overlap_end:
            continue
        slices.append((raw_offset + overlap_start - section_rva,
                       overlap_start - rva, overlap_end - overlap_start))
    return sorted(slices, key=lambda item: item[1])


def _overlay_pristine_data(
    file_data: bytearray,
    image_base: int,
    section_mappings: List[SectionFileMapping],
    pristine_ranges: List[MemoryRange],
    preserved_patch_ranges: List[Tuple[int, int]],
) -> Dict[str, int]:
    """Restore clean OEP bytes while retaining rebuilt import references."""
    preserved_patches: List[Tuple[List[Tuple[int, int, int]], bytes]] = []
    for patch_address, patch_size in preserved_patch_ranges:
        patch_rva = patch_address - image_base
        slices = _mapped_file_slices(section_mappings, patch_rva, patch_size)
        if sum(item[2] for item in slices) != patch_size:
            continue
        patch_buffer = bytearray(patch_size)
        for file_offset, source_offset, slice_size in slices:
            patch_buffer[source_offset:source_offset + slice_size] = \
                file_data[file_offset:file_offset + slice_size]
        preserved_patches.append((slices, bytes(patch_buffer)))

    restored_bytes = 0
    restored_ranges = 0
    for memory_range in pristine_ranges:
        if memory_range.data is None or memory_range.size <= 0:
            continue
        range_rva = memory_range.base - image_base
        slices = _mapped_file_slices(section_mappings, range_rva,
                                     memory_range.size)
        range_bytes = 0
        for file_offset, source_offset, slice_size in slices:
            file_data[file_offset:file_offset + slice_size] = \
                memory_range.data[source_offset:source_offset + slice_size]
            range_bytes += slice_size
        if range_bytes:
            restored_ranges += 1
            restored_bytes += range_bytes

    for slices, saved_patch in preserved_patches:
        for file_offset, source_offset, slice_size in slices:
            file_data[file_offset:file_offset + slice_size] = \
                saved_patch[source_offset:source_offset + slice_size]

    return {
        "restored_ranges": restored_ranges,
        "restored_bytes": restored_bytes,
        "preserved_rebuilt_regions": len(preserved_patches),
    }


def _patch_stale_vm_pointer_guards(
        file_data: bytearray,
        executable_mappings: List[SectionFileMapping]) -> List[int]:
    """Return RVAs of exact Themida private-state guards made inert."""
    patched_rvas: List[int] = []
    for section_rva, _virtual_size, raw_offset, raw_size in executable_mappings:
        section_data = bytes(file_data[raw_offset:raw_offset + raw_size])
        for match in _VM_POINTER_GUARD_PATTERN.finditer(section_data):
            file_offset = raw_offset + match.start()
            # xor eax, eax; ret -- the guard's documented success path.
            file_data[file_offset:file_offset + 3] = b"\x31\xc0\xc3"
            patched_rvas.append(section_rva + match.start())
    return patched_rvas


def _neutralize_stale_vm_pointer_guards(dumped_path: str) -> List[int]:
    binary = lief.PE.parse(dumped_path)
    if binary is None:
        return []
    executable_mappings: List[SectionFileMapping] = [
        (int(section.virtual_address), int(section.virtual_size),
         int(section.offset), int(section.size))
        for section in lief_pe_sections(binary)
        if section.has_characteristic(
            lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE)
    ]
    del binary

    try:
        with open(dumped_path, "rb") as dumped_file:
            file_data = bytearray(dumped_file.read())
        patched_rvas = _patch_stale_vm_pointer_guards(
            file_data, executable_mappings)
        if patched_rvas:
            with open(dumped_path, "wb") as dumped_file:
                dumped_file.write(file_data)
            LOG.info("Neutralized %d stale Themida private-state guard(s) at "
                     "RVA(s): %s", len(patched_rvas),
                     ", ".join(hex(rva) for rva in patched_rvas))
        return patched_rvas
    except OSError as error:
        LOG.warning("Failed to neutralize stale Themida state guards: %s",
                    error)
        return []


def _restore_pristine_ranges_in_dump(
    dumped_path: str,
    image_base: int,
    pristine_ranges: List[MemoryRange],
    preserved_patch_ranges: List[Tuple[int, int]],
) -> Dict[str, int]:
    """Replace late runtime state in a dump with the clean OEP snapshot."""
    empty_result = {
        "restored_ranges": 0,
        "restored_bytes": 0,
        "preserved_rebuilt_regions": 0,
    }
    if not pristine_ranges:
        return empty_result

    binary = lief.PE.parse(dumped_path)
    if binary is None:
        LOG.warning("Could not parse the IAT-fixed dump for runtime-state "
                    "restoration")
        return empty_result
    section_mappings: List[SectionFileMapping] = [
        (int(section.virtual_address), int(section.virtual_size),
         int(section.offset), int(section.size))
        for section in lief_pe_sections(binary)
    ]
    protected_ranges = list(preserved_patch_ranges)
    protected_sections = set()
    for directory in lief_pe_data_directories(binary):
        if directory.type not in (lief.PE.DATA_DIRECTORY.IMPORT_TABLE,
                                  lief.PE.DATA_DIRECTORY.IAT):
            continue
        if int(directory.rva) == 0:
            continue
        directory_section = directory.section
        if directory_section is not None:
            section_key = (int(directory_section.virtual_address),
                           int(directory_section.size))
            if section_key in protected_sections:
                continue
            protected_sections.add(section_key)
            protected_ranges.append(
                (image_base + int(directory_section.virtual_address),
                 int(directory_section.size)))
        elif int(directory.size) > 0:
            protected_ranges.append(
                (image_base + int(directory.rva), int(directory.size)))
    del binary

    try:
        with open(dumped_path, "rb") as dumped_file:
            file_data = bytearray(dumped_file.read())
        result = _overlay_pristine_data(file_data, image_base,
                                        section_mappings, pristine_ranges,
                                        protected_ranges)
        if result["restored_bytes"]:
            with open(dumped_path, "wb") as dumped_file:
                dumped_file.write(file_data)
            LOG.info(
                "Restored %d clean OEP bytes across %d image sections while "
                "preserving %d rebuilt import regions",
                result["restored_bytes"], result["restored_ranges"],
                result["preserved_rebuilt_regions"])
        return result
    except OSError as error:
        LOG.warning("Failed to restore clean OEP image state: %s", error)
        return empty_result


def get_section_ranges(pe_file_path: str) -> List[MemoryRange]:
    section_ranges: List[MemoryRange] = []
    binary = lief.PE.parse(pe_file_path)
    if binary is None:
        LOG.error("Failed to parse PE '%s'", pe_file_path)
        return section_ranges

    for section in lief_pe_sections(binary):
        section_ranges += [
            MemoryRange(section.virtual_address, section.virtual_size, "r--")
        ]

    return section_ranges


def probe_text_sections(pe_file_path: str) -> Optional[List[MemoryRange]]:
    text_sections = []
    binary = lief.PE.parse(pe_file_path)
    if binary is None:
        LOG.error("Failed to parse PE '%s'", pe_file_path)
        return None

    # Find the potential original text sections (i.e., executable sections with
    # "empty" names or named '.text*').
    # Note(ergrelet): we thus do not want to include Themida/WinLicense's
    # sections in that list.
    for section in lief_pe_sections(binary):
        section_name = section.fullname
        stripped_section_name = section_name.replace(' ',
                                                     '').replace('\00', '')
        if len(stripped_section_name) > 0 and \
                stripped_section_name not in [".text", ".textbss", ".textidx"]:
            break

        if section.has_characteristic(
                lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE):
            LOG.debug("Probed .text section at (0x%x, 0x%x)",
                      section.virtual_address, section.virtual_size)
            text_sections += [
                MemoryRange(section.virtual_address, section.virtual_size,
                            "r-x")
            ]

    return None if len(text_sections) == 0 else text_sections


def dump_pe(
    process_controller: ProcessController,
    pe_file_path: str,
    image_base: int,
    oep: int,
    iat_addr: int,
    iat_size: int,
    add_new_iat: bool,
    pristine_ranges: Optional[List[MemoryRange]] = None,
    preserved_patch_ranges: Optional[List[Tuple[int, int]]] = None,
    output_file_path: Optional[str] = None,
) -> bool:
    # Reclaim as much memory as possible. This is kind of a hack for 32-bit
    # interpreters not to run out of memory when dumping.
    # Idea: `pefile` might be less memory hungry than `lief` for our use case?
    process_controller.clear_cached_data()
    gc.collect()

    effective_iat_addr = iat_addr
    effective_iat_size = iat_size
    effective_add_new_iat = add_new_iat
    iat_strategy = "recovered"
    runtime_state_restoration = {
        "restored_ranges": 0,
        "restored_bytes": 0,
        "preserved_rebuilt_regions": 0,
    }
    neutralized_vm_state_guards: List[int] = []
    if effective_iat_size == 0:
        iat_strategy = "preserved_dump"
        LOG.warning(
            "No verified runtime IAT was recovered; preserving the dumped "
            "image's existing import directory. Automatic Scylla IAT search "
            "is disabled because malformed heuristic results can crash its "
            "native fix_iat routine")

    with TemporaryDirectory() as tmp_dir:
        TMP_FILE_PATH1 = os.path.join(tmp_dir, "unlicense.dump")
        TMP_FILE_PATH2 = os.path.join(tmp_dir, "unlicense.iat")
        try:
            pyscylla.dump_pe(process_controller.pid, image_base, oep,
                             TMP_FILE_PATH1, pe_file_path)
        except pyscylla.ScyllaException as scylla_exception:
            LOG.error("Failed to dump PE: %s", str(scylla_exception))
            return False

        LOG.info("Fixing dump ...")
        try:
            _materialize_iat_input(
                process_controller, image_base, effective_iat_addr,
                effective_iat_size, effective_add_new_iat, TMP_FILE_PATH1,
                TMP_FILE_PATH2)
        except pyscylla.ScyllaException as scylla_exception:
            # A native reconstruction failure should not destroy an otherwise
            # useful raw dump. Keep the original directories as a fallback
            # and make the strategy explicit in diagnostics.
            LOG.warning("Failed to fix the discovered IAT: %s; preserving "
                        "the unmodified memory dump", str(scylla_exception))
            shutil.copyfile(TMP_FILE_PATH1, TMP_FILE_PATH2)
            effective_iat_addr = 0
            effective_iat_size = 0
            iat_strategy = "preserved_after_iat_failure"

        if pristine_ranges:
            runtime_state_restoration = _restore_pristine_ranges_in_dump(
                TMP_FILE_PATH2, image_base, pristine_ranges,
                preserved_patch_ranges or [])
        neutralized_vm_state_guards = _neutralize_stale_vm_pointer_guards(
            TMP_FILE_PATH2)

        # All remaining operations are file-only.  Keeping a heavily packed
        # GUI target alive while Scylla and LIEF rebuild the dump wastes CPU,
        # lets it spawn children, and makes a slow rebuild look like a target
        # wait.  Cleanup remains idempotent in application.run_unlicense().
        LOG.info("Live-memory capture complete; terminating target before "
                 "file reconstruction")
        try:
            process_controller.terminate_process()
        except Exception as error:
            # The outer application cleanup retries this operation.  A target
            # teardown failure must not discard a successfully captured dump.
            LOG.warning("Could not terminate the target before file "
                        "reconstruction: %s", error)

        try:
            pyscylla.rebuild_pe(TMP_FILE_PATH2, False, True, False)
        except pyscylla.ScyllaException as scylla_exception:
            LOG.error("Failed to rebuild PE: %s", str(scylla_exception))
            return False

        LOG.info("Rebuilding PE ...")
        output_file_name = output_file_path or \
            f"unpacked_{process_controller.main_module_name}"
        _fix_pe(TMP_FILE_PATH2, output_file_name, pe_file_path)

        validation = _validate_dump(
            output_file_name, pe_file_path, oep - image_base,
            effective_iat_size // max(1, process_controller.pointer_size))
        validation["iat_reconstruction_strategy"] = iat_strategy
        validation["runtime_iat_address"] = hex(effective_iat_addr)
        validation["runtime_iat_size"] = effective_iat_size
        validation["runtime_state_restoration"] = runtime_state_restoration
        validation["neutralized_vm_state_guards"] = [
            hex(rva) for rva in neutralized_vm_state_guards
        ]
        validation_path = f"{output_file_name}.validation.json"
        try:
            with open(validation_path, "w", encoding="utf-8") as report_file:
                json.dump(validation, report_file, indent=2)
            LOG.info("Dump validation report saved at '%s'", validation_path)
        except OSError as error:
            LOG.warning("Failed to save dump validation report: %s", error)
        for issue in validation["issues"]:
            LOG.warning("Dump validation: %s", issue)

        if not validation["valid"]:
            LOG.error("Output file '%s' failed structural validation",
                      output_file_name)
            return False
        LOG.info("Output file has been validated and saved at '%s'",
                 output_file_name)

    return True


def dump_dotnet_assembly(
    process_controller: ProcessController,
    image_base: int,
    output_file_path: Optional[str] = None,
) -> bool:
    output_file_name = output_file_path or \
        f"unpacked_{process_controller.main_module_name}"
    try:
        pyscylla.dump_pe(process_controller.pid, image_base, image_base,
                         output_file_name, None)
    except pyscylla.ScyllaException as scylla_exception:
        LOG.error("Failed to dump PE: %s", str(scylla_exception))
        return False

    LOG.info("Output file has been saved at '%s'", output_file_name)

    return True


def _fix_pe(pe_file_path: str, output_file_path: str,
            original_file_path: str) -> None:
    with TemporaryDirectory() as tmp_dir:
        TMP_FILE_PATH = os.path.join(tmp_dir, "unlicense.tmp")
        _rebuild_pe(pe_file_path, TMP_FILE_PATH)
        _resize_pe(TMP_FILE_PATH, output_file_path, original_file_path)


def _rebuild_pe(pe_file_path: str, output_file_path: str) -> None:
    binary = lief.PE.parse(pe_file_path)
    if binary is None:
        LOG.error("Failed to parse PE '%s'", pe_file_path)
        return

    # Rename sections
    _resolve_section_names(binary)

    # Disable ASLR
    binary.header.add_characteristic(
        lief.PE.HEADER_CHARACTERISTICS.RELOCS_STRIPPED)
    binary.optional_header.remove(lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE)
    # Rebuild PE
    builder = lief.PE.Builder(binary)
    builder.build_dos_stub(True)
    builder.build_overlay(True)
    builder.build()
    builder.write(output_file_path)


def _resolve_section_names(binary: lief.PE.Binary) -> None:
    for data_dir in lief_pe_data_directories(binary):
        if data_dir.type == lief.PE.DATA_DIRECTORY.RESOURCE_TABLE and \
           data_dir.section is not None:
            LOG.debug(".rsrc section found (RVA=%s)",
                      hex(data_dir.section.virtual_address))
            data_dir.section.name = ".rsrc"

    ep_address = binary.optional_header.addressof_entrypoint
    for section in lief_pe_sections(binary):
        if section.virtual_address + section.virtual_size > ep_address >= section.virtual_address:
            LOG.debug(".text section found (RVA=%s)",
                      hex(section.virtual_address))
            section.name = ".text"


def _resize_pe(pe_file_path: str, output_file_path: str,
               original_file_path: str) -> None:
    pe_size = _get_pe_size(pe_file_path)
    if pe_size is None:
        return None

    # LIEF may leave bytes beyond the rebuilt sections. Trim those bytes, then
    # preserve the original overlay explicitly. Bundled applications often
    # store embedded DLLs or payload metadata there; the old implementation
    # unconditionally discarded it after asking LIEF to preserve overlays.
    shutil.copy(pe_file_path, output_file_path)
    with open(output_file_path, "ab") as pe_file:
        pe_file.truncate(pe_size)

    original_pe_size = _get_pe_size(original_file_path)
    if original_pe_size is None:
        return None
    original_file_size = os.path.getsize(original_file_path)
    overlay_size = max(0, original_file_size - original_pe_size)
    if overlay_size == 0:
        return None

    with open(original_file_path, "rb") as original_file, \
            open(output_file_path, "ab") as output_file:
        original_file.seek(original_pe_size)
        shutil.copyfileobj(original_file, output_file, 1024 * 1024)
    LOG.info("Preserved %d overlay bytes from bundled input", overlay_size)


def _get_pe_size(pe_file_path: str) -> Optional[int]:
    binary = lief.PE.parse(pe_file_path)
    if binary is None:
        LOG.error("Failed to parse PE '%s'", pe_file_path)
        return None

    return _get_binary_size(binary)


def _get_binary_size(binary: lief.PE.Binary) -> Optional[int]:
    number_of_sections = len(binary.sections)
    if number_of_sections == 0:
        # Shouldn't happen but hey
        return None

    # Determine the actual PE raw size
    highest_section = binary.sections[0]
    for section in lief_pe_sections(binary):
        # Select section with the highest offset
        if section.offset > highest_section.offset:
            highest_section = section
        # If sections have the same offset, select the one with the biggest size
        elif section.offset == highest_section.offset and section.size > highest_section.size:
            highest_section = section
    pe_size = highest_section.offset + highest_section.size

    return pe_size


def _validate_dump(output_file_path: str, original_file_path: str,
                   expected_oep_rva: int,
                   expected_import_count: int) -> Dict[str, Any]:
    issues: List[str] = []
    report: Dict[str, Any] = {
        "format_version": 1,
        "output": output_file_path,
        "expected_oep_rva": hex(expected_oep_rva),
        "expected_import_count": expected_import_count,
        "issues": issues,
    }
    try:
        output = lief.PE.parse(output_file_path)
        if output is None:
            issues.append("rebuilt output cannot be parsed as a PE")
            report["valid"] = False
            return report

        actual_oep = int(output.optional_header.addressof_entrypoint)
        report["actual_oep_rva"] = hex(actual_oep)
        if actual_oep != expected_oep_rva:
            issues.append(
                f"entry point mismatch: expected {hex(expected_oep_rva)}, "
                f"found {hex(actual_oep)}")

        entry_section = None
        sections = []
        for section in lief_pe_sections(output):
            section_info = {
                "name":
                section.fullname.replace("\x00", ""),
                "rva":
                hex(int(section.virtual_address)),
                "virtual_size":
                hex(int(section.virtual_size)),
                "raw_offset":
                hex(int(section.offset)),
                "raw_size":
                hex(int(section.size)),
                "executable":
                bool(
                    section.has_characteristic(
                        lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE)),
            }
            sections.append(section_info)
            span = max(int(section.virtual_size), int(section.size), 1)
            if (int(section.virtual_address) <= actual_oep <
                    int(section.virtual_address) + span):
                entry_section = section_info
        report["sections"] = sections
        report["entry_section"] = entry_section
        if entry_section is None:
            issues.append("entry point is not contained in any output section")
        elif not entry_section["executable"]:
            issues.append("entry point section is not executable")

        # Iterating LIEF's reconstructed import objects can take minutes on
        # large packed/PyInstaller images. Directory presence is the bounded
        # structural check needed here; Scylla already validates individual
        # entries while rebuilding the IAT.
        output_directories = list(lief_pe_data_directories(output))
        import_directory = next(
            (directory for directory in output_directories
             if directory.type == lief.PE.DATA_DIRECTORY.IMPORT_TABLE), None)
        iat_directory = next((directory for directory in output_directories
                              if directory.type == lief.PE.DATA_DIRECTORY.IAT),
                             None)
        report["import_directory_rva"] = hex(int(
            import_directory.rva)) if import_directory is not None else None
        report["import_directory_size"] = (int(import_directory.size) if
                                           import_directory is not None else 0)
        report["iat_directory_rva"] = hex(int(
            iat_directory.rva)) if iat_directory is not None else None
        report["iat_directory_size"] = (int(iat_directory.size)
                                        if iat_directory is not None else 0)
        if (expected_import_count > 0
                and (import_directory is None or int(import_directory.rva) == 0
                     or int(import_directory.size) == 0)):
            issues.append("rebuilt output has no import directory")

        output_has_resources = any(
            directory.type == lief.PE.DATA_DIRECTORY.RESOURCE_TABLE
            and int(directory.rva) != 0 for directory in output_directories)
        report["output_has_resources"] = output_has_resources

        # Do not parse the output again while retaining its LIEF object. Large
        # 32-bit bundles can otherwise exhaust the address space and make this
        # post-dump check appear to hang indefinitely.
        output_structural_size = _get_binary_size(output)
        output_file_size = os.path.getsize(output_file_path)
        report["file_size"] = output_file_size
        report["overlay_size"] = (0 if output_structural_size is None else max(
            0, output_file_size - output_structural_size))

        del output
        gc.collect()

        original = lief.PE.parse(original_file_path)
        if original is not None:
            original_has_resources = any(
                directory.type == lief.PE.DATA_DIRECTORY.RESOURCE_TABLE
                and int(directory.rva) != 0
                for directory in lief_pe_data_directories(original))
            report["original_has_resources"] = original_has_resources
            if original_has_resources and not output_has_resources:
                issues.append("resource directory was lost during rebuilding")
            original_structural_size = _get_binary_size(original)
            original_file_size = os.path.getsize(original_file_path)
            original_overlay_size = (0 if original_structural_size is None else
                                     max(
                                         0, original_file_size -
                                         original_structural_size))
            report["original_overlay_size"] = original_overlay_size
            if (original_overlay_size > 0
                    and report["overlay_size"] != original_overlay_size):
                issues.append(
                    "bundle overlay size changed during rebuilding: expected "
                    f"{original_overlay_size}, found {report['overlay_size']}")
    except Exception as error:
        issues.append(f"validation failed: {error}")

    report["valid"] = len(issues) == 0
    return report


def pointer_size_to_fmt(pointer_size: int) -> str:
    if pointer_size == 4:
        return "<I"
    if pointer_size == 8:
        return "<Q"
    raise NotImplementedError("Platform not supported")


def interpreter_can_dump_pe(pe_file_path: str) -> bool:
    current_platform = platform.machine()
    binary = lief.parse(pe_file_path)
    pe_architecture = binary.header.machine

    # 64-bit OS on x86
    if current_platform == "AMD64":
        bitness = struct.calcsize("P") * 8
        if bitness == 64:
            # Only 64-bit PEs are supported
            return bool(pe_architecture == lief.PE.MACHINE_TYPES.AMD64)
        if bitness == 32:
            # Only 32-bit PEs are supported
            return bool(pe_architecture == lief.PE.MACHINE_TYPES.I386)
        return False

    # 32-bit OS on x86
    if current_platform == "x86":
        # Only 32-bit PEs are supported
        return bool(pe_architecture == lief.PE.MACHINE_TYPES.I386)

    return False
