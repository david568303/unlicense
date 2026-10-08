import logging
import os
import re
import shutil
import struct
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .process_control import ProcessController

LOG = logging.getLogger(__name__)

_MAX_HEADER_SIZE = 1024 * 1024
_MAX_IMAGE_SIZE = 256 * 1024 * 1024
_MAX_READ_CHUNK = 4 * 1024 * 1024
_SAFE_DLL_NAME = re.compile(r"^[A-Za-z0-9_. -]{1,128}\.dll$",
                            re.IGNORECASE)


def _read_exact(read_memory: Callable[[int, int], bytes], address: int,
                size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk_size = min(_MAX_READ_CHUNK, size - len(result))
        chunk = read_memory(address + len(result), chunk_size)
        if len(chunk) != chunk_size:
            raise ValueError(
                f"short memory read at {hex(address + len(result))}")
        result.extend(chunk)
    return bytes(result)


def _parse_mapped_headers(data: bytes) -> Optional[Dict[str, Any]]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe_offset = struct.unpack_from("<I", data, 0x3c)[0]
    if pe_offset > _MAX_HEADER_SIZE or pe_offset + 24 > len(data):
        return None
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        return None

    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    optional_offset = pe_offset + 24
    section_offset = optional_offset + optional_size
    if (section_count == 0 or section_count > 96 or optional_size < 64
            or section_offset + section_count * 40 > len(data)):
        return None

    magic = struct.unpack_from("<H", data, optional_offset)[0]
    if magic == 0x10b:
        image_base_offset = optional_offset + 28
        image_base_size = 4
    elif magic == 0x20b:
        image_base_offset = optional_offset + 24
        image_base_size = 8
    else:
        return None
    if optional_offset + optional_size > len(data):
        return None

    image_size = struct.unpack_from("<I", data, optional_offset + 56)[0]
    header_size = struct.unpack_from("<I", data, optional_offset + 60)[0]
    entry_point_rva = struct.unpack_from("<I", data,
                                         optional_offset + 16)[0]
    if (image_size < 0x1000 or image_size > _MAX_IMAGE_SIZE
            or header_size < section_offset + section_count * 40
            or header_size > _MAX_HEADER_SIZE):
        return None

    sections = []
    for index in range(section_count):
        section_header = section_offset + index * 40
        name = data[section_header:section_header + 8].split(b"\0", 1)[0]
        virtual_size, virtual_address, raw_size, raw_offset = \
            struct.unpack_from("<IIII", data, section_header + 8)
        if virtual_address >= image_size:
            return None
        sections.append({
            "name": name.decode("ascii", errors="replace"),
            "virtual_size": virtual_size,
            "virtual_address": virtual_address,
            "raw_size": raw_size,
            "raw_offset": raw_offset,
        })

    return {
        "image_size": image_size,
        "header_size": header_size,
        "entry_point_rva": entry_point_rva,
        "image_base_offset": image_base_offset,
        "image_base_size": image_base_size,
        "sections": sections,
    }


def reconstruct_mapped_module(
    read_memory: Callable[[int, int], bytes],
    image_base: int,
) -> Tuple[bytes, Dict[str, Any]]:
    """Reconstruct a DLL file from a module that only remains in memory."""
    initial = _read_exact(read_memory, image_base, 0x1000)
    if len(initial) < 0x40:
        raise ValueError("mapped module header is truncated")
    pe_offset = struct.unpack_from("<I", initial, 0x3c)[0]
    if pe_offset > _MAX_HEADER_SIZE or pe_offset + 24 > len(initial):
        raise ValueError("mapped module has an invalid PE offset")
    section_count = struct.unpack_from("<H", initial, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", initial, pe_offset + 20)[0]
    minimum_headers = pe_offset + 24 + optional_size + section_count * 40
    if minimum_headers > _MAX_HEADER_SIZE:
        raise ValueError("mapped module section table is too large")
    if minimum_headers > len(initial):
        initial = _read_exact(read_memory, image_base, minimum_headers)

    provisional = _parse_mapped_headers(initial)
    if provisional is None:
        raise ValueError("mapped module does not contain a supported PE")
    header_size = int(provisional["header_size"])
    headers = initial[:header_size] if header_size <= len(initial) else \
        _read_exact(read_memory, image_base, header_size)
    metadata = _parse_mapped_headers(headers)
    if metadata is None:
        raise ValueError("mapped module headers are inconsistent")

    file_size = header_size
    for section in metadata["sections"]:
        raw_end = int(section["raw_offset"]) + int(section["raw_size"])
        if raw_end > _MAX_IMAGE_SIZE:
            raise ValueError("mapped module raw layout is too large")
        file_size = max(file_size, raw_end)
    file_data = bytearray(file_size)
    file_data[:len(headers)] = headers

    for section in metadata["sections"]:
        raw_size = int(section["raw_size"])
        if raw_size == 0:
            continue
        virtual_address = int(section["virtual_address"])
        if virtual_address + raw_size > int(metadata["image_size"]):
            raise ValueError(
                f"section {section['name']!r} exceeds mapped image size")
        raw_offset = int(section["raw_offset"])
        section_data = _read_exact(read_memory,
                                   image_base + virtual_address, raw_size)
        file_data[raw_offset:raw_offset + raw_size] = section_data

    # The captured bytes have already been relocated to image_base. Changing
    # the preferred base keeps the relocation delta correct on the next load.
    image_base_format = "<I" if metadata["image_base_size"] == 4 else "<Q"
    struct.pack_into(image_base_format, file_data,
                     int(metadata["image_base_offset"]), image_base)
    return bytes(file_data), metadata


def _same_directory(first: Path, second: Path) -> bool:
    return os.path.normcase(os.path.abspath(str(first))) == \
        os.path.normcase(os.path.abspath(str(second)))


def materialize_loaded_runtime_modules(
    process_controller: ProcessController,
    protected_file_path: str,
    output_file_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Persist local/bundled DLLs while the initialized target is alive."""
    protected_directory = Path(protected_file_path).resolve().parent
    if output_file_path is None:
        output_directory = Path.cwd()
    else:
        output_directory = Path(output_file_path).resolve().parent
    output_directory.mkdir(parents=True, exist_ok=True)

    results: List[Dict[str, Any]] = []
    try:
        module_names = process_controller.enumerate_modules()
    except Exception as error:
        LOG.warning("Could not enumerate initialized runtime modules: %s",
                    error)
        return results

    for module_name in module_names:
        if (module_name.lower() == process_controller.main_module_name.lower()
                or not _SAFE_DLL_NAME.fullmatch(module_name)
                or Path(module_name).name != module_name):
            continue
        try:
            module = process_controller.find_module_by_name(module_name)
        except Exception as error:
            LOG.debug("Could not inspect loaded module '%s': %s", module_name,
                      error)
            continue
        if not isinstance(module, dict):
            continue

        path_value = module.get("path")
        source = Path(path_value) if isinstance(path_value, str) else None
        is_local = source is not None and _same_directory(
            source.parent, protected_directory)
        if not is_local and module_name.lower() != "smartkey.dll":
            continue

        destination = output_directory / module_name
        result: Dict[str, Any] = {
            "module": module_name,
            "source": str(source) if source is not None else None,
            "output": str(destination),
        }
        if destination.exists():
            result["status"] = "already_present"
            results.append(result)
            continue

        try:
            if source is not None and source.is_file():
                if _same_directory(source, destination):
                    result["status"] = "already_present"
                else:
                    shutil.copy2(str(source), str(destination))
                    result["status"] = "copied"
                LOG.info("Preserved initialized runtime module '%s' at '%s'",
                         module_name, destination)
            else:
                base_value = module.get("base")
                if isinstance(base_value, str):
                    module_base = int(base_value, 0)
                elif isinstance(base_value, int):
                    module_base = base_value
                else:
                    raise ValueError("module has no usable base address")
                module_data, metadata = reconstruct_mapped_module(
                    process_controller.read_process_memory, module_base)
                destination.write_bytes(module_data)
                result.update({
                    "status": "reconstructed_from_memory",
                    "base": hex(module_base),
                    "size": len(module_data),
                    "entry_point_rva": hex(
                        int(metadata["entry_point_rva"])),
                })
                LOG.info("Reconstructed bundled runtime module '%s' from %s "
                         "at '%s'", module_name, hex(module_base), destination)
        except Exception as error:
            result.update({"status": "failed", "error": str(error)})
            LOG.warning("Could not preserve runtime module '%s': %s",
                        module_name, error)
        results.append(result)
    return results
