import json
import struct
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import Mock, patch

from unicorn import (  # type: ignore
    Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_ERR_MAP)
from capstone import Cs, CS_ARCH_X86, CS_MODE_32  # type: ignore

from unlicense.emulation import resolve_wrapped_api, _allocate_emulated_heap
from unlicense.imports import ImportToCallSiteDict
from unlicense.process_control import (Architecture, MemoryRange,
                                       ProcessController,
                                       ReadProcessMemoryError)
from unlicense.winlicense2 import _resolve_imports, _write_diagnostic_report


class FakeProcessController(ProcessController):

    def __init__(self, pages: Dict[int, bytes], exports: Dict[int, Dict[str,
                                                                        Any]]):
        super().__init__(1, "fixture.exe", Architecture.X86_32, 4, 0x1000)
        self.pages = pages
        self.exports = exports
        self.trace_results: Dict[int, int] = {}
        self.trace_timeout = 0
        self.active_probe = False

    def find_module_by_address(self, address: int) -> Optional[Dict[str, Any]]:
        return None

    def find_range_by_address(
            self,
            address: int,
            include_data: bool = False) -> Optional[MemoryRange]:
        page_base = address - address % self.page_size
        page = self.pages.get(page_base)
        if page is None:
            return None
        return MemoryRange(page_base, len(page), "r-x",
                           page if include_data else None)

    def find_export_by_name(self, module_name: str,
                            export_name: str) -> Optional[int]:
        return None

    def enumerate_modules(self) -> List[str]:
        return ["fixture.exe", "ntdll.dll", "kernel32.dll"]

    def enumerate_module_ranges(
            self,
            module_name: str,
            include_data: bool = False) -> List[MemoryRange]:
        return []

    def enumerate_exported_functions(self,
                                     update_cache: bool = False
                                     ) -> Dict[int, Dict[str, Any]]:
        return self.exports

    def trace_wrapped_imports(self,
                              wrappers: List[Dict[str, Any]],
                              timeout_ms: int,
                              active_probe: bool = False) -> Dict[int, int]:
        del wrappers
        self.trace_timeout = timeout_ms
        self.active_probe = active_probe
        return self.trace_results

    def allocate_process_memory(self, size: int, near: int) -> int:
        raise NotImplementedError

    def query_memory_protection(self, address: int) -> str:
        raise NotImplementedError

    def set_memory_protection(self, address: int, size: int,
                              protection: str) -> bool:
        raise NotImplementedError

    def read_process_memory(self, address: int, size: int) -> bytes:
        page_base = address - address % self.page_size
        page = self.pages.get(page_base)
        page_offset = address - page_base
        if page is None or page_offset + size > len(page):
            raise ReadProcessMemoryError
        return page[page_offset:page_offset + size]

    def write_process_memory(self, address: int, data: List[int]) -> None:
        raise NotImplementedError

    def terminate_process(self) -> None:
        return None


def _relative_branch(opcode: int, instruction_address: int,
                     destination: int) -> bytes:
    displacement = destination - (instruction_address + 5)
    return bytes([opcode]) + struct.pack("<i", displacement)


class HeapWrapperEmulationTests(unittest.TestCase):

    def test_native_trace_result_resolves_exception_wrapper(self) -> None:
        call_site = 0x401000
        wrapper = 0x402000
        target_api = 0x77003000
        call_page = bytearray(0x1000)
        call_page[0:5] = _relative_branch(0xe8, call_site, wrapper)
        pages = {
            call_site: bytes(call_page),
            wrapper: bytes([0xcc]) + bytes(0xfff),
        }
        exports = {target_api: {"name": "TargetApi"}}
        controller = FakeProcessController(pages, exports)
        controller.trace_results = {call_site: target_api}
        imports: ImportToCallSiteDict = defaultdict(list)
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True

        diagnostics = _resolve_imports(imports,
                                       {(call_site, 5, False, wrapper, None)},
                                       None, exports, disassembler, controller,
                                       250, True)

        self.assertEqual([(call_site, 5, False)], imports[target_api])
        self.assertEqual("native_trace", diagnostics[0]["resolution_method"])
        self.assertEqual(250, controller.trace_timeout)
        self.assertTrue(controller.active_probe)

    def test_synthetic_heap_search_is_bounded(self) -> None:
        controller = FakeProcessController({}, {})
        unicorn_mock = Mock()
        unicorn_mock.mem_map.side_effect = UcError(UC_ERR_MAP)
        context: Dict[str, Any] = {
            "process_controller": controller,
            "heap_next": 0x30000000,
            "heap_allocations": {},
            "diagnostic": {},
        }

        with self.assertRaisesRegex(RuntimeError, "bounded synthetic heap"):
            _allocate_emulated_heap(unicorn_mock, 0x20, context)
        self.assertIn("heap_error", context["diagnostic"])
        self.assertEqual(256, unicorn_mock.mem_map.call_count)

    def test_emulation_instruction_limit_returns_unresolved(self) -> None:
        call_site = 0x401000
        looping_page = bytearray(0x1000)
        looping_page[0:2] = b"\xeb\xfe"
        controller = FakeProcessController({call_site: bytes(looping_page)},
                                           {})
        diagnostic: Dict[str, Any] = {}

        with patch("unlicense.emulation.MAX_EMULATION_INSTRUCTIONS", 100):
            resolved = resolve_wrapped_api(call_site, controller, None,
                                           diagnostic)

        self.assertIsNone(resolved)
        self.assertIn("stopped before reaching", diagnostic["error"])

    def test_int3_wrapper_stops_with_diagnostic(self) -> None:
        call_site = 0x401000
        interrupt_page = bytes([0xcc]) + bytes(0xfff)
        controller = FakeProcessController({call_site: interrupt_page}, {})
        diagnostic: Dict[str, Any] = {}

        resolved = resolve_wrapped_api(call_site, controller, None, diagnostic)

        self.assertIsNone(resolved)
        self.assertEqual(3, diagnostic["interrupt"]["number"])
        self.assertIn("requires native handling", diagnostic["error"])

    def test_cleanup_apis_are_simulated_before_target_api(self) -> None:
        call_site = 0x401000
        wrapper = 0x402000
        free_unicode_string = 0x77001000
        delete_boundary_descriptor = 0x77002000
        target_api = 0x77003000

        call_page = bytearray(0x1000)
        call_page[0:5] = _relative_branch(0xe8, call_site, wrapper)

        wrapper_page = bytearray(0x1000)
        wrapper_code = bytearray(b"\x6a\x00")
        free_call = wrapper + len(wrapper_code)
        wrapper_code += _relative_branch(0xe8, free_call, free_unicode_string)
        wrapper_code += b"\x6a\x00"
        delete_call = wrapper + len(wrapper_code)
        wrapper_code += _relative_branch(0xe8, delete_call,
                                         delete_boundary_descriptor)
        target_jump = wrapper + len(wrapper_code)
        wrapper_code += _relative_branch(0xe9, target_jump, target_api)
        wrapper_page[0:len(wrapper_code)] = wrapper_code

        pages = {
            call_site: bytes(call_page),
            wrapper: bytes(wrapper_page),
            free_unicode_string: bytes([0xc3]) + bytes(0xfff),
            delete_boundary_descriptor: bytes([0xc3]) + bytes(0xfff),
            target_api: bytes([0xc3]) + bytes(0xfff),
        }
        exports = {
            free_unicode_string: {
                "name": "RtlFreeUnicodeString",
            },
            delete_boundary_descriptor: {
                "name": "RtlDeleteBoundaryDescriptor",
            },
            target_api: {
                "name": "TargetApi",
            },
        }
        diagnostic: Dict[str, Any] = {}

        resolved = resolve_wrapped_api(call_site,
                                       FakeProcessController(pages, exports),
                                       call_site + 5, diagnostic)

        self.assertEqual(target_api, resolved)
        self.assertEqual(
            ["RtlFreeUnicodeString", "RtlDeleteBoundaryDescriptor"],
            [api["name"] for api in diagnostic["simulated_apis"]])

    def test_rtl_allocate_heap_is_simulated_before_target_api(self) -> None:
        call_site = 0x401000
        wrapper = 0x402000
        rtl_allocate_heap = 0x77001000
        target_api = 0x77002000

        call_page = bytearray(0x1000)
        call_page[0:5] = _relative_branch(0xe8, call_site, wrapper)

        wrapper_page = bytearray(0x1000)
        wrapper_code = bytearray()
        wrapper_code += b"\x68\x20\x00\x00\x00"  # push 0x20 (size)
        wrapper_code += b"\x6a\x00"  # push 0 (flags)
        wrapper_code += b"\x6a\x01"  # push 1 (synthetic heap handle)
        heap_call = wrapper + len(wrapper_code)
        wrapper_code += _relative_branch(0xe8, heap_call, rtl_allocate_heap)
        target_jump = wrapper + len(wrapper_code)
        wrapper_code += _relative_branch(0xe9, target_jump, target_api)
        wrapper_page[0:len(wrapper_code)] = wrapper_code

        pages = {
            call_site: bytes(call_page),
            wrapper: bytes(wrapper_page),
            rtl_allocate_heap: bytes([0xc3]) + bytes(0xfff),
            target_api: bytes([0xc3]) + bytes(0xfff),
        }
        exports = {
            rtl_allocate_heap: {
                "name": "RtlAllocateHeap",
                "address": hex(rtl_allocate_heap),
            },
            target_api: {
                "name": "TargetApi",
                "address": hex(target_api),
            },
        }
        controller = FakeProcessController(pages, exports)
        diagnostic: Dict[str, Any] = {}

        resolved = resolve_wrapped_api(call_site, controller, call_site + 5,
                                       diagnostic)

        self.assertEqual(target_api, resolved)
        self.assertNotIn("error", diagnostic)
        self.assertEqual("RtlAllocateHeap",
                         diagnostic["simulated_apis"][0]["name"])
        self.assertEqual(0x20,
                         diagnostic["simulated_apis"][0]["requested_size"])

    def test_compact_diagnostic_report_is_serializable(self) -> None:
        target_api = 0x77002000
        controller = FakeProcessController(
            {},
            {target_api: {
                "name": "TargetApi",
                "address": hex(target_api),
            }})
        calls = {target_api: [(0x401000, 5, False)]}
        wrappers = [{
            "call_address": "0x401000",
            "wrapper_address": "0x402000",
            "wrapper_bytes": "90e900000000",
            "resolved_address": hex(target_api),
        }]

        with tempfile.TemporaryDirectory() as temporary_directory:
            report_path = Path(temporary_directory) / "diagnostic.json"
            _write_diagnostic_report(str(report_path), "fixture.exe", 0x400000,
                                     0x401000,
                                     MemoryRange(0x401000, 0x1000, "r-x"), 0,
                                     calls, wrappers, controller)
            report = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual("fixture.exe", report["target_name"])
        self.assertEqual(1, report["potential_wrapper_count"])
        self.assertEqual("TargetApi",
                         report["resolved_imports"][0]["export"]["name"])


if __name__ == "__main__":
    unittest.main()
