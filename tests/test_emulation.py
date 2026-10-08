import json
import struct
import tempfile
import threading
import unittest
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import Mock, patch

from unicorn import (  # type: ignore
    Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_ERR_MAP)
from capstone import Cs, CS_ARCH_X86, CS_MODE_32  # type: ignore

from unlicense.application import (_create_primary_process,
                                   _create_probe_process,
                                   _wait_for_event_with_progress)
from unlicense.dump_utils import _resize_pe
from unlicense.emulation import resolve_wrapped_api, _allocate_emulated_heap
from unlicense.frida_exec import _call_with_timeout
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
        self.trace_results_by_profile: Dict[str, Dict[int, int]] = {}
        self.trace_stats_by_profile: Dict[str, Dict[str, Any]] = {}
        self.trace_timeout = 0
        self.active_probe = False
        self.active_probe_timeout = 0
        self.active_probe_profiles: List[str] = []
        self.trace_wrappers: List[Dict[str, Any]] = []
        self.trace_error: Optional[Exception] = None
        self.trace_call_count = 0
        self.terminate_count = 0
        self.module_addresses: Dict[int, Dict[str, Any]] = {}
        self.module_names: Dict[str, Dict[str, Any]] = {}
        self.adopted_oep: Optional[int] = None

    def find_module_by_address(self, address: int) -> Optional[Dict[str, Any]]:
        return self.module_addresses.get(address)

    def find_module_by_name(self,
                            module_name: str) -> Optional[Dict[str, Any]]:
        return self.module_names.get(module_name.lower())

    def adopt_ready_target(self, oep: int) -> None:
        self.adopted_oep = oep

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
        for address, export in self.exports.items():
            if (str(export.get("module", "")).lower() == module_name.lower()
                    and export.get("name") == export_name):
                return address
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

    def trace_wrapped_imports(
            self,
            wrappers: List[Dict[str, Any]],
            timeout_ms: int,
            active_probe: bool = False,
            active_probe_timeout_ms: int = 5000,
            active_probe_profile: str = "zero") -> Dict[int, int]:
        self.trace_wrappers = wrappers
        self.trace_call_count += 1
        self.trace_timeout = timeout_ms
        self.active_probe = active_probe
        self.active_probe_timeout = active_probe_timeout_ms
        self.active_probe_profiles.append(active_probe_profile)
        self.last_wrapper_trace_stats = self.trace_stats_by_profile.get(
            active_probe_profile, {
                "activeProbes": 1 if active_probe else 0,
            })
        if self.trace_error is not None:
            raise self.trace_error
        return self.trace_results_by_profile.get(active_probe_profile,
                                                 self.trace_results)

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
        self.terminate_count += 1


def _relative_branch(opcode: int, instruction_address: int,
                     destination: int) -> bytes:
    displacement = destination - (instruction_address + 5)
    return bytes([opcode]) + struct.pack("<i", displacement)


class HeapWrapperEmulationTests(unittest.TestCase):

    def test_blocking_frida_rpc_has_host_side_deadline(self) -> None:
        release = threading.Event()
        try:
            with self.assertRaisesRegex(TimeoutError,
                                        "test RPC timed out after 1 ms"):
                _call_with_timeout(lambda: release.wait(), 1, "test RPC")
        finally:
            release.set()

    def test_oep_wait_uses_full_budget_and_reports_timeout(self) -> None:
        reached = threading.Event()
        self.assertFalse(
            _wait_for_event_with_progress(reached, 0.01, "test target", 0.005))
        reached.set()
        self.assertTrue(
            _wait_for_event_with_progress(reached, 0.01, "test target", 0.005))

    def test_sacrificial_startup_retries_with_isolated_callbacks(self) -> None:
        first = FakeProcessController({}, {})
        second = FakeProcessController({}, {})
        launches = 0
        rearm_modes: List[bool] = []

        def spawn(
                _path: Path,
                _ranges: List[MemoryRange],
                callback: Any,
                _timeout_ms: int,
                post_protect_oep_rearm: bool = False) -> FakeProcessController:
            nonlocal launches
            launches += 1
            rearm_modes.append(post_protect_oep_rearm)
            if launches == 1:
                return first
            callback(0x500000, 0x501000, False)
            return second

        with patch("unlicense.application.frida_exec.spawn_and_instrument",
                   side_effect=spawn):
            controller, image_base = _create_probe_process(
                Path("fixture.exe"), [MemoryRange(0x1000, 0x1000, "r-x")], 0.0,
                1000, 1)

        self.assertIs(second, controller)
        self.assertEqual(0x500000, image_base)
        self.assertEqual(1, first.terminate_count)
        self.assertEqual(0, second.terminate_count)
        self.assertEqual([True, True], rearm_modes)

    def test_primary_startup_retries_after_first_oep_miss(self) -> None:
        first = FakeProcessController({}, {})
        second = FakeProcessController({}, {})
        launches = 0

        def spawn(
                _path: Path,
                _ranges: List[MemoryRange],
                callback: Any,
                _timeout_ms: int = 15000,
                post_protect_oep_rearm: bool = False) -> FakeProcessController:
            nonlocal launches
            self.assertFalse(post_protect_oep_rearm)
            launches += 1
            if launches == 1:
                return first
            callback(0x400000, 0xd54c3f, False)
            return second

        with patch("unlicense.application.frida_exec.spawn_and_instrument",
                   side_effect=spawn):
            controller, image_base, oep, dotnet = _create_primary_process(
                Path("fixture.exe"), [MemoryRange(0x1000, 0x1000, "r-x")], 0.0,
                1)

        self.assertIs(second, controller)
        self.assertEqual(0x400000, image_base)
        self.assertEqual(0xd54c3f, oep)
        self.assertFalse(dotnet)
        self.assertEqual(1, first.terminate_count)
        self.assertEqual(0, second.terminate_count)

    def test_sacrificial_target_can_adopt_verified_unpacked_oep(self) -> None:
        image_base = 0x500000
        oep_rva = 0x1000
        signature = bytes.fromhex("558bec83ec105356")
        page = signature + bytes(0x1000 - len(signature))
        controller = FakeProcessController({image_base + oep_rva: page}, {})
        controller.module_names["fixture.exe"] = {
            "name": "fixture.exe",
            "base": hex(image_base),
        }

        def spawn(
                _path: Path,
                _ranges: List[MemoryRange],
                _callback: Any,
                _timeout_ms: int,
                post_protect_oep_rearm: bool = False) -> FakeProcessController:
            self.assertTrue(post_protect_oep_rearm)
            return controller

        with patch("unlicense.application.frida_exec.spawn_and_instrument",
                   side_effect=spawn):
            result, detected_base = _create_probe_process(
                Path("fixture.exe"), [MemoryRange(0x1000, 0x1000, "r-x")],
                0.01, 1000, 0, oep_rva, signature)

        self.assertIs(controller, result)
        self.assertEqual(image_base, detected_base)
        self.assertEqual(image_base + oep_rva, controller.adopted_oep)
        self.assertEqual(0, controller.terminate_count)

    def test_rebuilt_pe_preserves_original_bundle_overlay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rebuilt = root / "rebuilt.exe"
            original = root / "original.exe"
            output = root / "output.exe"
            rebuilt.write_bytes(b"R" * 80 + b"LIEF-GARBAGE")
            original.write_bytes(b"O" * 100 + b"BUNDLED-DLL-DATA")

            def fake_pe_size(path: str) -> int:
                return 80 if Path(path) == rebuilt else 100

            with patch("unlicense.dump_utils._get_pe_size",
                       side_effect=fake_pe_size):
                _resize_pe(str(rebuilt), str(output), str(original))

            self.assertEqual(b"R" * 80 + b"BUNDLED-DLL-DATA",
                             output.read_bytes())

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
                                       250, False)

        self.assertEqual([(call_site, 5, False)], imports[target_api])
        self.assertEqual("native_trace", diagnostics[0]["resolution_method"])
        self.assertEqual(250, controller.trace_timeout)
        self.assertFalse(controller.active_probe)

    def test_active_trace_uses_sacrificial_process_and_translates_export(
            self) -> None:
        image_base = 0x400000
        probe_image_base = 0x500000
        call_site = 0x401000
        wrapper = 0x402000
        probe_call_site = 0x501000
        probe_wrapper = 0x602000
        main_api = 0x76002000
        probe_api = 0x77003000

        main_call_page = bytearray(0x1000)
        main_call_page[0:5] = _relative_branch(0xe8, call_site, wrapper)
        main_controller = FakeProcessController(
            {
                call_site: bytes(main_call_page),
                wrapper: bytes([0xcc]) + bytes(0xfff),
            }, {main_api: {
                "name": "TargetApi",
                "module": "kernel32.dll",
            }})

        probe_call_page = bytearray(0x1000)
        probe_call_page[0:5] = _relative_branch(0xe8, probe_call_site,
                                                probe_wrapper)
        probe_controller = FakeProcessController(
            {probe_call_site: bytes(probe_call_page)},
            {probe_api: {
                "name": "TargetApi",
                "module": "kernel32.dll",
            }})
        probe_controller.trace_results = {probe_call_site: probe_api}

        imports: ImportToCallSiteDict = defaultdict(list)
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True
        diagnostics = _resolve_imports(
            imports, {(call_site, 5, False, wrapper, None)}, None,
            main_controller.exports, disassembler, main_controller, 250, True,
            7000, image_base, lambda: (probe_controller, probe_image_base))

        self.assertEqual([(call_site, 5, False)], imports[main_api])
        self.assertEqual("sacrificial_native_trace",
                         diagnostics[0]["resolution_method"])
        self.assertEqual(hex(probe_call_site),
                         diagnostics[0]["probe_call_address"])
        self.assertEqual(hex(probe_wrapper),
                         diagnostics[0]["probe_wrapper_address"])
        self.assertEqual({"activeProbes": 1},
                         diagnostics[0]["probe_trace_stats"])
        self.assertTrue(probe_controller.active_probe)
        self.assertEqual(7000, probe_controller.active_probe_timeout)
        self.assertFalse(main_controller.active_probe)
        self.assertEqual(0, main_controller.trace_timeout)
        self.assertEqual(1, probe_controller.terminate_count)

    def test_active_trace_retries_with_readable_arguments_after_timeout(
            self) -> None:
        image_base = 0x400000
        probe_image_base = 0x500000
        call_site = 0x401000
        wrapper = 0x402000
        probe_call_site = 0x501000
        probe_wrapper = 0x602000
        main_api = 0x76002000
        probe_api = 0x77003000

        main_page = bytearray(0x1000)
        main_page[0:5] = _relative_branch(0xe8, call_site, wrapper)
        main_controller = FakeProcessController(
            {
                call_site: bytes(main_page),
                wrapper: bytes([0xcc]) + bytes(0xfff),
            }, {main_api: {
                "name": "TargetApi",
                "module": "kernel32.dll",
            }})
        probe_page = bytearray(0x1000)
        probe_page[0:5] = _relative_branch(0xe8, probe_call_site,
                                           probe_wrapper)
        probe_controller = FakeProcessController(
            {probe_call_site: bytes(probe_page)},
            {probe_api: {
                "name": "TargetApi",
                "module": "kernel32.dll",
            }})
        probe_controller.trace_results_by_profile = {
            "zero": {},
            "readable": {
                probe_call_site: probe_api
            },
        }
        probe_controller.trace_stats_by_profile = {
            "zero": {
                "activeProbes": 1,
                "activeProbeReturns": 0,
                "activeProbeErrors": ["probe timed out"],
            },
            "readable": {
                "activeProbes": 1,
                "activeProbeReturns": 1,
                "activeProbeErrors": [],
            },
        }

        imports: ImportToCallSiteDict = defaultdict(list)
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True
        diagnostics = _resolve_imports(
            imports, {(call_site, 5, False, wrapper, None)}, None,
            main_controller.exports, disassembler, main_controller, 0, True,
            5000, image_base, lambda: (probe_controller, probe_image_base))

        self.assertEqual([(call_site, 5, False)], imports[main_api])
        self.assertEqual(["zero", "readable"],
                         probe_controller.active_probe_profiles)
        self.assertEqual(2, len(diagnostics[0]["probe_attempts"]))
        self.assertNotIn("probe_error", diagnostics[0])

    def test_active_trace_restarts_probe_after_sacrificial_crash(self) -> None:
        image_base = 0x400000
        probe_image_base = 0x500000
        first_call = 0x401000
        second_call = 0x403000
        first_wrapper = 0x402000
        second_wrapper = 0x404000
        first_probe_call = 0x501000
        second_probe_call = 0x503000
        first_probe_wrapper = 0x602000
        second_probe_wrapper = 0x604000
        main_api = 0x76002000
        probe_api = 0x77003000

        main_pages = {}
        for call, wrapper in ((first_call, first_wrapper), (second_call,
                                                            second_wrapper)):
            call_page = bytearray(0x1000)
            call_page[0:5] = _relative_branch(0xe8, call, wrapper)
            main_pages[call] = bytes(call_page)
            main_pages[wrapper] = bytes([0xcc]) + bytes(0xfff)
        main_controller = FakeProcessController(
            main_pages,
            {main_api: {
                "name": "TargetApi",
                "module": "kernel32.dll",
            }})

        failed_call_page = bytearray(0x1000)
        failed_call_page[0:5] = _relative_branch(0xe8, first_probe_call,
                                                 first_probe_wrapper)
        failed_probe = FakeProcessController(
            {first_probe_call: bytes(failed_call_page)}, {})
        failed_probe.trace_error = RuntimeError("probe process exited")

        successful_call_page = bytearray(0x1000)
        successful_call_page[0:5] = _relative_branch(0xe8, second_probe_call,
                                                     second_probe_wrapper)
        successful_probe = FakeProcessController(
            {second_probe_call: bytes(successful_call_page)},
            {probe_api: {
                "name": "TargetApi",
                "module": "kernel32.dll",
            }})
        successful_probe.trace_results = {second_probe_call: probe_api}
        probes = iter((failed_probe, successful_probe))

        imports: ImportToCallSiteDict = defaultdict(list)
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True
        diagnostics = _resolve_imports(
            imports, {(first_call, 5, False, first_wrapper, None),
                      (second_call, 5, False, second_wrapper, None)}, None,
            main_controller.exports, disassembler, main_controller, 0, True,
            5000, image_base, lambda: (next(probes), probe_image_base))

        self.assertEqual([(second_call, 5, False)], imports[main_api])
        self.assertEqual("unresolved", diagnostics[0]["resolution_method"])
        self.assertEqual("probe process exited", diagnostics[0]["probe_error"])
        self.assertEqual("sacrificial_native_trace",
                         diagnostics[1]["resolution_method"])
        self.assertEqual(1, failed_probe.terminate_count)
        self.assertEqual(1, successful_probe.terminate_count)
        self.assertEqual(0, main_controller.terminate_count)

    def test_active_trace_reuses_live_sacrificial_process(self) -> None:
        image_base = 0x400000
        probe_image_base = 0x500000
        first_call = 0x401000
        second_call = 0x403000
        first_wrapper = 0x402000
        second_wrapper = 0x404000
        first_probe_call = 0x501000
        second_probe_call = 0x503000
        first_probe_wrapper = 0x602000
        second_probe_wrapper = 0x604000
        main_apis = (0x76002000, 0x76004000)
        probe_apis = (0x77003000, 0x77005000)

        main_pages = {}
        probe_pages = {}
        for main_call, main_wrapper, probe_call, probe_wrapper in (
            (first_call, first_wrapper, first_probe_call, first_probe_wrapper),
            (second_call, second_wrapper, second_probe_call,
             second_probe_wrapper),
        ):
            main_page = bytearray(0x1000)
            main_page[0:5] = _relative_branch(0xe8, main_call, main_wrapper)
            main_pages[main_call] = bytes(main_page)
            main_pages[main_wrapper] = bytes([0xcc]) + bytes(0xfff)
            probe_page = bytearray(0x1000)
            probe_page[0:5] = _relative_branch(0xe8, probe_call, probe_wrapper)
            probe_pages[probe_call] = bytes(probe_page)

        main_controller = FakeProcessController(
            main_pages, {
                main_apis[0]: {
                    "name": "FirstApi",
                    "module": "kernel32.dll",
                },
                main_apis[1]: {
                    "name": "SecondApi",
                    "module": "kernel32.dll",
                },
            })
        probe_controller = FakeProcessController(
            probe_pages, {
                probe_apis[0]: {
                    "name": "FirstApi",
                    "module": "kernel32.dll",
                },
                probe_apis[1]: {
                    "name": "SecondApi",
                    "module": "kernel32.dll",
                },
            })
        probe_controller.trace_results = {
            first_probe_call: probe_apis[0],
            second_probe_call: probe_apis[1],
        }
        factory_calls = 0

        def create_probe() -> Tuple[FakeProcessController, int]:
            nonlocal factory_calls
            factory_calls += 1
            return probe_controller, probe_image_base

        imports: ImportToCallSiteDict = defaultdict(list)
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True
        _resolve_imports(
            imports, {(first_call, 5, False, first_wrapper, None),
                      (second_call, 5, False, second_wrapper, None)}, None,
            main_controller.exports, disassembler, main_controller, 0, True,
            5000, image_base, create_probe)

        self.assertEqual([(first_call, 5, False)], imports[main_apis[0]])
        self.assertEqual([(second_call, 5, False)], imports[main_apis[1]])
        self.assertEqual(1, factory_calls)
        self.assertEqual(2, probe_controller.trace_call_count)
        self.assertEqual(1, probe_controller.terminate_count)

    def test_internal_tail_call_is_not_treated_as_unresolved_import(
            self) -> None:
        call_site = 0x1000
        wrapper = 0x2000
        call_page = bytearray(0x1000)
        call_page[0] = 0x90
        call_page[1:6] = _relative_branch(0xe9, call_site + 1, wrapper)
        wrapper_page = bytes([0xc3]) + bytes(0xfff)
        controller = FakeProcessController(
            {
                call_site: bytes(call_page),
                wrapper: wrapper_page,
            }, {})
        controller.module_addresses[wrapper] = {
            "name": "fixture.exe",
            "base": "0x1000",
            "size": 0x2000,
        }

        imports: ImportToCallSiteDict = defaultdict(list)
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True
        diagnostics = _resolve_imports(imports,
                                       {(call_site, 5, True, wrapper, None)},
                                       None, {}, disassembler, controller)

        self.assertEqual({}, imports)
        self.assertEqual("internal_call", diagnostics[0]["resolution_method"])
        self.assertTrue(diagnostics[0]["emulation"]["returned_without_export"])

    def test_external_code_target_is_not_rewritten_on_hash_collision(
            self) -> None:
        call_site = 0x401000
        external_target = 0x76001234
        unrelated_api = 0x77005678
        call_page = bytearray(0x1000)
        call_page[0:5] = _relative_branch(0xe8, call_site, external_target)
        controller = FakeProcessController(
            {call_site: bytes(call_page)},
            {unrelated_api: {
                "name": "UnrelatedApi",
                "module": "other.dll",
            }})
        controller.module_addresses[external_target] = {
            "name": "msvcrt.dll",
            "base": "0x76000000",
            "size": 0x100000,
        }
        imports: ImportToCallSiteDict = defaultdict(list)
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True

        with patch("unlicense.winlicense2.compute_function_hash") as hasher:
            hasher.return_value = 0x12345678
            diagnostics = _resolve_imports(
                imports, {(call_site, 5, False, external_target, None)},
                {0x12345678: unrelated_api}, controller.exports, disassembler,
                controller)

        self.assertEqual({}, imports)
        self.assertEqual("external_code_target",
                         diagnostics[0]["resolution_method"])
        hasher.assert_not_called()

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
