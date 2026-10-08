import json
import os
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
                                   _create_probe_process, _normalize_cli_bool,
                                   _wait_for_event_with_progress)
from unlicense.dump_utils import (dump_pe, _materialize_iat_input,
                                  _overlay_pristine_data,
                                  _patch_stale_vm_pointer_guards, _resize_pe)
from unlicense.emulation import resolve_wrapped_api, _allocate_emulated_heap
from unlicense.frida_exec import (FridaProcessController, _call_with_timeout,
                                  _wrapper_trace_collection_timeout)
from unlicense.function_hashing import (compute_function_hash,
                                        EMPTY_FUNCTION_HASH)
from unlicense.imports import ImportToCallSiteDict, find_wrapped_imports
from unlicense.process_control import (Architecture, MemoryRange,
                                       ProcessController,
                                       ReadProcessMemoryError)
from unlicense.winlicense2 import (_generate_export_hashes,
                                   _generate_new_iat_in_process,
                                   _fix_import_references_in_process,
                                   _find_unhooked_export,
                                   _identify_themida_load_library_wrapper,
                                   _resolve_imports, _write_diagnostic_report)


class FakeProcessController(ProcessController):

    def __init__(self, pages: Dict[int, bytes], exports: Dict[int, Dict[str,
                                                                        Any]]):
        super().__init__(1, "fixture.exe", Architecture.X86_32, 4, 0x1000)
        self.pages = pages
        self.exports = exports
        self.trace_results: Dict[int, int] = {}
        self.trace_observed_imports: List[Dict[str, Any]] = []
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
        self.module_ranges: Dict[str, List[MemoryRange]] = {}
        self.adopted_oep: Optional[int] = None
        self.protections: Dict[int, str] = {}
        self.protection_changes: List[Tuple[int, int, str]] = []
        self.memory_writes: List[Tuple[int, List[int]]] = []

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
        ranges = self.module_ranges.get(module_name.lower(), [])
        if include_data:
            return ranges
        return [
            MemoryRange(memory_range.base, memory_range.size,
                        memory_range.protection) for memory_range in ranges
        ]

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
        self.last_observed_imports = self.trace_observed_imports
        if self.trace_error is not None:
            raise self.trace_error
        return self.trace_results_by_profile.get(active_probe_profile,
                                                 self.trace_results)

    def allocate_process_memory(self, size: int, near: int) -> int:
        raise NotImplementedError

    def query_memory_protection(self, address: int) -> str:
        page_base = address - address % self.page_size
        return self.protections.get(page_base, "r-x")

    def set_memory_protection(self, address: int, size: int,
                              protection: str) -> bool:
        self.protections[address] = protection
        self.protection_changes.append((address, size, protection))
        return True

    def read_process_memory(self, address: int, size: int) -> bytes:
        page_base = address - address % self.page_size
        page = self.pages.get(page_base)
        page_offset = address - page_base
        if page is None or page_offset + size > len(page):
            raise ReadProcessMemoryError
        return page[page_offset:page_offset + size]

    def write_process_memory(self, address: int, data: List[int]) -> None:
        self.memory_writes.append((address, data))
        page_base = address - address % self.page_size
        page = self.pages.get(page_base)
        if page is not None:
            mutable_page = bytearray(page)
            offset = address - page_base
            mutable_page[offset:offset + len(data)] = bytes(data)
            self.pages[page_base] = bytes(mutable_page)

    def terminate_process(self) -> None:
        self.terminate_count += 1


def _relative_branch(opcode: int, instruction_address: int,
                     destination: int) -> bytes:
    displacement = destination - (instruction_address + 5)
    return bytes([opcode]) + struct.pack("<i", displacement)


def _themida_load_library_family_fixture() -> bytes:
    def simple(seed: int) -> bytes:
        marker = struct.pack("<I", seed)
        return (bytes.fromhex("5589e583ec0452e8000000005a81ea") +
                marker + bytes.fromhex("ffb2") + marker + bytes([0xe8]) +
                marker + bytes.fromhex("52ff7508e8") + marker +
                bytes.fromhex("5a6a0050e8") + marker +
                bytes.fromhex("5ac9c20400"))

    def extended(seed: int) -> bytes:
        marker = struct.pack("<I", seed)
        return (bytes.fromhex("5589e583ec0452e8000000005a81ea") +
                marker + bytes.fromhex("ffb2") + marker + bytes([0xe8]) +
                marker + bytes.fromhex("52ff7510ff750cff7508e8") + marker +
                bytes.fromhex(
                    "5a538b5d1083e36285db0f8509000000ff751050e8") +
                marker + bytes.fromhex("5b5ac9c20c00"))

    return simple(1) + simple(2) + extended(3) + extended(4)


class HeapWrapperEmulationTests(unittest.TestCase):

    def test_cli_boolean_normalization_is_case_insensitive(self) -> None:
        for value in (False, 0, "false", "False", "FALSE", "no", "off"):
            self.assertFalse(_normalize_cli_bool(value, "test_flag"))
        for value in (True, 1, "true", "True", "TRUE", "yes", "on"):
            self.assertTrue(_normalize_cli_bool(value, "test_flag"))
        with self.assertRaisesRegex(ValueError, "--test_flag expects"):
            _normalize_cli_bool("not-a-boolean", "test_flag")

    def test_blocking_frida_rpc_has_host_side_deadline(self) -> None:
        release = threading.Event()
        try:
            with self.assertRaisesRegex(TimeoutError,
                                        "test RPC timed out after 1 ms"):
                _call_with_timeout(lambda: release.wait(), 1, "test RPC")
        finally:
            release.set()

    def test_wrapper_trace_collection_deadline_scales_but_stays_bounded(
            self) -> None:
        self.assertEqual(10000, _wrapper_trace_collection_timeout(0))
        self.assertEqual(10000, _wrapper_trace_collection_timeout(10000))
        self.assertEqual(30000, _wrapper_trace_collection_timeout(60000))
        self.assertEqual(30000, _wrapper_trace_collection_timeout(600000))

    def test_wrapper_trace_collection_skips_blocking_stalker_cleanup(
            self) -> None:
        script_path = (Path(__file__).parents[1] / "unlicense" / "resources" /
                       "frida.js")
        script = script_path.read_text(encoding="utf-8")
        collection_body = script.split("collectWrapperTrace: function () {")[
            1].split("getArchitecture: function", 1)[0]
        self.assertNotIn("Stalker.flush();", collection_body)
        self.assertNotIn("Stalker.garbageCollect();", collection_body)
        self.assertIn("Stalker.unfollow(threadId)", collection_body)
        self.assertIn("observedImports", collection_body)
        self.assertIn("unpatchableImportSamples", script)

    def test_termination_kills_tree_without_cleanup_rpc(self) -> None:
        controller = object.__new__(FridaProcessController)
        controller.pid = 4321
        controller._frida_rpc = Mock()
        controller._frida_session = Mock()
        with patch("unlicense.frida_exec.subprocess.run") as taskkill, \
                patch("unlicense.frida_exec.frida.kill") as frida_kill:
            controller.terminate_process()

        command = taskkill.call_args.args[0]
        self.assertEqual(["taskkill", "/PID", "4321", "/T", "/F"], command)
        controller._frida_rpc.notify_dumping_finished.assert_not_called()
        frida_kill.assert_called_once_with(4321)
        controller._frida_session.detach.assert_called_once_with()

    def test_empty_import_set_does_not_allocate_remote_memory(self) -> None:
        controller = FakeProcessController({}, {})
        address, size = _generate_new_iat_in_process(defaultdict(list),
                                                     0x401000, controller)
        self.assertEqual((0, 0), (address, size))

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
        self.assertEqual([False, False], rearm_modes)

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

    def test_dump_terminates_target_before_file_rebuild(self) -> None:
        controller = FakeProcessController({}, {})
        events: List[str] = []

        def dump_to_file(_pid: int, _base: int, _oep: int, path: str,
                         _original: str) -> None:
            Path(path).write_bytes(b"memory image")

        def terminate() -> None:
            events.append("terminate")
            controller.terminate_count += 1

        controller.terminate_process = terminate  # type: ignore
        with tempfile.TemporaryDirectory() as directory:
            previous_directory = os.getcwd()
            os.chdir(directory)
            try:
                with patch("unlicense.dump_utils.pyscylla.dump_pe",
                           side_effect=dump_to_file), patch(
                                   "unlicense.dump_utils.pyscylla.rebuild_pe",
                                   side_effect=lambda *_args: events.append(
                                       "rebuild")), patch(
                                           "unlicense.dump_utils._fix_pe"), \
                        patch("unlicense.dump_utils._validate_dump",
                              return_value={"valid": True, "issues": []}):
                    result = dump_pe(controller, "fixture.exe", 0x400000,
                                     0xd54c3f, 0, 0, True)
            finally:
                os.chdir(previous_directory)

        self.assertTrue(result)
        self.assertEqual(["terminate", "rebuild"], events)
        self.assertEqual(1, controller.terminate_count)

    def test_dump_can_preserve_original_executable_name_in_separate_dir(
            self) -> None:
        controller = FakeProcessController({}, {})
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "runtime" / "Titanium.exe"
            output.parent.mkdir()

            def dump_to_file(_pid: int, _base: int, _oep: int, path: str,
                             _original: str) -> None:
                Path(path).write_bytes(b"memory image")

            with patch("unlicense.dump_utils.pyscylla.dump_pe",
                       side_effect=dump_to_file), patch(
                           "unlicense.dump_utils.pyscylla.rebuild_pe"), patch(
                               "unlicense.dump_utils._fix_pe") as fix_pe, patch(
                                   "unlicense.dump_utils._validate_dump",
                                   return_value={"valid": True, "issues": []}):
                result = dump_pe(controller, "protected/Titanium.exe",
                                 0x400000, 0xd54c3f, 0, 0, True,
                                 output_file_path=str(output))

            self.assertTrue(result)
            self.assertEqual(str(output), fix_pe.call_args.args[1])

    def test_zero_iat_preserves_unmodified_memory_dump(self) -> None:
        controller = FakeProcessController({}, {})
        with tempfile.TemporaryDirectory() as directory:
            dumped = Path(directory) / "memory.dump"
            output = Path(directory) / "iat.input"
            dumped.write_bytes(b"PE-DUMP-WITH-ORIGINAL-DIRECTORIES")
            with patch("unlicense.dump_utils.pyscylla.fix_iat") as fix_iat:
                was_fixed = _materialize_iat_input(
                    controller, 0x400000, 0, 0, True, str(dumped),
                    str(output))

            self.assertFalse(was_fixed)
            self.assertEqual(dumped.read_bytes(), output.read_bytes())
            fix_iat.assert_not_called()

    def test_nonempty_iat_uses_scylla_reconstruction(self) -> None:
        controller = FakeProcessController({}, {})
        with patch("unlicense.dump_utils.pyscylla.fix_iat") as fix_iat:
            was_fixed = _materialize_iat_input(
                controller, 0x400000, 0x6400000, 0x80, True, "dumped.exe",
                "fixed.exe")

        self.assertTrue(was_fixed)
        fix_iat.assert_called_once_with(controller.pid, 0x400000, 0x6400000,
                                        0x80, True, "dumped.exe",
                                        "fixed.exe")

    def test_pristine_oep_overlay_preserves_rebuilt_import_patch(self) -> None:
        image_base = 0x400000
        file_data = bytearray(b"H" * 0x200 + b"L" * 0x100 + b"T" * 0x100)
        rebuilt_patch = bytes.fromhex("ff1510204000")
        file_data[0x220:0x226] = rebuilt_patch
        pristine = MemoryRange(0x401000, 0x100, "r-x", b"P" * 0x100)

        result = _overlay_pristine_data(
            file_data, image_base, [(0x1000, 0x100, 0x200, 0x100)],
            [pristine], [(0x401020, 6)])

        self.assertEqual(b"P" * 0x20, file_data[0x200:0x220])
        self.assertEqual(rebuilt_patch, file_data[0x220:0x226])
        self.assertEqual(b"P" * (0x100 - 0x26), file_data[0x226:0x300])
        self.assertEqual({
            "restored_ranges": 1,
            "restored_bytes": 0x100,
            "preserved_rebuilt_regions": 1,
        }, result)

    def test_exact_themida_private_state_guard_returns_success(self) -> None:
        guard = bytes.fromhex(
            "60e8000000005a81eaecb47c0b8bb26b0b7c0b85f6"
            "0f850700000061b800000000c38b063982c20d7c0b"
            "0f850b00000061b800000000e90600000061b801000000c3")
        file_data = bytearray(b"H" * 0x200 + b"X" * 0x100)
        file_data[0x220:0x220 + len(guard)] = guard

        patched = _patch_stale_vm_pointer_guards(
            file_data, [(0xb41000, 0x100, 0x200, 0x100)])

        self.assertEqual([0xb41020], patched)
        self.assertEqual(bytes.fromhex("31c0c3"), file_data[0x220:0x223])
        self.assertEqual(guard[3:],
                         file_data[0x223:0x220 + len(guard)])

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

    def test_native_trace_discovers_import_inside_text_without_static_wrapper(
            self) -> None:
        call_site = 0x401000
        internal_wrapper = 0x405000
        target_api = 0x77003000
        call_page = bytearray(0x1000)
        call_page[0:5] = _relative_branch(0xe8, call_site, internal_wrapper)
        call_page[5] = 0x90
        controller = FakeProcessController(
            {call_site: bytes(call_page)}, {target_api: {
                "name": "TargetApi",
                "module": "kernel32.dll",
            }})
        controller.trace_observed_imports = [{
            "callAddress": hex(call_site),
            "callSize": 5,
            "isJump": False,
            "address": hex(target_api),
            "name": "TargetApi",
            "module": "kernel32.dll",
            "hits": 3,
        }]
        imports: ImportToCallSiteDict = defaultdict(list)
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True

        diagnostics = _resolve_imports(imports, set(), None,
                                       controller.exports, disassembler,
                                       controller, 250, False)

        self.assertEqual([], diagnostics)
        self.assertEqual([(call_site, 5, False)], imports[target_api])
        self.assertEqual(1, controller.trace_call_count)
        self.assertTrue(controller.last_observed_imports[0]["accepted"])

    def test_static_scan_reserves_in_section_wrapper_for_native_confirmation(
            self) -> None:
        call_site = 0x401000
        internal_wrapper = 0x401100
        text_data = bytearray(0x1000)
        text_data[0:5] = _relative_branch(0xe8, call_site, internal_wrapper)
        text_data[5] = 0x90
        text_range = MemoryRange(call_site, len(text_data), "r-x",
                                 bytes(text_data))
        controller = FakeProcessController({call_site: bytes(text_data)}, {})
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True

        imports, external, runtime = find_wrapped_imports(
            text_range, {}, disassembler, controller)

        self.assertEqual({}, imports)
        self.assertEqual(set(), external)
        self.assertEqual({(call_site, 5, False, internal_wrapper, None)},
                         runtime)

    def test_native_trace_resolves_executed_in_section_wrapper(self) -> None:
        call_site = 0x401000
        internal_wrapper = 0x405000
        target_api = 0x77003000
        call_page = bytearray(0x1000)
        call_page[0:5] = _relative_branch(0xe8, call_site, internal_wrapper)
        call_page[5] = 0x90
        controller = FakeProcessController(
            {call_site: bytes(call_page)}, {target_api: {
                "name": "TargetApi",
                "module": "kernel32.dll",
            }})
        controller.trace_results = {call_site: target_api}
        imports: ImportToCallSiteDict = defaultdict(list)
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True

        _resolve_imports(
            imports, set(), None, controller.exports, disassembler,
            controller, native_trace_timeout=250,
            runtime_wrapper_set={(call_site, 5, False, internal_wrapper,
                                  None)})

        self.assertEqual([(call_site, 5, False)], imports[target_api])
        self.assertEqual(1, controller.trace_call_count)
        self.assertEqual(1, controller.last_wrapper_trace_stats[
            "runtimeCandidateResolutions"])

    def test_native_trace_preserves_unpatchable_plain_five_byte_call(
            self) -> None:
        call_site = 0x401000
        target_api = 0x77003000
        call_page = bytearray(0x1000)
        call_page[0:5] = _relative_branch(0xe8, call_site, target_api)
        call_page[5] = 0x55
        controller = FakeProcessController(
            {call_site: bytes(call_page)}, {target_api: {
                "name": "TargetApi",
                "module": "kernel32.dll",
            }})
        controller.trace_observed_imports = [{
            "callAddress": hex(call_site),
            "callSize": 5,
            "isJump": False,
            "address": hex(target_api),
            "name": "TargetApi",
            "module": "kernel32.dll",
            "hits": 1,
        }]
        imports: ImportToCallSiteDict = defaultdict(list)
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True

        _resolve_imports(imports, set(), None, controller.exports,
                         disassembler, controller, 250, False)

        self.assertEqual({}, imports)
        self.assertIn("safe Themida patch window",
                      controller.last_observed_imports[0]["rejection_reason"])

    def test_native_trace_accepts_and_patches_frame_relative_import_call(
            self) -> None:
        call_site = 0x401000
        target_api = 0x755310ff
        iat_address = 0x6400000
        call_page = bytearray(0x1000)
        call_page[0:6] = b"\xff\x95\x54\x1a\x74\x0b"
        controller = FakeProcessController(
            {call_site: bytes(call_page)}, {target_api: {
                "name": "Sleep",
                "module": "kernel32.dll",
            }})
        controller.trace_observed_imports = [{
            "callAddress": hex(call_site),
            "callSize": 6,
            "isJump": False,
            "address": hex(target_api),
            "name": "Sleep",
            "module": "kernel32.dll",
            "hits": 3,
        }]
        imports: ImportToCallSiteDict = defaultdict(list)
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True

        _resolve_imports(imports, set(), None, controller.exports,
                         disassembler, controller, 250, False)
        _fix_import_references_in_process(imports, iat_address, controller)

        self.assertEqual([(call_site, 6, False)], imports[target_api])
        self.assertTrue(controller.last_observed_imports[0]["accepted"])
        self.assertEqual(b"\xff\x15" + struct.pack("<I", iat_address),
                         controller.pages[call_site][:6])
        self.assertEqual([(call_site, 0x1000, "rwx"),
                          (call_site, 0x1000, "r-x")],
                         controller.protection_changes)

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
        self.assertEqual("sacrificial_natural_trace",
                         diagnostics[0]["resolution_method"])
        self.assertEqual(hex(probe_call_site),
                         diagnostics[0]["probe_call_address"])
        self.assertEqual(hex(probe_wrapper),
                         diagnostics[0]["probe_wrapper_address"])
        self.assertEqual({"activeProbes": 0},
                         diagnostics[0]["probe_trace_stats"])
        self.assertFalse(probe_controller.active_probe)
        self.assertEqual(7000, probe_controller.trace_timeout)
        self.assertFalse(main_controller.active_probe)
        self.assertEqual(250, main_controller.trace_timeout)
        self.assertEqual(1, main_controller.trace_call_count)
        self.assertEqual(1, probe_controller.terminate_count)

    def test_explicit_native_trace_is_not_suppressed_by_active_probe(
            self) -> None:
        call_site = 0x401000
        wrapper = 0x402000
        target_api = 0x77003000
        call_page = bytearray(0x1000)
        call_page[0:5] = _relative_branch(0xe8, call_site, wrapper)
        controller = FakeProcessController(
            {
                call_site: bytes(call_page),
                wrapper: bytes([0xcc]) + bytes(0xfff),
            }, {target_api: {
                "name": "TargetApi",
                "module": "kernel32.dll",
            }})
        controller.trace_results = {call_site: target_api}
        probe_factory = Mock()
        imports: ImportToCallSiteDict = defaultdict(list)
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True

        diagnostics = _resolve_imports(imports,
                                       {(call_site, 5, False, wrapper, None)},
                                       None, controller.exports, disassembler,
                                       controller, 60000, True, 5000, 0x400000,
                                       probe_factory)

        self.assertEqual([(call_site, 5, False)], imports[target_api])
        self.assertEqual("native_trace", diagnostics[0]["resolution_method"])
        self.assertEqual(60000, controller.trace_timeout)
        self.assertEqual(1, controller.trace_call_count)
        probe_factory.assert_not_called()

    def test_natural_trace_does_not_run_synthetic_argument_profiles(
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
        probe_controller.trace_results = {}

        imports: ImportToCallSiteDict = defaultdict(list)
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True
        diagnostics = _resolve_imports(
            imports, {(call_site, 5, False, wrapper, None)}, None,
            main_controller.exports, disassembler, main_controller, 0, True,
            5000, image_base, lambda: (probe_controller, probe_image_base))

        self.assertEqual([], imports[main_api])
        self.assertEqual(1, probe_controller.trace_call_count)
        self.assertFalse(probe_controller.active_probe)
        self.assertIn("not resolved during natural execution",
                      diagnostics[0]["probe_error"])

    def test_natural_trace_cleans_up_after_sacrificial_crash(self) -> None:
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

        imports: ImportToCallSiteDict = defaultdict(list)
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True
        diagnostics = _resolve_imports(
            imports, {(first_call, 5, False, first_wrapper, None),
                      (second_call, 5, False, second_wrapper, None)}, None,
            main_controller.exports, disassembler, main_controller, 0, True,
            5000, image_base, lambda: (failed_probe, probe_image_base))

        self.assertEqual([], imports[main_api])
        self.assertEqual("unresolved", diagnostics[0]["resolution_method"])
        self.assertEqual("probe process exited", diagnostics[0]["probe_error"])
        self.assertEqual("probe process exited", diagnostics[1]["probe_error"])
        self.assertEqual(1, failed_probe.terminate_count)
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
        self.assertEqual(1, probe_controller.trace_call_count)
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

    def test_themida_load_library_family_resolves_stale_internal_hook(
            self) -> None:
        family = _themida_load_library_family_fixture()
        self.assertEqual(0x102, len(family))
        family_address = 0x402100
        member_offsets = (0x00, 0x35, 0x6a, 0xb6)
        export_names = ("LoadLibraryA", "LoadLibraryW", "LoadLibraryExA",
                        "LoadLibraryExW")
        export_addresses = tuple(0x76001000 + index * 0x100
                                 for index in range(4))
        wrapper_page = bytearray(0x1000)
        wrapper_page[0x100:0x100 + len(family)] = family
        call_page = bytearray(0x1000)
        wrapper_set = set()
        exports: Dict[int, Dict[str, Any]] = {}
        for index, (member_offset, export_name, export_address) in enumerate(
                zip(member_offsets, export_names, export_addresses)):
            call_address = 0x401000 + index * 0x10
            wrapper_address = family_address + member_offset
            call_page[index * 0x10:index * 0x10 + 5] = _relative_branch(
                0xe9, call_address, wrapper_address)
            wrapper_set.add(
                (call_address, 5, True, wrapper_address, None))
            exports[export_address] = {
                "name": export_name,
                "module": "kernel32.dll",
            }

        controller = FakeProcessController({
            0x401000: bytes(call_page),
            0x402000: bytes(wrapper_page),
        }, exports)
        for member_offset in member_offsets:
            controller.module_addresses[family_address + member_offset] = {
                "name": "fixture.exe",
                "base": "0x400000",
                "size": 0x100000,
            }
        # Themida hooks name-based lookup too. The resolver must prefer the
        # enumerated external export and reject this circular answer.
        imports: ImportToCallSiteDict = defaultdict(list)
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True

        with patch.object(controller, "find_export_by_name",
                          return_value=family_address):
            diagnostics = _resolve_imports(imports, wrapper_set, None,
                                           exports, disassembler, controller)

        for index, (export_address, export_name) in enumerate(
                zip(export_addresses, export_names)):
            self.assertEqual([(0x401000 + index * 0x10, 5, True)],
                             imports[export_address])
            record = next(
                item for item in diagnostics
                if item["call_address"] == hex(0x401000 + index * 0x10))
            self.assertEqual("themida_loadlibrary_family",
                             record["resolution_method"])
            self.assertEqual(export_name, record["structural_wrapper"])

    def test_themida_load_library_signature_rejects_partial_family(
            self) -> None:
        family = _themida_load_library_family_fixture()
        base = 0x500000

        def get_data(address: int, size: int) -> bytes:
            offset = address - base
            if offset < 0 or offset + size > len(family) - 1:
                raise ReadProcessMemoryError
            return family[offset:offset + size]

        self.assertIsNone(
            _identify_themida_load_library_wrapper(base, get_data))

    def test_unhooked_export_rejects_name_lookup_back_into_wrapper(self) -> None:
        controller = FakeProcessController({}, {})
        wrapper = 0x402000

        with patch.object(controller, "find_export_by_name",
                          return_value=wrapper):
            self.assertIsNone(
                _find_unhooked_export("LoadLibraryA", wrapper, {},
                                      controller))

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

    def test_function_hash_handles_back_edge_without_partial_abort(
            self) -> None:
        function_address = 0x401000
        # inc eax; jmp 0x401000
        function_data = b"\x40\xeb\xfd" + bytes(0x100)
        controller = FakeProcessController({0x401000: function_data}, {})
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True
        diagnostic: Dict[str, Any] = {}

        function_hash = compute_function_hash(
            disassembler, function_address,
            lambda address, size: function_data[
                address - function_address:address - function_address + size],
            controller, diagnostic)

        self.assertNotEqual(EMPTY_FUNCTION_HASH, function_hash)
        self.assertEqual("loop", diagnostic["termination"])
        self.assertEqual(1, diagnostic["loop_edges"])
        self.assertEqual(1, diagnostic["basic_blocks"])

    def test_export_hash_generation_keeps_all_collision_candidates(
            self) -> None:
        first_export = 0x71001000
        second_export = 0x72001000
        first_page = b"\xc3" + bytes(0xfff)
        second_page = b"\xc3" + bytes(0xfff)
        exports = {
            first_export: {
                "name": "FirstApi",
                "module": "first.dll",
            },
            second_export: {
                "name": "SecondApi",
                "module": "second.dll",
            },
        }
        controller = FakeProcessController({}, exports)
        controller.module_ranges = {
            "ntdll.dll":
            [MemoryRange(first_export, len(first_page), "r-x", first_page)],
            "kernel32.dll":
            [MemoryRange(second_export, len(second_page), "r-x", second_page)],
        }
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True

        export_hashes = _generate_export_hashes(disassembler, exports,
                                                controller)

        self.assertEqual(1, len(export_hashes))
        self.assertEqual([first_export, second_export],
                         next(iter(export_hashes.values())))

    def test_ambiguous_hash_is_deferred_instead_of_picking_last_export(
            self) -> None:
        call_site = 0x401000
        wrapper = 0x402000
        first_export = 0x71001000
        second_export = 0x72001000
        call_page = bytearray(0x1000)
        call_page[0:5] = _relative_branch(0xe8, call_site, wrapper)
        wrapper_page = b"\xc3" + bytes(0xfff)
        exports = {
            first_export: {
                "name": "FirstApi",
                "module": "first.dll",
            },
            second_export: {
                "name": "SecondApi",
                "module": "second.dll",
            },
        }
        controller = FakeProcessController(
            {
                call_site: bytes(call_page),
                wrapper: wrapper_page,
            }, exports)
        controller.module_addresses[wrapper] = {
            "name": "fixture.exe",
            "base": "0x400000",
            "size": 0x100000,
        }
        imports: ImportToCallSiteDict = defaultdict(list)
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True

        with patch("unlicense.winlicense2.compute_function_hash",
                   return_value=0x12345678), patch(
                       "unlicense.winlicense2.resolve_wrapped_api",
                       return_value=None):
            diagnostics = _resolve_imports(
                imports, {(call_site, 5, False, wrapper, None)},
                {0x12345678: [first_export, second_export]}, exports,
                disassembler, controller)

        self.assertEqual({}, imports)
        self.assertTrue(diagnostics[0]["hash_ambiguous"])
        self.assertEqual(2, len(diagnostics[0]["hash_candidates"]))
        self.assertEqual("unresolved", diagnostics[0]["resolution_method"])

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
