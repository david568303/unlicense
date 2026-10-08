import functools
import logging
import time
from importlib import resources
from pathlib import Path
from typing import (List, Callable, Dict, Any, Optional)

import frida
import frida.core

from .process_control import (ProcessController, Architecture, MemoryRange,
                              QueryProcessMemoryError, ReadProcessMemoryError,
                              WriteProcessMemoryError)

LOG = logging.getLogger(__name__)
# See issue #7: messages cannot exceed 128MiB
MAX_DATA_CHUNK_SIZE = 64 * 1024 * 1024
# Frida's exception classes don't share a public common base across all
# versions, so enumerate the ones that can be raised while tearing down an
# already-dead process or an already-destroyed/detached session.
_TEARDOWN_ERRORS = (frida.InvalidOperationError, frida.ProcessNotFoundError,
                    frida.TransportError, frida.core.RPCException)

OepReachedCallback = Callable[[int, int, bool], None]


class FridaProcessController(ProcessController):

    def __init__(self, pid: int, main_module_name: str,
                 frida_session: frida.core.Session,
                 frida_script: frida.core.Script):
        frida_rpc = frida_script.exports

        # Initialize ProcessController
        super().__init__(pid, main_module_name,
                         _str_to_architecture(frida_rpc.get_architecture()),
                         frida_rpc.get_pointer_size(),
                         frida_rpc.get_page_size())

        # Initialize FridaProcessController specifics
        self._frida_rpc = frida_rpc
        self._frida_script = frida_script
        self._frida_session = frida_session
        self._exported_functions_cache: Optional[Dict[int, Dict[str,
                                                                Any]]] = None

    def find_module_by_address(self, address: int) -> Optional[Dict[str, Any]]:
        value: Optional[Dict[str,
                             Any]] = self._frida_rpc.find_module_by_address(
                                 hex(address))
        return value

    def find_range_by_address(
            self,
            address: int,
            include_data: bool = False) -> Optional[MemoryRange]:
        value: Optional[Dict[str,
                             Any]] = self._frida_rpc.find_range_by_address(
                                 hex(address))
        if value is None:
            return None
        return self._frida_range_to_mem_range(value, include_data)

    def find_export_by_name(self, module_name: str,
                            export_name: str) -> Optional[int]:
        export_address: Optional[str] = self._frida_rpc.find_export_by_name(
            module_name, export_name)
        if export_address is None:
            return None
        return int(export_address, 16)

    def enumerate_modules(self) -> List[str]:
        value: List[str] = self._frida_rpc.enumerate_modules()
        return value

    def enumerate_pe_candidates(self) -> List[Dict[str, Any]]:
        value: List[Dict[str, Any]] = self._frida_rpc.enumerate_pe_candidates()
        return value

    def trace_wrapped_imports(self,
                              wrappers: List[Dict[str, Any]],
                              timeout_ms: int,
                              active_probe: bool = False) -> Dict[int, int]:
        self._frida_rpc.setup_wrapper_trace(wrappers, self.main_module_name)
        if active_probe:
            self._frida_rpc.probe_wrapper_trace()
        if timeout_ms > 0:
            self._frida_script.post({"type": "block_on_oep"})
            time.sleep(timeout_ms / 1000.0)
        trace_data: Dict[str, Any] = self._frida_rpc.collect_wrapper_trace()
        value: List[Dict[str, Any]] = trace_data.get("results", [])
        stats: Optional[Dict[str, Any]] = trace_data.get("stats")
        if stats is not None:
            LOG.info(
                "Native trace stats: threads=%d blocks=%d wrapper_hits=%d "
                "export_hits=%d return_hits=%d active_probes=%d "
                "active_returns=%d skipped_final_apis=%d active_errors=%d",
                len(stats.get("threadIds",
                              [])), stats.get("compiledBlocks", 0),
                stats.get("wrapperHits", 0), stats.get("exportHits", 0),
                stats.get("returnHits", 0), stats.get("activeProbes", 0),
                stats.get("activeProbeReturns", 0),
                stats.get("skippedFinalApis", 0),
                len(stats.get("activeProbeErrors", [])))
            for probe_error in stats.get("activeProbeErrors", []):
                LOG.debug("Active wrapper probe error: %s", probe_error)

        traced = {
            int(result["callAddress"], 16): int(result["address"], 16)
            for result in value
        }
        # One protected wrapper may be referenced by several call sites. A
        # successful native probe resolves all of them, even though Stalker
        # records the first matching call site only.
        by_wrapper = {
            result["wrapperAddress"].lower(): int(result["address"], 16)
            for result in value
        }
        for wrapper in wrappers:
            resolved = by_wrapper.get(wrapper["wrapperAddress"].lower())
            if resolved is not None:
                traced[int(wrapper["callAddress"], 16)] = resolved
        return traced

    def enumerate_module_ranges(
            self,
            module_name: str,
            include_data: bool = False) -> List[MemoryRange]:

        def convert_range(dict_range: Dict[str, Any]) -> MemoryRange:
            return self._frida_range_to_mem_range(dict_range, include_data)

        value: List[Dict[str, Any]] = self._frida_rpc.enumerate_module_ranges(
            module_name)
        return list(map(convert_range, value))

    def enumerate_exported_functions(self,
                                     update_cache: bool = False
                                     ) -> Dict[int, Dict[str, Any]]:
        if self._exported_functions_cache is None or update_cache:
            value: List[Dict[
                str, Any]] = self._frida_rpc.enumerate_exported_functions(
                    self.main_module_name)
            exports_dict = {int(e["address"], 16): e for e in value}
            self._exported_functions_cache = exports_dict
            return exports_dict
        return self._exported_functions_cache

    def allocate_process_memory(self, size: int, near: int) -> int:
        buffer_addr = self._frida_rpc.allocate_process_memory(size, near)
        return int(buffer_addr, 16)

    def query_memory_protection(self, address: int) -> str:
        try:
            protection: str = self._frida_rpc.query_memory_protection(
                hex(address))
            return protection
        except frida.core.RPCException as rpc_exception:
            raise QueryProcessMemoryError from rpc_exception

    def set_memory_protection(self, address: int, size: int,
                              protection: str) -> bool:
        result: bool = self._frida_rpc.set_memory_protection(
            hex(address), size, protection)
        return result

    def read_process_memory(self, address: int, size: int) -> bytes:
        read_data = bytearray(size)
        try:
            for offset in range(0, size, MAX_DATA_CHUNK_SIZE):
                chunk_size = min(MAX_DATA_CHUNK_SIZE, size - offset)
                data = self._frida_rpc.read_process_memory(
                    hex(address + offset), chunk_size)
                if data is None:
                    raise ReadProcessMemoryError(
                        "read_process_memory failed (invalid parameters?)")
                read_data[offset:offset + chunk_size] = data
            return bytes(read_data)
        except frida.core.RPCException as rpc_exception:
            raise ReadProcessMemoryError from rpc_exception

    def write_process_memory(self, address: int, data: List[int]) -> None:
        try:
            self._frida_rpc.write_process_memory(hex(address), data)
        except frida.core.RPCException as rpc_exception:
            raise WriteProcessMemoryError from rpc_exception

    def terminate_process(self) -> None:
        # Cleanup is best-effort: the script, process or session may already
        # be gone (e.g. the target exited or crashed before the OEP was
        # reached, which destroys the injected script). Each step is isolated
        # so a failure in one doesn't skip the others or mask the original
        # error that triggered this cleanup.
        try:
            self._frida_rpc.notify_dumping_finished()
        except _TEARDOWN_ERRORS as frida_error:
            LOG.debug("Failed to notify script (already destroyed?): %s",
                      frida_error)

        try:
            frida.kill(self.pid)
        except _TEARDOWN_ERRORS as frida_error:
            LOG.debug("Failed to kill process (already dead?): %s",
                      frida_error)

        try:
            self._frida_session.detach()
        except _TEARDOWN_ERRORS as frida_error:
            LOG.debug("Failed to detach session: %s", frida_error)

    def _frida_range_to_mem_range(self, dict_range: Dict[str, Any],
                                  with_data: bool) -> MemoryRange:
        base = int(dict_range["base"], 16)
        size = dict_range["size"]
        data = None
        if with_data:
            data = self.read_process_memory(base, size)
        return MemoryRange(base=base,
                           size=size,
                           protection=dict_range["protection"],
                           data=data)


def _str_to_architecture(frida_arch: str) -> Architecture:
    if frida_arch == "ia32":
        return Architecture.X86_32
    if frida_arch == "x64":
        return Architecture.X86_64
    raise ValueError


def spawn_and_instrument(
        pe_path: Path, text_section_ranges: List[MemoryRange],
        notify_oep_reached: OepReachedCallback) -> ProcessController:
    pid: int
    if pe_path.suffix == ".dll":
        # Use `rundll32` to load the DLL
        rundll32_path = "C:\\Windows\\System32\\rundll32.exe"
        pid = frida.spawn(
            rundll32_path,
            [rundll32_path, str(pe_path.absolute()), "#0"])
    else:
        pid = frida.spawn(str(pe_path))

    main_module_name = pe_path.name
    session = frida.attach(pid)
    frida_js = resources.open_text("unlicense.resources", "frida.js").read()
    script = session.create_script(frida_js)
    on_message_callback = functools.partial(_frida_callback,
                                            notify_oep_reached)
    script.on('message', on_message_callback)
    script.load()

    frida_rpc = script.exports
    process_controller = FridaProcessController(pid, main_module_name, session,
                                                script)
    frida_rpc.setup_oep_tracing(pe_path.name, [[r.base, r.size]
                                               for r in text_section_ranges])
    frida.resume(pid)

    return process_controller


def _frida_callback(notify_oep_reached: OepReachedCallback,
                    message: Dict[str, Any], _data: Any) -> None:
    msg_type = message['type']
    if msg_type == 'error':
        LOG.error(message)
        LOG.error(message['stack'])
        return

    if msg_type == 'send':
        payload = message['payload']
        event = payload.get('event', '')
        if event == 'oep_reached':
            # Note: We cannot use RPCs in `on_message` callbacks, so we have to
            # delay the actual dumping.
            notify_oep_reached(int(payload['BASE'],
                                   16), int(payload['OEP'], 16),
                               bool(payload['DOTNET']))
            return

    raise NotImplementedError('Unknown message received')
