import logging
import struct
from typing import Dict, Tuple, Any, Optional, cast

from unicorn import (  # type: ignore
    Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_MODE_64, UC_PROT_READ,
    UC_PROT_WRITE, UC_PROT_ALL, UC_HOOK_MEM_UNMAPPED, UC_HOOK_BLOCK,
    UC_HOOK_INTR)
from unicorn.x86_const import (  # type: ignore
    UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_EIP, UC_X86_REG_RSP,
    UC_X86_REG_RBP, UC_X86_REG_RIP, UC_X86_REG_MSR, UC_X86_REG_EAX,
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8,
    UC_X86_REG_R9)

from .dump_utils import pointer_size_to_fmt
from .process_control import ProcessController, Architecture, ReadProcessMemoryError

STACK_MAGIC_RET_ADDR = 0xdeadbeef
MAX_EMULATED_HEAP_ALLOCATION = 64 * 1024 * 1024
MAX_HEAP_MAPPING_ATTEMPTS = 256
MAX_EMULATION_INSTRUCTIONS = 2_000_000
EMULATION_TIMEOUT_MICROSECONDS = 5_000_000
LOG = logging.getLogger(__name__)


def resolve_wrapped_api(
        wrapper_start_addr: int,
        process_controller: ProcessController,
        expected_ret_addr: Optional[int] = None,
        diagnostic: Optional[Dict[str, Any]] = None) -> Optional[int]:
    arch = process_controller.architecture
    if arch == Architecture.X86_32:
        uc_arch = UC_ARCH_X86
        uc_mode = UC_MODE_32
        pc_register = UC_X86_REG_EIP
        sp_register = UC_X86_REG_ESP
        bp_register = UC_X86_REG_EBP
        stack_addr = 0xff000000
        setup_teb = _setup_teb_x86
    elif arch == Architecture.X86_64:
        uc_arch = UC_ARCH_X86
        uc_mode = UC_MODE_64
        pc_register = UC_X86_REG_RIP
        sp_register = UC_X86_REG_RSP
        bp_register = UC_X86_REG_RBP
        stack_addr = 0xff00000000000000
        setup_teb = _setup_teb_x64
    else:
        raise NotImplementedError(f"Architecture '{arch}' isn't supported")

    if diagnostic is None:
        diagnostic = {}
    diagnostic.update({
        "start_address":
        hex(wrapper_start_addr),
        "expected_return_address":
        None if expected_ret_addr is None else hex(expected_ret_addr),
        "mapped_pages": [],
        "simulated_apis": [],
    })

    uc = Uc(uc_arch, uc_mode)
    try:
        # Map fake return address's page in case wrappers try to access it
        aligned_addr = STACK_MAGIC_RET_ADDR - (STACK_MAGIC_RET_ADDR %
                                               process_controller.page_size)
        uc.mem_map(aligned_addr, process_controller.page_size, UC_PROT_ALL)

        # Setup a stack
        stack_size = 3 * process_controller.page_size
        stack_start = stack_addr + stack_size - process_controller.page_size
        uc.mem_map(stack_addr, stack_size, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_write(
            stack_start,
            struct.pack(pointer_size_to_fmt(process_controller.pointer_size),
                        STACK_MAGIC_RET_ADDR))
        uc.reg_write(sp_register, stack_start)
        uc.reg_write(bp_register, stack_start)

        # Setup FS/GSBASE
        setup_teb(uc, process_controller)

        # Setup hooks
        if expected_ret_addr is None:
            stop_on_ret_addr = STACK_MAGIC_RET_ADDR
        else:
            stop_on_ret_addr = expected_ret_addr
        emulation_context: Dict[str, Any] = {
            "process_controller": process_controller,
            "stop_on_ret_addr": stop_on_ret_addr,
            "diagnostic": diagnostic,
            "heap_next":
            0x30000000 if arch == Architecture.X86_32 else 0x20000000000,
            "heap_allocations": {},
            "resolved_address": None,
        }
        uc.hook_add(UC_HOOK_MEM_UNMAPPED,
                    _unicorn_hook_unmapped,
                    user_data=emulation_context)
        uc.hook_add(UC_HOOK_BLOCK,
                    _unicorn_hook_block,
                    user_data=emulation_context)
        uc.hook_add(UC_HOOK_INTR,
                    _unicorn_hook_interrupt,
                    user_data=emulation_context)

        uc.emu_start(wrapper_start_addr,
                     wrapper_start_addr + 1024,
                     timeout=EMULATION_TIMEOUT_MICROSECONDS,
                     count=MAX_EMULATION_INSTRUCTIONS)

        resolved_address = emulation_context["resolved_address"]
        if resolved_address is None:
            pc = uc.reg_read(pc_register)
            assert isinstance(pc, int)
            diagnostic.setdefault(
                "error", "Emulation stopped before reaching a final API")
            diagnostic["pc"] = hex(pc)
            LOG.debug("Emulation limit reached before resolving the wrapper")
            return None

        assert isinstance(resolved_address, int)
        diagnostic["resolved_address"] = hex(resolved_address)
        return resolved_address
    except (UcError, RuntimeError) as e:
        LOG.debug("ERROR: %s", str(e))
        pc = uc.reg_read(pc_register)
        assert isinstance(pc, int)
        sp = uc.reg_read(sp_register)
        assert isinstance(sp, int)
        bp = uc.reg_read(bp_register)
        assert isinstance(bp, int)
        LOG.debug("PC=%s", hex(pc))
        LOG.debug("SP=%s", hex(sp))
        LOG.debug("BP=%s", hex(bp))
        diagnostic.update({
            "error": str(e),
            "pc": hex(pc),
            "sp": hex(sp),
            "bp": hex(bp),
        })
        return None


def _setup_teb_x86(uc: Uc, process_info: ProcessController) -> None:
    MSG_IA32_FS_BASE = 0xC0000100
    teb_addr = 0xff100000
    peb_addr = 0xff200000
    # Map tables
    uc.mem_map(teb_addr, process_info.page_size, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(peb_addr, process_info.page_size, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_write(teb_addr + 0x18, struct.pack(pointer_size_to_fmt(4),
                                              teb_addr))
    uc.mem_write(teb_addr + 0x30, struct.pack(pointer_size_to_fmt(4),
                                              peb_addr))
    uc.reg_write(UC_X86_REG_MSR, (MSG_IA32_FS_BASE, teb_addr))


def _setup_teb_x64(uc: Uc, process_info: ProcessController) -> None:
    MSG_IA32_GS_BASE = 0xC0000101
    teb_addr = 0xff10000000000000
    peb_addr = 0xff20000000000000
    # Map tables
    uc.mem_map(teb_addr, process_info.page_size, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(peb_addr, process_info.page_size, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_write(teb_addr + 0x30, struct.pack(pointer_size_to_fmt(8),
                                              teb_addr))
    uc.mem_write(teb_addr + 0x60, struct.pack(pointer_size_to_fmt(8),
                                              peb_addr))
    uc.reg_write(UC_X86_REG_MSR, (MSG_IA32_GS_BASE, teb_addr))


def _unicorn_hook_unmapped(uc: Uc, _access: Any, address: int, _size: int,
                           _value: int, emulation_context: Dict[str,
                                                                Any]) -> bool:
    process_controller: ProcessController = emulation_context[
        "process_controller"]
    diagnostic: Dict[str, Any] = emulation_context["diagnostic"]
    LOG.debug("Unmapped memory at %s", hex(address))
    if address == 0:
        diagnostic["unmapped_failure"] = hex(address)
        return False

    page_size = process_controller.page_size
    aligned_addr = address - (address & (page_size - 1))
    try:
        in_process_data = process_controller.read_process_memory(
            aligned_addr, page_size)
        uc.mem_map(aligned_addr, len(in_process_data), UC_PROT_ALL)
        uc.mem_write(aligned_addr, in_process_data)
        LOG.debug("Mapped %d bytes at %s", len(in_process_data),
                  hex(aligned_addr))
        diagnostic["mapped_pages"].append({
            "address": hex(aligned_addr),
            "size": len(in_process_data),
        })
        return True
    except UcError as e:
        LOG.error("ERROR: %s", str(e))
        return False
    except ReadProcessMemoryError as e:
        # Log this error as debug as it's expected to happen in cases where we
        # reach the end of the IAT.
        LOG.debug("ERROR: %s", str(e))
        diagnostic["unmapped_failure"] = hex(address)
        diagnostic["memory_error"] = str(e)
        return False
    except Exception as e:
        LOG.error("ERROR: %s", str(e))
        diagnostic["unmapped_failure"] = hex(address)
        diagnostic["memory_error"] = str(e)
        return False


def _unicorn_hook_block(uc: Uc, address: int, _size: int,
                        emulation_context: Dict[str, Any]) -> None:
    process_controller: ProcessController = emulation_context[
        "process_controller"]
    stop_on_ret_addr: int = emulation_context["stop_on_ret_addr"]
    diagnostic: Dict[str, Any] = emulation_context["diagnostic"]
    ptr_size = process_controller.pointer_size
    arch = process_controller.architecture
    if arch == Architecture.X86_32:
        pc_register = UC_X86_REG_EIP
        sp_register = UC_X86_REG_ESP
        result_register = UC_X86_REG_EAX
    elif arch == Architecture.X86_64:
        pc_register = UC_X86_REG_RIP
        sp_register = UC_X86_REG_RSP
        result_register = UC_X86_REG_RAX
    else:
        raise NotImplementedError(f"Unsupported architecture: {arch}")

    if address == STACK_MAGIC_RET_ADDR:
        diagnostic["returned_without_export"] = True
        diagnostic["pc"] = hex(address)
        uc.emu_stop()
        return

    exports_dict = process_controller.enumerate_exported_functions()
    if address in exports_dict:
        # Reached an export or returned to the call site
        sp = uc.reg_read(sp_register)
        assert isinstance(sp, int)
        ret_addr_data = uc.mem_read(sp, ptr_size)
        ret_addr = struct.unpack(pointer_size_to_fmt(ptr_size),
                                 ret_addr_data)[0]
        api_name = exports_dict[address]['name']
        LOG.debug("Reached API '%s'", api_name)
        if ret_addr == stop_on_ret_addr or \
            ret_addr == stop_on_ret_addr + 1 \
                or ret_addr == STACK_MAGIC_RET_ADDR:
            # Most wrappers should end up here directly
            uc.reg_write(result_register, address)
            emulation_context["resolved_address"] = address
            uc.emu_stop()
            return
        if _is_no_return_api(api_name):
            # Note: Dirty fix for ExitProcess-like wrappers on WinLicense 3.x
            LOG.debug("Reached noreturn API, stopping emulation")
            uc.reg_write(result_register, address)
            emulation_context["resolved_address"] = address
            uc.emu_stop()
            return
        if _is_simulated_api(api_name):
            # Note: Starting with Themida 3.1.4.0, wrappers call some useless
            # APIs to fool emulation-based unwrappers. Some Themida 2.x
            # wrappers also use heap APIs while computing the real target.
            LOG.debug("Reached auxiliary API call, simulating")
            result, arg_count, api_details = _simulate_api(
                api_name, uc, sp, arch, emulation_context)
            diagnostic["simulated_apis"].append(api_details)
            # Set result
            uc.reg_write(result_register, result)

            # Fix the stack
            if arch == Architecture.X86_32:
                # Pop return address and arguments from the stack
                uc.reg_write(sp_register, sp + ptr_size * (1 + arg_count))
            elif arch == Architecture.X86_64:
                # Pop return address and arguments from the stack
                stack_arg_count = max(0, arg_count - 4)
                uc.reg_write(sp_register,
                             sp + ptr_size * (1 + stack_arg_count))

            # Set next address
            uc.reg_write(pc_register, ret_addr)
            return


def _unicorn_hook_interrupt(uc: Uc, interrupt_number: int,
                            emulation_context: Dict[str, Any]) -> None:
    process_controller: ProcessController = emulation_context[
        "process_controller"]
    if process_controller.architecture == Architecture.X86_32:
        pc_register = UC_X86_REG_EIP
    else:
        pc_register = UC_X86_REG_RIP
    pc = uc.reg_read(pc_register)
    assert isinstance(pc, int)
    instruction_address = pc - 1 if interrupt_number == 3 else pc
    diagnostic: Dict[str, Any] = emulation_context["diagnostic"]
    diagnostic.update({
        "error": f"CPU interrupt {interrupt_number} requires native handling",
        "interrupt": {
            "number": interrupt_number,
            "instruction_address": hex(instruction_address),
            "next_pc": hex(pc),
        },
    })
    LOG.debug("Stopping at CPU interrupt %d at %s", interrupt_number,
              hex(instruction_address))
    uc.emu_stop()


def _is_no_return_api(api_name: str) -> bool:
    NO_RETURN_APIS = ["ExitProcess", "FatalExit", "ExitThread"]
    return api_name in NO_RETURN_APIS


def _is_simulated_api(api_name: str) -> bool:
    simulated_apis = [
        "Sleep", "GetProcessHeap", "RtlGetProcessHeap", "HeapAlloc",
        "RtlAllocateHeap", "HeapFree", "RtlFreeHeap", "HeapReAlloc",
        "RtlReAllocateHeap", "HeapSize", "RtlSizeHeap", "RtlFreeUnicodeString",
        "RtlFreeAnsiString", "RtlFreeOemString", "RtlDeleteBoundaryDescriptor"
    ]
    return api_name in simulated_apis


def _simulate_api(
        api_name: str, uc: Uc, sp: int, arch: Architecture,
        emulation_context: Dict[str, Any]) -> Tuple[int, int, Dict[str, Any]]:
    details: Dict[str, Any] = {"name": api_name}

    if api_name == "Sleep":
        return 0, 1, details

    if api_name in ["GetProcessHeap", "RtlGetProcessHeap"]:
        result = 0x12340000
        details["result"] = hex(result)
        return result, 0, details

    if api_name in ["HeapAlloc", "RtlAllocateHeap"]:
        flags = _read_api_argument(uc, sp, arch, 1)
        requested_size = _read_api_argument(uc, sp, arch, 2)
        result = _allocate_emulated_heap(uc, requested_size, emulation_context)
        details.update({
            "flags": hex(flags),
            "requested_size": requested_size,
            "result": hex(result),
        })
        return result, 3, details

    if api_name in ["HeapFree", "RtlFreeHeap"]:
        allocation = _read_api_argument(uc, sp, arch, 2)
        details["allocation"] = hex(allocation)
        return 1, 3, details

    if api_name in ["HeapReAlloc", "RtlReAllocateHeap"]:
        old_allocation = _read_api_argument(uc, sp, arch, 2)
        requested_size = _read_api_argument(uc, sp, arch, 3)
        result = _allocate_emulated_heap(uc, requested_size, emulation_context)
        old_size = emulation_context["heap_allocations"].get(old_allocation, 0)
        copy_size = min(old_size, requested_size)
        if copy_size > 0:
            try:
                old_data = uc.mem_read(old_allocation, copy_size)
                uc.mem_write(result, bytes(old_data))
            except UcError:
                pass
        details.update({
            "old_allocation": hex(old_allocation),
            "requested_size": requested_size,
            "result": hex(result),
        })
        return result, 4, details

    if api_name in ["HeapSize", "RtlSizeHeap"]:
        allocation = _read_api_argument(uc, sp, arch, 2)
        result = emulation_context["heap_allocations"].get(allocation, 0)
        details.update({
            "allocation": hex(allocation),
            "result": result,
        })
        return result, 3, details

    if api_name in [
            "RtlFreeUnicodeString", "RtlFreeAnsiString", "RtlFreeOemString"
    ]:
        descriptor = _read_api_argument(uc, sp, arch, 0)
        details["descriptor"] = hex(descriptor)
        details["descriptor_reset"] = False
        if descriptor != 0:
            descriptor_size = 8 if arch == Architecture.X86_32 else 16
            try:
                uc.mem_write(descriptor, bytes(descriptor_size))
                details["descriptor_reset"] = True
            except UcError:
                # Avoid a nested Frida RPC from the Unicorn callback. The
                # descriptor is only reset when its page was already mapped.
                pass
        return 0, 1, details

    if api_name == "RtlDeleteBoundaryDescriptor":
        descriptor = _read_api_argument(uc, sp, arch, 0)
        details["descriptor"] = hex(descriptor)
        return 0, 1, details

    raise NotImplementedError(f"No simulator for API '{api_name}'")


def _read_api_argument(uc: Uc, sp: int, arch: Architecture, index: int) -> int:
    if arch == Architecture.X86_32:
        argument_data = uc.mem_read(sp + 4 * (index + 1), 4)
        return cast(int, struct.unpack("<I", argument_data)[0])

    if arch == Architecture.X86_64:
        argument_registers = [
            UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9
        ]
        if index < len(argument_registers):
            value = uc.reg_read(argument_registers[index])
            assert isinstance(value, int)
            return value

        # Return address + 32 bytes of caller-provided shadow space.
        argument_data = uc.mem_read(sp + 0x28 + 8 * (index - 4), 8)
        return cast(int, struct.unpack("<Q", argument_data)[0])

    raise NotImplementedError(f"Architecture '{arch}' isn't supported")


def _allocate_emulated_heap(uc: Uc, requested_size: int,
                            emulation_context: Dict[str, Any]) -> int:
    process_controller: ProcessController = emulation_context[
        "process_controller"]
    page_size = process_controller.page_size
    allocation_size = max(1, min(requested_size, MAX_EMULATED_HEAP_ALLOCATION))
    mapped_size = ((allocation_size + page_size - 1) // page_size) * page_size
    candidate = cast(int, emulation_context["heap_next"])
    candidate -= candidate % page_size
    max_address = (0xe0000000 if process_controller.architecture
                   == Architecture.X86_32 else 0x00007f0000000000)
    LOG.debug("Allocating synthetic heap block: requested=%s mapped=%s",
              hex(requested_size), hex(mapped_size))

    # Only inspect Unicorn's local map here. Calling back into Frida from a
    # Unicorn hook can deadlock while the instrumented process is paused.
    for _attempt in range(MAX_HEAP_MAPPING_ATTEMPTS):
        if candidate + mapped_size >= max_address:
            break
        try:
            uc.mem_map(candidate, mapped_size, UC_PROT_READ | UC_PROT_WRITE)
            break
        except UcError:
            candidate += mapped_size + page_size
    else:
        candidate = max_address

    if candidate + mapped_size >= max_address:
        error = ("Unable to reserve a bounded synthetic heap range "
                 f"for {hex(mapped_size)} bytes")
        emulation_context["diagnostic"]["heap_error"] = error
        raise RuntimeError(error)

    emulation_context["heap_next"] = candidate + mapped_size + page_size
    emulation_context["heap_allocations"][candidate] = allocation_size
    return candidate
