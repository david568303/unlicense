"use strict";

const green = "\x1b[1;36m"
const reset = "\x1b[0m"

let allocatedBuffers = [];
let originalPageProtections = new Map();
let oepTracingListeners = [];
let oepReached = false;

// DLLs-related
let skipDllOepInstr32 = null;
let skipDllOepInstr64 = null;
let dllOepCandidate = null;

// TLS-related
let skipTlsInstr32 = null;
let skipTlsInstr64 = null;
let tlsCallbackCount = 0;

function log(message) {
    console.log(`${green}frida-agent${reset}: ${message}`);
}

function initializeTrampolines() {
    const instructionsBytes = new Uint8Array([
        0xC3,                                          // ret
        0xC2, 0x0C, 0x00,                              // ret 0x0C
        0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3,            // mov eax, 1; ret
        0xB8, 0x01, 0x00, 0x00, 0x00, 0xC2, 0x0C, 0x00 // mov eax, 1; ret 0x0C
    ]);

    let bufferPointer = Memory.alloc(instructionsBytes.length);
    Memory.protect(bufferPointer, instructionsBytes.length, 'rwx');
    bufferPointer.writeByteArray(instructionsBytes.buffer);

    skipTlsInstr64 = bufferPointer;
    skipTlsInstr32 = bufferPointer.add(0x1);
    skipDllOepInstr64 = bufferPointer.add(0x4);
    skipDllOepInstr32 = bufferPointer.add(0xA);
}

function rangeContainsAddress(range, address) {
    const rangeStart = range.base;
    const rangeEnd = range.base.add(range.size);
    return rangeStart.compare(address) <= 0 && rangeEnd.compare(address) > 0;
}

function addressInExpectedOepRanges(dumpedModule, expectedOepRanges, address) {
    for (const oepRange of expectedOepRanges) {
        const sectionStart = dumpedModule.base.add(oepRange[0]);
        const sectionRange = { base: sectionStart, size: oepRange[1] };
        if (rangeContainsAddress(sectionRange, address)) {
            return true;
        }
    }
    return false;
}

function notifyOepFound(dumpedModule, oepCandidate) {
    oepReached = true;
    
    // Make OEP ranges readable and writeable during the dumping phase
    setOepRangesProtection('rw-');
    // Remove hooks used to find the OEP
    removeOepTracingHooks();

    let isDotNetInitialized = isDotNetProcess();
    send({ 'event': 'oep_reached', 'OEP': oepCandidate, 'BASE': dumpedModule.base, 'DOTNET': isDotNetInitialized })
    let sync_op = recv('block_on_oep', function (_value) { });
    // Note: never returns
    sync_op.wait();
}

function isDotNetProcess() {
    return Process.findModuleByName("clr.dll") != null;
}

function makeOepRangesInaccessible(dumpedModule, expectedOepRanges) {
    // Ensure potential OEP ranges are not accessible
    expectedOepRanges.forEach((oepRange) => {
        const sectionStart = dumpedModule.base.add(oepRange[0]);
        const expectedSectionSize = oepRange[1];
        try {
            Memory.protect(sectionStart, expectedSectionSize, '---');
            originalPageProtections.set(sectionStart.toString(), expectedSectionSize);
        } catch (e) {
            // The section's virtual size (from the on-disk headers) can be
            // large (several MiB for packed executables) and may cover pages
            // that aren't currently committed, which makes a single
            // `Memory.protect` call over the whole range fail. Protecting the
            // range page by page ensures a single failing page doesn't leave
            // the whole trap unarmed (which would cause the OEP to never be
            // reached).
            protectRangePageByPage(sectionStart, expectedSectionSize);
        }
    });
}

function protectRangePageByPage(rangeStart, rangeSize) {
    const pageSize = Process.pageSize;
    for (let offset = 0; offset < rangeSize; offset += pageSize) {
        const pageAddr = rangeStart.add(offset);
        const chunkSize = Math.min(pageSize, rangeSize - offset);
        try {
            Memory.protect(pageAddr, chunkSize, '---');
            originalPageProtections.set(pageAddr.toString(), chunkSize);
        } catch (e) {
            // Skip pages that can't be protected (e.g. not committed).
        }
    }
}

function setOepRangesProtection(protection) {
    // Set pages' protection
    originalPageProtections.forEach((size, address_str, _map) => {
        Memory.protect(ptr(address_str), size, protection);
    });
}

function removeOepTracingHooks() {
    oepTracingListeners.forEach(listener => {
        listener.detach();
    })
    oepTracingListeners = [];
}

function registerExceptionHandler(dumpedModule, expectedOepRanges, moduleIsDll) {
    // Register an exception handler that'll detect the OEP
    Process.setExceptionHandler(exp => {
        let oepCandidate = exp.context.pc;
        let threadId = Process.getCurrentThreadId();

        if (exp.memory != null) {
            // Weird case where executing code actually only triggers a "read"
            // access violation on inaccessible pages. This can happen on some
            // 32-bit executables.
            if (exp.memory.operation == "read" && exp.memory.address.equals(exp.context.pc)) {
                // If we're in a TLS callback, the first argument is the
                // module's base address
                if (!moduleIsDll && isTlsCallback(exp.context, dumpedModule)) {
                    log(`TLS callback #${tlsCallbackCount} detected (at ${exp.context.pc}), skipping ...`);
                    tlsCallbackCount++;

                    // Modify PC to skip the callback's execution and return
                    skipTlsCallback(exp.context);
                    return true;
                }

                log(`OEP found (thread #${threadId}): ${oepCandidate}`);
                // Report the potential OEP
                notifyOepFound(dumpedModule, oepCandidate);
            }

            // If the access violation is a read/write on one of the pages we
            // deliberately made inaccessible (the expected OEP ranges), "allow"
            // the operation. Note: Pages will be reprotected on the next call
            // to `NtProtectVirtualMemory`.
            // Only handle faults that target our trapped ranges: the packer
            // triggers access violations of its own (for control flow and
            // anti-debugging) and may legitimately dereference memory outside
            // those ranges. Swallowing those would break the packer, and trying
            // to `Memory.protect` an unmapped address would throw and turn the
            // fault into an unhandled crash. Let such faults propagate to the
            // process's own exception handlers instead.
            if (exp.memory.operation != "execute" &&
                addressInExpectedOepRanges(dumpedModule, expectedOepRanges, exp.memory.address)) {
                try {
                    Memory.protect(exp.memory.address, Process.pageSize, "rw-");
                    return true;
                } catch (e) {
                    return false;
                }
            }
        }

        let expectionHandled = false;
        expectedOepRanges.forEach((oepRange) => {
            const sectionStart = dumpedModule.base.add(oepRange[0]);
            const sectionSize = oepRange[1];
            const sectionRange = { base: sectionStart, size: sectionSize };

            if (rangeContainsAddress(sectionRange, oepCandidate)) {
                // If we're in a TLS callback, the first argument is the
                // module's base address
                if (!moduleIsDll && isTlsCallback(exp.context, dumpedModule)) {
                    log(`TLS callback #${tlsCallbackCount} detected (at ${exp.context.pc}), skipping ...`);
                    tlsCallbackCount++;

                    // Modify PC to skip the callback's execution and return
                    skipTlsCallback(exp.context);
                    expectionHandled = true;
                    return;
                }
                
                if (moduleIsDll) {
                    // Save the potential OEP and and skip `DllMain` (`DLL_PROCESS_ATTACH`).
                    // Note: When dumping DLLs we have to release the loader
                    // lock before starting to dump.
                    // Other threads might call `DllMain` with the `DLL_THREAD_ATTACH`
                    // or `DLL_THREAD_DETACH` reasons later so we also skip the `DllMain`
                    // even after the OEP has been reached.
                    if (!oepReached) {
                        log(`OEP found (thread #${threadId}): ${oepCandidate}`);
                        dllOepCandidate = oepCandidate;
                    } 

                    skipDllEntryPoint(exp.context);
                    expectionHandled = true;
                    return;
                }

                // Report the potential OEP
                log(`OEP found (thread #${threadId}): ${oepCandidate}`);
                notifyOepFound(dumpedModule, oepCandidate);
            }
        });

        return expectionHandled;
    });
    log("Exception handler registered");
}

function isTlsCallback(exceptionCtx, dumpedModule) {
    if (Process.arch == "x64") {
        // If we're in a TLS callback, the first argument is the
        // module's base address
        let moduleBase = exceptionCtx.rcx;
        if (!moduleBase.equals(dumpedModule.base)) {
            return false;
        }
        // If we're in a TLS callback, the second argument is the
        // reason (from 0 to 3).
        let reason = exceptionCtx.rdx;
        if (reason.compare(ptr(4)) > 0) {
            return false;
        }
    }
    else if (Process.arch == "ia32") {
        let sp = exceptionCtx.sp;

        let moduleBase = sp.add(0x4).readPointer();
        if (!moduleBase.equals(dumpedModule.base)) {
            return false;
        }
        let reason = sp.add(0x8).readPointer();
        if (reason.compare(ptr(4)) > 0) {
            return false;
        }
    } else {
        return false;
    }

    // The checks above are only a heuristic (first argument is the module base,
    // second argument is a small "reason" value). The packer can reach the real
    // OEP (or a jump stub to it) with the module base in the first-argument
    // register and a small value in the second, which would match that
    // heuristic by coincidence. Genuine TLS callbacks are invoked by the
    // Windows loader (`ntdll`) via a `call`, so the return address at the top of
    // the stack points into `ntdll`. Requiring that rejects those false
    // positives: without it we would "skip" the OEP by forcing a `ret`, which,
    // when the code was reached by a `jmp` instead of a `call`, pops a
    // non-return value off the stack and transfers execution to a garbage
    // address, crashing the process before the OEP is ever reported.
    try {
        const returnAddress = exceptionCtx.sp.readPointer();
        const callerModule = Process.findModuleByAddress(returnAddress);
        if (callerModule == null || callerModule.name.toLowerCase() != "ntdll.dll") {
            const callerName = callerModule == null ? "<unknown>" : callerModule.name;
            log(`Ignoring TLS-callback-like entry at ${exceptionCtx.pc} ` +
                `(return address ${returnAddress} is in ${callerName}, not ntdll); ` +
                `treating it as a potential OEP`);
            return false;
        }
    } catch (e) {
        // If the stack can't be read for some reason, fall back to the
        // register/stack heuristic result (i.e. treat it as a TLS callback).
    }

    return true;
}

function skipTlsCallback(exceptionCtx) {
    if (Process.arch == "x64") {
        // Redirect to a `ret` instruction
        exceptionCtx.rip = skipTlsInstr64;
    }
    else if (Process.arch == "ia32") {
        // Redirect to a `ret 0xC` instruction
        exceptionCtx.eip = skipTlsInstr32;
    }
}

function skipDllEntryPoint(exceptionCtx) {
    if (Process.arch == "x64") {
        // Redirect to a `mov eax, 1; ret` instructions
        exceptionCtx.rip = skipDllOepInstr64;
    }
    else if (Process.arch == "ia32") {
        // Redirect to a `mov eax, 1; ret 0xC` instructions
        exceptionCtx.eip = skipDllOepInstr32;
    }
}

// Define available RPCs
rpc.exports = {
    setupOepTracing: function (moduleName, expectedOepRanges) {
        log(`Setting up OEP tracing for "${moduleName}"`);

        let targetIsDll = moduleName.endsWith(".dll");
        let dumpedModule = null;

        initializeTrampolines();

        // If the target isn't a DLL, it should be loaded already
        if (!targetIsDll) {
            dumpedModule = Process.findModuleByName(moduleName);
        }

        // Hook `ntdll.LdrLoadDll` on exit to get called at a point where the
        // loader lock is released. Needed to unpack (32-bit) DLLs.
        const loadDll = Module.findExportByName('ntdll', 'LdrLoadDll');
        const loadDllListener = Interceptor.attach(loadDll, {
            onLeave: function (_args) {
                // If `dllOepCandidate` is set, proceed with the dumping
                // but only once (for our target). Then let other executions go
                // through as it's not DLLs we're intersted in.
                if (dllOepCandidate != null && !oepReached) {
                    notifyOepFound(dumpedModule, dllOepCandidate);
                }
            }
        });
        oepTracingListeners.push(loadDllListener);

        let exceptionHandlerRegistered = false;
        const ntProtectVirtualMemory = Module.findExportByName('ntdll', 'NtProtectVirtualMemory');
        if (ntProtectVirtualMemory != null) {
            const ntProtectVirtualMemoryListener = Interceptor.attach(ntProtectVirtualMemory, {
                onEnter: function (args) {
                    let addr = args[1].readPointer();
                    // Arm the OEP trap when a protection change targets the
                    // module base or one of the expected OEP ranges (the
                    // `.text` section). The `BaseAddress` passed to
                    // `NtProtectVirtualMemory` is rounded down to a page
                    // boundary by the kernel, so when the packer restores the
                    // original protection of the `.text` section this address
                    // is the section's base (e.g. `base + 0x1000`), not the
                    // module's base. Only matching the module base would miss
                    // that common case and leave the trap unarmed (the OEP would
                    // then never be reached, timing out).
                    // We intentionally do NOT arm on protection changes to the
                    // rest of the module (e.g. the packer's own sections):
                    // re-arming makes the OEP ranges inaccessible again, which
                    // triggers a burst of extra access violations as the packer
                    // keeps running. That overhead can trip the packer's
                    // timing-based anti-debugging, so keep the trap as quiet as
                    // possible while still catching the entry point.
                    if (dumpedModule != null &&
                        (addr.equals(dumpedModule.base) ||
                         addressInExpectedOepRanges(dumpedModule, expectedOepRanges, addr))) {
                        // Reset potential OEP ranges to not accessible to
                        // (hopefully) catch the entry point next time.
                        makeOepRangesInaccessible(dumpedModule, expectedOepRanges);
                        if (!exceptionHandlerRegistered) {
                            registerExceptionHandler(dumpedModule, expectedOepRanges, targetIsDll);
                            exceptionHandlerRegistered = true;
                        }
                    }
                }
            });
            oepTracingListeners.push(ntProtectVirtualMemoryListener);
        }

        // Hook `ntdll.RtlActivateActivationContextUnsafeFast` on exit as a mean
        // to get called after new PE images are loaded and before their entry
        // point is called. Needed to unpack DLLs.
        let initializeFusionHooked = false;
        const activateActivationContext = Module.findExportByName('ntdll', 'RtlActivateActivationContextUnsafeFast');
        const activateActivationContextListener = Interceptor.attach(activateActivationContext, {
            onLeave: function (_args) {
                if (dumpedModule == null) {
                    dumpedModule = Process.findModuleByName(moduleName);
                    if (dumpedModule == null) {
                        // Module isn't loaded yet
                        return;
                    }
                    log(`Target module has been loaded (thread #${this.threadId}) ...`);
                }
                // After this, the target module is loaded.

                if (targetIsDll) {
                    if (!exceptionHandlerRegistered) {
                        makeOepRangesInaccessible(dumpedModule, expectedOepRanges);
                        registerExceptionHandler(dumpedModule, expectedOepRanges, targetIsDll);
                        exceptionHandlerRegistered = true;
                    }
                }

                // Hook `clr.InitializeFusion` if present.
                // This is used to detect a good point during the CLR's
                // initialization, to dump .NET EXE assemblies
                const initializeFusion = Module.findExportByName('clr', 'InitializeFusion');
                if (initializeFusion != null && !initializeFusionHooked) {
                    const initializeFusionListener = Interceptor.attach(initializeFusion, {
                        onEnter: function (_args) {
                            log(`.NET assembly loaded (thread #${this.threadId})`);
                            notifyOepFound(dumpedModule, '0');
                        }
                    });
                    oepTracingListeners.push(initializeFusionListener);
                    initializeFusionHooked = true;
                }
            }
        });
        oepTracingListeners.push(activateActivationContextListener);
    },
    notifyDumpingFinished: function () {
        // Make OEP executable again once dumping is finished
        setOepRangesProtection('rwx');
    },
    getArchitecture: function () { return Process.arch; },
    getPointerSize: function () { return Process.pointerSize; },
    getPageSize: function () { return Process.pageSize; },
    findModuleByAddress: function (address) {
        return Process.findModuleByAddress(ptr(address));
    },
    findRangeByAddress: function (address) {
        return Process.findRangeByAddress(ptr(address));
    },
    findExportByName: function (moduleName, exportName) {
        const mod = Process.findModuleByName(moduleName);
        if (mod == null) {
            return null;
        }

        return mod.findExportByName(exportName);
    },
    enumerateModules: function () {
        const modules = Process.enumerateModules();
        const moduleNames = modules.map(module => {
            return module.name;
        });
        return moduleNames;
    },
    enumerateModuleRanges: function (moduleName) {
        let ranges = Process.enumerateRangesSync("r--");
        return ranges.filter(range => {
            const module = Process.findModuleByAddress(range.base);
            return module != null && module.name.toUpperCase() == moduleName.toUpperCase();
        });
    },
    enumerateExportedFunctions: function (excludedModuleName) {
        const modules = Process.enumerateModules();
        const exports = modules.reduce((acc, m) => {
            if (m.name != excludedModuleName) {
                m.enumerateExports().forEach(e => {
                    if (e.type == "function" && e.hasOwnProperty('address')) {           
                        acc.push(e);
                    }
                });
            }

            return acc;
        }, []);
        return exports;
    },
    allocateProcessMemory: function (size, near) {
        const sizeRounded = size + (Process.pageSize - size % Process.pageSize);
        const addr = Memory.alloc(sizeRounded, { near: ptr(near), maxDistance: 0xff000000 });
        allocatedBuffers.push(addr)
        return addr;
    },
    queryMemoryProtection: function (address) {
        return Process.getRangeByAddress(ptr(address))['protection'];
    },
    setMemoryProtection: function (address, size, protection) {
        return Memory.protect(ptr(address), size, protection);
    },
    readProcessMemory: function (address, size) {
        return Memory.readByteArray(ptr(address), size);
    },
    writeProcessMemory: function (address, bytes) {
        return Memory.writeByteArray(ptr(address), bytes);
    },
    findEnclosingExport: function (address) {
        // Resolve an address that lies inside a loaded module to the export
        // whose function contains it (the export with the largest entry that is
        // <= `address`, within the same module). Used to resolve imports that
        // the packer redirected a few bytes into the real API.
        const addr = ptr(address);
        const module = Process.findModuleByAddress(addr);
        if (module == null) {
            return null;
        }
        let best = null;
        module.enumerateExports().forEach(exp => {
            if (exp.type != "function") {
                return;
            }
            // exp.address <= addr, and the closest such export
            if (exp.address.compare(addr) <= 0 &&
                (best == null || exp.address.compare(best.address) > 0)) {
                best = exp;
            }
        });
        if (best == null) {
            return null;
        }
        return { address: best.address.toString(), name: best.name };
    }
};
