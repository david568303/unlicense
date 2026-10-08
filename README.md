# Unlicense <img src="https://raw.githubusercontent.com/ergrelet/unlicense/dev/assets/unlicense.ico" width="40">

[![GitHub release](https://img.shields.io/github/release/ergrelet/unlicense.svg)](https://github.com/ergrelet/unlicense/releases) [![Minimum Python version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/) ![CI status](https://github.com/ergrelet/unlicense/actions/workflows/check.yml/badge.svg?branch=main)

A Python 3 tool to dynamically unpack executables protected with
Themida/WinLicense 2.x and 3.x.

Warning: This tool will execute the target executable. Make sure to use this
tool in a VM if you're unsure about what the target executable does.

Note: You need to use a 32-bit Python interpreter to dump 32-bit executables.

### Windows 7 legacy targets

The existing published release build uses Python 3.9 or newer and therefore
cannot run on Windows 7.  For a target that only runs on Windows 7, build
Unlicense with **CPython 3.8.10**, the final CPython release with Windows 7
support:

```powershell
# Build x64 Unlicense with a 64-bit Python 3.8 interpreter.
powershell -ExecutionPolicy Bypass -File .\scripts\build_win7.ps1 `
  -PythonPath C:\Python38-x64\python.exe

# Build x86 Unlicense separately with a 32-bit Python 3.8 interpreter.
powershell -ExecutionPolicy Bypass -File .\scripts\build_win7.ps1 `
  -PythonPath C:\Python38-x86\python.exe
```

Run the matching build and the protected target together inside the same
Windows 7 SP1 guest (or an isolated Windows 7 test machine):

```powershell
.\unlicense-win7-x86.exe .\protected-x86.exe --verbose=true --timeout=60 `
  --diagnostic_output=unlicense-diagnostics.json
```

The optional diagnostic report contains PE metadata, loaded-module names,
small byte windows around detected import wrappers, and emulation failures. It
does not contain the complete protected or unpacked executable. Themida 2.x
heap-based wrappers are emulated without entering the real Windows heap, which
allows import resolution to continue past calls such as `RtlAllocateHeap`.
When native tracing is enabled, the report also stores per-wrapper probe
addresses, counters, timeouts, and errors so failures can be diagnosed without
sharing the protected executable.

Exception-driven wrappers can optionally be resolved by briefly executing the
target after its OEP under Frida Stalker:

```powershell
.\unlicense-win7-x86.exe .\protected-x86.exe --verbose=true --timeout=60 `
  --native_trace_timeout=1500 `
  --diagnostic_output=unlicense-diagnostics.json
```

The native fallback is disabled by default because it lets the target execute
normally for the requested number of milliseconds. Use it only in an isolated
test system where target-side effects are acceptable.

If passive tracing reports `wrapper_hits=0`, the remaining wrappers were not
executed naturally. For 32-bit targets, an experimental active probe can invoke
each unresolved call site in a separate sacrificial target instance:

```powershell
.\unlicense-win7-x86.exe .\protected-x86.exe --verbose=true --timeout=60 `
  --active_wrapper_probe=true `
  --active_probe_timeout=5000 `
  --diagnostic_output=unlicense-diagnostics.json
```

The original dump target remains blocked at its OEP and is never actively
probed. Call sites are translated to the sacrificial process by module RVA, and
resolved exports are translated back by module and export name instead of
assuming equal ASLR addresses. A contained per-wrapper timeout terminates only
the synthetic probe thread and reuses the already prepared sacrificial target,
avoiding repeated OEP initialization and multi-instance stalls. If the process
or a Frida RPC fails, Unlicense discards that instance and starts a fresh one
for the next wrapper. Successful wrapper resolutions are committed one at a
time, so a later crash cannot erase earlier results.

Inside the sacrificial process, the probe supplies synthetic zero-filled
arguments first, then retries unresolved wrappers with readable-pointer and
mixed-value profiles. It temporarily places a jump to controlled stack cleanup
after each probed CALL and restores the original bytes immediately afterward.
Once the wrapper reaches its final Windows API, the tracer records the address
and skips the API body instead of invoking it with synthetic arguments.
Intermediate APIs used internally by the wrapper still execute and may have
side effects, so the probe remains experimental.
Use this option only in a disposable, isolated VM snapshot. It currently
supports 32-bit targets only. `--native_trace_timeout` is intentionally ignored
while active probing is enabled so the dump target is never released from its
OEP. Each active call is isolated in a probe thread and limited to five seconds
by default so a non-returning wrapper does not stall the whole dump. Adjust
`--active_probe_timeout` between 100 and 60000 milliseconds for unusually slow
wrappers; the default is 5000 milliseconds. Host-side deadlines also protect
OEP setup, trace setup, and trace collection if the injected agent itself stops
replying. Sacrificial startup uses the main `--timeout` budget, reports progress
every five seconds, and retries twice by default; use
`--active_probe_startup_retries=0` to disable those retries. The diagnostic JSON
records each argument-profile attempt, its errors, and the last 64 exports
reached by the active probe.

The rebuilt output preserves the original executable overlay, which is
important for single-file bundles that append DLLs or metadata after the PE
sections. Unlicense also writes `unpacked_<target>.validation.json` beside the
dump. This bounded post-build check records the recovered entry point, section
layout, import/IAT directories, resource preservation, and overlay size.

Unlicense is not a remote dumper: Frida starts the target locally and Scylla
opens that local process ID.  Consequently, running Unlicense on Windows 10/11
while the target runs in a Windows 7 VM will not work without replacing the
Scylla dumping backend.  If the protected target detects virtual machines, use
an isolated physical/dual-boot Windows 7 system instead.  Take a snapshot (when
using a VM) and disconnect unneeded network access before executing a target.

The guest should have Windows 7 SP1, the Universal CRT update (KB2999226), and a
Windows 7-compatible Visual C++ runtime, such as the 14.29.x redistributable.
The Unlicense build architecture must match the target architecture.

## Features

* Handles Themida/Winlicense 2.x and 3.x
* Handles 32-bit and 64-bit PEs (EXEs and DLLs)
* Handles 32-bit and 64-bit .NET assemblies (EXEs only)
* Recovers the original entry point (OEP) automatically
* Recovers the (obfuscated) import table automatically

## Known Limitations

* Doesn't handle .NET assembly DLLs
* Doesn't produce runnable dumps in most cases
* Resolving imports for 32-bit executables packed with Themida 2.x is pretty slow
* Requires a valid license file to unpack WinLicense-protected executables that
  require license files to start

## How To

### Download

You can either download the PyInstaller-generated executables from the "Releases"
section or fetch the project with `git` and install it with `pip`:
```
pip install git+https://github.com/ergrelet/unlicense.git
```

### Use

If you don't want to deal the command-line interface (CLI) you can simply
drag-and-drop the target binary on the appropriate (32-bit or 64-bit) `unlicense`
executable (which is available in the "Releases" section).

Otherwise here's what the CLI looks like:
```
unlicense --help
NAME
    unlicense.exe - Unpack executables protected with Themida/WinLicense 2.x and 3.x

SYNOPSIS
    unlicense.exe PE_TO_DUMP <flags>

DESCRIPTION
    Unpack executables protected with Themida/WinLicense 2.x and 3.x

POSITIONAL ARGUMENTS
    PE_TO_DUMP
        Type: str

FLAGS
    --verbose=VERBOSE
        Type: bool
        Default: False
    --pause_on_oep=PAUSE_ON_OEP
        Type: bool
        Default: False
    --no_imports=NO_IMPORTS
        Type: bool
        Default: False
    --force_oep=FORCE_OEP
        Type: Optional[Optional]
        Default: None
    --target_version=TARGET_VERSION
        Type: Optional[Optional]
        Default: None
    --timeout=TIMEOUT
        Type: int
        Default: 10
    --diagnostic_output=DIAGNOSTIC_OUTPUT
        Type: Optional[Optional]
        Default: None
    --native_trace_timeout=NATIVE_TRACE_TIMEOUT
        Type: int
        Default: 0
    --active_wrapper_probe=ACTIVE_WRAPPER_PROBE
        Type: bool
        Default: False
    --active_probe_timeout=ACTIVE_PROBE_TIMEOUT
        Type: int
        Default: 5000
    --active_probe_startup_retries=ACTIVE_PROBE_STARTUP_RETRIES
        Type: int
        Default: 2

NOTES
    You can also use flags syntax for POSITIONAL ARGUMENTS
```
