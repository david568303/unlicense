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

Some licensed applications include the executable name in their runtime
identity checks. To test such a target without overwriting the protected
input, write the dump into a separate runtime directory while preserving its
original filename:

```powershell
.\unlicense-win7-x86.exe C:\protected\Titanium.exe --verbose=true `
  --timeout=60 --native_trace_timeout=60000 `
  --active_wrapper_probe=false `
  --diagnostic_output=Titanium-diagnostics.json `
  --output_directory=C:\runtime-copy
```

This produces `C:\runtime-copy\Titanium.exe`. Populate that directory with
the target's normal DLLs, license files, and data before running the result.
Unlicense refuses to overwrite either the protected input or an existing file
at the identity-preserving output path.

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

Trace collection has its own bounded 10-to-30-second deadline, scaled from the
requested native trace window. Stalker is detached from every observed thread,
but its code cache is left for process teardown instead of being reclaimed
synchronously; on heavily threaded Windows 7 bundles that reclamation could
block Frida long enough to discard an otherwise successful trace.

The same native window also discovers import call sites that actually reach a
DLL export, even when the intermediate wrapper remains inside the unpacked
`.text` section. Only the existing six-byte Themida patterns are accepted, and
the host revalidates each call site before patching it. A call site observed
with different export destinations or without enough patch space is left
untouched and reported in the diagnostic JSON.
Frame-relative six-byte calls such as `FF 95 disp32` (`CALL [EBP+disp32]`) are
also supported. Their original register-relative slot is replaced in place by
an absolute reference to the reconstructed IAT. Forwarded exports that enter a
same-named KERNELBASE implementation retain the first public import module.

If neither static nor native wrapper recovery produces an import, Unlicense
preserves the dumped image's existing import directory and bypasses Scylla's
empty-table reconstruction. Automatic Scylla IAT searching is intentionally
disabled: its permissive advanced heuristic can return unrelated mapped memory
and malformed candidates have been observed to crash the native fixer before
Python can recover. The validation JSON records the selected
`iat_reconstruction_strategy` and runtime IAT range.

`--native_trace_timeout` and `--active_wrapper_probe` may be combined. The
explicit native-trace window always runs first on the dump target; a
sacrificial instance is started afterwards only for wrappers that remain
unresolved. The native timeout is never discarded merely because the
sacrificial fallback is enabled. Boolean values are case-insensitive, so both
`--active_wrapper_probe=false` and `--active_wrapper_probe=False` disable it.

If tracing the dump target is undesirable, 32-bit targets can instead trace
the normal startup path in one sacrificial target instance:

```powershell
.\unlicense-win7-x86.exe .\protected-x86.exe --verbose=true --timeout=60 `
  --active_wrapper_probe=true `
  --active_probe_timeout=5000 `
  --diagnostic_output=unlicense-diagnostics.json
```

The dump target remains blocked at its OEP. All unresolved wrapper addresses
are translated to the clone by module RVA, Stalker is installed once, and the
clone is released for the requested window so the program reaches APIs through
its genuine exception handlers and arguments. Resolved exports are translated
back by module and name instead of assuming equal ASLR addresses. No wrapper is
called from a synthetic thread and only one clone is live at a time.

`--active_probe_timeout` controls the natural-execution window (100 to 60000
milliseconds, default 5000). Sacrificial startup uses the main `--timeout`
budget and retries twice by default; use
`--active_probe_startup_retries=0` to disable retries. Cleanup does not depend
on a responsive Frida script: Unlicense force-terminates the clone and its child
process tree first, preventing timed-out RPCs from leaving instances behind.
Use this option only in a disposable, isolated VM snapshot because the clone
executes normally during the trace window. The primary target also retries once
by default when early WinLicense startup is intermittent; set
`--oep_startup_retries=0` to disable that retry.

The rebuilt output preserves the original executable overlay, which is
important for single-file bundles that append DLLs or metadata after the PE
sections. Unlicense also writes `unpacked_<target>.validation.json` beside the
dump. This bounded post-build check records the recovered entry point, section
layout, import/IAT directories, resource preservation, and overlay size.
The live target is terminated as soon as memory capture finishes, before the
file-only reconstruction phase.

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
    --oep_startup_retries=OEP_STARTUP_RETRIES
        Type: int
        Default: 1
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
