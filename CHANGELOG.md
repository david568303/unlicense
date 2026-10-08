# Changelog

## [Unreleased]

### Added
- Add a reproducible CPython 3.8 build path for Windows 7 legacy targets.
- Add compact Themida 2.x wrapper diagnostics and in-memory PE candidate
  reporting.
- Add an opt-in native Frida Stalker fallback for exception-driven wrappers.
  It follows worker threads created by bundled applications and reports trace
  counters for troubleshooting paths that were not executed.
- Add opt-in, bounded natural-execution tracing in a sacrificial 32-bit target,
  translating call sites by image RVA and exports back by module and name.
- Add host-side hard deadlines to OEP setup and wrapper-tracing RPCs so a
  stalled Frida agent cannot block the controller indefinitely.
- Add bounded sacrificial-process startup retries with visible progress and use
  the requested OEP timeout instead of an unrelated fixed ten-second limit.
- Add a bounded JSON post-build validation report for the OEP, executable entry
  section, import directories, resources, and bundle overlay.
- Discover executed Themida 2.x imports from exported-API return addresses
  during native tracing. This recovers wrappers located inside a large unpacked
  `.text` section that the original outside-section heuristic cannot see.

### Fixed
- Revalidate every dynamically observed call site on the host and only patch
  six-byte Themida patterns with one stable export destination. Conflicting or
  ordinary five-byte calls are preserved rather than overwritten.
- Return native wrapper-trace results before Frida Stalker code-cache
  reclamation and scale the bounded collection deadline with the trace window.
  This prevents a successful 60-second trace of a heavily threaded bundle from
  being discarded by the previous fixed ten-second collection timeout.
- Normalize all CLI boolean values independently of capitalization. With Fire
  0.4, a value such as `--active_wrapper_probe=false` previously arrived as a
  truthy string and unexpectedly enabled the sacrificial trace.
- Always honor an explicit `--native_trace_timeout` when sacrificial tracing is
  also enabled. Native tracing now runs first and the clone is only used for
  wrappers that remain unresolved.
- Treat export control-flow loops as bounded, deterministic hash input instead
  of emitting per-function abort warnings, retain every export involved in a
  fingerprint collision, and defer ambiguous matches to emulation/native
  tracing instead of selecting an address by enumeration order.
- Replace synthetic per-wrapper thread execution with one bounded natural-run
  trace in a clone blocked at its real OEP. This lets exception-driven wrappers
  receive their genuine thread state and arguments.
- Terminate sacrificial process trees before making any cleanup RPC, preventing
  a timed-out Frida dispatcher from deadlocking cleanup and leaving multiple
  target instances alive.
- Handle an empty resolved-import set without requesting a zero-byte remote
  allocation, and report a destroyed dump session without an uncaught traceback.
- Simulate Windows heap APIs while resolving import wrappers instead of
  executing the real heap implementation with an incomplete emulated PEB.
- Bound wrapper emulation and keep synthetic heap allocation local to Unicorn
  so a paused target cannot stall a nested Frida RPC indefinitely.
- Simulate RTL string and boundary-descriptor cleanup calls used as wrapper
  noise, and report INT3-based wrappers without treating them as resolved.
- Avoid printing raw ANSI color sequences in the Windows 7 console.
- Re-arm OEP pages after `NtProtectVirtualMemory` completes and detect any
  protection range that overlaps the expected code, fixing missed OEP events
  in subsequent protected instances.
- Stop the EXE OEP-discovery exception handler from swallowing faults after the
  OEP is found, allowing INT3/access-violation import wrappers to reach their
  own Themida exception handlers during native probing.
- Recognize wrapper candidates that return without reaching an export as
  internal calls instead of corrupting them into fake imports.
- Use separate Scylla input/output paths and preserve the original PE overlay
  after LIEF rebuilding so appended bundle payloads are not truncated.
- Keep post-`NtProtectVirtualMemory` OEP rearming isolated to sacrificial
  targets and remove execute permission only, preventing the primary target
  from faulting while Themida is still preparing its code section.
- Retry intermittent primary and sacrificial OEP startup automatically.
- Preserve non-export call targets already located inside external DLLs instead
  of hash-matching them to unrelated exports, preventing observed false import
  rewrites such as an msvcrt target becoming `WLDAP32!ldap_set_dbg_routine`.

## [0.4.0] - 2023-08-14
### Added
- Add a `--no_imports` option that allows dumping PEs at the original entry point without fixing imports

### Fixed
- Fix a potential deadlock when dumping DLLs
- Improve version detection for Themida/Winlicense 2.x
- Improve version detection for Themida/Winlicense 3.x
- Improve .text section detection for Themida/Winlicense 3.x
- Fix `lief.not_found` exception happening when dumping certain MinGW EXEs
- Fix TLS callback detection for some 32-bit EXEs
- Handle wrapped imports from Themida/Winlicense 3.1.4.0
- Improve IAT search algorithm for Themida/Winlicense 3.x
- Allow unpacking EXEs that require admin privilege at medium integrity level
- Properly skip DllMain invocations on thread creation/deletion when dumping DLLs

### Changed
- Silence some misleading "error" logs that were emitted

## [0.3.0] - 2022-07-22
### Fixed
- Fix a couple of bugs with the IAT search and resolution for Themida/Winlicense 3.x
- Fix potentially invalid IAT truncations for Themida/WinLicense 3.x
- OEP detection now works in a runtime-agnostic manner (and handles virtualized entry points and Delphi executables)
- TLS callbacks are now properly detected and skipped

## [0.2.0] - 2022-05-31
### Added
- Handle unpacking of 32-bit and 64-bit DLLs
- Handle unpacking of 32-bit and 64-bit .NET assembly PEs (EXE only)
- OEP detection times out after 10 seconds by default. The duration can be
  changed through the CLI.

### Fixed
- Improve .text section detection for Themida/Winlicense 2.x

## [0.1.1] - 2022-04-06
### Fixed
- Fix IAT patching in some cases for Themida/Winlicense 3.x
- Fix inability to read remote chunks of memory bigger than 128 MiB
- Improve version detection to handle packed Delphi executables
- Improve IAT search algorithm for Themida/Winlicense 3.x
- Gracefully handle bitness mismatch between interpreter and target PEs
- Fix IAT truncation issue for IATs bigger than 4 KiB

## [0.1.0] - 2021-11-13

Initial release with support for Themida/Winlicense 2.x and 3.x.  
This release has been tested on Themida 2.4 and 3.0.
