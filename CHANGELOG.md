# Changelog

## [Unreleased]

### Added
- Add a reproducible CPython 3.8 build path for Windows 7 legacy targets.
- Add compact Themida 2.x wrapper diagnostics and in-memory PE candidate
  reporting.
- Add an opt-in native Frida Stalker fallback for exception-driven wrappers.
  It follows worker threads created by bundled applications and reports trace
  counters for troubleshooting paths that were not executed.
- Add an experimental, opt-in active probe for 32-bit exception-driven import
  wrappers that are never reached during passive tracing.
- Run active wrapper probes in a sacrificial target instance, translate call
  sites by image RVA, and map resolved exports back by module and name so the
  dump target remains intact even if speculative execution crashes.
- Commit sacrificial probe results one wrapper at a time and restart the probe
  process for every wrapper so crashes and silent global-state corruption do
  not affect later attempts.
- Add a bounded, configurable timeout for each active wrapper probe.

### Fixed
- Skip the final imported API during active wrapper probing so synthetic
  arguments cannot terminate or corrupt the target process.
- Simulate Windows heap APIs while resolving import wrappers instead of
  executing the real heap implementation with an incomplete emulated PEB.
- Bound wrapper emulation and keep synthetic heap allocation local to Unicorn
  so a paused target cannot stall a nested Frida RPC indefinitely.
- Simulate RTL string and boundary-descriptor cleanup calls used as wrapper
  noise, and report INT3-based wrappers without treating them as resolved.
- Avoid printing raw ANSI color sequences in the Windows 7 console.

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
