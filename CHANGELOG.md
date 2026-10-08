# Changelog

## [Unreleased]
### Added
- Add a `--runtime_imports` option (Themida/WinLicense 2.x) that resolves import
  wrappers which defeat static emulation but point inside a loaded module
  (imports the packer redirected a few bytes into the real API) by mapping each
  target to the entry of the export whose function contains it. No wrapper code
  is executed
- Add an `--aggressive_imports` option (Themida/WinLicense 2.x) that lets the
  emulation-based import resolver map missing memory as zero (bounded by an
  instruction cap) instead of aborting. This can recover imports whose wrappers
  use anti-emulation tricks (e.g. calling real helper APIs during resolution).
  Resolutions are still validated against the known exports, so it won't add
  bogus imports, though it may resolve a wrapper incorrectly

### Fixed
- Fix OEP detection for Themida/WinLicense 2.x executables where the packer
  restores the original protection of the `.text` section at the section's
  base instead of the module's base (the OEP trap was never armed, causing a
  timeout)
- Make arming of the OEP trap robust to large/sparse `.text` sections by
  falling back to page-by-page protection when a bulk `Memory.protect` call
  fails
- Only "allow" read/write access violations that target the trapped OEP
  ranges. Faults elsewhere (used by the packer for control flow / anti-debug,
  or on unmapped memory) are now let through to the process's own exception
  handlers instead of being swallowed or turned into an unhandled crash
- Reject false-positive TLS callback detections by requiring the entry to be
  invoked by the Windows loader (return address in `ntdll`). This prevents
  "skipping" the real OEP (via a forced `ret`), which could crash the target
  before the OEP was reported
- Discard emulation-based import resolutions whose result isn't a known
  export. When the wrapper emulation stopped without reaching an API, a
  leftover register value was accepted as a resolved import, producing a bogus
  IAT entry that crashed the dumped binary (Themida/WinLicense 2.x)
- Report the number of import wrappers that couldn't be resolved (and their
  call sites in verbose mode) instead of silently producing a dump whose
  unresolved imports crash at runtime

### Changed
- Arm the OEP trap only on protection changes targeting the module base or the
  expected OEP ranges, instead of anywhere in the module. This avoids
  repeatedly re-trapping `.text` (and the burst of extra access violations that
  follows) while the packer runs, reducing the chance of tripping its
  timing-based anti-debugging
- Increase the default OEP detection timeout from 10 to 30 seconds
- Make the timeout error message suggest increasing `--timeout`

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
