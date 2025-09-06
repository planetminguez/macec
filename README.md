# macsec — Mach-O File CheckSec for macOS

macsec is a lightweight CLI tool that analyzes Mach-O binaries on macOS and reports common security features and metadata. It parses Mach-O headers directly and also uses system tools to detect protections such as stack canaries and code signing. It can also determine how a binary was linked (dynamic vs. static) and, for universal (FAT) binaries, reports linkage per-architecture.

## Features

- File information: size, permissions, executable bit
- Mach-O metadata: file type, architecture, bitness (32/64), PIE
- Security features:
  - NX/DEP (assumed on modern macOS)
  - Stack canaries (__stack_chk_*)
  - PIE and ASLR
  - FORTIFY_SOURCE ("*_chk" symbols)
  - ARC (Objective-C retain/release symbols)
  - Code signing status
  - Hardened Runtime indicators (best-effort)
- Linkage detection:
  - Dynamic vs. static for single-arch Mach-O
  - Per-architecture linkage summary for universal (FAT) binaries

## Requirements

- macOS with Xcode Command Line Tools (for clang, otool, nm, strings, codesign)
- make (optional, for the provided Makefile)

## Build

Using the Makefile:

```
make
```

Or compile directly:

```
cc -Wall -Wextra -std=c99 -O3 -o macsec macsec.c
```

## Usage

Analyze a binary:

```
./macsec /path/to/binary
```

Example (system binary):

```
$ ./macsec /bin/ls
┌─ FILE INFORMATION
│ File Size        : 154624 bytes
│ Permissions      : 755
│ Executable       : Yes
│ File Type        : Universal Binary
│ Architecture     : Universal
│ Bit Mode         : 32-bit
│ Linkage          : Universal: x86_64=Dynamic, ARM64=Dynamic
└─

┌─ SECURITY FEATURES
│ NX Bit (DEP)        : ENABLED  - Prevents execution of data segments
│ Stack Canaries      : ENABLED  - Detects stack buffer overflows
│ PIE                 : ENABLED  - Position Independent Executable
│ ASLR                : ENABLED  - Address Space Layout Randomization
│ FORTIFY_SOURCE      : (varies)
│ ARC                 : (varies)
```

Example (small test binary):

```
$ ./macsec ./testt
┌─ FILE INFORMATION
│ File Type        : Executable
│ Architecture     : x86_64
│ Bit Mode         : 64-bit
│ Linkage          : Dynamic (uses dyld)
└─
```

## Notes & Limitations

- Truly static binaries are rare on modern macOS; most are dynamically linked via dyld.
- Hardened Runtime and entitlements are derived from codesign output and are best-effort indicators.
- Universal (FAT) per-arch linkage is reported from each slice’s Mach-O load commands.

## License

Choose and add a license (e.g., MIT) if you plan to publish this repository.

## Acknowledgments

- Uses standard macOS tooling: otool, nm, strings, codesign
- Mach-O parsing via public headers: <mach-o/loader.h>, <mach-o/fat.h>
# macec
