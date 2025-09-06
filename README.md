# macsec — Mach-O File CheckSec: Just like checksec but for macOS !!!

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
