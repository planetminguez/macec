# macec (macOS checksec)

macec is a checksec-like tool for macOS that inspects Mach-O binaries (thin and universal) and reports common security hardening features, linkage, and linked shared libraries. The binary it builds is called `macsec`.

Program: macsec — macOS checksec-like tool
Author: @planetminguez • <https://github.com/planetminguez/macec>
Support: Cash App $planetminguez

## Features

- PIE detection
- Stack Canary detection (symbol heuristic: looks for `___stack_chk_*`)
- NX (W^X) detection (reports disabled if any segment is both W and X)
- RPATH presence
- Code Signature presence (not validity)
- Encryption status (LC_ENCRYPTION_INFO[_64].cryptid)
- Linked shared libraries (LC_LOAD_*_DYLIB install names)
- Linkage detection: dynamic (`dyn`) vs. static/none (`stat`)
- Pretty colored ASCII UI (red headers, green rows), auto when TTY
- Plain output mode for scripting

## Build

Requirements: Apple clang (Xcode Command Line Tools) on macOS.

```
make
```

This produces the `macsec` binary in the project root.

### Install / Uninstall (interactive by default)

By default installs to `/usr/local/bin`. You can change PREFIX.

```
make install            # prompts: Proceed? [y/N]
PREFIX=/opt/homebrew make install

make uninstall          # prompts: Proceed? [y/N]
PREFIX=/opt/homebrew make uninstall
```

## Usage

Basic:

```
./macsec <mach-o-file> [more files...]
```

Pretty UI (auto when TTY) and colors (auto when TTY). You can force modes with flags:

```
./macsec --pretty --color /bin/ls
./macsec --plain  --no-color /bin/ls
```

Command-line flags:

- `--pretty` | `--plain` — force pretty table vs. key-value output
- `--color`  | `--no-color` — force or disable ANSI colors
- `-h`, `--help` — show usage

Columns (pretty mode):

- Arch: architecture slice (arm64, x86_64, etc.)
- Link: linkage — `dyn` if any LC_LOAD_*_DYLIB is present, otherwise `stat`
- PIE: Position Independent Executable — `on` if MH_PIE flag is set
- Can: Stack Canary — `on` if `___stack_chk_*` symbols are found (heuristic)
- NX: `on` if no W+X segments were found (i.e., NX effectively enforced)
- RPATH: `yes` if any LC_RPATH is present
- Sig: Code signature load command present (not validity)
- Enc: Encrypted — `yes` if LC_ENCRYPTION_INFO[_64].cryptid != 0
- Libs: linked shared libraries (install names), may be truncated with `...`

Examples

Pretty, with color:

```
./macsec --pretty --color /bin/ls
```

Plain, no color, good for scripting:

```
./macsec --plain --no-color /bin/ls
```

Multiple files (fat + thin binaries):

```
./macsec --pretty /usr/bin/ssh /bin/ls /usr/lib/dyld
```

Example output (pretty):

```
File: /bin/ls
+--------+------+-----+-----+-----+-------+-----+--------------------------+
| Arch   | Link | PIE | Can | NX  | RPATH | Sig | Libs                     |
+--------+------+-----+-----+-----+-------+-----+--------------------------+
| arm64  | dyn  | on  | on  | on  | no    | yes | /usr/lib/libutil.dylib...|
| x86_64 | dyn  | on  | on  | on  | no    | yes | /usr/lib/libutil.dylib...|
+--------+------+-----+-----+-----+-------+-----+--------------------------+
```

Exit status:

- 0 on success
- non-zero if any input file could not be analyzed

## Makefile behavior

- Very verbose by default: commands are echoed.
- Interactive by default: install and uninstall prompt with "Proceed? [y/N]".

## Contributing

PRs welcome! Please:
- Keep changes minimal and idiomatic to the existing code style.
- Add a brief description and example output for UI-affecting changes.

## License

MIT — see LICENSE.
