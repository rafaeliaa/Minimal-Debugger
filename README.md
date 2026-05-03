# mdb — Minimal Debugger for 64-bit Linux ELF Binaries

`mdb` is a small educational debugger written in C for **64-bit, non-PIE ELF binaries on Linux**.

It uses `ptrace` for process control, `libelf` for ELF/symbol parsing, and `Capstone` for disassembly.

---

## Features

- Load symbols from ELF binaries
- Set software breakpoints using `int3`
- Set breakpoints by symbol name, raw address, or PLT symbol aliases such as `puts@plt`
- Handle pending breakpoints for symbols loaded at runtime
- Resolve symbols from shared libraries while the program is running
- Continue execution until the next breakpoint
- Single-step one instruction
- Disassemble code using Capstone
- Display symbol names near addresses when possible
- Restart the debugged program with optional arguments

---

## Requirements

This project is intended for Linux systems.

Install the required dependencies:

```bash
sudo apt update
sudo apt install build-essential libelf-dev libcapstone-dev
```

---

## Build

A `Makefile` is already provided, so build the project with:

```bash
make
```

To clean generated files:

```bash
make clean
```

---

## Usage

Run the debugger with a target binary:

```bash
./mdb ./target_program
```

Target programs should be compiled as **64-bit non-PIE ELF binaries**. For example:

```bash
gcc test.c -o test -no-pie
```

---

## Commands

| Command | Description |
|---|---|
| `b <symbol>` | Set a breakpoint at a symbol |
| `b *<hex>` | Set a breakpoint at a raw hexadecimal address |
| `l` | List all breakpoints |
| `d <num>` | Delete a breakpoint by number |
| `r [args...]` | Run or restart the target program |
| `c` | Continue execution until the next breakpoint or program exit |
| `si` | Single-step one instruction |
| `disas` | Disassemble instructions at the current position |
| `help` / `h` | Show the command list |
| `q` / `quit` | Exit the debugger |

---

## Example Session

```text
$ ./mdb ./test

(mdb) b main
Breakpoint 1 set at main

(mdb) r
[mdb] Starting ./test

Breakpoint 1 hit: main

(mdb) si
(mdb) disas
(mdb) c

[mdb] Program exited with code 0.
```

---

## Project Structure

```text
.
├── Makefile
├── mdb.c
├── LICENSE
└── README.md
```

---

## How It Works

At a high level, `mdb` loads ELF symbols using `libelf`, starts the target program under `ptrace`, inserts software breakpoints by replacing the first instruction byte with `0xCC`, handles `SIGTRAP` when breakpoints are hit, restores the original instruction byte, rewinds the instruction pointer, and uses Capstone to disassemble instructions around the current address.

It can also inspect runtime mappings through `/proc/<pid>/maps` to help resolve symbols from shared libraries.

---

## Limitations

- Supports **x86-64 Linux** only.
- Target programs should be compiled with `-no-pie`.
- Debug symbols are not required, but symbols make breakpoints and disassembly easier to read.
- This is an educational debugger, not a full replacement for GDB.
- Command parsing is simple and may not support complex quoted arguments.

---

## License

This project is licensed under the MIT License.
