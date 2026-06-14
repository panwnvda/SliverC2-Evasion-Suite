# crystal-exec Makefile
#
# Build pipeline (managed by `crystalkit build-ext`, but can also run manually):
#   1. Compile crystalexec.dll           (CRT-free shell runner DLL)
#   2. Wrap with Crystal Palace          → crystalexec.pico.bin
#   3. XOR-encrypt PICO → C header      → crystalexec_pico.h  (via crystalkit)
#   4. Compile crystal-exec.x64.dll      (extension with embedded PICO)
#
# Steps 2 and 3 require CRYSTAL_PALACE_HOME and the crystalkit binary.
# The `crystalkit build-ext` command runs all four steps automatically.
#
# Manual use (if you have Crystal Palace and crystalkit in PATH):
#   make crystalexec.dll
#   crystalkit gen-pico-header --input crystalexec.pico.bin --output crystalexec_pico.h \
#     --wrapper <path-to-postex-loader>
#   make crystal-exec.x64.dll

CC     := x86_64-w64-mingw32-gcc
CFLAGS := -Wall -Os -DBUILD_DLL -ffunction-sections -fdata-sections
LFLAGS := -shared -Wl,--subsystem,windows -s -Wl,--gc-sections

.PHONY: all clean step1 step4

# Step 1: compile the post-ex DLL (shell command runner)
step1: crystalexec.dll

crystalexec.dll: crystalexec.c
	$(CC) $(CFLAGS) -o $@ $< $(LFLAGS)

# Step 4: compile the extension DLL with embedded PICO (requires crystalexec_pico.h)
step4: crystal-exec.x64.dll

crystal-exec.x64.dll: crystal-exec.c crystalexec_pico.h
	$(CC) $(CFLAGS) -o $@ $< $(LFLAGS)

all: step1 step4

clean:
	rm -f crystalexec.dll crystalexec.pico.bin crystalexec_pico.h crystal-exec.x64.dll
