/*
 * unity.c — Single-TU build for MaskKit.
 *
 * Including all sources into one translation unit ensures that accesses to
 * globals like _NtAllocateVirtualMemory generate direct RIP-relative REL32
 * relocations (text→bss within the same .o file) instead of MinGW's
 * .refptr / ADDR64 cross-TU indirection, which requires runtime absolute
 * address patching that is incompatible with PIC shellcode.
 *
 * Link order matters:
 *   1. services.c  — defines all NT function pointer globals + patch_resolve
 *   2. mask.c      — mask_on / mask_off (uses _NtProtectVirtualMemory)
 *   3. hook.c      — hook_install (uses _NtProtectVirtualMemory, _NtWaitForSingleObject)
 *   4. masker.c    — go() entry (uses all of the above)
 */
#include "services.c"
#include "mask.c"
#include "hook.c"
#include "masker.c"
