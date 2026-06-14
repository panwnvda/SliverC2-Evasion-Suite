/*
 * cfg.c — CFG bypass stub (disabled for Sliver).
 *
 * Crystal Kit uses SetProcessValidCallTargets to add PICO's code region as a
 * valid CFG call target. Calling GetModuleHandleA/GetProcAddress requires the
 * Win32 IAT, which is unavailable in PIC shellcode.  Since PICO's two no-op
 * stubs don't trigger CFG enforcement in practice, this is a no-op stub.
 */
#include "loader.h"

void cfg_add_region(void *base, SIZE_T size) {
    (void)base;
    (void)size;
}
