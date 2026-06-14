/*
 * Minimal PICO implementation for Sliver.
 *
 * Crystal Palace's TCG generates a binary PICO format for the hook/mask/spoof
 * component. For Sliver, hooks and memory masking are disabled (Go runtime
 * incompatibility), so PICO only needs to host two no-op stub functions:
 *   setup_hooks(IMPORTFUNCS*)  — tag 0
 *   setup_memory(MEMORY_LAYOUT*) — tag 1
 *
 * PICO blob format (our simplified version, no TCG):
 *   [4] total_size
 *   [4] num_exports
 *   [num_exports × {[4]tag [4]code_offset}]
 *   [code bytes — PIC, can be executed directly]
 */
#include "loader.h"
#include "pico.h"
#include <stdint.h>

/* Tag IDs assigned by the spec evaluator */
int __tag_setup_hooks(void)  { return 0; }
int __tag_setup_memory(void) { return 1; }

/* PICO blob header accessors */
uint32_t PicoDataSize(const char *src) {
    /* We don't use a separate data region — return minimal size */
    (void)src;
    return 64;
}

uint32_t PicoCodeSize(const char *src) {
    if (!src) return 2;
    uint32_t total = *(const uint32_t *)src;
    return total;
}

void PicoLoad(IMPORTFUNCS *funcs, const char *src, char *code, char *data) {
    (void)funcs;
    (void)data;
    if (!src || !code) return;
    uint32_t total = *(const uint32_t *)src;
    /* Copy the entire PICO blob into the executable code region */
    for (uint32_t i = 0; i < total; i++)
        code[i] = src[i];
}

void *PicoGetExport(const char *src, const char *code, int tag) {
    if (!src || !code) return NULL;
    /* uint32_t total = *(const uint32_t *)src; */
    uint32_t num_exports = *(const uint32_t *)(src + 4);
    const uint8_t *table = (const uint8_t *)(src + 8);

    for (uint32_t i = 0; i < num_exports; i++) {
        uint32_t etag = *(const uint32_t *)(table + i * 8);
        uint32_t eoff = *(const uint32_t *)(table + i * 8 + 4);
        if ((int)etag == tag) {
            return (void *)(code + eoff);
        }
    }
    /* Tag not found — return pointer to a ret instruction */
    return (void *)code;
}

/* No-op stubs called via PicoGetExport */
void setup_hooks(IMPORTFUNCS *funcs) {
    (void)funcs;
    /* Hooks disabled for Sliver: Go sysmon preempts every 10ms,
       corrupting hook state and causing crashes.                */
}

void setup_memory(MEMORY_LAYOUT *layout) {
    (void)layout;
    /* Memory masking disabled for Sliver: Go goroutines run while
       XOR-masking is in progress = instant crash.                */
}
