#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef NTAPI
#define NTAPI __stdcall
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

/* ── Named-section magic markers ──────────────────────────────────────────
 * Each named section (dll, mask, pico) is prefixed with a 4-byte magic in
 * the assembled shellcode blob.  find_resource_by_magic() scans forward from
 * the shellcode base to find them without relying on COFF relocation fixups.
 * The values are chosen to be unlikely to appear in normal code/data.       */
#define MAGIC_DLL  0xC001B008ul
#define MAGIC_MASK 0xC001B009ul
#define MAGIC_PICO 0xC001B007ul

/* ── RESOURCE layout ──────────────────────────────────────────────────────
 * Each named-section payload is wrapped as { uint32_t len; uint8_t value[] }
 * by the `preplen` spec directive.  find_resource_by_magic() returns a
 * pointer to this struct (the byte immediately following the magic marker).  */
typedef struct {
    uint32_t len;
    uint8_t  value[];
} RESOURCE;

/* Scan forward from the shellcode base for a 4-byte magic marker and return
 * a pointer to the data that follows it.  Implemented inline in loader.c.   */
void *find_resource_by_magic(uint32_t magic);

/* ── Import function tables ── */
typedef struct {
    HMODULE (*LoadLibraryA)(LPCSTR lpLibFileName);
    FARPROC (*GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
} IMPORTFUNCS;

typedef struct {
    struct { void *Code; void *Data; } Pico;
} MEMORY_LAYOUT;

/* ── PICO runtime stubs (from pico.c) ── */
uint32_t PicoDataSize(const char *src);
uint32_t PicoCodeSize(const char *src);
void     PicoLoad(IMPORTFUNCS *funcs, const char *src, char *code, char *data);
void    *PicoGetExport(const char *src, const char *code, int tag);

/* ── NT native prototypes ── */
typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID,
    ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI *NtWaitForSingleObject_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *NtFreeVirtualMemory_t)(HANDLE, PVOID *, PSIZE_T, ULONG);
typedef NTSTATUS (NTAPI *RtlExitUserThread_t)(NTSTATUS);

#ifndef MEM_COMMIT
#define MEM_COMMIT   0x1000
#define MEM_RESERVE  0x2000
#define MEM_RELEASE  0x8000
#define MEM_TOP_DOWN 0x100000
#endif
