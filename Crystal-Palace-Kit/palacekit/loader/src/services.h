#pragma once
#include <stdint.h>
#include "loader.h"

/* ROR13 PEB walk: resolve a function from its ROR13 hash.
 * Used by the default DFR thunks PalaceKit emits at link time for any
 * MODULE$FUNCTION symbol that wasn't attached to a local hook.
 */
void *patch_resolve(uint32_t hash);

/* ── DFR (Dynamic Function Resolution) declarations ──────────────────────────
 * These are declared as plain function externs — the COFF will contain
 * unresolved external symbols, and PalaceKit's linker will resolve them at
 * link time either:
 *   • to a local hook function specified via `attach` in the spec, or
 *   • to a freshly-emitted PEB-resolver thunk that calls patch_resolve(hash)
 *     and tail-jumps to the resolved API.
 * Callers use them as if they were normal functions:
 *     LPVOID buf = KERNEL32$VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_RW);
 * Crystal Palace uses the same convention.
 */
NTSTATUS NTAPI NTDLL$NtAllocateVirtualMemory(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
NTSTATUS NTAPI NTDLL$NtProtectVirtualMemory (HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
NTSTATUS NTAPI NTDLL$NtCreateThreadEx       (PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
NTSTATUS NTAPI NTDLL$NtWaitForSingleObject  (HANDLE, BOOLEAN, PLARGE_INTEGER);
NTSTATUS NTAPI NTDLL$NtFreeVirtualMemory    (HANDLE, PVOID *, PSIZE_T, ULONG);
HMODULE  WINAPI KERNEL32$LoadLibraryA       (LPCSTR);

/* ── Legacy global pointer pattern (kept for source compatibility) ─────────
 * The pre-DFR loader used these globals and resolve_all() to populate them.
 * They are now thin wrappers around the DFR thunks and are NOT used by the
 * default loader, but downstream code (and the optional cleanup component)
 * may still rely on the symbols, so we expose them as forwarding inlines.
 */
extern NtAllocateVirtualMemory_t  _NtAllocateVirtualMemory;
extern NtProtectVirtualMemory_t   _NtProtectVirtualMemory;
extern NtCreateThreadEx_t         _NtCreateThreadEx;
extern NtWaitForSingleObject_t    _NtWaitForSingleObject;
extern NtFreeVirtualMemory_t      _NtFreeVirtualMemory;
extern RtlExitUserThread_t        _RtlExitUserThread;
extern HMODULE(WINAPI *_LoadLibraryA)(LPCSTR);

/* No-op kept for source compatibility — DFR thunks resolve per-call. */
void resolve_all(void);
