/*
 * hooks.c — Crystal Palace-style attach hook samples for Sliver.
 *
 * Each hook is a normal function that takes the same prototype as the API it
 * shadows. To install one, add a line to loader.spec:
 *     attach   "NTDLL$NtAllocateVirtualMemory" "_HookedNtAllocateVirtualMemory"
 *     preserve "NTDLL$NtAllocateVirtualMemory" "_HookedNtAllocateVirtualMemory"
 *
 * The `attach` causes PalaceKit to redirect every callsite of the DFR symbol
 * to the local hook. The `preserve` exempts the hook's own forward-call so
 * it can reach the real API through a default thunk instead of looping back
 * into itself.
 *
 * This demo hook simply forwards the call unchanged — it is here to prove
 * the attach/preserve machinery wires end-to-end. Operators replace the
 * body with real evasion logic (call-stack spoofing, syscall trampolines,
 * argument sanitisation, etc.) in their own builds.
 *
 * NOTE: this file is currently NOT merged into the main loader because the
 * default loader.spec does not reference these hooks. Enable a sample hook
 * by uncommenting the `attach` / `preserve` lines in loader.spec.
 */
#include "loader.h"
#include "services.h"

/* Reachable from the spec via:
 *   attach   "NTDLL$NtAllocateVirtualMemory" "_HookedNtAllocateVirtualMemory"
 *   preserve "NTDLL$NtAllocateVirtualMemory" "_HookedNtAllocateVirtualMemory"
 * The preserve is what lets the hook tail-call into the real API: PalaceKit
 * skips the attach rewrite for any call to NTDLL$NtAllocateVirtualMemory that
 * originates from inside _HookedNtAllocateVirtualMemory, so this body's call
 * goes through the default PEB-resolver thunk instead of recursing.        */
NTSTATUS NTAPI _HookedNtAllocateVirtualMemory(
    HANDLE     ProcessHandle,
    PVOID     *BaseAddress,
    ULONG_PTR  ZeroBits,
    PSIZE_T    RegionSize,
    ULONG      AllocationType,
    ULONG      Protect)
{
    /* Operator-defined evasion goes here. For example:
     *   - Coerce Protect from RWX to RW so a later VirtualProtect carries
     *     the only "PE region went executable" event.
     *   - Pipe the call through an indirect-syscall stub.
     *   - Spoof the call stack via Draugr or similar.
     */
    if (Protect == PAGE_EXECUTE_READWRITE)
        Protect = PAGE_READWRITE;

    return NTDLL$NtAllocateVirtualMemory(
        ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

/* Stub kept for source compatibility with older Crystal Palace specs. */
void hook_GetProcAddress(void) {}
void hook_LoadLibraryW(void)   {}
void hook_ExitThread(void)     {}
void install_hooks(void)       {}
void remove_hooks(void)        {}
