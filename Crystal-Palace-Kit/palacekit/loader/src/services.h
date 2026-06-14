#pragma once
#include <stdint.h>
#include "loader.h"

/* ROR13 PEB walk: resolve a function from its ROR13 hash */
void *patch_resolve(uint32_t hash);

/* Resolved NT functions (populated by go() at startup) */
extern NtAllocateVirtualMemory_t  _NtAllocateVirtualMemory;
extern NtProtectVirtualMemory_t   _NtProtectVirtualMemory;
extern NtCreateThreadEx_t         _NtCreateThreadEx;
extern NtWaitForSingleObject_t    _NtWaitForSingleObject;
extern NtFreeVirtualMemory_t      _NtFreeVirtualMemory;
extern RtlExitUserThread_t        _RtlExitUserThread;

/* Win32 functions resolved via GetProcAddress */
extern LPVOID (WINAPI *_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
extern BOOL   (WINAPI *_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
extern BOOL   (WINAPI *_VirtualFree)(LPVOID, SIZE_T, DWORD);
extern HMODULE(WINAPI *_LoadLibraryA)(LPCSTR);
