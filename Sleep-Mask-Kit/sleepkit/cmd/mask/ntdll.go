//go:build windows && amd64

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modNtdll = windows.NewLazySystemDLL("ntdll.dll")

	procNtAllocateVirtualMemory = modNtdll.NewProc("NtAllocateVirtualMemory")
	procNtProtectVirtualMemory  = modNtdll.NewProc("NtProtectVirtualMemory")
	procNtCreateThreadEx        = modNtdll.NewProc("NtCreateThreadEx")
)

const (
	memCommitReserve = uintptr(windows.MEM_COMMIT | windows.MEM_RESERVE)
	threadAllAccess  = uintptr(0x1FFFFF)
	currentProcess   = ^uintptr(0) // (HANDLE)-1
)

// ntAlloc allocates PAGE_READWRITE memory in the current process.
//
// NtAllocateVirtualMemory(NtCurrentProcess, &Base, 0, &Size,
//
//	MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
func ntAlloc(size uintptr) (uintptr, error) {
	var base uintptr
	sz := size
	r, _, _ := procNtAllocateVirtualMemory.Call(
		currentProcess,
		uintptr(unsafe.Pointer(&base)),
		0,
		uintptr(unsafe.Pointer(&sz)),
		memCommitReserve,
		uintptr(windows.PAGE_READWRITE),
	)
	if r != 0 {
		return 0, fmt.Errorf("NtAllocateVirtualMemory: 0x%X", r)
	}
	return base, nil
}

// ntProtect changes the protection of a memory region in the current process.
//
// NtProtectVirtualMemory(NtCurrentProcess, &Base, &Size, NewProt, &OldProt)
func ntProtect(base, size uintptr, prot uint32) error {
	var old uint32
	r, _, _ := procNtProtectVirtualMemory.Call(
		currentProcess,
		uintptr(unsafe.Pointer(&base)),
		uintptr(unsafe.Pointer(&size)),
		uintptr(prot),
		uintptr(unsafe.Pointer(&old)),
	)
	if r != 0 {
		return fmt.Errorf("NtProtectVirtualMemory: 0x%X", r)
	}
	return nil
}

// ntCreateThread starts a new thread in the current process at entry.
//
// NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nil, NtCurrentProcess,
//
//	entry, nil, 0, 0, 0, 0, nil)
//
// Returns the thread handle (caller must CloseHandle when done).
func ntCreateThread(entry uintptr) (windows.Handle, error) {
	var hThread uintptr
	r, _, _ := procNtCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&hThread)),
		threadAllAccess,
		0,
		currentProcess,
		entry,
		0, // Argument
		0, // CreateFlags (0 = start immediately)
		0, // ZeroBits
		0, // StackSize (system default)
		0, // MaxStackSize (system default)
		0, // AttributeList
	)
	if r != 0 {
		return 0, fmt.Errorf("NtCreateThreadEx: 0x%X", r)
	}
	return windows.Handle(hThread), nil
}
