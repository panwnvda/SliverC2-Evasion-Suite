//go:build windows

package main

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

type PROCESSENTRY32W struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [syscall.MAX_PATH]uint16
}

// findPIDByName returns the PID of the first running process whose name
// matches (case-insensitive). Returns an error if not found.
func findPIDByName(name string) (uint32, error) {
	snap, _, _ := procSnapshot.Call(TH32CS_SNAPPROCESS, 0)
	if snap == ^uintptr(0) {
		return 0, fmt.Errorf("CreateToolhelp32Snapshot failed")
	}
	defer syscall.CloseHandle(syscall.Handle(snap))

	var entry PROCESSENTRY32W
	entry.Size = uint32(unsafe.Sizeof(entry))

	r, _, _ := procProc32First.Call(snap, uintptr(unsafe.Pointer(&entry)))
	for r != 0 {
		if strings.EqualFold(syscall.UTF16ToString(entry.ExeFile[:]), name) {
			return entry.ProcessID, nil
		}
		r, _, _ = procProc32Next.Call(snap, uintptr(unsafe.Pointer(&entry)))
	}
	return 0, fmt.Errorf("process not found: %s", name)
}
