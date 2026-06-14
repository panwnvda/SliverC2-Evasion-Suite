// Package stage handles payload encryption and delivery.
package stage

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncBundle holds a ChaCha20-Poly1305–encrypted payload plus the key material
// that will be baked into the stager binary via ldflags.
type EncBundle struct {
	Ciphertext []byte
	Key        []byte // 32 bytes
	Nonce      []byte // 12 bytes
}

// Encrypt encrypts plaintext with a fresh random ChaCha20-Poly1305 key and nonce.
//
// Upgrade from CrystalSliver: AES-256-CBC → ChaCha20-Poly1305.
//   - Authenticated: any payload modification is detected at runtime.
//   - No padding oracle: AEAD construction is nonce-based.
//   - Unique ciphertext: fresh key+nonce every build, no repeating signatures.
func Encrypt(plaintext []byte) (*EncBundle, error) {
	key := make([]byte, chacha20poly1305.KeySize) // 32 bytes
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSize) // 12 bytes
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	ct := aead.Seal(nil, nonce, plaintext, nil)
	return &EncBundle{Ciphertext: ct, Key: key, Nonce: nonce}, nil
}
