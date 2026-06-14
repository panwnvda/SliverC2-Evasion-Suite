package stage

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncBundle holds the output of Encrypt.
type EncBundle struct {
	Ciphertext []byte
	Key        []byte // 32 bytes
	Nonce      []byte // 12 bytes
}

// Encrypt encrypts plaintext with a fresh random ChaCha20-Poly1305 key + nonce.
func Encrypt(plaintext []byte) (*EncBundle, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &EncBundle{
		Ciphertext: aead.Seal(nil, nonce, plaintext, nil),
		Key:        key,
		Nonce:      nonce,
	}, nil
}
