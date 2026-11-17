package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// Seal encrypts plaintext with key using AES-256-GCM and returns
// nonce|ciphertext. It protects RADIUS shared secrets (and later TOTP
// seeds) at rest (TECH_SPEC §5); the key is ENC_KEY, decrypted only in
// memory during verification.
func Seal(key [32]byte, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("crypto: plaintext must not be empty")
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("crypto: seal cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: seal gcm: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: seal nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Open decrypts a Seal payload with key. It fails closed on any
// tampering, truncation, or wrong key — callers must treat an error as
// "secret unavailable", never fall back to a default.
func Open(key [32]byte, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("crypto: open cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: open gcm: %w", err)
	}
	if len(sealed) < aead.NonceSize() {
		return nil, errors.New("crypto: sealed payload too short")
	}
	nonce, ciphertext := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("crypto: sealed payload failed authentication")
	}
	return plain, nil
}
