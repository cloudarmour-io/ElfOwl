// ANCHOR: AES-256-GCM event encryption - Dec 26, 2025
// Encrypts events for confidentiality

package evidence

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// Cipher provides AES-256-GCM encryption for evidence
type Cipher struct {
	key []byte
}

// NewCipher creates a new cipher with the given base64-encoded key
func NewCipher(secretKey string) (*Cipher, error) {
	// Decode base64 key
	keyBytes, err := base64.StdEncoding.DecodeString(secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %w", err)
	}

	// AES-256 requires exactly 32 bytes
	if len(keyBytes) != 32 {
		return nil, fmt.Errorf("encryption key must be exactly 32 bytes (256 bits), got %d", len(keyBytes))
	}

	return &Cipher{
		key: keyBytes,
	}, nil
}

// Encrypt encrypts plaintext and returns ciphertext + nonce
func (c *Cipher) Encrypt(plaintext []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	// Generate random nonce
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)

	return ciphertext, nonce, nil
}

// Decrypt decrypts ciphertext using the provided nonce
func (c *Cipher) Decrypt(ciphertext, nonce []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
