// ANCHOR: HMAC-SHA256 event signing - Dec 26, 2025
// Signs events for integrity and authenticity verification

package evidence

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Signer provides HMAC-SHA256 signing for evidence
type Signer struct {
	key []byte
}

// NewSigner creates a new signer with the given base64-encoded key
func NewSigner(secretKey string) (*Signer, error) {
	// Decode base64 key
	keyBytes, err := base64.StdEncoding.DecodeString(secretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signing key: %w", err)
	}

	// Ensure minimum key length (32 bytes for HMAC-SHA256)
	if len(keyBytes) < 32 {
		return nil, fmt.Errorf("signing key must be at least 32 bytes (got %d)", len(keyBytes))
	}

	// Use first 32 bytes
	return &Signer{
		key: keyBytes[:32],
	}, nil
}

// Sign computes HMAC-SHA256 signature of data
func (s *Signer) Sign(data []byte) string {
	h := hmac.New(sha256.New, s.key)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// Verify checks if the signature matches the data
func (s *Signer) Verify(data []byte, signature string) bool {
	expected := s.Sign(data)
	return hmac.Equal([]byte(expected), []byte(signature))
}
