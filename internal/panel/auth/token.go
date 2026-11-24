package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"snell-panel/internal/protocol"
)

var (
	ErrUnsupportedCipher = errors.New("auth: unsupported ss2022 cipher")
	ErrInvalidSS2022Key  = errors.New("auth: invalid ss2022 key")
)

func randomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("auth: crypto/rand read: %w", err)
	}
	return buf, nil
}

// GenerateNodeToken generates a 192-bit random NODE_TOKEN prefixed with "nd_live_".
func GenerateNodeToken() (string, error) {
	b, err := randomBytes(24)
	if err != nil {
		return "", err
	}
	return NodeTokenPrefix + hex.EncodeToString(b), nil
}

// HashToken returns the lowercase 64-character SHA-256 hex digest of raw.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// GenerateNodeTokenPair generates a fresh NODE_TOKEN and its SHA-256 hex hash.
func GenerateNodeTokenPair() (raw string, hash string, err error) {
	raw, err = GenerateNodeToken()
	if err != nil {
		return "", "", err
	}
	return raw, HashToken(raw), nil
}

// VerifyTokenHash checks raw against expectedHexHash in constant time.
func VerifyTokenHash(raw, expectedHexHash string) bool {
	if raw == "" || expectedHexHash == "" {
		return false
	}
	normalized := strings.ToLower(strings.TrimSpace(expectedHexHash))
	if len(normalized) != sha256.Size*2 {
		return false
	}
	actual := HashToken(raw)
	return subtle.ConstantTimeCompare([]byte(actual), []byte(normalized)) == 1
}

// GenerateSubToken generates a URL-safe 192-bit lowercase hex subscription token (48 chars).
func GenerateSubToken() (string, error) {
	b, err := randomBytes(24)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenerateUPSK16 generates a 16-byte Base64 SS2022 uPSK for 2022-blake3-aes-128-gcm.
func GenerateUPSK16() (string, error) {
	b, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// GenerateUPSK32 generates a 32-byte Base64 SS2022 uPSK for 2022-blake3-aes-256-gcm.
func GenerateUPSK32() (string, error) {
	b, err := randomBytes(32)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// GenerateIPSKForCipher generates a matching node iPSK for the given SS2022 cipher.
func GenerateIPSKForCipher(cipher string) (string, error) {
	switch cipher {
	case protocol.CipherAES128GCM:
		return GenerateUPSK16()
	case protocol.CipherAES256GCM:
		return GenerateUPSK32()
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedCipher, cipher)
	}
}

// ValidateSS2022Key verifies that encoded is single-line standard Base64 with exact byte length for cipher.
func ValidateSS2022Key(encoded, cipher string) error {
	var wantLen int
	switch cipher {
	case protocol.CipherAES128GCM:
		wantLen = 16
	case protocol.CipherAES256GCM:
		wantLen = 32
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedCipher, cipher)
	}
	if encoded == "" || strings.ContainsAny(encoded, "\r\n") {
		return fmt.Errorf("%w: key must be non-empty single-line base64", ErrInvalidSS2022Key)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSS2022Key, err)
	}
	if len(decoded) != wantLen {
		return fmt.Errorf("%w: got %d bytes, want %d for %s", ErrInvalidSS2022Key, len(decoded), wantLen, cipher)
	}
	return nil
}

// GenerateShadowTLSPassword generates a 192-bit URL/INI/CLI-safe ShadowTLS v3 password.
func GenerateShadowTLSPassword() (string, error) {
	b, err := randomBytes(24)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateSnellPSK generates a 192-bit URL/INI/Surge-safe Snell PSK.
func GenerateSnellPSK() (string, error) {
	b, err := randomBytes(24)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
