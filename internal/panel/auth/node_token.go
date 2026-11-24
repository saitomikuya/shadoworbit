package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	NodeTokenSettingPrefix  = "node_token_enc:"
	nodeTokenHKDFInfo       = "snell-panel:node-token:v1"
	nodeTokenCipherPrefixV1 = "v1:"
	nodeTokenNonceSize      = 12
)

var (
	ErrInvalidNodeID         = errors.New("auth: node ID must be positive")
	ErrInvalidMasterSecret   = errors.New("auth: master secret must be at least 32 bytes")
	ErrInvalidEncryptedToken = errors.New("auth: invalid encrypted node token")
)

// NodeTokenSettingKey returns the system_settings key for a node's encrypted NODE_TOKEN.
func NodeTokenSettingKey(nodeID int64) string {
	return fmt.Sprintf("%s%d", NodeTokenSettingPrefix, nodeID)
}

func deriveNodeTokenKey(masterSecret []byte) ([]byte, error) {
	if len(masterSecret) < 32 {
		return nil, ErrInvalidMasterSecret
	}
	key, err := hkdf.Key(sha256.New, masterSecret, nil, nodeTokenHKDFInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("auth: derive node token key: %w", err)
	}
	return key, nil
}

func nodeTokenAAD(nodeID int64) []byte {
	return []byte(fmt.Sprintf("node:%d", nodeID))
}

// EncryptNodeToken encrypts rawToken for nodeID using AES-256-GCM with a key derived from
// masterSecret (>= 32 bytes) via HKDF-SHA256 ("snell-panel:node-token:v1") and AAD "node:<id>".
// Output format: "v1:" + base64.StdEncoding(12-byte random nonce || ciphertext || 16-byte GCM tag).
func EncryptNodeToken(masterSecret []byte, nodeID int64, rawToken string) (string, error) {
	if nodeID <= 0 {
		return "", ErrInvalidNodeID
	}
	if rawToken == "" || strings.ContainsAny(rawToken, "\r\n") {
		return "", fmt.Errorf("%w: empty or malformed node token", ErrInvalidToken)
	}
	key, err := deriveNodeTokenKey(masterSecret)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("auth: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("auth: aes-gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if len(nonce) != nodeTokenNonceSize {
		return "", fmt.Errorf("auth: unexpected gcm nonce size %d", len(nonce))
	}
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("auth: generate nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(rawToken), nodeTokenAAD(nodeID))
	return nodeTokenCipherPrefixV1 + base64.StdEncoding.EncodeToString(sealed), nil
}

// DecryptNodeToken decrypts a ciphertext produced by EncryptNodeToken for the exact same nodeID.
func DecryptNodeToken(masterSecret []byte, nodeID int64, encoded string) (string, error) {
	if nodeID <= 0 {
		return "", ErrInvalidNodeID
	}
	if !strings.HasPrefix(encoded, nodeTokenCipherPrefixV1) || strings.ContainsAny(encoded, "\r\n") {
		return "", ErrInvalidEncryptedToken
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encoded, nodeTokenCipherPrefixV1))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidEncryptedToken, err)
	}
	key, err := deriveNodeTokenKey(masterSecret)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("auth: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("auth: aes-gcm: %w", err)
	}
	if len(raw) < gcm.NonceSize()+gcm.Overhead() {
		return "", ErrInvalidEncryptedToken
	}
	nonce := raw[:gcm.NonceSize()]
	ciphertext := raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nodeTokenAAD(nodeID))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidEncryptedToken, err)
	}
	if len(plain) == 0 {
		return "", ErrInvalidEncryptedToken
	}
	return string(plain), nil
}

// EncryptNodeToken encrypts rawToken for nodeID using the Service's persistent master secret.
func (s *Service) EncryptNodeToken(nodeID int64, rawToken string) (string, error) {
	secret, err := s.getSecret()
	if err != nil {
		return "", err
	}
	return EncryptNodeToken(secret, nodeID, rawToken)
}

// DecryptNodeToken decrypts an encrypted node token for nodeID using the Service's persistent master secret.
func (s *Service) DecryptNodeToken(nodeID int64, ciphertext string) (string, error) {
	secret, err := s.getSecret()
	if err != nil {
		return "", err
	}
	return DecryptNodeToken(secret, nodeID, ciphertext)
}

// SaveNodeToken encrypts rawToken for nodeID and persists it under node_token_enc:<nodeID>.
func (s *Service) SaveNodeToken(ctx context.Context, nodeID int64, rawToken string) error {
	enc, err := s.EncryptNodeToken(nodeID, rawToken)
	if err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, NodeTokenSettingKey(nodeID), enc); err != nil {
		return fmt.Errorf("auth: save encrypted node token: %w", err)
	}
	return nil
}

// GetNodeToken loads and decrypts the persisted NODE_TOKEN for nodeID.
func (s *Service) GetNodeToken(ctx context.Context, nodeID int64) (string, error) {
	if nodeID <= 0 {
		return "", ErrInvalidNodeID
	}
	enc, err := s.store.GetSetting(ctx, NodeTokenSettingKey(nodeID))
	if err != nil {
		return "", fmt.Errorf("auth: load encrypted node token: %w", err)
	}
	return s.DecryptNodeToken(nodeID, enc)
}
