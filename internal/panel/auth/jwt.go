package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// AdminClaims defines the JWT claims payload issued for authenticated admins.
type AdminClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// EnsureJWTSecret loads the persisted HS256 signing secret from SettingsStore,
// or atomically generates and persists a 256-bit random secret if absent.
func (s *Service) EnsureJWTSecret(ctx context.Context) ([]byte, error) {
	s.secretMu.Lock()
	defer s.secretMu.Unlock()

	if len(s.jwtSecret) >= 32 {
		out := make([]byte, len(s.jwtSecret))
		copy(out, s.jwtSecret)
		return out, nil
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("auth: generate jwt secret: %w", err)
	}
	candidate := base64.StdEncoding.EncodeToString(buf)

	actual, _, err := s.store.SetSettingIfAbsent(ctx, SettingJWTSecret, candidate)
	if err != nil {
		return nil, fmt.Errorf("auth: persist jwt secret: %w", err)
	}

	secretBytes, err := DecodeJWTSecret(actual)
	if err != nil {
		return nil, err
	}

	s.jwtSecret = secretBytes
	out := make([]byte, len(secretBytes))
	copy(out, secretBytes)
	return out, nil
}

// DecodeJWTSecret decodes and validates a JWT signing secret.
// It rejects empty, whitespace-only, and multi-line secrets, requires >= 32 decoded bytes
// when raw is valid hex or standard Base64, and otherwise requires >= 32 non-whitespace raw bytes.
func DecodeJWTSecret(raw string) ([]byte, error) {
	if raw == "" || strings.TrimSpace(raw) == "" || strings.ContainsAny(raw, "\r\n\x00") {
		return nil, fmt.Errorf("%w: jwt_secret must be non-empty single-line", ErrInvalidToken)
	}
	if decoded, err := hex.DecodeString(raw); err == nil {
		if len(decoded) < 32 {
			return nil, fmt.Errorf("auth: hex jwt_secret must decode to at least 32 bytes (got %d)", len(decoded))
		}
		return decoded, nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil {
		if len(decoded) < 32 {
			return nil, fmt.Errorf("auth: base64 jwt_secret must decode to at least 32 bytes (got %d)", len(decoded))
		}
		return decoded, nil
	}
	if len(strings.TrimSpace(raw)) >= 32 && len(raw) >= 32 {
		return []byte(raw), nil
	}
	return nil, errors.New("auth: persisted jwt_secret must decode to at least 32 bytes")
}

func (s *Service) getSecret() ([]byte, error) {
	s.secretMu.RLock()
	defer s.secretMu.RUnlock()
	if len(s.jwtSecret) < 32 {
		return nil, errors.New("auth: jwt secret not initialized")
	}
	out := make([]byte, len(s.jwtSecret))
	copy(out, s.jwtSecret)
	return out, nil
}

// IssueJWT signs a new HS256 JWT for username.
func (s *Service) IssueJWT(username string) (string, error) {
	if username == "" {
		return "", fmt.Errorf("%w: empty username", ErrInvalidCredentials)
	}
	secret, err := s.getSecret()
	if err != nil {
		return "", err
	}
	now := s.now().UTC()
	claims := AdminClaims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   username,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.tokenTTL)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(secret)
	if err != nil {
		return "", fmt.Errorf("auth: sign jwt: %w", err)
	}
	return signed, nil
}

// VerifyJWT validates an HS256 JWT, enforcing algorithm, signature, issuer, and expiration.
func (s *Service) VerifyJWT(tokenStr string) (*AdminClaims, error) {
	if strings.TrimSpace(tokenStr) == "" || strings.ContainsAny(tokenStr, " \t\r\n") {
		return nil, ErrInvalidToken
	}
	secret, err := s.getSecret()
	if err != nil {
		return nil, err
	}

	token, err := jwt.ParseWithClaims(
		tokenStr,
		&AdminClaims{},
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok || t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
				return nil, fmt.Errorf("%w: unexpected alg %v", ErrInvalidToken, t.Header["alg"])
			}
			return secret, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(s.issuer),
		jwt.WithTimeFunc(s.now),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("%w: %v", ErrExpiredToken, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	claims, ok := token.Claims.(*AdminClaims)
	if !ok || !token.Valid || claims.Username == "" {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// ExtractBearerToken parses an HTTP Authorization header of the form "Bearer <token>".
func ExtractBearerToken(authHeader string) (string, error) {
	trimmed := strings.TrimSpace(authHeader)
	if trimmed == "" {
		return "", ErrInvalidBearer
	}
	parts := strings.SplitN(trimmed, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", ErrInvalidBearer
	}
	tok := parts[1]
	if tok == "" || strings.ContainsAny(tok, " \t\r\n") {
		return "", ErrInvalidBearer
	}
	return tok, nil
}
