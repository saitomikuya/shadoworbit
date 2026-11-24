package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"snell-panel/internal/panel/store"
	"snell-panel/internal/protocol"
)

type mockSettingsStore struct {
	mu   sync.Mutex
	data map[string]string
}

func newMockSettingsStore() *mockSettingsStore {
	return &mockSettingsStore{data: make(map[string]string)}
}

func (m *mockSettingsStore) GetSetting(_ context.Context, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	if !ok {
		return "", store.ErrNotFound
	}
	return v, nil
}

func (m *mockSettingsStore) SetSetting(_ context.Context, key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
	return nil
}

func (m *mockSettingsStore) SetSettingIfAbsent(_ context.Context, key, value string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.data[key]; ok && existing != "" {
		return existing, false, nil
	}
	m.data[key] = value
	return value, true, nil
}

func TestBcryptPasswordAndLogin(t *testing.T) {
	ctx := context.Background()

	// Default cost and custom cost.
	hDef, err := HashPassword("CorrectHorseBatteryStaple!")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	if err := VerifyPassword(hDef, "CorrectHorseBatteryStaple!"); err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if err := VerifyPassword(hDef, "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	hMin, err := HashPasswordWithCost("pass123", bcrypt.MinCost)
	if err != nil {
		t.Fatalf("HashPasswordWithCost MinCost failed: %v", err)
	}
	if err := VerifyPassword(hMin, "pass123"); err != nil {
		t.Fatalf("VerifyPassword MinCost failed: %v", err)
	}

	// Empty and >72 byte rejections.
	if _, err := HashPassword(""); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("expected ErrEmptyPassword, got %v", err)
	}
	if err := VerifyPassword(hMin, ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for empty verify password, got %v", err)
	}
	tooLong := strings.Repeat("a", 73)
	if _, err := HashPassword(tooLong); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("expected ErrPasswordTooLong, got %v", err)
	}
	if err := VerifyPassword(hMin, tooLong); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for >72B verify, got %v", err)
	}

	// Invalid cost rejections.
	for _, badCost := range []int{-1, 1, 3, 32} {
		if _, err := HashPasswordWithCost("abc", badCost); !errors.Is(err, ErrInvalidCost) {
			t.Fatalf("cost %d: expected ErrInvalidCost, got %v", badCost, err)
		}
	}

	// Login & ChangePassword on mock store.
	ms := newMockSettingsStore()
	_ = ms.SetSetting(ctx, SettingAdminUsername, "admin")
	_ = ms.SetSetting(ctx, SettingAdminPasswordHash, hMin)

	svc, err := NewService(ctx, ms, Config{BcryptCost: bcrypt.MinCost})
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	tok, err := svc.Login(ctx, "admin", "pass123")
	if err != nil || tok == "" {
		t.Fatalf("Login failed: tok=%q err=%v", tok, err)
	}
	if _, err := svc.Login(ctx, "wronguser", "pass123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials on wrong username, got %v", err)
	}
	if _, err := svc.Login(ctx, "admin", "wrongpass"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials on wrong password, got %v", err)
	}
	if _, err := svc.Login(ctx, "", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials on empty login, got %v", err)
	}

	if err := svc.ChangePassword(ctx, "admin", "wrongold", "newpass"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials on wrong old password, got %v", err)
	}
	if err := svc.ChangePassword(ctx, "admin", "pass123", ""); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("expected ErrEmptyPassword on empty new password, got %v", err)
	}
	if err := svc.ChangePassword(ctx, "admin", "pass123", "newStrongPass!"); err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}
	if _, err := svc.Login(ctx, "admin", "pass123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("old password should fail after ChangePassword")
	}
	if _, err := svc.Login(ctx, "admin", "newStrongPass!"); err != nil {
		t.Fatalf("new password login failed: %v", err)
	}
}

func TestJWTIssuanceVerificationAndAlgorithmConfusion(t *testing.T) {
	ctx := context.Background()
	ms := newMockSettingsStore()

	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	svc, err := NewService(ctx, ms, Config{
		BcryptCost: bcrypt.MinCost,
		TokenTTL:   time.Hour,
		Issuer:     "snell-panel",
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	tok, err := svc.IssueJWT("admin")
	if err != nil {
		t.Fatalf("IssueJWT failed: %v", err)
	}
	claims, err := svc.VerifyJWT(tok)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	if claims.Username != "admin" || claims.Subject != "admin" || claims.Issuer != "snell-panel" {
		t.Fatalf("unexpected claims: %+v", claims)
	}

	// Tampered signature.
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	tampered := parts[0] + "." + parts[1] + ".tamperedsignature"
	if _, err := svc.VerifyJWT(tampered); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for tampered sig, got %v", err)
	}

	// alg: none attack.
	noneTok, err := jwt.NewWithClaims(jwt.SigningMethodNone, AdminClaims{
		Username: "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "snell-panel",
			Subject:   "admin",
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyJWT(noneTok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for alg:none, got %v", err)
	}

	// HS384 / HS512 signed with the real secret must be rejected.
	secret, err := svc.EnsureJWTSecret(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range []jwt.SigningMethod{jwt.SigningMethodHS384, jwt.SigningMethodHS512} {
		otherAlgTok, err := jwt.NewWithClaims(alg, AdminClaims{
			Username: "admin",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "snell-panel",
				Subject:   "admin",
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			},
		}).SignedString(secret)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.VerifyJWT(otherAlgTok); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("alg %s: expected ErrInvalidToken, got %v", alg.Alg(), err)
		}
	}

	// Missing exp claim signed with real HS256 secret must be rejected.
	noExpTok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, AdminClaims{
		Username: "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:  "snell-panel",
			Subject: "admin",
		},
	}).SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyJWT(noExpTok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for missing exp, got %v", err)
	}

	// Malformed and empty tokens.
	for _, bad := range []string{"", "   ", "not.a.jwt", "a.b"} {
		if _, err := svc.VerifyJWT(bad); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("token %q: expected ErrInvalidToken, got %v", bad, err)
		}
	}

	// Expiry via injected clock.
	now = now.Add(time.Hour + time.Second)
	if _, err := svc.VerifyJWT(tok); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("expected ErrExpiredToken after TTL, got %v", err)
	}
}

func TestJWTSecretPersistenceWithRealStoreAndConcurrency(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "auth.db")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("store.Open failed: %v", err)
	}
	defer st.Close()

	if err := st.SeedDefaults(ctx, store.SeedConfig{
		AdminUser:        "admin",
		AdminInitialPass: "initial123",
	}); err != nil {
		t.Fatalf("SeedDefaults failed: %v", err)
	}

	// Verify real store works with Login & ChangePassword.
	svc1, err := NewService(ctx, st, Config{BcryptCost: bcrypt.MinCost})
	if err != nil {
		t.Fatalf("NewService 1 failed: %v", err)
	}
	jwt1, err := svc1.Login(ctx, "admin", "initial123")
	if err != nil {
		t.Fatalf("Login against real store failed: %v", err)
	}

	// Second service instance loads same persisted jwt_secret and verifies svc1's token.
	svc2, err := NewService(ctx, st, Config{BcryptCost: bcrypt.MinCost})
	if err != nil {
		t.Fatalf("NewService 2 failed: %v", err)
	}
	claims, err := svc2.VerifyJWT(jwt1)
	if err != nil || claims.Username != "admin" {
		t.Fatalf("svc2 failed to verify svc1 token: claims=%+v err=%v", claims, err)
	}

	// Concurrent NewService initialization on a fresh unseeded store converges on one secret.
	dbPath2 := filepath.Join(t.TempDir(), "concurrent.db")
	st2, err := store.Open(ctx, dbPath2)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()

	const workers = 12
	secrets := make([][]byte, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			s, err := NewService(ctx, st2, Config{BcryptCost: bcrypt.MinCost})
			if err != nil {
				errs <- err
				return
			}
			sec, err := s.EnsureJWTSecret(ctx)
			if err != nil {
				errs <- err
				return
			}
			secrets[idx] = sec
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent NewService error: %v", err)
	}
	for i := 1; i < workers; i++ {
		if string(secrets[i]) != string(secrets[0]) {
			t.Fatalf("concurrent NewService converged on different secrets")
		}
	}
}

func TestExtractBearerToken(t *testing.T) {
	if tok, err := ExtractBearerToken("Bearer abc123"); err != nil || tok != "abc123" {
		t.Fatalf("unexpected result: tok=%q err=%v", tok, err)
	}
	if tok, err := ExtractBearerToken("bearer nd_live_xyz"); err != nil || tok != "nd_live_xyz" {
		t.Fatalf("unexpected lowercase bearer result: tok=%q err=%v", tok, err)
	}
	for _, bad := range []string{"", "   ", "Basic dXNlcjpwYXNz", "Bearer", "Bearer ", "Bearer   spaced", "Bearer a b"} {
		if _, err := ExtractBearerToken(bad); !errors.Is(err, ErrInvalidBearer) {
			t.Fatalf("header %q: expected ErrInvalidBearer, got %v", bad, err)
		}
	}
}

func TestNodeTokenAndSHA256Verification(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		raw, hash, err := GenerateNodeTokenPair()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(raw, NodeTokenPrefix) {
			t.Fatalf("expected prefix %q, got %q", NodeTokenPrefix, raw)
		}
		if len(raw) < 40 {
			t.Fatalf("expected node token len >= 40, got %d", len(raw))
		}
		if url.PathEscape(raw) != raw {
			t.Fatalf("node token not URL-safe: %q", raw)
		}
		if len(hash) != sha256.Size*2 || strings.ToLower(hash) != hash {
			t.Fatalf("unexpected sha256 hex hash: %q", hash)
		}
		if !VerifyTokenHash(raw, hash) || !VerifyTokenHash(raw, strings.ToUpper(hash)) {
			t.Fatalf("VerifyTokenHash failed on valid pair")
		}
		if VerifyTokenHash(raw+"x", hash) {
			t.Fatalf("VerifyTokenHash matched wrong raw token")
		}
		if _, dup := seen[raw]; dup {
			t.Fatalf("duplicate node token generated: %q", raw)
		}
		seen[raw] = struct{}{}
	}

	if VerifyTokenHash("", HashToken("abc")) || VerifyTokenHash("abc", "") || VerifyTokenHash("abc", "deadbeef") {
		t.Fatal("VerifyTokenHash should reject empty or wrong-length hashes")
	}
}

func TestCryptographicKeyAndTokenGenerators(t *testing.T) {
	// uPSK 16B
	seen16 := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		k16, err := GenerateUPSK16()
		if err != nil {
			t.Fatal(err)
		}
		if len(k16) != 24 {
			t.Fatalf("expected 24-char Base64 uPSK16, got %d (%q)", len(k16), k16)
		}
		raw, err := base64.StdEncoding.DecodeString(k16)
		if err != nil || len(raw) != 16 {
			t.Fatalf("expected 16 decoded bytes, got %d (err=%v)", len(raw), err)
		}
		if err := ValidateSS2022Key(k16, protocol.CipherAES128GCM); err != nil {
			t.Fatalf("ValidateSS2022Key aes-128 failed: %v", err)
		}
		if err := ValidateSS2022Key(k16, protocol.CipherAES256GCM); err == nil {
			t.Fatal("expected aes-128 key to fail aes-256 validation")
		}
		if _, dup := seen16[k16]; dup {
			t.Fatalf("duplicate uPSK16 generated")
		}
		seen16[k16] = struct{}{}
	}

	// uPSK 32B
	seen32 := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		k32, err := GenerateUPSK32()
		if err != nil {
			t.Fatal(err)
		}
		if len(k32) != 44 {
			t.Fatalf("expected 44-char Base64 uPSK32, got %d (%q)", len(k32), k32)
		}
		raw, err := base64.StdEncoding.DecodeString(k32)
		if err != nil || len(raw) != 32 {
			t.Fatalf("expected 32 decoded bytes, got %d (err=%v)", len(raw), err)
		}
		if err := ValidateSS2022Key(k32, protocol.CipherAES256GCM); err != nil {
			t.Fatalf("ValidateSS2022Key aes-256 failed: %v", err)
		}
		if _, dup := seen32[k32]; dup {
			t.Fatalf("duplicate uPSK32 generated")
		}
		seen32[k32] = struct{}{}
	}

	// GenerateIPSKForCipher
	ipsk16, err := GenerateIPSKForCipher(protocol.CipherAES128GCM)
	if err != nil || ValidateSS2022Key(ipsk16, protocol.CipherAES128GCM) != nil {
		t.Fatalf("GenerateIPSKForCipher 128 failed: %q, err=%v", ipsk16, err)
	}
	ipsk32, err := GenerateIPSKForCipher(protocol.CipherAES256GCM)
	if err != nil || ValidateSS2022Key(ipsk32, protocol.CipherAES256GCM) != nil {
		t.Fatalf("GenerateIPSKForCipher 256 failed: %q, err=%v", ipsk32, err)
	}
	if _, err := GenerateIPSKForCipher("aes-256-gcm"); !errors.Is(err, ErrUnsupportedCipher) {
		t.Fatalf("expected ErrUnsupportedCipher, got %v", err)
	}

	// SubToken, ShadowTLSPassword, SnellPSK
	seenSub := make(map[string]struct{}, 100)
	seenSTLS := make(map[string]struct{}, 100)
	seenSnell := make(map[string]struct{}, 100)
	const forbiddenDelims = ",=\r\n\t #;'\"\\"

	for i := 0; i < 100; i++ {
		subTok, err := GenerateSubToken()
		if err != nil {
			t.Fatal(err)
		}
		if len(subTok) < 32 || url.PathEscape(subTok) != subTok {
			t.Fatalf("invalid sub token: %q", subTok)
		}
		if _, err := hex.DecodeString(subTok); err != nil {
			t.Fatalf("expected hex sub token, got %q: %v", subTok, err)
		}
		if _, dup := seenSub[subTok]; dup {
			t.Fatal("duplicate sub token")
		}
		seenSub[subTok] = struct{}{}

		stls, err := GenerateShadowTLSPassword()
		if err != nil {
			t.Fatal(err)
		}
		if len(stls) < 32 || strings.ContainsAny(stls, forbiddenDelims) {
			t.Fatalf("invalid ShadowTLS password: %q", stls)
		}
		if _, dup := seenSTLS[stls]; dup {
			t.Fatal("duplicate ShadowTLS password")
		}
		seenSTLS[stls] = struct{}{}

		psk, err := GenerateSnellPSK()
		if err != nil {
			t.Fatal(err)
		}
		if len(psk) < 32 || strings.ContainsAny(psk, forbiddenDelims) {
			t.Fatalf("invalid Snell PSK: %q", psk)
		}
		if _, dup := seenSnell[psk]; dup {
			t.Fatal("duplicate Snell PSK")
		}
		seenSnell[psk] = struct{}{}
	}
}

func TestValidateSS2022KeyNewlinesAndCompatibility(t *testing.T) {
	k16, err := GenerateUPSK16()
	if err != nil {
		t.Fatal(err)
	}
	k32, err := GenerateUPSK32()
	if err != nil {
		t.Fatal(err)
	}

	// Non-strict padding vector used in protocol/messages_test.go must stay valid.
	if err := ValidateSS2022Key("BBBBBBBBBBBBBBBBBBBBBB==", protocol.CipherAES128GCM); err != nil {
		t.Fatalf("expected non-strict 16B key to remain valid, got %v", err)
	}

	badKeys := []struct {
		name   string
		key    string
		cipher string
	}{
		{"empty", "", protocol.CipherAES128GCM},
		{"trailing lf 16", k16 + "\n", protocol.CipherAES128GCM},
		{"trailing cr 16", k16 + "\r", protocol.CipherAES128GCM},
		{"trailing crlf 16", k16 + "\r\n", protocol.CipherAES128GCM},
		{"leading lf 16", "\n" + k16, protocol.CipherAES128GCM},
		{"embedded lf 16", k16[:4] + "\n" + k16[4:], protocol.CipherAES128GCM},
		{"embedded cr 32", k32[:8] + "\r" + k32[8:], protocol.CipherAES256GCM},
		{"whitespace", "   " + k16, protocol.CipherAES128GCM},
	}
	for _, tc := range badKeys {
		if err := ValidateSS2022Key(tc.key, tc.cipher); !errors.Is(err, ErrInvalidSS2022Key) {
			t.Fatalf("%s: expected ErrInvalidSS2022Key, got %v", tc.name, err)
		}
	}
}

func TestEncryptDecryptNodeTokenAndStoreIntegration(t *testing.T) {
	ctx := context.Background()
	master := []byte("0123456789abcdef0123456789abcdef-master")
	rawTok, hash, err := GenerateNodeTokenPair()
	if err != nil {
		t.Fatal(err)
	}

	enc1, err := EncryptNodeToken(master, 1, rawTok)
	if err != nil {
		t.Fatalf("EncryptNodeToken 1 failed: %v", err)
	}
	enc2, err := EncryptNodeToken(master, 1, rawTok)
	if err != nil {
		t.Fatalf("EncryptNodeToken 2 failed: %v", err)
	}
	if !strings.HasPrefix(enc1, nodeTokenCipherPrefixV1) || enc1 == enc2 {
		t.Fatalf("expected v1: prefix and distinct random nonces, got enc1=%q enc2=%q", enc1, enc2)
	}

	dec, err := DecryptNodeToken(master, 1, enc1)
	if err != nil || dec != rawTok {
		t.Fatalf("DecryptNodeToken mismatch: dec=%q err=%v", dec, err)
	}

	// Cross-node AAD check.
	if _, err := DecryptNodeToken(master, 2, enc1); !errors.Is(err, ErrInvalidEncryptedToken) {
		t.Fatalf("expected ErrInvalidEncryptedToken on wrong nodeID, got %v", err)
	}

	// Wrong master secret.
	wrongMaster := []byte("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
	if _, err := DecryptNodeToken(wrongMaster, 1, enc1); !errors.Is(err, ErrInvalidEncryptedToken) {
		t.Fatalf("expected ErrInvalidEncryptedToken on wrong master, got %v", err)
	}

	// Tampered / malformed ciphertexts.
	tampered := enc1[:len(enc1)-2] + "AA"
	for _, bad := range []string{"", "v2:abc", enc1 + "\n", "v1:not-base64!", "v1:AAAA", tampered} {
		if _, err := DecryptNodeToken(master, 1, bad); !errors.Is(err, ErrInvalidEncryptedToken) {
			t.Fatalf("ciphertext %q: expected ErrInvalidEncryptedToken, got %v", bad, err)
		}
	}

	// Invalid arguments.
	if _, err := EncryptNodeToken(master, 0, rawTok); !errors.Is(err, ErrInvalidNodeID) {
		t.Fatalf("expected ErrInvalidNodeID, got %v", err)
	}
	if _, err := EncryptNodeToken([]byte("short"), 1, rawTok); !errors.Is(err, ErrInvalidMasterSecret) {
		t.Fatalf("expected ErrInvalidMasterSecret, got %v", err)
	}
	if _, err := EncryptNodeToken(master, 1, ""); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for empty rawToken, got %v", err)
	}

	// Real SQLite store integration across service restarts.
	dbPath := filepath.Join(t.TempDir(), "nodetok.db")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SeedDefaults(ctx, store.SeedConfig{}); err != nil {
		st.Close()
		t.Fatal(err)
	}
	svc1, err := NewService(ctx, st, Config{BcryptCost: bcrypt.MinCost})
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	if err := svc1.SaveNodeToken(ctx, 42, rawTok); err != nil {
		st.Close()
		t.Fatalf("SaveNodeToken failed: %v", err)
	}
	_ = st.Close()

	st2, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	svc2, err := NewService(ctx, st2, Config{BcryptCost: bcrypt.MinCost})
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := svc2.GetNodeToken(ctx, 42)
	if err != nil {
		t.Fatalf("GetNodeToken after reopen failed: %v", err)
	}
	if recovered != rawTok || !VerifyTokenHash(recovered, hash) {
		t.Fatalf("recovered token mismatch: got %q, want %q", recovered, rawTok)
	}
	if _, err := svc2.GetNodeToken(ctx, 999); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected wrapped store.ErrNotFound for missing node, got %v", err)
	}
}

func TestDecodeJWTSecretAndVerifyJWTWhitespace(t *testing.T) {
	ctx := context.Background()

	// Valid secrets.
	b64Valid := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if got, err := DecodeJWTSecret(b64Valid); err != nil || len(got) != 32 {
		t.Fatalf("expected 32-byte base64 valid, got len=%d err=%v", len(got), err)
	}
	hexValid := strings.Repeat("ab", 32)
	if got, err := DecodeJWTSecret(hexValid); err != nil || len(got) != 32 {
		t.Fatalf("expected 32-byte hex valid (32 decoded bytes), got len=%d err=%v", len(got), err)
	}
	passValid := "my-custom-jwt-signing-secret-32+bytes!"
	if got, err := DecodeJWTSecret(passValid); err != nil || string(got) != passValid {
		t.Fatalf("expected passphrase valid, got %q err=%v", string(got), err)
	}

	// Invalid secrets.
	invalid := []string{
		"",
		"                                        ",
		"short",
		"0123456789abcdef0123456789abcdef", // 16-byte hex
		"AAAAAAAAAAAAAAAAAAAAAA==",         // 16-byte base64
		"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==", // 22-byte base64
		passValid + "\n",                   // trailing newline
		passValid + "\r",                   // trailing CR
		"a" + strings.Repeat(" ", 40),      // padded short
	}
	for _, s := range invalid {
		if _, err := DecodeJWTSecret(s); err == nil {
			t.Fatalf("expected DecodeJWTSecret(%q) to fail", s)
		}
	}

	// VerifyJWT rejects embedded spaces/CR/LF.
	ms := newMockSettingsStore()
	svc, err := NewService(ctx, ms, Config{BcryptCost: bcrypt.MinCost})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := svc.IssueJWT("admin")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{tok + "\n", tok + "\r", " " + tok, tok + " "} {
		if _, err := svc.VerifyJWT(bad); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken for %q, got %v", bad, err)
		}
	}
}

func TestTier5_AuthAdversarial_AADSwapCorruptSecretAndJWTRejection(t *testing.T) {
	ctx := context.Background()
	ms := newMockSettingsStore()
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

	svc, err := NewService(ctx, ms, Config{
		BcryptCost: bcrypt.MinCost,
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Cross-node AAD swap in persisted settings store must fail GetNodeToken.
	raw1, err := GenerateNodeToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SaveNodeToken(ctx, 1, raw1); err != nil {
		t.Fatal(err)
	}
	enc1, err := ms.GetSetting(ctx, NodeTokenSettingKey(1))
	if err != nil {
		t.Fatal(err)
	}
	if err := ms.SetSetting(ctx, NodeTokenSettingKey(2), enc1); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetNodeToken(ctx, 2); !errors.Is(err, ErrInvalidEncryptedToken) {
		t.Fatalf("expected ErrInvalidEncryptedToken on cross-node AAD ciphertext swap, got %v", err)
	}

	// Corrupted stored node ciphertext rejects GetNodeToken.
	if err := ms.SetSetting(ctx, NodeTokenSettingKey(1), "v1:corrupted!!!"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetNodeToken(ctx, 1); !errors.Is(err, ErrInvalidEncryptedToken) {
		t.Fatalf("expected ErrInvalidEncryptedToken for corrupted stored ciphertext, got %v", err)
	}

	// 2. Corrupted persisted jwt_secret rejects NewService initialization.
	badMS := newMockSettingsStore()
	if err := badMS.SetSetting(ctx, SettingJWTSecret, "too-short"); err != nil {
		t.Fatal(err)
	}
	if _, err := NewService(ctx, badMS, Config{BcryptCost: bcrypt.MinCost}); err == nil {
		t.Fatal("expected NewService to fail with short/corrupted persisted jwt_secret")
	}

	// 3. VerifyJWT rejects future NotBefore (nbf), RS256 signed token, and empty username/sub claim.
	secret, err := svc.getSecret()
	if err != nil {
		t.Fatal(err)
	}

	// Future nbf (+10m)
	nbfClaims := AdminClaims{
		Username: "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    DefaultJWTIssuer,
			Subject:   "admin",
			NotBefore: jwt.NewNumericDate(now.Add(10 * time.Minute)),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
	nbfTok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, nbfClaims).SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyJWT(nbfTok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for future nbf claim, got %v", err)
	}

	// Empty username / missing sub
	noSubClaims := AdminClaims{
		Username: "",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    DefaultJWTIssuer,
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
	noSubTok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, noSubClaims).SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyJWT(noSubTok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for missing username/sub, got %v", err)
	}

	// RS256 signed token rejected
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsClaims := AdminClaims{
		Username: "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    DefaultJWTIssuer,
			Subject:   "admin",
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}
	rsTok, err := jwt.NewWithClaims(jwt.SigningMethodRS256, rsClaims).SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyJWT(rsTok); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for alg=RS256 token, got %v", err)
	}

	// 4. Changing admin_username invalidates Authenticate for old username.
	hash, err := svc.HashPassword("pass12345")
	if err != nil {
		t.Fatal(err)
	}
	_ = ms.SetSetting(ctx, SettingAdminUsername, "admin")
	_ = ms.SetSetting(ctx, SettingAdminPasswordHash, hash)
	if _, err := svc.Login(ctx, "admin", "pass12345"); err != nil {
		t.Fatalf("expected initial admin login ok: %v", err)
	}
	_ = ms.SetSetting(ctx, SettingAdminUsername, "superadmin")
	if _, err := svc.Login(ctx, "admin", "pass12345"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials after ADMIN_USER change, got %v", err)
	}
}
