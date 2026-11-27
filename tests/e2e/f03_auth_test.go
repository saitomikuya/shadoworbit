//go:build e2e

package e2e_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func TestF03_Tier1_AdminLoginMeAndJWT(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{
		AdminPass: "super_secret_123",
	})
	client := panel.NewClient()

	st, loginResp, raw, err := client.Login("", "super_secret_123")
	if err != nil || st != http.StatusOK {
		t.Fatalf("login failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	if len(strings.Split(loginResp.Token, ".")) != 3 {
		t.Fatalf("unexpected login response: %+v", loginResp)
	}

	meSt, me, meRaw, err := client.GetMe(loginResp.Token)
	if err != nil || meSt != http.StatusOK || !me.Authenticated {
		t.Fatalf("GET /api/v1/auth/me failed: st=%d me=%+v err=%v body=%s", meSt, me, err, string(meRaw))
	}

	nodesSt, _, nodesRaw, err := client.ListNodes(loginResp.Token)
	if err != nil || nodesSt != http.StatusOK {
		t.Fatalf("GET /api/v1/admin/nodes with JWT failed: st=%d err=%v body=%s", nodesSt, err, string(nodesRaw))
	}
}

func TestF03_Tier1_PasswordUpdateAndBcryptStorage(t *testing.T) {
	env := NewTestEnv(t)
	dbPath := filepath.Join(env.RootDir, "panel.db")
	panel := StartPanel(env, PanelConfig{DBPath: dbPath, AdminPass: "old_pass_123"})
	client := panel.NewClient()
	jwtTok := client.MustLogin(t, "admin", "old_pass_123")

	st, raw, err := client.UpdatePassword(jwtTok, "old_pass_123", "new_pass_456")
	if err != nil || st >= 300 {
		t.Fatalf("UpdatePassword failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	if oldSt, _, _, _ := client.Login("admin", "old_pass_123"); oldSt != http.StatusUnauthorized {
		t.Fatalf("expected old password to be rejected with 401, got %d", oldSt)
	}
	_ = client.MustLogin(t, "admin", "new_pass_456")
	_ = panel.Stop()

	db := openSQLiteReadOnly(t, dbPath)
	rows, err := db.Query("SELECT value FROM system_settings WHERE value LIKE '$2%'")
	if err != nil {
		t.Fatalf("query system_settings bcrypt hash: %v", err)
	}
	defer rows.Close()
	matched := false
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err == nil {
			if !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2b$") {
				continue
			}
			if bcrypt.CompareHashAndPassword([]byte(hash), []byte("new_pass_456")) == nil {
				matched = true
			}
		}
	}
	if !matched {
		t.Fatal("expected bcrypt hash ($2a$/$2b$) in system_settings matching new_pass_456")
	}
}

func TestF03_Tier1_NodeTokenAuthAndSHA256HashStorage(t *testing.T) {
	env := NewTestEnv(t)
	dbPath := filepath.Join(env.RootDir, "panel.db")
	panel := StartPanel(env, PanelConfig{DBPath: dbPath})
	client := panel.NewClient()
	jwtTok := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, raw, err := client.CreateNode(jwtTok, CreateNodeReq{Name: "AuthNode", Enabled: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	nodeToken := node.EffectiveToken()
	if nodeToken == "" {
		t.Fatalf("missing plaintext node token in CreateNode response: %s", string(raw))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, wsSt, err := client.DialAgentWS(ctx, nodeToken)
	if err != nil {
		t.Fatalf("DialAgentWS failed (status=%d): %v", wsSt, err)
	}
	_ = ws.CloseNow()

	// GET /api/v1/admin/nodes/{id} must not leak token_hash or raw token
	_, _, getRaw, err := client.GetNode(jwtTok, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(getRaw), nodeToken) {
		t.Fatalf("GET /api/v1/admin/nodes/%d leaked plaintext node_token", node.ID)
	}

	_ = panel.Stop()
	db := openSQLiteReadOnly(t, dbPath)
	var storedHash string
	if err := db.QueryRow("SELECT token_hash FROM nodes WHERE id = ?", node.ID).Scan(&storedHash); err != nil {
		t.Fatalf("query nodes.token_hash: %v", err)
	}
	sum := sha256.Sum256([]byte(nodeToken))
	wantHash := hex.EncodeToString(sum[:])
	if storedHash != wantHash {
		t.Fatalf("token_hash mismatch: got %q want %q", storedHash, wantHash)
	}
	if storedHash == nodeToken {
		t.Fatal("plaintext token stored instead of SHA-256 hash")
	}
}

func TestF03_Tier1_UserDualUPSKAndHighEntropyTokens(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwtTok := client.MustLogin(t, "admin", "change_me_on_first_login")

	subTokens := map[string]bool{}
	stlsPasswords := map[string]bool{}
	for i := 0; i < 5; i++ {
		st, u, raw, err := client.CreateUser(jwtTok, CreateUserReq{
			Username: "entropy_user_" + string(rune('a'+i)),
		})
		if err != nil || st >= 300 {
			t.Fatalf("CreateUser #%d failed: st=%d err=%v body=%s", i, st, err, string(raw))
		}
		b16, err := base64.StdEncoding.DecodeString(u.SSUPSK16)
		if err != nil || len(b16) != 16 {
			t.Fatalf("user %s ss_upsk_16 invalid (%q): len=%d err=%v", u.Username, u.SSUPSK16, len(b16), err)
		}
		b32, err := base64.StdEncoding.DecodeString(u.SSUPSK32)
		if err != nil || len(b32) != 32 {
			t.Fatalf("user %s ss_upsk_32 invalid (%q): len=%d err=%v", u.Username, u.SSUPSK32, len(b32), err)
		}
		if len(u.SubToken) < 24 || subTokens[u.SubToken] {
			t.Fatalf("user %s sub_token weak or duplicate: %q", u.Username, u.SubToken)
		}
		if len(u.STLSPassword) < 12 || stlsPasswords[u.STLSPassword] {
			t.Fatalf("user %s stls_password weak or duplicate: %q", u.Username, u.STLSPassword)
		}
		subTokens[u.SubToken] = true
		stlsPasswords[u.STLSPassword] = true
	}
}

func TestF03_Tier1_ResetUserKeysRotatesCredentials(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwtTok := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, u1, _, err := client.CreateUser(jwtTok, CreateUserReq{Username: "rotate_user"})
	if err != nil {
		t.Fatal(err)
	}
	stBefore, _, _, err := client.GetUserSub(u1.SubToken, "target=mihomo&mode=proxy", "")
	if err != nil || stBefore != http.StatusOK {
		t.Fatalf("expected old sub_token to serve 200, got st=%d err=%v", stBefore, err)
	}

	stReset, u2, rawReset, err := client.ResetUserKeys(jwtTok, u1.ID, map[string]any{
		"reset_sub_token": true,
	})
	if err != nil || stReset >= 300 {
		t.Fatalf("ResetUserKeys failed: st=%d err=%v body=%s", stReset, err, string(rawReset))
	}

	if u2.SSUPSK16 == u1.SSUPSK16 || u2.SSUPSK32 == u1.SSUPSK32 || u2.STLSPassword == u1.STLSPassword || u2.SubToken == u1.SubToken {
		t.Fatalf("expected all user keys and sub_token to rotate: old=%+v new=%+v", u1, u2)
	}
	if b16, err := base64.StdEncoding.DecodeString(u2.SSUPSK16); err != nil || len(b16) != 16 {
		t.Fatalf("rotated ss_upsk_16 invalid: %q", u2.SSUPSK16)
	}
	if b32, err := base64.StdEncoding.DecodeString(u2.SSUPSK32); err != nil || len(b32) != 32 {
		t.Fatalf("rotated ss_upsk_32 invalid: %q", u2.SSUPSK32)
	}

	stOldAfter, _, _, _ := client.GetUserSub(u1.SubToken, "target=mihomo&mode=proxy", "")
	if stOldAfter == http.StatusOK {
		t.Fatalf("expected rotated-out sub_token to be rejected, still got 200")
	}
	stNewAfter, _, _, _ := client.GetUserSub(u2.SubToken, "target=mihomo&mode=proxy", "")
	if stNewAfter != http.StatusOK {
		t.Fatalf("expected new sub_token to serve 200, got %d", stNewAfter)
	}
}

func TestF03_Tier2_RejectMissingMalformedTamperedAndAlgNoneJWT(t *testing.T) {
	const testSecret = "known-test-secret-for-f03-32bytes!"
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{JWTSecret: testSecret})
	client := panel.NewClient()
	validJWT := client.MustLogin(t, "admin", "change_me_on_first_login")

	// Flip a non-trailing character in the Base64URL signature segment so raw HMAC bytes always change.
	parts := strings.Split(validJWT, ".")
	if len(parts) != 3 || len(parts[2]) < 2 {
		t.Fatalf("unexpected JWT format: %q", validJWT)
	}
	sigBytes := []byte(parts[2])
	if sigBytes[0] == 'X' {
		sigBytes[0] = 'Y'
	} else {
		sigBytes[0] = 'X'
	}
	tamperedJWT := parts[0] + "." + parts[1] + "." + string(sigBytes)

	// alg: none JWT
	algNoneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	algNonePayload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"snell-panel","sub":"admin","username":"admin","exp":9999999999}`))
	algNoneJWT := algNoneHeader + "." + algNonePayload + "."

	// Expired JWT signed with the real secret and matching issuer
	expTok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":      "snell-panel",
		"sub":      "admin",
		"username": "admin",
		"exp":      time.Now().Add(-1 * time.Hour).Unix(),
	})
	expiredJWT, err := expTok.SignedString([]byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}

	authCases := []struct {
		name   string
		header string
	}{
		{"missing_header", ""},
		{"basic_auth", "Basic YWRtaW46YWRtaW4="},
		{"malformed_jwt", "Bearer not.a.jwt"},
		{"tampered_sig", "Bearer " + tamperedJWT},
		{"alg_none", "Bearer " + algNoneJWT},
		{"expired_jwt", "Bearer " + expiredJWT},
	}

	for _, endpoint := range []string{"/api/v1/auth/me", "/api/v1/admin/nodes"} {
		for _, tc := range authCases {
			headers := map[string]string{}
			if tc.header != "" {
				headers["Authorization"] = tc.header
			}
			st, _, raw, err := client.DoRaw(context.Background(), http.MethodGet, endpoint, headers, nil)
			if err != nil {
				t.Fatalf("%s %s error: %v", tc.name, endpoint, err)
			}
			if st != http.StatusUnauthorized {
				t.Fatalf("%s %s expected 401, got %d (body=%s)", tc.name, endpoint, st, string(raw))
			}
		}
	}
}

func TestF03_Tier2_WrongCredentialsAndWrongOldPassword(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{AdminPass: "correct_pass"})
	client := panel.NewClient()

	if st, _, _, _ := client.Login("", "wrong_pass"); st != http.StatusUnauthorized {
		t.Fatalf("wrong password login expected 401, got %d", st)
	}
	if st, _, _, _ := client.Login("", ""); st != http.StatusUnauthorized {
		t.Fatalf("empty password login expected 401, got %d", st)
	}
	if st, _, _, _ := client.DoRaw(context.Background(), http.MethodPost, "/api/v1/auth/login", map[string]string{"Content-Type": "application/json"}, []byte("{bad-json")); st != http.StatusBadRequest {
		t.Fatalf("malformed login JSON expected 400, got %d", st)
	}

	jwtTok := client.MustLogin(t, "admin", "correct_pass")
	st, raw, err := client.UpdatePassword(jwtTok, "wrong_old_pass", "new_pass_789")
	if err != nil {
		t.Fatal(err)
	}
	if st != http.StatusUnauthorized && st != http.StatusBadRequest {
		t.Fatalf("wrong old_password expected 401/400, got %d (body=%s)", st, string(raw))
	}
	// Original password must remain valid
	_ = client.MustLogin(t, "admin", "correct_pass")
}

func TestF03_Tier2_AgentWSRejectsMissingWrongOrHashAsToken(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwtTok := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwtTok, CreateNodeReq{Name: "WSAuthNode", Enabled: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(node.EffectiveToken()))
	hashAsToken := hex.EncodeToString(sum[:])

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, tc := range []struct {
		name  string
		token string
	}{
		{"empty_token", ""},
		{"wrong_token", "nd_live_invalid_token_xyz"},
		{"admin_jwt", jwtTok},
		{"hash_as_token", hashAsToken},
	} {
		conn, wsStatus, err := client.DialAgentWS(ctx, tc.token)
		if err == nil {
			_ = conn.CloseNow()
			t.Fatalf("%s: expected WS handshake rejection, but upgraded", tc.name)
		}
		if wsStatus != http.StatusUnauthorized && wsStatus != http.StatusForbidden {
			t.Fatalf("%s: expected 401 or 403 handshake status, got %d (err=%v)", tc.name, wsStatus, err)
		}
	}
}

func TestF03_Tier2_DeletedNodeTokenImmediatelyRevoked(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwtTok := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwtTok, CreateNodeReq{Name: "RevokeNode", Enabled: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	tok := node.EffectiveToken()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := client.DialAgentWS(ctx, tok)
	if err != nil {
		t.Fatalf("initial DialAgentWS failed: %v", err)
	}
	_ = conn.CloseNow()

	if st, raw, err := client.DeleteNode(jwtTok, node.ID); err != nil || st >= 300 {
		t.Fatalf("DeleteNode failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	conn2, wsStatus, err := client.DialAgentWS(ctx, tok)
	if err == nil {
		_ = conn2.CloseNow()
		t.Fatal("expected deleted node token to be rejected on WS dial")
	}
	if wsStatus != http.StatusUnauthorized && wsStatus != http.StatusForbidden {
		t.Fatalf("expected 401/403 for deleted node token, got %d", wsStatus)
	}
}

func TestF03_Tier2_InvalidAndCrossTrackSubTokensRejected(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwtTok := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, user, _, err := client.CreateUser(jwtTok, CreateUserReq{Username: "sub_user"})
	if err != nil {
		t.Fatal(err)
	}
	_, settings, _, err := client.GetSettings(jwtTok)
	if err != nil || settings.AdminSubToken == "" {
		t.Fatalf("GetSettings failed: %+v err=%v", settings, err)
	}

	// Bad tokens
	for _, fn := range []func() (int, http.Header, string, error){
		func() (int, http.Header, string, error) { return client.GetUserSub("bad_user_token_xyz", "", "") },
		func() (int, http.Header, string, error) { return client.GetAdminSub("bad_admin_token_xyz", "") },
		// Cross-track isolation: admin token must NOT work on user sub route, and user token must NOT work on admin sub route
		func() (int, http.Header, string, error) { return client.GetUserSub(settings.AdminSubToken, "", "") },
		func() (int, http.Header, string, error) { return client.GetAdminSub(user.SubToken, "") },
	} {
		st, _, _, err := fn()
		if err != nil {
			t.Fatal(err)
		}
		if st != http.StatusUnauthorized && st != http.StatusForbidden && st != http.StatusNotFound {
			t.Fatalf("expected 401/403/404 for invalid/cross-track subscription token, got %d", st)
		}
	}
}

func TestF03_Tier2_AutoGeneratedJWTSecretPersistsAcrossRestart(t *testing.T) {
	env := NewTestEnv(t)
	dbPath := filepath.Join(env.RootDir, "panel.db")

	p1 := StartPanel(env, PanelConfig{DBPath: dbPath}) // JWTSecret intentionally omitted
	c1 := p1.NewClient()
	jwt1 := c1.MustLogin(t, "admin", "change_me_on_first_login")
	_ = p1.Stop()

	p2 := StartPanel(env, PanelConfig{DBPath: dbPath}) // JWTSecret intentionally omitted again
	c2 := p2.NewClient()
	meSt, me, meRaw, err := c2.GetMe(jwt1)
	if err != nil || meSt != http.StatusOK || !me.Authenticated {
		t.Fatalf("expected auto-generated JWT secret to persist across restart: st=%d me=%+v err=%v body=%s", meSt, me, err, string(meRaw))
	}
}
