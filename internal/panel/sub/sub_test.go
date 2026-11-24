package sub

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"snell-panel/internal/panel/auth"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/protocol"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "sub.db")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("store.Open failed: %v", err)
	}
	t.Cleanup(func() {
		_ = st.Close()
	})
	if err := st.SeedDefaults(ctx, store.SeedConfig{
		AdminUser:        "admin",
		AdminInitialPass: "admin123456",
	}); err != nil {
		t.Fatalf("SeedDefaults failed: %v", err)
	}
	return st
}

func mustNewUser(t *testing.T, st *store.Store, username string, enabled bool, quota int64, usedUp, usedDown int64, expireAt *time.Time) *store.User {
	t.Helper()
	subToken, err := auth.GenerateSubToken()
	if err != nil {
		t.Fatal(err)
	}
	upsk16, err := auth.GenerateUPSK16()
	if err != nil {
		t.Fatal(err)
	}
	upsk32, err := auth.GenerateUPSK32()
	if err != nil {
		t.Fatal(err)
	}
	stlsPwd, err := auth.GenerateShadowTLSPassword()
	if err != nil {
		t.Fatal(err)
	}
	u := &store.User{
		Username:          username,
		Enabled:           enabled,
		SubToken:          subToken,
		SSUPSK16:          upsk16,
		SSUPSK32:          upsk32,
		STLSPassword:      stlsPwd,
		TrafficQuotaBytes: quota,
		UsedUpBytes:       usedUp,
		UsedDownBytes:     usedDown,
		ExpireAt:          expireAt,
	}
	if err := st.CreateUser(context.Background(), u); err != nil {
		t.Fatalf("CreateUser(%s) failed: %v", username, err)
	}
	return u
}

func mustNewNode(t *testing.T, st *store.Store, n store.Node) *store.Node {
	t.Helper()
	if n.TokenHash == "" {
		_, hash, err := auth.GenerateNodeTokenPair()
		if err != nil {
			t.Fatal(err)
		}
		n.TokenHash = hash
	}
	if err := st.CreateNode(context.Background(), &n); err != nil {
		t.Fatalf("CreateNode(%s) failed: %v", n.Name, err)
	}
	return &n
}

func TestRenderAdminAuthAndValidation(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	r := NewRenderer(st)

	adminToken, err := st.GetSetting(ctx, "admin_sub_token")
	if err != nil || adminToken == "" {
		t.Fatalf("failed to load seeded admin_sub_token: %v", err)
	}
	user := mustNewUser(t, st, "alice", true, 0, 0, 0, nil)

	// Invalid, empty, CRLF, and cross-track user token must all fail with ErrUnauthorized.
	for _, badTok := range []string{"", "wrong-token", user.SubToken, adminToken + "\r\n", adminToken + "x"} {
		if _, err := r.RenderAdmin(ctx, badTok, AdminRenderOptions{}); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("RenderAdmin(%q) expected ErrUnauthorized, got %v", badTok, err)
		}
	}

	// Invalid mode.
	if _, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{Mode: "clash"}); !errors.Is(err, ErrInvalidMode) || !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidMode wrapping ErrInvalidArgument, got %v", err)
	}

	// CRLF / NUL / whitespace BaseURL injection.
	for _, badURL := range []string{
		"https://evil.com\r\nX-Injected: 1",
		"https://evil.com\nInjected = direct",
		"https://evil.com\x00",
		"https://evil.com space",
	} {
		if _, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{BaseURL: badURL}); !errors.Is(err, ErrInvalidBaseURL) || !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("expected ErrInvalidBaseURL for %q, got %v", badURL, err)
		}
	}

	// Empty stored admin_sub_token must reject with ErrUnauthorized.
	if err := st.SetSetting(ctx, "admin_sub_token", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized when stored admin_sub_token is empty, got %v", err)
	}

	// Missing admin_sub_token row must reject with ErrUnauthorized.
	if _, err := st.DB().ExecContext(ctx, `DELETE FROM system_settings WHERE key = 'admin_sub_token'`); err != nil {
		t.Fatal(err)
	}
	if _, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized when admin_sub_token missing, got %v", err)
	}
}

func TestRenderAdminNodeFilteringAndFormatting(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	r := NewRenderer(st)

	adminToken, err := st.GetSetting(ctx, "admin_sub_token")
	if err != nil {
		t.Fatal(err)
	}

	// Node 1: SortOrder 2, Snell v5, obfs=off (omitted), TFO=true, SNI with :443, emoji name.
	mustNewNode(t, st, store.Node{
		Name:      "🇭🇰 香港 01",
		PublicIP:  "203.0.113.10",
		SortOrder: 2,
		Enabled:   true,
		SnellConfig: protocol.SnellConfig{
			Enabled:      true,
			Version:      protocol.SnellVersionV5,
			PublicPort:   8443,
			PSK:          "snellpsk1",
			Obfs:         protocol.SnellObfsOff,
			TFO:          true,
			STLSPassword: "stlspwd1",
			STLSSNI:      "gateway.icloud.com:443",
		},
	})

	// Node 2: SortOrder 1 (appears first!), stop_ss_only paused -> MUST BE INCLUDED, CustomEntryHost/Port override, v4, obfs=http.
	mustNewNode(t, st, store.Node{
		Name:            "#; US, Node=2",
		PublicIP:        "198.51.100.1",
		CustomEntryHost: "us-cdn.example.com",
		CustomEntryPort: 9443,
		SortOrder:       1,
		Enabled:         true,
		IsTrafficPaused: true,
		ThresholdAction: protocol.ThresholdActionStopSSOnly,
		SnellConfig: protocol.SnellConfig{
			Enabled:      true,
			Version:      protocol.SnellVersionV4,
			PublicPort:   443,
			PSK:          "snellpsk2",
			Obfs:         protocol.SnellObfsHTTP,
			TFO:          false,
			STLSPassword: "stlspwd2",
			STLSSNI:      "swcdn.apple.com",
		},
	})

	// Node 3: SortOrder 3, IPv6 fallback (brackets stripped), obfs=tls, colliding sanitized name with Node 2.
	mustNewNode(t, st, store.Node{
		Name:       "US- Node-2",
		PublicIPv6: "[2001:db8::1]",
		SortOrder:  3,
		Enabled:    true,
		SnellConfig: protocol.SnellConfig{
			Enabled:      true,
			Version:      protocol.SnellVersionV5,
			PublicPort:   7443,
			PSK:          "snellpsk3",
			Obfs:         protocol.SnellObfsTLS,
			TFO:          true,
			STLSPassword: "stlspwd3",
			STLSSNI:      "itunes.apple.com",
		},
	})

	// Node 4: stop_all paused -> MUST BE EXCLUDED.
	mustNewNode(t, st, store.Node{
		Name:            "Paused StopAll",
		PublicIP:        "203.0.113.40",
		SortOrder:       4,
		Enabled:         true,
		IsTrafficPaused: true,
		ThresholdAction: protocol.ThresholdActionStopAll,
		SnellConfig: protocol.SnellConfig{
			Enabled:      true,
			Version:      protocol.SnellVersionV5,
			PublicPort:   8443,
			PSK:          "snellpsk4",
			STLSPassword: "stlspwd4",
			STLSSNI:      "gateway.icloud.com",
		},
	})

	// Node 5: Disabled node -> MUST BE EXCLUDED.
	mustNewNode(t, st, store.Node{
		Name:      "Disabled Node",
		PublicIP:  "203.0.113.50",
		SortOrder: 5,
		Enabled:   false,
		SnellConfig: protocol.SnellConfig{
			Enabled:      true,
			Version:      protocol.SnellVersionV5,
			PublicPort:   8443,
			PSK:          "snellpsk5",
			STLSPassword: "stlspwd5",
			STLSSNI:      "gateway.icloud.com",
		},
	})

	// Node 6: Snell disabled (SS enabled) -> MUST BE EXCLUDED.
	mustNewNode(t, st, store.Node{
		Name:      "SS Only Node",
		PublicIP:  "203.0.113.60",
		SortOrder: 6,
		Enabled:   true,
		SnellConfig: protocol.SnellConfig{
			Enabled:      false,
			Version:      protocol.SnellVersionV5,
			PublicPort:   8443,
			PSK:          "snellpsk6",
			STLSPassword: "stlspwd6",
			STLSSNI:      "gateway.icloud.com",
		},
		SSConfig: protocol.SSConfig{
			Enabled: true,
			TCPPort: 8443,
			UDPPort: 8443,
			Cipher:  protocol.CipherAES128GCM,
			IPSK:    "ipsk6",
			STLSSNI: "gateway.icloud.com",
		},
	})

	// Test mode=proxy
	resProxy, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{Mode: "proxy"})
	if err != nil {
		t.Fatalf("RenderAdmin(proxy) failed: %v", err)
	}
	if resProxy.NodeCount != 3 {
		t.Fatalf("expected NodeCount=3, got %d\nbody:\n%s", resProxy.NodeCount, resProxy.Body)
	}
	if resProxy.Target != protocol.SubTargetSurge {
		t.Fatalf("expected target=surge, got %q", resProxy.Target)
	}
	if resProxy.ContentType != "text/plain; charset=utf-8" {
		t.Fatalf("unexpected ContentType: %q", resProxy.ContentType)
	}
	if got := resProxy.Headers.Get("Profile-Update-Interval"); got != "12" {
		t.Fatalf("expected Profile-Update-Interval=12, got %q", got)
	}

	lines := strings.Split(strings.TrimSuffix(resProxy.Body, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 proxy lines, got %d: %v", len(lines), lines)
	}

	wantLine0 := "US- Node-2 = snell, us-cdn.example.com, 9443, psk=snellpsk2, version=4, reuse=true, tfo=false, shadow-tls-password=stlspwd2, shadow-tls-sni=swcdn.apple.com, shadow-tls-version=3, obfs=http"
	wantLine1 := "🇭🇰 香港 01 = snell, 203.0.113.10, 8443, psk=snellpsk1, version=5, reuse=true, tfo=true, shadow-tls-password=stlspwd1, shadow-tls-sni=gateway.icloud.com, shadow-tls-version=3"
	wantLine2 := "US- Node-2 (2) = snell, 2001:db8::1, 7443, psk=snellpsk3, version=5, reuse=true, tfo=true, shadow-tls-password=stlspwd3, shadow-tls-sni=itunes.apple.com, shadow-tls-version=3, obfs=tls"

	if lines[0] != wantLine0 {
		t.Fatalf("line[0] mismatch:\ngot:  %s\nwant: %s", lines[0], wantLine0)
	}
	if lines[1] != wantLine1 {
		t.Fatalf("line[1] mismatch:\ngot:  %s\nwant: %s", lines[1], wantLine1)
	}
	if lines[2] != wantLine2 {
		t.Fatalf("line[2] mismatch:\ngot:  %s\nwant: %s", lines[2], wantLine2)
	}

	// Test mode=full with trailing slash on BaseURL
	resFull, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{
		BaseURL: "https://panel.example.com/",
	})
	if err != nil {
		t.Fatalf("RenderAdmin(full) failed: %v", err)
	}
	if resFull.NodeCount != 3 {
		t.Fatalf("expected NodeCount=3, got %d", resFull.NodeCount)
	}
	fullLines := strings.Split(resFull.Body, "\n")
	wantHeader := fmt.Sprintf("#!MANAGED-CONFIG https://panel.example.com/s/admin/%s interval=43200 strict=false", adminToken)
	if fullLines[0] != wantHeader {
		t.Fatalf("line 1 mismatch:\ngot:  %s\nwant: %s", fullLines[0], wantHeader)
	}
	if !strings.Contains(resFull.Body, "🚀 节点选择 = select, ♻️ 自动选择, 🔯 故障转移, US- Node-2, 🇭🇰 香港 01, US- Node-2 (2), DIRECT") {
		t.Fatalf("missing expected 🚀 节点选择 group line in:\n%s", resFull.Body)
	}
	if !strings.Contains(resFull.Body, "♻️ 自动选择 = url-test, US- Node-2, 🇭🇰 香港 01, US- Node-2 (2), url = http://www.gstatic.com/generate_204") {
		t.Fatalf("missing expected ♻️ 自动选择 group line in:\n%s", resFull.Body)
	}
	if strings.Contains(resFull.Body, "Paused StopAll") || strings.Contains(resFull.Body, "Disabled Node") || strings.Contains(resFull.Body, "SS Only Node") {
		t.Fatalf("unexpected excluded node in admin output:\n%s", resFull.Body)
	}
}

func TestRenderAdminTemplatesAndZeroNodes(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	r := NewRenderer(st)

	adminToken, err := st.GetSetting(ctx, "admin_sub_token")
	if err != nil {
		t.Fatal(err)
	}

	// Zero nodes in mode=proxy -> empty body, NodeCount=0.
	resEmptyProxy, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{Mode: "proxy"})
	if err != nil {
		t.Fatalf("RenderAdmin(proxy, 0 nodes) failed: %v", err)
	}
	if resEmptyProxy.Body != "" || resEmptyProxy.NodeCount != 0 {
		t.Fatalf("expected empty body and NodeCount=0, got body=%q count=%d", resEmptyProxy.Body, resEmptyProxy.NodeCount)
	}

	// Zero nodes in mode=full -> valid DIRECT groups (collapsed ", DIRECT, DIRECT" -> ", DIRECT").
	resEmptyFull, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{BaseURL: "https://panel.example.com"})
	if err != nil {
		t.Fatalf("RenderAdmin(full, 0 nodes) failed: %v", err)
	}
	if !strings.Contains(resEmptyFull.Body, "🚀 节点选择 = select, ♻️ 自动选择, 🔯 故障转移, DIRECT\n") {
		t.Fatalf("expected collapsed '🚀 节点选择 = select, ..., DIRECT', got:\n%s", resEmptyFull.Body)
	}
	if !strings.Contains(resEmptyFull.Body, "♻️ 自动选择 = url-test, DIRECT, url =") {
		t.Fatalf("expected '♻️ 自动选择 = url-test, DIRECT, url =', got:\n%s", resEmptyFull.Body)
	}
	if strings.Contains(resEmptyFull.Body, "DIRECT, DIRECT") || strings.Contains(resEmptyFull.Body, ", ,") {
		t.Fatalf("invalid proxy group syntax in 0-node Surge output:\n%s", resEmptyFull.Body)
	}

	// Custom surge_admin template that omits {{MANAGED_CONFIG_HEADER}} must prepend line 1.
	customNoHeader := &store.SubTemplate{
		Name:       "No Header Surge Admin",
		ClientType: protocol.ClientTypeSurgeAdmin,
		Content:    "[General]\nloglevel = notify\n\n[Proxy]\n{{PROXIES}}\n\n[Proxy Group]\nProxy = select, {{PROXY_NAMES}}, DIRECT\n",
		IsDefault:  false,
	}
	if err := st.CreateSubTemplate(ctx, customNoHeader); err != nil {
		t.Fatal(err)
	}
	resCustom1, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{
		TemplateID: customNoHeader.ID,
		BaseURL:    "https://panel.example.com",
	})
	if err != nil {
		t.Fatalf("RenderAdmin(customNoHeader) failed: %v", err)
	}
	wantLine1 := fmt.Sprintf("#!MANAGED-CONFIG https://panel.example.com/s/admin/%s?tpl=%d interval=43200 strict=false", adminToken, customNoHeader.ID)
	if !strings.HasPrefix(resCustom1.Body, wantLine1+"\n[General]\n") {
		t.Fatalf("expected line 1 prepended with ?tpl=%d, got:\n%s", customNoHeader.ID, resCustom1.Body)
	}

	// Custom surge_admin template with stale #!MANAGED-CONFIG line 1 must replace line 1.
	customStaleHeader := &store.SubTemplate{
		Name:       "Stale Header Surge Admin",
		ClientType: protocol.ClientTypeSurgeAdmin,
		Content:    "#!MANAGED-CONFIG https://old.example.com/old interval=100 strict=true\n[General]\nloglevel = info\n",
		IsDefault:  false,
	}
	if err := st.CreateSubTemplate(ctx, customStaleHeader); err != nil {
		t.Fatal(err)
	}
	resCustom2, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{
		TemplateID: customStaleHeader.ID,
		BaseURL:    "https://new.example.com",
	})
	if err != nil {
		t.Fatalf("RenderAdmin(customStaleHeader) failed: %v", err)
	}
	if strings.Contains(resCustom2.Body, "old.example.com") {
		t.Fatalf("stale #!MANAGED-CONFIG header was not replaced:\n%s", resCustom2.Body)
	}
	wantLine1Stale := fmt.Sprintf("#!MANAGED-CONFIG https://new.example.com/s/admin/%s?tpl=%d interval=43200 strict=false", adminToken, customStaleHeader.ID)
	if !strings.HasPrefix(resCustom2.Body, wantLine1Stale+"\n[General]\n") {
		t.Fatalf("expected line 1 replaced, got:\n%s", resCustom2.Body)
	}

	// Nonexistent TemplateID -> ErrTemplateNotFound.
	if _, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{TemplateID: 99999}); !errors.Is(err, ErrTemplateNotFound) {
		t.Fatalf("expected ErrTemplateNotFound, got %v", err)
	}

	// Template with wrong ClientType -> ErrTemplateMismatch.
	mihomoTpls, err := st.ListSubTemplates(ctx, protocol.ClientTypeMihomoUser)
	if err != nil || len(mihomoTpls) == 0 {
		t.Fatalf("expected seeded mihomo_user template: %v", err)
	}
	if _, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{TemplateID: mihomoTpls[0].ID}); !errors.Is(err, ErrTemplateMismatch) {
		t.Fatalf("expected ErrTemplateMismatch, got %v", err)
	}

	// Remove default flag -> fallback to ListSubTemplates first item.
	adminTpls, err := st.ListSubTemplates(ctx, protocol.ClientTypeSurgeAdmin)
	if err != nil {
		t.Fatal(err)
	}
	for i := range adminTpls {
		if adminTpls[i].IsDefault {
			adminTpls[i].IsDefault = false
			if err := st.UpdateSubTemplate(ctx, &adminTpls[i]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{}); err != nil {
		t.Fatalf("expected fallback to first surge_admin template when no default, got %v", err)
	}

	// Delete all surge_admin templates -> ErrTemplateNotFound.
	for _, tpl := range adminTpls {
		if err := st.DeleteSubTemplate(ctx, tpl.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{}); !errors.Is(err, ErrTemplateNotFound) {
		t.Fatalf("expected ErrTemplateNotFound when no surge_admin templates exist, got %v", err)
	}
}

func TestRenderUserAuthStatesAndHeaders(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	fixedNow := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	r := NewRenderer(st, WithNow(func() time.Time { return fixedNow }))

	adminToken, err := st.GetSetting(ctx, "admin_sub_token")
	if err != nil {
		t.Fatal(err)
	}

	// Unknown token, empty token, and cross-track admin token -> ErrUnauthorized.
	for _, bad := range []string{"", "nonexistent", adminToken} {
		if _, err := r.RenderUser(ctx, bad, "", UserRenderOptions{}); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("RenderUser(%q) expected ErrUnauthorized, got %v", bad, err)
		}
	}

	// Disabled user -> ErrUserDisabled (wraps ErrForbidden) with Subscription-Userinfo header.
	disabledUser := mustNewUser(t, st, "disabled_u", false, 1000, 100, 200, nil)
	resDisabled, err := r.RenderUser(ctx, disabledUser.SubToken, "Surge/5", UserRenderOptions{})
	if !errors.Is(err, ErrUserDisabled) || !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrUserDisabled wrapping ErrForbidden, got %v", err)
	}
	if resDisabled == nil || resDisabled.Target != protocol.SubTargetSurge {
		t.Fatalf("expected non-nil RenderResult with target=surge, got %+v", resDisabled)
	}
	if got := resDisabled.Headers.Get("Subscription-Userinfo"); got != "upload=100; download=200; total=1000; expire=0" {
		t.Fatalf("unexpected Subscription-Userinfo: %q", got)
	}
	if got := resDisabled.Headers.Get("Profile-Update-Interval"); got != "12" {
		t.Fatalf("unexpected Profile-Update-Interval: %q", got)
	}

	// Expired user (ExpireAt == now boundary) -> ErrUserExpired with expire unix timestamp in header.
	expAt := fixedNow
	expiredUser := mustNewUser(t, st, "expired_u", true, 5000, 10, 20, &expAt)
	resExpired, err := r.RenderUser(ctx, expiredUser.SubToken, "", UserRenderOptions{Target: "shadowrocket"})
	if !errors.Is(err, ErrUserExpired) || !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrUserExpired wrapping ErrForbidden, got %v", err)
	}
	wantHeader := fmt.Sprintf("upload=10; download=20; total=5000; expire=%d", expAt.Unix())
	if got := resExpired.Headers.Get("Subscription-Userinfo"); got != wantHeader {
		t.Fatalf("expected %q, got %q", wantHeader, got)
	}

	// Quota-exhausted user (usedUp + usedDown == TrafficQuotaBytes) -> ErrUserQuotaExhausted.
	quotaUser := mustNewUser(t, st, "quota_u", true, 1000, 400, 600, nil)
	resQuota, err := r.RenderUser(ctx, quotaUser.SubToken, "", UserRenderOptions{})
	if !errors.Is(err, ErrUserQuotaExhausted) || !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrUserQuotaExhausted wrapping ErrForbidden, got %v", err)
	}
	if got := resQuota.Headers.Get("Subscription-Userinfo"); got != "upload=400; download=600; total=1000; expire=0" {
		t.Fatalf("unexpected Subscription-Userinfo: %q", got)
	}

	// Unlimited quota (TrafficQuotaBytes == 0) with high usage is allowed.
	futureExp := fixedNow.Add(24 * time.Hour)
	unlimitedUser := mustNewUser(t, st, "unlimited_u", true, 0, 999999, 888888, &futureExp)
	resOK, err := r.RenderUser(ctx, unlimitedUser.SubToken, "", UserRenderOptions{Mode: "proxy"})
	if err != nil {
		t.Fatalf("expected unlimited user to succeed, got %v", err)
	}
	wantUnlimitedHeader := fmt.Sprintf("upload=999999; download=888888; total=0; expire=%d", futureExp.Unix())
	if got := resOK.Headers.Get("Subscription-Userinfo"); got != wantUnlimitedHeader {
		t.Fatalf("expected %q, got %q", wantUnlimitedHeader, got)
	}
}

func TestRenderUserTargetDetectionAndValidation(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	r := NewRenderer(st)
	u := mustNewUser(t, st, "ua_user", true, 0, 0, 0, nil)

	tests := []struct {
		name       string
		explicit   string
		ua         string
		wantTarget string
	}{
		{name: "shadowrocket UA", ua: "Shadowrocket/2.2.15 CFNetwork/1404", wantTarget: protocol.SubTargetShadowrocket},
		{name: "surge UA", ua: "Surge iOS/3094 CFNetwork/1404", wantTarget: protocol.SubTargetSurge},
		{name: "mihomo UA", ua: "ClashMetaForAndroid/2.10", wantTarget: protocol.SubTargetMihomo},
		{name: "empty UA defaults mihomo", ua: "", wantTarget: protocol.SubTargetMihomo},
		{name: "shadowrocket beats surge", ua: "Shadowrocket Surge", wantTarget: protocol.SubTargetShadowrocket},
		{name: "explicit overrides UA", explicit: "surge", ua: "Shadowrocket/2.2", wantTarget: protocol.SubTargetSurge},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := r.RenderUser(ctx, u.SubToken, tc.ua, UserRenderOptions{Target: tc.explicit, Mode: "proxy"})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Target != tc.wantTarget {
				t.Fatalf("expected target=%q, got %q", tc.wantTarget, res.Target)
			}
		})
	}

	if _, err := r.RenderUser(ctx, u.SubToken, "", UserRenderOptions{Target: "quantumult"}); !errors.Is(err, ErrInvalidTarget) || !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidTarget, got %v", err)
	}
	if _, err := r.RenderUser(ctx, u.SubToken, "", UserRenderOptions{Mode: "invalid"}); !errors.Is(err, ErrInvalidMode) || !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidMode, got %v", err)
	}
	if _, err := r.RenderUser(ctx, u.SubToken, "", UserRenderOptions{BaseURL: "https://evil.com\r\n"}); !errors.Is(err, ErrInvalidBaseURL) {
		t.Fatalf("expected ErrInvalidBaseURL, got %v", err)
	}
}

func TestRenderUserTargetsAndZeroSnellLeakage(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	r := NewRenderer(st)

	user := mustNewUser(t, st, "bob", true, 10<<30, 1234, 5678, nil)

	ipsk16, err := auth.GenerateIPSKForCipher(protocol.CipherAES128GCM)
	if err != nil {
		t.Fatal(err)
	}
	ipsk32, err := auth.GenerateIPSKForCipher(protocol.CipherAES256GCM)
	if err != nil {
		t.Fatal(err)
	}

	// Node A (sort_order=2): AES-128-GCM, also has SnellConfig enabled with unique secret tokens to verify zero leakage!
	nodeA := mustNewNode(t, st, store.Node{
		Name:      `🇭🇰 HK: "01" #vip`,
		PublicIP:  "203.0.113.11",
		SortOrder: 2,
		Enabled:   true,
		SnellConfig: protocol.SnellConfig{
			Enabled:      true,
			Version:      protocol.SnellVersionV5,
			PublicPort:   44444,
			PSK:          "SECRET_SNELL_PSK_DO_NOT_LEAK",
			STLSPassword: "SECRET_SNELL_STLS_DO_NOT_LEAK",
			STLSSNI:      "snell-only.invalid",
		},
		SSConfig: protocol.SSConfig{
			Enabled: true,
			TCPPort: 8443,
			UDPPort: 9443, // distinct UDP port
			Cipher:  protocol.CipherAES128GCM,
			IPSK:    ipsk16,
			STLSSNI: "gateway.icloud.com:443",
		},
	})

	// Node B (sort_order=1): AES-256-GCM, IPv6 PublicIPv6 fallback, CustomEntryPort overriding unified TCP/UDP port.
	nodeB := mustNewNode(t, st, store.Node{
		Name:            "🇯🇵 JP, Edge=1",
		PublicIPv6:      "[2001:db8::2]",
		CustomEntryPort: 18443,
		SortOrder:       1,
		Enabled:         true,
		SSConfig: protocol.SSConfig{
			Enabled: true,
			TCPPort: 8443,
			UDPPort: 8443, // matches TCPPort -> CustomEntryPort overrides both!
			Cipher:  protocol.CipherAES256GCM,
			IPSK:    ipsk32,
			STLSSNI: "swcdn.apple.com",
		},
	})

	// Node C: Paused with stop_ss_only -> MUST BE EXCLUDED from user track!
	nodePausedSS := mustNewNode(t, st, store.Node{
		Name:            "Paused SS Only",
		PublicIP:        "203.0.113.33",
		SortOrder:       3,
		Enabled:         true,
		IsTrafficPaused: true,
		ThresholdAction: protocol.ThresholdActionStopSSOnly,
		SnellConfig: protocol.SnellConfig{
			Enabled:      true,
			Version:      protocol.SnellVersionV5,
			PublicPort:   8443,
			PSK:          "SECRET_SNELL_PAUSED",
			STLSPassword: "SECRET_STLS_PAUSED",
			STLSSNI:      "gateway.icloud.com",
		},
		SSConfig: protocol.SSConfig{
			Enabled: true,
			TCPPort: 8443,
			UDPPort: 8443,
			Cipher:  protocol.CipherAES128GCM,
			IPSK:    ipsk16,
			STLSSNI: "gateway.icloud.com",
		},
	})

	// Node D: Snell-only node (SSConfig.Enabled == false) authorized to user -> MUST BE EXCLUDED!
	nodeSnellOnly := mustNewNode(t, st, store.Node{
		Name:      "Snell Only Node",
		PublicIP:  "203.0.113.44",
		SortOrder: 4,
		Enabled:   true,
		SnellConfig: protocol.SnellConfig{
			Enabled:      true,
			Version:      protocol.SnellVersionV5,
			PublicPort:   8443,
			PSK:          "SECRET_SNELL_ONLY",
			STLSPassword: "SECRET_STLS_ONLY",
			STLSSNI:      "gateway.icloud.com",
		},
	})

	// Node E: Authorized SS node not assigned to user -> MUST BE EXCLUDED!
	mustNewNode(t, st, store.Node{
		Name:      "Unauthorized Node",
		PublicIP:  "203.0.113.55",
		SortOrder: 5,
		Enabled:   true,
		SSConfig: protocol.SSConfig{
			Enabled: true,
			TCPPort: 8443,
			UDPPort: 8443,
			Cipher:  protocol.CipherAES128GCM,
			IPSK:    ipsk16,
			STLSSNI: "gateway.icloud.com",
		},
	})

	if err := st.SetUserNodes(ctx, user.ID, []int64{nodeA.ID, nodeB.ID, nodePausedSS.ID, nodeSnellOnly.ID}); err != nil {
		t.Fatal(err)
	}

	assertZeroSnell := func(t *testing.T, body string) {
		t.Helper()
		lower := strings.ToLower(body)
		for _, forbidden := range []string{
			"snell",
			"secret_snell",
			"snell-only.invalid",
			"paused ss only",
			"snell only node",
			"unauthorized node",
		} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("user subscription leaked forbidden string %q in:\n%s", forbidden, body)
			}
		}
	}

	// 1. Mihomo proxy & full
	resMihomoProxy, err := r.RenderUser(ctx, user.SubToken, "", UserRenderOptions{Target: "mihomo", Mode: "proxy"})
	if err != nil {
		t.Fatalf("RenderUser(mihomo, proxy) failed: %v", err)
	}
	assertZeroSnell(t, resMihomoProxy.Body)
	if resMihomoProxy.ContentType != "text/yaml; charset=utf-8" || resMihomoProxy.NodeCount != 2 {
		t.Fatalf("unexpected mihomo proxy metadata: ct=%q count=%d", resMihomoProxy.ContentType, resMihomoProxy.NodeCount)
	}
	var parsedProxy struct {
		Proxies []mihomoProxy `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(resMihomoProxy.Body), &parsedProxy); err != nil {
		t.Fatalf("yaml.Unmarshal mihomo proxy failed: %v\n%s", err, resMihomoProxy.Body)
	}
	if len(parsedProxy.Proxies) != 2 {
		t.Fatalf("expected 2 mihomo proxies, got %d", len(parsedProxy.Proxies))
	}
	p0 := parsedProxy.Proxies[0] // Node B (sort_order=1)
	if p0.Name != "🇯🇵 JP, Edge=1" || p0.Type != "ss" || p0.Server != "2001:db8::2" || p0.Port != 18443 ||
		p0.Cipher != protocol.CipherAES256GCM || p0.Password != ipsk32+":"+user.SSUPSK32 ||
		!p0.UDP || !p0.UDPOverTCP || p0.UDPOverTCPVersion != 2 || p0.ClientFingerprint != "chrome" ||
		p0.Plugin != "shadow-tls" || p0.PluginOpts.Host != "swcdn.apple.com" || p0.PluginOpts.Password != user.STLSPassword || p0.PluginOpts.Version != 3 {
		t.Fatalf("unexpected mihomo proxy[0]: %+v", p0)
	}
	p1 := parsedProxy.Proxies[1] // Node A (sort_order=2)
	if p1.Name != `🇭🇰 HK: "01" #vip` || p1.Server != "203.0.113.11" || p1.Port != 8443 ||
		p1.Cipher != protocol.CipherAES128GCM || p1.Password != ipsk16+":"+user.SSUPSK16 ||
		p1.PluginOpts.Host != "gateway.icloud.com" {
		t.Fatalf("unexpected mihomo proxy[1]: %+v", p1)
	}

	resMihomoFull, err := r.RenderUser(ctx, user.SubToken, "", UserRenderOptions{Target: "mihomo", Mode: "full"})
	if err != nil {
		t.Fatalf("RenderUser(mihomo, full) failed: %v", err)
	}
	assertZeroSnell(t, resMihomoFull.Body)
	var parsedFull struct {
		Proxies     []mihomoProxy `yaml:"proxies"`
		ProxyGroups []struct {
			Name    string   `yaml:"name"`
			Type    string   `yaml:"type"`
			Proxies []string `yaml:"proxies"`
		} `yaml:"proxy-groups"`
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal([]byte(resMihomoFull.Body), &parsedFull); err != nil {
		t.Fatalf("yaml.Unmarshal mihomo full failed: %v\n%s", err, resMihomoFull.Body)
	}
	if len(parsedFull.Proxies) != 2 || len(parsedFull.ProxyGroups) < 3 {
		t.Fatalf("unexpected parsed full mihomo: proxies=%d groups=%d", len(parsedFull.Proxies), len(parsedFull.ProxyGroups))
	}
	if len(parsedFull.ProxyGroups[0].Proxies) != 5 ||
		parsedFull.ProxyGroups[0].Proxies[0] != "♻️ 自动选择" ||
		parsedFull.ProxyGroups[0].Proxies[1] != "🔯 故障转移" ||
		parsedFull.ProxyGroups[0].Proxies[2] != "🇯🇵 JP, Edge=1" ||
		parsedFull.ProxyGroups[0].Proxies[3] != `🇭🇰 HK: "01" #vip` ||
		parsedFull.ProxyGroups[0].Proxies[4] != "DIRECT" {
		t.Fatalf("unexpected 节点选择 group members: %v", parsedFull.ProxyGroups[0].Proxies)
	}

	// 2. Surge user proxy & full
	resSurgeProxy, err := r.RenderUser(ctx, user.SubToken, "", UserRenderOptions{Target: "surge", Mode: "proxy"})
	if err != nil {
		t.Fatalf("RenderUser(surge, proxy) failed: %v", err)
	}
	assertZeroSnell(t, resSurgeProxy.Body)
	surgeLines := strings.Split(strings.TrimSuffix(resSurgeProxy.Body, "\n"), "\n")
	if len(surgeLines) != 2 {
		t.Fatalf("expected 2 surge lines, got %d", len(surgeLines))
	}
	wantSurge0 := fmt.Sprintf(
		"🇯🇵 JP- Edge-1 = ss, 2001:db8::2, 18443, encrypt-method=%s, password=%s:%s, shadow-tls-password=%s, shadow-tls-sni=swcdn.apple.com, shadow-tls-version=3, udp-relay=true, udp-port=18443, tfo=true",
		protocol.CipherAES256GCM, ipsk32, user.SSUPSK32, user.STLSPassword,
	)
	wantSurge1 := fmt.Sprintf(
		`🇭🇰 HK: "01" #vip = ss, 203.0.113.11, 8443, encrypt-method=%s, password=%s:%s, shadow-tls-password=%s, shadow-tls-sni=gateway.icloud.com, shadow-tls-version=3, udp-relay=true, udp-port=9443, tfo=true`,
		protocol.CipherAES128GCM, ipsk16, user.SSUPSK16, user.STLSPassword,
	)
	if surgeLines[0] != wantSurge0 {
		t.Fatalf("surge line[0] mismatch:\ngot:  %s\nwant: %s", surgeLines[0], wantSurge0)
	}
	if surgeLines[1] != wantSurge1 {
		t.Fatalf("surge line[1] mismatch:\ngot:  %s\nwant: %s", surgeLines[1], wantSurge1)
	}

	resSurgeFull, err := r.RenderUser(ctx, user.SubToken, "", UserRenderOptions{
		Target:  "surge",
		Mode:    "full",
		BaseURL: "https://panel.example.com",
	})
	if err != nil {
		t.Fatalf("RenderUser(surge, full) failed: %v", err)
	}
	assertZeroSnell(t, resSurgeFull.Body)
	wantSurgeLine1 := fmt.Sprintf("#!MANAGED-CONFIG https://panel.example.com/s/u/%s?target=surge interval=43200 strict=false", user.SubToken)
	if !strings.HasPrefix(resSurgeFull.Body, wantSurgeLine1+"\n") {
		t.Fatalf("expected Surge user line 1 %q, got:\n%s", wantSurgeLine1, resSurgeFull.Body)
	}

	// 3. Shadowrocket Base64 URI verification
	resRocket, err := r.RenderUser(ctx, user.SubToken, "Shadowrocket/2.2", UserRenderOptions{})
	if err != nil {
		t.Fatalf("RenderUser(shadowrocket) failed: %v", err)
	}
	if resRocket.NodeCount != 2 || resRocket.ContentType != "text/plain; charset=utf-8" {
		t.Fatalf("unexpected shadowrocket metadata: count=%d ct=%q", resRocket.NodeCount, resRocket.ContentType)
	}
	decodedOuter, err := base64.StdEncoding.DecodeString(resRocket.Body)
	if err != nil {
		t.Fatalf("outer base64 decode failed: %v", err)
	}
	assertZeroSnell(t, string(decodedOuter))
	uris := strings.Split(string(decodedOuter), "\n")
	if len(uris) != 2 {
		t.Fatalf("expected 2 shadowrocket URIs, got %d: %v", len(uris), uris)
	}

	u0, err := url.Parse(uris[0])
	if err != nil {
		t.Fatalf("url.Parse(uris[0]) failed: %v (%s)", err, uris[0])
	}
	if u0.Scheme != "ss" || u0.Host != "[2001:db8::2]:18443" || u0.Fragment != "🇯🇵 JP, Edge=1" {
		t.Fatalf("unexpected u0: scheme=%q host=%q frag=%q", u0.Scheme, u0.Host, u0.Fragment)
	}
	rawInfo0, err := base64.RawURLEncoding.DecodeString(u0.User.Username())
	if err != nil {
		t.Fatalf("decode u0 userinfo failed: %v", err)
	}
	if string(rawInfo0) != protocol.CipherAES256GCM+":"+ipsk32+":"+user.SSUPSK32 {
		t.Fatalf("unexpected u0 userinfo: %q", string(rawInfo0))
	}
	q0 := u0.Query()
	if q0.Get("uot") != "1" {
		t.Fatalf("expected uot=1, got %q", q0.Get("uot"))
	}
	stlsBytes0, err := base64.StdEncoding.DecodeString(q0.Get("shadow-tls"))
	if err != nil {
		t.Fatalf("decode shadow-tls param failed: %v", err)
	}
	var stlsObj0 struct {
		Version  string `json:"version"`
		Password string `json:"password"`
		Host     string `json:"host"`
	}
	if err := json.Unmarshal(stlsBytes0, &stlsObj0); err != nil {
		t.Fatalf("unmarshal shadow-tls json failed: %v", err)
	}
	if stlsObj0.Version != "3" || stlsObj0.Password != user.STLSPassword || stlsObj0.Host != "swcdn.apple.com" {
		t.Fatalf("unexpected shadow-tls params: %+v", stlsObj0)
	}

	u1, err := url.Parse(uris[1])
	if err != nil {
		t.Fatalf("url.Parse(uris[1]) failed: %v (%s)", err, uris[1])
	}
	if u1.Host != "203.0.113.11:8443" || u1.Fragment != `🇭🇰 HK: "01" #vip` {
		t.Fatalf("unexpected u1 host=%q frag=%q", u1.Host, u1.Fragment)
	}

	// Shadowrocket rejects TemplateID > 0 with ErrTemplateMismatch.
	if _, err := r.RenderUser(ctx, user.SubToken, "", UserRenderOptions{
		Target:     "shadowrocket",
		TemplateID: 1,
	}); !errors.Is(err, ErrTemplateMismatch) {
		t.Fatalf("expected ErrTemplateMismatch for shadowrocket with TemplateID, got %v", err)
	}

	// Wrong template type for Mihomo -> ErrTemplateMismatch; missing -> ErrTemplateNotFound.
	surgeUserTpls, err := st.ListSubTemplates(ctx, protocol.ClientTypeSurgeUser)
	if err != nil || len(surgeUserTpls) == 0 {
		t.Fatal(err)
	}
	if _, err := r.RenderUser(ctx, user.SubToken, "", UserRenderOptions{
		Target:     "mihomo",
		TemplateID: surgeUserTpls[0].ID,
	}); !errors.Is(err, ErrTemplateMismatch) {
		t.Fatalf("expected ErrTemplateMismatch for mihomo with surge_user tpl, got %v", err)
	}
	if _, err := r.RenderUser(ctx, user.SubToken, "", UserRenderOptions{
		Target:     "mihomo",
		TemplateID: 99999,
	}); !errors.Is(err, ErrTemplateNotFound) {
		t.Fatalf("expected ErrTemplateNotFound, got %v", err)
	}
}

func TestRenderUserZeroNodesAcrossAllTargets(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	r := NewRenderer(st)

	user := mustNewUser(t, st, "empty_user", true, 0, 0, 0, nil)

	// Mihomo mode=proxy (0 nodes)
	resMProxy, err := r.RenderUser(ctx, user.SubToken, "", UserRenderOptions{Target: "mihomo", Mode: "proxy"})
	if err != nil {
		t.Fatalf("mihomo proxy 0-node failed: %v", err)
	}
	if resMProxy.Body != "proxies: []\n" || resMProxy.NodeCount != 0 {
		t.Fatalf("unexpected mihomo proxy 0-node output: %q", resMProxy.Body)
	}
	var mProxyDoc struct {
		Proxies []mihomoProxy `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(resMProxy.Body), &mProxyDoc); err != nil {
		t.Fatalf("yaml.Unmarshal failed: %v", err)
	}

	// Mihomo mode=full (0 nodes)
	resMFull, err := r.RenderUser(ctx, user.SubToken, "", UserRenderOptions{Target: "mihomo", Mode: "full"})
	if err != nil {
		t.Fatalf("mihomo full 0-node failed: %v", err)
	}
	var mFullDoc struct {
		Proxies     []mihomoProxy `yaml:"proxies"`
		ProxyGroups []struct {
			Name    string   `yaml:"name"`
			Proxies []string `yaml:"proxies"`
		} `yaml:"proxy-groups"`
	}
	if err := yaml.Unmarshal([]byte(resMFull.Body), &mFullDoc); err != nil {
		t.Fatalf("yaml.Unmarshal mihomo full 0-node failed: %v\n%s", err, resMFull.Body)
	}
	if len(mFullDoc.Proxies) != 0 {
		t.Fatalf("expected 0 proxies, got %d", len(mFullDoc.Proxies))
	}
	for _, g := range mFullDoc.ProxyGroups {
		if len(g.Proxies) == 0 {
			t.Fatalf("group %s has empty proxies list in 0-node template\n%s", g.Name, resMFull.Body)
		}
		if (g.Name == "♻️ 自动选择" || g.Name == "🔯 故障转移") && (len(g.Proxies) != 1 || g.Proxies[0] != "DIRECT") {
			t.Fatalf("group %s expected [DIRECT], got %v\n%s", g.Name, g.Proxies, resMFull.Body)
		}
		directCount := 0
		for _, p := range g.Proxies {
			if p == "DIRECT" {
				directCount++
			}
		}
		if directCount > 1 {
			t.Fatalf("group %s contains duplicate DIRECT entries: %v\n%s", g.Name, g.Proxies, resMFull.Body)
		}
	}

	// Surge mode=full (0 nodes)
	resSFull, err := r.RenderUser(ctx, user.SubToken, "", UserRenderOptions{Target: "surge", Mode: "full", BaseURL: "https://panel.example.com"})
	if err != nil {
		t.Fatalf("surge full 0-node failed: %v", err)
	}
	if !strings.Contains(resSFull.Body, "🚀 节点选择 = select, ♻️ 自动选择, 🔯 故障转移, DIRECT\n") || strings.Contains(resSFull.Body, "DIRECT, DIRECT") {
		t.Fatalf("unexpected surge 0-node output:\n%s", resSFull.Body)
	}

	// Shadowrocket (0 nodes)
	resRocket, err := r.RenderUser(ctx, user.SubToken, "", UserRenderOptions{Target: "shadowrocket"})
	if err != nil {
		t.Fatalf("shadowrocket 0-node failed: %v", err)
	}
	if resRocket.Body != "" || resRocket.NodeCount != 0 {
		t.Fatalf("expected empty body for 0-node shadowrocket, got %q", resRocket.Body)
	}
}

func TestRenderConcurrentRaceSafety(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	r := NewRenderer(st)

	adminToken, err := st.GetSetting(ctx, "admin_sub_token")
	if err != nil {
		t.Fatal(err)
	}
	user := mustNewUser(t, st, "concurrent_u", true, 10<<30, 10, 20, nil)
	ipsk, err := auth.GenerateIPSKForCipher(protocol.CipherAES128GCM)
	if err != nil {
		t.Fatal(err)
	}
	n := mustNewNode(t, st, store.Node{
		Name:     "Concurrent Node",
		PublicIP: "203.0.113.99",
		Enabled:  true,
		SnellConfig: protocol.SnellConfig{
			Enabled:      true,
			Version:      protocol.SnellVersionV5,
			PublicPort:   8443,
			PSK:          "snellpsk99",
			STLSPassword: "stlspwd99",
			STLSSNI:      "gateway.icloud.com",
		},
		SSConfig: protocol.SSConfig{
			Enabled: true,
			TCPPort: 8443,
			UDPPort: 8443,
			Cipher:  protocol.CipherAES128GCM,
			IPSK:    ipsk,
			STLSSNI: "gateway.icloud.com",
		},
	})
	if err := st.SetUserNodes(ctx, user.ID, []int64{n.ID}); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			res, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{BaseURL: "https://panel.example.com"})
			if err != nil {
				errs <- err
				return
			}
			if res.NodeCount != 1 {
				errs <- fmt.Errorf("admin node count=%d", res.NodeCount)
			}
		}()
		go func(idx int) {
			defer wg.Done()
			target := protocol.SubTargetMihomo
			switch idx % 3 {
			case 1:
				target = protocol.SubTargetSurge
			case 2:
				target = protocol.SubTargetShadowrocket
			}
			res, err := r.RenderUser(ctx, user.SubToken, "", UserRenderOptions{
				Target:  target,
				BaseURL: "https://panel.example.com",
			})
			if err != nil {
				errs <- err
				return
			}
			if res.NodeCount != 1 {
				errs <- fmt.Errorf("user target=%s node count=%d", target, res.NodeCount)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestRenderEdgeCasesAndCustomTemplates(t *testing.T) {
	ctx := context.Background()

	// Nil store returns ErrInvalidArgument cleanly without panic.
	nilRenderer := NewRenderer(nil)
	if _, err := nilRenderer.RenderAdmin(ctx, "tok", AdminRenderOptions{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument on nil store RenderAdmin, got %v", err)
	}
	if _, err := nilRenderer.RenderUser(ctx, "tok", "", UserRenderOptions{}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument on nil store RenderUser, got %v", err)
	}

	st := openTestStore(t)
	r := NewRenderer(st)

	adminToken, err := st.GetSetting(ctx, "admin_sub_token")
	if err != nil {
		t.Fatal(err)
	}
	user := mustNewUser(t, st, "edge_u", true, 0, 0, 0, nil)
	ipsk, err := auth.GenerateIPSKForCipher(protocol.CipherAES128GCM)
	if err != nil {
		t.Fatal(err)
	}

	// Valid user node with CustomEntryHost overriding PublicIP and UDPPort=0 falling back to tcpPort.
	validNode := mustNewNode(t, st, store.Node{
		Name:            "Edge Valid",
		PublicIP:        "198.51.100.10",
		CustomEntryHost: "cdn.edge.example.com",
		Enabled:         true,
		SSConfig: protocol.SSConfig{
			Enabled: true,
			TCPPort: 8443,
			UDPPort: 0,
			Cipher:  protocol.CipherAES128GCM,
			IPSK:    ipsk,
			STLSSNI: "gateway.icloud.com",
		},
	})

	// Malformed/incomplete nodes that must be skipped without breaking valid output.
	badHostNode := mustNewNode(t, st, store.Node{
		Name:    "No Host",
		Enabled: true,
		SnellConfig: protocol.SnellConfig{
			Enabled: true, Version: protocol.SnellVersionV5, PublicPort: 8443, PSK: "p", STLSPassword: "s", STLSSNI: "a.com",
		},
		SSConfig: protocol.SSConfig{
			Enabled: true, TCPPort: 8443, UDPPort: 8443, Cipher: protocol.CipherAES128GCM, IPSK: ipsk, STLSSNI: "a.com",
		},
	})
	badPortNode := mustNewNode(t, st, store.Node{
		Name: "Zero Port", PublicIP: "198.51.100.11", Enabled: true,
		SnellConfig: protocol.SnellConfig{
			Enabled: true, Version: protocol.SnellVersionV5, PublicPort: 0, PSK: "p", STLSPassword: "s", STLSSNI: "a.com",
		},
		SSConfig: protocol.SSConfig{
			Enabled: true, TCPPort: 0, UDPPort: 0, Cipher: protocol.CipherAES128GCM, IPSK: ipsk, STLSSNI: "a.com",
		},
	})
	badSNINode := mustNewNode(t, st, store.Node{
		Name: "Bad SNI", PublicIP: "198.51.100.12", Enabled: true,
		SnellConfig: protocol.SnellConfig{
			Enabled: true, Version: protocol.SnellVersionV5, PublicPort: 8443, PSK: "p", STLSPassword: "s", STLSSNI: "bad sni",
		},
		SSConfig: protocol.SSConfig{
			Enabled: true, TCPPort: 8443, UDPPort: 8443, Cipher: protocol.CipherAES128GCM, IPSK: ipsk, STLSSNI: "bad sni",
		},
	})

	if err := st.SetUserNodes(ctx, user.ID, []int64{validNode.ID, badHostNode.ID, badPortNode.ID, badSNINode.ID}); err != nil {
		t.Fatal(err)
	}

	resAdmin, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{Mode: "proxy"})
	if err != nil {
		t.Fatalf("RenderAdmin failed: %v", err)
	}
	if resAdmin.NodeCount != 0 {
		t.Fatalf("expected 0 valid admin nodes, got %d:\n%s", resAdmin.NodeCount, resAdmin.Body)
	}

	resSurgeProxy, err := r.RenderUser(ctx, user.SubToken, "", UserRenderOptions{Target: "surge", Mode: "proxy"})
	if err != nil {
		t.Fatalf("RenderUser(surge, proxy) failed: %v", err)
	}
	if resSurgeProxy.NodeCount != 1 {
		t.Fatalf("expected 1 valid user node, got %d:\n%s", resSurgeProxy.NodeCount, resSurgeProxy.Body)
	}
	if !strings.Contains(resSurgeProxy.Body, "Edge Valid = ss, cdn.edge.example.com, 8443,") || !strings.Contains(resSurgeProxy.Body, "udp-port=8443,") {
		t.Fatalf("expected CustomEntryHost and udp-port fallback in:\n%s", resSurgeProxy.Body)
	}

	// Custom surge_user template with TemplateID in #!MANAGED-CONFIG URL.
	customSurgeUser := &store.SubTemplate{
		Name:       "Custom Surge User",
		ClientType: protocol.ClientTypeSurgeUser,
		Content:    "[General]\nloglevel = info\n[Proxy]\n{{PROXIES}}\n[Proxy Group]\nProxy = select, {{PROXY_NAMES}}, DIRECT\n",
	}
	if err := st.CreateSubTemplate(ctx, customSurgeUser); err != nil {
		t.Fatal(err)
	}
	resSurgeFull, err := r.RenderUser(ctx, user.SubToken, "", UserRenderOptions{
		Target:     "surge",
		Mode:       "full",
		TemplateID: customSurgeUser.ID,
		BaseURL:    "https://panel.example.com/",
	})
	if err != nil {
		t.Fatalf("RenderUser(surge, full, tpl) failed: %v", err)
	}
	wantSurgeHeader := fmt.Sprintf("#!MANAGED-CONFIG https://panel.example.com/s/u/%s?target=surge&tpl=%d interval=43200 strict=false", user.SubToken, customSurgeUser.ID)
	if !strings.HasPrefix(resSurgeFull.Body, wantSurgeHeader+"\n") {
		t.Fatalf("expected header %q, got:\n%s", wantSurgeHeader, resSurgeFull.Body)
	}

	// Custom mihomo_user template with 4-space group indentation.
	customMihomo := &store.SubTemplate{
		Name:       "Custom Mihomo 4-space",
		ClientType: protocol.ClientTypeMihomoUser,
		Content: `mode: rule
proxies:
{{PROXIES}}
proxy-groups:
  - name: Proxy
    type: select
    proxies:
{{PROXY_NAMES_YAML}}
      - DIRECT
`,
	}
	if err := st.CreateSubTemplate(ctx, customMihomo); err != nil {
		t.Fatal(err)
	}
	resMihomoCustom, err := r.RenderUser(ctx, user.SubToken, "", UserRenderOptions{
		Target:     "mihomo",
		Mode:       "full",
		TemplateID: customMihomo.ID,
	})
	if err != nil {
		t.Fatalf("RenderUser(mihomo, custom) failed: %v", err)
	}
	var doc any
	if err := yaml.Unmarshal([]byte(resMihomoCustom.Body), &doc); err != nil {
		t.Fatalf("custom mihomo YAML unmarshal failed: %v\n%s", err, resMihomoCustom.Body)
	}

	// Invalid YAML custom mihomo_user template returns ErrInvalidArgument.
	badMihomo := &store.SubTemplate{
		Name:       "Broken YAML",
		ClientType: protocol.ClientTypeMihomoUser,
		Content:    "proxies:\n{{PROXIES}}\nbad: [\n",
	}
	if err := st.CreateSubTemplate(ctx, badMihomo); err != nil {
		t.Fatal(err)
	}
	if _, err := r.RenderUser(ctx, user.SubToken, "", UserRenderOptions{
		Target:     "mihomo",
		Mode:       "full",
		TemplateID: badMihomo.ID,
	}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for invalid YAML template, got %v", err)
	}
}

func TestRegressionBaseURLValidation(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	r := NewRenderer(st)

	adminToken, err := st.GetSetting(ctx, "admin_sub_token")
	if err != nil {
		t.Fatal(err)
	}
	user := mustNewUser(t, st, "baseurl_u", true, 0, 0, 0, nil)

	invalidURLs := []string{
		"https://panel.example.com?foo=bar",
		"https://panel.example.com#frag",
		"https://panel.example.com?",
		"https://panel.example.com#",
		"javascript:alert(1)",
		"ftp://panel.example.com",
		"//evil.com",
		"https://user:pass@panel.example.com",
		"https://user@panel.example.com",
		"https://",
		"https:///",
		"http://",
	}
	for _, bad := range invalidURLs {
		if _, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{BaseURL: bad}); !errors.Is(err, ErrInvalidBaseURL) {
			t.Fatalf("RenderAdmin(%q) expected ErrInvalidBaseURL, got %v", bad, err)
		}
		if _, err := r.RenderUser(ctx, user.SubToken, "", UserRenderOptions{Target: "surge", BaseURL: bad}); !errors.Is(err, ErrInvalidBaseURL) {
			t.Fatalf("RenderUser(%q) expected ErrInvalidBaseURL, got %v", bad, err)
		}
	}

	validCases := []struct {
		raw  string
		want string
	}{
		{raw: "", want: ""},
		{raw: "///", want: ""},
		{raw: "https://panel.example.com///", want: "https://panel.example.com"},
		{raw: "http://panel.example.com:8080/sub/", want: "http://panel.example.com:8080/sub"},
		{raw: "https://[2001:db8::1]:8443/", want: "https://[2001:db8::1]:8443"},
	}
	for _, tc := range validCases {
		res, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{BaseURL: tc.raw})
		if err != nil {
			t.Fatalf("RenderAdmin(%q) unexpected error: %v", tc.raw, err)
		}
		wantPrefix := fmt.Sprintf("#!MANAGED-CONFIG %s/s/admin/%s interval=43200 strict=false\n", tc.want, adminToken)
		if !strings.HasPrefix(res.Body, wantPrefix) {
			t.Fatalf("RenderAdmin(%q) expected prefix %q, got:\n%s", tc.raw, wantPrefix, res.Body)
		}
	}
}

func TestRegressionManagedConfigWhitespaceAndDeduplication(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	r := NewRenderer(st)

	adminToken, err := st.GetSetting(ctx, "admin_sub_token")
	if err != nil {
		t.Fatal(err)
	}
	user := mustNewUser(t, st, "managed_u", true, 0, 0, 0, nil)

	cases := []struct {
		name       string
		clientType string
		content    string
		wantBody   func(header string) string
	}{
		{
			name:       "leading whitespace-only CRLF lines before stale managed config",
			clientType: protocol.ClientTypeSurgeAdmin,
			content:    "  \r\n\t\r\n#!MANAGED-CONFIG http://old.example.com/sub\r\n[General]\r\nloglevel = info\r\n",
			wantBody: func(header string) string {
				return header + "\n[General]\nloglevel = info\n"
			},
		},
		{
			name:       "leading whitespace before stale managed config",
			clientType: protocol.ClientTypeSurgeAdmin,
			content:    "   \n   #!MANAGED-CONFIG http://old.example.com/old\n[General]\n",
			wantBody: func(header string) string {
				return header + "\n[General]\n"
			},
		},
		{
			name:       "duplicate literal line1 and placeholder later",
			clientType: protocol.ClientTypeSurgeAdmin,
			content:    "#!MANAGED-CONFIG http://old.example.com/1\n[General]\n{{MANAGED_CONFIG_HEADER}}\n[Proxy]\n{{PROXIES}}\n",
			wantBody: func(header string) string {
				return header + "\n[General]\n[Proxy]\n"
			},
		},
		{
			name:       "placeholder placed later without line 1",
			clientType: protocol.ClientTypeSurgeUser,
			content:    "[General]\nloglevel = notify\n{{MANAGED_CONFIG_HEADER}}\n[Proxy]\n{{PROXIES}}\n",
			wantBody: func(header string) string {
				return header + "\n[General]\nloglevel = notify\n[Proxy]\n"
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tpl := &store.SubTemplate{
				Name:       tc.name,
				ClientType: tc.clientType,
				Content:    tc.content,
			}
			if err := st.CreateSubTemplate(ctx, tpl); err != nil {
				t.Fatal(err)
			}

			var body string
			var wantHeader string
			if tc.clientType == protocol.ClientTypeSurgeAdmin {
				res, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{
					Mode:       ModeFull,
					TemplateID: tpl.ID,
					BaseURL:    "https://new.example.com",
				})
				if err != nil {
					t.Fatalf("RenderAdmin failed: %v", err)
				}
				body = res.Body
				wantHeader = fmt.Sprintf("#!MANAGED-CONFIG https://new.example.com/s/admin/%s?tpl=%d interval=43200 strict=false", adminToken, tpl.ID)
			} else {
				res, err := r.RenderUser(ctx, user.SubToken, "", UserRenderOptions{
					Target:     protocol.SubTargetSurge,
					Mode:       ModeFull,
					TemplateID: tpl.ID,
					BaseURL:    "https://new.example.com",
				})
				if err != nil {
					t.Fatalf("RenderUser failed: %v", err)
				}
				body = res.Body
				wantHeader = fmt.Sprintf("#!MANAGED-CONFIG https://new.example.com/s/u/%s?target=surge&tpl=%d interval=43200 strict=false", user.SubToken, tpl.ID)
			}

			if strings.Contains(body, "\r") {
				t.Fatalf("unexpected CR in output: %q", body)
			}
			if strings.Contains(body, "old.example.com") {
				t.Fatalf("stale managed config survived in output:\n%s", body)
			}
			if count := strings.Count(body, "#!MANAGED-CONFIG"); count != 1 {
				t.Fatalf("expected exactly 1 #!MANAGED-CONFIG directive, got %d:\n%s", count, body)
			}
			if body != tc.wantBody(wantHeader) {
				t.Fatalf("body mismatch:\ngot:\n%s\nwant:\n%s", body, tc.wantBody(wantHeader))
			}
		})
	}
}

func TestRegressionResolveEntryHostValidation(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	r := NewRenderer(st)

	adminToken, err := st.GetSetting(ctx, "admin_sub_token")
	if err != nil {
		t.Fatal(err)
	}
	user := mustNewUser(t, st, "host_u", true, 0, 0, 0, nil)
	ipsk, err := auth.GenerateIPSKForCipher(protocol.CipherAES128GCM)
	if err != nil {
		t.Fatal(err)
	}

	badHosts := []string{
		"[2001:db8::1",
		"2001:db8::1]",
		"[[2001:db8::1]]",
		"evil.com:9999",
		"evil.com/path",
		"evil.com?x",
		"user@evil.com",
		`evil.com\path`,
		"bad\u00a0host.com",
	}

	var nodeIDs []int64
	for i, badHost := range badHosts {
		n := mustNewNode(t, st, store.Node{
			Name:            fmt.Sprintf("BadHost-%d", i),
			PublicIP:        "203.0.113.50", // must NOT fall back and leak PublicIP when CustomEntryHost is malformed
			CustomEntryHost: badHost,
			SortOrder:       i + 1,
			Enabled:         true,
			SnellConfig: protocol.SnellConfig{
				Enabled: true, Version: protocol.SnellVersionV5, PublicPort: 8443,
				PSK: "psk", STLSPassword: "stls", STLSSNI: "gateway.icloud.com",
			},
			SSConfig: protocol.SSConfig{
				Enabled: true, TCPPort: 8443, UDPPort: 8443,
				Cipher: protocol.CipherAES128GCM, IPSK: ipsk, STLSSNI: "gateway.icloud.com",
			},
		})
		nodeIDs = append(nodeIDs, n.ID)
	}

	// Valid bracketed IPv6 node must still succeed.
	validNode := mustNewNode(t, st, store.Node{
		Name:            "ValidIPv6",
		CustomEntryHost: "[2001:db8::9]",
		SortOrder:       100,
		Enabled:         true,
		SnellConfig: protocol.SnellConfig{
			Enabled: true, Version: protocol.SnellVersionV5, PublicPort: 8443,
			PSK: "psk", STLSPassword: "stls", STLSSNI: "gateway.icloud.com",
		},
		SSConfig: protocol.SSConfig{
			Enabled: true, TCPPort: 8443, UDPPort: 8443,
			Cipher: protocol.CipherAES128GCM, IPSK: ipsk, STLSSNI: "gateway.icloud.com",
		},
	})
	nodeIDs = append(nodeIDs, validNode.ID)
	if err := st.SetUserNodes(ctx, user.ID, nodeIDs); err != nil {
		t.Fatal(err)
	}

	resAdmin, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{Mode: ModeProxy})
	if err != nil {
		t.Fatalf("RenderAdmin failed: %v", err)
	}
	if resAdmin.NodeCount != 1 || !strings.Contains(resAdmin.Body, "ValidIPv6 = snell, 2001:db8::9, 8443,") {
		t.Fatalf("expected only ValidIPv6 in admin output, got count=%d body:\n%s", resAdmin.NodeCount, resAdmin.Body)
	}

	for _, target := range []string{protocol.SubTargetMihomo, protocol.SubTargetSurge, protocol.SubTargetShadowrocket} {
		resUser, err := r.RenderUser(ctx, user.SubToken, "", UserRenderOptions{Target: target, Mode: ModeProxy})
		if err != nil {
			t.Fatalf("RenderUser(%s) failed: %v", target, err)
		}
		if resUser.NodeCount != 1 {
			t.Fatalf("RenderUser(%s) expected NodeCount=1, got %d:\n%s", target, resUser.NodeCount, resUser.Body)
		}
		if target == protocol.SubTargetShadowrocket {
			raw, err := base64.StdEncoding.DecodeString(resUser.Body)
			if err != nil {
				t.Fatalf("shadowrocket decode failed: %v", err)
			}
			u, err := url.Parse(strings.TrimSpace(string(raw)))
			if err != nil {
				t.Fatalf("shadowrocket url.Parse failed: %v (%s)", err, string(raw))
			}
			if u.Host != "[2001:db8::9]:8443" {
				t.Fatalf("unexpected shadowrocket host: %q", u.Host)
			}
		}
	}
}

func TestRegressionMihomoIndentAndTypedValidation(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	r := NewRenderer(st)

	user0 := mustNewUser(t, st, "mihomo_0", true, 0, 0, 0, nil)
	userN := mustNewUser(t, st, "mihomo_n", true, 0, 0, 0, nil)
	ipsk, err := auth.GenerateIPSKForCipher(protocol.CipherAES128GCM)
	if err != nil {
		t.Fatal(err)
	}
	n1 := mustNewNode(t, st, store.Node{
		Name: "Indent-Node-1", PublicIP: "203.0.113.10", SortOrder: 1, Enabled: true,
		SSConfig: protocol.SSConfig{
			Enabled: true, TCPPort: 8443, UDPPort: 8443,
			Cipher: protocol.CipherAES128GCM, IPSK: ipsk, STLSSNI: "gateway.icloud.com",
		},
	})
	n2 := mustNewNode(t, st, store.Node{
		Name: "Indent-Node-2", PublicIP: "203.0.113.11", SortOrder: 2, Enabled: true,
		SSConfig: protocol.SSConfig{
			Enabled: true, TCPPort: 8443, UDPPort: 8443,
			Cipher: protocol.CipherAES128GCM, IPSK: ipsk, STLSSNI: "swcdn.apple.com",
		},
	})
	if err := st.SetUserNodes(ctx, userN.ID, []int64{n1.ID, n2.ID}); err != nil {
		t.Fatal(err)
	}

	type parsedMihomoDoc struct {
		Proxies     []mihomoProxy `yaml:"proxies"`
		ProxyGroups []struct {
			Name    string   `yaml:"name"`
			Type    string   `yaml:"type"`
			Proxies []string `yaml:"proxies"`
		} `yaml:"proxy-groups"`
	}

	validTemplates := []struct {
		name           string
		content        string
		wantGroup0Zero []string
		wantGroup0Two  []string
	}{
		{
			name: "8-space proxies with col-0 placeholder and no sibling DIRECT",
			content: `mode: rule
proxies:
{{PROXIES}}
proxy-groups:
      - name: Auto
        type: url-test
        proxies:
{{PROXY_NAMES_YAML}}
      - name: Fallback
        type: fallback
        proxies:
{{PROXY_NAMES_YAML}}
`,
			wantGroup0Zero: []string{"DIRECT"},
			wantGroup0Two:  []string{"Indent-Node-1", "Indent-Node-2"},
		},
		{
			name: "4-space explicit placeholder indent with 6-space sibling DIRECT",
			content: `mode: rule
proxies:
{{PROXIES}}
proxy-groups:
  - name: Proxy
    type: select
    proxies:
    {{PROXY_NAMES_YAML}}
      - DIRECT
`,
			wantGroup0Zero: []string{"DIRECT"},
			wantGroup0Two:  []string{"Indent-Node-1", "Indent-Node-2", "DIRECT"},
		},
		{
			name: "backward sibling only before outer group",
			content: `mode: rule
proxies:
{{PROXIES}}
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - Auto
{{PROXY_NAMES_YAML}}
  - name: Auto
    type: url-test
    proxies:
{{PROXY_NAMES_YAML}}
`,
			wantGroup0Zero: []string{"Auto", "DIRECT"},
			wantGroup0Two:  []string{"Auto", "Indent-Node-1", "Indent-Node-2"},
		},
	}

	for _, tc := range validTemplates {
		t.Run(tc.name, func(t *testing.T) {
			tpl := &store.SubTemplate{
				Name:       tc.name,
				ClientType: protocol.ClientTypeMihomoUser,
				Content:    tc.content,
			}
			if err := st.CreateSubTemplate(ctx, tpl); err != nil {
				t.Fatal(err)
			}

			// 0 nodes
			res0, err := r.RenderUser(ctx, user0.SubToken, "", UserRenderOptions{
				Target:     protocol.SubTargetMihomo,
				Mode:       ModeFull,
				TemplateID: tpl.ID,
			})
			if err != nil {
				t.Fatalf("0-node RenderUser failed: %v", err)
			}
			var doc0 parsedMihomoDoc
			if err := yaml.Unmarshal([]byte(res0.Body), &doc0); err != nil {
				t.Fatalf("0-node typed yaml.Unmarshal failed: %v\n%s", err, res0.Body)
			}
			if len(doc0.ProxyGroups) == 0 || strings.Join(doc0.ProxyGroups[0].Proxies, ",") != strings.Join(tc.wantGroup0Zero, ",") {
				t.Fatalf("0-node group[0] proxies mismatch: got %+v, want %v\n%s", doc0.ProxyGroups, tc.wantGroup0Zero, res0.Body)
			}

			// N nodes
			resN, err := r.RenderUser(ctx, userN.SubToken, "", UserRenderOptions{
				Target:     protocol.SubTargetMihomo,
				Mode:       ModeFull,
				TemplateID: tpl.ID,
			})
			if err != nil {
				t.Fatalf("N-node RenderUser failed: %v", err)
			}
			var docN parsedMihomoDoc
			if err := yaml.Unmarshal([]byte(resN.Body), &docN); err != nil {
				t.Fatalf("N-node typed yaml.Unmarshal failed: %v\n%s", err, resN.Body)
			}
			if len(docN.Proxies) != 2 {
				t.Fatalf("expected 2 proxies, got %d", len(docN.Proxies))
			}
			if len(docN.ProxyGroups) == 0 || strings.Join(docN.ProxyGroups[0].Proxies, ",") != strings.Join(tc.wantGroup0Two, ",") {
				t.Fatalf("N-node group[0] proxies mismatch: got %+v, want %v\n%s", docN.ProxyGroups, tc.wantGroup0Two, resN.Body)
			}
		})
	}

	// Corrupted proxy-groups structure (parses as `any` YAML, fails typed Mihomo struct) must return ErrInvalidArgument.
	corruptedTemplates := []string{
		"proxies:\n{{PROXIES}}\nproxy-groups:\n  - not-a-group-mapping\n",
		"proxies:\n{{PROXIES}}\nproxy-groups: \"not-a-list\"\n",
		"proxies:\n{{PROXIES}}\nproxy-groups:\n  - name: Proxy\n    type: select\n    proxies: \"not-a-list\"\n",
	}
	for i, content := range corruptedTemplates {
		tpl := &store.SubTemplate{
			Name:       fmt.Sprintf("Corrupted-%d", i),
			ClientType: protocol.ClientTypeMihomoUser,
			Content:    content,
		}
		if err := st.CreateSubTemplate(ctx, tpl); err != nil {
			t.Fatal(err)
		}
		if _, err := r.RenderUser(ctx, userN.SubToken, "", UserRenderOptions{
			Target:     protocol.SubTargetMihomo,
			Mode:       ModeFull,
			TemplateID: tpl.ID,
		}); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("corrupted template %d expected ErrInvalidArgument, got %v", i, err)
		}
	}
}

type stubSubStore struct {
	adminToken string
	nodes      []store.Node
}

func (s *stubSubStore) GetSetting(_ context.Context, key string) (string, error) {
	if key == "admin_sub_token" {
		return s.adminToken, nil
	}
	return "", store.ErrNotFound
}

func (s *stubSubStore) ListNodes(_ context.Context) ([]store.Node, error) {
	return s.nodes, nil
}

func (s *stubSubStore) GetUserBySubToken(_ context.Context, _ string) (*store.User, error) {
	return nil, store.ErrNotFound
}

func (s *stubSubStore) ListAuthorizedNodesForUser(_ context.Context, _ int64) ([]store.Node, error) {
	return nil, nil
}

func (s *stubSubStore) GetSubTemplateByID(_ context.Context, _ int64) (*store.SubTemplate, error) {
	return nil, store.ErrNotFound
}

func (s *stubSubStore) GetDefaultSubTemplate(_ context.Context, _ string) (*store.SubTemplate, error) {
	return nil, store.ErrNotFound
}

func (s *stubSubStore) ListSubTemplates(_ context.Context, _ string) ([]store.SubTemplate, error) {
	return nil, nil
}

func TestRegressionDefensivePolish(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	r := NewRenderer(st)

	adminToken, err := st.GetSetting(ctx, "admin_sub_token")
	if err != nil {
		t.Fatal(err)
	}
	user := mustNewUser(t, st, "polish_u", true, 0, 0, 0, nil)

	// 1. Negative TemplateID must return ErrInvalidArgument across admin & user tracks.
	if _, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{Mode: ModeFull, TemplateID: -1}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("RenderAdmin(TemplateID=-1) expected ErrInvalidArgument, got %v", err)
	}
	for _, target := range []string{protocol.SubTargetMihomo, protocol.SubTargetSurge, protocol.SubTargetShadowrocket} {
		if _, err := r.RenderUser(ctx, user.SubToken, "", UserRenderOptions{Target: target, Mode: ModeFull, TemplateID: -1}); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("RenderUser(%s, TemplateID=-1) expected ErrInvalidArgument, got %v", target, err)
		}
	}

	// 2. Leading '[' stripped in sanitizeSurgeName so INI section headers cannot be forged.
	mustNewNode(t, st, store.Node{
		Name: "[Rule]", PublicIP: "203.0.113.71", SortOrder: 1, Enabled: true,
		SnellConfig: protocol.SnellConfig{
			Enabled: true, Version: protocol.SnellVersionV5, PublicPort: 8443,
			PSK: "psk", STLSPassword: "stls", STLSSNI: "gateway.icloud.com",
		},
	})
	mustNewNode(t, st, store.Node{
		Name: "[[", PublicIP: "203.0.113.72", SortOrder: 2, Enabled: true,
		SnellConfig: protocol.SnellConfig{
			Enabled: true, Version: protocol.SnellVersionV5, PublicPort: 8443,
			PSK: "psk", STLSPassword: "stls", STLSSNI: "gateway.icloud.com",
		},
	})
	mustNewNode(t, st, store.Node{
		Name: "HK [VIP]", PublicIP: "203.0.113.73", SortOrder: 3, Enabled: true,
		SnellConfig: protocol.SnellConfig{
			Enabled: true, Version: protocol.SnellVersionV5, PublicPort: 8443,
			PSK: "psk", STLSPassword: "stls", STLSSNI: "gateway.icloud.com",
		},
	})
	resSurge, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{Mode: ModeProxy})
	if err != nil {
		t.Fatalf("RenderAdmin failed: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(resSurge.Body, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 surge lines, got %d:\n%s", len(lines), resSurge.Body)
	}
	if !strings.HasPrefix(lines[0], "Rule] = snell,") {
		t.Fatalf("expected leading '[' stripped from [Rule], got %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "Node-") {
		t.Fatalf("expected '[[' fallback to Node-<id>, got %q", lines[1])
	}
	if !strings.HasPrefix(lines[2], "HK [VIP] = snell,") {
		t.Fatalf("expected mid-name '[VIP]' preserved, got %q", lines[2])
	}

	// 3. Whitespace-only admin_sub_token in DB must reject authentication.
	if err := st.SetSetting(ctx, "admin_sub_token", "   \t  "); err != nil {
		t.Fatal(err)
	}
	if _, err := r.RenderAdmin(ctx, "   \t  ", AdminRenderOptions{}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for whitespace-only admin_sub_token, got %v", err)
	}

	// 4. IsTrafficPaused=true with empty ThresholdAction must pause Snell (fail closed).
	stub := &stubSubStore{
		adminToken: "valid-admin-token",
		nodes: []store.Node{
			{
				ID: 1, Name: "PausedEmptyAction", PublicIP: "203.0.113.80", Enabled: true,
				IsTrafficPaused: true, ThresholdAction: "",
				SnellConfig: protocol.SnellConfig{
					Enabled: true, Version: protocol.SnellVersionV5, PublicPort: 8443,
					PSK: "psk", STLSPassword: "stls", STLSSNI: "gateway.icloud.com",
				},
			},
			{
				ID: 2, Name: "PausedStopSSOnly", PublicIP: "203.0.113.81", Enabled: true,
				IsTrafficPaused: true, ThresholdAction: protocol.ThresholdActionStopSSOnly,
				SnellConfig: protocol.SnellConfig{
					Enabled: true, Version: protocol.SnellVersionV5, PublicPort: 8443,
					PSK: "psk", STLSPassword: "stls", STLSSNI: "gateway.icloud.com",
				},
			},
		},
	}
	stubRenderer := &Renderer{store: stub, now: time.Now}
	resStub, err := stubRenderer.RenderAdmin(ctx, "valid-admin-token", AdminRenderOptions{Mode: ModeProxy})
	if err != nil {
		t.Fatalf("stub RenderAdmin failed: %v", err)
	}
	if resStub.NodeCount != 1 || !strings.HasPrefix(resStub.Body, "PausedStopSSOnly = snell,") {
		t.Fatalf("expected empty ThresholdAction paused node excluded and stop_ss_only retained, got count=%d body:\n%s", resStub.NodeCount, resStub.Body)
	}
}

type tier5StubSubStore struct {
	users    map[string]*store.User
	nodes    []store.Node
	assigned map[int64][]int64
}

func (s *tier5StubSubStore) GetSetting(_ context.Context, _ string) (string, error) {
	return "", store.ErrNotFound
}

func (s *tier5StubSubStore) ListNodes(_ context.Context) ([]store.Node, error) {
	return s.nodes, nil
}

func (s *tier5StubSubStore) GetUserBySubToken(_ context.Context, tok string) (*store.User, error) {
	u, ok := s.users[tok]
	if !ok {
		return nil, store.ErrNotFound
	}
	return u, nil
}

func (s *tier5StubSubStore) ListAuthorizedNodesForUser(_ context.Context, uid int64) ([]store.Node, error) {
	ids := s.assigned[uid]
	idSet := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		idSet[id] = struct{}{}
	}
	var out []store.Node
	for _, n := range s.nodes {
		if _, ok := idSet[n.ID]; ok {
			out = append(out, n)
		}
	}
	return out, nil
}

func (s *tier5StubSubStore) GetSubTemplateByID(_ context.Context, _ int64) (*store.SubTemplate, error) {
	return nil, store.ErrNotFound
}

func (s *tier5StubSubStore) GetDefaultSubTemplate(_ context.Context, _ string) (*store.SubTemplate, error) {
	return nil, store.ErrNotFound
}

func (s *tier5StubSubStore) ListSubTemplates(_ context.Context, _ string) ([]store.SubTemplate, error) {
	return nil, nil
}

func TestTier5_BugB2_UserQuotaOverflowUint64(t *testing.T) {
	ctx := context.Background()
	u := store.User{
		ID: 10, Username: "overflow-user", Enabled: true, SubToken: "tok-overflow",
		SSUPSK16:     "Q0FOQVJZX1NTX0lQU0tfMQ==",
		SSUPSK32:     "Q0FOQVJZX0YxNV9TU19JUFNLXzMyQllURVNfMDAwMDE=",
		STLSPassword: "pw", TrafficQuotaBytes: 9_223_372_036_854_775_807,
		UsedUpBytes:   5_000_000_000_000_000_000,
		UsedDownBytes: 5_000_000_000_000_000_000,
	}
	stub := &tier5StubSubStore{
		users: map[string]*store.User{u.SubToken: &u},
		nodes: []store.Node{
			{
				ID: 1, Name: "N1", PublicIP: "203.0.113.10", Enabled: true,
				SnellConfig: protocol.SnellConfig{Enabled: true, Version: protocol.SnellVersionV5, PublicPort: 2443, PSK: "psk"},
			},
		},
		assigned: map[int64][]int64{u.ID: {1}},
	}
	r := &Renderer{store: stub, now: time.Now}
	if _, err := r.RenderUser(ctx, u.SubToken, "", UserRenderOptions{Target: protocol.SubTargetSurge, Mode: ModeProxy}); !errors.Is(err, ErrUserQuotaExhausted) {
		t.Fatalf("expected ErrUserQuotaExhausted on 5e18+5e18 >= MaxInt64, got %v", err)
	}
}

func TestTier5_BugB5_FilterUserNodesDefenseInDepthSS2022(t *testing.T) {
	ctx := context.Background()
	u := store.User{
		ID: 11, Username: "ss-u", Enabled: true, SubToken: "tok-ss",
		SSUPSK16:     "Q0FOQVJZX1NTX0lQU0tfMQ==",
		SSUPSK32:     "not-valid-base64",
		STLSPassword: "stls-pw",
	}
	stub := &tier5StubSubStore{
		users: map[string]*store.User{u.SubToken: &u},
		nodes: []store.Node{
			{
				ID: 1, Name: "Bad-IPSK-Node", PublicIP: "203.0.113.21", Enabled: true, SortOrder: 1,
				SSConfig: protocol.SSConfig{
					Enabled: true, TCPPort: 443, Cipher: "2022-blake3-aes-128-gcm", IPSK: "bad-ipsk", STLSSNI: "gateway.icloud.com",
				},
			},
			{
				ID: 2, Name: "Bad-UserPSK32-Node", PublicIP: "203.0.113.22", Enabled: true, SortOrder: 2,
				SSConfig: protocol.SSConfig{
					Enabled: true, TCPPort: 443, Cipher: "2022-blake3-aes-256-gcm", IPSK: "Q0FOQVJZX0YxNV9TU19JUFNLXzMyQllURVNfMDAwMDE=", STLSSNI: "gateway.icloud.com",
				},
			},
			{
				ID: 3, Name: "Good-SS128-Node", PublicIP: "203.0.113.23", Enabled: true, SortOrder: 3,
				SSConfig: protocol.SSConfig{
					Enabled: true, TCPPort: 443, Cipher: "2022-blake3-aes-128-gcm", IPSK: "Q0FOQVJZX1NTX0lQU0tfMQ==", STLSSNI: "gateway.icloud.com",
				},
			},
		},
		assigned: map[int64][]int64{u.ID: {1, 2, 3}},
	}
	r := &Renderer{store: stub, now: time.Now}
	res, err := r.RenderUser(ctx, u.SubToken, "", UserRenderOptions{Target: protocol.SubTargetSurge, Mode: ModeProxy})
	if err != nil {
		t.Fatalf("RenderUser: %v", err)
	}
	if res.NodeCount != 1 || !strings.Contains(res.Body, "Good-SS128-Node") {
		t.Fatalf("expected only Good-SS128-Node emitted, got count=%d body=%s", res.NodeCount, res.Body)
	}
	if strings.Contains(res.Body, "Bad-IPSK-Node") || strings.Contains(res.Body, "Bad-UserPSK32-Node") {
		t.Fatalf("invalid SS2022 node leaked into output:\n%s", res.Body)
	}
}

func TestTier5_BugB6_MihomoFlowSequenceProxyNamesEscaping(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	user := mustNewUser(t, st, "flow-user", true, 0, 0, 0, nil)

	trickyNames := []string{
		`HK [VIP, 1]: "fast"`,
		`JP ] #comment 'single'`,
		`- dash: {braces}`,
	}
	var ids []int64
	for i, nm := range trickyNames {
		n := mustNewNode(t, st, store.Node{
			Name: nm, PublicIP: fmt.Sprintf("203.0.113.%d", 40+i), SortOrder: i + 1, Enabled: true,
			SSConfig: protocol.SSConfig{
				Enabled: true, TCPPort: 25443 + i, UDPPort: 25443 + i,
				Cipher: protocol.CipherAES128GCM, IPSK: "Q0FOQVJZX1NTX0lQU0tfMQ==",
				STLSSNI: "gateway.icloud.com",
			},
		})
		ids = append(ids, n.ID)
	}
	if err := st.SetUserNodes(ctx, user.ID, ids); err != nil {
		t.Fatal(err)
	}

	tpl := &store.SubTemplate{
		Name:       "FlowSeqTpl",
		ClientType: protocol.ClientTypeMihomoUser,
		Content: `mode: rule
proxies:
{{PROXIES}}
proxy-groups:
  - name: FlowSelect
    type: select
    proxies: [{{PROXY_NAMES}}]
  - name: YAMLSeq
    type: url-test
    proxies:
{{PROXY_NAMES_YAML}}
`,
	}
	if err := st.CreateSubTemplate(ctx, tpl); err != nil {
		t.Fatal(err)
	}

	r := NewRenderer(st)
	res, err := r.RenderUser(ctx, user.SubToken, "", UserRenderOptions{
		Target:     protocol.SubTargetMihomo,
		Mode:       ModeFull,
		TemplateID: tpl.ID,
	})
	if err != nil {
		t.Fatalf("RenderUser mihomo flow sequence with special chars failed: %v", err)
	}

	var doc struct {
		Proxies     []map[string]any `yaml:"proxies"`
		ProxyGroups []struct {
			Name    string   `yaml:"name"`
			Proxies []string `yaml:"proxies"`
		} `yaml:"proxy-groups"`
	}
	if err := yaml.Unmarshal([]byte(res.Body), &doc); err != nil {
		t.Fatalf("yaml.Unmarshal failed: %v\n%s", err, res.Body)
	}
	if len(doc.ProxyGroups) != 2 {
		t.Fatalf("expected 2 proxy groups, got %d", len(doc.ProxyGroups))
	}
	for gIdx, g := range doc.ProxyGroups {
		if len(g.Proxies) != len(trickyNames) {
			t.Fatalf("group[%d] proxy count mismatch: got %v want %v", gIdx, g.Proxies, trickyNames)
		}
		for i, want := range trickyNames {
			if g.Proxies[i] != want {
				t.Fatalf("group[%d] proxy[%d] mismatch: got %q want %q\nbody:\n%s", gIdx, i, g.Proxies[i], want, res.Body)
			}
		}
	}
}

func TestTier5_SubHelpersAndCRLFInjectionMatrix(t *testing.T) {
	// normalizeSNIHost cases
	sniCases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"swscan.apple.com", "swscan.apple.com", true},
		{"swscan.apple.com:443", "swscan.apple.com", true},
		{"[2001:db8::1]:8443", "2001:db8::1", true},
		{"[2001:db8::1]", "2001:db8::1", true},
		{"2001:db8::1", "", false},
		{"", "", false},
		{"bad\r\nhost", "", false},
		{"bad host", "", false},
		{"host,inject", "", false},
		{"host=inject", "", false},
		{"host#frag", "", false},
		{"host:99999", "", false},
		{"host:0", "", false},
		{"bad:ipv6:addr", "", false},
	}
	for _, tc := range sniCases {
		got, ok := normalizeSNIHost(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("normalizeSNIHost(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}

	// sanitizePlainName cases
	if got := sanitizePlainName("  Node\r\nName\x00  ", 42); got != "NodeName" {
		t.Fatalf("sanitizePlainName control strip failed: %q", got)
	}
	if got := sanitizePlainName("\r\n\t\x7f", 42); got != "Node-42" {
		t.Fatalf("sanitizePlainName empty fallback failed: %q", got)
	}

	// resolveProxyNamesYAMLIndent cases
	if ind := resolveProxyNamesYAMLIndent([]string{"  - name: G", "    proxies:", "{{PROXY_NAMES_YAML}}"}, 2, ""); ind != "      " {
		t.Fatalf("expected 6 spaces indent under 4-space proxies:, got %q", ind)
	}
	if ind := resolveProxyNamesYAMLIndent([]string{"proxies:", "      - DIRECT", "{{PROXY_NAMES_YAML}}"}, 2, ""); ind != "      " {
		t.Fatalf("expected sibling list indent 6 spaces, got %q", ind)
	}
	if ind := resolveProxyNamesYAMLIndent([]string{"  {{PROXY_NAMES_YAML}}"}, 0, "  "); ind != "  " {
		t.Fatalf("expected fallback lineIndent 2 spaces, got %q", ind)
	}

	// validateBaseURL rejects CRLF/query/userinfo/space/non-http schemes
	for _, badURL := range []string{
		"https://sub.example.com\r\nX-Injected: 1",
		"https://user:pass@sub.example.com",
		"https://sub.example.com?foo=bar",
		"https://sub.example.com#frag",
		"ftp://sub.example.com",
		"https://sub.example.com/with space",
	} {
		if _, err := validateBaseURL(badURL); !errors.Is(err, ErrInvalidBaseURL) {
			t.Fatalf("validateBaseURL(%q): expected ErrInvalidBaseURL, got %v", badURL, err)
		}
	}

	// CRLF/control chars in node name + SNI cannot break Surge line integrity.
	ctx := context.Background()
	u := store.User{
		ID: 19, Username: "crlf-u", Enabled: true, SubToken: "tok-crlf",
		SSUPSK16:     "Q0FOQVJZX1NTX0lQU0tfMQ==",
		STLSPassword: "stls-clean-pw",
	}
	stub := &tier5StubSubStore{
		users: map[string]*store.User{u.SubToken: &u},
		nodes: []store.Node{
			{
				ID: 1, Name: "Evil\r\n[Rule]\r\nDIRECT", PublicIP: "203.0.113.99", Enabled: true, SortOrder: 1,
				SSConfig: protocol.SSConfig{
					Enabled: true, TCPPort: 25443, UDPPort: 25443,
					Cipher: protocol.CipherAES128GCM, IPSK: "Q0FOQVJZX1NTX0lQU0tfMQ==",
					STLSSNI: "gateway.icloud.com",
				},
			},
			{
				ID: 2, Name: "BadSNI", PublicIP: "203.0.113.100", Enabled: true, SortOrder: 2,
				SSConfig: protocol.SSConfig{
					Enabled: true, TCPPort: 25444, UDPPort: 25444,
					Cipher: protocol.CipherAES128GCM, IPSK: "Q0FOQVJZX1NTX0lQU0tfMQ==",
					STLSSNI: "evil\r\n.example.com",
				},
			},
		},
		assigned: map[int64][]int64{u.ID: {1, 2}},
	}
	r := &Renderer{store: stub, now: time.Now}
	res, err := r.RenderUser(ctx, u.SubToken, "", UserRenderOptions{Target: protocol.SubTargetSurge, Mode: ModeProxy})
	if err != nil {
		t.Fatalf("RenderUser CRLF matrix: %v", err)
	}
	if strings.Contains(res.Body, "evil") || strings.Contains(res.Body, "\r") {
		t.Fatalf("CRLF/control injection leaked into rendered Surge body:\n%q", res.Body)
	}
	// Line count must be exactly 1 single proxy line (+ trailing newline); CR/LF in node name stripped.
	lines := strings.Split(strings.TrimSuffix(res.Body, "\n"), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "Evil[Rule]DIRECT = ") {
		t.Fatalf("expected 1 single proxy line with stripped CRLF, got %d: %q", len(lines), res.Body)
	}
}

func TestSurgeTemplatesNoBuiltinPolicyOverrides(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	r := NewRenderer(st)

	adminToken, err := st.GetSetting(ctx, "admin_sub_token")
	if err != nil {
		t.Fatal(err)
	}
	n := mustNewNode(t, st, store.Node{
		Name:     "SG-Surge-Test",
		PublicIP: "203.0.113.10",
		Enabled:  true,
		SnellConfig: protocol.SnellConfig{
			Enabled:      true,
			Version:      protocol.SnellVersionV5,
			PublicPort:   8443,
			PSK:          "snellpsk1",
			STLSPassword: "stlspwd1",
			STLSSNI:      "gateway.icloud.com",
		},
		SSConfig: protocol.SSConfig{
			Enabled: true,
			TCPPort: 28443,
			UDPPort: 28443,
			Cipher:  protocol.CipherAES128GCM,
			IPSK:    "Q0FOQVJZX1NTX0lQU0tfMQ==",
			STLSSNI: "gateway.icloud.com",
		},
	})
	u := mustNewUser(t, st, "surge_check", true, 0, 0, 0, nil)
	if _, _, err := st.ReplaceUserNodes(ctx, u.ID, []int64{n.ID}); err != nil {
		t.Fatal(err)
	}

	adminRes, err := r.RenderAdmin(ctx, adminToken, AdminRenderOptions{Mode: ModeFull, BaseURL: "https://panel.example.com"})
	if err != nil {
		t.Fatalf("RenderAdmin failed: %v", err)
	}
	for _, forbidden := range []string{"DIRECT = direct", "REJECT = reject", "raw.githubusercontent.com"} {
		if strings.Contains(adminRes.Body, forbidden) {
			t.Fatalf("admin Surge full config must not contain %q:\n%s", forbidden, adminRes.Body)
		}
	}
	if !strings.Contains(adminRes.Body, "https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/") {
		t.Fatalf("expected CDN mirror URL in admin Surge full config:\n%s", adminRes.Body)
	}

	userRes, err := r.RenderUser(ctx, u.SubToken, "", UserRenderOptions{
		Target:  protocol.SubTargetSurge,
		Mode:    ModeFull,
		BaseURL: "https://panel.example.com",
	})
	if err != nil {
		t.Fatalf("RenderUser Surge failed: %v", err)
	}
	for _, forbidden := range []string{"DIRECT = direct", "REJECT = reject", "raw.githubusercontent.com"} {
		if strings.Contains(userRes.Body, forbidden) {
			t.Fatalf("user Surge full config must not contain %q:\n%s", forbidden, userRes.Body)
		}
	}
	if !strings.Contains(userRes.Body, "https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/") {
		t.Fatalf("expected CDN mirror URL in user Surge full config:\n%s", userRes.Body)
	}

	mihomoRes, err := r.RenderUser(ctx, u.SubToken, "", UserRenderOptions{
		Target:  protocol.SubTargetMihomo,
		Mode:    ModeFull,
		BaseURL: "https://panel.example.com",
	})
	if err != nil {
		t.Fatalf("RenderUser Mihomo failed: %v", err)
	}
	if strings.Contains(mihomoRes.Body, "raw.githubusercontent.com") ||
		!strings.Contains(mihomoRes.Body, "https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/") {
		t.Fatalf("expected CDN mirror URL and no raw.githubusercontent.com in mihomo full config:\n%s", mihomoRes.Body)
	}
}
