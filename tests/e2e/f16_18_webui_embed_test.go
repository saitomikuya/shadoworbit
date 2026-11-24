//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	f16_scriptSrcRe        = regexp.MustCompile(`(?is)<script[^>]*\ssrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'=<>` + "`" + `]+))`)
	f16_linkHrefRe         = regexp.MustCompile(`(?is)<link[^>]*\shref\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'=<>` + "`" + `]+))`)
	f16_jsChunkRefRe       = regexp.MustCompile(`["'` + "`" + `](/?assets/[A-Za-z0-9_.\-/]+\.js)["'` + "`" + `]`)
	f16_lineCommentRe      = regexp.MustCompile(`(?m)//.*$`)
	f16_blockCommentRe     = regexp.MustCompile(`(?s)/\*.*?\*/`)
	f16_viteRelativeBaseRe = regexp.MustCompile(`\bbase\s*:\s*['"]\.\/?['"]`)
)

func f16_boolPtr(v bool) *bool { return &v }

func f16_firstCapture(m []string) string {
	for i := 1; i < len(m); i++ {
		if m[i] != "" {
			return strings.TrimSpace(m[i])
		}
	}
	return ""
}

func f16_extractAssetURLs(html string) (jsAssets []string, cssAssets []string, allAssets []string) {
	seen := map[string]bool{}
	for _, m := range f16_scriptSrcRe.FindAllStringSubmatch(html, -1) {
		ref := f16_firstCapture(m)
		if ref == "" || strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") || strings.HasPrefix(ref, "data:") {
			continue
		}
		if !seen[ref] {
			seen[ref] = true
			allAssets = append(allAssets, ref)
			jsAssets = append(jsAssets, ref)
		}
	}
	for _, m := range f16_linkHrefRe.FindAllStringSubmatch(html, -1) {
		ref := f16_firstCapture(m)
		if ref == "" || strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") || strings.HasPrefix(ref, "data:") {
			continue
		}
		if !seen[ref] {
			seen[ref] = true
			allAssets = append(allAssets, ref)
			if strings.Contains(strings.ToLower(ref), ".css") {
				cssAssets = append(cssAssets, ref)
			}
		}
	}
	return jsAssets, cssAssets, allAssets
}

func f16_resolveAssetPath(pagePath, ref string) string {
	if strings.HasPrefix(ref, "/") {
		return ref
	}
	base, _ := url.Parse("http://panel.local" + pagePath)
	rel, err := url.Parse(ref)
	if err != nil {
		return "/" + strings.TrimLeft(ref, "./")
	}
	return base.ResolveReference(rel).Path
}

func f16_fetchHTML(t *testing.T, client *PanelClient, path string) (http.Header, string) {
	t.Helper()
	st, hdr, raw, err := client.DoRaw(context.Background(), http.MethodGet, path, nil, nil)
	if err != nil {
		t.Fatalf("GET %s failed: %v", path, err)
	}
	if st != http.StatusOK {
		t.Fatalf("GET %s expected 200 OK, got %d (body=%s)", path, st, string(raw))
	}
	ct := strings.ToLower(hdr.Get("Content-Type"))
	if !strings.Contains(ct, "text/html") {
		t.Fatalf("GET %s expected Content-Type text/html, got %q", path, hdr.Get("Content-Type"))
	}
	return hdr, string(raw)
}

func f16_collectBundleText(t *testing.T, client *PanelClient, pagePath, html string) string {
	t.Helper()
	var sb strings.Builder
	sb.WriteString(html)
	_, _, allAssets := f16_extractAssetURLs(html)
	fetched := map[string]bool{}
	var jsBodies []string

	for _, ref := range allAssets {
		assetPath := f16_resolveAssetPath(pagePath, ref)
		if !strings.HasSuffix(strings.ToLower(assetPath), ".js") || fetched[assetPath] {
			continue
		}
		fetched[assetPath] = true
		st, _, raw, err := client.DoRaw(context.Background(), http.MethodGet, assetPath, nil, nil)
		if err == nil && st == http.StatusOK {
			s := string(raw)
			jsBodies = append(jsBodies, s)
			sb.WriteString("\n")
			sb.WriteString(s)
		}
	}
	// Follow 1 hop of Vite lazy-loaded /assets/*.js chunks if code-split.
	for _, body := range jsBodies {
		for _, m := range f16_jsChunkRefRe.FindAllStringSubmatch(body, -1) {
			chunkPath := f16_resolveAssetPath("/", m[1])
			if fetched[chunkPath] {
				continue
			}
			fetched[chunkPath] = true
			st, _, raw, err := client.DoRaw(context.Background(), http.MethodGet, chunkPath, nil, nil)
			if err == nil && st == http.StatusOK {
				sb.WriteString("\n")
				sb.Write(raw)
			}
		}
	}
	return sb.String()
}

// =====================================================================
// Feature 16: Public Status Page (/) UI (5 Tier 1 + 5 Tier 2)
// =====================================================================

func TestF16_Tier1_PublicRootPageServedUnauthenticated(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()

	_, html := f16_fetchHTML(t, client, "/")
	lower := strings.ToLower(html)
	if !strings.Contains(lower, "<html") && !strings.Contains(lower, "<!doctype html") {
		t.Fatalf("GET / did not return valid HTML document: %s", html)
	}
	if !strings.Contains(lower, "<script") {
		t.Fatalf("GET / HTML missing <script> bundle reference: %s", html)
	}
}

func TestF16_Tier1_PublicPageReferencedAssetsLoad200(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()

	_, html := f16_fetchHTML(t, client, "/")
	jsAssets, _, allAssets := f16_extractAssetURLs(html)
	if len(jsAssets) == 0 {
		t.Fatalf("expected at least 1 JS asset referenced from /, html=%s", html)
	}

	for _, ref := range allAssets {
		assetPath := f16_resolveAssetPath("/", ref)
		st, hdr, raw, err := client.DoRaw(context.Background(), http.MethodGet, assetPath, nil, nil)
		if err != nil {
			t.Fatalf("GET asset %s failed: %v", assetPath, err)
		}
		if st != http.StatusOK || len(raw) == 0 {
			t.Fatalf("GET asset %s expected 200 non-empty, got st=%d len=%d", assetPath, st, len(raw))
		}
		ct := strings.ToLower(hdr.Get("Content-Type"))
		if strings.HasSuffix(assetPath, ".js") && !strings.Contains(ct, "javascript") {
			t.Fatalf("JS asset %s expected javascript Content-Type, got %q", assetPath, hdr.Get("Content-Type"))
		}
		if strings.HasSuffix(assetPath, ".css") && !strings.Contains(ct, "text/css") {
			t.Fatalf("CSS asset %s expected text/css Content-Type, got %q", assetPath, hdr.Get("Content-Type"))
		}
	}

	bundle := f16_collectBundleText(t, client, "/", html)
	hasPublicAPI := strings.Contains(bundle, "/api/v1/public/status") ||
		strings.Contains(bundle, "/api/v1/public/ws") ||
		(strings.Contains(bundle, "/api/v1") && (strings.Contains(bundle, "/public/status") || strings.Contains(bundle, "/public/ws")))
	if !hasPublicAPI {
		t.Fatalf("public UI bundle appears to be a hollow stub: missing /api/v1/public/status or /api/v1/public/ws reference")
	}
}

func TestF16_Tier1_PublicPageThemeAndResponsiveMarkers(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()

	_, html := f16_fetchHTML(t, client, "/")
	if !strings.Contains(strings.ToLower(html), `name="viewport"`) && !strings.Contains(strings.ToLower(html), `name='viewport'`) {
		t.Fatalf("GET / HTML missing responsive viewport meta tag: %s", html)
	}

	_, _, allAssets := f16_extractAssetURLs(html)
	var bundleText strings.Builder
	bundleText.WriteString(html)
	for _, ref := range allAssets {
		assetPath := f16_resolveAssetPath("/", ref)
		if strings.HasSuffix(assetPath, ".js") || strings.HasSuffix(assetPath, ".css") {
			st, _, raw, err := client.DoRaw(context.Background(), http.MethodGet, assetPath, nil, nil)
			if err == nil && st == http.StatusOK {
				bundleText.WriteString("\n")
				bundleText.Write(raw)
			}
		}
	}
	combined := strings.ToLower(bundleText.String())
	if !strings.Contains(combined, "dark") {
		t.Fatalf("expected dark/light theme support markers in public UI bundle")
	}
	if !strings.Contains(combined, "@media") && !strings.Contains(combined, "grid") && !strings.Contains(combined, "flex") {
		t.Fatalf("expected responsive CSS layout markers in public UI bundle")
	}
}

func TestF16_Tier1_PublicPageBackedByLiveRedactedStatusAndWS(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	st, raw, err := client.UpdateSettings(jwt, map[string]any{
		"site_title":   "F16 Live Status UI",
		"announcement": "Zero downtime tonight",
	})
	if err != nil || st >= 300 {
		t.Fatalf("UpdateSettings failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	stN, node, rawN, err := client.CreateNode(jwt, CreateNodeReq{
		Name:              "F16-Edge-JP",
		RegionTag:         "JP",
		Enabled:           f16_boolPtr(true),
		TrafficLimitBytes: 100 << 20,
	})
	if err != nil || stN >= 300 || node.ID <= 0 {
		t.Fatalf("CreateNode failed: st=%d err=%v body=%s", stN, err, string(rawN))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	agentWS, wsSt, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatalf("DialAgentWS failed (http=%d): %v", wsSt, err)
	}
	defer agentWS.CloseNow()
	if err := SendWSEnvelope(ctx, agentWS, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"}); err != nil {
		t.Fatalf("send agent.hello: %v", err)
	}
	if _, _, err := ReadWSEnvelope(ctx, agentWS, 3*time.Second); err != nil {
		t.Fatalf("read initial server.config_sync: %v", err)
	}
	if err := SendWSEnvelope(ctx, agentWS, "agent.metrics", "m1", AgentMetricsPayload{
		TS: time.Now().Unix(), CPUPercent: 18.2, MemUsedBytes: 256 << 20, MemTotalBytes: 1024 << 20,
		UptimeSeconds: 3600, RxBPS: 50000, TxBPS: 75000,
		Health: AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatalf("send agent.metrics: %v", err)
	}

	_, _ = f16_fetchHTML(t, client, "/")

	deadline := time.Now().Add(5 * time.Second)
	restOK := false
	for time.Now().Before(deadline) {
		stPub, snap, _, err := client.GetPublicStatus()
		if err == nil && stPub == http.StatusOK && len(snap.Nodes) == 1 && snap.Nodes[0].Status == "online" {
			if snap.SiteTitle != "F16 Live Status UI" || snap.Announcement != "Zero downtime tonight" {
				t.Fatalf("unexpected public status settings: %+v", snap)
			}
			n := snap.Nodes[0]
			if !n.CoreAHealthy || !n.CoreBHealthy || n.RxBPS != 50000 || n.TxBPS != 75000 {
				t.Fatalf("unexpected public node metrics: %+v", n)
			}
			restOK = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !restOK {
		t.Fatalf("public status did not reflect live node metrics")
	}

	// Verify /api/v1/public/ws with a single outer 5s context (never per-iteration timeout + continue)
	pubWS, pubSt, err := client.DialPublicWS(ctx)
	if err != nil {
		t.Fatalf("DialPublicWS failed (http=%d): %v", pubSt, err)
	}
	defer pubWS.CloseNow()

	rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
	defer rcancel()
	var wsSnap PublicStatusSnapshotDTO
	for {
		_, frame, rerr := pubWS.Read(rctx)
		if rerr != nil {
			t.Fatalf("/api/v1/public/ws read failed before live online snapshot: %v (last=%+v)", rerr, wsSnap)
		}
		if json.Unmarshal(frame, &wsSnap) == nil && len(wsSnap.Nodes) == 1 &&
			wsSnap.Nodes[0].Status == "online" && wsSnap.Nodes[0].RxBPS == 50000 && wsSnap.Nodes[0].TxBPS == 75000 {
			break
		}
	}
}

func TestF16_Tier1_PublicPagePercentageOnlyAndCoreHealth(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	if stS, rawS, err := client.UpdateSettings(jwt, map[string]any{"percentage_only": true}); err != nil || stS >= 300 {
		t.Fatalf("UpdateSettings percentage_only=true failed: st=%d err=%v body=%s", stS, err, string(rawS))
	}
	stN, node, rawN, err := client.CreateNode(jwt, CreateNodeReq{
		Name:              "F16-Pct-Node",
		Enabled:           f16_boolPtr(true),
		TrafficLimitBytes: 10000,
		TrafficCountMode:  "both",
	})
	if err != nil || stN >= 300 || node.ID <= 0 {
		t.Fatalf("CreateNode failed: st=%d err=%v body=%s", stN, err, string(rawN))
	}
	if stC, rawC, err := client.CalibrateNodeTraffic(jwt, node.ID, 3000, 2000); err != nil || stC >= 300 {
		t.Fatalf("CalibrateNodeTraffic failed: st=%d err=%v body=%s", stC, err, string(rawC))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	agentWS, wsSt, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatalf("DialAgentWS failed (http=%d): %v", wsSt, err)
	}
	defer agentWS.CloseNow()
	if err := SendWSEnvelope(ctx, agentWS, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"}); err != nil {
		t.Fatalf("send agent.hello: %v", err)
	}
	if _, _, err := ReadWSEnvelope(ctx, agentWS, 3*time.Second); err != nil {
		t.Fatalf("read server.config_sync: %v", err)
	}
	if err := SendWSEnvelope(ctx, agentWS, "agent.metrics", "m1", AgentMetricsPayload{
		TS: time.Now().Unix(), Health: AgentHealthDTO{Snell: true, ShadowTLS: false, SingBox: true},
	}); err != nil {
		t.Fatalf("send agent.metrics: %v", err)
	}

	_, _ = f16_fetchHTML(t, client, "/")

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		stPub, snap, _, err := client.GetPublicStatus()
		if err == nil && stPub == http.StatusOK && len(snap.Nodes) == 1 && snap.Nodes[0].Status == "online" {
			n := snap.Nodes[0]
			if !snap.PercentageOnly || !n.PercentageOnly || n.TrafficUsedBytes != 0 || n.TrafficLimitBytes != 0 || n.TrafficPercent < 49.0 {
				t.Fatalf("percentage_only projection mismatch: %+v", n)
			}
			if n.CoreAHealthy || !n.CoreBHealthy {
				t.Fatalf("expected CoreA=false CoreB=true, got %+v", n)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("node did not reach online state")
}

func TestF16_Tier2_PublicPageZeroSecretsInHTMLAndAssets(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{
		AdminPass: "F16_ADMIN_CANARY_PASS_XYZ",
		JWTSecret: "F16_JWT_SECRET_CANARY_32_BYTES!!",
	})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "F16_ADMIN_CANARY_PASS_XYZ")

	stSet, settings, rawSet, err := client.GetSettings(jwt)
	if err != nil || stSet != http.StatusOK || settings.AdminSubToken == "" {
		t.Fatalf("GetSettings failed: st=%d err=%v token=%q body=%s", stSet, err, settings.AdminSubToken, string(rawSet))
	}
	stN, node, rawN, err := client.CreateNode(jwt, CreateNodeReq{
		Name:             "F16 Safe Node",
		PublicIP:         "198.51.100.161",
		CustomEntryHost:  "f16-canary.internal",
		Enabled:          f16_boolPtr(true),
		SnellConfig:      &SnellConfigDTO{Enabled: true, Version: "v5", PublicPort: 41601, InnerPort: 31601, PSK: "F16_SNELL_PSK_CANARY", STLSPassword: "F16_STLS_CANARY"},
		DNSUnlockEnabled: true,
		DNSUnlockServer:  "198.51.100.162:3535",
	})
	if err != nil || stN >= 300 || node.ID <= 0 {
		t.Fatalf("CreateNode failed: st=%d err=%v body=%s", stN, err, string(rawN))
	}
	stU, user, rawU, err := client.CreateUser(jwt, CreateUserReq{Username: "f16_user_canary", NodeIDs: []int64{node.ID}})
	if err != nil || stU >= 300 || user.ID <= 0 {
		t.Fatalf("CreateUser failed: st=%d err=%v body=%s", stU, err, string(rawU))
	}
	if node.EffectiveToken() == "" || user.SubToken == "" || user.SSUPSK16 == "" || user.SSUPSK32 == "" || user.STLSPassword == "" {
		t.Fatalf("expected non-empty canary secrets on node/user")
	}

	secrets := []string{
		"F16_ADMIN_CANARY_PASS_XYZ",
		"F16_JWT_SECRET_CANARY_32_BYTES!!",
		settings.AdminSubToken,
		"198.51.100.161",
		"198.51.100.162:3535",
		"f16-canary.internal",
		"F16_SNELL_PSK_CANARY",
		"F16_STLS_CANARY",
		node.EffectiveToken(),
		user.SubToken,
		user.SSUPSK16,
		user.SSUPSK32,
		user.STLSPassword,
	}

	_, html := f16_fetchHTML(t, client, "/")
	for _, s := range secrets {
		if s != "" && strings.Contains(html, s) {
			t.Fatalf("secret %q leaked in GET / HTML", s)
		}
	}
	_, _, allAssets := f16_extractAssetURLs(html)
	for _, ref := range allAssets {
		assetPath := f16_resolveAssetPath("/", ref)
		st, _, raw, err := client.DoRaw(context.Background(), http.MethodGet, assetPath, nil, nil)
		if err != nil || st != http.StatusOK {
			t.Fatalf("GET referenced public asset %s failed: st=%d err=%v", assetPath, st, err)
		}
		for _, s := range secrets {
			if s != "" && strings.Contains(string(raw), s) {
				t.Fatalf("secret %q leaked in public asset %s", s, assetPath)
			}
		}
	}
}

func TestF16_Tier2_PublicPageNonGetMethodsAndQueryParams(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()

	_, _ = f16_fetchHTML(t, client, "/?theme=dark&lang=en")

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		st, _, raw, err := client.DoRaw(context.Background(), method, "/", nil, []byte("x"))
		if err != nil {
			t.Fatalf("%s /: %v", method, err)
		}
		if st == http.StatusOK || st >= 500 {
			t.Fatalf("expected non-200 4xx (e.g. 405) for %s /, got st=%d body=%s", method, st, string(raw))
		}
	}
}

func TestF16_Tier2_PublicPageMissingAssetDoesNotFallbackToHTML(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()

	_, _ = f16_fetchHTML(t, client, "/")

	for _, p := range []string{"/assets/nonexistent-f16.js", "/assets/nonexistent-f16.css"} {
		st, hdr, raw, err := client.DoRaw(context.Background(), http.MethodGet, p, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if st != http.StatusNotFound {
			t.Fatalf("missing asset %s expected 404, got %d (ct=%s body=%s)", p, st, hdr.Get("Content-Type"), string(raw))
		}
		if strings.Contains(strings.ToLower(string(raw)), "<html") {
			t.Fatalf("missing asset %s must NOT return HTML SPA fallback", p)
		}
	}
}

func TestF16_Tier2_PublicPageEmptyNodesAndOfflineState(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()

	_, _ = f16_fetchHTML(t, client, "/")
	st, snap, _, err := client.GetPublicStatus()
	if err != nil || st != http.StatusOK || len(snap.Nodes) != 0 {
		t.Fatalf("empty panel public status failed: st=%d err=%v snap=%+v", st, err, snap)
	}

	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")
	stN, _, rawN, err := client.CreateNode(jwt, CreateNodeReq{Name: "F16 Offline Node", Enabled: f16_boolPtr(true)})
	if err != nil || stN >= 300 {
		t.Fatalf("CreateNode failed: st=%d err=%v body=%s", stN, err, string(rawN))
	}

	st2, snap2, raw2, err := client.GetPublicStatus()
	if err != nil || st2 != http.StatusOK {
		t.Fatalf("GetPublicStatus failed: st=%d err=%v body=%s", st2, err, string(raw2))
	}
	if len(snap2.Nodes) != 1 || snap2.Nodes[0].Status != "offline" || snap2.Nodes[0].CoreAHealthy || snap2.Nodes[0].CoreBHealthy {
		t.Fatalf("expected offline node with unhealthy cores, got %+v", snap2.Nodes)
	}
}

func TestF16_Tier2_PublicPageConcurrentAssetAndStatusFetches(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()

	_, html := f16_fetchHTML(t, client, "/")
	jsAssets, _, _ := f16_extractAssetURLs(html)
	if len(jsAssets) == 0 {
		t.Fatalf("no JS assets found on /")
	}
	jsPath := f16_resolveAssetPath("/", jsAssets[0])

	var wg sync.WaitGroup
	errCh := make(chan error, 30)
	for i := 0; i < 10; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			st, _, _, err := client.DoRaw(context.Background(), http.MethodGet, "/", nil, nil)
			if err != nil || st != http.StatusOK {
				errCh <- fmt.Errorf("GET / st=%d err=%v", st, err)
			}
		}()
		go func() {
			defer wg.Done()
			st, _, _, err := client.DoRaw(context.Background(), http.MethodGet, jsPath, nil, nil)
			if err != nil || st != http.StatusOK {
				errCh <- fmt.Errorf("GET %s st=%d err=%v", jsPath, st, err)
			}
		}()
		go func() {
			defer wg.Done()
			st, _, _, err := client.GetPublicStatus()
			if err != nil || st != http.StatusOK {
				errCh <- fmt.Errorf("GET public/status st=%d err=%v", st, err)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		t.Fatal(e)
	}
}

// =====================================================================
// Feature 17: Admin Console (/admin) UI (5 Tier 1 + 5 Tier 2)
// =====================================================================

func TestF17_Tier1_AdminConsoleServedAtAdmin(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()

	for _, p := range []string{"/admin", "/admin/"} {
		_, html := f16_fetchHTML(t, client, p)
		lower := strings.ToLower(html)
		if !strings.Contains(lower, "<html") && !strings.Contains(lower, "<!doctype html") {
			t.Fatalf("GET %s did not return HTML document", p)
		}
		if !strings.Contains(lower, "<script") {
			t.Fatalf("GET %s missing <script> bundle", p)
		}
	}
}

func TestF17_Tier1_AdminConsoleSPAFallbackSubroutes(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()

	subroutes := []string{
		"/admin/nodes",
		"/admin/users",
		"/admin/dns-rules",
		"/admin/templates",
		"/admin/kernels",
		"/admin/webhooks",
		"/admin/settings",
	}
	for _, route := range subroutes {
		_, html := f16_fetchHTML(t, client, route)
		if !strings.Contains(strings.ToLower(html), "<script") {
			t.Fatalf("SPA route %s missing <script> tag", route)
		}
	}
}

func TestF17_Tier1_AdminConsoleRootRelativeAssetsResolve(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()

	_, html := f16_fetchHTML(t, client, "/admin/nodes")
	jsAssets, _, allAssets := f16_extractAssetURLs(html)
	if len(jsAssets) == 0 {
		t.Fatalf("expected JS asset tags in /admin/nodes HTML")
	}
	for _, ref := range allAssets {
		if !strings.HasPrefix(ref, "/") {
			t.Fatalf("admin deep-link asset reference %q MUST be root-relative (start with '/') so /admin/* subroutes load properly", ref)
		}
		st, _, raw, err := client.DoRaw(context.Background(), http.MethodGet, ref, nil, nil)
		if err != nil || st != http.StatusOK || len(raw) == 0 {
			t.Fatalf("GET %s from /admin/nodes failed: st=%d len=%d err=%v", ref, st, len(raw), err)
		}
	}

	bundle := f16_collectBundleText(t, client, "/admin/nodes", html)
	hasAdminAPI := strings.Contains(bundle, "/api/v1/auth/login") ||
		strings.Contains(bundle, "/api/v1/admin") ||
		(strings.Contains(bundle, "/api/v1") && (strings.Contains(bundle, "/auth/login") || strings.Contains(bundle, "/admin/")))
	if !hasAdminAPI {
		t.Fatalf("admin UI bundle appears to be a hollow stub: missing /api/v1/auth/login or /api/v1/admin reference")
	}
}

func TestF17_Tier1_AdminLoginMeAndSettingsReflected(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()

	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")
	st, me, _, err := client.GetMe(jwt)
	if err != nil || st != http.StatusOK || me.Username != "admin" {
		t.Fatalf("GetMe failed: st=%d me=%+v err=%v", st, me, err)
	}

	st, raw, err := client.UpdateSettings(jwt, map[string]any{
		"site_title":             "F17 Admin Configured",
		"announcement":           "Admin Console Notice",
		"percentage_only":        true,
		"alert_cooldown_minutes": 12,
	})
	if err != nil || st >= 300 {
		t.Fatalf("UpdateSettings failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	st, settings, raw, err := client.GetSettings(jwt)
	if err != nil || st != http.StatusOK {
		t.Fatalf("GetSettings failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	if settings.SiteTitle != "F17 Admin Configured" || settings.Announcement != "Admin Console Notice" || !settings.PercentageOnly {
		t.Fatalf("unexpected settings after update: %+v", settings)
	}

	stPub, snap, rawPub, err := client.GetPublicStatus()
	if err != nil || stPub != http.StatusOK {
		t.Fatalf("GetPublicStatus failed: st=%d err=%v body=%s", stPub, err, string(rawPub))
	}
	if snap.SiteTitle != "F17 Admin Configured" || snap.Announcement != "Admin Console Notice" || !snap.PercentageOnly {
		t.Fatalf("settings not reflected on public status: %+v", snap)
	}
}

func TestF17_Tier1_AdminConsoleAllManagementAPIsAccessible(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, grp, _, err := client.CreateDNSRuleGroup(jwt, "F17-Stream", []string{"netflix.com"})
	if err != nil || grp.ID <= 0 {
		t.Fatalf("CreateDNSRuleGroup failed: %v", err)
	}
	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:             "F17-Node",
		Enabled:          f16_boolPtr(true),
		DNSUnlockEnabled: true,
		DNSUnlockServer:  "198.51.100.55:3535",
		DNSRuleGroupID:   &grp.ID,
	})
	if err != nil || node.ID <= 0 {
		t.Fatalf("CreateNode failed: %v", err)
	}
	if st, cmdRaw, err := client.GetInstallCmd(jwt, node.ID); err != nil || st != http.StatusOK || len(cmdRaw) == 0 {
		t.Fatalf("GetInstallCmd failed: st=%d err=%v", st, err)
	}
	_, usr, _, err := client.CreateUser(jwt, CreateUserReq{Username: "f17_user", NodeIDs: []int64{node.ID}})
	if err != nil || usr.ID <= 0 {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if st, _, _, err := client.ListTemplates(jwt); err != nil || st != http.StatusOK {
		t.Fatalf("ListTemplates failed: st=%d err=%v", st, err)
	}
	if st, _, err := client.DoJSON(context.Background(), http.MethodGet, "/api/v1/admin/kernels", jwt, nil, nil); err != nil || st != http.StatusOK {
		t.Fatalf("GET /api/v1/admin/kernels failed: st=%d err=%v", st, err)
	}
	if st, _, _, err := client.ListWebhooks(jwt); err != nil || st != http.StatusOK {
		t.Fatalf("ListWebhooks failed: st=%d err=%v", st, err)
	}
	if st, _, _, err := client.ListDailyTraffic(jwt, ""); err != nil || st != http.StatusOK {
		t.Fatalf("ListDailyTraffic failed: st=%d err=%v", st, err)
	}
}

func TestF17_Tier2_AdminAPIsRejectUnauthenticatedAndInvalidJWT(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()

	// /admin HTML login shell loads without JWT
	_, _ = f16_fetchHTML(t, client, "/admin")

	protected := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/auth/me"},
		{http.MethodGet, "/api/v1/admin/nodes"},
		{http.MethodGet, "/api/v1/admin/users"},
		{http.MethodGet, "/api/v1/admin/dns-rules"},
		{http.MethodGet, "/api/v1/admin/templates"},
		{http.MethodGet, "/api/v1/admin/kernels"},
		{http.MethodGet, "/api/v1/admin/webhooks"},
		{http.MethodGet, "/api/v1/admin/traffic/daily"},
		{http.MethodGet, "/api/v1/admin/settings"},
	}

	for _, ep := range protected {
		for _, badTok := range []string{"", "not.a.valid.jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.invalidsig"} {
			st, _, err := client.DoJSON(context.Background(), ep.method, ep.path, badTok, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if st != http.StatusUnauthorized {
				t.Fatalf("expected 401 for %s %s with tok=%q, got %d", ep.method, ep.path, badTok, st)
			}
		}
	}
}

func TestF17_Tier2_AdminHTMLAndAssetsContainNoHardcodedSecrets(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{
		AdminPass: "F17_CANARY_ADMIN_PASS_777",
		JWTSecret: "F17_CANARY_JWT_SECRET_32_BYTES!!",
	})
	client := panel.NewClient()

	_, html := f16_fetchHTML(t, client, "/admin")
	secrets := []string{
		"F17_CANARY_ADMIN_PASS_777",
		"F17_CANARY_JWT_SECRET_32_BYTES!!",
		"change_me_on_first_login",
	}
	for _, s := range secrets {
		if strings.Contains(html, s) {
			t.Fatalf("admin HTML leaked secret/default %q", s)
		}
	}
	_, _, allAssets := f16_extractAssetURLs(html)
	for _, ref := range allAssets {
		st, _, raw, err := client.DoRaw(context.Background(), http.MethodGet, f16_resolveAssetPath("/admin", ref), nil, nil)
		if err == nil && st == http.StatusOK {
			for _, s := range secrets {
				if strings.Contains(string(raw), s) {
					t.Fatalf("admin asset %s leaked secret/default %q", ref, s)
				}
			}
		}
	}
}

func TestF17_Tier2_AdminBadJSONAndInvalidSettingsRejected(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	// Preconditions: prove all target admin routes are mounted before negative JSON checks
	if st, _, raw, err := client.GetSettings(jwt); err != nil || st != http.StatusOK {
		t.Fatalf("precondition GET /api/v1/admin/settings expected 200 OK, got st=%d err=%v body=%s", st, err, string(raw))
	}
	if st, _, raw, err := client.ListNodes(jwt); err != nil || st != http.StatusOK {
		t.Fatalf("precondition GET /api/v1/admin/nodes expected 200 OK, got st=%d err=%v body=%s", st, err, string(raw))
	}
	if st, _, raw, err := client.ListUsers(jwt); err != nil || st != http.StatusOK {
		t.Fatalf("precondition GET /api/v1/admin/users expected 200 OK, got st=%d err=%v body=%s", st, err, string(raw))
	}

	headers := map[string]string{
		"Authorization": "Bearer " + jwt,
		"Content-Type":  "application/json",
	}
	for _, ep := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/auth/login"},
		{http.MethodPut, "/api/v1/admin/settings"},
		{http.MethodPost, "/api/v1/admin/nodes"},
		{http.MethodPost, "/api/v1/admin/users"},
	} {
		st, _, raw, err := client.DoRaw(context.Background(), ep.method, ep.path, headers, []byte(`{"broken":`))
		if err != nil {
			t.Fatal(err)
		}
		if st < 400 || st >= 500 || st == http.StatusNotFound || st == http.StatusMethodNotAllowed {
			t.Fatalf("malformed JSON to %s %s expected 400/422 (non-404/405 4xx), got %d body=%s", ep.method, ep.path, st, string(raw))
		}
	}

	st, raw, err := client.UpdateSettings(jwt, map[string]any{"alert_cooldown_minutes": -10})
	if err != nil {
		t.Fatal(err)
	}
	if st < 400 || st >= 500 || st == http.StatusNotFound || st == http.StatusMethodNotAllowed {
		t.Fatalf("negative alert_cooldown_minutes expected 400/422 (non-404/405 4xx), got st=%d body=%s", st, string(raw))
	}
	if st2, settingsAfter, raw2, err2 := client.GetSettings(jwt); err2 != nil || st2 != http.StatusOK || settingsAfter.AlertCooldownMins < 0 {
		t.Fatalf("settings after rejected update invalid: st=%d err=%v cooldown=%d body=%s", st2, err2, settingsAfter.AlertCooldownMins, string(raw2))
	}
}

func TestF17_Tier2_AdminUnknownSubrouteVsUnknownAPI(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	// Unknown /admin/* client route falls back to SPA HTML
	_, _ = f16_fetchHTML(t, client, "/admin/unknown-client-view")

	// Unknown /api/v1/admin/* API route MUST return 404 JSON (NOT HTML)
	st, hdr, raw, err := client.DoRaw(context.Background(), http.MethodGet, "/api/v1/admin/unknown-endpoint", map[string]string{
		"Authorization": "Bearer " + jwt,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown admin API endpoint, got %d body=%s", st, string(raw))
	}
	if !strings.Contains(strings.ToLower(hdr.Get("Content-Type")), "application/json") || strings.Contains(strings.ToLower(string(raw)), "<html") {
		t.Fatalf("expected JSON 404 for unknown admin API, got ct=%q body=%s", hdr.Get("Content-Type"), string(raw))
	}
}

func TestF17_Tier2_AdminPasswordChangeInvalidatesOldCredentials(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{AdminPass: "initial_f17_pass"})
	client := panel.NewClient()

	jwt1 := client.MustLogin(t, "admin", "initial_f17_pass")
	st, raw, err := client.UpdatePassword(jwt1, "initial_f17_pass", "rotated_f17_pass_2026")
	if err != nil || st >= 300 {
		t.Fatalf("UpdatePassword failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	if oldSt, _, _, _ := client.Login("admin", "initial_f17_pass"); oldSt != http.StatusUnauthorized {
		t.Fatalf("expected old password rejected with 401, got %d", oldSt)
	}
	jwt2 := client.MustLogin(t, "admin", "rotated_f17_pass_2026")
	if st, _, _, err := client.GetSettings(jwt2); err != nil || st != http.StatusOK {
		t.Fatalf("new password JWT cannot access settings: st=%d err=%v", st, err)
	}
}

// =====================================================================
// Feature 18: Embedded Frontend Build (web/dist -> cmd/panel) (5+5)
// =====================================================================

func TestF18_Tier1_WebBuildArtifactsAndEmbedDirectiveExist(t *testing.T) {
	repoRoot := findRepoRoot(t)

	pkgBytes, err := os.ReadFile(filepath.Join(repoRoot, "web", "package.json"))
	if err != nil {
		t.Fatalf("read web/package.json: %v", err)
	}
	var pkg struct {
		Name    string            `json:"name"`
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(pkgBytes, &pkg); err != nil {
		t.Fatalf("invalid web/package.json: %v", err)
	}
	if pkg.Scripts["build"] == "" {
		t.Fatalf("web/package.json missing scripts.build: %s", string(pkgBytes))
	}

	var viteFound bool
	for _, cand := range []string{"vite.config.ts", "vite.config.js", "vite.config.mts", "vite.config.mjs"} {
		if b, err := os.ReadFile(filepath.Join(repoRoot, "web", cand)); err == nil {
			viteFound = true
			stripped := f16_lineCommentRe.ReplaceAllString(f16_blockCommentRe.ReplaceAllString(string(b), ""), "")
			if f16_viteRelativeBaseRe.MatchString(stripped) {
				t.Fatalf("web/%s must not use relative base './' which breaks /admin/* deep routes", cand)
			}
			break
		}
	}
	if !viteFound {
		t.Fatalf("missing web/vite.config.{ts,js,mts,mjs}")
	}

	embedBytes, err := os.ReadFile(filepath.Join(repoRoot, "web", "embed.go"))
	if err != nil {
		t.Fatalf("read web/embed.go: %v", err)
	}
	if !strings.Contains(string(embedBytes), "//go:embed") || !strings.Contains(string(embedBytes), "dist") {
		t.Fatalf("web/embed.go must contain //go:embed directive for dist: %s", string(embedBytes))
	}

	distIndex, err := os.ReadFile(filepath.Join(repoRoot, "web", "dist", "index.html"))
	if err != nil || len(bytes.TrimSpace(distIndex)) == 0 {
		t.Fatalf("missing or empty web/dist/index.html: err=%v len=%d", err, len(distIndex))
	}
}

func TestF18_Tier1_BinaryServesEmbeddedUIWithoutWebDirOnDisk(t *testing.T) {
	env := NewTestEnv(t)
	if _, err := os.Stat(filepath.Join(env.RootDir, "web")); !os.IsNotExist(err) {
		t.Fatalf("expected empty TempDir without web/ directory, got err=%v", err)
	}

	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()

	_, rootHTML := f16_fetchHTML(t, client, "/")
	_, adminHTML := f16_fetchHTML(t, client, "/admin")
	if len(rootHTML) == 0 || len(adminHTML) == 0 {
		t.Fatal("expected non-empty embedded HTML for / and /admin")
	}

	jsAssets, _, _ := f16_extractAssetURLs(rootHTML)
	if len(jsAssets) == 0 {
		t.Fatalf("expected JS asset in embedded HTML: %s", rootHTML)
	}
	for _, ref := range jsAssets {
		st, _, raw, err := client.DoRaw(context.Background(), http.MethodGet, f16_resolveAssetPath("/", ref), nil, nil)
		if err != nil || st != http.StatusOK || len(raw) == 0 {
			t.Fatalf("embedded asset %s failed when CWD has no web/dist: st=%d len=%d err=%v", ref, st, len(raw), err)
		}
	}

	bundle := f16_collectBundleText(t, client, "/", rootHTML)
	hasPanelAPI := strings.Contains(bundle, "/api/v1/public/status") ||
		strings.Contains(bundle, "/api/v1/public/ws") ||
		strings.Contains(bundle, "/api/v1/auth/login") ||
		(strings.Contains(bundle, "/api/v1") && (strings.Contains(bundle, "/public/status") || strings.Contains(bundle, "/auth/login")))
	if !hasPanelAPI {
		t.Fatalf("embedded UI bundle appears to be a hollow stub: missing panel /api/v1/ references")
	}
}

func TestF18_Tier1_EmbeddedAssetMIMEAndCacheControlHeaders(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()

	hdrRoot, html := f16_fetchHTML(t, client, "/")
	if strings.Contains(strings.ToLower(hdrRoot.Get("Cache-Control")), "immutable") {
		t.Fatalf("index.html must NOT be marked immutable: Cache-Control=%q", hdrRoot.Get("Cache-Control"))
	}

	jsAssets, cssAssets, _ := f16_extractAssetURLs(html)
	if len(jsAssets) == 0 {
		t.Fatalf("expected JS assets in index.html")
	}
	for _, js := range jsAssets {
		st, hdr, _, err := client.DoRaw(context.Background(), http.MethodGet, f16_resolveAssetPath("/", js), nil, nil)
		if err != nil || st != http.StatusOK {
			t.Fatalf("GET %s failed: st=%d err=%v", js, st, err)
		}
		if !strings.Contains(strings.ToLower(hdr.Get("Content-Type")), "javascript") {
			t.Fatalf("expected javascript MIME for %s, got %q", js, hdr.Get("Content-Type"))
		}
		cc := strings.ToLower(hdr.Get("Cache-Control"))
		if strings.Contains(cc, "no-store") || strings.Contains(cc, "no-cache") || strings.Contains(cc, "max-age=0") {
			t.Fatalf("static asset %s must allow caching (not no-store/no-cache/max-age=0), got Cache-Control=%q", js, hdr.Get("Cache-Control"))
		}
	}
	for _, css := range cssAssets {
		st, hdr, _, err := client.DoRaw(context.Background(), http.MethodGet, f16_resolveAssetPath("/", css), nil, nil)
		if err != nil || st != http.StatusOK {
			t.Fatalf("GET %s failed: st=%d err=%v", css, st, err)
		}
		if !strings.Contains(strings.ToLower(hdr.Get("Content-Type")), "text/css") {
			t.Fatalf("expected text/css MIME for %s, got %q", css, hdr.Get("Content-Type"))
		}
		cc := strings.ToLower(hdr.Get("Cache-Control"))
		if strings.Contains(cc, "no-store") || strings.Contains(cc, "no-cache") || strings.Contains(cc, "max-age=0") {
			t.Fatalf("static asset %s must allow caching (not no-store/no-cache/max-age=0), got Cache-Control=%q", css, hdr.Get("Cache-Control"))
		}
	}
}

func TestF18_Tier1_HealthzReturnsJSONNotSPA(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()

	st, hdr, raw, err := client.DoRaw(context.Background(), http.MethodGet, "/healthz", nil, nil)
	if err != nil || st != http.StatusOK {
		t.Fatalf("GET /healthz failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	if !strings.Contains(strings.ToLower(hdr.Get("Content-Type")), "application/json") {
		t.Fatalf("GET /healthz expected application/json, got %q", hdr.Get("Content-Type"))
	}
	var out map[string]string
	if err := json.Unmarshal(raw, &out); err != nil || out["status"] != "ok" {
		t.Fatalf("GET /healthz expected {\"status\":\"ok\"}, got %s", string(raw))
	}
}

func TestF18_Tier1_EmbeddedMatchesWebDistIndexHTML(t *testing.T) {
	repoRoot := findRepoRoot(t)
	diskHTML, err := os.ReadFile(filepath.Join(repoRoot, "web", "dist", "index.html"))
	if err != nil {
		t.Fatalf("read web/dist/index.html: %v", err)
	}

	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()

	for _, route := range []string{"/", "/admin", "/admin/nodes"} {
		st, _, served, err := client.DoRaw(context.Background(), http.MethodGet, route, nil, nil)
		if err != nil || st != http.StatusOK {
			t.Fatalf("GET %s failed: st=%d err=%v", route, st, err)
		}
		if !bytes.Equal(served, diskHTML) {
			t.Fatalf("GET %s body does not match web/dist/index.html byte-for-byte (served len=%d disk len=%d)", route, len(served), len(diskHTML))
		}
	}
}

func TestF18_Tier2_UnmatchedAPIRoutesReturnJSON404NotHTML(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	cases := []struct {
		method string
		path   string
		token  string
	}{
		{http.MethodGet, "/api/v1/unknown", ""},
		{http.MethodGet, "/api/unknown", ""},
		{http.MethodPost, "/api/v1/does-not-exist", ""},
		{http.MethodGet, "/api/v1/admin/unknown-resource", jwt},
	}

	for _, tc := range cases {
		headers := map[string]string{}
		if tc.token != "" {
			headers["Authorization"] = "Bearer " + tc.token
		}
		st, hdr, raw, err := client.DoRaw(context.Background(), tc.method, tc.path, headers, nil)
		if err != nil {
			t.Fatalf("%s %s err=%v", tc.method, tc.path, err)
		}
		if st != http.StatusNotFound {
			t.Fatalf("expected 404 for %s %s, got %d body=%s", tc.method, tc.path, st, string(raw))
		}
		ct := strings.ToLower(hdr.Get("Content-Type"))
		if !strings.Contains(ct, "application/json") {
			t.Fatalf("%s %s expected application/json 404, got Content-Type=%q body=%s", tc.method, tc.path, hdr.Get("Content-Type"), string(raw))
		}
		var js any
		if err := json.Unmarshal(raw, &js); err != nil {
			t.Fatalf("%s %s 404 body is not valid JSON: %v (body=%s)", tc.method, tc.path, err, string(raw))
		}
		if strings.Contains(strings.ToLower(string(raw)), "<html") {
			t.Fatalf("%s %s returned HTML instead of JSON 404", tc.method, tc.path)
		}
	}
}

func TestF18_Tier2_MissingStaticAssetsReturn404NotHTML(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()

	_, _ = f16_fetchHTML(t, client, "/")

	for _, p := range []string{"/assets/does-not-exist-12345.js", "/assets/does-not-exist-12345.css", "/assets/"} {
		st, _, raw, err := client.DoRaw(context.Background(), http.MethodGet, p, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if st != http.StatusNotFound {
			t.Fatalf("missing static path %s expected 404, got %d body=%s", p, st, string(raw))
		}
		if strings.Contains(strings.ToLower(string(raw)), "<html") {
			t.Fatalf("missing static path %s must NOT return HTML SPA fallback", p)
		}
	}
}

func TestF18_Tier2_PathTraversalRejectedSafely(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()

	_, _ = f16_fetchHTML(t, client, "/")

	rawPaths := []string{
		"/assets/../../go.mod",
		"/assets/%2e%2e/%2e%2e/go.mod",
		"/../../go.mod",
		"/admin/../../go.mod",
	}

	for _, p := range rawPaths {
		conn, err := net.DialTimeout("tcp", panel.ListenAddr, 3*time.Second)
		if err != nil {
			t.Fatalf("dial %s: %v", panel.ListenAddr, err)
		}
		_, err = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", p, panel.ListenAddr)
		if err != nil {
			_ = conn.Close()
			t.Fatalf("write raw HTTP request for %s: %v", p, err)
		}
		respBytes, err := io.ReadAll(conn)
		_ = conn.Close()
		if err != nil {
			t.Fatalf("read raw HTTP response for %s: %v", p, err)
		}
		respStr := string(respBytes)
		if strings.Contains(respStr, "module snell-panel") {
			t.Fatalf("PATH TRAVERSAL LEAK for %s: returned go.mod contents!", p)
		}
		firstLine := strings.SplitN(respStr, "\r\n", 2)[0]
		if !strings.Contains(firstLine, " 400 ") && !strings.Contains(firstLine, " 403 ") && !strings.Contains(firstLine, " 404 ") && !strings.Contains(firstLine, " 301 ") && !strings.Contains(firstLine, " 307 ") {
			t.Fatalf("path traversal probe %s returned unexpected status line %q", p, firstLine)
		}
	}
}

func TestF18_Tier2_UnknownSubscriptionTokensDoNotFallbackToSPA(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()

	_, _ = f16_fetchHTML(t, client, "/")

	for _, p := range []string{"/s/admin/nonexistent_admin_tok", "/s/u/nonexistent_user_tok"} {
		st, _, raw, err := client.DoRaw(context.Background(), http.MethodGet, p, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if st == http.StatusOK || strings.Contains(strings.ToLower(string(raw)), "<html") {
			t.Fatalf("invalid sub token %s must not return 200/SPA HTML, got st=%d body=%s", p, st, string(raw))
		}
	}
}

func TestF18_Tier2_ByteIdenticalAcrossIndependentTempWorkdirs(t *testing.T) {
	env1 := NewTestEnv(t)
	env2 := NewTestEnv(t)
	p1 := StartPanel(env1, PanelConfig{})
	p2 := StartPanel(env2, PanelConfig{})
	c1 := p1.NewClient()
	c2 := p2.NewClient()

	for _, route := range []string{"/", "/admin"} {
		st1, _, b1, err1 := c1.DoRaw(context.Background(), http.MethodGet, route, nil, nil)
		st2, _, b2, err2 := c2.DoRaw(context.Background(), http.MethodGet, route, nil, nil)
		if err1 != nil || err2 != nil || st1 != http.StatusOK || st2 != http.StatusOK {
			t.Fatalf("GET %s failed: p1=(%d,%v) p2=(%d,%v)", route, st1, err1, st2, err2)
		}
		if !bytes.Equal(b1, b2) {
			t.Fatalf("GET %s differed across independent empty temp dirs", route)
		}
	}
}
