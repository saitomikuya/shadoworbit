//go:build e2e

package e2e_test

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func f13_boolPtr(v bool) *bool { return &v }

func f13_dialAgentHelloAndSync(t *testing.T, ctx context.Context, client *PanelClient, nodeToken, arch string) *websocket.Conn {
	t.Helper()
	conn, wsStatus, err := client.DialAgentWS(ctx, nodeToken)
	if err != nil {
		t.Fatalf("DialAgentWS failed (http=%d): %v", wsStatus, err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })

	if err := SendWSEnvelope(ctx, conn, "agent.hello", "f13-hello", AgentHelloPayload{
		OS:            "linux",
		Arch:          arch,
		CPUCores:      2,
		TotalRAMBytes: 4 * 1024 * 1024 * 1024,
		Versions: AgentVersionsDTO{
			SingBox:     "1.11.0",
			SnellServer: "5.0.0",
			ShadowTLS:   "0.2.24",
		},
		ConfigRevision: 0,
	}); err != nil {
		t.Fatalf("send agent.hello: %v", err)
	}

	env, raw, err := ReadWSEnvelope(ctx, conn, 5*time.Second)
	if err != nil {
		t.Fatalf("read initial server.config_sync: %v", err)
	}
	if env.Type != "server.config_sync" {
		t.Fatalf("expected server.config_sync on hello, got %q (%s)", env.Type, string(raw))
	}
	return conn
}

func f13_readUntilKernelUpdate(t *testing.T, ctx context.Context, conn *websocket.Conn, timeout time.Duration) ServerKernelUpdatePayload {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		rem := time.Until(deadline)
		if rem <= 0 {
			break
		}
		env, raw, err := ReadWSEnvelope(ctx, conn, rem)
		if err != nil {
			t.Fatalf("waiting for server.kernel_update: %v", err)
		}
		if env.Type == "server.kernel_update" {
			var payload ServerKernelUpdatePayload
			if err := json.Unmarshal(env.Payload, &payload); err != nil {
				t.Fatalf("decode server.kernel_update payload: %v (raw=%s)", err, string(raw))
			}
			return payload
		}
	}
	t.Fatalf("timed out waiting for server.kernel_update within %s", timeout)
	return ServerKernelUpdatePayload{}
}

func f13_hasNonEmptyErrorJSON(raw []byte) bool {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return false
	}
	for _, key := range []string{"error", "err"} {
		if s, ok := obj[key].(string); ok && strings.TrimSpace(s) != "" {
			return true
		}
	}
	if s, ok := obj["status"].(string); ok {
		ls := strings.ToLower(strings.TrimSpace(s))
		if ls == "error" || ls == "failed" || ls == "partial" {
			return true
		}
	}
	for _, key := range []string{"errors", "failed"} {
		if arr, ok := obj[key].([]any); ok && len(arr) > 0 {
			return true
		}
		if mp, ok := obj[key].(map[string]any); ok && len(mp) > 0 {
			return true
		}
	}
	return false
}

func f13_assertOfflineNodeReported(t *testing.T, raw []byte, offlineID int64) {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("batch update response must be valid JSON: %v (body=%s)", err, string(raw))
	}
	offlineStr := strconv.FormatInt(offlineID, 10)
	if disp, ok := obj["dispatched"].([]any); ok {
		for _, item := range disp {
			if f, ok := item.(float64); ok && int64(f) == offlineID {
				t.Fatalf("offline node %d must not appear in dispatched list: %s", offlineID, string(raw))
			}
			if s, ok := item.(string); ok && s == offlineStr {
				t.Fatalf("offline node %d must not appear in dispatched list: %s", offlineID, string(raw))
			}
		}
	}
	if results, ok := obj["results"].([]any); ok && len(results) > 0 {
		for _, r := range results {
			rm, ok := r.(map[string]any)
			if !ok {
				continue
			}
			idMatch := false
			if f, ok := rm["node_id"].(float64); ok && int64(f) == offlineID {
				idMatch = true
			} else if f, ok := rm["id"].(float64); ok && int64(f) == offlineID {
				idMatch = true
			}
			if !idMatch {
				continue
			}
			statusStr, _ := rm["status"].(string)
			errStr, _ := rm["error"].(string)
			ls := strings.ToLower(strings.TrimSpace(statusStr))
			if errStr != "" || ls == "offline" || ls == "failed" || ls == "error" || ls == "skipped" || ls == "not_connected" {
				return
			}
		}
	}
	for _, key := range []string{"failed", "errors", "offline", "offline_node_ids", "failed_node_ids", "skipped"} {
		val, exists := obj[key]
		if !exists || val == nil {
			continue
		}
		switch v := val.(type) {
		case []any:
			if len(v) > 0 {
				b, _ := json.Marshal(v)
				if strings.Contains(string(b), offlineStr) {
					return
				}
			}
		case map[string]any:
			if len(v) > 0 {
				b, _ := json.Marshal(v)
				if strings.Contains(string(b), offlineStr) {
					return
				}
			}
		}
	}
	t.Fatalf("expected non-empty failure/offline entry for offline node %d in JSON response, got: %s", offlineID, string(raw))
}

func TestF13_Tier1_GetKernelsReturnsBuiltinAndCacheStructure(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	st, raw, err := client.DoJSON(context.Background(), http.MethodGet, "/api/v1/admin/kernels", jwt, nil, nil)
	if err != nil || st != http.StatusOK {
		t.Fatalf("GET /api/v1/admin/kernels failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("GET /api/v1/admin/kernels returned invalid JSON: %v (body=%s)", err, string(raw))
	}
	if len(obj) == 0 {
		t.Fatalf("GET /api/v1/admin/kernels returned empty JSON object")
	}
	bodyLower := strings.ToLower(string(raw))
	hasSing := strings.Contains(bodyLower, "sing-box") || strings.Contains(bodyLower, "sing_box")
	hasSnell := strings.Contains(bodyLower, "snell")
	hasShadow := strings.Contains(bodyLower, "shadow")
	if !hasSing || !hasSnell || !hasShadow {
		t.Fatalf("expected all 3 kernels (sing-box, snell-server, shadow-tls) in GET /api/v1/admin/kernels, got: %s", string(raw))
	}
}

func TestF13_Tier1_SyncGitHubReleasesAndPersistCache(t *testing.T) {
	gh := StartMockGitHubServer(t, MockGitHubOptions{
		Releases: []MockGitHubRelease{
			{
				Owner:   "SagerNet",
				Repo:    "sing-box",
				TagName: "v1.11.4",
				Assets: []MockGitHubAsset{
					{
						Name:       "sing-box-1.11.4-linux-amd64.tar.gz",
						Archive:    true,
						BinaryName: "sing-box",
						Payload:    []byte("#!/bin/sh\necho sing-box 1.11.4\n"),
					},
					{
						Name:       "sing-box-1.11.4-linux-arm64.tar.gz",
						Archive:    true,
						BinaryName: "sing-box",
						Payload:    []byte("#!/bin/sh\necho sing-box 1.11.4\n"),
					},
				},
			},
			{
				Owner:   "ihciah",
				Repo:    "shadow-tls",
				TagName: "v0.2.25",
				Assets: []MockGitHubAsset{
					{
						Name:    "shadow-tls-x86_64-unknown-linux-musl",
						Payload: []byte("#!/bin/sh\necho shadow-tls 0.2.25\n"),
					},
					{
						Name:    "shadow-tls-aarch64-unknown-linux-musl",
						Payload: []byte("#!/bin/sh\necho shadow-tls 0.2.25\n"),
					},
				},
			},
		},
	})

	env := NewTestEnv(t)
	dbPath := filepath.Join(env.RootDir, "panel.db")
	panel := StartPanel(env, PanelConfig{
		DBPath:   dbPath,
		ExtraEnv: []string{"GITHUB_API_URL=" + gh.URL()},
	})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	st, syncRaw, err := client.DoJSON(context.Background(), http.MethodPost, "/api/v1/admin/kernels/sync", jwt, nil, nil)
	if err != nil || st < 200 || st >= 300 {
		t.Fatalf("POST /api/v1/admin/kernels/sync failed: st=%d err=%v body=%s", st, err, string(syncRaw))
	}

	paths := gh.PathsRequested()
	if len(paths) < 2 {
		t.Fatalf("expected mock GitHub server to be queried for sing-box and shadow-tls, got paths=%v", paths)
	}
	joinedPaths := strings.Join(paths, ",")
	if !strings.Contains(joinedPaths, "sing-box") || !strings.Contains(joinedPaths, "shadow-tls") {
		t.Fatalf("expected sync to query both sing-box and shadow-tls releases, got %v", paths)
	}

	st, kernelsRaw, err := client.DoJSON(context.Background(), http.MethodGet, "/api/v1/admin/kernels", jwt, nil, nil)
	if err != nil || st != http.StatusOK {
		t.Fatalf("GET /api/v1/admin/kernels failed: st=%d err=%v body=%s", st, err, string(kernelsRaw))
	}
	if !strings.Contains(string(kernelsRaw), "1.11.4") || !strings.Contains(string(kernelsRaw), "0.2.25") {
		t.Fatalf("expected synced versions 1.11.4 and 0.2.25 in kernels cache, got: %s", string(kernelsRaw))
	}

	// Restart panel and verify kernel cache survived in SQLite
	if err := panel.Stop(); err != nil {
		t.Fatalf("panel.Stop: %v", err)
	}
	panel2 := StartPanel(env, PanelConfig{DBPath: dbPath})
	client2 := panel2.NewClient()
	jwt2 := client2.MustLogin(t, "admin", "change_me_on_first_login")

	st, cachedRaw, err := client2.DoJSON(context.Background(), http.MethodGet, "/api/v1/admin/kernels", jwt2, nil, nil)
	if err != nil || st != http.StatusOK {
		t.Fatalf("GET /api/v1/admin/kernels after restart failed: st=%d err=%v body=%s", st, err, string(cachedRaw))
	}
	if !strings.Contains(string(cachedRaw), "1.11.4") || !strings.Contains(string(cachedRaw), "0.2.25") {
		t.Fatalf("expected persisted kernel versions after restart, got: %s", string(cachedRaw))
	}
}

func TestF13_Tier1_SnellVersionsBuiltinAndCustomMap(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	st, raw, err := client.DoJSON(context.Background(), http.MethodGet, "/api/v1/admin/kernels/snell-versions", jwt, nil, nil)
	if err != nil || st != http.StatusOK {
		t.Fatalf("GET /api/v1/admin/kernels/snell-versions failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	lower := strings.ToLower(string(raw))
	if (!strings.Contains(lower, "v4") && !strings.Contains(lower, "4.")) || (!strings.Contains(lower, "v5") && !strings.Contains(lower, "5.")) {
		t.Fatalf("expected built-in snell v4 and v5 entries, got: %s", string(raw))
	}
	if !strings.Contains(lower, "amd64") || !strings.Contains(lower, "arm64") {
		t.Fatalf("expected both amd64 and arm64 URLs in snell-versions, got: %s", string(raw))
	}

	// Add custom snell-server version URL map
	customReq := map[string]any{
		"version": "v5.0.1-e2e",
		"urls": map[string]string{
			"amd64": "https://dl.example.com/snell-server-v5.0.1-e2e-linux-amd64.zip",
			"arm64": "https://dl.example.com/snell-server-v5.0.1-e2e-linux-arm64.zip",
		},
	}
	st, postRaw, err := client.DoJSON(context.Background(), http.MethodPost, "/api/v1/admin/kernels/snell-versions", jwt, customReq, nil)
	if err != nil || st < 200 || st >= 300 {
		t.Fatalf("POST /api/v1/admin/kernels/snell-versions failed: st=%d err=%v body=%s", st, err, string(postRaw))
	}

	st, afterRaw, err := client.DoJSON(context.Background(), http.MethodGet, "/api/v1/admin/kernels/snell-versions", jwt, nil, nil)
	if err != nil || st != http.StatusOK {
		t.Fatalf("GET snell-versions after POST failed: st=%d err=%v", st, err)
	}
	if !strings.Contains(string(afterRaw), "v5.0.1-e2e") || !strings.Contains(string(afterRaw), "snell-server-v5.0.1-e2e-linux-arm64.zip") {
		t.Fatalf("expected custom snell version v5.0.1-e2e in GET response, got: %s", string(afterRaw))
	}
}

func TestF13_Tier1_SingleNodeKernelUpdateDispatchesWSPayload(t *testing.T) {
	gh := StartMockGitHubServer(t, MockGitHubOptions{
		Releases: []MockGitHubRelease{
			{
				Owner:   "SagerNet",
				Repo:    "sing-box",
				TagName: "v1.11.4",
				Assets: []MockGitHubAsset{
					{
						Name:       "sing-box-1.11.4-linux-amd64.tar.gz",
						Archive:    true,
						BinaryName: "sing-box",
						Payload:    []byte("mock-sing-box-binary-v1.11.4"),
					},
				},
			},
		},
	})

	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	stNode, node, raw, err := client.CreateNode(jwt, CreateNodeReq{Name: "F13 Single Update", Enabled: f13_boolPtr(true)})
	if err != nil || (stNode != http.StatusOK && stNode != http.StatusCreated) {
		t.Fatalf("CreateNode failed: st=%d err=%v body=%s", stNode, err, string(raw))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn := f13_dialAgentHelloAndSync(t, ctx, client, node.EffectiveToken(), "amd64")

	dlURL := gh.AssetURL("sing-box-1.11.4-linux-amd64.tar.gz")
	sha := gh.AssetSHA256("sing-box-1.11.4-linux-amd64.tar.gz")

	st, updRaw, err := client.TriggerKernelUpdate(jwt, []int64{node.ID}, "sing-box", "1.11.4", dlURL, sha)
	if err != nil || st < 200 || st >= 300 {
		t.Fatalf("TriggerKernelUpdate failed: st=%d err=%v body=%s", st, err, string(updRaw))
	}

	got := f13_readUntilKernelUpdate(t, ctx, conn, 5*time.Second)
	if got.Kernel != "sing-box" || got.Version != "1.11.4" || got.DownloadURL != dlURL || got.SHA256 != sha {
		t.Fatalf("server.kernel_update mismatch: got=%+v want kernel=sing-box version=1.11.4 url=%s sha=%s", got, dlURL, sha)
	}
}

func TestF13_Tier1_BatchKernelUpdateDispatchesToAllConnectedNodes(t *testing.T) {
	gh := StartMockGitHubServer(t, MockGitHubOptions{
		Releases: []MockGitHubRelease{
			{
				Owner:   "ihciah",
				Repo:    "shadow-tls",
				TagName: "v0.2.25",
				Assets: []MockGitHubAsset{
					{
						Name:    "shadow-tls-linux-amd64",
						Payload: []byte("mock-shadow-tls-0.2.25"),
					},
				},
			},
		},
	})

	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	nodeIDs := make([]int64, 0, 3)
	conns := make([]*websocket.Conn, 0, 3)
	for _, name := range []string{"F13-Batch-1", "F13-Batch-2", "F13-Batch-3"} {
		stN, node, rawN, err := client.CreateNode(jwt, CreateNodeReq{Name: name, Enabled: f13_boolPtr(true)})
		if err != nil || (stN != http.StatusOK && stN != http.StatusCreated) {
			t.Fatalf("CreateNode(%s) failed: st=%d err=%v body=%s", name, stN, err, string(rawN))
		}
		nodeIDs = append(nodeIDs, node.ID)
		conns = append(conns, f13_dialAgentHelloAndSync(t, ctx, client, node.EffectiveToken(), "amd64"))
	}

	dlURL := gh.AssetURL("shadow-tls-linux-amd64")
	sha := gh.AssetSHA256("shadow-tls-linux-amd64")
	st, raw, err := client.TriggerKernelUpdate(jwt, nodeIDs, "shadow-tls", "0.2.25", dlURL, sha)
	if err != nil || st < 200 || st >= 300 {
		t.Fatalf("batch TriggerKernelUpdate failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	for i, c := range conns {
		got := f13_readUntilKernelUpdate(t, ctx, c, 5*time.Second)
		if got.Kernel != "shadow-tls" || got.Version != "0.2.25" || got.DownloadURL != dlURL || got.SHA256 != sha {
			t.Fatalf("node[%d] server.kernel_update mismatch: got=%+v", i, got)
		}
	}
}

func TestF13_Tier2_GitHubSyncFailurePreservesCachedVersions(t *testing.T) {
	gh := StartMockGitHubServer(t, MockGitHubOptions{
		Releases: []MockGitHubRelease{
			{
				Owner:   "SagerNet",
				Repo:    "sing-box",
				TagName: "v1.11.4",
				Assets: []MockGitHubAsset{
					{Name: "sing-box-1.11.4-linux-amd64.tar.gz", Archive: true, BinaryName: "sing-box", Payload: []byte("v1")},
				},
			},
			{
				Owner:   "ihciah",
				Repo:    "shadow-tls",
				TagName: "v0.2.25",
				Assets: []MockGitHubAsset{
					{Name: "shadow-tls-x86_64-unknown-linux-musl", Payload: []byte("v1")},
				},
			},
		},
	})

	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{ExtraEnv: []string{"GITHUB_API_URL=" + gh.URL()}})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	st, raw, err := client.DoJSON(context.Background(), http.MethodPost, "/api/v1/admin/kernels/sync", jwt, nil, nil)
	if err != nil || st < 200 || st >= 300 {
		t.Fatalf("initial sync failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	// Simulate GitHub upstream failure
	gh.SetStatusCode(http.StatusServiceUnavailable)
	stFail, failRaw, err := client.DoJSON(context.Background(), http.MethodPost, "/api/v1/admin/kernels/sync", jwt, nil, nil)
	if err != nil {
		t.Fatalf("sync request error: %v", err)
	}
	if stFail == http.StatusNotFound {
		t.Fatalf("POST /api/v1/admin/kernels/sync returned 404 on upstream failure")
	}
	if stFail >= 200 && stFail < 300 && !f13_hasNonEmptyErrorJSON(failRaw) {
		t.Fatalf("expected non-2xx status or non-empty error/errors in JSON when GitHub returns 503, got st=%d body=%s", stFail, string(failRaw))
	}

	// Cached versions must remain intact
	st, cachedRaw, err := client.DoJSON(context.Background(), http.MethodGet, "/api/v1/admin/kernels", jwt, nil, nil)
	if err != nil || st != http.StatusOK {
		t.Fatalf("GET /api/v1/admin/kernels after failed sync: st=%d err=%v", st, err)
	}
	if !strings.Contains(string(cachedRaw), "1.11.4") || !strings.Contains(string(cachedRaw), "0.2.25") {
		t.Fatalf("failed GitHub sync wiped cached versions! body=%s", string(cachedRaw))
	}
}

func TestF13_Tier2_UpdateRejectsInvalidKernelURLAndSHA256(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	if stK, kRaw, errK := client.DoJSON(context.Background(), http.MethodGet, "/api/v1/admin/kernels", jwt, nil, nil); errK != nil || stK != http.StatusOK {
		t.Fatalf("precondition GET /api/v1/admin/kernels expected 200 OK, got st=%d err=%v body=%s", stK, errK, string(kRaw))
	}

	stN, node, rawN, err := client.CreateNode(jwt, CreateNodeReq{Name: "F13 Validation Node", Enabled: f13_boolPtr(true)})
	if err != nil || (stN != http.StatusOK && stN != http.StatusCreated) {
		t.Fatalf("CreateNode failed: st=%d err=%v body=%s", stN, err, string(rawN))
	}

	validSHA := strings.Repeat("a", 64)

	// Positive control: prove POST /api/v1/admin/kernels/update is mounted and dispatches valid update
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn := f13_dialAgentHelloAndSync(t, ctx, client, node.EffectiveToken(), "amd64")
	stValid, rawValid, errValid := client.TriggerKernelUpdate(jwt, []int64{node.ID}, "sing-box", "1.11.4", "https://example.com/sing-box.tar.gz", validSHA)
	if errValid != nil || stValid < 200 || stValid >= 300 {
		t.Fatalf("positive-control TriggerKernelUpdate expected 2xx, got st=%d err=%v body=%s", stValid, errValid, string(rawValid))
	}
	_ = f13_readUntilKernelUpdate(t, ctx, conn, 5*time.Second)

	cases := []struct {
		name    string
		nodeIDs []int64
		kernel  string
		version string
		url     string
		sha256  string
	}{
		{"invalid_kernel_xray", []int64{node.ID}, "xray", "1.0.0", "https://example.com/xray", validSHA},
		{"empty_kernel", []int64{node.ID}, "", "1.0.0", "https://example.com/bin", validSHA},
		{"ftp_download_url", []int64{node.ID}, "sing-box", "1.11.4", "ftp://example.com/sing-box.tar.gz", validSHA},
		{"empty_download_url", []int64{node.ID}, "sing-box", "1.11.4", "", validSHA},
		{"short_sha256", []int64{node.ID}, "sing-box", "1.11.4", "https://example.com/sing-box.tar.gz", "abcd1234"},
		{"non_hex_sha256", []int64{node.ID}, "sing-box", "1.11.4", "https://example.com/sing-box.tar.gz", strings.Repeat("z", 64)},
		{"empty_node_ids", []int64{}, "sing-box", "1.11.4", "https://example.com/sing-box.tar.gz", validSHA},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, raw, err := client.TriggerKernelUpdate(jwt, tc.nodeIDs, tc.kernel, tc.version, tc.url, tc.sha256)
			if err != nil {
				t.Fatalf("TriggerKernelUpdate HTTP error: %v", err)
			}
			if st == http.StatusNotFound || st < 400 || st >= 500 {
				t.Fatalf("expected non-404 4xx rejection for %s, got status=%d body=%s", tc.name, st, string(raw))
			}
		})
	}
}

func TestF13_Tier2_BatchUpdatePartialOnlineAndOfflineNode(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	stOn, onlineNode, rawOn, err := client.CreateNode(jwt, CreateNodeReq{Name: "F13 Online", Enabled: f13_boolPtr(true)})
	if err != nil || (stOn != http.StatusOK && stOn != http.StatusCreated) {
		t.Fatalf("CreateNode(online) failed: st=%d err=%v body=%s", stOn, err, string(rawOn))
	}
	stOff, offlineNode, rawOff, err := client.CreateNode(jwt, CreateNodeReq{Name: "F13 Offline", Enabled: f13_boolPtr(true)})
	if err != nil || (stOff != http.StatusOK && stOff != http.StatusCreated) {
		t.Fatalf("CreateNode(offline) failed: st=%d err=%v body=%s", stOff, err, string(rawOff))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn := f13_dialAgentHelloAndSync(t, ctx, client, onlineNode.EffectiveToken(), "amd64")

	dlURL := "https://example.com/snell-server-v5.0.0.zip"
	sha := strings.Repeat("b", 64)
	st, raw, err := client.TriggerKernelUpdate(jwt, []int64{onlineNode.ID, offlineNode.ID}, "snell-server", "5.0.0", dlURL, sha)
	if err != nil {
		t.Fatalf("TriggerKernelUpdate HTTP error: %v", err)
	}
	if st == http.StatusNotFound || st >= 500 {
		t.Fatalf("partial batch update must not return 404 or 5xx, got st=%d body=%s", st, string(raw))
	}

	// Online node must still receive the dispatch
	got := f13_readUntilKernelUpdate(t, ctx, conn, 5*time.Second)
	if got.Kernel != "snell-server" || got.Version != "5.0.0" || got.DownloadURL != dlURL {
		t.Fatalf("online node received unexpected kernel update payload: %+v", got)
	}

	// Response must report failure/offline status for offlineNode in structured JSON
	f13_assertOfflineNodeReported(t, raw, offlineNode.ID)
}

func TestF13_Tier2_CustomSnellVersionValidation(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	if stS, sRaw, errS := client.DoJSON(context.Background(), http.MethodGet, "/api/v1/admin/kernels/snell-versions", jwt, nil, nil); errS != nil || stS != http.StatusOK {
		t.Fatalf("precondition GET /api/v1/admin/kernels/snell-versions expected 200 OK, got st=%d err=%v body=%s", stS, errS, string(sRaw))
	}
	validReq := map[string]any{
		"version": "v5.0.2-valid-precheck",
		"urls": map[string]string{
			"amd64": "https://example.com/snell-v5.0.2-amd64.zip",
			"arm64": "https://example.com/snell-v5.0.2-arm64.zip",
		},
	}
	if stV, vRaw, errV := client.DoJSON(context.Background(), http.MethodPost, "/api/v1/admin/kernels/snell-versions", jwt, validReq, nil); errV != nil || stV < 200 || stV >= 300 {
		t.Fatalf("positive-control POST /api/v1/admin/kernels/snell-versions expected 2xx, got st=%d err=%v body=%s", stV, errV, string(vRaw))
	}

	cases := []struct {
		name string
		body map[string]any
	}{
		{
			name: "missing_version",
			body: map[string]any{
				"version": "",
				"urls":    map[string]string{"amd64": "https://example.com/snell.zip"},
			},
		},
		{
			name: "bad_url_scheme",
			body: map[string]any{
				"version": "v5.9.9-bad",
				"urls":    map[string]string{"amd64": "ftp://example.com/snell.zip"},
			},
		},
		{
			name: "invalid_arch_key",
			body: map[string]any{
				"version": "v5.9.9-badarch",
				"urls":    map[string]string{"mips64": "https://example.com/snell.zip"},
			},
		},
		{
			name: "empty_urls_map",
			body: map[string]any{
				"version": "v5.9.9-empty",
				"urls":    map[string]string{},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, raw, err := client.DoJSON(context.Background(), http.MethodPost, "/api/v1/admin/kernels/snell-versions", jwt, tc.body, nil)
			if err != nil {
				t.Fatalf("HTTP error: %v", err)
			}
			if st == http.StatusNotFound || st < 400 || st >= 500 {
				t.Fatalf("expected non-404 4xx for %s, got st=%d body=%s", tc.name, st, string(raw))
			}
		})
	}
}

func TestF13_Tier2_KernelEndpointsRequireAuth(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()

	endpoints := []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, "/api/v1/admin/kernels", nil},
		{http.MethodPost, "/api/v1/admin/kernels/sync", nil},
		{http.MethodGet, "/api/v1/admin/kernels/snell-versions", nil},
		{http.MethodPost, "/api/v1/admin/kernels/snell-versions", map[string]any{"version": "v5.0.0", "urls": map[string]string{"amd64": "https://example.com/a.zip"}}},
		{http.MethodPost, "/api/v1/admin/kernels/update", map[string]any{"node_ids": []int64{1}, "kernel": "sing-box", "version": "1.11.4", "download_url": "https://example.com/a.tar.gz"}},
	}

	for _, ep := range endpoints {
		for _, tok := range []string{"", "invalid.jwt.token"} {
			st, raw, err := client.DoJSON(context.Background(), ep.method, ep.path, tok, ep.body, nil)
			if err != nil {
				t.Fatalf("%s %s err=%v", ep.method, ep.path, err)
			}
			if st != http.StatusUnauthorized {
				t.Fatalf("expected 401 for %s %s (tok=%q), got %d body=%s", ep.method, ep.path, tok, st, string(raw))
			}
		}
	}
}

func TestF13_Tier2_AgentKernelUpdateEventFeedbackDoesNotPanic(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	whSrv := StartMockWebhookServer(t)
	st, _, whRaw, err := client.CreateWebhook(jwt, WebhookChannelDTO{
		Name:             "F13 Kernel Hook",
		Provider:         "custom",
		URL:              whSrv.URL(),
		SubscribedEvents: []string{"kernel_update"},
		Enabled:          true,
	})
	if err != nil || st >= 300 {
		t.Fatalf("CreateWebhook failed: st=%d err=%v body=%s", st, err, string(whRaw))
	}

	stNode, node, rawNode, err := client.CreateNode(jwt, CreateNodeReq{Name: "F13 Feedback Node", Enabled: f13_boolPtr(true)})
	if err != nil || (stNode != http.StatusOK && stNode != http.StatusCreated) {
		t.Fatalf("CreateNode failed: st=%d err=%v body=%s", stNode, err, string(rawNode))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn := f13_dialAgentHelloAndSync(t, ctx, client, node.EffectiveToken(), "amd64")

	// Send progress then update_failed event from agent
	for _, ev := range []AgentEventPayload{
		{
			Event:   "kernel_update_progress",
			Kernel:  "sing-box",
			Status:  "in_progress",
			Version: "1.11.4",
			Message: "downloading",
		},
		{
			Event:   "kernel_update_result",
			Kernel:  "sing-box",
			Status:  "update_failed",
			Version: "1.11.4",
			Message: "health check failed; rolled back to 1.11.0",
			Detail:  "exit status 1",
		},
	} {
		if err := SendWSEnvelope(ctx, conn, "agent.event", "ev-"+ev.Status, ev); err != nil {
			t.Fatalf("send agent.event (%s): %v", ev.Event, err)
		}
	}

	// Verify session remains alive by sending metrics and seeing node online
	if err := SendWSEnvelope(ctx, conn, "agent.metrics", "m-after-ev", AgentMetricsPayload{
		TS:         time.Now().Unix(),
		CPUPercent: 12.5,
		Health:     AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatalf("send metrics after kernel_update_result: %v", err)
	}

	reqs, ok := whSrv.WaitForRequests(1, 5*time.Second)
	if !ok || len(reqs) < 1 {
		t.Fatalf("expected webhook notification for kernel_update failure event, got %d requests", len(reqs))
	}
	if !strings.Contains(reqs[0].Body, "sing-box") && !strings.Contains(reqs[0].Body, "kernel_update") {
		t.Fatalf("unexpected webhook payload for kernel_update_result: %s", reqs[0].Body)
	}

	st, _, nodeRaw, err := client.GetNode(jwt, node.ID)
	if err != nil || st != http.StatusOK {
		t.Fatalf("GetNode after kernel_update_result failed: st=%d err=%v body=%s", st, err, string(nodeRaw))
	}
	var nodeDetail struct {
		Status           string           `json:"status"`
		ReportedVersions AgentVersionsDTO `json:"reported_versions"`
	}
	if err := json.Unmarshal(nodeRaw, &nodeDetail); err != nil {
		t.Fatalf("decode GetNode response: %v (body=%s)", err, string(nodeRaw))
	}
	if nodeDetail.Status != "online" {
		t.Fatalf("expected node status=online after metrics, got %q (body=%s)", nodeDetail.Status, string(nodeRaw))
	}
	if nodeDetail.ReportedVersions.SingBox != "1.11.0" {
		t.Fatalf("expected reported_versions.sing_box to remain \"1.11.0\" after update_failed, got %q (body=%s)", nodeDetail.ReportedVersions.SingBox, string(nodeRaw))
	}
}
