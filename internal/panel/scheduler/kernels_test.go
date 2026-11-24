package scheduler_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"snell-panel/internal/panel/hub"
	"snell-panel/internal/panel/scheduler"
	"snell-panel/internal/protocol"
)

func TestListKernels_DefaultsAndBuiltInSnell(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	sched := scheduler.NewScheduler(st, nil, nil)

	cat, err := sched.ListKernels(ctx)
	if err != nil {
		t.Fatalf("ListKernels: %v", err)
	}
	raw, err := json.Marshal(cat)
	if err != nil {
		t.Fatalf("marshal catalog: %v", err)
	}
	body := string(raw)
	if !strings.Contains(body, `"sing-box":[]`) || !strings.Contains(body, `"shadow-tls":[]`) || !strings.Contains(body, `"snell-server":[`) {
		t.Fatalf("unexpected catalog JSON keys/values: %s", body)
	}
	if len(cat.SnellServer) < 2 {
		t.Fatalf("expected built-in v4 & v5 snell entries, got %+v", cat.SnellServer)
	}
}

func TestSyncKernels_MockGitHubAndAssetFiltering(t *testing.T) {
	ctx := context.Background()
	var failShadow atomic.Bool

	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("User-Agent") != "snell-panel/1.0" {
			t.Errorf("unexpected GitHub headers: Accept=%q UA=%q", r.Header.Get("Accept"), r.Header.Get("User-Agent"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/SagerNet/sing-box/releases":
			_, _ = w.Write([]byte(`[
				{
					"tag_name": "v1.11.99-draft",
					"draft": true,
					"assets": [
						{"name": "sing-box-1.11.99-linux-amd64.tar.gz", "browser_download_url": "https://example.com/draft.tar.gz", "size": 100}
					]
				},
				{
					"tag_name": "v1.11.4",
					"draft": false,
					"published_at": "2026-11-01T00:00:00Z",
					"assets": [
						{"name": "sing-box-1.11.4-linux-amd64.tar.gz", "browser_download_url": "https://example.com/sb-amd64.tar.gz", "size": 1234, "digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
						{"name": "sing-box-1.11.4-linux-arm64.tar.gz", "browser_download_url": "https://example.com/sb-arm64.tar.gz", "size": 1235},
						{"name": "sing-box-1.11.4-linux-amd64.tar.gz.sha256", "browser_download_url": "https://example.com/sb.sha256"},
						{"name": "sing-box-1.11.4-linux-amd64.deb", "browser_download_url": "https://example.com/sb.deb"},
						{"name": "sing-box-1.11.4-linux-amd64.tar.xz", "browser_download_url": "https://example.com/sb.tar.xz"},
						{"name": "sing-box-1.11.4-windows-amd64.zip", "browser_download_url": "https://example.com/sb-win.zip"},
						{"name": "sing-box-1.11.4-darwin-arm64.tar.gz", "browser_download_url": "https://example.com/sb-mac.tar.gz"},
						{"name": "sing-box-1.11.4-linux-386.tar.gz", "browser_download_url": "https://example.com/sb-386.tar.gz"}
					]
				}
			]`))
		case "/repos/ihciah/shadow-tls/releases":
			if failShadow.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"message":"upstream unavailable"}`))
				return
			}
			_, _ = w.Write([]byte(`[
				{
					"tag_name": "v0.2.25",
					"draft": false,
					"assets": [
						{"name": "shadow-tls-x86_64-unknown-linux-musl", "browser_download_url": "https://example.com/stls-amd64", "size": 555},
						{"name": "shadow-tls-aarch64-unknown-linux-musl", "browser_download_url": "https://example.com/stls-arm64", "size": 666},
						{"name": "shadow-tls-x86_64-apple-darwin", "browser_download_url": "https://example.com/stls-mac", "size": 777},
						{"name": "shadow-tls-x86_64-unknown-linux-musl.sig", "browser_download_url": "https://example.com/stls.sig"}
					]
				}
			]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ghSrv.Close()

	st := openTestStore(t)
	clk := newFakeClock(time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC))
	sched := scheduler.NewScheduler(
		st,
		nil,
		nil,
		scheduler.WithNow(clk.Now),
		scheduler.WithGitHubAPIBaseURL(ghSrv.URL),
	)

	cat, err := sched.SyncKernels(ctx)
	if err != nil {
		t.Fatalf("SyncKernels: %v", err)
	}
	if len(cat.SingBox) != 1 || cat.SingBox[0].Version != "1.11.4" {
		t.Fatalf("expected 1 non-draft sing-box 1.11.4 release, got %+v", cat.SingBox)
	}
	sbAMD := cat.SingBox[0].Assets["amd64"]
	if sbAMD.DownloadURL != "https://example.com/sb-amd64.tar.gz" || sbAMD.SHA256 != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("unexpected sing-box amd64 asset: %+v", sbAMD)
	}
	if len(cat.ShadowTLS) != 1 || cat.ShadowTLS[0].Assets["arm64"].DownloadURL != "https://example.com/stls-arm64" {
		t.Fatalf("unexpected shadow-tls releases: %+v", cat.ShadowTLS)
	}

	// Failure atomicity: fail shadow-tls -> error returned AND existing cache preserved!
	failShadow.Store(true)
	if _, err := sched.SyncKernels(ctx); err == nil {
		t.Fatalf("expected SyncKernels error when shadow-tls returns 503")
	}
	cached, err := sched.ListKernels(ctx)
	if err != nil {
		t.Fatalf("ListKernels after failed sync: %v", err)
	}
	if len(cached.SingBox) != 1 || len(cached.ShadowTLS) != 1 {
		t.Fatalf("expected previous cache preserved after failed sync, got %+v", cached)
	}
}

func TestCustomSnellVersions_CRUDAndValidation(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	sched := scheduler.NewScheduler(st, nil, nil)

	// Invalid cases -> ErrInvalidArgument.
	invalidCases := []struct {
		name string
		ver  string
		urls map[string]string
	}{
		{name: "empty version", ver: "  ", urls: map[string]string{"amd64": "https://example.com/a.zip"}},
		{name: "control char", ver: "v5.0.1\n", urls: map[string]string{"amd64": "https://example.com/a.zip"}},
		{name: "built-in collision", ver: "v5.0.0", urls: map[string]string{"amd64": "https://example.com/a.zip"}},
		{name: "empty urls", ver: "v5.0.1", urls: map[string]string{}},
		{name: "invalid arch mips64", ver: "v5.0.1", urls: map[string]string{"mips64": "https://example.com/a.zip"}},
		{name: "bad scheme ftp", ver: "v5.0.1", urls: map[string]string{"amd64": "ftp://example.com/a.zip"}},
		{name: "empty host", ver: "v5.0.1", urls: map[string]string{"amd64": "https:///a.zip"}},
	}
	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := sched.AddCustomSnellVersion(ctx, tc.ver, tc.urls); !errors.Is(err, scheduler.ErrInvalidArgument) {
				t.Fatalf("expected ErrInvalidArgument for %s, got %v", tc.name, err)
			}
		})
	}

	// Valid add with linux/amd64 & linux/arm64 normalization.
	entry, err := sched.AddCustomSnellVersion(ctx, "v5.0.2-custom", map[string]string{
		"linux/amd64": "https://dl.example.com/snell-amd64.zip",
		"linux/arm64": "https://dl.example.com/snell-arm64.zip",
	})
	if err != nil {
		t.Fatalf("AddCustomSnellVersion: %v", err)
	}
	if entry.Major != protocol.SnellVersionV5 || entry.URLs["amd64"] == "" || entry.URLs["arm64"] == "" {
		t.Fatalf("unexpected normalized entry: %+v", entry)
	}

	list, err := sched.ListSnellVersions(ctx)
	if err != nil || len(list) != 3 {
		t.Fatalf("expected 3 snell versions (2 built-in + 1 custom), got len=%d err=%v", len(list), err)
	}

	// Cannot delete built-in or missing.
	if err := sched.DeleteCustomSnellVersion(ctx, "v4.1.1"); !errors.Is(err, scheduler.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument deleting built-in, got %v", err)
	}
	if err := sched.DeleteCustomSnellVersion(ctx, "v9.9.9"); !errors.Is(err, scheduler.ErrNotFound) {
		t.Fatalf("expected ErrNotFound deleting missing, got %v", err)
	}

	// Delete custom version succeeds.
	if err := sched.DeleteCustomSnellVersion(ctx, "v5.0.2-custom"); err != nil {
		t.Fatalf("DeleteCustomSnellVersion: %v", err)
	}
	listAfter, _ := sched.ListSnellVersions(ctx)
	if len(listAfter) != 2 {
		t.Fatalf("expected 2 built-in versions after delete, got %d", len(listAfter))
	}
}

func TestDispatchKernelUpdate_ValidationAndPartialOnlineOffline(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	h := hub.NewHub(st, nil)
	defer func() { _ = h.Close() }()
	sched := scheduler.NewScheduler(st, h, nil)

	// Validation errors.
	badReqs := []scheduler.KernelUpdateRequest{
		{NodeIDs: nil, Kernel: protocol.KernelSnellServer, Version: "v5.0.0"},
		{NodeIDs: []int64{1}, Kernel: "bad-kernel", Version: "1.0.0"},
		{NodeIDs: []int64{1}, Kernel: protocol.KernelSnellServer, Version: ""},
		{NodeIDs: []int64{1}, Kernel: protocol.KernelSnellServer, Version: "v5.0.0", DownloadURL: "ftp://bad"},
		{NodeIDs: []int64{1}, Kernel: protocol.KernelSnellServer, Version: "v5.0.0", SHA256: "deadbeef"},
	}
	for i, req := range badReqs {
		if _, err := sched.DispatchKernelUpdate(ctx, req); !errors.Is(err, scheduler.ErrInvalidArgument) {
			t.Fatalf("req[%d]: expected ErrInvalidArgument, got %v", i, err)
		}
	}

	// Setup 1 online arm64 node, 1 offline node, and 1 nonexistent node ID.
	nOnline, tokOnline := createTestNode(t, st, "online-arm64", true)
	nOffline, _ := createTestNode(t, st, "offline-node", true)

	conn, _ := dialAgent(t, h, tokOnline)
	_ = readEnvelope(t, conn, 3*time.Second) // initial config_sync
	sendEnvelope(t, conn, protocol.MsgTypeAgentHello, "h-arm64", protocol.AgentHello{
		OS:   "linux",
		Arch: "aarch64",
	})
	waitUntil(t, 2*time.Second, func() bool {
		tel, ok := h.GetTelemetry(nOnline.ID)
		return ok && tel.Arch == "aarch64"
	}, "hub recorded arm64 telemetry")

	// Dispatch built-in snell-server v5.0.0 without DownloadURL (auto-resolves arm64 URL!).
	batch, err := sched.DispatchKernelUpdate(ctx, scheduler.KernelUpdateRequest{
		NodeIDs: []int64{nOnline.ID, nOffline.ID, 99999, nOnline.ID},
		Kernel:  protocol.KernelSnellServer,
		Version: "v5.0.0",
	})
	if err != nil {
		t.Fatalf("DispatchKernelUpdate: %v", err)
	}
	if len(batch.Dispatched) != 1 || batch.Dispatched[0] != nOnline.ID {
		t.Fatalf("expected dispatched=[%d], got %+v", nOnline.ID, batch.Dispatched)
	}
	if len(batch.Failed) != 2 || len(batch.Results) != 3 {
		t.Fatalf("expected 2 failed and 3 total deduplicated results, got %+v", batch)
	}

	var sawOffline bool
	for _, r := range batch.Failed {
		if r.NodeID == nOffline.ID && r.Status == "offline" {
			sawOffline = true
		}
	}
	if !sawOffline {
		t.Fatalf("expected offline status for offline node, got %+v", batch.Failed)
	}

	env := readEnvelope(t, conn, 3*time.Second)
	if env.Type != protocol.MsgTypeServerKernelUpdate {
		t.Fatalf("expected server.kernel_update, got %s", env.Type)
	}
	var cmd protocol.ServerKernelUpdate
	if err := json.Unmarshal(env.Payload, &cmd); err != nil {
		t.Fatalf("unmarshal kernel_update: %v", err)
	}
	if cmd.Kernel != protocol.KernelSnellServer || !strings.Contains(cmd.DownloadURL, "linux-aarch64.zip") {
		t.Fatalf("expected resolved arm64 snell URL, got %+v", cmd)
	}
}

func TestSyncKernels_FiltersPrereleases(t *testing.T) {
	ctx := context.Background()
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/SagerNet/sing-box/releases":
			_, _ = w.Write([]byte(`[
				{
					"tag_name": "v1.12.0-alpha.1",
					"draft": false,
					"prerelease": true,
					"published_at": "2026-11-21T00:00:00Z",
					"assets": [
						{"name": "sing-box-1.12.0-alpha.1-linux-amd64.tar.gz", "browser_download_url": "https://example.com/sb-pre-amd64.tar.gz", "size": 100},
						{"name": "sing-box-1.12.0-alpha.1-linux-arm64.tar.gz", "browser_download_url": "https://example.com/sb-pre-arm64.tar.gz", "size": 100}
					]
				}
			]`))
		case "/repos/ihciah/shadow-tls/releases":
			_, _ = w.Write([]byte(`[
				{
					"tag_name": "v0.2.26-rc1",
					"draft": false,
					"prerelease": true,
					"published_at": "2026-11-21T00:00:00Z",
					"assets": [
						{"name": "shadow-tls-x86_64-unknown-linux-musl", "browser_download_url": "https://example.com/stls-pre-amd64", "size": 100},
						{"name": "shadow-tls-aarch64-unknown-linux-musl", "browser_download_url": "https://example.com/stls-pre-arm64", "size": 100}
					]
				}
			]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ghSrv.Close()

	st := openTestStore(t)
	sched := scheduler.NewScheduler(st, nil, nil, scheduler.WithGitHubAPIBaseURL(ghSrv.URL))

	cat, err := sched.SyncKernels(ctx)
	if err != nil {
		t.Fatalf("SyncKernels: %v", err)
	}
	if len(cat.SingBox) != 0 {
		t.Fatalf("expected sing-box prereleases excluded, got %+v", cat.SingBox)
	}
	if len(cat.ShadowTLS) != 0 {
		t.Fatalf("expected shadow-tls prereleases excluded, got %+v", cat.ShadowTLS)
	}
}

func TestSyncKernels_AMD64MicroArchDoesNotShadowStandardAMD64(t *testing.T) {
	ctx := context.Background()
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/SagerNet/sing-box/releases":
			_, _ = w.Write([]byte(`[
				{
					"tag_name": "v1.11.4",
					"draft": false,
					"prerelease": false,
					"published_at": "2026-11-20T00:00:00Z",
					"assets": [
						{"name": "sing-box-1.11.4-linux-amd64v3.tar.gz", "browser_download_url": "https://example.com/sb-amd64v3.tar.gz", "size": 111},
						{"name": "sing-box-1.11.4-linux-amd64-v3.tar.gz", "browser_download_url": "https://example.com/sb-amd64-v3.tar.gz", "size": 112},
						{"name": "sing-box-1.11.4-linux-amd64_v3.tar.gz", "browser_download_url": "https://example.com/sb-amd64_v3.tar.gz", "size": 113},
						{"name": "sing-box-1.11.4-linux-amd64v2.tar.gz", "browser_download_url": "https://example.com/sb-amd64v2.tar.gz", "size": 114},
						{"name": "sing-box-1.11.4-linux-x86_64_v3.tar.gz", "browser_download_url": "https://example.com/sb-x86_64_v3.tar.gz", "size": 115},
						{"name": "sing-box-1.11.4-linux-x86-64-v3.tar.gz", "browser_download_url": "https://example.com/sb-x86-64-v3.tar.gz", "size": 116},
						{"name": "sing-box-1.11.4-linux-amd64.tar.gz", "browser_download_url": "https://example.com/sb-amd64.tar.gz", "size": 120},
						{"name": "sing-box-1.11.4-linux-arm64.tar.gz", "browser_download_url": "https://example.com/sb-arm64.tar.gz", "size": 121}
					]
				},
				{
					"tag_name": "v1.11.3",
					"draft": false,
					"prerelease": false,
					"published_at": "2026-11-19T00:00:00Z",
					"assets": [
						{"name": "sing-box-1.11.3-linux-amd64v3.tar.gz", "browser_download_url": "https://example.com/sb-113-amd64v3.tar.gz", "size": 111},
						{"name": "sing-box-1.11.3-linux-arm64.tar.gz", "browser_download_url": "https://example.com/sb-113-arm64.tar.gz", "size": 121}
					]
				}
			]`))
		case "/repos/ihciah/shadow-tls/releases":
			_, _ = w.Write([]byte(`[]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ghSrv.Close()

	st := openTestStore(t)
	sched := scheduler.NewScheduler(st, nil, nil, scheduler.WithGitHubAPIBaseURL(ghSrv.URL))

	cat, err := sched.SyncKernels(ctx)
	if err != nil {
		t.Fatalf("SyncKernels: %v", err)
	}
	if len(cat.SingBox) != 2 {
		t.Fatalf("expected 2 sing-box releases, got %+v", cat.SingBox)
	}
	amdAsset, ok := cat.SingBox[0].Assets["amd64"]
	if !ok {
		t.Fatalf("expected amd64 asset for v1.11.4")
	}
	if amdAsset.Name != "sing-box-1.11.4-linux-amd64.tar.gz" || amdAsset.DownloadURL != "https://example.com/sb-amd64.tar.gz" {
		t.Fatalf("expected standard linux-amd64 asset, got %+v", amdAsset)
	}
	if badAsset, hasAMD64 := cat.SingBox[1].Assets["amd64"]; hasAMD64 {
		t.Fatalf("expected amd64v3-only release not to populate amd64 asset, got %+v", badAsset)
	}
}

func TestCustomSnellVersions_VPrefixCollisionAndDedup(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	sched := scheduler.NewScheduler(st, nil, nil)

	for _, builtInAlias := range []string{"5.0.0", "V5.0.0", "4.1.1", "V4.1.1"} {
		if _, err := sched.AddCustomSnellVersion(ctx, builtInAlias, map[string]string{
			"amd64": "https://example.com/custom.zip",
		}); !errors.Is(err, scheduler.ErrInvalidArgument) {
			t.Fatalf("AddCustomSnellVersion(%q): expected ErrInvalidArgument, got %v", builtInAlias, err)
		}
		if err := sched.DeleteCustomSnellVersion(ctx, builtInAlias); !errors.Is(err, scheduler.ErrInvalidArgument) {
			t.Fatalf("DeleteCustomSnellVersion(%q): expected ErrInvalidArgument, got %v", builtInAlias, err)
		}
	}

	if _, err := sched.AddCustomSnellVersion(ctx, "v", map[string]string{
		"amd64": "https://example.com/v.zip",
	}); !errors.Is(err, scheduler.ErrInvalidArgument) {
		t.Fatalf("AddCustomSnellVersion(\"v\"): expected ErrInvalidArgument, got %v", err)
	}

	// Add "v5.2.0", then update via "5.2.0" -> must deduplicate cleanly instead of keeping two entries.
	if _, err := sched.AddCustomSnellVersion(ctx, "v5.2.0", map[string]string{
		"amd64": "https://example.com/v5.2.0-first.zip",
	}); err != nil {
		t.Fatalf("AddCustomSnellVersion(v5.2.0): %v", err)
	}
	if _, err := sched.AddCustomSnellVersion(ctx, "5.2.0", map[string]string{
		"amd64": "https://example.com/v5.2.0-updated.zip",
	}); err != nil {
		t.Fatalf("AddCustomSnellVersion(5.2.0): %v", err)
	}

	list, err := sched.ListSnellVersions(ctx)
	if err != nil {
		t.Fatalf("ListSnellVersions: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 snell versions (2 built-in + 1 deduplicated custom), got %d: %+v", len(list), list)
	}
	if list[2].Version != "5.2.0" || list[2].URLs["amd64"] != "https://example.com/v5.2.0-updated.zip" {
		t.Fatalf("unexpected deduplicated custom entry: %+v", list[2])
	}

	// Delete using "v5.2.0" must match stored "5.2.0".
	if err := sched.DeleteCustomSnellVersion(ctx, "v5.2.0"); err != nil {
		t.Fatalf("DeleteCustomSnellVersion(v5.2.0): %v", err)
	}
	listAfter, err := sched.ListSnellVersions(ctx)
	if err != nil {
		t.Fatalf("ListSnellVersions after delete: %v", err)
	}
	if len(listAfter) != 2 {
		t.Fatalf("expected 2 built-in versions after delete, got %+v", listAfter)
	}
}
