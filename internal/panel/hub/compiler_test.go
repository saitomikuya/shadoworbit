package hub_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"snell-panel/internal/panel/auth"
	"snell-panel/internal/panel/hub"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/protocol"
)

func TestBuildConfigSync_PauseActionsAndDisabledNode(t *testing.T) {
	st := openTestStore(t)
	h := hub.NewHub(st, nil)
	t.Cleanup(func() { _ = h.Close() })
	ctx := context.Background()

	node, _ := createTestNode(t, st, "pause-node", true)

	// 1. Normal enabled state -> both Snell and SS enabled.
	cfg, err := h.BuildConfigSync(ctx, node.ID)
	if err != nil {
		t.Fatalf("BuildConfigSync normal: %v", err)
	}
	if !cfg.Snell.Enabled || !cfg.SS.Enabled {
		t.Fatalf("expected both Snell & SS enabled, got snell=%v ss=%v", cfg.Snell.Enabled, cfg.SS.Enabled)
	}
	if cfg.SS.Users == nil || len(cfg.SS.Users) != 0 {
		t.Fatalf("expected non-nil empty SS.Users, got %#v", cfg.SS.Users)
	}

	// 2. Traffic paused with stop_all -> disables both Snell & SS.
	if err := st.SetNodeTrafficPaused(ctx, node.ID, true, "limit reached"); err != nil {
		t.Fatal(err)
	}
	cfg, err = h.BuildConfigSync(ctx, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Snell.Enabled || cfg.SS.Enabled {
		t.Fatalf("expected stop_all to disable both Snell & SS, got snell=%v ss=%v", cfg.Snell.Enabled, cfg.SS.Enabled)
	}

	// 3. Traffic paused with stop_ss_only -> disables SS while keeping Snell enabled.
	dbNode, err := st.GetNodeByID(ctx, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	dbNode.ThresholdAction = protocol.ThresholdActionStopSSOnly
	if err := st.UpdateNode(ctx, dbNode); err != nil {
		t.Fatal(err)
	}
	cfg, err = h.BuildConfigSync(ctx, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Snell.Enabled || cfg.SS.Enabled {
		t.Fatalf("expected stop_ss_only to keep Snell enabled and disable SS, got snell=%v ss=%v", cfg.Snell.Enabled, cfg.SS.Enabled)
	}

	// 4. Disabled node (!Enabled) -> disables both regardless of ThresholdAction.
	dbNode.Enabled = false
	if err := st.UpdateNode(ctx, dbNode); err != nil {
		t.Fatal(err)
	}
	cfg, err = h.BuildConfigSync(ctx, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Snell.Enabled || cfg.SS.Enabled {
		t.Fatalf("expected disabled node to disable both Snell & SS, got snell=%v ss=%v", cfg.Snell.Enabled, cfg.SS.Enabled)
	}
}

func TestBuildConfigSync_UserFilteringAndCipherUPSK(t *testing.T) {
	st := openTestStore(t)
	clk := newFakeClock(time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC))
	h := hub.NewHub(st, nil, hub.WithNow(clk.Now))
	t.Cleanup(func() { _ = h.Close() })
	ctx := context.Background()

	node, _ := createTestNode(t, st, "users-node", true)

	uValid := createTestUser(t, st, "valid-user", true)
	uDisabled := createTestUser(t, st, "disabled-user", false)

	uExpired := createTestUser(t, st, "expired-user", true)
	past := clk.Now().Add(-time.Hour)
	uExpired.ExpireAt = &past
	if err := st.UpdateUser(ctx, uExpired); err != nil {
		t.Fatal(err)
	}

	uQuota := createTestUser(t, st, "quota-user", true)
	uQuota.TrafficQuotaBytes = 1000
	if err := st.UpdateUser(ctx, uQuota); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddUserTrafficDelta(ctx, uQuota.ID, 600, 400); err != nil {
		t.Fatal(err)
	}

	uBadKey := createTestUser(t, st, "badkey-user", true)
	if err := st.ResetUserKeys(ctx, uBadKey.ID, "not-valid-base64-key", "", "", ""); err != nil {
		t.Fatal(err)
	}

	uUnauth := createTestUser(t, st, "unauth-user", true)
	_ = uUnauth

	for _, u := range []*store.User{uValid, uDisabled, uExpired, uQuota, uBadKey} {
		if err := st.SetUserNodes(ctx, u.ID, []int64{node.ID}); err != nil {
			t.Fatal(err)
		}
	}

	// Cipher 2022-blake3-aes-128-gcm -> expects SSUPSK16.
	cfg16, err := h.BuildConfigSync(ctx, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg16.SS.Users) != 1 || cfg16.SS.Users[0].UserID != uValid.ID || cfg16.SS.Users[0].UPSK != uValid.SSUPSK16 {
		t.Fatalf("expected only uValid with 16B uPSK, got %+v", cfg16.SS.Users)
	}

	// Switch node cipher to 2022-blake3-aes-256-gcm -> expects SSUPSK32 (and uBadKey has valid SSUPSK32 so 2 users).
	dbNode, err := st.GetNodeByID(ctx, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	ipsk32, err := auth.GenerateIPSKForCipher(protocol.CipherAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	dbNode.SSConfig.Cipher = protocol.CipherAES256GCM
	dbNode.SSConfig.IPSK = ipsk32
	if err := st.UpdateNode(ctx, dbNode); err != nil {
		t.Fatal(err)
	}

	cfg32, err := h.BuildConfigSync(ctx, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg32.SS.Users) != 2 {
		t.Fatalf("expected 2 valid users for 256-gcm, got %+v", cfg32.SS.Users)
	}
	if cfg32.SS.Users[0].UPSK != uValid.SSUPSK32 {
		t.Fatalf("expected 32B uPSK %q, got %q", uValid.SSUPSK32, cfg32.SS.Users[0].UPSK)
	}
}

func TestBuildConfigSync_DNSGroupExtraRulesAndSettings(t *testing.T) {
	st := openTestStore(t)
	h := hub.NewHub(st, nil)
	t.Cleanup(func() { _ = h.Close() })
	ctx := context.Background()

	if err := st.SetSetting(ctx, "default_upstream_dns", "8.8.8.8:5353"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting(ctx, "default_local_dns_port", "15555"); err != nil {
		t.Fatal(err)
	}

	grp := &store.DNSRuleGroup{
		Name: "streaming",
		Rules: []string{
			"netflix.com",
			"*.netflix.com\n# comment inside multiline\n^disneyplus.com\r",
		},
	}
	if err := st.CreateDNSRuleGroup(ctx, grp); err != nil {
		t.Fatal(err)
	}

	node, _ := createTestNode(t, st, "dns-node", true)
	dbNode, err := st.GetNodeByID(ctx, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	dbNode.DNSUnlockEnabled = true
	dbNode.DNSUnlockServer = "10.0.0.53:53"
	dbNode.DNSRuleGroupID = &grp.ID
	dbNode.DNSExtraRules = []string{
		"  Netflix.com  ", // case-insensitive duplicate of group rule
		"// line comment",
		"",
		"hulu.com\r\n*.hulu.com",
	}
	if err := st.UpdateNode(ctx, dbNode); err != nil {
		t.Fatal(err)
	}

	cfg, err := h.BuildConfigSync(ctx, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DNS.UnlockEnabled || cfg.DNS.UnlockServer != "10.0.0.53:53" {
		t.Fatalf("unexpected DNS unlock fields: %+v", cfg.DNS)
	}
	if cfg.DNS.UpstreamDNS != "8.8.8.8:5353" || cfg.DNS.LocalPort != 15555 {
		t.Fatalf("unexpected DNS settings: upstream=%q port=%d", cfg.DNS.UpstreamDNS, cfg.DNS.LocalPort)
	}
	wantRules := []string{"netflix.com", "*.netflix.com", "^disneyplus.com", "hulu.com", "*.hulu.com"}
	if len(cfg.DNS.Rules) != len(wantRules) {
		t.Fatalf("expected rules %v, got %v", wantRules, cfg.DNS.Rules)
	}
	for i := range wantRules {
		if cfg.DNS.Rules[i] != wantRules[i] {
			t.Fatalf("rule[%d]: want %q, got %q (all=%v)", i, wantRules[i], cfg.DNS.Rules[i], cfg.DNS.Rules)
		}
	}

	// Deleted DNS group -> falls back gracefully to extra rules (or non-nil empty slice).
	if err := st.DeleteDNSRuleGroup(ctx, grp.ID); err != nil {
		t.Fatal(err)
	}
	cfgAfterDel, err := h.BuildConfigSync(ctx, node.ID)
	if err != nil {
		t.Fatalf("BuildConfigSync after group delete: %v", err)
	}
	if len(cfgAfterDel.DNS.Rules) != 3 {
		t.Fatalf("expected 3 extra rules after group delete, got %v", cfgAfterDel.DNS.Rules)
	}
}

func TestCommandDispatch(t *testing.T) {
	st := openTestStore(t)
	h := hub.NewHub(st, nil, hub.WithPublicDebounce(10*time.Millisecond))
	t.Cleanup(func() { _ = h.Close() })
	srv := newTestServer(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nOnline, tokOnline := createTestNode(t, st, "cmd-online", true)
	nOffline, _ := createTestNode(t, st, "cmd-offline", true)
	u := createTestUser(t, st, "cmd-user", true)
	if err := st.SetUserNodes(ctx, u.ID, []int64{nOnline.ID, nOffline.ID}); err != nil {
		t.Fatal(err)
	}

	// Offline checks before connect.
	if err := h.SyncNode(ctx, nOffline.ID); !errors.Is(err, hub.ErrNodeOffline) {
		t.Fatalf("expected ErrNodeOffline on offline SyncNode, got %v", err)
	}
	if err := h.SyncNode(ctx, 999999); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected store.ErrNotFound for missing node, got %v", err)
	}
	if err := h.SendKernelUpdate(ctx, nOffline.ID, protocol.ServerKernelUpdate{
		Kernel: protocol.KernelSingBox, Version: "1.12.0", DownloadURL: "https://example.com/sb.tar.gz",
	}); !errors.Is(err, hub.ErrNodeOffline) {
		t.Fatalf("expected ErrNodeOffline on SendKernelUpdate, got %v", err)
	}
	if err := h.SendServiceCtl(ctx, nOffline.ID, protocol.ServerServiceCtl{
		Action: protocol.ServiceActionRestartAll,
	}); !errors.Is(err, hub.ErrNodeOffline) {
		t.Fatalf("expected ErrNodeOffline on SendServiceCtl, got %v", err)
	}

	// Invalid commands -> ErrInvalidCommand.
	if err := h.SendKernelUpdate(ctx, nOnline.ID, protocol.ServerKernelUpdate{
		Kernel: "bad-kernel", Version: "1.0", DownloadURL: "https://example.com/x",
	}); !errors.Is(err, hub.ErrInvalidCommand) {
		t.Fatalf("expected ErrInvalidCommand for bad kernel, got %v", err)
	}
	if err := h.SendKernelUpdate(ctx, nOnline.ID, protocol.ServerKernelUpdate{
		Kernel: protocol.KernelSingBox, Version: "1.0", DownloadURL: "ftp://example.com/x",
	}); !errors.Is(err, hub.ErrInvalidCommand) {
		t.Fatalf("expected ErrInvalidCommand for bad scheme, got %v", err)
	}
	if err := h.SendKernelUpdate(ctx, nOnline.ID, protocol.ServerKernelUpdate{
		Kernel: protocol.KernelSingBox, Version: "1.0", DownloadURL: "https://example.com/x", SHA256: "short",
	}); !errors.Is(err, hub.ErrInvalidCommand) {
		t.Fatalf("expected ErrInvalidCommand for bad sha256, got %v", err)
	}
	if err := h.SendServiceCtl(ctx, nOnline.ID, protocol.ServerServiceCtl{Action: "drop_db"}); !errors.Is(err, hub.ErrInvalidCommand) {
		t.Fatalf("expected ErrInvalidCommand for bad service action, got %v", err)
	}

	// Connect nOnline.
	c, _, err := dialAgentWS(ctx, srv.URL, tokOnline)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	_ = readEnvelope(t, c, 3*time.Second) // initial config_sync

	// SyncNodesForUser & SyncAll ignore offline node and push to nOnline.
	if err := h.SyncNodesForUser(ctx, u.ID); err != nil {
		t.Fatalf("SyncNodesForUser: %v", err)
	}
	if env := readEnvelope(t, c, 3*time.Second); env.Type != protocol.MsgTypeServerConfigSync {
		t.Fatalf("expected server.config_sync from SyncNodesForUser, got %q", env.Type)
	}

	if err := h.SyncAll(ctx); err != nil {
		t.Fatalf("SyncAll: %v", err)
	}
	if env := readEnvelope(t, c, 3*time.Second); env.Type != protocol.MsgTypeServerConfigSync {
		t.Fatalf("expected server.config_sync from SyncAll, got %q", env.Type)
	}

	// SendKernelUpdate -> agent receives server.kernel_update.
	if err := h.SendKernelUpdate(ctx, nOnline.ID, protocol.ServerKernelUpdate{
		Kernel:      protocol.KernelShadowTLS,
		Version:     "0.2.26",
		DownloadURL: "https://example.com/shadow-tls",
		SHA256:      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}); err != nil {
		t.Fatalf("SendKernelUpdate: %v", err)
	}
	kuEnv := readEnvelope(t, c, 3*time.Second)
	if kuEnv.Type != protocol.MsgTypeServerKernelUpdate {
		t.Fatalf("expected server.kernel_update, got %q", kuEnv.Type)
	}
	var kuPayload protocol.ServerKernelUpdate
	if err := kuEnv.DecodePayload(&kuPayload); err != nil || kuPayload.Version != "0.2.26" {
		t.Fatalf("unexpected kernel update payload: %+v err=%v", kuPayload, err)
	}

	// SendServiceCtl -> agent receives server.service_ctl.
	if err := h.SendServiceCtl(ctx, nOnline.ID, protocol.ServerServiceCtl{
		Action: protocol.ServiceActionRestartSnell,
	}); err != nil {
		t.Fatalf("SendServiceCtl: %v", err)
	}
	scEnv := readEnvelope(t, c, 3*time.Second)
	if scEnv.Type != protocol.MsgTypeServerServiceCtl {
		t.Fatalf("expected server.service_ctl, got %q", scEnv.Type)
	}
	var scPayload protocol.ServerServiceCtl
	if err := scEnv.DecodePayload(&scPayload); err != nil || scPayload.Action != protocol.ServiceActionRestartSnell {
		t.Fatalf("unexpected service_ctl payload: %+v err=%v", scPayload, err)
	}

	// Closed hub returns ErrHubClosed across command methods.
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.SyncNode(ctx, nOnline.ID); !errors.Is(err, hub.ErrHubClosed) {
		t.Fatalf("expected ErrHubClosed, got %v", err)
	}
	if err := h.SyncNodesForUser(ctx, u.ID); !errors.Is(err, hub.ErrHubClosed) {
		t.Fatalf("expected ErrHubClosed, got %v", err)
	}
	if err := h.SyncAll(ctx); !errors.Is(err, hub.ErrHubClosed) {
		t.Fatalf("expected ErrHubClosed, got %v", err)
	}
	if err := h.SendKernelUpdate(ctx, nOnline.ID, protocol.ServerKernelUpdate{
		Kernel: protocol.KernelSingBox, Version: "1.12.0", DownloadURL: "https://example.com/sb",
	}); !errors.Is(err, hub.ErrHubClosed) {
		t.Fatalf("expected ErrHubClosed, got %v", err)
	}
	if err := h.SendServiceCtl(ctx, nOnline.ID, protocol.ServerServiceCtl{Action: protocol.ServiceActionRestartAll}); !errors.Is(err, hub.ErrHubClosed) {
		t.Fatalf("expected ErrHubClosed, got %v", err)
	}
}
