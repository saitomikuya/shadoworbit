//go:build e2e

package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func f15_boolPtr(v bool) *bool { return &v }

func f15_assertExactPublicSchema(t *testing.T, raw []byte) {
	t.Helper()
	var top map[string]any
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("unmarshal public snapshot: %v (raw=%s)", err, string(raw))
	}
	wantTop := []string{"site_title", "announcement", "percentage_only", "nodes"}
	if len(top) != len(wantTop) {
		t.Fatalf("PublicStatusSnapshot must have exactly %d keys (%v), got %d keys: %v", len(wantTop), wantTop, len(top), top)
	}
	for _, k := range wantTop {
		if _, ok := top[k]; !ok {
			t.Fatalf("PublicStatusSnapshot missing key %q in %s", k, string(raw))
		}
	}

	nodesAny, ok := top["nodes"].([]any)
	if !ok {
		t.Fatalf("PublicStatusSnapshot.nodes must be a JSON array, got %T (%s)", top["nodes"], string(raw))
	}
	wantNode := []string{
		"id", "name", "region_tag", "sort_order", "status", "paused_reason",
		"billing_reset_day", "cpu_percent", "mem_used_bytes", "mem_total_bytes",
		"uptime_seconds", "rx_bps", "tx_bps", "traffic_used_bytes",
		"traffic_limit_bytes", "traffic_percent", "percentage_only",
		"core_a_healthy", "core_b_healthy",
	}
	for i, elem := range nodesAny {
		m, ok := elem.(map[string]any)
		if !ok {
			t.Fatalf("nodes[%d] must be JSON object, got %T", i, elem)
		}
		if len(m) != len(wantNode) {
			t.Fatalf("PublicNodeView[%d] must have exactly %d keys (%v), got %d keys: %v", i, len(wantNode), wantNode, len(m), m)
		}
		for _, k := range wantNode {
			if _, ok := m[k]; !ok {
				t.Fatalf("PublicNodeView[%d] missing key %q in %v", i, k, m)
			}
		}
	}
}

func f15_assertNoForbiddenKeys(t *testing.T, v any, path string) {
	t.Helper()
	forbidden := map[string]bool{
		"public_ip": true, "public_ipv4": true, "public_ipv6": true,
		"custom_entry_host": true, "custom_entry_port": true,
		"snell_config": true, "ss_config": true,
		"dns_unlock_server": true, "dns_extra_rules": true,
		"token": true, "token_hash": true, "node_token": true,
		"psk": true, "ipsk": true, "upsk": true, "ss_upsk_16": true, "ss_upsk_32": true,
		"stls_password": true, "stls_sni": true, "sub_token": true, "admin_sub_token": true,
		"username": true, "users": true, "password": true, "secret": true,
	}
	switch val := v.(type) {
	case map[string]any:
		for k, child := range val {
			if forbidden[strings.ToLower(k)] {
				t.Fatalf("forbidden key %q found at %s.%s", k, path, k)
			}
			f15_assertNoForbiddenKeys(t, child, path+"."+k)
		}
	case []any:
		for i, child := range val {
			f15_assertNoForbiddenKeys(t, child, fmt.Sprintf("%s[%d]", path, i))
		}
	}
}

func f15_dialAgentHelloAndSync(t *testing.T, ctx context.Context, client *PanelClient, nodeToken string) *websocket.Conn {
	t.Helper()
	conn, wsSt, err := client.DialAgentWS(ctx, nodeToken)
	if err != nil {
		t.Fatalf("DialAgentWS failed (http=%d): %v", wsSt, err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })
	if err := SendWSEnvelope(ctx, conn, "agent.hello", "f15-hello", AgentHelloPayload{
		OS:         "linux",
		Arch:       "amd64",
		PublicIPv4: "198.51.100.202",
		PublicIPv6: "2001:db8:cafe::202",
		Versions:   AgentVersionsDTO{SingBox: "1.11.4", SnellServer: "5.0.0", ShadowTLS: "0.2.25"},
	}); err != nil {
		t.Fatalf("send agent.hello: %v", err)
	}
	_, _, err = ReadWSEnvelope(ctx, conn, 5*time.Second)
	if err != nil {
		t.Fatalf("read initial server.config_sync: %v", err)
	}
	return conn
}

func TestF15_Tier1_PublicStatusExactSchemaAndUnauthenticatedAccess(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	stN, node, rawN, err := client.CreateNode(jwt, CreateNodeReq{
		Name:      "Tokyo-01",
		RegionTag: "JP",
		SortOrder: 1,
		Enabled:   f15_boolPtr(true),
	})
	if err != nil || (stN != http.StatusOK && stN != http.StatusCreated) {
		t.Fatalf("CreateNode failed: st=%d err=%v body=%s", stN, err, string(rawN))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := f15_dialAgentHelloAndSync(t, ctx, client, node.EffectiveToken())
	if err := SendWSEnvelope(ctx, conn, "agent.metrics", "m1", AgentMetricsPayload{
		TS:            time.Now().Unix(),
		CPUPercent:    24.5,
		MemUsedBytes:  1024 * 1024 * 512,
		MemTotalBytes: 1024 * 1024 * 2048,
		UptimeSeconds: 7200,
		RxBPS:         102400,
		TxBPS:         204800,
		Health:        AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatalf("send agent.metrics: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	var lastRaw []byte
	for time.Now().Before(deadline) {
		st, _, raw, err := client.DoRaw(ctx, http.MethodGet, "/api/v1/public/status", nil, nil)
		if err == nil && st == http.StatusOK {
			lastRaw = raw
			var snap PublicStatusSnapshotDTO
			if json.Unmarshal(raw, &snap) == nil && len(snap.Nodes) == 1 &&
				snap.Nodes[0].Status == "online" && snap.Nodes[0].CPUPercent == 24.5 &&
				snap.Nodes[0].CoreAHealthy && snap.Nodes[0].CoreBHealthy {
				f15_assertExactPublicSchema(t, raw)
				if snap.Nodes[0].Name != "Tokyo-01" || snap.Nodes[0].RegionTag != "JP" || snap.Nodes[0].CPUPercent != 24.5 {
					t.Fatalf("unexpected public node fields: %+v", snap.Nodes[0])
				}
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("node did not reach online state on unauthenticated GET /api/v1/public/status; last=%s", string(lastRaw))
}

func TestF15_Tier1_PublicWSStreamsLiveRedactedUpdates(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:      "Singapore-WS",
		RegionTag: "SG",
		Enabled:   f15_boolPtr(true),
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	pubWS, wsSt, err := client.DialPublicWS(ctx)
	if err != nil {
		t.Fatalf("DialPublicWS failed (http=%d): %v", wsSt, err)
	}
	defer pubWS.CloseNow()

	agentWS := f15_dialAgentHelloAndSync(t, ctx, client, node.EffectiveToken())
	if err := SendWSEnvelope(ctx, agentWS, "agent.metrics", "ws-m1", AgentMetricsPayload{
		TS:         time.Now().Unix(),
		CPUPercent: 42.5,
		RxBPS:      123456,
		TxBPS:      654321,
		Health:     AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}

	rctx, rcancel := context.WithTimeout(ctx, 8*time.Second)
	defer rcancel()
	for {
		_, frame, err := pubWS.Read(rctx)
		if err != nil {
			t.Fatalf("read public WS frame before live updated metrics: %v", err)
		}
		f15_assertExactPublicSchema(t, frame)
		var snap PublicStatusSnapshotDTO
		if err := json.Unmarshal(frame, &snap); err != nil {
			t.Fatalf("decode public WS frame: %v (frame=%s)", err, string(frame))
		}
		if len(snap.Nodes) == 1 &&
			snap.Nodes[0].Status == "online" && snap.Nodes[0].CPUPercent == 42.5 &&
			snap.Nodes[0].RxBPS == 123456 && snap.Nodes[0].TxBPS == 654321 {
			return
		}
	}
}

func TestF15_Tier1_PercentageOnlyModeHidesRawTrafficBytes(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:              "PctOnly-Node",
		Enabled:           f15_boolPtr(true),
		TrafficLimitBytes: 1_000_000,
		TrafficCountMode:  "both",
	})
	if err != nil {
		t.Fatal(err)
	}
	st, raw, err := client.CalibrateNodeTraffic(jwt, node.ID, 150_000, 100_000) // 250_000 / 1_000_000 = 25%
	if err != nil || st >= 300 {
		t.Fatalf("CalibrateNodeTraffic failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	st, raw, err = client.UpdateSettings(jwt, map[string]any{"percentage_only": true})
	if err != nil || st >= 300 {
		t.Fatalf("UpdateSettings percentage_only=true failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	st, snap, restRaw, err := client.GetPublicStatus()
	if err != nil || st != http.StatusOK || len(snap.Nodes) != 1 {
		t.Fatalf("GetPublicStatus failed: st=%d err=%v body=%s", st, err, string(restRaw))
	}
	if !snap.PercentageOnly || !snap.Nodes[0].PercentageOnly {
		t.Fatalf("expected percentage_only=true on snapshot and node, got snap=%v node=%v", snap.PercentageOnly, snap.Nodes[0].PercentageOnly)
	}
	if snap.Nodes[0].TrafficPercent < 24.9 || snap.Nodes[0].TrafficPercent > 25.1 {
		t.Fatalf("expected traffic_percent ~25.0, got %v", snap.Nodes[0].TrafficPercent)
	}
	if snap.Nodes[0].TrafficUsedBytes != 0 || snap.Nodes[0].TrafficLimitBytes != 0 {
		t.Fatalf("percentage_only=true must hide/zero raw traffic bytes, got used=%d limit=%d", snap.Nodes[0].TrafficUsedBytes, snap.Nodes[0].TrafficLimitBytes)
	}

	// Verify /api/v1/public/ws also applies percentage_only redaction
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pubWS, _, err := client.DialPublicWS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer pubWS.CloseNow()
	_, wsFrame, err := pubWS.Read(ctx)
	if err != nil {
		t.Fatalf("read public WS frame: %v", err)
	}
	var wsSnap PublicStatusSnapshotDTO
	if err := json.Unmarshal(wsFrame, &wsSnap); err != nil {
		t.Fatal(err)
	}
	if len(wsSnap.Nodes) != 1 || wsSnap.Nodes[0].TrafficUsedBytes != 0 || wsSnap.Nodes[0].TrafficLimitBytes != 0 || wsSnap.Nodes[0].TrafficPercent < 24.9 {
		t.Fatalf("public WS percentage_only mismatch: %+v", wsSnap)
	}

	// Turning percentage_only=false restores exact byte counts
	st, raw, err = client.UpdateSettings(jwt, map[string]any{"percentage_only": false})
	if err != nil || st < 200 || st >= 300 {
		t.Fatalf("UpdateSettings percentage_only=false failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	st, fullSnap, raw, err := client.GetPublicStatus()
	if err != nil || st != http.StatusOK || len(fullSnap.Nodes) != 1 {
		t.Fatalf("GetPublicStatus after percentage_only=false failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	if fullSnap.PercentageOnly || fullSnap.Nodes[0].TrafficUsedBytes != 250_000 || fullSnap.Nodes[0].TrafficLimitBytes != 1_000_000 {
		t.Fatalf("expected raw traffic bytes restored when percentage_only=false, got %+v", fullSnap.Nodes[0])
	}
}

func TestF15_Tier1_CoreAAndCoreBHealthDerivation(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{Name: "HealthMatrix", Enabled: f15_boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn := f15_dialAgentHelloAndSync(t, ctx, client, node.EffectiveToken())

	matrix := []struct {
		name      string
		health    AgentHealthDTO
		wantCoreA bool
		wantCoreB bool
	}{
		{"all_healthy", AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true}, true, true},
		{"shadowtls_down", AgentHealthDTO{Snell: true, ShadowTLS: false, SingBox: true}, false, true},
		{"snell_down", AgentHealthDTO{Snell: false, ShadowTLS: true, SingBox: true}, false, true},
		{"singbox_down", AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: false}, true, false},
		{"all_down", AgentHealthDTO{Snell: false, ShadowTLS: false, SingBox: false}, false, false},
	}

	for i, tc := range matrix {
		if err := SendWSEnvelope(ctx, conn, "agent.metrics", fmt.Sprintf("hm-%d", i), AgentMetricsPayload{
			TS:     time.Now().Unix() + int64(i),
			Health: tc.health,
		}); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(4 * time.Second)
		matched := false
		for time.Now().Before(deadline) {
			_, snap, _, err := client.GetPublicStatus()
			if err == nil && len(snap.Nodes) == 1 &&
				snap.Nodes[0].CoreAHealthy == tc.wantCoreA &&
				snap.Nodes[0].CoreBHealthy == tc.wantCoreB {
				matched = true
				break
			}
			time.Sleep(40 * time.Millisecond)
		}
		if !matched {
			_, snap, _, _ := client.GetPublicStatus()
			t.Fatalf("%s: expected CoreA=%v CoreB=%v, got %+v", tc.name, tc.wantCoreA, tc.wantCoreB, snap.Nodes)
		}
	}
}

func TestF15_Tier1_SortOrderSiteTitleAndAnnouncement(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	stSet, rawSet, err := client.UpdateSettings(jwt, map[string]any{
		"site_title":   "Family Node Radar",
		"announcement": "US node upgraded to 10Gbps",
	})
	if err != nil || stSet < 200 || stSet >= 300 {
		t.Fatalf("UpdateSettings failed: st=%d err=%v body=%s", stSet, err, string(rawSet))
	}

	stA, nA, rawA, err := client.CreateNode(jwt, CreateNodeReq{Name: "Node-A", SortOrder: 30, Enabled: f15_boolPtr(true)})
	if err != nil || (stA != http.StatusOK && stA != http.StatusCreated) {
		t.Fatalf("CreateNode A failed: st=%d err=%v body=%s", stA, err, string(rawA))
	}
	stB, nB, rawB, err := client.CreateNode(jwt, CreateNodeReq{Name: "Node-B", SortOrder: 10, Enabled: f15_boolPtr(true)})
	if err != nil || (stB != http.StatusOK && stB != http.StatusCreated) {
		t.Fatalf("CreateNode B failed: st=%d err=%v body=%s", stB, err, string(rawB))
	}
	stC, nC, rawC, err := client.CreateNode(jwt, CreateNodeReq{Name: "Node-C", SortOrder: 20, Enabled: f15_boolPtr(true)})
	if err != nil || (stC != http.StatusOK && stC != http.StatusCreated) {
		t.Fatalf("CreateNode C failed: st=%d err=%v body=%s", stC, err, string(rawC))
	}

	st, snap, raw, err := client.GetPublicStatus()
	if err != nil || st != http.StatusOK {
		t.Fatalf("GetPublicStatus failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	if snap.SiteTitle != "Family Node Radar" || snap.Announcement != "US node upgraded to 10Gbps" {
		t.Fatalf("unexpected site_title/announcement: %+v", snap)
	}
	if len(snap.Nodes) != 3 || snap.Nodes[0].ID != nB.ID || snap.Nodes[1].ID != nC.ID || snap.Nodes[2].ID != nA.ID {
		t.Fatalf("expected sort_order [B,C,A], got %+v", snap.Nodes)
	}

	st, raw, err = client.ReorderNodes(jwt, []int64{nA.ID, nB.ID, nC.ID})
	if err != nil || st >= 300 {
		t.Fatalf("ReorderNodes failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	st2, snap2, raw2, err := client.GetPublicStatus()
	if err != nil || st2 != http.StatusOK {
		t.Fatalf("GetPublicStatus after reorder failed: st=%d err=%v body=%s", st2, err, string(raw2))
	}
	if len(snap2.Nodes) != 3 || snap2.Nodes[0].ID != nA.ID || snap2.Nodes[1].ID != nB.ID || snap2.Nodes[2].ID != nC.ID {
		t.Fatalf("expected reordered [A,B,C], got %+v", snap2.Nodes)
	}
}

func TestF15_Tier2_ZeroLeakCanariesAllSensitiveFieldsRESTAndWS(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	stSet, settings, setRaw, err := client.GetSettings(jwt)
	if err != nil || stSet != http.StatusOK || settings.AdminSubToken == "" {
		t.Fatalf("GetSettings failed: st=%d err=%v token=%q body=%s", stSet, err, settings.AdminSubToken, string(setRaw))
	}

	stN, node, rawN, err := client.CreateNode(jwt, CreateNodeReq{
		Name:            "PublicSafeNode",
		RegionTag:       "HK",
		PublicIP:        "198.51.100.201",
		CustomEntryHost: "canary-f15-entry.secret.example",
		CustomEntryPort: 54321,
		Enabled:         f15_boolPtr(true),
		SnellConfig: &SnellConfigDTO{
			Enabled:      true,
			Version:      "v5",
			PublicPort:   54322,
			InnerPort:    31999,
			PSK:          "CANARY_F15_SNELL_PSK",
			Obfs:         "tls",
			STLSPassword: "CANARY_F15_SN_STLS",
			STLSSNI:      "canary-snell-sni.internal",
		},
		SSConfig: &SSConfigDTO{
			Enabled: true,
			TCPPort: 54323,
			UDPPort: 54324,
			Cipher:  "2022-blake3-aes-256-gcm",
			IPSK:    "Q0FOQVJZX0YxNV9TU19JUFNLXzMyQllURVNfMDAwMDE=",
			STLSSNI: "canary-ss-sni.internal",
		},
		DNSUnlockEnabled: true,
		DNSUnlockServer:  "198.51.100.203:3535",
		ExtraDNSRules:    []string{"canary-unlock-domain.secret"},
	})
	if err != nil || (stN != http.StatusOK && stN != http.StatusCreated) {
		t.Fatalf("CreateNode failed: st=%d err=%v body=%s", stN, err, string(rawN))
	}

	stU, user, rawU, err := client.CreateUser(jwt, CreateUserReq{
		Username: "canary_f15_user",
		NodeIDs:  []int64{node.ID},
	})
	if err != nil || (stU != http.StatusOK && stU != http.StatusCreated) {
		t.Fatalf("CreateUser failed: st=%d err=%v body=%s", stU, err, string(rawU))
	}
	if node.EffectiveToken() == "" || user.SubToken == "" || user.SSUPSK16 == "" || user.SSUPSK32 == "" || user.STLSPassword == "" {
		t.Fatalf("expected non-empty canary secrets on node/user")
	}

	canaries := []string{
		"198.51.100.201",
		"198.51.100.202",
		"2001:db8:cafe::202",
		"canary-f15-entry.secret.example",
		"54321",
		"54322",
		"31999",
		"54323",
		"54324",
		"CANARY_F15_SNELL_PSK",
		"CANARY_F15_SN_STLS",
		"canary-snell-sni.internal",
		"Q0FOQVJZX0YxNV9TU19JUFNLXzMyQllURVNfMDAwMDE=",
		"canary-ss-sni.internal",
		"198.51.100.203:3535",
		"canary-unlock-domain.secret",
		node.EffectiveToken(),
		"canary_f15_user",
		user.SubToken,
		user.SSUPSK16,
		user.SSUPSK32,
		user.STLSPassword,
		settings.AdminSubToken,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pubWS, _, err := client.DialPublicWS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer pubWS.CloseNow()

	agentWS := f15_dialAgentHelloAndSync(t, ctx, client, node.EffectiveToken())
	if err := SendWSEnvelope(ctx, agentWS, "agent.metrics", "m-leak", AgentMetricsPayload{
		TS: time.Now().Unix(), Health: AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatalf("send agent.metrics: %v", err)
	}

	// Poll until node is online in REST (fail if not reached)
	deadline := time.Now().Add(4 * time.Second)
	var restRaw []byte
	var lastRestRaw []byte
	for time.Now().Before(deadline) {
		st, snap, raw, err := client.GetPublicStatus()
		if err == nil && st == http.StatusOK {
			lastRestRaw = raw
			if len(snap.Nodes) == 1 && snap.Nodes[0].Status == "online" {
				restRaw = raw
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
	}
	if len(restRaw) == 0 {
		t.Fatalf("node did not reach online state in /api/v1/public/status within 4s; last=%s", string(lastRestRaw))
	}

	var restParsed any
	if err := json.Unmarshal(restRaw, &restParsed); err != nil {
		t.Fatal(err)
	}
	f15_assertExactPublicSchema(t, restRaw)
	f15_assertNoForbiddenKeys(t, restParsed, "rest_status")
	for _, secret := range canaries {
		if secret != "" && strings.Contains(string(restRaw), secret) {
			t.Fatalf("CANARY SECRET LEAK in /api/v1/public/status: %q (body=%s)", secret, string(restRaw))
		}
	}

	// Scan EVERY WS frame (initial snapshot + live broadcasts) until node reaches online
	rctx, rcancel := context.WithTimeout(ctx, 8*time.Second)
	defer rcancel()
	for {
		_, wsRaw, err := pubWS.Read(rctx)
		if err != nil {
			t.Fatalf("read public WS frame before node online: %v", err)
		}
		var wsParsed any
		if err := json.Unmarshal(wsRaw, &wsParsed); err != nil {
			t.Fatal(err)
		}
		f15_assertExactPublicSchema(t, wsRaw)
		f15_assertNoForbiddenKeys(t, wsParsed, "public_ws")
		for _, secret := range canaries {
			if secret != "" && strings.Contains(string(wsRaw), secret) {
				t.Fatalf("CANARY SECRET LEAK in /api/v1/public/ws: %q (frame=%s)", secret, string(wsRaw))
			}
		}
		var snap PublicStatusSnapshotDTO
		if err := json.Unmarshal(wsRaw, &snap); err == nil && len(snap.Nodes) == 1 && snap.Nodes[0].Status == "online" {
			return
		}
	}
}

func TestF15_Tier2_DisabledNodeHiddenFromPublicStatus(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	stEn, enabledNode, rawEn, err := client.CreateNode(jwt, CreateNodeReq{Name: "Visible-Enabled-Node", Enabled: f15_boolPtr(true)})
	if err != nil || (stEn != http.StatusOK && stEn != http.StatusCreated) {
		t.Fatalf("CreateNode enabled failed: st=%d err=%v body=%s", stEn, err, string(rawEn))
	}
	stDis, disabledNode, rawDis, err := client.CreateNode(jwt, CreateNodeReq{Name: "Hidden-Disabled-Node", Enabled: f15_boolPtr(false)})
	if err != nil || (stDis != http.StatusOK && stDis != http.StatusCreated) {
		t.Fatalf("CreateNode disabled failed: st=%d err=%v body=%s", stDis, err, string(rawDis))
	}

	st, snap, raw, err := client.GetPublicStatus()
	if err != nil || st != http.StatusOK {
		t.Fatalf("GetPublicStatus failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	var foundEnabled bool
	for _, n := range snap.Nodes {
		if n.ID == disabledNode.ID || n.Name == "Hidden-Disabled-Node" {
			t.Fatalf("disabled node must not be exposed on public status, got %+v", n)
		}
		if n.ID == enabledNode.ID {
			foundEnabled = true
		}
	}
	if !foundEnabled {
		t.Fatalf("expected enabled node %d in public status, got %+v", enabledNode.ID, snap.Nodes)
	}
}

func TestF15_Tier2_TrafficPausedAndPausedReasonDisplay(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	stN, node, rawN, err := client.CreateNode(jwt, CreateNodeReq{
		Name:                  "F15 Paused Node",
		Enabled:               f15_boolPtr(true),
		TrafficLimitBytes:     20000,
		TrafficThresholdBytes: 10000,
		TrafficCountMode:      "both",
		ThresholdAction:       "stop_all",
		BillingResetDay:       18,
	})
	if err != nil || (stN != http.StatusOK && stN != http.StatusCreated) {
		t.Fatalf("CreateNode failed: st=%d err=%v body=%s", stN, err, string(rawN))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := f15_dialAgentHelloAndSync(t, ctx, client, node.EffectiveToken())
	if err := SendWSEnvelope(ctx, conn, "agent.metrics", "m-pause", AgentMetricsPayload{
		TS:         time.Now().Unix(),
		NicRxDelta: 12000,
		Health:     AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatalf("send agent.metrics: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, snap, _, err := client.GetPublicStatus()
		if err == nil && len(snap.Nodes) == 1 && snap.Nodes[0].Status == "traffic_paused" {
			n := snap.Nodes[0]
			if n.PausedReason == "" || n.BillingResetDay != 18 {
				t.Fatalf("expected non-empty paused_reason and billing_reset_day=18, got %+v", n)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, snap, _, _ := client.GetPublicStatus()
	t.Fatalf("node did not transition to traffic_paused in public status: %+v", snap.Nodes)
}

func TestF15_Tier2_ZeroTrafficLimitProducesNoNaNOrInf(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	stN, node, rawN, err := client.CreateNode(jwt, CreateNodeReq{
		Name:              "Unlimited-ZeroLimit",
		Enabled:           f15_boolPtr(true),
		TrafficLimitBytes: 0,
	})
	if err != nil || (stN != http.StatusOK && stN != http.StatusCreated) {
		t.Fatalf("CreateNode failed: st=%d err=%v body=%s", stN, err, string(rawN))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn := f15_dialAgentHelloAndSync(t, ctx, client, node.EffectiveToken())
	if err := SendWSEnvelope(ctx, conn, "agent.metrics", "m-zero", AgentMetricsPayload{
		TS:         time.Now().Unix(),
		NicRxDelta: 8192,
		Health:     AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatalf("send agent.metrics: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	var lastRaw []byte
	for time.Now().Before(deadline) {
		st, snap, raw, err := client.GetPublicStatus()
		if err == nil && st == http.StatusOK {
			lastRaw = raw
			if len(snap.Nodes) == 1 && snap.Nodes[0].Status == "online" && snap.Nodes[0].TrafficUsedBytes == 8192 {
				rawStr := string(raw)
				if strings.Contains(rawStr, "NaN") || strings.Contains(rawStr, "Inf") {
					t.Fatalf("invalid float in public status JSON: %s", rawStr)
				}
				if snap.Nodes[0].TrafficLimitBytes != 0 || snap.Nodes[0].TrafficPercent != 0 {
					t.Fatalf("expected limit=0 and percent=0, got %+v", snap.Nodes[0])
				}
				return
			}
		}
		time.Sleep(40 * time.Millisecond)
	}
	t.Fatalf("node did not reach online with TrafficUsedBytes=8192 within 5s; last=%s", string(lastRaw))
}

func TestF15_Tier2_NonGetMethodsRejectedOnPublicEndpoints(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()

	ctx := context.Background()
	// Ensure /api/v1/public/status is actually mounted before testing method rejection
	if st, _, _, err := client.GetPublicStatus(); err != nil || st != http.StatusOK {
		t.Fatalf("expected GET /api/v1/public/status 200 OK, got st=%d err=%v", st, err)
	}
	for _, path := range []string{"/api/v1/public/status", "/api/v1/public/ws"} {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			st, _, raw, err := client.DoRaw(ctx, method, path, nil, []byte(`{}`))
			if err != nil {
				t.Fatalf("%s %s err=%v", method, path, err)
			}
			if st != http.StatusMethodNotAllowed && st != http.StatusBadRequest {
				t.Fatalf("expected 405/400 for %s %s, got %d body=%s", method, path, st, string(raw))
			}
		}
	}
}

func TestF15_Tier2_AdminSettingsSecretsNeverExposedPublicly(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{AdminPass: "F15_ADMIN_CANARY_PASS"})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "F15_ADMIN_CANARY_PASS")

	stSet, settings, setRaw, err := client.GetSettings(jwt)
	if err != nil || stSet != http.StatusOK || settings.AdminSubToken == "" {
		t.Fatalf("GetSettings failed: st=%d err=%v token=%q body=%s", stSet, err, settings.AdminSubToken, string(setRaw))
	}
	st, _, raw, err := client.DoRaw(context.Background(), http.MethodGet, "/api/v1/public/status", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st != http.StatusOK {
		t.Fatalf("GET /api/v1/public/status expected 200 OK, got %d body=%s", st, string(raw))
	}
	f15_assertExactPublicSchema(t, raw)
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal public status: %v (body=%s)", err, string(raw))
	}
	f15_assertNoForbiddenKeys(t, parsed, "public_status")

	body := string(raw)
	for _, needle := range []string{
		settings.AdminSubToken,
		"admin_sub_token",
		"alert_cooldown",
		"F15_ADMIN_CANARY_PASS",
	} {
		if needle != "" && strings.Contains(body, needle) {
			t.Fatalf("public status exposed admin setting %q: %s", needle, body)
		}
	}
}
