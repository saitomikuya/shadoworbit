//go:build e2e

package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func boolPtr(v bool) *bool { return &v }

func assertNoForbiddenJSONKeys(t *testing.T, v any, path string) {
	t.Helper()
	forbidden := map[string]bool{
		"public_ip":         true,
		"custom_entry_host": true,
		"custom_entry_port": true,
		"snell_config":      true,
		"ss_config":         true,
		"dns_unlock_server": true,
		"token":             true,
		"token_hash":        true,
		"psk":               true,
		"ipsk":              true,
		"upsk":              true,
		"ss_upsk_16":        true,
		"ss_upsk_32":        true,
		"stls_password":     true,
		"sub_token":         true,
		"admin_sub_token":   true,
		"username":          true,
		"users":             true,
	}
	switch val := v.(type) {
	case map[string]any:
		for k, child := range val {
			lk := strings.ToLower(k)
			if forbidden[lk] {
				t.Fatalf("forbidden key %q found at %s.%s", k, path, k)
			}
			assertNoForbiddenJSONKeys(t, child, path+"."+k)
		}
	case []any:
		for i, child := range val {
			assertNoForbiddenJSONKeys(t, child, fmt.Sprintf("%s[%d]", path, i))
		}
	}
}

func TestF01_Tier1_ModuleAndBinaryBuildContract(t *testing.T) {
	repoRoot := findRepoRoot(t)
	goModBytes, err := os.ReadFile(filepath.Join(repoRoot, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	goMod := string(goModBytes)
	for _, required := range []string{
		"module snell-panel",
		"go 1.24",
		"modernc.org/sqlite",
		"github.com/coder/websocket",
		"github.com/miekg/dns",
		"github.com/golang-jwt/jwt/v5",
		"golang.org/x/crypto",
		"google.golang.org/grpc",
		"google.golang.org/protobuf",
	} {
		if !strings.Contains(goMod, required) {
			t.Fatalf("go.mod missing required declaration %q", required)
		}
	}

	panelBin := BuildPanelBinary(t)
	out, err := exec.Command(panelBin, "-version").CombinedOutput()
	if err != nil {
		t.Fatalf("panel -version failed: err=%v out=%s", err, string(out))
	}

	agentBin := BuildAgentBinary(t)
	out, err = exec.Command(agentBin, "-version").CombinedOutput()
	if err != nil {
		t.Fatalf("agent -version failed: err=%v out=%s", err, string(out))
	}
}

func TestF01_Tier1_AgentWS_HelloAndConfigSync(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	status, node, raw, err := client.CreateNode(jwt, CreateNodeReq{
		Name:      "F01 Hello Node",
		RegionTag: "US",
		Enabled:   boolPtr(true),
	})
	if err != nil || (status != http.StatusOK && status != http.StatusCreated) {
		t.Fatalf("CreateNode failed: status=%d err=%v body=%s", status, err, string(raw))
	}
	nodeToken := node.EffectiveToken()
	if nodeToken == "" {
		t.Fatalf("CreateNode did not return node token: %s", string(raw))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, wsStatus, err := client.DialAgentWS(ctx, nodeToken)
	if err != nil {
		t.Fatalf("DialAgentWS failed (http=%d): %v", wsStatus, err)
	}
	defer conn.CloseNow()

	err = SendWSEnvelope(ctx, conn, "agent.hello", "hello-1", AgentHelloPayload{
		OS:            "linux",
		Arch:          "amd64",
		CPUCores:      4,
		TotalRAMBytes: 8 * 1024 * 1024 * 1024,
		PublicIPv4:    "203.0.113.10",
		Versions: AgentVersionsDTO{
			SingBox:     "1.11.4",
			SnellServer: "5.0.0",
			ShadowTLS:   "0.2.25",
		},
		ConfigRevision: 0,
	})
	if err != nil {
		t.Fatalf("send agent.hello: %v", err)
	}

	wsEnv, rawFrame, err := ReadWSEnvelope(ctx, conn, 5*time.Second)
	if err != nil {
		t.Fatalf("read server.config_sync: %v", err)
	}
	if wsEnv.Type != "server.config_sync" {
		t.Fatalf("expected server.config_sync, got %q (raw=%s)", wsEnv.Type, string(rawFrame))
	}
	var syncPayload ServerConfigSyncPayload
	if err := json.Unmarshal(wsEnv.Payload, &syncPayload); err != nil {
		t.Fatalf("decode ServerConfigSyncPayload: %v (raw=%s)", err, string(wsEnv.Payload))
	}
	if syncPayload.ConfigRevision < 1 {
		t.Fatalf("expected config_revision >= 1, got %d", syncPayload.ConfigRevision)
	}
}

func TestF01_Tier1_AgentWS_MetricsAndEventContract(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:      "F01 Metrics Node",
		RegionTag: "JP",
		Enabled:   boolPtr(true),
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatalf("DialAgentWS: %v", err)
	}
	defer conn.CloseNow()

	if err := SendWSEnvelope(ctx, conn, "agent.hello", "h1", AgentHelloPayload{
		OS: "linux", Arch: "arm64", CPUCores: 2, TotalRAMBytes: 4 << 30, PublicIPv4: "203.0.113.20",
	}); err != nil {
		t.Fatal(err)
	}
	syncEnv, _, err := ReadWSEnvelope(ctx, conn, 5*time.Second)
	if err != nil {
		t.Fatalf("read config_sync: %v", err)
	}
	var syncPayload ServerConfigSyncPayload
	_ = json.Unmarshal(syncEnv.Payload, &syncPayload)

	if err := SendWSEnvelope(ctx, conn, "agent.event", "ev1", AgentEventPayload{
		Event:          "config_applied",
		ConfigRevision: syncPayload.ConfigRevision,
		Status:         "success",
		Message:        "applied cleanly",
	}); err != nil {
		t.Fatal(err)
	}

	if err := SendWSEnvelope(ctx, conn, "agent.metrics", "m1", AgentMetricsPayload{
		TS:              time.Now().Unix(),
		CPUPercent:      42.5,
		MemUsedBytes:    1024 * 1024 * 512,
		MemTotalBytes:   1024 * 1024 * 2048,
		DiskUsedPercent: 31.2,
		UptimeSeconds:   3600,
		RxBPS:           150000,
		TxBPS:           250000,
		NicRxDelta:      4096,
		NicTxDelta:      8192,
		UserDeltas:      []UserTrafficDeltaDTO{},
		Health:          AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st, snap, _, err := client.GetPublicStatus()
		if err == nil && st == http.StatusOK && len(snap.Nodes) == 1 {
			n := snap.Nodes[0]
			if n.Status == "online" && n.CoreAHealthy && n.CoreBHealthy && n.UptimeSeconds == 3600 && n.RxBPS == 150000 {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, snap, raw, _ := client.GetPublicStatus()
	t.Fatalf("node metrics did not propagate to public status: snap=%+v raw=%s", snap, string(raw))
}

func TestF01_Tier1_PublicStatusExact19Keys(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	if _, _, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:              "F01 Schema Node",
		RegionTag:         "SG",
		Enabled:           boolPtr(true),
		TrafficLimitBytes: 1000,
		BillingResetDay:   15,
	}); err != nil {
		t.Fatal(err)
	}

	status, _, raw, err := client.DoRaw(context.Background(), http.MethodGet, "/api/v1/public/status", nil, nil)
	if err != nil || status != http.StatusOK {
		t.Fatalf("GET /api/v1/public/status failed: status=%d err=%v body=%s", status, err, string(raw))
	}

	var top map[string]any
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("unmarshal public status: %v", err)
	}
	expectedTop := []string{"site_title", "announcement", "percentage_only", "nodes"}
	if len(top) != len(expectedTop) {
		t.Fatalf("expected %d top-level keys, got %d: %v", len(expectedTop), len(top), top)
	}
	for _, k := range expectedTop {
		if _, ok := top[k]; !ok {
			t.Fatalf("missing top-level key %q in %s", k, string(raw))
		}
	}

	nodes, ok := top["nodes"].([]any)
	if !ok || len(nodes) != 1 {
		t.Fatalf("expected 1 node in public status, got %v", top["nodes"])
	}
	nodeObj, ok := nodes[0].(map[string]any)
	if !ok {
		t.Fatalf("expected node object, got %T", nodes[0])
	}

	expectedNodeKeys := []string{
		"id", "name", "region_tag", "sort_order", "status", "paused_reason",
		"billing_reset_day", "cpu_percent", "mem_used_bytes", "mem_total_bytes",
		"uptime_seconds", "rx_bps", "tx_bps", "total_rx_bytes", "total_tx_bytes",
		"traffic_used_bytes", "traffic_limit_bytes", "traffic_percent", "percentage_only",
		"core_a_healthy", "core_b_healthy",
	}
	if len(nodeObj) != len(expectedNodeKeys) {
		t.Fatalf("expected exact %d PublicNodeView keys, got %d: %v", len(expectedNodeKeys), len(nodeObj), nodeObj)
	}
	for _, k := range expectedNodeKeys {
		if _, ok := nodeObj[k]; !ok {
			t.Fatalf("missing PublicNodeView key %q in %s", k, string(raw))
		}
	}
}

func TestF01_Tier1_PublicWS_RedactedSnapshotFrame(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:      "F01 WS Snapshot",
		RegionTag: "TW",
		Enabled:   boolPtr(true),
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, wsStatus, err := client.DialPublicWS(ctx)
	if err != nil {
		t.Fatalf("DialPublicWS failed (http=%d): %v", wsStatus, err)
	}
	defer ws.CloseNow()

	// Trigger an update via agent metrics to guarantee a push frame if server only pushes on tick/event
	agentWS, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err == nil {
		defer agentWS.CloseNow()
		_ = SendWSEnvelope(ctx, agentWS, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
		_, _, _ = ReadWSEnvelope(ctx, agentWS, 2*time.Second)
		_ = SendWSEnvelope(ctx, agentWS, "agent.metrics", "m1", AgentMetricsPayload{
			TS: time.Now().Unix(), CPUPercent: 12.3, Health: AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
		})
	}

	rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
	defer rcancel()
	_, frame, err := ws.Read(rctx)
	if err != nil {
		t.Fatalf("read /api/v1/public/ws frame: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(frame, &decoded); err != nil {
		t.Fatalf("unmarshal public WS frame: %v (raw=%s)", err, string(frame))
	}
	assertNoForbiddenJSONKeys(t, decoded, "public_ws")

	var snap PublicStatusSnapshotDTO
	if err := json.Unmarshal(frame, &snap); err != nil {
		t.Fatalf("decode PublicStatusSnapshotDTO from public WS: %v", err)
	}
	if len(snap.Nodes) == 0 {
		t.Fatalf("expected >=1 node in public WS snapshot, got %+v", snap)
	}
}

func TestF01_Tier1_ServerServiceCtlEnvelope(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{Name: "F01 ServiceCtl Node", Enabled: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatalf("DialAgentWS: %v", err)
	}
	defer conn.CloseNow()

	if err := SendWSEnvelope(ctx, conn, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"}); err != nil {
		t.Fatal(err)
	}
	_, _, err = ReadWSEnvelope(ctx, conn, 5*time.Second)
	if err != nil {
		t.Fatalf("drain initial config_sync: %v", err)
	}

	st, raw, err := client.ServiceCtlNode(jwt, node.ID, "restart_singbox")
	if err != nil || st < 200 || st >= 300 {
		t.Fatalf("ServiceCtlNode failed: status=%d err=%v body=%s", st, err, string(raw))
	}

	wsEnv, rawFrame, err := ReadWSEnvelope(ctx, conn, 5*time.Second)
	if err != nil {
		t.Fatalf("read server.service_ctl: %v", err)
	}
	if wsEnv.Type != "server.service_ctl" {
		t.Fatalf("expected server.service_ctl, got %q (raw=%s)", wsEnv.Type, string(rawFrame))
	}
	var payload ServerServiceCtlPayload
	if err := json.Unmarshal(wsEnv.Payload, &payload); err != nil {
		t.Fatalf("decode ServerServiceCtlPayload: %v", err)
	}
	if payload.Action != "restart_singbox" {
		t.Fatalf("expected action=restart_singbox, got %q", payload.Action)
	}
}

func TestF01_Tier2_AgentWS_MalformedAndEmptyTypeFrames(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{Name: "F01 Malformed WS", Enabled: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatalf("DialAgentWS: %v", err)
	}
	defer conn.CloseNow()

	// Send malformed JSON and empty type frame
	_ = conn.Write(ctx, websocket.MessageText, []byte("{not-valid-json"))
	_ = SendWSEnvelope(ctx, conn, "", "empty-type", map[string]string{"k": "v"})

	// Panel must stay alive and accept a fresh WS session
	conn2, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatalf("DialAgentWS after malformed frames failed: %v", err)
	}
	defer conn2.CloseNow()
	if err := SendWSEnvelope(ctx, conn2, "agent.hello", "ok-1", AgentHelloPayload{OS: "linux", Arch: "amd64"}); err != nil {
		t.Fatalf("send valid agent.hello after malformed frames: %v", err)
	}
	env2, _, err := ReadWSEnvelope(ctx, conn2, 5*time.Second)
	if err != nil || env2.Type != "server.config_sync" {
		t.Fatalf("expected server.config_sync on healthy reconnect, got env=%+v err=%v", env2, err)
	}

	st, _, _, err := client.GetPublicStatus()
	if err != nil || st != http.StatusOK {
		t.Fatalf("panel public status unhealthy after malformed WS frames: st=%d err=%v", st, err)
	}
}

func TestF01_Tier2_AgentWS_UnknownMessageType(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{Name: "F01 Unknown Msg", Enabled: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	_ = SendWSEnvelope(ctx, conn, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	_, _, _ = ReadWSEnvelope(ctx, conn, 3*time.Second)

	if err := SendWSEnvelope(ctx, conn, "agent.unknown_future", "unk-1", map[string]any{"x": 1}); err != nil {
		t.Fatalf("send unknown message type: %v", err)
	}

	// Same session must still process valid agent.metrics
	if err := SendWSEnvelope(ctx, conn, "agent.metrics", "m1", AgentMetricsPayload{
		TS: time.Now().Unix(), CPUPercent: 55.5, Health: AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatalf("send metrics after unknown type: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, snap, _, err := client.GetPublicStatus()
		if err == nil && len(snap.Nodes) == 1 && snap.Nodes[0].Status == "online" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("agent session stopped updating metrics after unknown message type")
}

func TestF01_Tier2_PublicRedactionCanarySecrets(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	canaries := []string{
		"198.51.100.77",
		"canary-entry.secret.internal",
		"CANARY_SNELL_PSK_991",
		"CANARY_SN_STLS_992",
		"Q0FOQVJZX1NTX0lQU0tfMQ==",
		"198.51.100.88:3535",
		"canary_user_secret_994",
	}

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:            "Public Safe Name",
		RegionTag:       "HK",
		PublicIP:        "198.51.100.77",
		CustomEntryHost: "canary-entry.secret.internal",
		CustomEntryPort: 49443,
		Enabled:         boolPtr(true),
		SnellConfig: &SnellConfigDTO{
			Enabled:      true,
			Version:      "v5",
			PublicPort:   49444,
			InnerPort:    31001,
			PSK:          "CANARY_SNELL_PSK_991",
			Obfs:         "off",
			STLSPassword: "CANARY_SN_STLS_992",
			STLSSNI:      "gateway.icloud.com",
		},
		SSConfig: &SSConfigDTO{
			Enabled: true,
			TCPPort: 49445,
			UDPPort: 49445,
			Cipher:  "2022-blake3-aes-128-gcm",
			IPSK:    "Q0FOQVJZX1NTX0lQU0tfMQ==",
			STLSSNI: "swscan.apple.com",
		},
		DNSUnlockEnabled: true,
		DNSUnlockServer:  "198.51.100.88:3535",
	})
	if err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	canaries = append(canaries, node.EffectiveToken())

	_, user, _, err := client.CreateUser(jwt, CreateUserReq{
		Username: "canary_user_secret_994",
		NodeIDs:  []int64{node.ID},
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	canaries = append(canaries, user.SubToken, user.SSUPSK16, user.SSUPSK32, user.STLSPassword)

	// Connect agent WS + public WS so live WS frames also include the node
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pubWS, _, err := client.DialPublicWS(ctx)
	if err != nil {
		t.Fatalf("DialPublicWS: %v", err)
	}
	defer pubWS.CloseNow()

	agentWS, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err == nil {
		defer agentWS.CloseNow()
		_ = SendWSEnvelope(ctx, agentWS, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64", PublicIPv4: "198.51.100.77"})
		_, _, _ = ReadWSEnvelope(ctx, agentWS, 2*time.Second)
		_ = SendWSEnvelope(ctx, agentWS, "agent.metrics", "m1", AgentMetricsPayload{TS: time.Now().Unix(), Health: AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true}})
	}

	_, _, rawHTTP, err := client.DoRaw(ctx, http.MethodGet, "/api/v1/public/status", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var parsedHTTP any
	if err := json.Unmarshal(rawHTTP, &parsedHTTP); err != nil {
		t.Fatal(err)
	}
	assertNoForbiddenJSONKeys(t, parsedHTTP, "public_status")
	for _, secret := range canaries {
		if secret != "" && strings.Contains(string(rawHTTP), secret) {
			t.Fatalf("SECRET LEAK in /api/v1/public/status: found %q", secret)
		}
	}

	rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
	defer rcancel()
	_, rawWS, err := pubWS.Read(rctx)
	if err != nil {
		t.Fatalf("read public WS frame: %v", err)
	}
	var parsedWS any
	if err := json.Unmarshal(rawWS, &parsedWS); err != nil {
		t.Fatal(err)
	}
	assertNoForbiddenJSONKeys(t, parsedWS, "public_ws")
	for _, secret := range canaries {
		if secret != "" && strings.Contains(string(rawWS), secret) {
			t.Fatalf("SECRET LEAK in /api/v1/public/ws: found %q", secret)
		}
	}
}

func TestF01_Tier2_AgentWS_EmptySlicesAndUnhealthyCores(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{Name: "F01 Unhealthy Node", Enabled: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	_ = SendWSEnvelope(ctx, conn, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	_, _, _ = ReadWSEnvelope(ctx, conn, 3*time.Second)

	// Send partial Core A failure (snell=true, shadow_tls=false, sing_box=true)
	if err := SendWSEnvelope(ctx, conn, "agent.metrics", "m1", AgentMetricsPayload{
		TS:         time.Now().Unix(),
		UserDeltas: []UserTrafficDeltaDTO{},
		Health:     AgentHealthDTO{Snell: true, ShadowTLS: false, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	var matched bool
	for time.Now().Before(deadline) {
		_, snap, raw, err := client.GetPublicStatus()
		if err == nil && len(snap.Nodes) == 1 && snap.Nodes[0].Status == "online" {
			if strings.Contains(string(raw), "NaN") || strings.Contains(string(raw), "Inf") {
				t.Fatalf("invalid float representation in JSON: %s", string(raw))
			}
			if !snap.Nodes[0].CoreAHealthy && snap.Nodes[0].CoreBHealthy {
				matched = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !matched {
		_, snap, _, _ := client.GetPublicStatus()
		t.Fatalf("expected CoreAHealthy=false (snell&&shadow_tls) and CoreBHealthy=true, got %+v", snap.Nodes)
	}
}

func TestF01_Tier2_UTF8EmojiAndLargeDNSRuleSync(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	rules := make([]string, 500)
	for i := 0; i < 500; i++ {
		rules[i] = fmt.Sprintf("unlock-%03d.example.com", i)
	}
	st, grp, raw, err := client.CreateDNSRuleGroup(jwt, "Large Unlock Group", rules)
	if err != nil || (st != http.StatusOK && st != http.StatusCreated) {
		t.Fatalf("CreateDNSRuleGroup failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	nodeName := "🇭🇰 香港-01"
	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:             nodeName,
		RegionTag:        "🇭🇰 HK",
		Enabled:          boolPtr(true),
		DNSUnlockEnabled: true,
		DNSUnlockServer:  "198.51.100.53:3535",
		DNSRuleGroupID:   &grp.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	_ = SendWSEnvelope(ctx, conn, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	wsEnv, _, err := ReadWSEnvelope(ctx, conn, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var syncPayload ServerConfigSyncPayload
	if err := json.Unmarshal(wsEnv.Payload, &syncPayload); err != nil {
		t.Fatal(err)
	}
	if len(syncPayload.DNS.Rules) != 500 {
		t.Fatalf("expected 500 DNS rules in config_sync, got %d", len(syncPayload.DNS.Rules))
	}

	_, snap, _, err := client.GetPublicStatus()
	if err != nil || len(snap.Nodes) != 1 || snap.Nodes[0].Name != nodeName {
		t.Fatalf("expected UTF-8 node name %q in public status, got %+v", nodeName, snap.Nodes)
	}
}

func TestF01_Tier2_InvalidProtocolEnumsRejected(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	cases := []struct {
		name string
		req  CreateNodeReq
	}{
		{
			name: "invalid_traffic_count_mode",
			req:  CreateNodeReq{Name: "BadMode", TrafficCountMode: "invalid_mode"},
		},
		{
			name: "invalid_threshold_action",
			req:  CreateNodeReq{Name: "BadAction", ThresholdAction: "nuke_everything"},
		},
		{
			name: "invalid_snell_version",
			req:  CreateNodeReq{Name: "BadSnellVer", SnellConfig: &SnellConfigDTO{Enabled: true, Version: "v99"}},
		},
		{
			name: "invalid_ss_cipher",
			req:  CreateNodeReq{Name: "BadCipher", SSConfig: &SSConfigDTO{Enabled: true, Cipher: "rc4-md5"}},
		},
	}

	for _, tc := range cases {
		st, _, raw, err := client.CreateNode(jwt, tc.req)
		if err != nil {
			t.Fatalf("%s request error: %v", tc.name, err)
		}
		if st < 400 || st >= 500 {
			t.Fatalf("%s expected 4xx rejection, got %d (body=%s)", tc.name, st, string(raw))
		}
	}

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{Name: "ValidNode", Enabled: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	st, raw, err := client.ServiceCtlNode(jwt, node.ID, "rm_rf_root")
	if err != nil {
		t.Fatal(err)
	}
	if st < 400 || st >= 500 {
		t.Fatalf("invalid service-ctl action expected 4xx, got %d (body=%s)", st, string(raw))
	}
}
