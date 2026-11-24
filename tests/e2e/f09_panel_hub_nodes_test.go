//go:build e2e

package e2e_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type f09_nodeDTO struct {
	ID                     int64            `json:"id"`
	Name                   string           `json:"name"`
	RegionTag              string           `json:"region_tag"`
	NodeToken              string           `json:"node_token,omitempty"`
	Token                  string           `json:"token,omitempty"`
	TokenHash              string           `json:"token_hash,omitempty"`
	PublicIP               string           `json:"public_ip"`
	PublicIPv6             string           `json:"public_ipv6"`
	CustomEntryHost        string           `json:"custom_entry_host"`
	CustomEntryPort        int              `json:"custom_entry_port"`
	SortOrder              int              `json:"sort_order"`
	Enabled                bool             `json:"enabled"`
	Status                 string           `json:"status"`
	PausedReason           string           `json:"paused_reason"`
	SnellConfig            *SnellConfigDTO  `json:"snell_config,omitempty"`
	SSConfig               *SSConfigDTO     `json:"ss_config,omitempty"`
	DNSUnlockEnabled       bool             `json:"dns_unlock_enabled"`
	DNSUnlockServer        string           `json:"dns_unlock_server"`
	DNSRuleGroupID         *int64           `json:"dns_rule_group_id"`
	ExtraDNSRules          []string         `json:"dns_extra_rules,omitempty"`
	TrafficLimitBytes      int64            `json:"traffic_limit_bytes"`
	TrafficThresholdBytes  int64            `json:"traffic_threshold_bytes"`
	TrafficCountMode       string           `json:"traffic_count_mode"`
	ThresholdAction        string           `json:"threshold_action"`
	BillingResetDay        int              `json:"billing_reset_day"`
	CycleRxBytes           int64            `json:"cycle_rx_bytes"`
	CycleTxBytes           int64            `json:"cycle_tx_bytes"`
	IsTrafficPaused        bool             `json:"is_traffic_paused"`
	ConfigRevision         int64            `json:"config_revision"`
	ReportedConfigRevision int64            `json:"reported_config_revision"`
	ReportedVersions       AgentVersionsDTO `json:"reported_versions"`
	AgentOS                string           `json:"agent_os"`
	AgentArch              string           `json:"agent_arch"`
	CPUCores               int              `json:"cpu_cores"`
	CPUPercent             float64          `json:"cpu_percent"`
	MemUsedBytes           uint64           `json:"mem_used_bytes"`
	MemTotalBytes          uint64           `json:"mem_total_bytes"`
	DiskUsedPercent        float64          `json:"disk_used_percent"`
	UptimeSeconds          uint64           `json:"uptime_seconds"`
	RxBPS                  uint64           `json:"rx_bps"`
	TxBPS                  uint64           `json:"tx_bps"`
	CoreAHealthy           bool             `json:"core_a_healthy"`
	CoreBHealthy           bool             `json:"core_b_healthy"`
}

func f09_getNodeExt(t *testing.T, client *PanelClient, jwt string, id int64) (int, f09_nodeDTO, []byte) {
	t.Helper()
	var out f09_nodeDTO
	st, raw, err := client.DoJSON(context.Background(), http.MethodGet, fmt.Sprintf("/api/v1/admin/nodes/%d", id), jwt, nil, &out)
	if err != nil {
		t.Fatalf("GET /api/v1/admin/nodes/%d failed: err=%v body=%s", id, err, string(raw))
	}
	return st, out, raw
}

func f09_readEnvelopeOfType(t *testing.T, ctx context.Context, conn *websocket.Conn, wantType string, timeout time.Duration) WSEnvelope {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		rem := time.Until(deadline)
		if rem <= 0 {
			break
		}
		env, raw, err := ReadWSEnvelope(ctx, conn, rem)
		if err != nil {
			t.Fatalf("ReadWSEnvelope waiting for %q failed: %v", wantType, err)
		}
		if env.Type == wantType {
			return env
		}
		t.Logf("f09_readEnvelopeOfType: skipped %q while waiting for %q (raw=%s)", env.Type, wantType, string(raw))
	}
	t.Fatalf("timed out waiting for WS envelope type %q after %s", wantType, timeout)
	return WSEnvelope{}
}

func f09_collectStrings(v any, b *strings.Builder) {
	switch x := v.(type) {
	case string:
		b.WriteString(x)
		b.WriteByte('\n')
	case []any:
		for _, elem := range x {
			f09_collectStrings(elem, b)
		}
	case map[string]any:
		for _, elem := range x {
			f09_collectStrings(elem, b)
		}
	}
}

func TestF09_Tier1_NodeCRUDAndTokenRedaction(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	createReq := CreateNodeReq{
		Name:            "F09-Tokyo-01",
		RegionTag:       "JP",
		PublicIP:        "203.0.113.10",
		CustomEntryHost: "jp1.example.com",
		CustomEntryPort: 1443,
		SortOrder:       3,
		Enabled:         boolPtr(true),
		SnellConfig: &SnellConfigDTO{
			Enabled:         true,
			Version:         "v5",
			PublicPort:      2443,
			InnerPort:       31001,
			PSK:             "snell_psk_f09_test",
			Obfs:            "off",
			TFO:             true,
			DNSIPPreference: "prefer-ipv4",
			STLSPassword:    "snell_stls_f09",
			STLSSNI:         "gateway.icloud.com",
		},
		SSConfig: &SSConfigDTO{
			Enabled: true,
			TCPPort: 3443,
			UDPPort: 3443,
			Cipher:  "2022-blake3-aes-128-gcm",
			IPSK:    "AAAAAAAAAAAAAAAAAAAAAA==",
			STLSSNI: "swscan.apple.com",
		},
		DNSUnlockEnabled:      true,
		DNSUnlockServer:       "198.51.100.53:3535",
		ExtraDNSRules:         []string{"netflix.com", "^hulu.com"},
		TrafficLimitBytes:     1000 << 30,
		TrafficThresholdBytes: 850 << 30,
		TrafficCountMode:      "both",
		ThresholdAction:       "stop_all",
		BillingResetDay:       15,
	}

	st, created, rawCreate, err := client.CreateNode(jwt, createReq)
	if err != nil || (st != http.StatusOK && st != http.StatusCreated) {
		t.Fatalf("CreateNode failed: st=%d err=%v body=%s", st, err, string(rawCreate))
	}
	nodeToken := created.EffectiveToken()
	if nodeToken == "" {
		t.Fatalf("CreateNode did not return plaintext node_token: %s", string(rawCreate))
	}
	if created.ID <= 0 || created.Name != "F09-Tokyo-01" || created.BillingResetDay != 15 {
		t.Fatalf("unexpected created node: %+v", created)
	}

	// ListNodes must include the node and redact node_token/token_hash
	stList, list, rawList, err := client.ListNodes(jwt)
	if err != nil || stList != http.StatusOK || len(list) != 1 {
		t.Fatalf("ListNodes failed: st=%d len=%d err=%v body=%s", stList, len(list), err, string(rawList))
	}
	if strings.Contains(string(rawList), nodeToken) || strings.Contains(string(rawList), "token_hash") {
		t.Fatalf("ListNodes leaked node_token or token_hash: %s", string(rawList))
	}

	// GetNode must persist fields and redact node_token/token_hash
	stGet, got, rawGet := f09_getNodeExt(t, client, jwt, created.ID)
	if stGet != http.StatusOK {
		t.Fatalf("GetNode failed: st=%d body=%s", stGet, string(rawGet))
	}
	if strings.Contains(string(rawGet), nodeToken) || strings.Contains(string(rawGet), "token_hash") {
		t.Fatalf("GetNode leaked node_token or token_hash: %s", string(rawGet))
	}
	if got.CustomEntryHost != "jp1.example.com" || got.CustomEntryPort != 1443 || got.TrafficThresholdBytes != 850<<30 {
		t.Fatalf("GetNode mismatch: %+v", got)
	}
	if got.SnellConfig == nil || got.SnellConfig.Version != "v5" || got.SSConfig == nil || got.SSConfig.Cipher != "2022-blake3-aes-128-gcm" {
		t.Fatalf("GetNode protocol configs mismatch: %+v", got)
	}

	// UpdateNode
	updReq := CreateNodeReq{
		Name:            "F09-Tokyo-Updated",
		RegionTag:       "JP-2",
		PublicIP:        "203.0.113.10",
		CustomEntryHost: "jp2.example.com",
		CustomEntryPort: 4443,
		SortOrder:       3,
		Enabled:         boolPtr(true),
		SnellConfig: &SnellConfigDTO{
			Enabled:      true,
			Version:      "v4",
			PublicPort:   2443,
			InnerPort:    31001,
			PSK:          "snell_psk_f09_test",
			Obfs:         "http",
			STLSPassword: "snell_stls_f09",
			STLSSNI:      "gateway.icloud.com",
		},
		SSConfig: &SSConfigDTO{
			Enabled: true,
			TCPPort: 3443,
			UDPPort: 3443,
			Cipher:  "2022-blake3-aes-256-gcm",
			IPSK:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			STLSSNI: "swscan.apple.com",
		},
		TrafficLimitBytes:     1200 << 30,
		TrafficThresholdBytes: 900 << 30,
		TrafficCountMode:      "tx_only",
		ThresholdAction:       "stop_ss_only",
		BillingResetDay:       20,
	}
	stUpd, updated, rawUpd, err := client.UpdateNode(jwt, created.ID, updReq)
	if err != nil || stUpd != http.StatusOK {
		t.Fatalf("UpdateNode failed: st=%d err=%v body=%s", stUpd, err, string(rawUpd))
	}
	if updated.Name != "F09-Tokyo-Updated" || updated.CustomEntryHost != "jp2.example.com" || updated.CustomEntryPort != 4443 || updated.BillingResetDay != 20 {
		t.Fatalf("UpdateNode mismatch: %+v", updated)
	}
	if updated.TrafficCountMode != "tx_only" || updated.ThresholdAction != "stop_ss_only" || updated.TrafficLimitBytes != 1200<<30 || updated.TrafficThresholdBytes != 900<<30 {
		t.Fatalf("UpdateNode traffic settings mismatch: %+v", updated)
	}
	if updated.ConfigRevision <= created.ConfigRevision {
		t.Fatalf("expected updated ConfigRevision (%d) > created ConfigRevision (%d)", updated.ConfigRevision, created.ConfigRevision)
	}
	if updated.SnellConfig == nil || updated.SnellConfig.Version != "v4" || updated.SSConfig == nil || updated.SSConfig.Cipher != "2022-blake3-aes-256-gcm" {
		t.Fatalf("UpdateNode protocol mismatch: %+v", updated)
	}

	// DeleteNode
	stDel, rawDel, err := client.DeleteNode(jwt, created.ID)
	if err != nil || stDel < 200 || stDel >= 300 {
		t.Fatalf("DeleteNode failed: st=%d err=%v body=%s", stDel, err, string(rawDel))
	}
	stAfterDel, _, _, err := client.GetNode(jwt, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stAfterDel != http.StatusNotFound {
		t.Fatalf("expected 404 after DeleteNode, got %d", stAfterDel)
	}
	_, listAfter, _, err := client.ListNodes(jwt)
	if err != nil || len(listAfter) != 0 {
		t.Fatalf("expected 0 nodes after DeleteNode, got %d (err=%v)", len(listAfter), err)
	}
}

func TestF09_Tier1_NodeReorderAndPublicSortOrder(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, n1, _, err := client.CreateNode(jwt, CreateNodeReq{Name: "Node-A", RegionTag: "A", Enabled: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	_, n2, _, err := client.CreateNode(jwt, CreateNodeReq{Name: "Node-B", RegionTag: "B", Enabled: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	_, n3, _, err := client.CreateNode(jwt, CreateNodeReq{Name: "Node-C", RegionTag: "C", Enabled: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}

	st, raw, err := client.ReorderNodes(jwt, []int64{n3.ID, n1.ID, n2.ID})
	if err != nil || st < 200 || st >= 300 {
		t.Fatalf("ReorderNodes failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	_, list, _, err := client.ListNodes(jwt)
	if err != nil || len(list) != 3 {
		t.Fatalf("ListNodes failed: len=%d err=%v", len(list), err)
	}
	wantOrder := []int64{n3.ID, n1.ID, n2.ID}
	for i, id := range wantOrder {
		if list[i].ID != id || list[i].SortOrder != i {
			t.Fatalf("ListNodes[%d] expected ID=%d SortOrder=%d, got ID=%d SortOrder=%d", i, id, i, list[i].ID, list[i].SortOrder)
		}
	}

	stPub, snap, rawPub, err := client.GetPublicStatus()
	if err != nil || stPub != http.StatusOK || len(snap.Nodes) != 3 {
		t.Fatalf("GetPublicStatus failed: st=%d len=%d err=%v body=%s", stPub, len(snap.Nodes), err, string(rawPub))
	}
	for i, id := range wantOrder {
		if snap.Nodes[i].ID != id || snap.Nodes[i].SortOrder != i {
			t.Fatalf("PublicStatus.Nodes[%d] expected ID=%d SortOrder=%d, got ID=%d SortOrder=%d", i, id, i, snap.Nodes[i].ID, snap.Nodes[i].SortOrder)
		}
	}
}

func TestF09_Tier1_InstallCmdGeneration(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{Name: "InstallCmdNode", Enabled: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	nodeToken := node.EffectiveToken()
	if nodeToken == "" {
		t.Fatal("missing node token")
	}

	st, raw, err := client.GetInstallCmd(jwt, node.ID)
	if err != nil || st != http.StatusOK {
		t.Fatalf("GetInstallCmd failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("decode install-cmd JSON: %v (body=%s)", err, string(raw))
	}

	var allText strings.Builder
	f09_collectStrings(parsed, &allText)
	combined := allText.String() + "\n" + string(raw)

	if !strings.Contains(combined, "docker run") {
		t.Fatalf("expected install-cmd to contain 'docker run', got: %s", string(raw))
	}
	if !strings.Contains(combined, "docker compose") && !strings.Contains(combined, "services:") {
		t.Fatalf("expected install-cmd to contain docker compose snippet, got: %s", string(raw))
	}
	if !strings.Contains(combined, "NODE_TOKEN") || !strings.Contains(combined, nodeToken) {
		t.Fatalf("expected install-cmd to include NODE_TOKEN and node token %q, got: %s", nodeToken, string(raw))
	}
	if !strings.Contains(combined, "PANEL_URL") {
		t.Fatalf("expected install-cmd to include PANEL_URL, got: %s", string(raw))
	}
}

func TestF09_Tier1_TrafficCalibrateAndReset(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:                  "CalibrateNode",
		Enabled:               boolPtr(true),
		TrafficLimitBytes:     10 << 30,
		TrafficThresholdBytes: 8 << 30,
		TrafficCountMode:      "both",
	})
	if err != nil {
		t.Fatal(err)
	}

	stCal, rawCal, err := client.CalibrateNodeTraffic(jwt, node.ID, 111222333, 444555666)
	if err != nil || stCal < 200 || stCal >= 300 {
		t.Fatalf("CalibrateNodeTraffic failed: st=%d err=%v body=%s", stCal, err, string(rawCal))
	}

	_, got, _, err := client.GetNode(jwt, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CycleRxBytes != 111222333 || got.CycleTxBytes != 444555666 {
		t.Fatalf("calibrated counters mismatch: rx=%d tx=%d", got.CycleRxBytes, got.CycleTxBytes)
	}

	_, snap, _, err := client.GetPublicStatus()
	if err != nil || len(snap.Nodes) != 1 {
		t.Fatalf("GetPublicStatus failed: %v", err)
	}
	if snap.Nodes[0].TrafficUsedBytes != 111222333+444555666 {
		t.Fatalf("expected public TrafficUsedBytes=%d, got %d", 111222333+444555666, snap.Nodes[0].TrafficUsedBytes)
	}

	stReset, rawReset, err := client.ResetNodeTraffic(jwt, node.ID)
	if err != nil || stReset < 200 || stReset >= 300 {
		t.Fatalf("ResetNodeTraffic failed: st=%d err=%v body=%s", stReset, err, string(rawReset))
	}
	_, afterReset, _, err := client.GetNode(jwt, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if afterReset.CycleRxBytes != 0 || afterReset.CycleTxBytes != 0 || afterReset.IsTrafficPaused {
		t.Fatalf("expected zeroed counters after reset, got rx=%d tx=%d paused=%v", afterReset.CycleRxBytes, afterReset.CycleTxBytes, afterReset.IsTrafficPaused)
	}
}

func TestF09_Tier1_WSHubHelloConfigSyncServiceCtlAndManualSync(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, dnsGrp, _, err := client.CreateDNSRuleGroup(jwt, "HubDNS", []string{"netflix.com", "^hulu.com"})
	if err != nil {
		t.Fatal(err)
	}
	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:      "HubControlNode",
		RegionTag: "US",
		Enabled:   boolPtr(true),
		SnellConfig: &SnellConfigDTO{
			Enabled: true, Version: "v5", PublicPort: 18443, InnerPort: 31001,
			PSK: "snell_psk_hub", Obfs: "off", TFO: true, STLSPassword: "stls_snell_hub", STLSSNI: "gateway.icloud.com",
		},
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: 19443, UDPPort: 19443,
			Cipher: "2022-blake3-aes-128-gcm", IPSK: "AAAAAAAAAAAAAAAAAAAAAA==", STLSSNI: "swscan.apple.com",
		},
		DNSUnlockEnabled: true,
		DNSUnlockServer:  "198.51.100.53:3535",
		DNSRuleGroupID:   &dnsGrp.ID,
		ExtraDNSRules:    []string{"disneyplus.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, user, _, err := client.CreateUser(jwt, CreateUserReq{
		Username: "hub_user",
		NodeIDs:  []int64{node.ID},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, wsStatus, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatalf("DialAgentWS failed (status=%d): %v", wsStatus, err)
	}
	defer conn.CloseNow()

	if err := SendWSEnvelope(ctx, conn, "agent.hello", "hello-1", AgentHelloPayload{
		OS:            "linux",
		Arch:          "amd64",
		CPUCores:      4,
		TotalRAMBytes: 8 << 30,
		PublicIPv4:    "203.0.113.99",
		PublicIPv6:    "2001:db8::99",
		Versions: AgentVersionsDTO{
			SingBox:     "1.11.4",
			SnellServer: "5.0.0",
			ShadowTLS:   "0.2.25",
		},
		ConfigRevision: 0,
	}); err != nil {
		t.Fatal(err)
	}

	syncEnv := f09_readEnvelopeOfType(t, ctx, conn, "server.config_sync", 5*time.Second)
	var syncPayload ServerConfigSyncPayload
	if err := json.Unmarshal(syncEnv.Payload, &syncPayload); err != nil {
		t.Fatalf("unmarshal server.config_sync: %v", err)
	}
	if syncPayload.ConfigRevision < 1 {
		t.Fatalf("expected config_revision >= 1, got %d", syncPayload.ConfigRevision)
	}
	if !syncPayload.Snell.Enabled || syncPayload.Snell.PublicPort != 18443 || !syncPayload.SS.Enabled || len(syncPayload.SS.Users) != 1 || syncPayload.SS.Users[0].UserID != user.ID {
		t.Fatalf("unexpected server.config_sync payload: %+v", syncPayload)
	}
	if !syncPayload.DNS.UnlockEnabled || len(syncPayload.DNS.Rules) != 3 {
		t.Fatalf("expected 3 merged DNS rules in config_sync, got %+v", syncPayload.DNS)
	}

	if err := SendWSEnvelope(ctx, conn, "agent.event", "ev-applied", AgentEventPayload{
		Event:          "config_applied",
		ConfigRevision: syncPayload.ConfigRevision,
		Status:         "success",
		Message:        "applied",
	}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	var reportedOK bool
	for time.Now().Before(deadline) {
		_, ext, _ := f09_getNodeExt(t, client, jwt, node.ID)
		if ext.ReportedConfigRevision == syncPayload.ConfigRevision && ext.AgentOS == "linux" && ext.AgentArch == "amd64" && ext.PublicIP == "203.0.113.99" {
			reportedOK = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !reportedOK {
		_, ext, raw := f09_getNodeExt(t, client, jwt, node.ID)
		t.Fatalf("agent.hello / config_applied did not update node record: %+v raw=%s", ext, string(raw))
	}

	// Test all 3 valid service-ctl actions
	for _, action := range []string{"restart_snell", "restart_singbox", "restart_all"} {
		stCtl, rawCtl, err := client.ServiceCtlNode(jwt, node.ID, action)
		if err != nil || stCtl < 200 || stCtl >= 300 {
			t.Fatalf("ServiceCtlNode(%s) failed: st=%d err=%v body=%s", action, stCtl, err, string(rawCtl))
		}
		ctlEnv := f09_readEnvelopeOfType(t, ctx, conn, "server.service_ctl", 5*time.Second)
		var ctlPayload ServerServiceCtlPayload
		if err := json.Unmarshal(ctlEnv.Payload, &ctlPayload); err != nil {
			t.Fatal(err)
		}
		if ctlPayload.Action != action {
			t.Fatalf("expected server.service_ctl action %q, got %q", action, ctlPayload.Action)
		}
	}

	// Test manual POST .../sync
	stSync, rawSync, err := client.SyncNode(jwt, node.ID)
	if err != nil || stSync < 200 || stSync >= 300 {
		t.Fatalf("SyncNode failed: st=%d err=%v body=%s", stSync, err, string(rawSync))
	}
	manualSyncEnv := f09_readEnvelopeOfType(t, ctx, conn, "server.config_sync", 5*time.Second)
	var manualPayload ServerConfigSyncPayload
	if err := json.Unmarshal(manualSyncEnv.Payload, &manualPayload); err != nil {
		t.Fatal(err)
	}
	if manualPayload.ConfigRevision < syncPayload.ConfigRevision {
		t.Fatalf("manual sync revision regressed: %d < %d", manualPayload.ConfigRevision, syncPayload.ConfigRevision)
	}
}

func TestF09_Tier1_OfflineDetectionOnHeartbeatTimeout(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	// Set short offline_timeout_seconds via settings API
	stSet, rawSet, err := client.UpdateSettings(jwt, map[string]any{
		"offline_timeout_seconds": 1,
	})
	if err != nil || stSet < 200 || stSet >= 300 {
		t.Fatalf("UpdateSettings(offline_timeout_seconds=1) failed: st=%d err=%v body=%s", stSet, err, string(rawSet))
	}

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{Name: "HeartbeatTimeoutNode", Enabled: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	conn, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	_ = SendWSEnvelope(ctx, conn, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	_, _, _ = ReadWSEnvelope(ctx, conn, 3*time.Second)
	_ = SendWSEnvelope(ctx, conn, "agent.metrics", "m1", AgentMetricsPayload{
		TS:     time.Now().Unix(),
		Health: AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	})

	// Confirm node transitions to online
	onlineDeadline := time.Now().Add(5 * time.Second)
	isOnline := false
	for time.Now().Before(onlineDeadline) {
		_, got, _, _ := client.GetNode(jwt, node.ID)
		if got.Status == "online" {
			isOnline = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !isOnline {
		_, got, _, _ := client.GetNode(jwt, node.ID)
		t.Fatalf("node did not transition to online after hello+metrics: %+v", got)
	}

	// Keep conn open silently without sending agent.metrics; drain reads in a context-canceled
	// background goroutine so WS Pong frames still succeed until Hub.CheckHeartbeats() evicts conn.
	readCtx, readCancel := context.WithCancel(ctx)
	readErrCh := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	t.Cleanup(func() {
		readCancel()
		_ = conn.CloseNow()
		wg.Wait()
	})
	go func() {
		defer wg.Done()
		for {
			_, _, rErr := conn.Read(readCtx)
			if rErr != nil {
				readErrCh <- rErr
				return
			}
		}
	}()

	// Wait for offline_timeout_seconds=1 + Hub.CheckHeartbeats() to transition node status to offline
	offlineDeadline := time.Now().Add(15 * time.Second)
	isOffline := false
	for time.Now().Before(offlineDeadline) {
		_, got, _, _ := client.GetNode(jwt, node.ID)
		if got.Status == "offline" {
			isOffline = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !isOffline {
		_, got, _, _ := client.GetNode(jwt, node.ID)
		t.Fatalf("expected node to transition to offline after heartbeat timeout, still %q", got.Status)
	}

	// Assert the server closed/evicted the stale silent WS connection
	select {
	case rErr := <-readErrCh:
		if rErr == nil || errors.Is(rErr, context.Canceled) || errors.Is(rErr, context.DeadlineExceeded) {
			t.Fatalf("expected server to close/evict stale conn on heartbeat timeout, got err=%v", rErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("node marked offline, but server did not close/evict stale WS connection within 5s")
	}
}

func TestF09_Tier2_InvalidNodePayloadsRejected(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	missingGrp := int64(999999)
	badCreates := []struct {
		name string
		req  CreateNodeReq
	}{
		{"empty_name", CreateNodeReq{Name: ""}},
		{"invalid_traffic_count_mode", CreateNodeReq{Name: "Bad1", TrafficCountMode: "sum_squared"}},
		{"invalid_threshold_action", CreateNodeReq{Name: "Bad2", ThresholdAction: "delete_all"}},
		{"invalid_snell_version", CreateNodeReq{Name: "Bad3", SnellConfig: &SnellConfigDTO{Enabled: true, Version: "v9"}}},
		{"invalid_ss_cipher", CreateNodeReq{Name: "Bad4", SSConfig: &SSConfigDTO{Enabled: true, Cipher: "aes-128-cfb"}}},
		{"billing_reset_day_negative", CreateNodeReq{Name: "Bad5", BillingResetDay: -1}},
		{"billing_reset_day_32", CreateNodeReq{Name: "Bad6", BillingResetDay: 32}},
		{"nonexistent_dns_group", CreateNodeReq{Name: "Bad7", DNSRuleGroupID: &missingGrp}},
	}
	for _, tc := range badCreates {
		st, _, raw, err := client.CreateNode(jwt, tc.req)
		if err != nil {
			t.Fatalf("%s error: %v", tc.name, err)
		}
		if st < 400 || st >= 500 {
			t.Fatalf("%s expected 4xx, got %d (body=%s)", tc.name, st, string(raw))
		}
	}

	// Malformed JSON
	stBadJSON, _, _, err := client.DoRaw(context.Background(), http.MethodPost, "/api/v1/admin/nodes", map[string]string{
		"Authorization": "Bearer " + jwt,
		"Content-Type":  "application/json",
	}, []byte("{bad-json"))
	if err != nil || stBadJSON != http.StatusBadRequest {
		t.Fatalf("malformed JSON expected 400, got %d (err=%v)", stBadJSON, err)
	}

	// Create valid node and test invalid UpdateNode billing_reset_day=0, -1, 32
	_, validNode, _, err := client.CreateNode(jwt, CreateNodeReq{Name: "ValidForUpdate", BillingResetDay: 15, Enabled: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	for _, badDay := range []int{0, -1, 32} {
		stUpd, _, rawUpd, err := client.UpdateNode(jwt, validNode.ID, map[string]any{
			"name":              "ValidForUpdate",
			"enabled":           true,
			"billing_reset_day": badDay,
		})
		if err != nil {
			t.Fatal(err)
		}
		if stUpd < 400 || stUpd >= 500 {
			t.Fatalf("UpdateNode billing_reset_day=%d expected 4xx, got %d (body=%s)", badDay, stUpd, string(rawUpd))
		}
	}
}

func TestF09_Tier2_NonExistentNodeIDReturns404(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	const missingID int64 = 999999

	stGet, _, _, _ := client.GetNode(jwt, missingID)
	stUpd, _, _, _ := client.UpdateNode(jwt, missingID, CreateNodeReq{Name: "Ghost", BillingResetDay: 1})
	stDel, _, _ := client.DeleteNode(jwt, missingID)
	stInst, _, _ := client.GetInstallCmd(jwt, missingID)
	stCal, _, _ := client.CalibrateNodeTraffic(jwt, missingID, 10, 20)
	stRes, _, _ := client.ResetNodeTraffic(jwt, missingID)
	stCtl, _, _ := client.ServiceCtlNode(jwt, missingID, "restart_all")
	stSync, _, _ := client.SyncNode(jwt, missingID)
	stReord, _, _ := client.ReorderNodes(jwt, []int64{missingID})

	for name, st := range map[string]int{
		"GET":       stGet,
		"PUT":       stUpd,
		"DELETE":    stDel,
		"install":   stInst,
		"calibrate": stCal,
		"reset":     stRes,
		"service":   stCtl,
		"sync":      stSync,
	} {
		if st != http.StatusNotFound {
			t.Fatalf("missing node %s expected 404, got %d", name, st)
		}
	}
	if stReord != http.StatusNotFound && stReord != http.StatusBadRequest {
		t.Fatalf("reorder with missing node ID expected 404/400, got %d", stReord)
	}
}

func TestF09_Tier2_DuplicateAgentWSReplacesOldConnection(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{Name: "DupWSNode", Enabled: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	tok := node.EffectiveToken()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn1, _, err := client.DialAgentWS(ctx, tok)
	if err != nil {
		t.Fatalf("DialAgentWS conn1: %v", err)
	}
	defer conn1.CloseNow()
	_ = SendWSEnvelope(ctx, conn1, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	_ = f09_readEnvelopeOfType(t, ctx, conn1, "server.config_sync", 5*time.Second)

	conn2, _, err := client.DialAgentWS(ctx, tok)
	if err != nil {
		t.Fatalf("DialAgentWS conn2: %v", err)
	}
	defer conn2.CloseNow()
	_ = SendWSEnvelope(ctx, conn2, "agent.hello", "h2", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	_ = f09_readEnvelopeOfType(t, ctx, conn2, "server.config_sync", 5*time.Second)

	// Send service-ctl: newest connection conn2 must receive it; stale conn1 must be closed/replaced
	stCtl, rawCtl, err := client.ServiceCtlNode(jwt, node.ID, "restart_all")
	if err != nil || stCtl < 200 || stCtl >= 300 {
		t.Fatalf("ServiceCtlNode failed: st=%d err=%v body=%s", stCtl, err, string(rawCtl))
	}

	ctlEnv := f09_readEnvelopeOfType(t, ctx, conn2, "server.service_ctl", 5*time.Second)
	var ctlPayload ServerServiceCtlPayload
	_ = json.Unmarshal(ctlEnv.Payload, &ctlPayload)
	if ctlPayload.Action != "restart_all" {
		t.Fatalf("expected conn2 to receive restart_all, got %+v", ctlPayload)
	}

	// Verify stale conn1 is actively closed by server (not a read timeout)
	staleDeadline := time.Now().Add(3 * time.Second)
	closedByServer := false
	for time.Now().Before(staleDeadline) {
		rem := time.Until(staleDeadline)
		if rem <= 0 {
			break
		}
		staleEnv, _, staleErr := ReadWSEnvelope(ctx, conn1, rem)
		if staleErr != nil {
			if errors.Is(staleErr, context.DeadlineExceeded) {
				t.Fatalf("expected server to close stale conn1, but ReadWSEnvelope timed out: %v", staleErr)
			}
			closedByServer = true
			break
		}
		if staleEnv.Type == "server.service_ctl" {
			t.Fatalf("stale conn1 unexpectedly received server.service_ctl: %+v", staleEnv)
		}
	}
	if !closedByServer {
		t.Fatalf("expected stale conn1 to be closed/replaced by server")
	}

	// Verify zero cleanup-race eviction or false-offline flicker after conn1 teardown
	_, gotAfter, _, err := client.GetNode(jwt, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotAfter.Status != "online" {
		t.Fatalf("expected node status to remain online after conn1 replacement, got %q (%+v)", gotAfter.Status, gotAfter)
	}
	if stSync, rawSync, err := client.SyncNode(jwt, node.ID); err != nil || stSync < 200 || stSync >= 300 {
		t.Fatalf("post-replacement SyncNode failed: st=%d err=%v body=%s", stSync, err, string(rawSync))
	}
	_ = f09_readEnvelopeOfType(t, ctx, conn2, "server.config_sync", 5*time.Second)
	_, gotFinal, _, err := client.GetNode(jwt, node.ID)
	if err != nil || gotFinal.Status != "online" {
		t.Fatalf("expected node status still online after post-replacement sync, got %+v err=%v", gotFinal, err)
	}
}

func TestF09_Tier2_NegativeCalibrationValuesRejected(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{Name: "NegCalNode", Enabled: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	if st, raw, err := client.CalibrateNodeTraffic(jwt, node.ID, 1000, 2000); err != nil || st >= 300 {
		t.Fatalf("initial calibrate failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	for _, pair := range [][2]int64{{-1, 500}, {500, -10}, {-5, -5}} {
		st, raw, err := client.CalibrateNodeTraffic(jwt, node.ID, pair[0], pair[1])
		if err != nil {
			t.Fatal(err)
		}
		if st < 400 || st >= 500 {
			t.Fatalf("negative calibration (%d, %d) expected 4xx, got %d (body=%s)", pair[0], pair[1], st, string(raw))
		}
	}

	_, got, _, err := client.GetNode(jwt, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CycleRxBytes != 1000 || got.CycleTxBytes != 2000 {
		t.Fatalf("expected existing counters (1000, 2000) untouched, got (%d, %d)", got.CycleRxBytes, got.CycleTxBytes)
	}
}

func TestF09_Tier2_MalformedNodeWSTokenAndInvalidServiceCtl(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{Name: "OfflineCtlNode", Enabled: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Missing / malformed / JWT WS tokens rejected with 401/403
	for _, hdrs := range []http.Header{
		{},
		{"Authorization": []string{"Bearer "}},
		{"Authorization": []string{"Basic Zm9vOmJhcg=="}},
		{"Authorization": []string{"Bearer malformed-not-a-node-token"}},
		{"Authorization": []string{"Bearer " + jwt}},
	} {
		conn, wsSt, err := client.DialAgentWSWithHeaders(ctx, hdrs)
		if err == nil {
			_ = conn.CloseNow()
			t.Fatalf("expected WS rejection for headers %v, but upgraded", hdrs)
		}
		if wsSt != http.StatusUnauthorized && wsSt != http.StatusForbidden {
			t.Fatalf("expected 401/403 for headers %v, got %d (err=%v)", hdrs, wsSt, err)
		}
	}

	// Disabled node dialing /api/v1/agent/ws rejected with 401/403 (403 Forbidden)
	_, disabledNode, rawDis, err := client.CreateNode(jwt, CreateNodeReq{Name: "DisabledWSNode", Enabled: boolPtr(false)})
	if err != nil || disabledNode.EffectiveToken() == "" {
		t.Fatalf("CreateNode(disabled) failed: err=%v body=%s", err, string(rawDis))
	}
	disConn, disSt, disErr := client.DialAgentWS(ctx, disabledNode.EffectiveToken())
	if disErr == nil {
		_ = disConn.CloseNow()
		t.Fatalf("expected WS rejection for disabled node, but upgraded")
	}
	if disSt != http.StatusForbidden && disSt != http.StatusUnauthorized {
		t.Fatalf("expected 401/403 (403 Forbidden) for disabled node WS, got %d (err=%v)", disSt, disErr)
	}

	// Invalid service-ctl actions rejected with 4xx
	for _, badAction := range []string{"", "stop_all", "exec_shell"} {
		st, raw, err := client.ServiceCtlNode(jwt, node.ID, badAction)
		if err != nil {
			t.Fatal(err)
		}
		if st < 400 || st >= 500 {
			t.Fatalf("invalid service-ctl action %q expected 4xx, got %d (body=%s)", badAction, st, string(raw))
		}
	}

	// Offline node service-ctl and manual sync must be handled cleanly without 5xx
	stOffCtl, rawOffCtl, err := client.ServiceCtlNode(jwt, node.ID, "restart_snell")
	if err != nil {
		t.Fatal(err)
	}
	if stOffCtl >= 500 {
		t.Fatalf("offline node service-ctl returned 5xx: st=%d body=%s", stOffCtl, string(rawOffCtl))
	}

	stOffSync, rawOffSync, err := client.SyncNode(jwt, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stOffSync >= 500 {
		t.Fatalf("offline node sync returned 5xx: st=%d body=%s", stOffSync, string(rawOffSync))
	}
}
