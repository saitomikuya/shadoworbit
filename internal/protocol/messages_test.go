package protocol

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
)

func toJSONMap(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal to map failed: %v", err)
	}
	return m
}

func assertHasKeys(t *testing.T, m map[string]any, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			t.Errorf("missing expected JSON key %q in %v", k, m)
		}
	}
	if len(m) != len(keys) {
		t.Errorf("unexpected JSON key count: got %d (%v), want %d (%v)", len(m), m, len(keys), keys)
	}
}

func TestMessageWireJSONKeys(t *testing.T) {
	helloMap := toJSONMap(t, AgentHello{
		Versions: AgentVersions{SingBox: "1", SnellServer: "2", ShadowTLS: "3"},
	})
	assertHasKeys(t, helloMap,
		"os", "arch", "cpu_cores", "total_ram_bytes",
		"public_ipv4", "public_ipv6", "versions", "config_revision",
	)
	versionsMap := helloMap["versions"].(map[string]any)
	assertHasKeys(t, versionsMap, "sing_box", "snell_server", "shadow_tls")

	metricsMap := toJSONMap(t, AgentMetrics{
		UserDeltas: []UserTrafficDelta{{Username: "u", UserID: 1, UpBytes: 2, DownBytes: 3}},
	})
	assertHasKeys(t, metricsMap,
		"ts", "cpu_percent", "mem_used_bytes", "mem_total_bytes",
		"disk_used_percent", "uptime_seconds", "rx_bps", "tx_bps",
		"nic_rx_delta", "nic_tx_delta", "user_deltas", "health",
	)
	healthMap := metricsMap["health"].(map[string]any)
	assertHasKeys(t, healthMap, "snell", "shadow_tls", "sing_box")
	userDeltaMap := metricsMap["user_deltas"].([]any)[0].(map[string]any)
	assertHasKeys(t, userDeltaMap, "username", "user_id", "up_bytes", "down_bytes")

	eventMap := toJSONMap(t, AgentEvent{})
	assertHasKeys(t, eventMap, "event", "config_revision", "kernel", "status", "version", "message", "detail")

	syncMap := toJSONMap(t, ServerConfigSync{
		SS: SSConfig{
			Users: []SSUserEntry{{UserID: 1}},
		},
		DNS: DNSConfig{
			Rules: []string{"abc.com"},
		},
	})
	assertHasKeys(t, syncMap, "config_revision", "snell", "ss", "dns")

	snellMap := syncMap["snell"].(map[string]any)
	assertHasKeys(t, snellMap,
		"enabled", "version", "public_port", "inner_port",
		"psk", "obfs", "tfo", "dns_ip_preference", "stls_password", "stls_sni",
	)

	ssMap := syncMap["ss"].(map[string]any)
	assertHasKeys(t, ssMap, "enabled", "tcp_port", "udp_port", "cipher", "ipsk", "stls_sni", "tfo", "users")
	ssUserMap := ssMap["users"].([]any)[0].(map[string]any)
	assertHasKeys(t, ssUserMap, "user_id", "username", "upsk", "stls_password")

	dnsMap := syncMap["dns"].(map[string]any)
	assertHasKeys(t, dnsMap, "unlock_enabled", "unlock_server", "rules", "upstream_dns", "local_port")

	updateMap := toJSONMap(t, ServerKernelUpdate{})
	assertHasKeys(t, updateMap, "kernel", "version", "download_url", "sha256")

	ctlMap := toJSONMap(t, ServerServiceCtl{})
	assertHasKeys(t, ctlMap, "action")
}

func TestEmptySlicesSurviveRoundTrip(t *testing.T) {
	metrics := AgentMetrics{UserDeltas: []UserTrafficDelta{}}
	raw, err := MarshalEnvelope(MsgTypeAgentMetrics, "r1", metrics)
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	var gotMetrics AgentMetrics
	if err := env.DecodePayload(&gotMetrics); err != nil {
		t.Fatal(err)
	}
	if gotMetrics.UserDeltas == nil || len(gotMetrics.UserDeltas) != 0 {
		t.Fatalf("expected non-nil empty UserDeltas, got %#v", gotMetrics.UserDeltas)
	}

	sync := ServerConfigSync{
		SS:  SSConfig{Users: []SSUserEntry{}},
		DNS: DNSConfig{Rules: []string{}},
	}
	raw, err = MarshalEnvelope(MsgTypeServerConfigSync, "r2", sync)
	if err != nil {
		t.Fatal(err)
	}
	env, err = ParseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	var gotSync ServerConfigSync
	if err := env.DecodePayload(&gotSync); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotSync, sync) {
		t.Fatalf("empty slices round-trip mismatch: got %#v want %#v", gotSync, sync)
	}
}

func TestValidators(t *testing.T) {
	cases := []struct {
		name  string
		fn    func(string) bool
		valid []string
		bad   []string
	}{
		{
			name:  "NodeStatus",
			fn:    IsValidNodeStatus,
			valid: []string{NodeStatusOnline, NodeStatusOffline, NodeStatusTrafficPaused},
			bad:   []string{"", "paused", "ONLINE"},
		},
		{
			name:  "SnellVersion",
			fn:    IsValidSnellVersion,
			valid: []string{SnellVersionV4, SnellVersionV5},
			bad:   []string{"", "v3", "5"},
		},
		{
			name:  "SnellObfs",
			fn:    IsValidSnellObfs,
			valid: []string{SnellObfsOff, SnellObfsHTTP, SnellObfsTLS},
			bad:   []string{"", "none", "ws"},
		},
		{
			name:  "Cipher",
			fn:    IsValidCipher,
			valid: []string{CipherAES128GCM, CipherAES256GCM},
			bad:   []string{"", "aes-256-gcm", "2022-blake3-chacha20-poly1305"},
		},
		{
			name:  "TrafficCountMode",
			fn:    IsValidTrafficCountMode,
			valid: []string{TrafficCountBoth, TrafficCountTxOnly, TrafficCountRxOnly, TrafficCountMaxDir},
			bad:   []string{"", "rx", "sum"},
		},
		{
			name:  "ThresholdAction",
			fn:    IsValidThresholdAction,
			valid: []string{ThresholdActionStopAll, ThresholdActionStopSSOnly},
			bad:   []string{"", "warn", "stop"},
		},
		{
			name:  "Kernel",
			fn:    IsValidKernel,
			valid: []string{KernelSingBox, KernelSnellServer, KernelShadowTLS},
			bad:   []string{"", "xray", "snell"},
		},
		{
			name:  "ServiceAction",
			fn:    IsValidServiceAction,
			valid: []string{ServiceActionRestartSnell, ServiceActionRestartSingBox, ServiceActionRestartAll},
			bad:   []string{"", "stop", "restart"},
		},
		{
			name: "AgentEvent",
			fn:   IsValidAgentEvent,
			valid: []string{
				EventConfigApplied, EventConfigError, EventProcessCrashed,
				EventKernelUpdateProgress, EventKernelUpdateResult,
			},
			bad: []string{"", "unknown"},
		},
		{
			name:  "ClientType",
			fn:    IsValidClientType,
			valid: []string{ClientTypeSurgeAdmin, ClientTypeMihomoUser, ClientTypeSurgeUser},
			bad:   []string{"", "shadowrocket"},
		},
		{
			name:  "WebhookProvider",
			fn:    IsValidWebhookProvider,
			valid: []string{WebhookProviderFeishu, WebhookProviderDingTalk, WebhookProviderWeCom, WebhookProviderCustom},
			bad:   []string{"", "slack", "telegram"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, v := range tc.valid {
				if !tc.fn(v) {
					t.Errorf("expected %q to be valid", v)
				}
			}
			for _, b := range tc.bad {
				if tc.fn(b) {
					t.Errorf("expected %q to be invalid", b)
				}
			}
		})
	}
}

func TestPublicNodeView_ZeroSecretLeakAndUnknownFields(t *testing.T) {
	allowedNodeKeys := map[string]bool{
		"id": true, "name": true, "region_tag": true, "sort_order": true,
		"status": true, "paused_reason": true, "billing_reset_day": true,
		"cpu_percent": true, "mem_used_bytes": true, "mem_total_bytes": true,
		"uptime_seconds": true, "rx_bps": true, "tx_bps": true,
		"total_rx_bytes": true, "total_tx_bytes": true,
		"traffic_used_bytes": true, "traffic_limit_bytes": true,
		"traffic_percent": true, "percentage_only": true,
		"core_a_healthy": true, "core_b_healthy": true,
	}
	forbiddenSubstrings := []string{
		"psk", "ipsk", "upsk", "stls_password", "node_token",
		"token_hash", "public_ip", "custom_entry_host", "custom_entry_port",
		"dns_unlock_server", "snell_config", "ss_config",
	}

	snap := PublicStatusSnapshot{
		SiteTitle:      "Public Status",
		Announcement:   "Nominal",
		PercentageOnly: true,
		Nodes: []PublicNodeView{
			{
				ID:                42,
				Name:              "JP-Tokyo",
				RegionTag:         "JP",
				SortOrder:         1,
				Status:            NodeStatusOnline,
				PausedReason:      "",
				BillingResetDay:   15,
				CPUPercent:        12.5,
				MemUsedBytes:      math.MaxUint64 - 1,
				MemTotalBytes:     math.MaxUint64,
				UptimeSeconds:     999999,
				RxBPS:             1234567,
				TxBPS:             7654321,
				TrafficUsedBytes:  math.MaxInt64,
				TrafficLimitBytes: math.MaxInt64,
				TrafficPercent:    100.0,
				PercentageOnly:    true,
				CoreAHealthy:      true,
				CoreBHealthy:      false,
			},
		},
	}

	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal PublicStatusSnapshot: %v", err)
	}
	lowerRaw := strings.ToLower(string(raw))
	for _, bad := range forbiddenSubstrings {
		if strings.Contains(lowerRaw, `"`+bad+`"`) {
			t.Fatalf("PublicStatusSnapshot JSON contains forbidden key %q: %s", bad, string(raw))
		}
	}

	var decoded struct {
		SiteTitle      string           `json:"site_title"`
		Announcement   string           `json:"announcement"`
		PercentageOnly bool             `json:"percentage_only"`
		Nodes          []map[string]any `json:"nodes"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	if len(decoded.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(decoded.Nodes))
	}
	for k := range decoded.Nodes[0] {
		if !allowedNodeKeys[k] {
			t.Fatalf("unexpected key %q in PublicNodeView JSON (outside allowlist)", k)
		}
	}

	// Unknown fields in PublicStatusSnapshot / ServerConfigSync / AgentMetrics must be tolerated cleanly,
	// and max uint64/int64 numeric boundaries must survive round-trip without overflow.
	withUnknown := `{"ts":9223372036854775807,"nic_rx_delta":18446744073709551615,"nic_tx_delta":18446744073709551614,"future_field":"ignored","user_deltas":[{"username":"u1","user_id":9223372036854775807,"up_bytes":18446744073709551615,"down_bytes":1,"extra":123}]}`
	var m AgentMetrics
	if err := json.Unmarshal([]byte(withUnknown), &m); err != nil {
		t.Fatalf("unmarshal AgentMetrics with unknown fields and uint64 max: %v", err)
	}
	if m.TS != math.MaxInt64 || m.NicRxDelta != math.MaxUint64 || m.NicTxDelta != math.MaxUint64-1 {
		t.Fatalf("numeric boundary mismatch: %+v", m)
	}
	if len(m.UserDeltas) != 1 || m.UserDeltas[0].UserID != math.MaxInt64 || m.UserDeltas[0].UpBytes != math.MaxUint64 {
		t.Fatalf("user delta numeric boundary mismatch: %+v", m.UserDeltas)
	}
}
