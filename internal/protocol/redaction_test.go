package protocol

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestPublicDTOReflectionRedactionGuard(t *testing.T) {
	forbidden := map[string]struct{}{
		"publicip":          {},
		"public_ip":         {},
		"publicipv4":        {},
		"public_ipv4":       {},
		"publicipv6":        {},
		"public_ipv6":       {},
		"customentryhost":   {},
		"custom_entry_host": {},
		"customentryport":   {},
		"custom_entry_port": {},
		"snellconfig":       {},
		"snell_config":      {},
		"ssconfig":          {},
		"ss_config":         {},
		"dnsunlockserver":   {},
		"dns_unlock_server": {},
		"token":             {},
		"tokenhash":         {},
		"token_hash":        {},
		"subtoken":          {},
		"sub_token":         {},
		"psk":               {},
		"ipsk":              {},
		"upsk":              {},
		"ssupsk16":          {},
		"ss_upsk_16":        {},
		"ssupsk32":          {},
		"ss_upsk_32":        {},
		"password":          {},
		"stlspassword":      {},
		"stls_password":     {},
		"username":          {},
		"users":             {},
		"secret":            {},
	}

	var inspectType func(rt reflect.Type)
	inspectType = func(rt reflect.Type) {
		for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice || rt.Kind() == reflect.Array {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			if _, bad := forbidden[strings.ToLower(f.Name)]; bad {
				t.Errorf("forbidden struct field %s.%s found in public DTO", rt.Name(), f.Name)
			}
			tag := strings.Split(f.Tag.Get("json"), ",")[0]
			if _, bad := forbidden[strings.ToLower(tag)]; bad {
				t.Errorf("forbidden JSON tag %q on %s.%s found in public DTO", tag, rt.Name(), f.Name)
			}
			inspectType(f.Type)
		}
	}

	inspectType(reflect.TypeOf(PublicNodeView{}))
	inspectType(reflect.TypeOf(PublicStatusSnapshot{}))
}

func TestPublicDTOPositiveJSONKeysAndCanaryGuard(t *testing.T) {
	const (
		canaryIP       = "203.0.113.42"
		canaryToken    = "nd_live_deadbeefcafebabe1234567890"
		canaryPSK      = "super_secret_snell_psk"
		canaryUser     = "alice_sensitive_user"
		canaryUnlockIP = "198.51.100.77:3535"
	)

	// Hold canaries in local internal structs to verify PublicStatusSnapshot serialization
	// cannot leak any sensitive fields or values.
	_ = ServerConfigSync{
		Snell: SnellConfig{PSK: canaryPSK, STLSPassword: canaryToken},
		SS:    SSConfig{IPSK: canaryPSK, Users: []SSUserEntry{{Username: canaryUser, UPSK: canaryPSK}}},
		DNS:   DNSConfig{UnlockServer: canaryUnlockIP},
	}
	_ = AgentHello{PublicIPv4: canaryIP}

	snap := PublicStatusSnapshot{
		SiteTitle:      "Status Board",
		Announcement:   "All systems nominal",
		PercentageOnly: false,
		Nodes: []PublicNodeView{
			{
				ID:                1,
				Name:              "HK-01",
				RegionTag:         "HK",
				SortOrder:         0,
				Status:            NodeStatusOnline,
				PausedReason:      "",
				BillingResetDay:   1,
				CPUPercent:        15.4,
				MemUsedBytes:      512 * 1024 * 1024,
				MemTotalBytes:     2048 * 1024 * 1024,
				UptimeSeconds:     3600,
				RxBPS:             100000,
				TxBPS:             200000,
				TrafficUsedBytes:  420000,
				TrafficLimitBytes: 1000000,
				TrafficPercent:    42.0,
				PercentageOnly:    false,
				CoreAHealthy:      true,
				CoreBHealthy:      true,
			},
		},
	}

	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal PublicStatusSnapshot failed: %v", err)
	}
	jsonStr := string(raw)

	for _, secret := range []string{canaryIP, canaryToken, canaryPSK, canaryUser, canaryUnlockIP} {
		if strings.Contains(jsonStr, secret) {
			t.Fatalf("public snapshot leaked canary value %q: %s", secret, jsonStr)
		}
	}

	var top map[string]any
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	assertHasKeys(t, top, "site_title", "announcement", "percentage_only", "nodes")

	nodeSlice, ok := top["nodes"].([]any)
	if !ok || len(nodeSlice) != 1 {
		t.Fatalf("unexpected nodes field: %#v", top["nodes"])
	}
	nodeMap := nodeSlice[0].(map[string]any)
	assertHasKeys(t, nodeMap,
		"id", "name", "region_tag", "sort_order", "status", "paused_reason",
		"billing_reset_day", "cpu_percent", "mem_used_bytes", "mem_total_bytes",
		"uptime_seconds", "rx_bps", "tx_bps", "total_rx_bytes", "total_tx_bytes",
		"traffic_used_bytes", "traffic_limit_bytes", "traffic_percent", "percentage_only",
		"core_a_healthy", "core_b_healthy",
	)
}
