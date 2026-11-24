//go:build e2e

package e2e_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

func t3_boolPtr(v bool) *bool { return &v }

func t3_b64Key16(seed string) string {
	b := make([]byte, 16)
	copy(b, []byte(seed))
	return base64.StdEncoding.EncodeToString(b)
}

func t3_b64Key32(seed string) string {
	b := make([]byte, 32)
	copy(b, []byte(seed))
	return base64.StdEncoding.EncodeToString(b)
}

func t3_decodeBase64Flexible(s string) ([]byte, error) {
	trimmed := strings.TrimSpace(s)
	if b, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(trimmed); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(trimmed)
}

func t3_waitUntil(t *testing.T, timeout time.Duration, desc string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s within %s", desc, timeout)
}

func t3_waitTCPReady(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("TCP addr %s not listening within %s", addr, timeout)
}

func t3_mustCreateNode(t *testing.T, client *PanelClient, jwt string, req CreateNodeReq) NodeDTO {
	t.Helper()
	st, node, raw, err := client.CreateNode(jwt, req)
	if err != nil || (st != http.StatusOK && st != http.StatusCreated) {
		t.Fatalf("CreateNode(%q) failed: st=%d err=%v body=%s", req.Name, st, err, string(raw))
	}
	return node
}

func t3_mustCreateUser(t *testing.T, client *PanelClient, jwt string, req CreateUserReq) UserDTO {
	t.Helper()
	st, user, raw, err := client.CreateUser(jwt, req)
	if err != nil || (st != http.StatusOK && st != http.StatusCreated) {
		t.Fatalf("CreateUser(%q) failed: st=%d err=%v body=%s", req.Username, st, err, string(raw))
	}
	return user
}

func t3_getAdminSubToken(t *testing.T, client *PanelClient, jwt string) string {
	t.Helper()
	st, settings, raw, err := client.GetSettings(jwt)
	if err != nil || st != http.StatusOK || settings.AdminSubToken == "" {
		t.Fatalf("GetSettings failed: st=%d err=%v settings=%+v body=%s", st, err, settings, string(raw))
	}
	return settings.AdminSubToken
}

func t3_dialAgentHelloAndSync(t *testing.T, ctx context.Context, client *PanelClient, nodeToken, arch string) (*websocket.Conn, ServerConfigSyncPayload) {
	t.Helper()
	conn, wsSt, err := client.DialAgentWS(ctx, nodeToken)
	if err != nil {
		t.Fatalf("DialAgentWS failed (http=%d): %v", wsSt, err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })

	if err := SendWSEnvelope(ctx, conn, "agent.hello", "t3-hello", AgentHelloPayload{
		OS:            "linux",
		Arch:          arch,
		CPUCores:      4,
		TotalRAMBytes: 8 << 30,
		PublicIPv4:    "198.51.100.199",
		PublicIPv6:    "2001:db8:dead::199",
		Versions: AgentVersionsDTO{
			SingBox:     "1.11.4",
			SnellServer: "5.0.0",
			ShadowTLS:   "0.2.25",
		},
		ConfigRevision: 0,
	}); err != nil {
		t.Fatalf("send agent.hello: %v", err)
	}
	syncPayload := t3_waitConfigSync(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		return p.ConfigRevision >= 1
	}, "initial hello sync")
	return conn, syncPayload
}

func t3_waitConfigSync(t *testing.T, ctx context.Context, conn *websocket.Conn, timeout time.Duration, pred func(ServerConfigSyncPayload) bool, desc string) ServerConfigSyncPayload {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last ServerConfigSyncPayload
	for time.Now().Before(deadline) {
		rem := time.Until(deadline)
		if rem <= 0 {
			break
		}
		env, _, err := ReadWSEnvelope(ctx, conn, rem)
		if err != nil {
			t.Fatalf("waiting for server.config_sync (%s) failed: %v (last=%+v)", desc, err, last)
		}
		if env.Type != "server.config_sync" {
			continue
		}
		var payload ServerConfigSyncPayload
		if err := json.Unmarshal(env.Payload, &payload); err != nil {
			t.Fatalf("decode server.config_sync: %v", err)
		}
		last = payload
		if pred(payload) {
			return payload
		}
	}
	t.Fatalf("timed out waiting for server.config_sync (%s), last=%+v", desc, last)
	return ServerConfigSyncPayload{}
}

func t3_findSSUser(users []SSUserEntryDTO, userID int64) (SSUserEntryDTO, bool) {
	for _, u := range users {
		if u.UserID == userID {
			return u, true
		}
	}
	return SSUserEntryDTO{}, false
}

func t3_assertExactPublicSchema(t *testing.T, raw []byte) {
	t.Helper()
	var top map[string]any
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("unmarshal public snapshot: %v (raw=%s)", err, string(raw))
	}
	wantTop := []string{"site_title", "announcement", "percentage_only", "nodes"}
	if len(top) != len(wantTop) {
		t.Fatalf("PublicStatusSnapshot must have exactly %d keys (%v), got %d: %v", len(wantTop), wantTop, len(top), top)
	}
	for _, k := range wantTop {
		if _, ok := top[k]; !ok {
			t.Fatalf("PublicStatusSnapshot missing key %q in %s", k, string(raw))
		}
	}
	nodesAny, ok := top["nodes"].([]any)
	if !ok {
		t.Fatalf("PublicStatusSnapshot.nodes must be array, got %T", top["nodes"])
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
			t.Fatalf("nodes[%d] must be object, got %T", i, elem)
		}
		if len(m) != len(wantNode) {
			t.Fatalf("PublicNodeView[%d] must have %d keys (%v), got %d: %v", i, len(wantNode), wantNode, len(m), m)
		}
		for _, k := range wantNode {
			if _, ok := m[k]; !ok {
				t.Fatalf("PublicNodeView[%d] missing key %q", i, k)
			}
		}
	}
}

func t3_assertNoForbiddenKeys(t *testing.T, v any, path string) {
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
			t3_assertNoForbiddenKeys(t, child, path+"."+k)
		}
	case []any:
		for i, child := range val {
			t3_assertNoForbiddenKeys(t, child, fmt.Sprintf("%s[%d]", path, i))
		}
	}
}

type t3_walFile struct {
	Version    int                            `json:"version"`
	NicRxDelta uint64                         `json:"nic_rx_delta"`
	NicTxDelta uint64                         `json:"nic_tx_delta"`
	UserDeltas map[string]UserTrafficDeltaDTO `json:"user_deltas"`
}

func t3_readWAL(walPath string) (t3_walFile, error) {
	b, err := os.ReadFile(walPath)
	if err != nil {
		return t3_walFile{}, err
	}
	var w t3_walFile
	if err := json.Unmarshal(b, &w); err != nil {
		return t3_walFile{}, err
	}
	return w, nil
}

type t3_mockPanelWS struct {
	t    *testing.T
	addr string

	mu      sync.Mutex
	srv     *http.Server
	conns   map[*websocket.Conn]struct{}
	hellos  []AgentHelloPayload
	metrics []AgentMetricsPayload
	events  []AgentEventPayload
}

func t3_newMockPanelWS(t *testing.T) *t3_mockPanelWS {
	t.Helper()
	port := AllocFreePort(t)
	m := &t3_mockPanelWS{
		t:     t,
		addr:  fmt.Sprintf("127.0.0.1:%d", port),
		conns: make(map[*websocket.Conn]struct{}),
	}
	m.Start()
	t.Cleanup(func() { m.Stop() })
	return m
}

func (m *t3_mockPanelWS) WSBaseURL() string { return "ws://" + m.addr }

func (m *t3_mockPanelWS) Start() {
	m.t.Helper()
	ln, err := net.Listen("tcp", m.addr)
	if err != nil {
		m.t.Fatalf("t3_mockPanelWS listen %s: %v", m.addr, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agent/ws", m.handleWS)
	srv := &http.Server{Handler: mux}
	m.mu.Lock()
	m.srv = srv
	m.mu.Unlock()
	go func() { _ = srv.Serve(ln) }()
}

func (m *t3_mockPanelWS) Stop() {
	m.mu.Lock()
	srv := m.srv
	m.srv = nil
	conns := make([]*websocket.Conn, 0, len(m.conns))
	for c := range m.conns {
		conns = append(conns, c)
	}
	m.conns = make(map[*websocket.Conn]struct{})
	m.mu.Unlock()
	for _, c := range conns {
		_ = c.CloseNow()
	}
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = srv.Shutdown(ctx)
		cancel()
	}
}

func (m *t3_mockPanelWS) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	m.mu.Lock()
	m.conns[conn] = struct{}{}
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.conns, conn)
		m.mu.Unlock()
		_ = conn.CloseNow()
	}()
	for {
		_, data, err := conn.Read(r.Context())
		if err != nil {
			return
		}
		var env WSEnvelope
		if json.Unmarshal(data, &env) != nil {
			continue
		}
		m.mu.Lock()
		switch env.Type {
		case "agent.hello":
			var p AgentHelloPayload
			if json.Unmarshal(env.Payload, &p) == nil {
				m.hellos = append(m.hellos, p)
			}
		case "agent.metrics":
			var p AgentMetricsPayload
			if json.Unmarshal(env.Payload, &p) == nil {
				m.metrics = append(m.metrics, p)
			}
		case "agent.event":
			var p AgentEventPayload
			if json.Unmarshal(env.Payload, &p) == nil {
				m.events = append(m.events, p)
			}
		}
		m.mu.Unlock()
	}
}

func (m *t3_mockPanelWS) SendEnvelope(msgType, reqID string, payload any) error {
	m.mu.Lock()
	var target *websocket.Conn
	for c := range m.conns {
		target = c
	}
	m.mu.Unlock()
	if target == nil {
		return fmt.Errorf("no active ws connection")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return SendWSEnvelope(ctx, target, msgType, reqID, payload)
}

func (m *t3_mockPanelWS) WaitForHelloCount(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		got := len(m.hellos)
		m.mu.Unlock()
		if got >= n {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}

func (m *t3_mockPanelWS) WaitForEvent(timeout time.Duration, match func(AgentEventPayload) bool) (AgentEventPayload, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		for _, ev := range m.events {
			if match(ev) {
				m.mu.Unlock()
				return ev, true
			}
		}
		m.mu.Unlock()
		time.Sleep(25 * time.Millisecond)
	}
	return AgentEventPayload{}, false
}

func (m *t3_mockPanelWS) WaitForMetricsCount(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		got := len(m.metrics)
		m.mu.Unlock()
		if got >= n {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func (m *t3_mockPanelWS) MetricsLen() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.metrics)
}

func (m *t3_mockPanelWS) MetricsSince(idx int) []AgentMetricsPayload {
	m.mu.Lock()
	defer m.mu.Unlock()
	if idx >= len(m.metrics) {
		return nil
	}
	return append([]AgentMetricsPayload(nil), m.metrics[idx:]...)
}

func t3_baseSyncPayload(t *testing.T, rev int64, psk string, dnsPort int, unlockAddr, upstreamAddr string, ssEnabled bool) ServerConfigSyncPayload {
	t.Helper()
	return ServerConfigSyncPayload{
		ConfigRevision: rev,
		Snell: SnellConfigDTO{
			Enabled:         true,
			Version:         "v5",
			PublicPort:      AllocFreePort(t),
			InnerPort:       AllocFreePort(t),
			PSK:             psk,
			Obfs:            "off",
			TFO:             false,
			DNSIPPreference: "prefer-ipv4",
			STLSPassword:    "t3-snell-stls-pwd",
			STLSSNI:         "gateway.icloud.com",
		},
		SS: SSConfigDTO{
			Enabled: ssEnabled,
			TCPPort: AllocFreePort(t),
			UDPPort: AllocFreeUDPPort(t),
			Cipher:  "2022-blake3-aes-128-gcm",
			IPSK:    t3_b64Key16("t3-server-ipsk!!"),
			STLSSNI: "swscan.apple.com",
			Users: []SSUserEntryDTO{
				{
					UserID:       101,
					Username:     "alice",
					UPSK:         t3_b64Key16("t3-alice-upsk!!!"),
					STLSPassword: "t3-alice-stls",
				},
			},
		},
		DNS: DNSConfigDTO{
			UnlockEnabled: unlockAddr != "",
			UnlockServer:  unlockAddr,
			Rules:         []string{"netflix.com", "^openai.com", "*.disneyplus.com"},
			UpstreamDNS:   upstreamAddr,
			LocalPort:     dnsPort,
		},
	}
}

func t3_dnsExchange(t *testing.T, addr, proto, qname string, qtype uint16) *dns.Msg {
	t.Helper()
	c := &dns.Client{Net: proto, Timeout: 3 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("DNS %s query(%s, %s) failed: %v", proto, qname, dns.TypeToString[qtype], err)
	}
	return resp
}

var (
	t3_scriptSrcRe = regexp.MustCompile(`(?is)<script[^>]*\ssrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'=<>` + "`" + `]+))`)
	t3_linkHrefRe  = regexp.MustCompile(`(?is)<link[^>]*\shref\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'=<>` + "`" + `]+))`)
	t3_envVarRe    = regexp.MustCompile(`(?:os\.Getenv|os\.LookupEnv|getenvDefault|getenvBool|envOrDefault|\bgetenv)\(\s*"([A-Z0-9_]+)"`)
)

func t3_extractAssets(html string) []string {
	var out []string
	seen := map[string]bool{}
	pick := func(m []string) string {
		for i := 1; i < len(m); i++ {
			if m[i] != "" {
				return strings.TrimSpace(m[i])
			}
		}
		return ""
	}
	for _, re := range []*regexp.Regexp{t3_scriptSrcRe, t3_linkHrefRe} {
		for _, m := range re.FindAllStringSubmatch(html, -1) {
			ref := pick(m)
			if ref == "" || strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") || strings.HasPrefix(ref, "data:") {
				continue
			}
			if !seen[ref] {
				seen[ref] = true
				out = append(out, ref)
			}
		}
	}
	return out
}

// 1. F01 + F15: PublicNodeView WS live frame + REST redaction vs full admin node view
func TestTier3_F01_F15_PublicNodeViewRedactionVsAdminView(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")
	adminSubTok := t3_getAdminSubToken(t, client, jwt)

	node := t3_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:            "T3-Tokyo-Edge",
		RegionTag:       "JP",
		PublicIP:        "203.0.113.10",
		CustomEntryHost: "t3-secret-entry.example.com",
		CustomEntryPort: 55443,
		SortOrder:       1,
		Enabled:         t3_boolPtr(true),
		SnellConfig: &SnellConfigDTO{
			Enabled: true, Version: "v5", PublicPort: 51001, InnerPort: 31001,
			PSK: "T3_CANARY_SNELL_PSK", STLSPassword: "T3_CANARY_SN_STLS", STLSSNI: "t3-snell.sni.internal",
		},
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: 52001, UDPPort: 52002,
			Cipher: "2022-blake3-aes-128-gcm", IPSK: t3_b64Key16("T3_CANARY_IPSK!!"), STLSSNI: "t3-ss.sni.internal",
		},
		DNSUnlockEnabled:  true,
		DNSUnlockServer:   "198.51.100.88:3535",
		ExtraDNSRules:     []string{"t3-canary-unlock.internal"},
		TrafficLimitBytes: 100000,
	})
	user := t3_mustCreateUser(t, client, jwt, CreateUserReq{
		Username: "t3_canary_user",
		NodeIDs:  []int64{node.ID},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pubWS, wsSt, err := client.DialPublicWS(ctx)
	if err != nil {
		t.Fatalf("DialPublicWS failed (http=%d): %v", wsSt, err)
	}
	defer pubWS.CloseNow()

	agentWS, _ := t3_dialAgentHelloAndSync(t, ctx, client, node.EffectiveToken(), "amd64")
	if err := SendWSEnvelope(ctx, agentWS, "agent.metrics", "m1", AgentMetricsPayload{
		TS:            time.Now().Unix(),
		CPUPercent:    31.5,
		MemUsedBytes:  512 << 20,
		MemTotalBytes: 2048 << 20,
		UptimeSeconds: 900,
		RxBPS:         44444,
		TxBPS:         88888,
		Health:        AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}

	// Admin view MUST contain full node configuration
	stAdm, admNode, rawAdm, err := client.GetNode(jwt, node.ID)
	if err != nil || stAdm != http.StatusOK {
		t.Fatalf("GetNode failed: st=%d err=%v body=%s", stAdm, err, string(rawAdm))
	}
	if admNode.CustomEntryHost != "t3-secret-entry.example.com" || admNode.CustomEntryPort != 55443 ||
		admNode.SnellConfig == nil || admNode.SnellConfig.PSK != "T3_CANARY_SNELL_PSK" ||
		admNode.SSConfig == nil || admNode.DNSUnlockServer != "198.51.100.88:3535" {
		t.Fatalf("admin view missing expected sensitive node config: %+v", admNode)
	}

	canaries := []string{
		"203.0.113.10", "198.51.100.199", "2001:db8:dead::199",
		"t3-secret-entry.example.com", "55443", "51001", "52001", "52002",
		"T3_CANARY_SNELL_PSK", "T3_CANARY_SN_STLS", "t3-snell.sni.internal",
		"t3-ss.sni.internal", "198.51.100.88:3535", "t3-canary-unlock.internal",
		node.EffectiveToken(), "t3_canary_user", user.SubToken, user.SSUPSK16, user.SSUPSK32, user.STLSPassword, adminSubTok,
	}

	// Verify REST /api/v1/public/status redaction
	var restRaw []byte
	t3_waitUntil(t, 5*time.Second, "public REST node online", func() bool {
		st, snap, raw, err := client.GetPublicStatus()
		if err == nil && st == http.StatusOK && len(snap.Nodes) == 1 && snap.Nodes[0].Status == "online" && snap.Nodes[0].RxBPS == 44444 {
			restRaw = raw
			return true
		}
		return false
	})
	t3_assertExactPublicSchema(t, restRaw)
	var restAny any
	_ = json.Unmarshal(restRaw, &restAny)
	t3_assertNoForbiddenKeys(t, restAny, "public_rest")
	for _, sec := range canaries {
		if sec != "" && strings.Contains(string(restRaw), sec) {
			t.Fatalf("canary %q leaked in public REST status: %s", sec, string(restRaw))
		}
	}

	// Verify Public WS live frames redaction
	rctx, rcancel := context.WithTimeout(ctx, 8*time.Second)
	defer rcancel()
	for {
		_, wsRaw, err := pubWS.Read(rctx)
		if err != nil {
			t.Fatalf("read public WS frame before live metrics: %v", err)
		}
		t3_assertExactPublicSchema(t, wsRaw)
		var wsAny any
		_ = json.Unmarshal(wsRaw, &wsAny)
		t3_assertNoForbiddenKeys(t, wsAny, "public_ws")
		for _, sec := range canaries {
			if sec != "" && strings.Contains(string(wsRaw), sec) {
				t.Fatalf("canary %q leaked in public WS frame: %s", sec, string(wsRaw))
			}
		}
		var snap PublicStatusSnapshotDTO
		if json.Unmarshal(wsRaw, &snap) == nil && len(snap.Nodes) == 1 && snap.Nodes[0].Status == "online" && snap.Nodes[0].RxBPS == 44444 {
			break
		}
	}
}

// 2. F02 + F11: Panel restart preserves cycle traffic, pause state & billing reset day
func TestTier3_F02_F11_PanelRestartPreservesTrafficPauseAndBillingDay(t *testing.T) {
	env := NewTestEnv(t)
	dbPath := filepath.Join(env.RootDir, "panel.db")
	p1 := StartPanel(env, PanelConfig{DBPath: dbPath, TZ: "UTC"})
	c1 := p1.NewClient()
	jwt1 := c1.MustLogin(t, "admin", "change_me_on_first_login")

	node := t3_mustCreateNode(t, c1, jwt1, CreateNodeReq{
		Name:                  "T3-Persist-Pause",
		Enabled:               t3_boolPtr(true),
		TrafficLimitBytes:     2000,
		TrafficThresholdBytes: 1000,
		TrafficCountMode:      "both",
		ThresholdAction:       "stop_all",
		BillingResetDay:       29,
		SnellConfig:           &SnellConfigDTO{Enabled: true, Version: "v5", PublicPort: 25001, InnerPort: 31001, PSK: "psk-t3"},
		SSConfig:              &SSConfigDTO{Enabled: true, TCPPort: 25002, UDPPort: 25002, Cipher: "2022-blake3-aes-128-gcm", IPSK: t3_b64Key16("t3-persist-ipsk!")},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn1, _ := t3_dialAgentHelloAndSync(t, ctx, c1, node.EffectiveToken(), "amd64")

	if err := SendWSEnvelope(ctx, conn1, "agent.metrics", "m-pause", AgentMetricsPayload{
		TS:         time.Now().Unix(),
		NicRxDelta: 600,
		NicTxDelta: 500,
		Health:     AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}
	_ = t3_waitConfigSync(t, ctx, conn1, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		return !p.Snell.Enabled && !p.SS.Enabled
	}, "paused before restart")
	_ = conn1.CloseNow()

	if err := p1.Stop(); err != nil {
		t.Fatalf("p1.Stop: %v", err)
	}

	// Restart panel on same SQLite DB
	p2 := StartPanel(env, PanelConfig{DBPath: dbPath, TZ: "UTC"})
	c2 := p2.NewClient()
	jwt2 := c2.MustLogin(t, "admin", "change_me_on_first_login")

	_, gotN, _, err := c2.GetNode(jwt2, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !gotN.IsTrafficPaused || gotN.Status != "traffic_paused" || gotN.BillingResetDay != 29 ||
		gotN.CycleRxBytes != 600 || gotN.CycleTxBytes != 500 {
		t.Fatalf("paused state or billing day lost across panel restart: %+v", gotN)
	}

	_, pubSnap, _, err := c2.GetPublicStatus()
	if err != nil || len(pubSnap.Nodes) != 1 || pubSnap.Nodes[0].Status != "traffic_paused" || pubSnap.Nodes[0].BillingResetDay != 29 {
		t.Fatalf("public status after restart mismatch: %+v err=%v", pubSnap, err)
	}

	// Reconnecting agent receives paused config_sync (both disabled)
	conn2, sync2 := t3_dialAgentHelloAndSync(t, ctx, c2, node.EffectiveToken(), "amd64")
	if sync2.Snell.Enabled || sync2.SS.Enabled {
		t.Fatalf("expected reconnecting agent after restart to receive paused config, got %+v", sync2)
	}

	// Manual reset recovers and re-enables services
	if st, raw, err := c2.ResetNodeTraffic(jwt2, node.ID); err != nil || st >= 300 {
		t.Fatalf("ResetNodeTraffic failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	_ = t3_waitConfigSync(t, ctx, conn2, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		return p.Snell.Enabled && p.SS.Enabled
	}, "recovered after reset")
}

// 3. F03 + F09: Admin password rotation + auth enforcement while active agent WS stays authenticated
func TestTier3_F03_F09_AdminPasswordRotationAndAgentWSAuth(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{AdminPass: "t3_initial_pass"})
	client := panel.NewClient()
	jwt1 := client.MustLogin(t, "admin", "t3_initial_pass")

	node := t3_mustCreateNode(t, client, jwt1, CreateNodeReq{
		Name:    "T3-WS-Auth-Node",
		Enabled: t3_boolPtr(true),
		SnellConfig: &SnellConfigDTO{
			Enabled: true, Version: "v5", PublicPort: 25101, InnerPort: 31001, PSK: "psk-auth",
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, initSync := t3_dialAgentHelloAndSync(t, ctx, client, node.EffectiveToken(), "amd64")
	if err := SendWSEnvelope(ctx, conn, "agent.metrics", "m1", AgentMetricsPayload{
		TS: time.Now().Unix(), CPUPercent: 11.0, Health: AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}
	t3_waitUntil(t, 5*time.Second, "node online before password rotation", func() bool {
		_, n, _, _ := client.GetNode(jwt1, node.ID)
		return n.Status == "online"
	})

	// Rotate admin password
	stPwd, rawPwd, err := client.UpdatePassword(jwt1, "t3_initial_pass", "t3_rotated_pass_2026")
	if err != nil || stPwd >= 300 {
		t.Fatalf("UpdatePassword failed: st=%d err=%v body=%s", stPwd, err, string(rawPwd))
	}

	// Old password rejected, tampered/invalid JWT rejected, new password succeeds
	if oldSt, _, _, _ := client.Login("admin", "t3_initial_pass"); oldSt != http.StatusUnauthorized {
		t.Fatalf("expected old password login to fail with 401, got %d", oldSt)
	}
	if badSt, _, _, _ := client.GetMe(jwt1 + "tamper"); badSt != http.StatusUnauthorized {
		t.Fatalf("expected tampered JWT rejected with 401, got %d", badSt)
	}
	jwt2 := client.MustLogin(t, "admin", "t3_rotated_pass_2026")
	if meSt, me, _, err := client.GetMe(jwt2); err != nil || meSt != http.StatusOK || me.Username != "admin" {
		t.Fatalf("GetMe with rotated JWT failed: st=%d me=%+v err=%v", meSt, me, err)
	}

	// Active agent WS connection stays authenticated and responsive to SyncNode via jwt2
	if stSync, rawSync, err := client.SyncNode(jwt2, node.ID); err != nil || stSync >= 300 {
		t.Fatalf("SyncNode with new JWT failed: st=%d err=%v body=%s", stSync, err, string(rawSync))
	}
	syncAfter := t3_waitConfigSync(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		return p.ConfigRevision >= initSync.ConfigRevision
	}, "active WS receives sync after admin password rotation")
	_ = syncAfter

	if err := SendWSEnvelope(ctx, conn, "agent.metrics", "m2", AgentMetricsPayload{
		TS: time.Now().Unix(), CPUPercent: 55.5, Health: AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}
	t3_waitUntil(t, 5*time.Second, "post-rotation metrics accepted on active agent WS", func() bool {
		_, snap, _, _ := client.GetPublicStatus()
		return len(snap.Nodes) == 1 && snap.Nodes[0].CPUPercent == 55.5
	})
}

// 4. F03 + F10: 16B vs 32B uPSK cipher switch preserves user auth across node config sync
func TestTier3_F03_F10_CipherSwitchPreservesUserAuth(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	ipsk16 := t3_b64Key16("t3-ipsk-16-bytes")
	ipsk32 := t3_b64Key32("t3-ipsk-32-bytes-key-material!!!")

	node := t3_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:            "T3-CipherSwitch",
		Enabled:         t3_boolPtr(true),
		BillingResetDay: 1,
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: 25202, UDPPort: 25202,
			Cipher: "2022-blake3-aes-128-gcm", IPSK: ipsk16, STLSSNI: "swscan.apple.com",
		},
	})
	user := t3_mustCreateUser(t, client, jwt, CreateUserReq{
		Username: "t3_cipher_user",
		NodeIDs:  []int64{node.ID},
	})
	orig16, orig32, origSTLS, origSub := user.SSUPSK16, user.SSUPSK32, user.STLSPassword, user.SubToken

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, sync128 := t3_dialAgentHelloAndSync(t, ctx, client, node.EffectiveToken(), "amd64")
	u128, ok := t3_findSSUser(sync128.SS.Users, user.ID)
	if !ok || sync128.SS.Cipher != "2022-blake3-aes-128-gcm" || u128.UPSK != orig16 || u128.STLSPassword != origSTLS {
		t.Fatalf("unexpected 128-gcm sync user: ok=%v u=%+v", ok, u128)
	}

	// Switch cipher to 2022-blake3-aes-256-gcm
	stUpd, _, rawUpd, err := client.UpdateNode(jwt, node.ID, CreateNodeReq{
		Name:            "T3-CipherSwitch",
		Enabled:         t3_boolPtr(true),
		BillingResetDay: 1,
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: 25202, UDPPort: 25202,
			Cipher: "2022-blake3-aes-256-gcm", IPSK: ipsk32, STLSSNI: "swscan.apple.com",
		},
	})
	if err != nil || stUpd != http.StatusOK {
		t.Fatalf("UpdateNode cipher failed: st=%d err=%v body=%s", stUpd, err, string(rawUpd))
	}

	sync256 := t3_waitConfigSync(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		u, found := t3_findSSUser(p.SS.Users, user.ID)
		return found && p.SS.Cipher == "2022-blake3-aes-256-gcm" && u.UPSK == orig32
	}, "aes-256-gcm uses 32B uPSK")
	dec32, err := base64.StdEncoding.DecodeString(sync256.SS.Users[0].UPSK)
	if err != nil || len(dec32) != 32 {
		t.Fatalf("expected 32-byte decoded uPSK, got len=%d err=%v", len(dec32), err)
	}

	_, gotUser, _, err := client.GetUser(jwt, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotUser.SSUPSK16 != orig16 || gotUser.SSUPSK32 != orig32 || gotUser.STLSPassword != origSTLS || gotUser.SubToken != origSub {
		t.Fatalf("user credentials mutated during cipher switch: got=%+v", gotUser)
	}
}

// 5. F04 + F07: Agent WS disconnect + /proc/net/dev + gRPC WAL buffering + reconnect flush
func TestTier3_F04_F07_OfflineWALBufferingAndReconnectFlush(t *testing.T) {
	env := NewTestEnv(t)
	srv := t3_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})
	procPath := WriteProcNetDevFixture(t, "eth0", 2000, 3000)

	ag := StartAgent(env, AgentConfig{
		PanelURL:       srv.WSBaseURL(),
		NodeToken:      "nd_live_t3_f04_f07_wal",
		Iface:          "eth0",
		ProcNetDevPath: procPath,
		SnellBin:       kernels.SnellBin,
		ShadowTLSBin:   kernels.ShadowTLSBin,
		SingBoxBin:     kernels.SingBoxBin,
	})

	if !srv.WaitForHelloCount(1, 8*time.Second) {
		t.Fatalf("expected initial agent.hello; logs:\n%s", ag.Logs())
	}
	if err := srv.SendEnvelope("server.config_sync", "s1", t3_baseSyncPayload(t, 1, "t3-wal-psk", ag.LocalDNSPort, "", normalDNS.Addr(), true)); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 1
	}); !ok {
		t.Fatalf("expected config_applied rev 1")
	}
	t3_waitTCPReady(t, fmt.Sprintf("127.0.0.1:%d", ag.StatsPort), 5*time.Second)
	if !srv.WaitForMetricsCount(1, 15*time.Second) {
		t.Fatalf("expected baseline metrics frame")
	}

	// Disconnect WS and accumulate NIC + user deltas into pending_traffic.json WAL
	srv.Stop()
	mark := srv.MetricsLen()
	UpdateProcNetDevFixture(t, procPath, "eth0", 10000, 15000) // +8000 rx, +12000 tx
	kernels.SetStats([]MockUserStat{
		{Name: "user>>>alice>>>traffic>>>uplink", Value: 2500},
		{Name: "user>>>alice>>>traffic>>>downlink", Value: 3500},
	})

	walPath := filepath.Join(ag.DataDir, "pending_traffic.json")
	var wal t3_walFile
	t3_waitUntil(t, 25*time.Second, "WAL buffering offline NIC + user deltas", func() bool {
		w, err := t3_readWAL(walPath)
		if err != nil {
			return false
		}
		wal = w
		return w.NicRxDelta >= 8000 && w.NicTxDelta >= 12000 && w.UserDeltas["alice"].UpBytes >= 2500 && w.UserDeltas["alice"].DownBytes >= 3500
	})
	if wal.NicRxDelta != 8000 || wal.NicTxDelta != 12000 {
		t.Fatalf("unexpected buffered WAL NIC deltas: %+v", wal)
	}

	// Reconnect on same port and confirm complete WAL flush
	srv.Start()
	if !srv.WaitForHelloCount(2, 35*time.Second) {
		t.Fatalf("expected reconnect hello")
	}

	var rxSum, txSum, aUp, aDown uint64
	t3_waitUntil(t, 20*time.Second, "WAL reconnect flush", func() bool {
		rxSum, txSum, aUp, aDown = 0, 0, 0, 0
		for _, m := range srv.MetricsSince(mark) {
			rxSum += m.NicRxDelta
			txSum += m.NicTxDelta
			for _, u := range m.UserDeltas {
				if u.Username == "alice" {
					aUp += u.UpBytes
					aDown += u.DownBytes
				}
			}
		}
		return rxSum >= 8000 && txSum >= 12000 && aUp >= 2500 && aDown >= 3500
	})
	if rxSum != 8000 || txSum != 12000 || aUp != 2500 || aDown != 3500 {
		t.Fatalf("WAL flush mismatch: rx=%d tx=%d aUp=%d aDown=%d", rxSum, txSum, aUp, aDown)
	}
	t3_waitUntil(t, 5*time.Second, "WAL cleared after flush", func() bool {
		w, err := t3_readWAL(walPath)
		return err == nil && w.NicRxDelta == 0 && w.NicTxDelta == 0 && len(w.UserDeltas) == 0
	})
}

// 6. F04 + F05: Agent offline restart restores last valid 3-kernel config & continues serving
func TestTier3_F04_F05_AgentOfflineRestartRestoresLastValidConfigs(t *testing.T) {
	env := NewTestEnv(t)
	srv := t3_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.org": {"93.184.216.34"}}})
	unlockDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"netflix.com": {"203.0.113.77"}}})

	dataDir := filepath.Join(env.RootDir, "agent-offline-data")
	dnsPort := AllocFreeDualPort(t)
	statsPort := AllocFreePort(t)

	ag1 := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    "nd_live_t3_offline_restore",
		DataDir:      dataDir,
		LocalDNSPort: dnsPort,
		StatsPort:    statsPort,
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})
	if !srv.WaitForHelloCount(1, 8*time.Second) {
		t.Fatalf("expected agent #1 hello")
	}

	sync5 := t3_baseSyncPayload(t, 5, "t3-offline-psk-rev5", dnsPort, unlockDNS.Addr(), normalDNS.Addr(), true)
	if err := srv.SendEnvelope("server.config_sync", "s5", sync5); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 5
	}); !ok {
		t.Fatalf("expected config_applied rev 5")
	}

	if err := ag1.Stop(); err != nil {
		t.Fatalf("ag1.Stop: %v", err)
	}
	srv.Stop()

	// Cold-start ag2 while panel is completely unreachable
	ag2 := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    "nd_live_t3_offline_restore",
		DataDir:      dataDir,
		LocalDNSPort: dnsPort,
		StatsPort:    statsPort,
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})
	_ = ag2

	t3_waitUntil(t, 10*time.Second, "all 3 kernels booted offline from cached config", func() bool {
		return kernels.LiveProcessCount("snell-server") == 1 &&
			kernels.LiveProcessCount("shadow-tls") == 1 &&
			kernels.LiveProcessCount("sing-box") == 1
	})

	snellConf, err := os.ReadFile(filepath.Join(dataDir, "configs", "snell-server.conf"))
	if err != nil || !strings.Contains(string(snellConf), "t3-offline-psk-rev5") {
		t.Fatalf("offline snell-server.conf mismatch: err=%v conf=%s", err, string(snellConf))
	}
	sbConf, err := os.ReadFile(filepath.Join(dataDir, "configs", "sing-box.json"))
	if err != nil || !strings.Contains(string(sbConf), `"alice"`) {
		t.Fatalf("offline sing-box.json mismatch: err=%v conf=%s", err, string(sbConf))
	}
	resp := t3_dnsExchange(t, fmt.Sprintf("127.0.0.1:%d", dnsPort), "udp", "netflix.com.", dns.TypeA)
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "203.0.113.77" {
		t.Fatalf("offline DNS unlock failed: %+v", resp)
	}
}

// 7. F05 + F06: DNS unlock shared across Snell + sing-box; stop_ss_only keeps Snell using DNS unlock
func TestTier3_F05_F06_SharedDNSUnlockAndStopSSOnlyIsolation(t *testing.T) {
	env := NewTestEnv(t)
	srv := t3_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	unlockSrv := StartMockDNSServer(t, MockDNSOptions{
		Records:      map[string][]string{"netflix.com": {"203.0.113.55"}, "openai.com": {"203.0.113.56"}, "www.disneyplus.com": {"203.0.113.57"}},
		AAAARecords:  map[string][]string{"netflix.com": {"2001:db8::55"}},
		HTTPSRecords: map[string]bool{"netflix.com": true},
	})
	normalSrv := StartMockDNSServer(t, MockDNSOptions{
		Records: map[string][]string{"example.org": {"198.51.100.10"}, "api.openai.com": {"198.51.100.11"}, "disneyplus.com": {"198.51.100.12"}},
	})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    "nd_live_t3_f05_f06",
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})
	if !srv.WaitForHelloCount(1, 8*time.Second) {
		t.Fatalf("expected agent.hello")
	}

	sync1 := t3_baseSyncPayload(t, 1, "t3-dns-psk", ag.LocalDNSPort, unlockSrv.Addr(), normalSrv.Addr(), true)
	if err := srv.SendEnvelope("server.config_sync", "s1", sync1); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 1
	}); !ok {
		t.Fatalf("expected config_applied rev 1")
	}

	snellPID1 := kernels.RunningPIDs("snell-server")[0]
	stlsPID1 := kernels.RunningPIDs("shadow-tls")[0]

	dnsAddr := fmt.Sprintf("127.0.0.1:%d", ag.LocalDNSPort)
	if r := t3_dnsExchange(t, dnsAddr, "udp", "netflix.com.", dns.TypeA); len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "203.0.113.55" {
		t.Fatalf("expected netflix.com A via unlockSrv, got %+v", r)
	}
	if r := t3_dnsExchange(t, dnsAddr, "udp", "netflix.com.", dns.TypeAAAA); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Fatalf("expected empty NODATA for AAAA, got %+v", r)
	}

	// Push stop_ss_only (SS.Enabled=false, Snell.Enabled=true)
	sync2 := sync1
	sync2.ConfigRevision = 2
	sync2.SS.Enabled = false
	if err := srv.SendEnvelope("server.config_sync", "s2", sync2); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 2
	}); !ok {
		t.Fatalf("expected config_applied rev 2")
	}

	if kernels.LiveProcessCount("sing-box") != 0 {
		t.Fatalf("expected sing-box stopped on stop_ss_only, got %v", kernels.RunningPIDs("sing-box"))
	}
	if got := kernels.RunningPIDs("snell-server"); len(got) != 1 || got[0] != snellPID1 {
		t.Fatalf("snell-server PID changed on stop_ss_only: before=%d after=%v", snellPID1, got)
	}
	if got := kernels.RunningPIDs("shadow-tls"); len(got) != 1 || got[0] != stlsPID1 {
		t.Fatalf("shadow-tls PID changed on stop_ss_only: before=%d after=%v", stlsPID1, got)
	}

	// Shared DNS unlock continues serving Snell after sing-box stops
	if r := t3_dnsExchange(t, dnsAddr, "tcp", "openai.com.", dns.TypeA); len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "203.0.113.56" {
		t.Fatalf("expected openai.com via unlockSrv while sing-box stopped, got %+v", r)
	}
	if r := t3_dnsExchange(t, dnsAddr, "udp", "api.openai.com.", dns.TypeA); len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "198.51.100.11" {
		t.Fatalf("expected api.openai.com via normalSrv while sing-box stopped, got %+v", r)
	}
}

// 8. F05 + F10: User added/removed/expired hot-syncs ONLY sing-box while snell-server/shadow-tls PIDs stay untouched
func TestTier3_F05_F10_UserLifecycleHotSyncsSingBoxOnly(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")
	kernels := BuildMockKernels(t, MockKernelOptions{})

	node := t3_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:    "T3-UserHotSync",
		Enabled: t3_boolPtr(true),
		SnellConfig: &SnellConfigDTO{
			Enabled: true, Version: "v5",
			PublicPort: AllocFreePort(t), InnerPort: AllocFreePort(t),
			PSK: "t3-hotsync-psk", Obfs: "off", STLSPassword: "t3-hotsync-stls", STLSSNI: "gateway.icloud.com",
		},
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: AllocFreePort(t), UDPPort: AllocFreeUDPPort(t),
			Cipher: "2022-blake3-aes-128-gcm", IPSK: t3_b64Key16("t3-hotsync-ipsk!"), STLSSNI: "swscan.apple.com",
		},
	})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     panel.WSBaseURL(),
		NodeToken:    node.EffectiveToken(),
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	t3_waitUntil(t, 12*time.Second, "all 3 kernels running", func() bool {
		return kernels.LiveProcessCount("snell-server") == 1 &&
			kernels.LiveProcessCount("shadow-tls") == 1 &&
			kernels.LiveProcessCount("sing-box") == 1
	})
	snellPID := kernels.RunningPIDs("snell-server")[0]
	stlsPID := kernels.RunningPIDs("shadow-tls")[0]
	sbPID1 := kernels.RunningPIDs("sing-box")[0]

	// Add user -> sing-box reloads with user, Snell & shadow-tls PIDs untouched
	u := t3_mustCreateUser(t, client, jwt, CreateUserReq{
		Username: "t3_hot_user",
		Enabled:  t3_boolPtr(true),
		NodeIDs:  []int64{node.ID},
	})
	sbCfgPath := filepath.Join(ag.DataDir, "configs", "sing-box.json")
	t3_waitUntil(t, 10*time.Second, "sing-box.json includes t3_hot_user", func() bool {
		b, err := os.ReadFile(sbCfgPath)
		return err == nil && strings.Contains(string(b), `"t3_hot_user"`)
	})
	t3_waitUntil(t, 5*time.Second, "sing-box reloaded with new PID", func() bool {
		pids := kernels.RunningPIDs("sing-box")
		return len(pids) == 1 && pids[0] != sbPID1
	})
	sbPID2 := kernels.RunningPIDs("sing-box")[0]

	if got := kernels.RunningPIDs("snell-server"); len(got) != 1 || got[0] != snellPID {
		t.Fatalf("snell-server PID interrupted on user add: before=%d after=%v", snellPID, got)
	}
	if got := kernels.RunningPIDs("shadow-tls"); len(got) != 1 || got[0] != stlsPID {
		t.Fatalf("shadow-tls PID interrupted on user add: before=%d after=%v", stlsPID, got)
	}

	// Expire user -> sing-box reloads without user, Snell & shadow-tls STILL untouched
	past := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
	if st, _, raw, err := client.UpdateUser(jwt, u.ID, CreateUserReq{
		Username:        "t3_hot_user",
		Enabled:         t3_boolPtr(true),
		BillingResetDay: 1,
		ExpireAt:        &past,
	}); err != nil || st != http.StatusOK {
		t.Fatalf("UpdateUser expire failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	t3_waitUntil(t, 10*time.Second, "sing-box.json removes expired t3_hot_user", func() bool {
		b, err := os.ReadFile(sbCfgPath)
		return err == nil && !strings.Contains(string(b), `"t3_hot_user"`)
	})
	t3_waitUntil(t, 5*time.Second, "sing-box reloaded after expiry", func() bool {
		pids := kernels.RunningPIDs("sing-box")
		return len(pids) == 1 && pids[0] != sbPID2
	})
	if got := kernels.RunningPIDs("snell-server"); len(got) != 1 || got[0] != snellPID {
		t.Fatalf("snell-server PID interrupted on user expire: before=%d after=%v", snellPID, got)
	}
	if got := kernels.RunningPIDs("shadow-tls"); len(got) != 1 || got[0] != stlsPID {
		t.Fatalf("shadow-tls PID interrupted on user expire: before=%d after=%v", stlsPID, got)
	}
}

// 9. F06 + F09: Updating DNS rule group on panel pushes updated unlock rules via server.config_sync
func TestTier3_F06_F09_DNSRuleGroupUpdateConfigSync(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	stGrp, grp, rawGrp, err := client.CreateDNSRuleGroup(jwt, "T3-StreamGroup", []string{"netflix.com"})
	if err != nil || (stGrp != http.StatusOK && stGrp != http.StatusCreated) {
		t.Fatalf("CreateDNSRuleGroup failed: st=%d err=%v body=%s", stGrp, err, string(rawGrp))
	}
	node := t3_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:             "T3-DNSGroupNode",
		Enabled:          t3_boolPtr(true),
		DNSUnlockEnabled: true,
		DNSUnlockServer:  "198.51.100.53:3535",
		DNSRuleGroupID:   &grp.ID,
		ExtraDNSRules:    []string{"^openai.com"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, sync1 := t3_dialAgentHelloAndSync(t, ctx, client, node.EffectiveToken(), "amd64")
	joined1 := strings.Join(sync1.DNS.Rules, ",")
	if !strings.Contains(joined1, "netflix.com") || !strings.Contains(joined1, "^openai.com") {
		t.Fatalf("expected initial rules netflix.com & ^openai.com, got %+v", sync1.DNS.Rules)
	}

	// Update DNS rule group
	stPut, rawPut, err := client.DoJSON(ctx, http.MethodPut, fmt.Sprintf("/api/v1/admin/dns-rules/%d", grp.ID), jwt, map[string]any{
		"name":  "T3-StreamGroup-Updated",
		"rules": []string{"netflix.com", "*.disneyplus.com"},
	}, nil)
	if err != nil || stPut >= 300 {
		t.Fatalf("PUT dns-rules failed: st=%d err=%v body=%s", stPut, err, string(rawPut))
	}

	sync2 := t3_waitConfigSync(t, ctx, conn, 6*time.Second, func(p ServerConfigSyncPayload) bool {
		joined := strings.Join(p.DNS.Rules, ",")
		return p.ConfigRevision > sync1.ConfigRevision && strings.Contains(joined, "*.disneyplus.com") && strings.Contains(joined, "^openai.com")
	}, "updated DNS rule group synced to agent")
	if !sync2.DNS.UnlockEnabled || sync2.DNS.UnlockServer != "198.51.100.53:3535" {
		t.Fatalf("unexpected DNS config after rule group update: %+v", sync2.DNS)
	}
}

// 10. F07 + F11: traffic_count_mode applied to real agent /proc/net/dev deltas triggers pause
func TestTier3_F07_F11_TrafficCountModesWithAgentDeltasTriggerPause(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")
	kernels := BuildMockKernels(t, MockKernelOptions{})
	procPath := WriteProcNetDevFixture(t, "eth0", 1000, 1000)

	snellPub := AllocFreePort(t)
	snellIn := AllocFreePort(t)
	ssPort := AllocFreePort(t)
	ssUDP := AllocFreeUDPPort(t)
	ipsk := t3_b64Key16("t3-f07-f11-ipsk!")

	node := t3_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:                  "T3-Mode-Agent-Node",
		Enabled:               t3_boolPtr(true),
		TrafficLimitBytes:     20000,
		TrafficThresholdBytes: 5000,
		TrafficCountMode:      "tx_only",
		ThresholdAction:       "stop_all",
		BillingResetDay:       1,
		SnellConfig: &SnellConfigDTO{
			Enabled: true, Version: "v5", PublicPort: snellPub, InnerPort: snellIn,
			PSK: "t3-mode-psk", STLSPassword: "t3-mode-stls", STLSSNI: "gateway.icloud.com",
		},
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: ssPort, UDPPort: ssUDP,
			Cipher: "2022-blake3-aes-128-gcm", IPSK: ipsk, STLSSNI: "swscan.apple.com",
		},
	})

	_ = StartAgent(env, AgentConfig{
		PanelURL:       panel.WSBaseURL(),
		NodeToken:      node.EffectiveToken(),
		Iface:          "eth0",
		ProcNetDevPath: procPath,
		SnellBin:       kernels.SnellBin,
		ShadowTLSBin:   kernels.ShadowTLSBin,
		SingBoxBin:     kernels.SingBoxBin,
	})

	// Wait for node online and baseline metrics collected
	t3_waitUntil(t, 15*time.Second, "node online with baseline telemetry", func() bool {
		_, got, _, err := client.GetNode(jwt, node.ID)
		return err == nil && got.Status == "online" && kernels.LiveProcessCount("sing-box") == 1
	})
	time.Sleep(1500 * time.Millisecond)

	// In tx_only mode, huge RX (+50000) with small TX (+2000) must NOT pause!
	UpdateProcNetDevFixture(t, procPath, "eth0", 51000, 3000)
	t3_waitUntil(t, 15*time.Second, "tx_only rx=50000 tx=2000 persisted without pause", func() bool {
		_, got, _, err := client.GetNode(jwt, node.ID)
		return err == nil && got.CycleRxBytes >= 50000 && got.CycleTxBytes >= 2000
	})
	_, midNode, _, _ := client.GetNode(jwt, node.ID)
	if midNode.IsTrafficPaused {
		t.Fatalf("tx_only mode should NOT pause on RX=50000 when TX=2000 < 5000: %+v", midNode)
	}

	// Increment TX past threshold (+4000 -> total TX=6000 >= 5000) -> MUST pause and stop all 3 kernels
	UpdateProcNetDevFixture(t, procPath, "eth0", 51000, 7000)
	t3_waitUntil(t, 15*time.Second, "tx_only TX>=5000 triggers traffic_paused", func() bool {
		_, got, _, err := client.GetNode(jwt, node.ID)
		return err == nil && got.IsTrafficPaused && got.Status == "traffic_paused"
	})
	t3_waitUntil(t, 10*time.Second, "all 3 kernels stopped by stop_all", func() bool {
		return kernels.LiveProcessCount("snell-server") == 0 &&
			kernels.LiveProcessCount("shadow-tls") == 0 &&
			kernels.LiveProcessCount("sing-box") == 0
	})

	// Switch to max_dir + ResetNodeTraffic -> check max_dir (rx=4000, tx=6000 -> counted=6000 >= 5000) pauses
	if st, raw, err := client.ResetNodeTraffic(jwt, node.ID); err != nil || st >= 300 {
		t.Fatalf("ResetNodeTraffic failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	if st, _, raw, err := client.UpdateNode(jwt, node.ID, CreateNodeReq{
		Name:                  "T3-Mode-Agent-Node",
		Enabled:               t3_boolPtr(true),
		TrafficLimitBytes:     20000,
		TrafficThresholdBytes: 5000,
		TrafficCountMode:      "max_dir",
		ThresholdAction:       "stop_all",
		BillingResetDay:       1,
		SnellConfig:           &SnellConfigDTO{Enabled: true, Version: "v5", PublicPort: snellPub, InnerPort: snellIn, PSK: "t3-mode-psk", STLSPassword: "t3-mode-stls", STLSSNI: "gateway.icloud.com"},
		SSConfig:              &SSConfigDTO{Enabled: true, TCPPort: ssPort, UDPPort: ssUDP, Cipher: "2022-blake3-aes-128-gcm", IPSK: ipsk, STLSSNI: "swscan.apple.com"},
	}); err != nil || st != http.StatusOK {
		t.Fatalf("UpdateNode max_dir failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	t3_waitUntil(t, 10*time.Second, "kernels restarted before max_dir check", func() bool {
		return kernels.LiveProcessCount("sing-box") == 1
	})

	UpdateProcNetDevFixture(t, procPath, "eth0", 55000, 13000) // +4000 rx, +6000 tx => max_dir=6000 >= 5000
	t3_waitUntil(t, 15*time.Second, "max_dir triggers pause", func() bool {
		_, got, _, err := client.GetNode(jwt, node.ID)
		return err == nil && got.IsTrafficPaused
	})
}

// 11. F08 + F13: Panel kernel center batch/single update -> agent download/verify/3s check -> rollback on faulty binary
func TestTier3_F08_F13_KernelCenterUpdateAndFaultyBinaryRollback(t *testing.T) {
	crashBytes := BuildMockKernelVariant(t, "sing-box", "sing-box version 9.9.9-crash", true)
	goodBytes := BuildMockKernelVariant(t, "sing-box", "sing-box version 1.12.0", false)
	crashAsset := "sing-box-9.9.9-linux-amd64.tar.gz"
	goodAsset := "sing-box-1.12.0-linux-amd64.tar.gz"

	gh := StartMockGitHubServer(t, MockGitHubOptions{
		Releases: []MockGitHubRelease{
			{
				Owner: "SagerNet", Repo: "sing-box", TagName: "v1.12.0",
				Assets: []MockGitHubAsset{
					{Name: goodAsset, Archive: true, BinaryName: "sing-box", Payload: goodBytes},
				},
			},
			{
				Owner: "SagerNet", Repo: "sing-box", TagName: "v9.9.9",
				Assets: []MockGitHubAsset{
					{Name: crashAsset, Archive: true, BinaryName: "sing-box", Payload: crashBytes},
				},
			},
			{
				Owner: "ihciah", Repo: "shadow-tls", TagName: "v0.2.25",
				Assets: []MockGitHubAsset{
					{Name: "shadow-tls-x86_64-unknown-linux-musl", Payload: []byte("mock")},
				},
			},
		},
	})

	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{ExtraEnv: []string{"GITHUB_API_URL=" + gh.URL()}})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")
	kernels := BuildMockKernels(t, MockKernelOptions{})

	node := t3_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:    "T3-KernelRollback",
		Enabled: t3_boolPtr(true),
		SnellConfig: &SnellConfigDTO{
			Enabled: true, Version: "v5", PublicPort: AllocFreePort(t), InnerPort: AllocFreePort(t),
			PSK: "t3-kr-psk", STLSPassword: "t3-kr-stls", STLSSNI: "gateway.icloud.com",
		},
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: AllocFreePort(t), UDPPort: AllocFreeUDPPort(t),
			Cipher: "2022-blake3-aes-128-gcm", IPSK: t3_b64Key16("t3-kr-ipsk!!!!!!"), STLSSNI: "swscan.apple.com",
		},
	})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     panel.WSBaseURL(),
		NodeToken:    node.EffectiveToken(),
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})
	_ = ag

	t3_waitUntil(t, 12*time.Second, "node online with all 3 kernels", func() bool {
		_, n, _, err := client.GetNode(jwt, node.ID)
		return err == nil && n.Status == "online" && kernels.LiveProcessCount("sing-box") == 1
	})

	// Sync GitHub releases in Kernel Center
	if st, raw, err := client.DoJSON(context.Background(), http.MethodPost, "/api/v1/admin/kernels/sync", jwt, nil, nil); err != nil || st >= 300 {
		t.Fatalf("POST kernels/sync failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	// Dispatch faulty crashOnStart binary -> agent must attempt 9.9.9-crash, fail startup, and rollback to 1.11.4
	invBeforeCrash := len(kernels.Invocations("sing-box"))
	if st, raw, err := client.TriggerKernelUpdate(jwt, []int64{node.ID}, "sing-box", "9.9.9-crash", gh.AssetURL(crashAsset), gh.AssetSHA256(crashAsset)); err != nil || st >= 300 {
		t.Fatalf("TriggerKernelUpdate faulty failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	t3_waitUntil(t, 20*time.Second, "faulty sing-box attempted, crashed, rolled back to 1.11.4 and running", func() bool {
		if _, err := os.Stat(kernels.SingBoxBin + ".bak"); err != nil {
			return false
		}
		invs := kernels.Invocations("sing-box")
		startIdx := invBeforeCrash
		if startIdx > len(invs) {
			startIdx = len(invs)
		}
		sawCrashExit := false
		for _, inv := range invs[startIdx:] {
			if inv.Event == "exit" && inv.ExitCode == 2 {
				sawCrashExit = true
				break
			}
		}
		if !sawCrashExit {
			return false
		}
		out, err := exec.Command(kernels.SingBoxBin, "version").CombinedOutput()
		if err != nil || !strings.Contains(string(out), "1.11.4") {
			return false
		}
		if kernels.LiveProcessCount("sing-box") != 1 {
			return false
		}
		st, _, nodeRaw, err := client.GetNode(jwt, node.ID)
		if err != nil || st != http.StatusOK {
			return false
		}
		var nodeDetail struct {
			Status           string           `json:"status"`
			ReportedVersions AgentVersionsDTO `json:"reported_versions"`
		}
		if err := json.Unmarshal(nodeRaw, &nodeDetail); err != nil {
			return false
		}
		return nodeDetail.Status == "online" && strings.Contains(nodeDetail.ReportedVersions.SingBox, "1.11.4")
	})

	// Dispatch valid 1.12.0 binary -> succeeds, survives 3s observeHealth, and updates reported version
	if st, raw, err := client.TriggerKernelUpdate(jwt, []int64{node.ID}, "sing-box", "1.12.0", gh.AssetURL(goodAsset), gh.AssetSHA256(goodAsset)); err != nil || st >= 300 {
		t.Fatalf("TriggerKernelUpdate good failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	t3_waitUntil(t, 20*time.Second, "valid sing-box 1.12.0 installed, running, and reported_versions updated", func() bool {
		st, _, nodeRaw, err := client.GetNode(jwt, node.ID)
		if err != nil || st != http.StatusOK {
			return false
		}
		var nodeDetail struct {
			Status           string           `json:"status"`
			ReportedVersions AgentVersionsDTO `json:"reported_versions"`
		}
		if err := json.Unmarshal(nodeRaw, &nodeDetail); err != nil {
			return false
		}
		if nodeDetail.Status != "online" || !strings.Contains(nodeDetail.ReportedVersions.SingBox, "1.12.0") {
			return false
		}
		out, err := exec.Command(kernels.SingBoxBin, "version").CombinedOutput()
		if err != nil || !strings.Contains(string(out), "1.12.0") {
			return false
		}
		return kernels.LiveProcessCount("sing-box") == 1
	})
}

// 12. F08 + F14: Failed kernel update rollback triggers webhook alert; subsequent valid update emits resolved notification
func TestTier3_F08_F14_KernelRollbackAlertAndResolvedWebhook(t *testing.T) {
	crashBytes := BuildMockKernelVariant(t, "sing-box", "sing-box version 9.9.9-crash", true)
	goodBytes := BuildMockKernelVariant(t, "sing-box", "sing-box version 1.12.1", false)
	crashAsset := "sing-box-9.9.9-crash.tar.gz"
	goodAsset := "sing-box-1.12.1.tar.gz"

	gh := StartMockGitHubServer(t, MockGitHubOptions{
		Releases: []MockGitHubRelease{{
			Owner: "SagerNet", Repo: "sing-box", TagName: "v1.12.1",
			Assets: []MockGitHubAsset{
				{Name: crashAsset, Archive: true, BinaryName: "sing-box", Payload: crashBytes},
				{Name: goodAsset, Archive: true, BinaryName: "sing-box", Payload: goodBytes},
			},
		}},
	})
	whSrv := StartMockWebhookServer(t)

	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{ExtraEnv: []string{"GITHUB_API_URL=" + gh.URL()}})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")
	kernels := BuildMockKernels(t, MockKernelOptions{})

	if st, _, raw, err := client.CreateWebhook(jwt, WebhookChannelDTO{
		Name:             "T3 Kernel Alert Hook",
		Provider:         "custom",
		URL:              whSrv.URL(),
		SubscribedEvents: []string{"kernel_update"},
		Enabled:          true,
	}); err != nil || st >= 300 {
		t.Fatalf("CreateWebhook failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	node := t3_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:    "T3-KernelWebhookNode",
		Enabled: t3_boolPtr(true),
		SnellConfig: &SnellConfigDTO{
			Enabled: true, Version: "v5", PublicPort: AllocFreePort(t), InnerPort: AllocFreePort(t),
			PSK: "t3-kw-psk", STLSPassword: "t3-kw-stls", STLSSNI: "gateway.icloud.com",
		},
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: AllocFreePort(t), UDPPort: AllocFreeUDPPort(t),
			Cipher: "2022-blake3-aes-128-gcm", IPSK: t3_b64Key16("t3-kw-ipsk!!!!!!"), STLSSNI: "swscan.apple.com",
		},
	})

	_ = StartAgent(env, AgentConfig{
		PanelURL:     panel.WSBaseURL(),
		NodeToken:    node.EffectiveToken(),
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})
	t3_waitUntil(t, 12*time.Second, "node online", func() bool {
		_, n, _, err := client.GetNode(jwt, node.ID)
		return err == nil && n.Status == "online" && kernels.LiveProcessCount("sing-box") == 1
	})

	// 1. Trigger faulty update -> rollback + failure webhook
	if st, raw, err := client.TriggerKernelUpdate(jwt, []int64{node.ID}, "sing-box", "9.9.9-crash", gh.AssetURL(crashAsset), gh.AssetSHA256(crashAsset)); err != nil || st >= 300 {
		t.Fatalf("TriggerKernelUpdate crash failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	reqs1, ok1 := whSrv.WaitForRequests(1, 20*time.Second)
	if !ok1 || len(reqs1) < 1 {
		t.Fatalf("expected kernel_update failure webhook, got %d", len(reqs1))
	}
	var p1 struct {
		Type     string `json:"type"`
		Resolved bool   `json:"resolved"`
	}
	if err := json.Unmarshal([]byte(reqs1[0].Body), &p1); err != nil || p1.Type != "kernel_update" || p1.Resolved {
		t.Fatalf("expected kernel_update resolved=false alert, got %+v raw=%s", p1, reqs1[0].Body)
	}

	// 2. Trigger valid update -> resolved webhook
	if st, raw, err := client.TriggerKernelUpdate(jwt, []int64{node.ID}, "sing-box", "1.12.1", gh.AssetURL(goodAsset), gh.AssetSHA256(goodAsset)); err != nil || st >= 300 {
		t.Fatalf("TriggerKernelUpdate good failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	reqs2, ok2 := whSrv.WaitForRequests(2, 20*time.Second)
	if !ok2 || len(reqs2) < 2 {
		t.Fatalf("expected kernel_update resolved webhook, got %d", len(reqs2))
	}
	var p2 struct {
		Type     string `json:"type"`
		Resolved bool   `json:"resolved"`
	}
	if err := json.Unmarshal([]byte(reqs2[1].Body), &p2); err != nil || p2.Type != "kernel_update" || !p2.Resolved {
		t.Fatalf("expected kernel_update resolved=true notification, got %+v raw=%s", p2, reqs2[1].Body)
	}
}

// 13. F09 + F12: Custom entry host/port & node sort order reflected in both /s/admin/<token> and /s/u/<token>
func TestTier3_F09_F12_CustomEntryAndSortOrderInDualSubscriptions(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	nLate := t3_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:            "Node-Custom-Late",
		RegionTag:       "JP",
		PublicIP:        "203.0.113.10",
		CustomEntryHost: "cdn-entry.example.com",
		CustomEntryPort: 1443,
		SortOrder:       20,
		Enabled:         t3_boolPtr(true),
		SnellConfig: &SnellConfigDTO{
			Enabled: true, Version: "v5", PublicPort: 26001, InnerPort: 31001,
			PSK: "PSK_LATE", STLSPassword: "STLS_LATE", STLSSNI: "gateway.icloud.com",
		},
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: 26002, UDPPort: 26002,
			Cipher: "2022-blake3-aes-128-gcm", IPSK: t3_b64Key16("t3-late-ipsk!!!!"), STLSSNI: "swscan.apple.com",
		},
	})
	nEarly := t3_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:      "Node-Direct-Early",
		RegionTag: "SG",
		PublicIP:  "203.0.113.20",
		SortOrder: 10,
		Enabled:   t3_boolPtr(true),
		SnellConfig: &SnellConfigDTO{
			Enabled: true, Version: "v5", PublicPort: 27001, InnerPort: 31002,
			PSK: "PSK_EARLY", STLSPassword: "STLS_EARLY", STLSSNI: "gateway.icloud.com",
		},
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: 27002, UDPPort: 27002,
			Cipher: "2022-blake3-aes-128-gcm", IPSK: t3_b64Key16("t3-early-ipsk!!!"), STLSSNI: "swscan.apple.com",
		},
	})
	user := t3_mustCreateUser(t, client, jwt, CreateUserReq{
		Username: "t3_order_user",
		NodeIDs:  []int64{nLate.ID, nEarly.ID},
	})
	adminTok := t3_getAdminSubToken(t, client, jwt)

	// Verify initial order (Early before Late) and custom entry host/port in both subscriptions
	stA, _, bodyA, err := client.GetAdminSub(adminTok, "mode=proxy")
	if err != nil || stA != http.StatusOK {
		t.Fatalf("GetAdminSub failed: st=%d err=%v", stA, err)
	}
	if !strings.Contains(bodyA, "cdn-entry.example.com, 1443") {
		t.Fatalf("admin sub missing custom entry host/port:\n%s", bodyA)
	}
	if strings.Index(bodyA, "Node-Direct-Early") > strings.Index(bodyA, "Node-Custom-Late") {
		t.Fatalf("admin sub order wrong, expected Early before Late:\n%s", bodyA)
	}

	stU, _, bodyU, err := client.GetUserSub(user.SubToken, "target=mihomo&mode=proxy", "")
	if err != nil || stU != http.StatusOK {
		t.Fatalf("GetUserSub failed: st=%d err=%v", stU, err)
	}
	var doc struct {
		Proxies []struct {
			Name   string `yaml:"name"`
			Server string `yaml:"server"`
			Port   int    `yaml:"port"`
		} `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(bodyU), &doc); err != nil || len(doc.Proxies) != 2 {
		t.Fatalf("invalid Mihomo YAML: err=%v body=%s", err, bodyU)
	}
	if !strings.Contains(doc.Proxies[0].Name, "Node-Direct-Early") ||
		!strings.Contains(doc.Proxies[1].Name, "Node-Custom-Late") ||
		doc.Proxies[1].Server != "cdn-entry.example.com" || doc.Proxies[1].Port != 1443 {
		t.Fatalf("unexpected initial user sub order/custom entry: %+v", doc.Proxies)
	}

	// Reorder nodes [nLate, nEarly]
	if stR, rawR, err := client.ReorderNodes(jwt, []int64{nLate.ID, nEarly.ID}); err != nil || stR >= 300 {
		t.Fatalf("ReorderNodes failed: st=%d err=%v body=%s", stR, err, string(rawR))
	}

	_, _, bodyA2, _ := client.GetAdminSub(adminTok, "mode=proxy")
	if strings.Index(bodyA2, "Node-Custom-Late") > strings.Index(bodyA2, "Node-Direct-Early") {
		t.Fatalf("admin sub did not reflect ReorderNodes:\n%s", bodyA2)
	}
	_, _, bodyU2, _ := client.GetUserSub(user.SubToken, "target=mihomo&mode=proxy", "")
	var doc2 struct {
		Proxies []struct {
			Name string `yaml:"name"`
		} `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(bodyU2), &doc2); err != nil || len(doc2.Proxies) != 2 {
		t.Fatalf("invalid reordered Mihomo YAML: err=%v body=%s", err, bodyU2)
	}
	if !strings.Contains(doc2.Proxies[0].Name, "Node-Custom-Late") || !strings.Contains(doc2.Proxies[1].Name, "Node-Direct-Early") {
		t.Fatalf("user sub did not reflect ReorderNodes: %+v", doc2.Proxies)
	}
}

// 14. F10 + F12: User node authorization matrix + quota/expiry reflected in /s/u/<token> & Subscription-Userinfo
func TestTier3_F10_F12_UserAccessMatrixQuotaExpiryInSubscription(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	n1 := t3_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name: "T3-Matrix-N1", PublicIP: "203.0.113.31", Enabled: t3_boolPtr(true),
		SSConfig: &SSConfigDTO{Enabled: true, TCPPort: 28001, UDPPort: 28001, Cipher: "2022-blake3-aes-128-gcm", IPSK: t3_b64Key16("t3-m1-ipsk!!!!!!"), STLSSNI: "swscan.apple.com"},
	})
	n2 := t3_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name: "T3-Matrix-N2", PublicIP: "203.0.113.32", Enabled: t3_boolPtr(true),
		SSConfig: &SSConfigDTO{Enabled: true, TCPPort: 28002, UDPPort: 28002, Cipher: "2022-blake3-aes-128-gcm", IPSK: t3_b64Key16("t3-m2-ipsk!!!!!!"), STLSSNI: "swscan.apple.com"},
	})

	expTime := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	expStr := expTime.Format(time.RFC3339)
	user := t3_mustCreateUser(t, client, jwt, CreateUserReq{
		Username:          "t3_matrix_sub_user",
		TrafficQuotaBytes: 5000,
		ExpireAt:          &expStr,
		NodeIDs:           []int64{n1.ID},
	})

	// Authorized on N1 only
	st1, hdr1, body1, err := client.GetUserSub(user.SubToken, "target=mihomo", "")
	if err != nil || st1 != http.StatusOK {
		t.Fatalf("GetUserSub initial failed: st=%d err=%v body=%s", st1, err, body1)
	}
	if !strings.Contains(body1, "T3-Matrix-N1") || strings.Contains(body1, "T3-Matrix-N2") {
		t.Fatalf("expected only N1 in sub, got:\n%s", body1)
	}
	wantHdr1 := fmt.Sprintf("upload=0; download=0; total=5000; expire=%d", expTime.Unix())
	if hdr1.Get("Subscription-Userinfo") != wantHdr1 {
		t.Fatalf("Subscription-Userinfo mismatch: got %q want %q", hdr1.Get("Subscription-Userinfo"), wantHdr1)
	}

	// Grant N2 as well
	if st, raw, err := client.SetUserNodes(jwt, user.ID, []int64{n1.ID, n2.ID}); err != nil || st >= 300 {
		t.Fatalf("SetUserNodes failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	_, _, body2, _ := client.GetUserSub(user.SubToken, "target=mihomo", "")
	if !strings.Contains(body2, "T3-Matrix-N1") || !strings.Contains(body2, "T3-Matrix-N2") {
		t.Fatalf("expected both N1 and N2 in sub after matrix grant:\n%s", body2)
	}

	// Exhaust quota via agent metrics
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, _ := t3_dialAgentHelloAndSync(t, ctx, client, n1.EffectiveToken(), "amd64")
	if err := SendWSEnvelope(ctx, conn, "agent.metrics", "m-quota", AgentMetricsPayload{
		TS:         time.Now().Unix(),
		UserDeltas: []UserTrafficDeltaDTO{{Username: user.Username, UserID: user.ID, UpBytes: 2000, DownBytes: 3000}},
		Health:     AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}
	t3_waitUntil(t, 5*time.Second, "user quota exhausted persisted", func() bool {
		_, u, _, _ := client.GetUser(jwt, user.ID)
		return u.UsedUpBytes == 2000 && u.UsedDownBytes == 3000
	})
	stExh, hdrExh, _, _ := client.GetUserSub(user.SubToken, "target=mihomo", "")
	if stExh != http.StatusForbidden && stExh != http.StatusNotFound {
		t.Fatalf("expected 403/404 for exhausted user sub, got %d", stExh)
	}
	wantExh := fmt.Sprintf("upload=2000; download=3000; total=5000; expire=%d", expTime.Unix())
	if hdrExh.Get("Subscription-Userinfo") != wantExh {
		t.Fatalf("exhausted Subscription-Userinfo mismatch: got %q want %q", hdrExh.Get("Subscription-Userinfo"), wantExh)
	}

	// Reset traffic -> 200 OK; then expire user -> 403/404
	if st, raw, err := client.ResetUserTraffic(jwt, user.ID); err != nil || st >= 300 {
		t.Fatalf("ResetUserTraffic failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	if stOk, _, _, _ := client.GetUserSub(user.SubToken, "target=mihomo", ""); stOk != http.StatusOK {
		t.Fatalf("expected 200 after ResetUserTraffic, got %d", stOk)
	}
	pastStr := time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
	if stUpd, _, rawUpd, err := client.UpdateUser(jwt, user.ID, CreateUserReq{
		Username: user.Username, Enabled: t3_boolPtr(true), TrafficQuotaBytes: 5000, ExpireAt: &pastStr,
	}); err != nil || stUpd != http.StatusOK {
		t.Fatalf("UpdateUser past expire failed: st=%d err=%v body=%s", stUpd, err, string(rawUpd))
	}
	if stExp, _, _, _ := client.GetUserSub(user.SubToken, "target=mihomo", ""); stExp != http.StatusForbidden && stExp != http.StatusNotFound {
		t.Fatalf("expected 403/404 for expired user sub, got %d", stExp)
	}
}

// 15. F11 + F12: stop_all omits node from BOTH admin & user subs; stop_ss_only omits from user sub ONLY
func TestTier3_F11_F12_StopAllVsStopSSOnlySubscriptionFiltering(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	nStopAll := t3_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name: "T3-Sub-StopAll", PublicIP: "203.0.113.41", Enabled: t3_boolPtr(true),
		TrafficLimitBytes: 2000, TrafficThresholdBytes: 1000, TrafficCountMode: "both", ThresholdAction: "stop_all",
		SnellConfig: &SnellConfigDTO{Enabled: true, Version: "v5", PublicPort: 29001, InnerPort: 31001, PSK: "T3_PSK_SA", STLSPassword: "STLS_SA", STLSSNI: "gateway.icloud.com"},
		SSConfig:    &SSConfigDTO{Enabled: true, TCPPort: 29002, UDPPort: 29002, Cipher: "2022-blake3-aes-128-gcm", IPSK: t3_b64Key16("t3-sa-ipsk!!!!!!"), STLSSNI: "swscan.apple.com"},
	})
	nStopSS := t3_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name: "T3-Sub-StopSSOnly", PublicIP: "203.0.113.42", Enabled: t3_boolPtr(true),
		TrafficLimitBytes: 2000, TrafficThresholdBytes: 1000, TrafficCountMode: "both", ThresholdAction: "stop_ss_only",
		SnellConfig: &SnellConfigDTO{Enabled: true, Version: "v5", PublicPort: 29101, InnerPort: 31002, PSK: "T3_PSK_SS", STLSPassword: "STLS_SS", STLSSNI: "gateway.icloud.com"},
		SSConfig:    &SSConfigDTO{Enabled: true, TCPPort: 29102, UDPPort: 29102, Cipher: "2022-blake3-aes-128-gcm", IPSK: t3_b64Key16("t3-ss-ipsk!!!!!!"), STLSSNI: "swscan.apple.com"},
	})
	user := t3_mustCreateUser(t, client, jwt, CreateUserReq{
		Username: "t3_pause_sub_user",
		NodeIDs:  []int64{nStopAll.ID, nStopSS.ID},
	})
	adminTok := t3_getAdminSubToken(t, client, jwt)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, n := range []NodeDTO{nStopAll, nStopSS} {
		conn, _ := t3_dialAgentHelloAndSync(t, ctx, client, n.EffectiveToken(), "amd64")
		if err := SendWSEnvelope(ctx, conn, "agent.metrics", "m-trip", AgentMetricsPayload{
			TS: time.Now().Unix(), NicRxDelta: 600, NicTxDelta: 600,
			Health: AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
		}); err != nil {
			t.Fatal(err)
		}
	}
	t3_waitUntil(t, 5*time.Second, "both nodes paused", func() bool {
		_, g1, _, _ := client.GetNode(jwt, nStopAll.ID)
		_, g2, _, _ := client.GetNode(jwt, nStopSS.ID)
		return g1.IsTrafficPaused && g2.IsTrafficPaused
	})

	// Admin sub omits stop_all, keeps stop_ss_only
	stA, _, bodyA, err := client.GetAdminSub(adminTok, "mode=proxy")
	if err != nil || stA != http.StatusOK {
		t.Fatalf("GetAdminSub failed: st=%d err=%v", stA, err)
	}
	if strings.Contains(bodyA, "T3-Sub-StopAll") || strings.Contains(bodyA, "T3_PSK_SA") {
		t.Fatalf("admin sub leaked stop_all node:\n%s", bodyA)
	}
	if !strings.Contains(bodyA, "T3-Sub-StopSSOnly") {
		t.Fatalf("admin sub must retain stop_ss_only Snell node:\n%s", bodyA)
	}

	// User sub omits BOTH
	for _, q := range []string{"target=mihomo", "target=surge", "target=shadowrocket"} {
		stU, _, bodyU, err := client.GetUserSub(user.SubToken, q, "")
		if err != nil || stU != http.StatusOK {
			t.Fatalf("GetUserSub(%s) failed: st=%d err=%v", q, stU, err)
		}
		check := bodyU
		if q == "target=shadowrocket" {
			dec, err := t3_decodeBase64Flexible(bodyU)
			if err != nil {
				t.Fatal(err)
			}
			check = string(dec)
		}
		if strings.Contains(check, "T3-Sub-StopAll") || strings.Contains(check, "T3-Sub-StopSSOnly") {
			t.Fatalf("user sub (%s) must omit both paused nodes:\n%s", q, check)
		}
	}

	// Reset stop_all -> reappears in both
	if st, raw, err := client.ResetNodeTraffic(jwt, nStopAll.ID); err != nil || st >= 300 {
		t.Fatalf("ResetNodeTraffic failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	_, _, bodyA2, _ := client.GetAdminSub(adminTok, "mode=proxy")
	_, _, bodyU2, _ := client.GetUserSub(user.SubToken, "target=mihomo", "")
	if !strings.Contains(bodyA2, "T3-Sub-StopAll") || !strings.Contains(bodyU2, "T3-Sub-StopAll") {
		t.Fatalf("reset node did not reappear in admin/user subs: adm=%s user=%s", bodyA2, bodyU2)
	}
}

// 16. F11 + F14: Threshold warning/pause triggers webhook + cooldown; reset triggers resolved notification
func TestTier3_F11_F14_TrafficThresholdCooldownAndResetResolved(t *testing.T) {
	whSrv := StartMockWebhookServer(t)
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	if st, raw, err := client.UpdateSettings(jwt, map[string]any{"alert_cooldown_minutes": 60}); err != nil || st >= 300 {
		t.Fatalf("UpdateSettings cooldown failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	if st, _, raw, err := client.CreateWebhook(jwt, WebhookChannelDTO{
		Name:             "T3 Feishu Threshold",
		Provider:         "feishu",
		URL:              whSrv.URL() + "/feishu",
		SubscribedEvents: []string{"traffic_warning", "traffic_paused", "traffic_recovered"},
		Enabled:          true,
	}); err != nil || st >= 300 {
		t.Fatalf("CreateWebhook failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	node := t3_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:                  "T3-Alert-Threshold",
		Enabled:               t3_boolPtr(true),
		TrafficLimitBytes:     2000,
		TrafficThresholdBytes: 1000,
		TrafficCountMode:      "both",
		ThresholdAction:       "stop_all",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, _ := t3_dialAgentHelloAndSync(t, ctx, client, node.EffectiveToken(), "amd64")

	// Warning at 85% (850 / 1000)
	if err := SendWSEnvelope(ctx, conn, "agent.metrics", "m-warn", AgentMetricsPayload{
		TS: time.Now().Unix(), NicRxDelta: 500, NicTxDelta: 350, Health: AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}
	reqs1, ok1 := whSrv.WaitForRequests(1, 5*time.Second)
	if !ok1 || !strings.Contains(reqs1[0].Body, "traffic_warning") {
		t.Fatalf("expected traffic_warning webhook, got %+v", reqs1)
	}

	// Pause at >=100% (1050 >= 1000)
	if err := SendWSEnvelope(ctx, conn, "agent.metrics", "m-pause", AgentMetricsPayload{
		TS: time.Now().Unix(), NicRxDelta: 200, NicTxDelta: 0, Health: AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}
	reqs2, ok2 := whSrv.WaitForRequests(2, 5*time.Second)
	if !ok2 || !strings.Contains(reqs2[1].Body, "traffic_paused") || strings.Contains(reqs2[1].Body, `"template":"green"`) {
		t.Fatalf("expected non-green traffic_paused webhook, got %+v", reqs2)
	}

	// Extra delta while paused should not spam duplicate traffic_paused within 60m cooldown
	if err := SendWSEnvelope(ctx, conn, "agent.metrics", "m-extra", AgentMetricsPayload{
		TS: time.Now().Unix(), NicRxDelta: 100, NicTxDelta: 0, Health: AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	if got := len(whSrv.Requests()); got != 2 {
		t.Fatalf("expected cooldown/state to prevent duplicate pause alerts, got %d requests", got)
	}

	// Reset traffic -> resolved traffic_recovered bypasses 60m cooldown with green card
	if st, raw, err := client.ResetNodeTraffic(jwt, node.ID); err != nil || st >= 300 {
		t.Fatalf("ResetNodeTraffic failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	reqs3, ok3 := whSrv.WaitForRequests(3, 5*time.Second)
	if !ok3 || !strings.Contains(reqs3[2].Body, "traffic_recovered") || !strings.Contains(reqs3[2].Body, `"template":"green"`) {
		t.Fatalf("expected green traffic_recovered bypassing cooldown, got %+v", reqs3)
	}
}

// 17. F12 + F14: Token rotation invalidates old subscription immediately while new token serves valid config & alerts
func TestTier3_F12_F14_TokenRotationInvalidatesOldSubscriptionAndAlerts(t *testing.T) {
	whSrv := StartMockWebhookServer(t)
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	if st, _, raw, err := client.CreateWebhook(jwt, WebhookChannelDTO{
		Name:             "T3 User Alert Hook",
		Provider:         "custom",
		URL:              whSrv.URL(),
		SubscribedEvents: []string{"user_quota_exhausted", "traffic_paused"},
		Enabled:          true,
	}); err != nil || st >= 300 {
		t.Fatalf("CreateWebhook failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	node := t3_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name: "T3-Rotate-SubNode", PublicIP: "203.0.113.60", Enabled: t3_boolPtr(true),
		SSConfig: &SSConfigDTO{Enabled: true, TCPPort: 29202, UDPPort: 29202, Cipher: "2022-blake3-aes-128-gcm", IPSK: t3_b64Key16("t3-rot-ipsk!!!!!"), STLSSNI: "swscan.apple.com"},
	})
	u1 := t3_mustCreateUser(t, client, jwt, CreateUserReq{
		Username:          "t3_rotate_user",
		TrafficQuotaBytes: 1000,
		NodeIDs:           []int64{node.ID},
	})

	stBefore, _, bodyBefore, err := client.GetUserSub(u1.SubToken, "target=mihomo", "")
	if err != nil || stBefore != http.StatusOK || !strings.Contains(bodyBefore, u1.SSUPSK16) {
		t.Fatalf("old sub token expected 200 with uPSK, got st=%d err=%v body=%s", stBefore, err, bodyBefore)
	}

	// Rotate user keys & sub_token
	stRot, u2, rawRot, err := client.ResetUserKeys(jwt, u1.ID, map[string]any{"reset_sub_token": true})
	if err != nil || stRot >= 300 || u2.SubToken == u1.SubToken || u2.SSUPSK16 == u1.SSUPSK16 {
		t.Fatalf("ResetUserKeys failed: st=%d err=%v u2=%+v body=%s", stRot, err, u2, string(rawRot))
	}

	// Old token immediately invalidated; new token serves updated uPSK & stls_password
	if stOld, _, _, err := client.GetUserSub(u1.SubToken, "target=mihomo", ""); err != nil || stOld == http.StatusOK {
		t.Fatalf("expected rotated-out sub_token to be rejected cleanly, got st=%d err=%v", stOld, err)
	}
	stNew, _, bodyNew, err := client.GetUserSub(u2.SubToken, "target=mihomo", "")
	if err != nil || stNew != http.StatusOK || !strings.Contains(bodyNew, u2.SSUPSK16) || !strings.Contains(bodyNew, u2.STLSPassword) {
		t.Fatalf("new sub_token failed: st=%d err=%v body=%s", stNew, err, bodyNew)
	}
	if strings.Contains(bodyNew, u1.SSUPSK16) || strings.Contains(bodyNew, u1.STLSPassword) {
		t.Fatalf("new sub leaked rotated-out credentials:\n%s", bodyNew)
	}

	// Trigger user_quota_exhausted alert and confirm new sub reflects cutoff & webhook fires
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, _ := t3_dialAgentHelloAndSync(t, ctx, client, node.EffectiveToken(), "amd64")
	if err := SendWSEnvelope(ctx, conn, "agent.metrics", "m-exh", AgentMetricsPayload{
		TS:         time.Now().Unix(),
		UserDeltas: []UserTrafficDeltaDTO{{Username: u2.Username, UserID: u2.ID, UpBytes: 600, DownBytes: 400}},
		Health:     AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}
	reqs, ok := whSrv.WaitForRequests(1, 5*time.Second)
	if !ok || !strings.Contains(reqs[0].Body, "user_quota_exhausted") {
		t.Fatalf("expected user_quota_exhausted webhook, got %+v", reqs)
	}
	if stExh, hdrExh, _, _ := client.GetUserSub(u2.SubToken, "target=mihomo", ""); stExh != http.StatusForbidden && stExh != http.StatusNotFound {
		t.Fatalf("expected 403/404 after quota exhausted, got %d", stExh)
	} else if !strings.Contains(hdrExh.Get("Subscription-Userinfo"), "upload=600; download=400; total=1000") {
		t.Fatalf("unexpected Subscription-Userinfo after exhaustion: %q", hdrExh.Get("Subscription-Userinfo"))
	}
}

// 18. F15 + F16: Public / HTML + /api/v1/public/status + /api/v1/public/ws consistent percentage_only & zero-leak
func TestTier3_F15_F16_PublicStatusPageAndWSPercentageOnlyZeroLeak(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{AdminPass: "T3_ADMIN_CANARY_PASS"})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "T3_ADMIN_CANARY_PASS")
	adminSubTok := t3_getAdminSubToken(t, client, jwt)

	if st, raw, err := client.UpdateSettings(jwt, map[string]any{
		"site_title":      "T3 Redacted Radar",
		"announcement":    "T3 Notice",
		"percentage_only": true,
	}); err != nil || st >= 300 {
		t.Fatalf("UpdateSettings failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	node := t3_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:              "T3-Public-Pct-Node",
		RegionTag:         "HK",
		PublicIP:          "198.51.100.250",
		CustomEntryHost:   "t3-pub-secret.internal",
		Enabled:           t3_boolPtr(true),
		TrafficLimitBytes: 100_000,
		TrafficCountMode:  "both",
		SnellConfig:       &SnellConfigDTO{Enabled: true, Version: "v5", PublicPort: 45111, InnerPort: 31111, PSK: "T3_PUB_SNELL_PSK"},
		DNSUnlockServer:   "198.51.100.251:3535",
	})
	if st, raw, err := client.CalibrateNodeTraffic(jwt, node.ID, 15_000, 15_000); err != nil || st >= 300 {
		t.Fatalf("CalibrateNodeTraffic failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	pubWS, _, err := client.DialPublicWS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer pubWS.CloseNow()

	agentWS, _ := t3_dialAgentHelloAndSync(t, ctx, client, node.EffectiveToken(), "amd64")
	if err := SendWSEnvelope(ctx, agentWS, "agent.metrics", "m1", AgentMetricsPayload{
		TS: time.Now().Unix(), CPUPercent: 22.0, Health: AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}

	secrets := []string{
		"T3_ADMIN_CANARY_PASS", adminSubTok, "198.51.100.250", "198.51.100.251:3535",
		"t3-pub-secret.internal", "T3_PUB_SNELL_PSK", node.EffectiveToken(),
	}

	// Verify / HTML & assets
	stHTML, hdrHTML, htmlRaw, err := client.DoRaw(ctx, http.MethodGet, "/", nil, nil)
	if err != nil || stHTML != http.StatusOK || !strings.Contains(strings.ToLower(hdrHTML.Get("Content-Type")), "text/html") {
		t.Fatalf("GET / failed: st=%d err=%v ct=%q", stHTML, err, hdrHTML.Get("Content-Type"))
	}
	for _, s := range secrets {
		if strings.Contains(string(htmlRaw), s) {
			t.Fatalf("secret %q leaked in GET / HTML", s)
		}
	}
	for _, ref := range t3_extractAssets(string(htmlRaw)) {
		p := ref
		if !strings.HasPrefix(p, "/") {
			p = "/" + strings.TrimLeft(p, "./")
		}
		stA, _, aRaw, err := client.DoRaw(ctx, http.MethodGet, p, nil, nil)
		if err != nil || stA != http.StatusOK {
			t.Fatalf("GET asset %s failed: st=%d err=%v", p, stA, err)
		}
		for _, s := range secrets {
			if strings.Contains(string(aRaw), s) {
				t.Fatalf("secret %q leaked in asset %s", s, p)
			}
		}
	}

	// Verify REST percentage_only
	t3_waitUntil(t, 5*time.Second, "REST online percentage_only", func() bool {
		st, snap, raw, err := client.GetPublicStatus()
		if err != nil || st != http.StatusOK || len(snap.Nodes) != 1 || snap.Nodes[0].Status != "online" {
			return false
		}
		n := snap.Nodes[0]
		if !snap.PercentageOnly || !n.PercentageOnly || n.TrafficUsedBytes != 0 || n.TrafficLimitBytes != 0 || n.TrafficPercent < 29.9 || n.TrafficPercent > 30.1 {
			t.Fatalf("REST percentage_only mismatch: %+v", n)
		}
		for _, s := range secrets {
			if strings.Contains(string(raw), s) {
				t.Fatalf("secret %q leaked in REST public status", s)
			}
		}
		return true
	})

	// Verify WS percentage_only + zero leak
	rctx, rcancel := context.WithTimeout(ctx, 8*time.Second)
	defer rcancel()
	for {
		_, frame, err := pubWS.Read(rctx)
		if err != nil {
			t.Fatalf("public WS read failed: %v", err)
		}
		t3_assertExactPublicSchema(t, frame)
		for _, s := range secrets {
			if strings.Contains(string(frame), s) {
				t.Fatalf("secret %q leaked in WS frame", s)
			}
		}
		var snap PublicStatusSnapshotDTO
		if json.Unmarshal(frame, &snap) == nil && len(snap.Nodes) == 1 && snap.Nodes[0].Status == "online" {
			n := snap.Nodes[0]
			if !snap.PercentageOnly || !n.PercentageOnly || n.TrafficUsedBytes != 0 || n.TrafficLimitBytes != 0 || n.TrafficPercent < 29.9 || n.TrafficPercent > 30.1 {
				t.Fatalf("WS percentage_only mismatch: %+v", n)
			}
			break
		}
	}
}

// 19. F17 + F18: /admin SPA embedded in cmd/panel works from empty working dir and requires JWT for /api/v1/admin/*
func TestTier3_F17_F18_EmbeddedAdminSPAFromEmptyDirAndJWTGate(t *testing.T) {
	env := NewTestEnv(t)
	if _, err := os.Stat(filepath.Join(env.RootDir, "web")); !os.IsNotExist(err) {
		t.Fatalf("expected empty TempDir without web/, got err=%v", err)
	}
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()

	for _, route := range []string{"/admin", "/admin/nodes", "/admin/users", "/admin/settings"} {
		st, hdr, raw, err := client.DoRaw(context.Background(), http.MethodGet, route, nil, nil)
		if err != nil || st != http.StatusOK || !strings.Contains(strings.ToLower(hdr.Get("Content-Type")), "text/html") {
			t.Fatalf("GET %s from empty dir failed: st=%d ct=%q err=%v", route, st, hdr.Get("Content-Type"), err)
		}
		assets := t3_extractAssets(string(raw))
		if len(assets) == 0 {
			t.Fatalf("GET %s HTML missing assets", route)
		}
		for _, ref := range assets {
			if !strings.HasPrefix(ref, "/") {
				t.Fatalf("SPA asset %q on %s must be root-relative", ref, route)
			}
			stA, _, bodyA, errA := client.DoRaw(context.Background(), http.MethodGet, ref, nil, nil)
			if errA != nil || stA != http.StatusOK || len(bodyA) == 0 {
				t.Fatalf("GET embedded asset %s failed: st=%d len=%d err=%v", ref, stA, len(bodyA), errA)
			}
		}
	}

	// JWT gate on /api/v1/admin/*
	for _, ep := range []string{"/api/v1/admin/nodes", "/api/v1/admin/users", "/api/v1/admin/settings"} {
		if st, _, _ := client.DoJSON(context.Background(), http.MethodGet, ep, "", nil, nil); st != http.StatusUnauthorized {
			t.Fatalf("expected 401 without JWT on %s, got %d", ep, st)
		}
	}

	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")
	if st, _, raw, err := client.GetSettings(jwt); err != nil || st != http.StatusOK {
		t.Fatalf("GET settings with valid JWT failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	st404, hdr404, raw404, err := client.DoRaw(context.Background(), http.MethodGet, "/api/v1/admin/nonexistent", map[string]string{"Authorization": "Bearer " + jwt}, nil)
	if err != nil || st404 != http.StatusNotFound || !strings.Contains(strings.ToLower(hdr404.Get("Content-Type")), "application/json") {
		t.Fatalf("unknown admin API must return JSON 404, got st=%d ct=%q err=%v body=%s", st404, hdr404.Get("Content-Type"), err, string(raw404))
	}
}

// 20. F19 + F20: deploy/ env vars & ports match README.md and .github/workflows/ CI checks
func TestTier3_F19_F20_DeployEnvPortsMatchReadmeAndCI(t *testing.T) {
	repoRoot := findRepoRoot(t)
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(b)
	}

	panelDF := read("deploy/Dockerfile.panel")
	agentDF := read("deploy/Dockerfile.agent")
	composeRaw := read("deploy/docker-compose.yml")
	readme := read("README.md")
	panelMain := read("cmd/panel/main.go")
	agentMain := read("cmd/agent/main.go")

	// Extract env vars supported by cmd/panel and cmd/agent
	supported := map[string]bool{"TZ": true, "GITHUB_API_URL": true}
	for _, src := range []string{panelMain, agentMain} {
		for _, m := range t3_envVarRe.FindAllStringSubmatch(src, -1) {
			supported[m[1]] = true
		}
	}

	var compose struct {
		Services map[string]struct {
			Ports       []string `yaml:"ports"`
			Volumes     []string `yaml:"volumes"`
			Environment any      `yaml:"environment"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(composeRaw), &compose); err != nil {
		t.Fatalf("invalid deploy/docker-compose.yml: %v", err)
	}

	composeEnvs := map[string]string{}
	found8080 := false
	foundDataVol := false
	for _, svc := range compose.Services {
		for _, p := range svc.Ports {
			if strings.Contains(p, "8080") {
				found8080 = true
			}
		}
		for _, v := range svc.Volumes {
			if strings.Contains(v, "./data:/app/data") {
				foundDataVol = true
			}
		}
		switch ev := svc.Environment.(type) {
		case map[string]any:
			for k, val := range ev {
				composeEnvs[k] = fmt.Sprint(val)
			}
		case []any:
			for _, item := range ev {
				s := fmt.Sprint(item)
				if idx := strings.IndexByte(s, '='); idx > 0 {
					composeEnvs[strings.TrimSpace(s[:idx])] = strings.TrimSpace(s[idx+1:])
				} else if strings.TrimSpace(s) != "" {
					composeEnvs[strings.TrimSpace(s)] = ""
				}
			}
		}
	}
	if !found8080 || !foundDataVol {
		t.Fatalf("docker-compose.yml missing port 8080 (%v) or ./data:/app/data (%v)", found8080, foundDataVol)
	}
	for k := range composeEnvs {
		if !supported[k] {
			t.Fatalf("docker-compose.yml references env var %q not parsed by cmd/panel or cmd/agent", k)
		}
	}

	// Cross-check ports/volumes/env vars with Dockerfiles and README
	if !strings.Contains(panelDF, "8080") || !strings.Contains(readme, "8080") || !strings.Contains(readme, "./data") {
		t.Fatalf("port 8080 or ./data volume missing across Dockerfile.panel / README.md")
	}
	if !strings.Contains(agentDF, "/var/lib/snell-panel-agent") || !strings.Contains(readme, "/var/lib/snell-panel-agent") {
		t.Fatalf("/var/lib/snell-panel-agent missing across Dockerfile.agent / README.md")
	}
	for _, envKey := range []string{"ADMIN_USER", "ADMIN_INITIAL_PASS", "PANEL_URL", "NODE_TOKEN", "TZ"} {
		if !strings.Contains(readme, envKey) {
			t.Fatalf("README.md missing documented env var %q", envKey)
		}
	}

	// Verify CI workflows validate Go tests, web build, and multi-arch builds referencing deploy/Dockerfiles
	wfDir := filepath.Join(repoRoot, ".github", "workflows")
	entries, err := os.ReadDir(wfDir)
	if err != nil {
		t.Fatalf("read .github/workflows: %v", err)
	}
	var wfAll strings.Builder
	for _, e := range entries {
		if !e.IsDir() && (strings.HasSuffix(e.Name(), ".yml") || strings.HasSuffix(e.Name(), ".yaml")) {
			wfAll.WriteString(read(filepath.Join(".github", "workflows", e.Name())))
			wfAll.WriteByte('\n')
		}
	}
	wfText := wfAll.String()
	for _, req := range []string{"go vet", "go test", "-race", "npm run build", "linux/amd64", "linux/arm64", "Dockerfile"} {
		if !strings.Contains(wfText, req) {
			t.Fatalf(".github/workflows missing CI requirement %q", req)
		}
	}
}
