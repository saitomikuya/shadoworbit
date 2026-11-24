//go:build e2e

package e2e_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

func t4_boolPtr(v bool) *bool { return &v }

func t4_b64Key16(seed string) string {
	b := make([]byte, 16)
	copy(b, []byte(seed))
	return base64.StdEncoding.EncodeToString(b)
}

func t4_b64Key32(seed string) string {
	b := make([]byte, 32)
	copy(b, []byte(seed))
	return base64.StdEncoding.EncodeToString(b)
}

func t4_decodeBase64Flexible(s string) ([]byte, error) {
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

func t4_waitUntil(t *testing.T, timeout time.Duration, desc string, fn func() bool) {
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

func t4_waitTCPReady(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	t4_waitUntil(t, timeout, "TCP listening on "+addr, func() bool {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return true
		}
		return false
	})
}

func t4_mustCreateNode(t *testing.T, client *PanelClient, jwt string, req CreateNodeReq) NodeDTO {
	t.Helper()
	st, node, raw, err := client.CreateNode(jwt, req)
	if err != nil || (st != http.StatusOK && st != http.StatusCreated) {
		t.Fatalf("CreateNode(%q) failed: st=%d err=%v body=%s", req.Name, st, err, string(raw))
	}
	return node
}

func t4_mustCreateUser(t *testing.T, client *PanelClient, jwt string, req CreateUserReq) UserDTO {
	t.Helper()
	st, user, raw, err := client.CreateUser(jwt, req)
	if err != nil || (st != http.StatusOK && st != http.StatusCreated) {
		t.Fatalf("CreateUser(%q) failed: st=%d err=%v body=%s", req.Username, st, err, string(raw))
	}
	return user
}

func t4_getAdminSubToken(t *testing.T, client *PanelClient, jwt string) string {
	t.Helper()
	st, settings, raw, err := client.GetSettings(jwt)
	if err != nil || st != http.StatusOK || settings.AdminSubToken == "" {
		t.Fatalf("GetSettings failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	return settings.AdminSubToken
}

func t4_countStartInvocations(kernels *MockKernelSet, role string) int {
	n := 0
	for _, inv := range kernels.Invocations(role) {
		if inv.Event == "start" {
			n++
		}
	}
	return n
}

func t4_dnsExchange(t *testing.T, addr, proto, qname string, qtype uint16) *dns.Msg {
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

type t4_walFile struct {
	Version    int                            `json:"version"`
	NicRxDelta uint64                         `json:"nic_rx_delta"`
	NicTxDelta uint64                         `json:"nic_tx_delta"`
	UserDeltas map[string]UserTrafficDeltaDTO `json:"user_deltas"`
}

func t4_readWAL(walPath string) (t4_walFile, error) {
	b, err := os.ReadFile(walPath)
	if err != nil {
		return t4_walFile{}, err
	}
	var w t4_walFile
	if err := json.Unmarshal(b, &w); err != nil {
		return t4_walFile{}, err
	}
	return w, nil
}

type t4_nodeExtDTO struct {
	ID                     int64            `json:"id"`
	Status                 string           `json:"status"`
	ReportedConfigRevision int64            `json:"reported_config_revision"`
	ReportedVersions       AgentVersionsDTO `json:"reported_versions"`
	AgentOS                string           `json:"agent_os"`
	AgentArch              string           `json:"agent_arch"`
	CycleRxBytes           int64            `json:"cycle_rx_bytes"`
	CycleTxBytes           int64            `json:"cycle_tx_bytes"`
	IsTrafficPaused        bool             `json:"is_traffic_paused"`
	BillingResetDay        int              `json:"billing_reset_day"`
}

func t4_getNodeExt(t *testing.T, client *PanelClient, jwt string, id int64) t4_nodeExtDTO {
	t.Helper()
	var out t4_nodeExtDTO
	st, raw, err := client.DoJSON(context.Background(), http.MethodGet, fmt.Sprintf("/api/v1/admin/nodes/%d", id), jwt, nil, &out)
	if err != nil || st != http.StatusOK {
		t.Fatalf("GET /api/v1/admin/nodes/%d failed: st=%d err=%v body=%s", id, st, err, string(raw))
	}
	return out
}

var (
	t4_scriptSrcRe = regexp.MustCompile(`(?is)<script[^>]*\ssrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'=<>` + "`" + `]+))`)
	t4_linkHrefRe  = regexp.MustCompile(`(?is)<link[^>]*\shref\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'=<>` + "`" + `]+))`)
	t4_envVarRe    = regexp.MustCompile(`(?:os\.Getenv|os\.LookupEnv|getenvDefault|getenvBool|envOrDefault|\bgetenv)\(\s*"([A-Z0-9_]+)"`)
	t4_stubWordRe  = regexp.MustCompile(`\b(TODO|FIXME|TBD|XXX|PLACEHOLDER)\b|\[(?i:TODO|FIXME|TBD|XXX|PLACEHOLDER)\]|<(?i:TODO|FIXME|TBD|XXX|PLACEHOLDER)>`)
	t4_secretRe    = regexp.MustCompile(`(?i)(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY|nd_live_[A-Za-z0-9]{16,})`)
)

func t4_extractAssets(html string) []string {
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
	for _, re := range []*regexp.Regexp{t4_scriptSrcRe, t4_linkHrefRe} {
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

func t4_stripDockerfileComments(df string) string {
	norm := strings.ReplaceAll(df, "\r\n", "\n")
	var sb strings.Builder
	for _, line := range strings.Split(norm, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// Scenario 1: Fresh panel bootstrap -> admin password update -> node onboarding -> agent hello & config_sync
func TestTier4_Scenario01_BootstrapPasswordOnboardingAndSync(t *testing.T) {
	env := NewTestEnv(t)
	dbPath := filepath.Join(env.RootDir, "data", "panel.db")
	panel := StartPanel(env, PanelConfig{DBPath: dbPath})
	client := panel.NewClient()
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.org": {"93.184.216.34"}}})

	// 1. Bootstrap login with default password, then rotate admin password
	jwt1 := client.MustLogin(t, "admin", "change_me_on_first_login")
	if st, raw, err := client.UpdatePassword(jwt1, "change_me_on_first_login", "S4_StrongAdminPass!2026"); err != nil || st >= 300 {
		t.Fatalf("UpdatePassword failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	if oldSt, _, _, _ := client.Login("admin", "change_me_on_first_login"); oldSt != http.StatusUnauthorized {
		t.Fatalf("expected old bootstrap password rejected with 401, got %d", oldSt)
	}
	jwt := client.MustLogin(t, "admin", "S4_StrongAdminPass!2026")

	// 2. Create DNS rule group and onboard node
	stGrp, grp, rawGrp, err := client.CreateDNSRuleGroup(jwt, "S4-Stream", []string{"netflix.com"})
	if err != nil || stGrp >= 300 {
		t.Fatalf("CreateDNSRuleGroup failed: st=%d err=%v body=%s", stGrp, err, string(rawGrp))
	}
	snellPub := AllocFreePort(t)
	snellIn := AllocFreePort(t)
	ssPort := AllocFreePort(t)
	ssUDP := AllocFreeUDPPort(t)

	node := t4_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:      "S4-Onboard-JP",
		RegionTag: "JP",
		Enabled:   t4_boolPtr(true),
		SnellConfig: &SnellConfigDTO{
			Enabled: true, Version: "v5", PublicPort: snellPub, InnerPort: snellIn,
			PSK: "s4-onboard-psk", Obfs: "off", TFO: true,
			STLSPassword: "s4-snell-stls-pwd", STLSSNI: "gateway.icloud.com",
		},
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: ssPort, UDPPort: ssUDP,
			Cipher: "2022-blake3-aes-128-gcm", IPSK: t4_b64Key16("s4-onboard-ipsk!"), STLSSNI: "swscan.apple.com",
		},
		DNSUnlockEnabled: true,
		DNSUnlockServer:  normalDNS.Addr(),
		DNSRuleGroupID:   &grp.ID,
		BillingResetDay:  15,
	})
	tok := node.EffectiveToken()
	if tok == "" {
		t.Fatal("missing node_token from CreateNode")
	}

	stCmd, cmdRaw, err := client.GetInstallCmd(jwt, node.ID)
	if err != nil || stCmd != http.StatusOK || !strings.Contains(string(cmdRaw), tok) || !strings.Contains(string(cmdRaw), "PANEL_URL") {
		t.Fatalf("GetInstallCmd failed: st=%d err=%v body=%s", stCmd, err, string(cmdRaw))
	}

	// 3. Start real cmd/agent and verify hello, config_sync, 3 kernels, and online telemetry
	ag := StartAgent(env, AgentConfig{
		PanelURL:     panel.WSBaseURL(),
		NodeToken:    tok,
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	t4_waitUntil(t, 15*time.Second, "node online & 3 kernels running & config revision synced", func() bool {
		ext := t4_getNodeExt(t, client, jwt, node.ID)
		return ext.Status == "online" &&
			ext.ReportedConfigRevision >= 1 &&
			ext.AgentOS != "" && ext.AgentArch != "" &&
			strings.Contains(ext.ReportedVersions.SingBox, "1.11.4") &&
			kernels.LiveProcessCount("snell-server") == 1 &&
			kernels.LiveProcessCount("shadow-tls") == 1 &&
			kernels.LiveProcessCount("sing-box") == 1
	})

	lastCfgRaw, err := os.ReadFile(filepath.Join(ag.DataDir, "last_config.json"))
	if err != nil || !strings.Contains(string(lastCfgRaw), "s4-onboard-psk") {
		t.Fatalf("expected persisted last_config.json on agent: err=%v body=%s", err, string(lastCfgRaw))
	}
	t4_waitTCPReady(t, fmt.Sprintf("127.0.0.1:%d", snellPub), 5*time.Second)
	t4_waitTCPReady(t, fmt.Sprintf("127.0.0.1:%d", ssPort), 5*time.Second)
	t4_waitTCPReady(t, fmt.Sprintf("127.0.0.1:%d", ag.StatsPort), 5*time.Second)
}

// Scenario 2: User addition/removal hot-syncs sing-box without interrupting Snell + ShadowTLS admin channel
func TestTier4_Scenario02_UserHotSyncPreservesSnellAdminChannel(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")
	kernels := BuildMockKernels(t, MockKernelOptions{})

	node := t4_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:    "S4-Isolation-Node",
		Enabled: t4_boolPtr(true),
		SnellConfig: &SnellConfigDTO{
			Enabled: true, Version: "v5", PublicPort: AllocFreePort(t), InnerPort: AllocFreePort(t),
			PSK: "s4-iso-snell-psk", Obfs: "off", STLSPassword: "s4-iso-stls", STLSSNI: "gateway.icloud.com",
		},
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: AllocFreePort(t), UDPPort: AllocFreeUDPPort(t),
			Cipher: "2022-blake3-aes-128-gcm", IPSK: t4_b64Key16("s4-iso-ipsk!!!!!"), STLSSNI: "swscan.apple.com",
		},
	})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     panel.WSBaseURL(),
		NodeToken:    node.EffectiveToken(),
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	t4_waitUntil(t, 12*time.Second, "all 3 kernels active", func() bool {
		return kernels.LiveProcessCount("snell-server") == 1 &&
			kernels.LiveProcessCount("shadow-tls") == 1 &&
			kernels.LiveProcessCount("sing-box") == 1
	})
	snellPID := kernels.RunningPIDs("snell-server")[0]
	stlsPID := kernels.RunningPIDs("shadow-tls")[0]
	sbPIDBefore := kernels.RunningPIDs("sing-box")
	if len(sbPIDBefore) != 1 {
		t.Fatalf("expected 1 running sing-box PID before user mutations, got %v", sbPIDBefore)
	}
	snellStarts := t4_countStartInvocations(kernels, "snell-server")
	stlsStarts := t4_countStartInvocations(kernels, "shadow-tls")
	sbCfgPath := filepath.Join(ag.DataDir, "configs", "sing-box.json")

	// Add alice
	alice := t4_mustCreateUser(t, client, jwt, CreateUserReq{Username: "s4_alice", NodeIDs: []int64{node.ID}})
	t4_waitUntil(t, 10*time.Second, "sing-box.json includes s4_alice", func() bool {
		b, err := os.ReadFile(sbCfgPath)
		return err == nil && strings.Contains(string(b), `"s4_alice"`)
	})

	// Add bob
	bob := t4_mustCreateUser(t, client, jwt, CreateUserReq{Username: "s4_bob", NodeIDs: []int64{node.ID}})
	t4_waitUntil(t, 10*time.Second, "sing-box.json includes s4_alice and s4_bob", func() bool {
		b, err := os.ReadFile(sbCfgPath)
		return err == nil && strings.Contains(string(b), `"s4_alice"`) && strings.Contains(string(b), `"s4_bob"`)
	})

	// Delete alice, keep bob
	if stDel, rawDel, err := client.DeleteUser(jwt, alice.ID); err != nil || stDel >= 300 {
		t.Fatalf("DeleteUser(alice) failed: st=%d err=%v body=%s", stDel, err, string(rawDel))
	}
	var sbPIDAfter []int
	t4_waitUntil(t, 12*time.Second, "sing-box.json drops s4_alice while keeping s4_bob and reloads sing-box", func() bool {
		b, err := os.ReadFile(sbCfgPath)
		if err != nil || strings.Contains(string(b), `"s4_alice"`) || !strings.Contains(string(b), `"s4_bob"`) || !strings.Contains(string(b), bob.SSUPSK16) {
			return false
		}
		sbPIDAfter = kernels.RunningPIDs("sing-box")
		return len(sbPIDAfter) == 1 && sbPIDAfter[0] != sbPIDBefore[0]
	})

	if got := kernels.RunningPIDs("snell-server"); len(got) != 1 || got[0] != snellPID {
		t.Fatalf("snell-server PID changed during user hot-syncs: before=%d after=%v", snellPID, got)
	}
	if got := kernels.RunningPIDs("shadow-tls"); len(got) != 1 || got[0] != stlsPID {
		t.Fatalf("shadow-tls PID changed during user hot-syncs: before=%d after=%v", stlsPID, got)
	}
	if t4_countStartInvocations(kernels, "snell-server") != snellStarts || t4_countStartInvocations(kernels, "shadow-tls") != stlsStarts {
		t.Fatalf("snell-server or shadow-tls restarted during user lifecycle")
	}
}

// Scenario 3: Streaming unlock DNS across both Snell & SS2022 with AAAA/HTTPS/SVCB/ANY NODATA blocking + non-53 upstream
func TestTier4_Scenario03_StreamingDNSUnlockDualChannelAndNodata(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")
	kernels := BuildMockKernels(t, MockKernelOptions{})

	unlockSrv := StartMockDNSServer(t, MockDNSOptions{
		Records: map[string][]string{
			"netflix.com":        {"203.0.113.100"},
			"api.netflix.com":    {"203.0.113.101"},
			"openai.com":         {"203.0.113.102"},
			"www.disneyplus.com": {"203.0.113.103"},
		},
		AAAARecords:  map[string][]string{"netflix.com": {"2001:db8::100"}},
		HTTPSRecords: map[string]bool{"netflix.com": true},
		SVCBRecords:  map[string]bool{"netflix.com": true},
	})
	normalSrv := StartMockDNSServer(t, MockDNSOptions{
		Records: map[string][]string{
			"api.openai.com": {"198.51.100.102"},
			"disneyplus.com": {"198.51.100.103"},
			"example.org":    {"198.51.100.104"},
		},
	})
	if unlockSrv.Port() == 53 {
		t.Fatalf("expected non-53 unlock DNS port")
	}

	_, grp, _, err := client.CreateDNSRuleGroup(jwt, "S4-Streaming", []string{"netflix.com", "^openai.com"})
	if err != nil {
		t.Fatal(err)
	}
	node := t4_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:             "S4-DNS-Node",
		Enabled:          t4_boolPtr(true),
		DNSUnlockEnabled: true,
		DNSUnlockServer:  unlockSrv.Addr(),
		DNSRuleGroupID:   &grp.ID,
		ExtraDNSRules:    []string{"*.disneyplus.com"},
		SnellConfig: &SnellConfigDTO{
			Enabled: true, Version: "v5", PublicPort: AllocFreePort(t), InnerPort: AllocFreePort(t),
			PSK: "s4-dns-psk", STLSPassword: "s4-dns-stls", STLSSNI: "gateway.icloud.com",
		},
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: AllocFreePort(t), UDPPort: AllocFreeUDPPort(t),
			Cipher: "2022-blake3-aes-128-gcm", IPSK: t4_b64Key16("s4-dns-ipsk!!!!!"), STLSSNI: "swscan.apple.com",
		},
	})

	// Update default upstream DNS and local DNS port on panel
	localDNSPort := AllocFreeDualPort(t)
	if stSet, rawSet, errSet := client.UpdateSettings(jwt, map[string]any{
		"default_upstream_dns":   normalSrv.Addr(),
		"default_local_dns_port": fmt.Sprintf("%d", localDNSPort),
	}); errSet != nil || stSet != http.StatusOK {
		t.Fatalf("UpdateSettings failed: st=%d err=%v body=%s", stSet, errSet, string(rawSet))
	}

	ag := StartAgent(env, AgentConfig{
		PanelURL:     panel.WSBaseURL(),
		NodeToken:    node.EffectiveToken(),
		LocalDNSPort: localDNSPort,
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	snellConfPath := filepath.Join(ag.DataDir, "configs", "snell-server.conf")
	sbConfPath := filepath.Join(ag.DataDir, "configs", "sing-box.json")
	reDNS := regexp.MustCompile(`dns\s*=\s*127\.0\.0\.1:(\d+)`)
	var dnsPort string
	t4_waitUntil(t, 12*time.Second, "both snell and sing-box configured with shared local DNS port", func() bool {
		b1, err1 := os.ReadFile(snellConfPath)
		b2, err2 := os.ReadFile(sbConfPath)
		if err1 != nil || err2 != nil {
			return false
		}
		m := reDNS.FindStringSubmatch(string(b1))
		if len(m) != 2 {
			return false
		}
		dnsPort = m[1]
		return strings.Contains(string(b2), "127.0.0.1:"+dnsPort) ||
			(strings.Contains(string(b2), `"127.0.0.1"`) && strings.Contains(string(b2), `"server_port": `+dnsPort))
	})
	dnsAddr := "127.0.0.1:" + dnsPort

	unlockSrv.ResetQueries()
	normalSrv.ResetQueries()

	// Root + subdomain rule (`netflix.com`), exact (`^openai.com`), wildcard (`*.disneyplus.com`)
	for _, tc := range []struct {
		qname  string
		proto  string
		wantIP string
	}{
		{"netflix.com.", "udp", "203.0.113.100"},
		{"api.netflix.com.", "tcp", "203.0.113.101"},
		{"openai.com.", "udp", "203.0.113.102"},
		{"www.disneyplus.com.", "udp", "203.0.113.103"},
	} {
		resp := t4_dnsExchange(t, dnsAddr, tc.proto, tc.qname, dns.TypeA)
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 || resp.Answer[0].(*dns.A).A.String() != tc.wantIP {
			t.Fatalf("%s (%s) A mismatch: got %+v want %s", tc.qname, tc.proto, resp.Answer, tc.wantIP)
		}
	}

	// Non-unlock domains and boundary exclusions (`^openai.com` vs `api.openai.com`, `*.disneyplus.com` vs `disneyplus.com`) route to normalSrv only
	unlockSrv.ResetQueries()
	normalSrv.ResetQueries()
	for _, tc := range []struct {
		qname  string
		wantIP string
	}{
		{"api.openai.com.", "198.51.100.102"},
		{"disneyplus.com.", "198.51.100.103"},
		{"example.org.", "198.51.100.104"},
	} {
		resp := t4_dnsExchange(t, dnsAddr, "udp", tc.qname, dns.TypeA)
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 || resp.Answer[0].(*dns.A).A.String() != tc.wantIP {
			t.Fatalf("%s non-unlock A mismatch: got %+v want %s", tc.qname, resp.Answer, tc.wantIP)
		}
	}
	if len(unlockSrv.Queries()) != 0 {
		t.Fatalf("non-unlock queries leaked to unlockSrv: %+v", unlockSrv.Queries())
	}
	seenNormal := map[string]bool{}
	for _, q := range normalSrv.Queries() {
		seenNormal[q.Name] = true
	}
	for _, want := range []string{"api.openai.com.", "disneyplus.com.", "example.org."} {
		if !seenNormal[want] {
			t.Fatalf("expected normalSrv to receive %q, got queries=%+v", want, normalSrv.Queries())
		}
	}

	// Blocked qtypes on unlock domain return immediate empty NODATA without touching unlockSrv or normalSrv
	unlockSrv.ResetQueries()
	normalSrv.ResetQueries()
	for _, qt := range []uint16{dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB, dns.TypeANY} {
		resp := t4_dnsExchange(t, dnsAddr, "udp", "netflix.com.", qt)
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 || len(resp.Ns) != 0 {
			t.Fatalf("blocked qtype %s expected empty NODATA, got rcode=%d ans=%d", dns.TypeToString[qt], resp.Rcode, len(resp.Answer))
		}
	}
	if len(unlockSrv.Queries()) != 0 || len(normalSrv.Queries()) != 0 {
		t.Fatalf("blocked qtypes leaked to upstreams: unlock=%+v normal=%+v", unlockSrv.Queries(), normalSrv.Queries())
	}
}

// Scenario 4: Agent disconnect -> /proc/net/dev + gRPC WAL buffering + host reboot counter reset -> reconnect flush
func TestTier4_Scenario04_DisconnectWALRebootResetAndReconnectFlush(t *testing.T) {
	env := NewTestEnv(t)
	dbPath := filepath.Join(env.RootDir, "panel.db")
	panelAddr := fmt.Sprintf("127.0.0.1:%d", AllocFreePort(t))
	p1 := StartPanel(env, PanelConfig{ListenAddr: panelAddr, DBPath: dbPath})
	c1 := p1.NewClient()
	jwt1 := c1.MustLogin(t, "admin", "change_me_on_first_login")

	kernels := BuildMockKernels(t, MockKernelOptions{})
	procPath := WriteProcNetDevFixture(t, "eth0", 10000, 20000)

	node := t4_mustCreateNode(t, c1, jwt1, CreateNodeReq{
		Name:    "S4-WAL-Reboot-Node",
		Enabled: t4_boolPtr(true),
		SnellConfig: &SnellConfigDTO{
			Enabled: true, Version: "v5", PublicPort: AllocFreePort(t), InnerPort: AllocFreePort(t),
			PSK: "s4-wal-psk", STLSPassword: "s4-wal-stls", STLSSNI: "gateway.icloud.com",
		},
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: AllocFreePort(t), UDPPort: AllocFreeUDPPort(t),
			Cipher: "2022-blake3-aes-128-gcm", IPSK: t4_b64Key16("s4-wal-ipsk!!!!!"), STLSSNI: "swscan.apple.com",
		},
	})
	alice := t4_mustCreateUser(t, c1, jwt1, CreateUserReq{Username: "alice", NodeIDs: []int64{node.ID}})

	ag := StartAgent(env, AgentConfig{
		PanelURL:       p1.WSBaseURL(),
		NodeToken:      node.EffectiveToken(),
		Iface:          "eth0",
		ProcNetDevPath: procPath,
		SnellBin:       kernels.SnellBin,
		ShadowTLSBin:   kernels.ShadowTLSBin,
		SingBoxBin:     kernels.SingBoxBin,
	})

	t4_waitUntil(t, 15*time.Second, "node online & sing-box gRPC ready", func() bool {
		ext := t4_getNodeExt(t, c1, jwt1, node.ID)
		return ext.Status == "online" && kernels.LiveProcessCount("sing-box") == 1
	})
	t4_waitTCPReady(t, fmt.Sprintf("127.0.0.1:%d", ag.StatsPort), 5*time.Second)
	// Allow baseline /proc/net/dev & gRPC poll to complete cleanly
	time.Sleep(2 * time.Second)

	// Shut down panel -> agent goes offline and buffers deltas to pending_traffic.json
	if err := p1.Stop(); err != nil {
		t.Fatalf("p1.Stop: %v", err)
	}

	UpdateProcNetDevFixture(t, procPath, "eth0", 25000, 45000) // +15000 rx, +25000 tx
	kernels.SetStats([]MockUserStat{
		{Name: "user>>>alice>>>traffic>>>uplink", Value: 3000},
		{Name: "user>>>alice>>>traffic>>>downlink", Value: 5000},
	})

	walPath := filepath.Join(ag.DataDir, "pending_traffic.json")
	t4_waitUntil(t, 25*time.Second, "WAL buffers +15000/+25000 and alice stats", func() bool {
		w, err := t4_readWAL(walPath)
		return err == nil && w.NicRxDelta >= 15000 && w.NicTxDelta >= 25000 &&
			w.UserDeltas["alice"].UpBytes >= 3000 && w.UserDeltas["alice"].DownBytes >= 5000
	})

	// Simulate host reboot counter reset (25000,45000 -> 500,800)
	UpdateProcNetDevFixture(t, procPath, "eth0", 500, 800)
	time.Sleep(8 * time.Second)

	// Increment post-reboot counters (500,800 -> 1500,2800 = +1000 rx, +2000 tx)
	UpdateProcNetDevFixture(t, procPath, "eth0", 1500, 2800)
	t4_waitUntil(t, 15*time.Second, "WAL accumulates post-reboot deltas cleanly without underflow", func() bool {
		w, err := t4_readWAL(walPath)
		return err == nil && w.NicRxDelta == 16000 && w.NicTxDelta == 27000
	})

	// Restart panel on same ListenAddr & DBPath -> agent reconnects and flushes WAL
	p2 := StartPanel(env, PanelConfig{ListenAddr: panelAddr, DBPath: dbPath})
	c2 := p2.NewClient()
	jwt2 := c2.MustLogin(t, "admin", "change_me_on_first_login")

	t4_waitUntil(t, 45*time.Second, "panel receives exact flushed WAL deltas", func() bool {
		_, gotN, _, errN := c2.GetNode(jwt2, node.ID)
		_, gotU, _, errU := c2.GetUser(jwt2, alice.ID)
		return errN == nil && errU == nil &&
			gotN.CycleRxBytes == 16000 && gotN.CycleTxBytes == 27000 &&
			gotU.UsedUpBytes == 3000 && gotU.UsedDownBytes == 5000
	})

	t4_waitUntil(t, 5*time.Second, "WAL cleared after reconnect flush", func() bool {
		w, err := t4_readWAL(walPath)
		return err == nil && w.NicRxDelta == 0 && w.NicTxDelta == 0 && len(w.UserDeltas) == 0
	})
}

// Scenario 5: Node stop_all threshold trigger -> public status pause + admin/user sub removal + webhook -> reset recovery
func TestTier4_Scenario05_StopAllThresholdSubRemovalWebhookAndBillingReset(t *testing.T) {
	whSrv := StartMockWebhookServer(t)
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{TZ: "UTC"})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")
	kernels := BuildMockKernels(t, MockKernelOptions{})
	procPath := WriteProcNetDevFixture(t, "eth0", 1000, 1000)

	if st, _, raw, err := client.CreateWebhook(jwt, WebhookChannelDTO{
		Name:             "S4 StopAll Hook",
		Provider:         "feishu",
		URL:              whSrv.URL() + "/feishu",
		SubscribedEvents: []string{"traffic_paused", "traffic_recovered"},
		Enabled:          true,
	}); err != nil || st >= 300 {
		t.Fatalf("CreateWebhook failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	node := t4_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:                  "S4-StopAll-Node",
		RegionTag:             "US",
		PublicIP:              "203.0.113.50",
		Enabled:               t4_boolPtr(true),
		TrafficLimitBytes:     20000,
		TrafficThresholdBytes: 10000,
		TrafficCountMode:      "both",
		ThresholdAction:       "stop_all",
		BillingResetDay:       31,
		SnellConfig: &SnellConfigDTO{
			Enabled: true, Version: "v5", PublicPort: AllocFreePort(t), InnerPort: AllocFreePort(t),
			PSK: "S4_STOPALL_PSK", STLSPassword: "S4_STOPALL_STLS", STLSSNI: "gateway.icloud.com",
		},
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: AllocFreePort(t), UDPPort: AllocFreeUDPPort(t),
			Cipher: "2022-blake3-aes-128-gcm", IPSK: t4_b64Key16("s4-sa-ipsk!!!!!!"), STLSSNI: "swscan.apple.com",
		},
	})
	user := t4_mustCreateUser(t, client, jwt, CreateUserReq{Username: "s4_sa_user", NodeIDs: []int64{node.ID}})
	adminTok := t4_getAdminSubToken(t, client, jwt)

	_ = StartAgent(env, AgentConfig{
		PanelURL:       panel.WSBaseURL(),
		NodeToken:      node.EffectiveToken(),
		Iface:          "eth0",
		ProcNetDevPath: procPath,
		SnellBin:       kernels.SnellBin,
		ShadowTLSBin:   kernels.ShadowTLSBin,
		SingBoxBin:     kernels.SingBoxBin,
	})

	t4_waitUntil(t, 15*time.Second, "node online with all 3 kernels", func() bool {
		ext := t4_getNodeExt(t, client, jwt, node.ID)
		return ext.Status == "online" &&
			kernels.LiveProcessCount("snell-server") == 1 &&
			kernels.LiveProcessCount("shadow-tls") == 1 &&
			kernels.LiveProcessCount("sing-box") == 1
	})
	time.Sleep(1500 * time.Millisecond)

	// Cross threshold (12000 >= 10000) via real agent /proc/net/dev delta
	UpdateProcNetDevFixture(t, procPath, "eth0", 7000, 7000) // +6000 rx, +6000 tx
	t4_waitUntil(t, 15*time.Second, "node paused and all 3 kernels stopped", func() bool {
		ext := t4_getNodeExt(t, client, jwt, node.ID)
		return ext.IsTrafficPaused && ext.Status == "traffic_paused" &&
			kernels.LiveProcessCount("snell-server") == 0 &&
			kernels.LiveProcessCount("shadow-tls") == 0 &&
			kernels.LiveProcessCount("sing-box") == 0
	})

	// Public status reflects traffic_paused & billing_reset_day=31
	_, pubSnap, _, err := client.GetPublicStatus()
	if err != nil || len(pubSnap.Nodes) != 1 || pubSnap.Nodes[0].Status != "traffic_paused" || pubSnap.Nodes[0].BillingResetDay != 31 {
		t.Fatalf("unexpected public status on pause: %+v err=%v", pubSnap, err)
	}

	// Both admin & user subscriptions remove the stop_all node
	stAdm, _, admBody, errAdm := client.GetAdminSub(adminTok, "mode=proxy")
	if errAdm != nil || stAdm != http.StatusOK {
		t.Fatalf("GetAdminSub failed: st=%d err=%v body=%s", stAdm, errAdm, admBody)
	}
	stUsr, _, usrBody, errUsr := client.GetUserSub(user.SubToken, "target=mihomo", "")
	if errUsr != nil || stUsr != http.StatusOK {
		t.Fatalf("GetUserSub failed: st=%d err=%v body=%s", stUsr, errUsr, usrBody)
	}
	if strings.Contains(admBody, "S4-StopAll-Node") || strings.Contains(usrBody, "S4-StopAll-Node") {
		t.Fatalf("stop_all paused node leaked into subscriptions: adm=%s user=%s", admBody, usrBody)
	}

	// Webhook fired traffic_paused
	reqs1, ok1 := whSrv.WaitForRequests(1, 5*time.Second)
	if !ok1 || !strings.Contains(reqs1[0].Body, "traffic_paused") {
		t.Fatalf("expected traffic_paused webhook, got %+v", reqs1)
	}

	// Billing reset recovery (via ResetNodeTraffic API) -> re-enables 3 kernels, subs, and resolved green card
	if st, raw, err := client.ResetNodeTraffic(jwt, node.ID); err != nil || st >= 300 {
		t.Fatalf("ResetNodeTraffic failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	t4_waitUntil(t, 12*time.Second, "all 3 kernels recovered after billing reset", func() bool {
		ext := t4_getNodeExt(t, client, jwt, node.ID)
		return !ext.IsTrafficPaused && ext.Status == "online" &&
			kernels.LiveProcessCount("snell-server") == 1 &&
			kernels.LiveProcessCount("shadow-tls") == 1 &&
			kernels.LiveProcessCount("sing-box") == 1
	})
	_, _, admAfter, _ := client.GetAdminSub(adminTok, "mode=proxy")
	_, _, usrAfter, _ := client.GetUserSub(user.SubToken, "target=mihomo", "")
	if !strings.Contains(admAfter, "S4-StopAll-Node") || !strings.Contains(usrAfter, "S4-StopAll-Node") {
		t.Fatalf("recovered node missing from subs: adm=%s user=%s", admAfter, usrAfter)
	}
	reqs2, ok2 := whSrv.WaitForRequests(2, 5*time.Second)
	if !ok2 || !strings.Contains(reqs2[1].Body, "traffic_recovered") || !strings.Contains(reqs2[1].Body, `"template":"green"`) {
		t.Fatalf("expected green traffic_recovered webhook, got %+v", reqs2)
	}
}

// Scenario 6: Node stop_ss_only threshold trigger -> user SS2022 disabled & removed from user sub while admin Snell stays active
func TestTier4_Scenario06_StopSSOnlyKeepsAdminSnellAndRemovesUserSS(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")
	kernels := BuildMockKernels(t, MockKernelOptions{})
	procPath := WriteProcNetDevFixture(t, "eth0", 1000, 1000)

	nStopSS := t4_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:                  "S4-StopSSOnly-Node",
		PublicIP:              "203.0.113.61",
		Enabled:               t4_boolPtr(true),
		TrafficLimitBytes:     10000,
		TrafficThresholdBytes: 5000,
		TrafficCountMode:      "both",
		ThresholdAction:       "stop_ss_only",
		SnellConfig: &SnellConfigDTO{
			Enabled: true, Version: "v5", PublicPort: AllocFreePort(t), InnerPort: AllocFreePort(t),
			PSK: "S4_KEEP_SNELL_PSK", STLSPassword: "S4_KEEP_STLS", STLSSNI: "gateway.icloud.com",
		},
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: AllocFreePort(t), UDPPort: AllocFreeUDPPort(t),
			Cipher: "2022-blake3-aes-128-gcm", IPSK: t4_b64Key16("s4-ss-ipsk!!!!!!"), STLSSNI: "swscan.apple.com",
		},
	})
	nControl := t4_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:     "S4-Control-Node",
		PublicIP: "203.0.113.62",
		Enabled:  t4_boolPtr(true),
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: AllocFreePort(t), UDPPort: AllocFreeUDPPort(t),
			Cipher: "2022-blake3-aes-128-gcm", IPSK: t4_b64Key16("s4-ctrl-ipsk!!!!"), STLSSNI: "swscan.apple.com",
		},
	})
	user := t4_mustCreateUser(t, client, jwt, CreateUserReq{Username: "s4_ssonly_user", NodeIDs: []int64{nStopSS.ID, nControl.ID}})
	adminTok := t4_getAdminSubToken(t, client, jwt)

	_ = StartAgent(env, AgentConfig{
		PanelURL:       panel.WSBaseURL(),
		NodeToken:      nStopSS.EffectiveToken(),
		Iface:          "eth0",
		ProcNetDevPath: procPath,
		SnellBin:       kernels.SnellBin,
		ShadowTLSBin:   kernels.ShadowTLSBin,
		SingBoxBin:     kernels.SingBoxBin,
	})

	t4_waitUntil(t, 15*time.Second, "stop_ss_only node online with all 3 kernels", func() bool {
		ext := t4_getNodeExt(t, client, jwt, nStopSS.ID)
		return ext.Status == "online" &&
			kernels.LiveProcessCount("snell-server") == 1 &&
			kernels.LiveProcessCount("shadow-tls") == 1 &&
			kernels.LiveProcessCount("sing-box") == 1
	})
	snellPID := kernels.RunningPIDs("snell-server")[0]
	stlsPID := kernels.RunningPIDs("shadow-tls")[0]
	time.Sleep(1500 * time.Millisecond)

	// Exceed threshold -> sing-box stops, snell-server & shadow-tls stay running with identical PIDs
	UpdateProcNetDevFixture(t, procPath, "eth0", 4000, 4000) // +3000 rx, +3000 tx = 6000 >= 5000
	t4_waitUntil(t, 15*time.Second, "stop_ss_only stops sing-box while keeping snell & shadow-tls", func() bool {
		ext := t4_getNodeExt(t, client, jwt, nStopSS.ID)
		return ext.IsTrafficPaused && kernels.LiveProcessCount("sing-box") == 0
	})

	if got := kernels.RunningPIDs("snell-server"); len(got) != 1 || got[0] != snellPID {
		t.Fatalf("snell-server PID interrupted by stop_ss_only: before=%d after=%v", snellPID, got)
	}
	if got := kernels.RunningPIDs("shadow-tls"); len(got) != 1 || got[0] != stlsPID {
		t.Fatalf("shadow-tls PID interrupted by stop_ss_only: before=%d after=%v", stlsPID, got)
	}

	// Admin sub keeps S4-StopSSOnly-Node; User sub removes S4-StopSSOnly-Node and keeps S4-Control-Node
	stAdm, _, admBody, errAdm := client.GetAdminSub(adminTok, "mode=proxy")
	if errAdm != nil || stAdm != http.StatusOK {
		t.Fatalf("GetAdminSub failed: st=%d err=%v body=%s", stAdm, errAdm, admBody)
	}
	if !strings.Contains(admBody, "S4-StopSSOnly-Node") || !strings.Contains(admBody, "S4_KEEP_SNELL_PSK") {
		t.Fatalf("admin sub must keep Snell on stop_ss_only:\n%s", admBody)
	}
	stUsr, _, usrBody, errUsr := client.GetUserSub(user.SubToken, "target=mihomo", "")
	if errUsr != nil || stUsr != http.StatusOK {
		t.Fatalf("GetUserSub failed: st=%d err=%v body=%s", stUsr, errUsr, usrBody)
	}
	if strings.Contains(usrBody, "S4-StopSSOnly-Node") || !strings.Contains(usrBody, "S4-Control-Node") {
		t.Fatalf("user sub must drop stop_ss_only node while keeping control node:\n%s", usrBody)
	}

	// Public status shows CoreAHealthy=true, CoreBHealthy=false
	t4_waitUntil(t, 20*time.Second, "public status reflects CoreA=true CoreB=false", func() bool {
		_, snap, _, err := client.GetPublicStatus()
		if err != nil {
			return false
		}
		for _, pn := range snap.Nodes {
			if pn.ID == nStopSS.ID {
				return pn.Status == "traffic_paused" && pn.CoreAHealthy && !pn.CoreBHealthy
			}
		}
		return false
	})
}

// Scenario 7: Cipher switch (aes-128-gcm <-> aes-256-gcm) preserves user credentials across Mihomo/Surge/Shadowrocket
func TestTier4_Scenario07_CipherSwitchPreservesUserCredentialsAcrossClients(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")
	kernels := BuildMockKernels(t, MockKernelOptions{})

	ipsk16 := t4_b64Key16("s4-cipher-16byte")
	ipsk32 := t4_b64Key32("s4-cipher-32byte-key-material!!!")
	snellPub := AllocFreePort(t)
	snellIn := AllocFreePort(t)
	ssTCP := AllocFreePort(t)
	ssUDP := AllocFreeUDPPort(t)

	node := t4_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name: "S4-Cipher-Node", PublicIP: "203.0.113.70", Enabled: t4_boolPtr(true), BillingResetDay: 1,
		SnellConfig: &SnellConfigDTO{Enabled: true, Version: "v5", PublicPort: snellPub, InnerPort: snellIn, PSK: "s4-c-psk", STLSPassword: "s4-c-stls", STLSSNI: "gateway.icloud.com"},
		SSConfig:    &SSConfigDTO{Enabled: true, TCPPort: ssTCP, UDPPort: ssUDP, Cipher: "2022-blake3-aes-128-gcm", IPSK: ipsk16, STLSSNI: "swscan.apple.com"},
	})
	user := t4_mustCreateUser(t, client, jwt, CreateUserReq{Username: "s4_cipher_u", NodeIDs: []int64{node.ID}})
	orig16, orig32, origSTLS, origSub := user.SSUPSK16, user.SSUPSK32, user.STLSPassword, user.SubToken

	ag := StartAgent(env, AgentConfig{
		PanelURL:     panel.WSBaseURL(),
		NodeToken:    node.EffectiveToken(),
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})
	sbCfgPath := filepath.Join(ag.DataDir, "configs", "sing-box.json")
	t4_waitUntil(t, 12*time.Second, "sing-box.json configured with 128-gcm and uPSK16 and running", func() bool {
		b, err := os.ReadFile(sbCfgPath)
		return err == nil && strings.Contains(string(b), "2022-blake3-aes-128-gcm") && strings.Contains(string(b), orig16) && kernels.LiveProcessCount("sing-box") == 1
	})
	sbPIDBefore := kernels.RunningPIDs("sing-box")
	if len(sbPIDBefore) != 1 {
		t.Fatalf("expected 1 running sing-box PID before cipher switch, got %v", sbPIDBefore)
	}

	checkClientSubs := func(cipher, wantIPSK, wantUPSK string) {
		_, _, mihomoBody, _ := client.GetUserSub(user.SubToken, "target=mihomo", "")
		if !strings.Contains(mihomoBody, cipher) || !strings.Contains(mihomoBody, wantIPSK+":"+wantUPSK) {
			t.Fatalf("mihomo sub mismatch for %s:\n%s", cipher, mihomoBody)
		}
		_, _, surgeBody, _ := client.GetUserSub(user.SubToken, "target=surge", "")
		if !strings.Contains(surgeBody, "encrypt-method="+cipher) || !strings.Contains(surgeBody, "password="+wantIPSK+":"+wantUPSK) {
			t.Fatalf("surge sub mismatch for %s:\n%s", cipher, surgeBody)
		}
		_, _, srBody, _ := client.GetUserSub(user.SubToken, "target=shadowrocket", "")
		dec, err := t4_decodeBase64Flexible(srBody)
		if err != nil {
			t.Fatalf("shadowrocket base64 decode: %v", err)
		}
		parsed, err := url.Parse(strings.TrimSpace(strings.Split(string(dec), "\n")[0]))
		if err != nil {
			t.Fatalf("shadowrocket uri parse: %v", err)
		}
		cred, _ := t4_decodeBase64Flexible(parsed.User.Username())
		if string(cred) != cipher+":"+wantIPSK+":"+wantUPSK {
			t.Fatalf("shadowrocket credential mismatch: got %q", string(cred))
		}
	}
	checkClientSubs("2022-blake3-aes-128-gcm", ipsk16, orig16)

	// Switch to 2022-blake3-aes-256-gcm
	if st, _, raw, err := client.UpdateNode(jwt, node.ID, CreateNodeReq{
		Name: "S4-Cipher-Node", PublicIP: "203.0.113.70", Enabled: t4_boolPtr(true), BillingResetDay: 1,
		SnellConfig: &SnellConfigDTO{Enabled: true, Version: "v5", PublicPort: snellPub, InnerPort: snellIn, PSK: "s4-c-psk", STLSPassword: "s4-c-stls", STLSSNI: "gateway.icloud.com"},
		SSConfig:    &SSConfigDTO{Enabled: true, TCPPort: ssTCP, UDPPort: ssUDP, Cipher: "2022-blake3-aes-256-gcm", IPSK: ipsk32, STLSSNI: "swscan.apple.com"},
	}); err != nil || st != http.StatusOK {
		t.Fatalf("UpdateNode cipher failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	var sbPIDAfter []int
	t4_waitUntil(t, 12*time.Second, "sing-box.json updated to 256-gcm and uPSK32 and sing-box reloaded", func() bool {
		b, err := os.ReadFile(sbCfgPath)
		if err != nil || !strings.Contains(string(b), "2022-blake3-aes-256-gcm") || !strings.Contains(string(b), orig32) {
			return false
		}
		sbPIDAfter = kernels.RunningPIDs("sing-box")
		return len(sbPIDAfter) == 1 && sbPIDAfter[0] != sbPIDBefore[0]
	})
	checkClientSubs("2022-blake3-aes-256-gcm", ipsk32, orig32)

	_, gotU, _, _ := client.GetUser(jwt, user.ID)
	if gotU.SSUPSK16 != orig16 || gotU.SSUPSK32 != orig32 || gotU.STLSPassword != origSTLS || gotU.SubToken != origSub {
		t.Fatalf("user credentials unexpectedly changed across cipher switch: %+v", gotU)
	}
}

// Scenario 8: Kernel online update -> crash during 3s health window -> .bak rollback + webhook alert + resolved recovery
func TestTier4_Scenario08_KernelUpdateCrashRollbackAlertAndResolvedRecovery(t *testing.T) {
	crashBytes := BuildMockKernelVariant(t, "sing-box", "sing-box version 9.9.9-crash", true)
	goodBytes := BuildMockKernelVariant(t, "sing-box", "sing-box version 1.12.2", false)
	crashAsset := "sing-box-9.9.9-crash.tar.gz"
	goodAsset := "sing-box-1.12.2.tar.gz"

	gh := StartMockGitHubServer(t, MockGitHubOptions{
		Releases: []MockGitHubRelease{{
			Owner: "SagerNet", Repo: "sing-box", TagName: "v1.12.2",
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
		Name:             "S4 Kernel Recovery Hook",
		Provider:         "feishu",
		URL:              whSrv.URL() + "/feishu",
		SubscribedEvents: []string{"kernel_update"},
		Enabled:          true,
	}); err != nil || st >= 300 {
		t.Fatalf("CreateWebhook failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	ssTCP := AllocFreePort(t)
	node := t4_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:    "S4-Updater-Node",
		Enabled: t4_boolPtr(true),
		SnellConfig: &SnellConfigDTO{
			Enabled: true, Version: "v5", PublicPort: AllocFreePort(t), InnerPort: AllocFreePort(t),
			PSK: "s4-upd-psk", STLSPassword: "s4-upd-stls", STLSSNI: "gateway.icloud.com",
		},
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: ssTCP, UDPPort: AllocFreeUDPPort(t),
			Cipher: "2022-blake3-aes-128-gcm", IPSK: t4_b64Key16("s4-upd-ipsk!!!!!"), STLSSNI: "swscan.apple.com",
		},
	})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     panel.WSBaseURL(),
		NodeToken:    node.EffectiveToken(),
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})
	t4_waitUntil(t, 12*time.Second, "node online & sing-box listening", func() bool {
		return t4_getNodeExt(t, client, jwt, node.ID).Status == "online" && kernels.LiveProcessCount("sing-box") == 1
	})
	t4_waitTCPReady(t, fmt.Sprintf("127.0.0.1:%d", ssTCP), 5*time.Second)

	// 1. Trigger crashing update -> .bak rollback + red Feishu alert
	if st, raw, err := client.TriggerKernelUpdate(jwt, []int64{node.ID}, "sing-box", "9.9.9-crash", gh.AssetURL(crashAsset), gh.AssetSHA256(crashAsset)); err != nil || st >= 300 {
		t.Fatalf("TriggerKernelUpdate crash failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	reqs1, ok1 := whSrv.WaitForRequests(1, 20*time.Second)
	if !ok1 || !strings.Contains(reqs1[0].Body, `"template":"red"`) {
		t.Fatalf("expected red kernel_update failure alert, got ok=%v reqs=%+v", ok1, reqs1)
	}
	if _, err := os.Stat(kernels.SingBoxBin + ".bak"); err != nil {
		t.Fatalf("expected .bak file after rollback: %v", err)
	}
	if out, err := exec.Command(kernels.SingBoxBin, "version").CombinedOutput(); err != nil || !strings.Contains(string(out), "1.11.4") {
		t.Fatalf("expected rolled-back binary 1.11.4, got err=%v out=%s", err, string(out))
	}
	t4_waitTCPReady(t, fmt.Sprintf("127.0.0.1:%d", ag.StatsPort), 5*time.Second)

	// 2. Trigger valid update -> 1.12.2 running + green resolved notification
	if st, raw, err := client.TriggerKernelUpdate(jwt, []int64{node.ID}, "sing-box", "1.12.2", gh.AssetURL(goodAsset), gh.AssetSHA256(goodAsset)); err != nil || st >= 300 {
		t.Fatalf("TriggerKernelUpdate good failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	reqs2, ok2 := whSrv.WaitForRequests(2, 20*time.Second)
	if !ok2 || !strings.Contains(reqs2[1].Body, `"template":"green"`) {
		t.Fatalf("expected green resolved notification, got ok=%v reqs=%+v", ok2, reqs2)
	}
	if out, err := exec.Command(kernels.SingBoxBin, "version").CombinedOutput(); err != nil || !strings.Contains(string(out), "1.12.2") {
		t.Fatalf("expected updated binary 1.12.2, got err=%v out=%s", err, string(out))
	}
	t4_waitTCPReady(t, fmt.Sprintf("127.0.0.1:%d", ssTCP), 5*time.Second)
}

// Scenario 9: Multi-user quota exhaustion & expire_at cutoff -> sing-box removal + Subscription-Userinfo + webhook
func TestTier4_Scenario09_MultiUserQuotaExpiryCutoffHeadersAndWebhook(t *testing.T) {
	whSrv := StartMockWebhookServer(t)
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")
	kernels := BuildMockKernels(t, MockKernelOptions{})

	if st, _, raw, err := client.CreateWebhook(jwt, WebhookChannelDTO{
		Name:             "S4 User Cutoff Hook",
		Provider:         "custom",
		URL:              whSrv.URL(),
		SubscribedEvents: []string{"user_quota_exhausted", "user_expired"},
		Enabled:          true,
	}); err != nil || st >= 300 {
		t.Fatalf("CreateWebhook failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	node := t4_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name: "S4-MultiUser-Node", PublicIP: "203.0.113.90", Enabled: t4_boolPtr(true),
		SnellConfig: &SnellConfigDTO{Enabled: true, Version: "v5", PublicPort: AllocFreePort(t), InnerPort: AllocFreePort(t), PSK: "s4-mu-psk", STLSPassword: "s4-mu-stls", STLSSNI: "gateway.icloud.com"},
		SSConfig:    &SSConfigDTO{Enabled: true, TCPPort: AllocFreePort(t), UDPPort: AllocFreeUDPPort(t), Cipher: "2022-blake3-aes-128-gcm", IPSK: t4_b64Key16("s4-mu-ipsk!!!!!!"), STLSSNI: "swscan.apple.com"},
	})

	futureExp := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	expStr := futureExp.Format(time.RFC3339)
	uQuota := t4_mustCreateUser(t, client, jwt, CreateUserReq{
		Username:          "s4_quota_u",
		TrafficQuotaBytes: 4000,
		NodeIDs:           []int64{node.ID},
	})
	uExpiry := t4_mustCreateUser(t, client, jwt, CreateUserReq{
		Username: "s4_expiry_u",
		ExpireAt: &expStr,
		NodeIDs:  []int64{node.ID},
	})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     panel.WSBaseURL(),
		NodeToken:    node.EffectiveToken(),
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})
	sbCfgPath := filepath.Join(ag.DataDir, "configs", "sing-box.json")
	t4_waitUntil(t, 12*time.Second, "both users in sing-box.json and gRPC ready", func() bool {
		b, err := os.ReadFile(sbCfgPath)
		return err == nil && strings.Contains(string(b), `"s4_quota_u"`) && strings.Contains(string(b), `"s4_expiry_u"`) && kernels.LiveProcessCount("sing-box") == 1
	})
	t4_waitTCPReady(t, fmt.Sprintf("127.0.0.1:%d", ag.StatsPort), 5*time.Second)

	// 1. Exhaust uQuota via gRPC StatsService -> removed from sing-box, webhook fired, sub rejected with headers
	kernels.SetStats([]MockUserStat{
		{Name: "user>>>s4_quota_u>>>traffic>>>uplink", Value: 1500},
		{Name: "user>>>s4_quota_u>>>traffic>>>downlink", Value: 2500},
	})
	t4_waitUntil(t, 20*time.Second, "s4_quota_u exhausted and removed from sing-box.json", func() bool {
		b, err := os.ReadFile(sbCfgPath)
		return err == nil && !strings.Contains(string(b), `"s4_quota_u"`) && strings.Contains(string(b), `"s4_expiry_u"`)
	})

	stQ, hdrQ, _, _ := client.GetUserSub(uQuota.SubToken, "target=mihomo", "")
	if stQ != http.StatusForbidden && stQ != http.StatusNotFound {
		t.Fatalf("expected 403/404 for exhausted user sub, got %d", stQ)
	}
	if hdrQ.Get("Subscription-Userinfo") != "upload=1500; download=2500; total=4000; expire=0" {
		t.Fatalf("unexpected exhausted Subscription-Userinfo: %q", hdrQ.Get("Subscription-Userinfo"))
	}

	// 2. Expire uExpiry -> removed from sing-box, webhook fired, sub rejected with expire header
	pastExp := time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Second)
	pastStr := pastExp.Format(time.RFC3339)
	if st, _, raw, err := client.UpdateUser(jwt, uExpiry.ID, CreateUserReq{
		Username: uExpiry.Username, Enabled: t4_boolPtr(true), ExpireAt: &pastStr,
	}); err != nil || st != http.StatusOK {
		t.Fatalf("UpdateUser expire failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	t4_waitUntil(t, 10*time.Second, "s4_expiry_u removed from sing-box.json", func() bool {
		b, err := os.ReadFile(sbCfgPath)
		return err == nil && !strings.Contains(string(b), `"s4_expiry_u"`)
	})

	stE, hdrE, _, _ := client.GetUserSub(uExpiry.SubToken, "target=mihomo", "")
	if stE != http.StatusForbidden && stE != http.StatusNotFound {
		t.Fatalf("expected 403/404 for expired user sub, got %d", stE)
	}
	wantExpHdr := fmt.Sprintf("upload=0; download=0; total=0; expire=%d", pastExp.Unix())
	if hdrE.Get("Subscription-Userinfo") != wantExpHdr {
		t.Fatalf("expired Subscription-Userinfo mismatch: got %q want %q", hdrE.Get("Subscription-Userinfo"), wantExpHdr)
	}

	reqs, ok := whSrv.WaitForRequests(2, 25*time.Second)
	if !ok || len(reqs) < 2 {
		t.Fatalf("expected >=2 user cutoff webhooks, got %d", len(reqs))
	}
	joinedHooks := reqs[0].Body + "\n" + reqs[1].Body
	if !strings.Contains(joinedHooks, "user_quota_exhausted") || !strings.Contains(joinedHooks, "user_expired") {
		t.Fatalf("expected both user_quota_exhausted and user_expired webhooks, got:\n%s", joinedHooks)
	}

	// 3. Reset uQuota traffic -> restored to sing-box.json and sub returns 200 OK
	if st, raw, err := client.ResetUserTraffic(jwt, uQuota.ID); err != nil || st >= 300 {
		t.Fatalf("ResetUserTraffic failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	t4_waitUntil(t, 10*time.Second, "s4_quota_u restored to sing-box.json and sing-box running", func() bool {
		b, err := os.ReadFile(sbCfgPath)
		return err == nil && strings.Contains(string(b), `"s4_quota_u"`) && kernels.LiveProcessCount("sing-box") == 1
	})
	if stOk, _, _, _ := client.GetUserSub(uQuota.SubToken, "target=mihomo", ""); stOk != http.StatusOK {
		t.Fatalf("expected 200 OK for restored user sub, got %d", stOk)
	}
}

// Scenario 10: Public visitor & admin browser flow -> / SPA & redacted /api/v1/public/ws zero-leak + /admin authenticated management
func TestTier4_Scenario10_PublicZeroLeakLiveWSAndAdminSPAWorkflow(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{AdminPass: "S4_CANARY_PASS_2026"})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "S4_CANARY_PASS_2026")
	adminSubTok := t4_getAdminSubToken(t, client, jwt)
	kernels := BuildMockKernels(t, MockKernelOptions{})

	if st, raw, err := client.UpdateSettings(jwt, map[string]any{
		"site_title":      "S4 Public Status",
		"announcement":    "All systems nominal",
		"percentage_only": true,
	}); err != nil || st >= 300 {
		t.Fatalf("UpdateSettings failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	node := t4_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:              "S4-Public-Node",
		RegionTag:         "SG",
		PublicIP:          "198.51.100.222",
		CustomEntryHost:   "s4-secret-entry.internal",
		CustomEntryPort:   55555,
		Enabled:           t4_boolPtr(true),
		TrafficLimitBytes: 100000,
		SnellConfig: &SnellConfigDTO{
			Enabled: true, Version: "v5", PublicPort: AllocFreePort(t), InnerPort: AllocFreePort(t),
			PSK: "S4_CANARY_SNELL_PSK", STLSPassword: "S4_CANARY_STLS_PWD", STLSSNI: "s4-snell.internal",
		},
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: AllocFreePort(t), UDPPort: AllocFreeUDPPort(t),
			Cipher: "2022-blake3-aes-128-gcm", IPSK: t4_b64Key16("S4_CANARY_IPSK!!"), STLSSNI: "s4-ss.internal",
		},
		DNSUnlockServer: "198.51.100.223:3535",
	})
	user := t4_mustCreateUser(t, client, jwt, CreateUserReq{Username: "s4_secret_user", NodeIDs: []int64{node.ID}})
	if st, raw, err := client.CalibrateNodeTraffic(jwt, node.ID, 20000, 20000); err != nil || st >= 300 { // 40%
		t.Fatalf("CalibrateNodeTraffic failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pubWS, _, err := client.DialPublicWS(ctx)
	if err != nil {
		t.Fatalf("DialPublicWS failed: %v", err)
	}
	defer pubWS.CloseNow()

	_ = StartAgent(env, AgentConfig{
		PanelURL:     panel.WSBaseURL(),
		NodeToken:    node.EffectiveToken(),
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	secrets := []string{
		"S4_CANARY_PASS_2026", adminSubTok, "198.51.100.222", "198.51.100.223:3535",
		"s4-secret-entry.internal", "S4_CANARY_SNELL_PSK", "S4_CANARY_STLS_PWD",
		"S4_CANARY_IPSK!!", "s4-snell.internal", "s4-ss.internal",
		node.EffectiveToken(), "s4_secret_user", user.SubToken, user.SSUPSK16, user.SSUPSK32, user.STLSPassword,
	}

	// Visitor checks / HTML + assets
	stRoot, hdrRoot, rootHTML, err := client.DoRaw(ctx, http.MethodGet, "/", nil, nil)
	if err != nil || stRoot != http.StatusOK || !strings.Contains(strings.ToLower(hdrRoot.Get("Content-Type")), "text/html") {
		t.Fatalf("GET / failed: st=%d err=%v", stRoot, err)
	}
	for _, sec := range secrets {
		if strings.Contains(string(rootHTML), sec) {
			t.Fatalf("secret %q leaked in GET / HTML", sec)
		}
	}
	for _, ref := range t4_extractAssets(string(rootHTML)) {
		p := ref
		if !strings.HasPrefix(p, "/") {
			p = "/" + strings.TrimLeft(p, "./")
		}
		stA, _, bodyA, errA := client.DoRaw(ctx, http.MethodGet, p, nil, nil)
		if errA != nil || stA != http.StatusOK {
			t.Fatalf("GET asset %s failed: st=%d err=%v", p, stA, errA)
		}
		for _, sec := range secrets {
			if strings.Contains(string(bodyA), sec) {
				t.Fatalf("secret %q leaked in public asset %s", sec, p)
			}
		}
	}

	// Live /api/v1/public/ws reaches online with percentage_only & zero leaks
	rctx, rcancel := context.WithTimeout(ctx, 15*time.Second)
	defer rcancel()
	for {
		_, frame, err := pubWS.Read(rctx)
		if err != nil {
			t.Fatalf("public WS read failed before live online frame: %v", err)
		}
		for _, sec := range secrets {
			if strings.Contains(string(frame), sec) {
				t.Fatalf("secret %q leaked in public WS frame: %s", sec, string(frame))
			}
		}
		var snap PublicStatusSnapshotDTO
		if json.Unmarshal(frame, &snap) == nil && len(snap.Nodes) == 1 {
			n := snap.Nodes[0]
			if n.Status == "online" && n.CoreAHealthy && n.CoreBHealthy &&
				snap.PercentageOnly && n.PercentageOnly &&
				n.TrafficPercent >= 39.9 && n.TrafficPercent <= 40.1 {
				if n.TrafficUsedBytes != 0 || n.TrafficLimitBytes != 0 {
					t.Fatalf("unexpected raw traffic bytes leaked in public WS node view: %+v", n)
				}
				break
			}
		}
	}

	// Admin SPA routes + JWT gate
	for _, route := range []string{"/admin", "/admin/nodes", "/admin/users"} {
		st, _, html, err := client.DoRaw(ctx, http.MethodGet, route, nil, nil)
		if err != nil || st != http.StatusOK || !strings.Contains(strings.ToLower(string(html)), "<script") {
			t.Fatalf("GET %s failed: st=%d err=%v", route, st, err)
		}
	}
	if st, _, _ := client.DoJSON(ctx, http.MethodGet, "/api/v1/admin/nodes", "", nil, nil); st != http.StatusUnauthorized {
		t.Fatalf("expected 401 unauthenticated /api/v1/admin/nodes, got %d", st)
	}
	if st, nodes, _, err := client.ListNodes(jwt); err != nil || st != http.StatusOK || len(nodes) != 1 {
		t.Fatalf("authenticated ListNodes failed: st=%d len=%d err=%v", st, len(nodes), err)
	}
}

// Scenario 11: Deployment artifact validation -> multi-arch Dockerfiles, docker-compose, GitHub Actions CI, and README consistency
func TestTier4_Scenario11_DeploymentDockerCIRunbookConsistency(t *testing.T) {
	repoRoot := findRepoRoot(t)
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if len(strings.TrimSpace(string(b))) == 0 {
			t.Fatalf("%s is empty", rel)
		}
		return string(b)
	}

	panelDF := read("deploy/Dockerfile.panel")
	agentDF := read("deploy/Dockerfile.agent")
	composeRaw := read("deploy/docker-compose.yml")
	readme := read("README.md")
	embedGo := read("web/embed.go")
	panelMain := read("cmd/panel/main.go")
	agentMain := read("cmd/agent/main.go")

	// Zero stubs or leaked credentials
	for name, txt := range map[string]string{
		"deploy/Dockerfile.panel":   panelDF,
		"deploy/Dockerfile.agent":   agentDF,
		"deploy/docker-compose.yml": composeRaw,
		"README.md":                 readme,
	} {
		if m := t4_stubWordRe.FindString(txt); m != "" {
			t.Fatalf("%s contains placeholder/stub marker %q", name, m)
		}
		if m := t4_secretRe.FindString(txt); m != "" {
			t.Fatalf("%s contains leaked credential pattern %q", name, m)
		}
	}

	// Web embed directive
	if !strings.Contains(embedGo, "//go:embed") || !strings.Contains(embedGo, "dist") {
		t.Fatalf("web/embed.go missing //go:embed dist directive")
	}

	// Dockerfile.panel multi-stage + 8080 + /app/data
	pLower := strings.ToLower(t4_stripDockerfileComments(panelDF))
	for _, req := range []string{"node", "npm", "golang", "1.24", "cgo_enabled=0", "./cmd/panel", "8080", "/app/data"} {
		if !strings.Contains(pLower, req) {
			t.Fatalf("deploy/Dockerfile.panel missing %q", req)
		}
	}

	// Dockerfile.agent multi-arch + tini + 3 kernels + /var/lib/snell-panel-agent
	aLower := strings.ToLower(t4_stripDockerfileComments(agentDF))
	for _, req := range []string{"golang", "1.24", "cgo_enabled=0", "./cmd/agent", "tini", "snell-server", "shadow-tls", "sing-box", "/var/lib/snell-panel-agent"} {
		if !strings.Contains(aLower, req) {
			t.Fatalf("deploy/Dockerfile.agent missing %q", req)
		}
	}
	if !strings.Contains(aLower, "targetarch") && !strings.Contains(aLower, "targetplatform") {
		t.Fatalf("deploy/Dockerfile.agent missing TARGETARCH/TARGETPLATFORM")
	}

	// docker-compose.yml valid YAML + env parity with Go binaries
	allowedEnv := map[string]bool{"TZ": true, "GITHUB_API_URL": true}
	for _, src := range []string{panelMain, agentMain} {
		for _, m := range t4_envVarRe.FindAllStringSubmatch(src, -1) {
			allowedEnv[m[1]] = true
		}
	}
	var compose struct {
		Services map[string]struct {
			Restart     string   `yaml:"restart"`
			NetworkMode string   `yaml:"network_mode"`
			Ports       []string `yaml:"ports"`
			Volumes     []string `yaml:"volumes"`
			Environment any      `yaml:"environment"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(composeRaw), &compose); err != nil {
		t.Fatalf("deploy/docker-compose.yml invalid YAML: %v", err)
	}
	if len(compose.Services) == 0 {
		t.Fatal("deploy/docker-compose.yml has 0 services")
	}
	for svcName, svc := range compose.Services {
		switch ev := svc.Environment.(type) {
		case map[string]any:
			for k := range ev {
				if !allowedEnv[k] {
					t.Fatalf("compose service %q uses unknown env %q", svcName, k)
				}
			}
		case []any:
			for _, item := range ev {
				s := fmt.Sprint(item)
				k := strings.TrimSpace(strings.SplitN(s, "=", 2)[0])
				if k != "" && !allowedEnv[k] {
					t.Fatalf("compose service %q uses unknown env %q", svcName, k)
				}
			}
		}
	}

	// GitHub Actions workflows
	wfDir := filepath.Join(repoRoot, ".github", "workflows")
	entries, err := os.ReadDir(wfDir)
	if err != nil {
		t.Fatalf("read .github/workflows: %v", err)
	}
	var wfAll strings.Builder
	for _, e := range entries {
		if !e.IsDir() && (strings.HasSuffix(e.Name(), ".yml") || strings.HasSuffix(e.Name(), ".yaml")) {
			raw := read(filepath.Join(".github", "workflows", e.Name()))
			var doc map[string]any
			if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
				t.Fatalf("workflow %s invalid YAML: %v", e.Name(), err)
			}
			wfAll.WriteString(raw)
			wfAll.WriteByte('\n')
		}
	}
	wfText := wfAll.String()
	for _, req := range []string{"go vet", "go test", "-race", "npm run build", "docker/setup-qemu-action", "docker/setup-buildx-action", "docker/build-push-action", "linux/amd64", "linux/arm64"} {
		if !strings.Contains(wfText, req) {
			t.Fatalf("CI workflows missing %q", req)
		}
	}

	// README documentation completeness
	for _, req := range []string{"docker-compose.yml", "8080", "./data", "ADMIN_USER", "ADMIN_INITIAL_PASS", "PANEL_URL", "NODE_TOKEN", "--network host", "/var/lib/snell-panel-agent", "/s/admin/", "/s/u/", "Surge", "Mihomo", "Shadowrocket", "MoeClub/haproxy_docker", "panel.db"} {
		if !strings.Contains(readme, req) {
			t.Fatalf("README.md missing %q", req)
		}
	}
}
