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
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/miekg/dns"
)

type f06_mockPanelWS struct {
	t    *testing.T
	addr string

	mu     sync.Mutex
	srv    *http.Server
	conns  map[*websocket.Conn]struct{}
	hellos []AgentHelloPayload
	events []AgentEventPayload
}

func f06_newMockPanelWS(t *testing.T) *f06_mockPanelWS {
	t.Helper()
	port := AllocFreePort(t)
	m := &f06_mockPanelWS{
		t:     t,
		addr:  fmt.Sprintf("127.0.0.1:%d", port),
		conns: make(map[*websocket.Conn]struct{}),
	}
	ln, err := net.Listen("tcp", m.addr)
	if err != nil {
		t.Fatalf("f06_mockPanelWS listen: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agent/ws", m.handleWS)
	srv := &http.Server{Handler: mux}
	m.srv = srv
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { m.Stop() })
	return m
}

func (m *f06_mockPanelWS) WSBaseURL() string { return "ws://" + m.addr }

func (m *f06_mockPanelWS) Stop() {
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

func (m *f06_mockPanelWS) handleWS(w http.ResponseWriter, r *http.Request) {
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
		case "agent.event":
			var p AgentEventPayload
			if json.Unmarshal(env.Payload, &p) == nil {
				m.events = append(m.events, p)
			}
		}
		m.mu.Unlock()
	}
}

func (m *f06_mockPanelWS) SendEnvelope(msgType, reqID string, payload any) error {
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

func (m *f06_mockPanelWS) WaitForHello(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		n := len(m.hellos)
		m.mu.Unlock()
		if n > 0 {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}

func (m *f06_mockPanelWS) WaitForEvent(timeout time.Duration, match func(AgentEventPayload) bool) (AgentEventPayload, bool) {
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

func f06_b64Key16(seed string) string {
	b := make([]byte, 16)
	copy(b, []byte(seed))
	return base64.StdEncoding.EncodeToString(b)
}

func f06_startAgentWithDNS(t *testing.T, dnsCfg DNSConfigDTO) (*AgentProcess, *f06_mockPanelWS, *MockKernelSet) {
	t.Helper()
	env := NewTestEnv(t)
	srv := f06_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    "nd_live_f06_dns_test",
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})
	if !srv.WaitForHello(8 * time.Second) {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}

	if dnsCfg.LocalPort == 0 {
		dnsCfg.LocalPort = ag.LocalDNSPort
	}
	syncPayload := ServerConfigSyncPayload{
		ConfigRevision: 1,
		Snell: SnellConfigDTO{
			Enabled:      true,
			Version:      "v5",
			PublicPort:   AllocFreePort(t),
			InnerPort:    AllocFreePort(t),
			PSK:          "f06-snell-psk",
			Obfs:         "off",
			STLSPassword: "f06-stls-pwd",
			STLSSNI:      "gateway.icloud.com",
		},
		SS: SSConfigDTO{
			Enabled: true,
			TCPPort: AllocFreePort(t),
			UDPPort: AllocFreeUDPPort(t),
			Cipher:  "2022-blake3-aes-128-gcm",
			IPSK:    f06_b64Key16("f06-server-ipsk!"),
			STLSSNI: "swscan.apple.com",
			Users: []SSUserEntryDTO{
				{UserID: 1, Username: "alice", UPSK: f06_b64Key16("f06-alice-upsk!!"), STLSPassword: "p1"},
			},
		},
		DNS: dnsCfg,
	}
	if err := srv.SendEnvelope("server.config_sync", "s1", syncPayload); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 1
	}); !ok {
		t.Fatalf("expected config_applied rev 1; logs:\n%s", ag.Logs())
	}
	return ag, srv, kernels
}

func f06_exchange(t *testing.T, addr, proto, qname string, qtype uint16, timeout time.Duration) *dns.Msg {
	t.Helper()
	c := &dns.Client{Net: proto, Timeout: timeout}
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("DNS %s query(%s, %s) to %s failed: %v", proto, qname, dns.TypeToString[qtype], addr, err)
	}
	return resp
}

func f06_assertFirstA(t *testing.T, resp *dns.Msg, wantIP string) {
	t.Helper()
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) == 0 {
		t.Fatalf("expected >=1 A answer for %s, got 0", wantIP)
	}
	aRec, ok := resp.Answer[0].(*dns.A)
	if !ok || aRec.A.String() != wantIP {
		t.Fatalf("expected A=%s, got %+v", wantIP, resp.Answer[0])
	}
}

func TestF06_Tier1_LoopbackDispatcherSharedBySnellAndSingBox(t *testing.T) {
	unlockSrv := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"netflix.com": {"203.0.113.10"}}})
	normalSrv := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.org": {"198.51.100.10"}}})

	ag, _, _ := f06_startAgentWithDNS(t, DNSConfigDTO{
		UnlockEnabled: true,
		UnlockServer:  unlockSrv.Addr(),
		Rules:         []string{"netflix.com"},
		UpstreamDNS:   normalSrv.Addr(),
	})

	addr := fmt.Sprintf("127.0.0.1:%d", ag.LocalDNSPort)
	f06_assertFirstA(t, f06_exchange(t, addr, "udp", "netflix.com.", dns.TypeA, 3*time.Second), "203.0.113.10")
	f06_assertFirstA(t, f06_exchange(t, addr, "tcp", "netflix.com.", dns.TypeA, 3*time.Second), "203.0.113.10")

	snellConf, err := os.ReadFile(filepath.Join(ag.DataDir, "configs", "snell-server.conf"))
	if err != nil {
		t.Fatalf("read snell-server.conf: %v", err)
	}
	if ag.LocalDNSPort == 53 {
		if !strings.Contains(string(snellConf), "dns = 127.0.0.1\n") {
			t.Fatalf("expected bare loopback dns = 127.0.0.1 in snell-server.conf:\n%s", string(snellConf))
		}
	} else if strings.Contains(string(snellConf), fmt.Sprintf("dns = 127.0.0.1:%d", ag.LocalDNSPort)) {
		t.Fatalf("snell-server.conf must not emit non-53 host:port dns line:\n%s", string(snellConf))
	}

	sbConf, err := os.ReadFile(filepath.Join(ag.DataDir, "configs", "sing-box.json"))
	if err != nil {
		t.Fatalf("read sing-box.json: %v", err)
	}
	if !strings.Contains(string(sbConf), fmt.Sprintf("127.0.0.1:%d", ag.LocalDNSPort)) &&
		!(strings.Contains(string(sbConf), `"127.0.0.1"`) && strings.Contains(string(sbConf), fmt.Sprintf(`"server_port": %d`, ag.LocalDNSPort))) {
		t.Fatalf("expected sing-box.json to reference loopback DNS port %d:\n%s", ag.LocalDNSPort, string(sbConf))
	}
}

func TestF06_Tier1_RuleGranularityRootAndSubdomains(t *testing.T) {
	unlockSrv := StartMockDNSServer(t, MockDNSOptions{
		Records: map[string][]string{
			"netflix.com":        {"203.0.113.20"},
			"api.us.netflix.com": {"203.0.113.21"},
		},
	})
	normalSrv := StartMockDNSServer(t, MockDNSOptions{
		Records: map[string][]string{
			"netflix.com":        {"198.51.100.20"},
			"api.us.netflix.com": {"198.51.100.21"},
			"notnetflix.com":     {"198.51.100.22"},
		},
	})

	ag, _, _ := f06_startAgentWithDNS(t, DNSConfigDTO{
		UnlockEnabled: true,
		UnlockServer:  unlockSrv.Addr(),
		Rules:         []string{"netflix.com"},
		UpstreamDNS:   normalSrv.Addr(),
	})

	addr := fmt.Sprintf("127.0.0.1:%d", ag.LocalDNSPort)
	f06_assertFirstA(t, f06_exchange(t, addr, "udp", "netflix.com.", dns.TypeA, 3*time.Second), "203.0.113.20")
	f06_assertFirstA(t, f06_exchange(t, addr, "udp", "api.us.netflix.com.", dns.TypeA, 3*time.Second), "203.0.113.21")
	f06_assertFirstA(t, f06_exchange(t, addr, "udp", "notnetflix.com.", dns.TypeA, 3*time.Second), "198.51.100.22")

	for _, q := range unlockSrv.Queries() {
		if q.Name == "notnetflix.com." {
			t.Fatalf("notnetflix.com should not route to unlockSrv")
		}
	}
	for _, q := range normalSrv.Queries() {
		if q.Name == "netflix.com." || q.Name == "api.us.netflix.com." {
			t.Fatalf("matched domain %q leaked to normalSrv", q.Name)
		}
	}
}

func TestF06_Tier1_RuleGranularityExactDomain(t *testing.T) {
	unlockSrv := StartMockDNSServer(t, MockDNSOptions{
		Records: map[string][]string{
			"openai.com":  {"203.0.113.30"},
			"chatgpt.com": {"203.0.113.31"},
		},
	})
	normalSrv := StartMockDNSServer(t, MockDNSOptions{
		Records: map[string][]string{
			"api.openai.com":  {"198.51.100.30"},
			"cdn.chatgpt.com": {"198.51.100.31"},
		},
	})

	ag, _, _ := f06_startAgentWithDNS(t, DNSConfigDTO{
		UnlockEnabled: true,
		UnlockServer:  unlockSrv.Addr(),
		Rules:         []string{"^openai.com", "@chatgpt.com"},
		UpstreamDNS:   normalSrv.Addr(),
	})

	addr := fmt.Sprintf("127.0.0.1:%d", ag.LocalDNSPort)
	f06_assertFirstA(t, f06_exchange(t, addr, "udp", "openai.com.", dns.TypeA, 3*time.Second), "203.0.113.30")
	f06_assertFirstA(t, f06_exchange(t, addr, "udp", "chatgpt.com.", dns.TypeA, 3*time.Second), "203.0.113.31")
	f06_assertFirstA(t, f06_exchange(t, addr, "udp", "api.openai.com.", dns.TypeA, 3*time.Second), "198.51.100.30")
	f06_assertFirstA(t, f06_exchange(t, addr, "udp", "cdn.chatgpt.com.", dns.TypeA, 3*time.Second), "198.51.100.31")

	for _, q := range unlockSrv.Queries() {
		if q.Name == "api.openai.com." || q.Name == "cdn.chatgpt.com." {
			t.Fatalf("subdomain %q should not match exact rule", q.Name)
		}
	}
}

func TestF06_Tier1_RuleGranularityWildcardSubdomainOnly(t *testing.T) {
	unlockSrv := StartMockDNSServer(t, MockDNSOptions{
		Records: map[string][]string{
			"www.disneyplus.com": {"203.0.113.40"},
			"a.b.disneyplus.com": {"203.0.113.41"},
		},
	})
	normalSrv := StartMockDNSServer(t, MockDNSOptions{
		Records: map[string][]string{
			"disneyplus.com": {"198.51.100.40"},
		},
	})

	ag, _, _ := f06_startAgentWithDNS(t, DNSConfigDTO{
		UnlockEnabled: true,
		UnlockServer:  unlockSrv.Addr(),
		Rules:         []string{"*.disneyplus.com"},
		UpstreamDNS:   normalSrv.Addr(),
	})

	addr := fmt.Sprintf("127.0.0.1:%d", ag.LocalDNSPort)
	f06_assertFirstA(t, f06_exchange(t, addr, "udp", "www.disneyplus.com.", dns.TypeA, 3*time.Second), "203.0.113.40")
	f06_assertFirstA(t, f06_exchange(t, addr, "udp", "a.b.disneyplus.com.", dns.TypeA, 3*time.Second), "203.0.113.41")
	f06_assertFirstA(t, f06_exchange(t, addr, "udp", "disneyplus.com.", dns.TypeA, 3*time.Second), "198.51.100.40")

	for _, q := range unlockSrv.Queries() {
		if q.Name == "disneyplus.com." {
			t.Fatalf("root disneyplus.com should not match *.disneyplus.com")
		}
	}
}

func TestF06_Tier1_NonStandardUnlockPortAndNormalFallback(t *testing.T) {
	unlockSrv := StartMockDNSServer(t, MockDNSOptions{
		Records: map[string][]string{"hulu.com": {"203.0.113.50"}},
	})
	normalSrv := StartMockDNSServer(t, MockDNSOptions{
		Records: map[string][]string{"example.org": {"198.51.100.50"}},
	})
	if unlockSrv.Port() == 53 {
		t.Fatalf("expected ephemeral non-53 unlock port")
	}

	ag, _, _ := f06_startAgentWithDNS(t, DNSConfigDTO{
		UnlockEnabled: true,
		UnlockServer:  unlockSrv.Addr(),
		Rules:         []string{"hulu.com"},
		UpstreamDNS:   normalSrv.Addr(),
	})

	addr := fmt.Sprintf("127.0.0.1:%d", ag.LocalDNSPort)
	f06_assertFirstA(t, f06_exchange(t, addr, "udp", "hulu.com.", dns.TypeA, 3*time.Second), "203.0.113.50")
	f06_assertFirstA(t, f06_exchange(t, addr, "udp", "example.org.", dns.TypeA, 3*time.Second), "198.51.100.50")

	if len(unlockSrv.Queries()) != 1 || unlockSrv.Queries()[0].Name != "hulu.com." {
		t.Fatalf("expected only hulu.com on unlockSrv, got %+v", unlockSrv.Queries())
	}
	if len(normalSrv.Queries()) != 1 || normalSrv.Queries()[0].Name != "example.org." {
		t.Fatalf("expected only example.org on normalSrv, got %+v", normalSrv.Queries())
	}
}

func TestF06_Tier2_ImmediateEmptyNODATABlockTypes(t *testing.T) {
	unlockSrv := StartMockDNSServer(t, MockDNSOptions{
		Records:      map[string][]string{"netflix.com": {"203.0.113.60"}},
		AAAARecords:  map[string][]string{"netflix.com": {"2001:db8::60"}},
		HTTPSRecords: map[string]bool{"netflix.com": true},
		SVCBRecords:  map[string]bool{"netflix.com": true},
	})
	normalSrv := StartMockDNSServer(t, MockDNSOptions{
		Records:      map[string][]string{"netflix.com": {"198.51.100.60"}},
		AAAARecords:  map[string][]string{"netflix.com": {"2001:db8::61"}},
		HTTPSRecords: map[string]bool{"netflix.com": true},
		SVCBRecords:  map[string]bool{"netflix.com": true},
	})

	ag, _, _ := f06_startAgentWithDNS(t, DNSConfigDTO{
		UnlockEnabled: true,
		UnlockServer:  unlockSrv.Addr(),
		Rules:         []string{"netflix.com"},
		UpstreamDNS:   normalSrv.Addr(),
	})
	unlockSrv.ResetQueries()
	normalSrv.ResetQueries()

	addr := fmt.Sprintf("127.0.0.1:%d", ag.LocalDNSPort)
	for _, qt := range []uint16{dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB, dns.TypeANY} {
		resp := f06_exchange(t, addr, "udp", "netflix.com.", qt, 3*time.Second)
		if resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("qtype %s expected NOERROR, got %s", dns.TypeToString[qt], dns.RcodeToString[resp.Rcode])
		}
		if len(resp.Answer) != 0 || len(resp.Ns) != 0 {
			t.Fatalf("qtype %s expected empty NODATA, got answer=%d ns=%d", dns.TypeToString[qt], len(resp.Answer), len(resp.Ns))
		}
	}

	if len(unlockSrv.Queries()) != 0 {
		t.Fatalf("blocked qtypes leaked to unlockSrv: %+v", unlockSrv.Queries())
	}
	if len(normalSrv.Queries()) != 0 {
		t.Fatalf("blocked qtypes leaked to normalSrv: %+v", normalSrv.Queries())
	}
}

func TestF06_Tier2_UnlockDisabledRoutesAllToNormalUpstream(t *testing.T) {
	unlockSrv := StartMockDNSServer(t, MockDNSOptions{
		Records: map[string][]string{"netflix.com": {"203.0.113.70"}},
	})
	normalSrv := StartMockDNSServer(t, MockDNSOptions{
		Records:      map[string][]string{"netflix.com": {"198.51.100.70"}},
		AAAARecords:  map[string][]string{"netflix.com": {"2001:db8::70"}},
		HTTPSRecords: map[string]bool{"netflix.com": true},
		SVCBRecords:  map[string]bool{"netflix.com": true},
	})

	ag, _, _ := f06_startAgentWithDNS(t, DNSConfigDTO{
		UnlockEnabled: false,
		UnlockServer:  unlockSrv.Addr(),
		Rules:         []string{"netflix.com"},
		UpstreamDNS:   normalSrv.Addr(),
	})

	addr := fmt.Sprintf("127.0.0.1:%d", ag.LocalDNSPort)
	f06_assertFirstA(t, f06_exchange(t, addr, "udp", "netflix.com.", dns.TypeA, 3*time.Second), "198.51.100.70")

	for _, qt := range []uint16{dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB} {
		resp := f06_exchange(t, addr, "udp", "netflix.com.", qt, 3*time.Second)
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
			t.Fatalf("unlock disabled qtype %s expected real answer from normalSrv, got rcode=%s ans=%d",
				dns.TypeToString[qt], dns.RcodeToString[resp.Rcode], len(resp.Answer))
		}
	}
	if len(unlockSrv.Queries()) != 0 {
		t.Fatalf("unlockSrv should receive 0 queries when unlock_enabled=false, got %+v", unlockSrv.Queries())
	}
}

func TestF06_Tier2_UnreachableUnlockUpstreamSERVFAILNoLeak(t *testing.T) {
	closedPort := AllocFreeDualPort(t)
	normalSrv := StartMockDNSServer(t, MockDNSOptions{
		Records: map[string][]string{"netflix.com": {"198.51.100.80"}},
	})

	ag, _, _ := f06_startAgentWithDNS(t, DNSConfigDTO{
		UnlockEnabled: true,
		UnlockServer:  fmt.Sprintf("127.0.0.1:%d", closedPort),
		Rules:         []string{"netflix.com"},
		UpstreamDNS:   normalSrv.Addr(),
	})
	normalSrv.ResetQueries()

	addr := fmt.Sprintf("127.0.0.1:%d", ag.LocalDNSPort)
	resp := f06_exchange(t, addr, "udp", "netflix.com.", dns.TypeA, 6*time.Second)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL when unlock server unreachable, got %s", dns.RcodeToString[resp.Rcode])
	}
	if len(normalSrv.Queries()) != 0 {
		t.Fatalf("unreachable unlock query leaked to normalSrv: %+v", normalSrv.Queries())
	}
}

func TestF06_Tier2_CaseInsensitiveAndTrailingDotFQDN(t *testing.T) {
	unlockSrv := StartMockDNSServer(t, MockDNSOptions{
		Records:     map[string][]string{"netflix.com": {"203.0.113.90"}, "www.netflix.com": {"203.0.113.91"}},
		AAAARecords: map[string][]string{"www.netflix.com": {"2001:db8::91"}},
	})
	normalSrv := StartMockDNSServer(t, MockDNSOptions{
		Records: map[string][]string{"netflix.com": {"198.51.100.90"}, "www.netflix.com": {"198.51.100.91"}},
	})

	ag, _, _ := f06_startAgentWithDNS(t, DNSConfigDTO{
		UnlockEnabled: true,
		UnlockServer:  unlockSrv.Addr(),
		Rules:         []string{"netflix.com"},
		UpstreamDNS:   normalSrv.Addr(),
	})

	addr := fmt.Sprintf("127.0.0.1:%d", ag.LocalDNSPort)
	f06_assertFirstA(t, f06_exchange(t, addr, "udp", "WWw.NeTfLiX.CoM.", dns.TypeA, 3*time.Second), "203.0.113.91")
	f06_assertFirstA(t, f06_exchange(t, addr, "udp", "NETFLIX.COM.", dns.TypeA, 3*time.Second), "203.0.113.90")

	aaaaResp := f06_exchange(t, addr, "udp", "WWw.NeTfLiX.CoM.", dns.TypeAAAA, 3*time.Second)
	if aaaaResp.Rcode != dns.RcodeSuccess || len(aaaaResp.Answer) != 0 {
		t.Fatalf("expected empty NODATA for mixed-case AAAA, got rcode=%s ans=%d", dns.RcodeToString[aaaaResp.Rcode], len(aaaaResp.Answer))
	}
	if len(normalSrv.Queries()) != 0 {
		t.Fatalf("mixed-case unlock queries leaked to normalSrv: %+v", normalSrv.Queries())
	}
}

func TestF06_Tier2_TCPAndLargeResponseHandling(t *testing.T) {
	largeParts := make([]string, 30)
	for i := range largeParts {
		largeParts[i] = fmt.Sprintf("chunk-%02d-abcdefghijklmnopqrstuvwxyz0123456789abcdefghij", i)
	}
	normalSrv := StartMockDNSServer(t, MockDNSOptions{
		TXTRecords: map[string][]string{
			"large.example.org": largeParts,
		},
	})

	ag, _, _ := f06_startAgentWithDNS(t, DNSConfigDTO{
		UnlockEnabled: false,
		UpstreamDNS:   normalSrv.Addr(),
	})

	addr := fmt.Sprintf("127.0.0.1:%d", ag.LocalDNSPort)
	tcpResp := f06_exchange(t, addr, "tcp", "large.example.org.", dns.TypeTXT, 3*time.Second)
	if tcpResp.Rcode != dns.RcodeSuccess || len(tcpResp.Answer) != 1 {
		t.Fatalf("expected large TXT answer over TCP, got rcode=%s ans=%d", dns.RcodeToString[tcpResp.Rcode], len(tcpResp.Answer))
	}
	txtRec, ok := tcpResp.Answer[0].(*dns.TXT)
	if !ok || len(txtRec.Txt) != len(largeParts) {
		t.Fatalf("expected %d TXT chunks over TCP, got %+v", len(largeParts), tcpResp.Answer[0])
	}
}
