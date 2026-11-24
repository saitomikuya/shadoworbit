package dnsproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"

	"snell-panel/internal/protocol"
)

type mockQueryRecord struct {
	Net   string
	Qname string
	Qtype uint16
}

type mockDNSServer struct {
	addr    string
	udpSrv  *dns.Server
	tcpSrv  *dns.Server
	hits    atomic.Int64
	mu      sync.Mutex
	records []mockQueryRecord
}

func startMockDNSServer(t *testing.T, handler func(w dns.ResponseWriter, r *dns.Msg)) *mockDNSServer {
	t.Helper()

	pc, ln, port, err := bindPairedListeners("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("bind mock dns listeners: %v", err)
	}

	m := &mockDNSServer{
		addr: net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)),
	}

	wrapped := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m.hits.Add(1)
		if len(r.Question) > 0 {
			netName := "udp"
			if w.RemoteAddr() != nil && strings.HasPrefix(w.RemoteAddr().Network(), "tcp") {
				netName = "tcp"
			}
			m.mu.Lock()
			m.records = append(m.records, mockQueryRecord{
				Net:   netName,
				Qname: r.Question[0].Name,
				Qtype: r.Question[0].Qtype,
			})
			m.mu.Unlock()
		}
		handler(w, r)
	})

	udpReady := make(chan struct{})
	tcpReady := make(chan struct{})
	m.udpSrv = &dns.Server{
		PacketConn:        pc,
		Handler:           wrapped,
		UDPSize:           dns.DefaultMsgSize,
		NotifyStartedFunc: func() { close(udpReady) },
	}
	m.tcpSrv = &dns.Server{
		Listener:          ln,
		Handler:           wrapped,
		NotifyStartedFunc: func() { close(tcpReady) },
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = m.udpSrv.ActivateAndServe()
	}()
	go func() {
		defer wg.Done()
		_ = m.tcpSrv.ActivateAndServe()
	}()

	<-udpReady
	<-tcpReady

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = m.udpSrv.ShutdownContext(ctx)
		_ = m.tcpSrv.ShutdownContext(ctx)
		wg.Wait()
	})

	return m
}

func (m *mockDNSServer) Hits() int64 {
	return m.hits.Load()
}

func (m *mockDNSServer) ResetHits() {
	m.hits.Store(0)
	m.mu.Lock()
	m.records = nil
	m.mu.Unlock()
}

func exchangeQuery(t *testing.T, proto, addr, qname string, qtype uint16, edns0Size uint16) *dns.Msg {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), qtype)
	if edns0Size > 0 {
		msg.SetEdns0(edns0Size, false)
	}
	c := &dns.Client{
		Net:     proto,
		UDPSize: dns.DefaultMsgSize,
		Timeout: 3 * time.Second,
	}
	resp, _, err := c.Exchange(msg, addr)
	if err != nil {
		t.Fatalf("dns exchange (%s %s %s -> %s): %v", proto, qname, dns.TypeToString[qtype], addr, err)
	}
	return resp
}

func reserveClosedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserveClosedAddr: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func reserveFreePort(t *testing.T) int {
	t.Helper()
	pc, ln, port, err := bindPairedListeners("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("reserveFreePort: %v", err)
	}
	_ = pc.Close()
	_ = ln.Close()
	return port
}

func isAddrInUseErr(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.EADDRINUSE) || strings.Contains(strings.ToLower(err.Error()), "address already in use")
}

func exchangeWithCancel(ctx context.Context, c *dns.Client, m *dns.Msg, addr string) error {
	conn, err := c.DialContext(ctx, addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stop()

	_, _, err = c.ExchangeWithConnContext(ctx, m, conn)
	return err
}

func TestParseRulesAndMatchDomain(t *testing.T) {
	var nilMatcher *RuleMatcher
	if nilMatcher.Len() != 0 {
		t.Fatalf("expected nil matcher Len() == 0, got %d", nilMatcher.Len())
	}
	if nilMatcher.MatchDomain("netflix.com") {
		t.Fatalf("expected nil matcher MatchDomain == false")
	}

	rules := []string{
		"",
		"   # full line comment",
		"   // double slash comment",
		"netflix.com  # inline comment",
		"Netflix.COM. // duplicate after normalization",
		"^hulu.com",
		"@exactonly.org.",
		"*.disneyplus.com",
		".subonly.net",
		"multi1.io\n^multi2.io\r\n*.multi3.io # multi-line",
		// Invalid tokens that must be skipped cleanly:
		"^",
		"@",
		"*.",
		".",
		"*badprefix.com",
		"a..b.com",
		"bad domain.com",
		"http://example.com",
		"1.2.3.4:53",
		"-leadingdash.com",
		"trailingdash-.com",
	}

	m := ParseRules(rules)
	if m.Len() != 8 {
		t.Fatalf("expected 8 distinct valid rules, got %d", m.Len())
	}

	cases := []struct {
		domain string
		want   bool
	}{
		// Root + subdomains ("netflix.com")
		{"netflix.com", true},
		{"netflix.com.", true},
		{"WWW.NETFLIX.COM.", true},
		{"api.us.netflix.com", true},
		{"_acme-challenge.netflix.com.", true},
		{"notnetflix.com", false},
		{"netflix.com.cn", false},
		{"xnetflix.com", false},

		// Exact root only ("^hulu.com", "@exactonly.org")
		{"hulu.com", true},
		{"HULU.COM.", true},
		{"www.hulu.com", false},
		{"a.b.hulu.com", false},
		{"exactonly.org", true},
		{"sub.exactonly.org", false},

		// Subdomains only ("*.disneyplus.com", ".subonly.net")
		{"disneyplus.com", false},
		{"disneyplus.com.", false},
		{"www.disneyplus.com", true},
		{"cdn.eu.disneyplus.com.", true},
		{"notdisneyplus.com", false},
		{"subonly.net", false},
		{"a.subonly.net", true},
		{"a.b.subonly.net", true},

		// Multi-line entries
		{"multi1.io", true},
		{"sub.multi1.io", true},
		{"multi2.io", true},
		{"sub.multi2.io", false},
		{"multi3.io", false},
		{"edge.multi3.io", true},

		// Edge invalid inputs
		{"", false},
		{".", false},
		{"..com", false},
		{"bad domain.com", false},
	}

	for _, tc := range cases {
		got := m.MatchDomain(tc.domain)
		if got != tc.want {
			t.Errorf("MatchDomain(%q) = %v, want %v", tc.domain, got, tc.want)
		}
	}
}

func TestConfigValidationAndNormalization(t *testing.T) {
	def := DefaultConfig()
	if def.ListenHost != DefaultListenHost || def.ListenPort != DefaultListenPort ||
		def.UpstreamDNS != DefaultUpstreamDNS || def.UpstreamTimeout != DefaultUpstreamTimeout {
		t.Fatalf("unexpected DefaultConfig: %+v", def)
	}

	// Preserve ListenPort == 0 as ephemeral port (must NOT overwrite with 1053).
	srv, err := New(Config{ListenPort: 0})
	if err != nil {
		t.Fatalf("New(ListenPort: 0) failed: %v", err)
	}
	st := srv.snap.Load()
	if st.cfg.ListenPort != 0 {
		t.Fatalf("expected ListenPort 0 preserved, got %d", st.cfg.ListenPort)
	}
	if st.cfg.ListenHost != DefaultListenHost {
		t.Fatalf("expected default ListenHost %q, got %q", DefaultListenHost, st.cfg.ListenHost)
	}
	if len(st.upstreams) != 2 || st.upstreams[0] != "1.1.1.1:53" || st.upstreams[1] != "8.8.8.8:53" {
		t.Fatalf("unexpected default upstreams: %v", st.upstreams)
	}

	// Address normalization cases.
	addrCases := []struct {
		in   string
		want string
	}{
		{"1.2.3.4:3535", "1.2.3.4:3535"},
		{"1.2.3.4", "1.2.3.4:53"},
		{"::1", "[::1]:53"},
		{"[::1]", "[::1]:53"},
		{"[::1]:5353", "[::1]:5353"},
		{"udp://1.2.3.4:3535", "1.2.3.4:3535"},
		{"TCP://1.2.3.4", "1.2.3.4:53"},
		{"dns.example", "dns.example:53"},
		{"dns.example:5353", "dns.example:5353"},
	}
	for _, tc := range addrCases {
		got, err := normalizeDNSAddr(tc.in)
		if err != nil {
			t.Errorf("normalizeDNSAddr(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("normalizeDNSAddr(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	// Invalid configs must fail.
	invalidCfgs := []Config{
		{ListenPort: -1},
		{ListenPort: 65536},
		{UnlockServer: "1.2.3.4:0"},
		{UnlockServer: "1.2.3.4:70000"},
		{UnlockServer: "1.2.3.4:abc"},
		{UnlockServer: ":53"},
		{UnlockServer: "https://1.2.3.4"},
		{UpstreamDNS: ","},
		{UpstreamDNS: "1.1.1.1:99999"},
		{UpstreamDNS: "https://dns.google/dns-query"},
	}
	for i, cfg := range invalidCfgs {
		if _, err := New(cfg); err == nil {
			t.Errorf("invalidCfgs[%d] (%+v) expected error, got nil", i, cfg)
		}
	}
}

func TestServerLifecycleAndRollback(t *testing.T) {
	upstream := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("93.184.216.34"),
		})
		_ = w.WriteMsg(resp)
	})

	srv, err := New(Config{
		ListenHost:  "127.0.0.1",
		ListenPort:  0,
		UpstreamDNS: upstream.addr,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Stopped state before Start.
	if srv.Addr() != "" || srv.UDPAddr() != "" || srv.TCPAddr() != "" || srv.Port() != 0 {
		t.Fatalf("expected empty addresses and port 0 before Start")
	}
	if err := srv.Stop(context.Background()); err != nil {
		t.Fatalf("Stop before Start should succeed idempotently: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if srv.Port() <= 0 {
		t.Fatalf("expected positive ephemeral port, got %d", srv.Port())
	}
	if srv.Addr() == "" || srv.UDPAddr() != srv.Addr() || srv.TCPAddr() != srv.Addr() {
		t.Fatalf("expected identical active UDP/TCP addr, got addr=%q udp=%q tcp=%q", srv.Addr(), srv.UDPAddr(), srv.TCPAddr())
	}
	if err := srv.Start(context.Background()); err != ErrAlreadyStarted {
		t.Fatalf("second Start expected ErrAlreadyStarted, got %v", err)
	}

	// Verify both UDP and TCP serve on the same port.
	for _, proto := range []string{"udp", "tcp"} {
		resp := exchangeQuery(t, proto, srv.Addr(), "example.com", dns.TypeA, 0)
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("%s query failed: rcode=%d ans=%d", proto, resp.Rcode, len(resp.Answer))
		}
	}

	// Cancel context -> server must shut down cleanly.
	cancel()
	deadline := time.Now().Add(3 * time.Second)
	for srv.Port() != 0 && time.Now().Before(deadline) {
		time.Sleep(15 * time.Millisecond)
	}
	if srv.Port() != 0 || srv.Addr() != "" {
		t.Fatalf("expected server stopped after context cancel, port=%d addr=%q", srv.Port(), srv.Addr())
	}
	// Stop after cancel is idempotent.
	if err := srv.Stop(context.Background()); err != nil {
		t.Fatalf("idempotent Stop failed: %v", err)
	}
}

func TestPortCollisionRollbackNoSocketLeak(t *testing.T) {
	// Pre-bind TCP only on port P so UDP bind succeeds first and TCP bind fails.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	defer ln.Close()

	srv, err := New(Config{
		ListenHost: "127.0.0.1",
		ListenPort: port,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Start(context.Background()); err == nil {
		_ = srv.Stop(context.Background())
		t.Fatalf("expected Start to fail on TCP port collision %d", port)
	}

	// Verify UDP socket on port was rolled back and not leaked.
	pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("expected UDP port %d to be free after rollback, got: %v", port, err)
	}
	_ = pc.Close()
}

func TestDNSDispatchSemantics(t *testing.T) {
	unlockMock := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.RecursionAvailable = true
		q := r.Question[0]
		switch q.Qtype {
		case dns.TypeA:
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("10.10.10.10"),
			})
		case dns.TypeTXT:
			resp.Answer = append(resp.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{"unlocked"},
			})
		}
		_ = w.WriteMsg(resp)
	})

	upstream1 := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.RecursionAvailable = true
		q := r.Question[0]
		switch q.Qtype {
		case dns.TypeA:
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("20.20.20.20"),
			})
		case dns.TypeAAAA:
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: net.ParseIP("2001:db8::2"),
			})
		case dns.TypeHTTPS:
			resp.Answer = append(resp.Answer, &dns.HTTPS{
				SVCB: dns.SVCB{
					Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60},
					Priority: 1,
					Target:   ".",
				},
			})
		case dns.TypeSVCB:
			resp.Answer = append(resp.Answer, &dns.SVCB{
				Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 60},
				Priority: 1,
				Target:   ".",
			})
		case dns.TypeANY:
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("20.20.20.20"),
			})
		}
		_ = w.WriteMsg(resp)
	})

	srv, err := New(Config{
		ListenHost:      "127.0.0.1",
		ListenPort:      0,
		UnlockEnabled:   true,
		UnlockServer:    unlockMock.addr,
		Rules:           []string{"netflix.com", "^hulu.com", "*.disneyplus.com"},
		UpstreamDNS:     upstream1.addr,
		UpstreamTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })

	// 1. Matched unlock domain + AAAA / HTTPS / SVCB / ANY -> immediate empty NODATA, 0 upstream hits.
	blockedQtypes := []uint16{dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB, dns.TypeANY}
	for _, proto := range []string{"udp", "tcp"} {
		for _, qt := range blockedQtypes {
			// Without EDNS0 OPT: Extra must stay empty.
			resp := exchangeQuery(t, proto, srv.Addr(), "www.netflix.com", qt, 0)
			if resp.Rcode != dns.RcodeSuccess || !resp.RecursionAvailable {
				t.Fatalf("NODATA (%s %s) bad header: rcode=%d ra=%v", proto, dns.TypeToString[qt], resp.Rcode, resp.RecursionAvailable)
			}
			if len(resp.Answer) != 0 || len(resp.Ns) != 0 || len(resp.Extra) != 0 {
				t.Fatalf("NODATA (%s %s) expected empty sections, got ans=%d ns=%d extra=%d",
					proto, dns.TypeToString[qt], len(resp.Answer), len(resp.Ns), len(resp.Extra))
			}

			// With EDNS0 OPT: OPT echoed in Extra, Answer/Ns still empty.
			ednsResp := exchangeQuery(t, proto, srv.Addr(), "hulu.com", qt, 4096)
			if ednsResp.Rcode != dns.RcodeSuccess || len(ednsResp.Answer) != 0 || len(ednsResp.Ns) != 0 {
				t.Fatalf("EDNS0 NODATA (%s %s) unexpected answer/ns", proto, dns.TypeToString[qt])
			}
			if ednsResp.IsEdns0() == nil {
				t.Fatalf("EDNS0 NODATA (%s %s) expected OPT echoed in Extra", proto, dns.TypeToString[qt])
			}
		}
	}
	if unlockMock.Hits() != 0 || upstream1.Hits() != 0 {
		t.Fatalf("expected 0 upstream/unlock hits for blocked Qtypes, got unlock=%d upstream=%d",
			unlockMock.Hits(), upstream1.Hits())
	}

	// 2. Matched unlock domain + A / TXT -> routed exclusively to unlockMock.
	for _, proto := range []string{"udp", "tcp"} {
		respA := exchangeQuery(t, proto, srv.Addr(), "api.netflix.com", dns.TypeA, 0)
		if respA.Rcode != dns.RcodeSuccess || len(respA.Answer) != 1 || respA.Answer[0].(*dns.A).A.String() != "10.10.10.10" {
			t.Fatalf("unlock A (%s) unexpected response: %+v", proto, respA.Answer)
		}
		respTXT := exchangeQuery(t, proto, srv.Addr(), "cdn.disneyplus.com", dns.TypeTXT, 0)
		if respTXT.Rcode != dns.RcodeSuccess || len(respTXT.Answer) != 1 || respTXT.Answer[0].(*dns.TXT).Txt[0] != "unlocked" {
			t.Fatalf("unlock TXT (%s) unexpected response: %+v", proto, respTXT.Answer)
		}
	}
	if unlockMock.Hits() != 4 || upstream1.Hits() != 0 {
		t.Fatalf("expected unlock=4 upstream=0, got unlock=%d upstream=%d", unlockMock.Hits(), upstream1.Hits())
	}

	// 3. Unmatched domains (including ^hulu.com sub & *.disneyplus.com root) -> upstream1.
	unlockMock.ResetHits()
	upstream1.ResetHits()
	for _, domain := range []string{"www.hulu.com", "disneyplus.com", "notnetflix.com"} {
		respA := exchangeQuery(t, "udp", srv.Addr(), domain, dns.TypeA, 0)
		if len(respA.Answer) != 1 || respA.Answer[0].(*dns.A).A.String() != "20.20.20.20" {
			t.Fatalf("unmatched %s A unexpected answer: %+v", domain, respA.Answer)
		}
		respAAAA := exchangeQuery(t, "udp", srv.Addr(), domain, dns.TypeAAAA, 0)
		if len(respAAAA.Answer) != 1 || respAAAA.Answer[0].(*dns.AAAA).AAAA.String() != "2001:db8::2" {
			t.Fatalf("unmatched %s AAAA should NOT be blocked: %+v", domain, respAAAA.Answer)
		}
	}
	if unlockMock.Hits() != 0 || upstream1.Hits() != 6 {
		t.Fatalf("expected unlock=0 upstream=6, got unlock=%d upstream=%d", unlockMock.Hits(), upstream1.Hits())
	}

	// 4. Disabled unlock -> even netflix.com AAAA/HTTPS go to upstream1.
	unlockMock.ResetHits()
	upstream1.ResetHits()
	if err := srv.UpdateConfig(Config{
		ListenPort:      0, // preserve active port
		UnlockEnabled:   false,
		UnlockServer:    unlockMock.addr,
		Rules:           []string{"netflix.com"},
		UpstreamDNS:     upstream1.addr,
		UpstreamTimeout: time.Second,
	}); err != nil {
		t.Fatalf("UpdateConfig disable unlock: %v", err)
	}
	respAAAA := exchangeQuery(t, "udp", srv.Addr(), "netflix.com", dns.TypeAAAA, 0)
	if len(respAAAA.Answer) != 1 || respAAAA.Answer[0].(*dns.AAAA).AAAA.String() != "2001:db8::2" {
		t.Fatalf("disabled unlock should forward AAAA to upstream, got: %+v", respAAAA.Answer)
	}
	if unlockMock.Hits() != 0 || upstream1.Hits() != 1 {
		t.Fatalf("expected unlock=0 upstream=1, got unlock=%d upstream=%d", unlockMock.Hits(), upstream1.Hits())
	}

	// 5. UnlockServer failure must NEVER leak to UpstreamDNS.
	unlockMock.ResetHits()
	upstream1.ResetHits()
	closedUnlock := reserveClosedAddr(t)
	if err := srv.UpdateConfig(Config{
		UnlockEnabled:   true,
		UnlockServer:    closedUnlock,
		Rules:           []string{"netflix.com"},
		UpstreamDNS:     upstream1.addr,
		UpstreamTimeout: 200 * time.Millisecond,
	}); err != nil {
		t.Fatalf("UpdateConfig closed unlock: %v", err)
	}
	failResp := exchangeQuery(t, "udp", srv.Addr(), "netflix.com", dns.TypeA, 0)
	if failResp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL when UnlockServer unreachable, got rcode=%d", failResp.Rcode)
	}
	if upstream1.Hits() != 0 {
		t.Fatalf("UnlockServer failure leaked to UpstreamDNS (%d hits)!", upstream1.Hits())
	}

	// 6. UnlockEnabled=true with empty UnlockServer: AAAA still NODATA (0 upstream hits), A falls back to UpstreamDNS.
	upstream1.ResetHits()
	if err := srv.UpdateConfig(Config{
		UnlockEnabled:   true,
		UnlockServer:    "",
		Rules:           []string{"netflix.com"},
		UpstreamDNS:     upstream1.addr,
		UpstreamTimeout: time.Second,
	}); err != nil {
		t.Fatalf("UpdateConfig empty unlock server: %v", err)
	}
	nodataResp := exchangeQuery(t, "udp", srv.Addr(), "netflix.com", dns.TypeAAAA, 0)
	if nodataResp.Rcode != dns.RcodeSuccess || len(nodataResp.Answer) != 0 {
		t.Fatalf("expected empty NODATA with empty UnlockServer, got rcode=%d ans=%v", nodataResp.Rcode, nodataResp.Answer)
	}
	if upstream1.Hits() != 0 {
		t.Fatalf("expected 0 upstream hits for blocked AAAA with empty UnlockServer, got %d", upstream1.Hits())
	}
	fallbackAResp := exchangeQuery(t, "udp", srv.Addr(), "netflix.com", dns.TypeA, 0)
	if fallbackAResp.Rcode != dns.RcodeSuccess || len(fallbackAResp.Answer) != 1 || fallbackAResp.Answer[0].(*dns.A).A.String() != "20.20.20.20" {
		t.Fatalf("expected A to fall back to UpstreamDNS when UnlockServer empty, got %v", fallbackAResp.Answer)
	}
	if upstream1.Hits() != 1 {
		t.Fatalf("expected 1 upstream hit for A with empty UnlockServer, got %d", upstream1.Hits())
	}
}

func TestUpstreamFailoverAndNXDOMAINStop(t *testing.T) {
	var primaryMode atomic.Int32 // 0=SERVFAIL, 1=REFUSED, 2=NOTIMP, 3=FORMERR, 4=NXDOMAIN
	primary := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		switch primaryMode.Load() {
		case 0:
			resp.SetRcode(r, dns.RcodeServerFailure)
		case 1:
			resp.SetRcode(r, dns.RcodeRefused)
		case 2:
			resp.SetRcode(r, dns.RcodeNotImplemented)
		case 3:
			resp.SetRcode(r, dns.RcodeFormatError)
		case 4:
			resp.SetRcode(r, dns.RcodeNameError)
		}
		_ = w.WriteMsg(resp)
	})

	secondary := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("8.8.4.4"),
		})
		_ = w.WriteMsg(resp)
	})

	closedAddr := reserveClosedAddr(t)
	srv, err := New(Config{
		ListenPort:      0,
		UpstreamDNS:     fmt.Sprintf("%s,%s,%s", closedAddr, primary.addr, secondary.addr),
		UpstreamTimeout: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })

	// Infrastructure Rcodes must fail over from closed -> primary -> secondary.
	for _, mode := range []int32{0, 1, 2, 3} {
		primaryMode.Store(mode)
		secondary.ResetHits()
		resp := exchangeQuery(t, "udp", srv.Addr(), "example.org", dns.TypeA, 0)
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "8.8.4.4" {
			t.Fatalf("mode %d expected secondary failover success, got rcode=%d ans=%v", mode, resp.Rcode, resp.Answer)
		}
		if secondary.Hits() != 1 {
			t.Fatalf("mode %d expected secondary hit=1, got %d", mode, secondary.Hits())
		}
	}

	// NXDOMAIN must stop immediately at primary and NOT hit secondary.
	primaryMode.Store(4)
	secondary.ResetHits()
	resp := exchangeQuery(t, "udp", srv.Addr(), "missing.example.org", dns.TypeA, 0)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got rcode=%d", resp.Rcode)
	}
	if secondary.Hits() != 0 {
		t.Fatalf("expected 0 secondary hits on NXDOMAIN, got %d", secondary.Hits())
	}
}

func TestUDPTruncatedRetryOverTCPAndDownstreamTruncate(t *testing.T) {
	// Upstream returns TC=1 on UDP, full multi-TXT (~800 bytes) on TCP.
	largeStrings := make([]string, 0, 12)
	for i := 0; i < 12; i++ {
		largeStrings = append(largeStrings, strings.Repeat("x", 60))
	}

	upstream := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		isTCP := w.RemoteAddr() != nil && strings.HasPrefix(w.RemoteAddr().Network(), "tcp")
		if !isTCP {
			resp.Truncated = true
			_ = w.WriteMsg(resp)
			return
		}
		for _, txt := range largeStrings {
			resp.Answer = append(resp.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{txt},
			})
		}
		_ = w.WriteMsg(resp)
	})

	srv, err := New(Config{
		ListenPort:  0,
		UpstreamDNS: upstream.addr,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })

	// EDNS0 4096 UDP client -> dnsproxy retries upstream via TCP and returns all 12 TXT records!
	respEDNS := exchangeQuery(t, "udp", srv.Addr(), "big.example.com", dns.TypeTXT, 4096)
	if respEDNS.Truncated || len(respEDNS.Answer) != len(largeStrings) {
		t.Fatalf("expected full %d answers via TCP retry, got len=%d tc=%v", len(largeStrings), len(respEDNS.Answer), respEDNS.Truncated)
	}

	// Plain UDP client (512-byte limit, no EDNS0) -> dnsproxy truncates oversized answer with TC=1.
	respPlain := exchangeQuery(t, "udp", srv.Addr(), "big.example.com", dns.TypeTXT, 0)
	if !respPlain.Truncated {
		t.Fatalf("expected Truncated=true for plain 512B UDP client receiving >512B answer")
	}
}

type mockResponseWriter struct {
	mu  sync.Mutex
	msg *dns.Msg
}

func (m *mockResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1053}
}
func (m *mockResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54321}
}
func (m *mockResponseWriter) WriteMsg(msg *dns.Msg) error {
	m.mu.Lock()
	m.msg = msg
	m.mu.Unlock()
	return nil
}
func (m *mockResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (m *mockResponseWriter) Close() error                { return nil }
func (m *mockResponseWriter) TsigStatus() error           { return nil }
func (m *mockResponseWriter) TsigTimersOnly(bool)         {}
func (m *mockResponseWriter) Hijack()                     {}

func TestServeDNSGuardsAndIDPreservation(t *testing.T) {
	srv, err := New(Config{ListenPort: 0})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Empty question -> FORMERR
	w1 := &mockResponseWriter{}
	req1 := &dns.Msg{MsgHdr: dns.MsgHdr{Id: 0x1234, Opcode: dns.OpcodeQuery}}
	srv.ServeDNS(w1, req1)
	if w1.msg == nil || w1.msg.Rcode != dns.RcodeFormatError || w1.msg.Id != 0x1234 {
		t.Fatalf("expected FORMERR with ID 0x1234, got %+v", w1.msg)
	}

	// Non-query opcode -> NOTIMP
	w2 := &mockResponseWriter{}
	req2 := new(dns.Msg)
	req2.SetQuestion("example.com.", dns.TypeA)
	req2.Opcode = dns.OpcodeNotify
	req2.Id = 0x5678
	srv.ServeDNS(w2, req2)
	if w2.msg == nil || w2.msg.Rcode != dns.RcodeNotImplemented || w2.msg.Id != 0x5678 {
		t.Fatalf("expected NOTIMP with ID 0x5678, got %+v", w2.msg)
	}
}

func TestHotReloadRebindAndConcurrency(t *testing.T) {
	unlockMock := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("10.0.0.1"),
		})
		_ = w.WriteMsg(resp)
	})
	upstreamMock := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("20.0.0.1"),
		})
		_ = w.WriteMsg(resp)
	})

	srv, err := New(Config{
		ListenHost:  "127.0.0.1",
		ListenPort:  0,
		UpstreamDNS: upstreamMock.addr,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })

	port1 := srv.Port()
	addr1 := srv.Addr()

	// Before reload: hits upstreamMock.
	r1 := exchangeQuery(t, "udp", addr1, "netflix.com", dns.TypeA, 0)
	if r1.Answer[0].(*dns.A).A.String() != "20.0.0.1" {
		t.Fatalf("expected 20.0.0.1 before reload, got %v", r1.Answer)
	}

	// ApplyProtocolConfig with LocalPort: 0 preserves active ephemeral port1!
	if err := srv.ApplyProtocolConfig(protocol.DNSConfig{
		UnlockEnabled: true,
		UnlockServer:  unlockMock.addr,
		Rules:         []string{"netflix.com"},
		UpstreamDNS:   upstreamMock.addr,
		LocalPort:     0,
	}); err != nil {
		t.Fatalf("ApplyProtocolConfig: %v", err)
	}
	if srv.Port() != port1 || srv.Addr() != addr1 {
		t.Fatalf("expected port preserved (%d), got %d (%s)", port1, srv.Port(), srv.Addr())
	}

	r2 := exchangeQuery(t, "tcp", addr1, "netflix.com", dns.TypeA, 0)
	if r2.Answer[0].(*dns.A).A.String() != "10.0.0.1" {
		t.Fatalf("expected 10.0.0.1 after reload, got %v", r2.Answer)
	}

	// Invalid UpdateConfig must fail and keep prior config active.
	if err := srv.UpdateConfig(Config{UnlockServer: "bad:99999"}); err == nil {
		t.Fatalf("expected invalid UpdateConfig to fail")
	}
	r3 := exchangeQuery(t, "udp", addr1, "netflix.com", dns.TypeA, 0)
	if r3.Answer[0].(*dns.A).A.String() != "10.0.0.1" {
		t.Fatalf("expected prior config retained after invalid UpdateConfig")
	}

	// Failed port rebind (occupied port) keeps old listener alive.
	busyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen busy port: %v", err)
	}
	busyPort := busyLn.Addr().(*net.TCPAddr).Port
	if err := srv.ApplyProtocolConfig(protocol.DNSConfig{
		UnlockEnabled: true,
		UnlockServer:  unlockMock.addr,
		Rules:         []string{"netflix.com"},
		UpstreamDNS:   upstreamMock.addr,
		LocalPort:     busyPort,
	}); err == nil {
		_ = busyLn.Close()
		t.Fatalf("expected rebind to busy port %d to fail", busyPort)
	}
	_ = busyLn.Close()
	if srv.Port() != port1 {
		t.Fatalf("expected port %d still active after failed rebind, got %d", port1, srv.Port())
	}

	// Valid port rebind via ApplyProtocolConfig (LocalPort: port2).
	var port2 int
	var rebindErr error
	for attempt := 0; attempt < 5; attempt++ {
		port2 = reserveFreePort(t)
		rebindErr = srv.ApplyProtocolConfig(protocol.DNSConfig{
			UnlockEnabled: true,
			UnlockServer:  unlockMock.addr,
			Rules:         []string{"netflix.com"},
			UpstreamDNS:   upstreamMock.addr,
			LocalPort:     port2,
		})
		if rebindErr == nil {
			break
		}
		if !isAddrInUseErr(rebindErr) {
			break
		}
	}
	if rebindErr != nil {
		t.Fatalf("rebind to port %d failed: %v", port2, rebindErr)
	}
	if srv.Port() != port2 {
		t.Fatalf("expected active port %d after rebind, got %d", port2, srv.Port())
	}
	addr2 := srv.Addr()
	r4 := exchangeQuery(t, "udp", addr2, "netflix.com", dns.TypeA, 0)
	if r4.Answer[0].(*dns.A).A.String() != "10.0.0.1" {
		t.Fatalf("expected query on new port %d to succeed", port2)
	}

	// Concurrent query + hot-reload stress under -race.
	var wg sync.WaitGroup
	stopQueries := make(chan struct{})
	errCh := make(chan error, 16)

	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			proto := "udp"
			if id%2 == 1 {
				proto = "tcp"
			}
			c := &dns.Client{Net: proto, UDPSize: dns.DefaultMsgSize, Timeout: 2 * time.Second}
			for {
				select {
				case <-stopQueries:
					return
				default:
				}
				m := new(dns.Msg)
				qname := "netflix.com."
				qtype := dns.TypeA
				if id%3 == 0 {
					qtype = dns.TypeAAAA
				} else if id%3 == 1 {
					qname = "other.example.com."
				}
				m.SetQuestion(qname, qtype)
				curAddr := srv.Addr()
				if curAddr == "" {
					continue
				}
				resp, _, err := c.Exchange(m, curAddr)
				if err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}
				if resp.Rcode != dns.RcodeSuccess {
					select {
					case errCh <- fmt.Errorf("unexpected rcode %d", resp.Rcode):
					default:
					}
					return
				}
			}
		}(i)
	}

	for iter := 0; iter < 50; iter++ {
		enabled := iter%2 == 0
		if err := srv.UpdateConfig(Config{
			ListenPort:      0, // preserve active port2
			UnlockEnabled:   enabled,
			UnlockServer:    unlockMock.addr,
			Rules:           []string{"netflix.com", "^hulu.com"},
			UpstreamDNS:     upstreamMock.addr,
			UpstreamTimeout: 2 * time.Second,
		}); err != nil {
			close(stopQueries)
			wg.Wait()
			t.Fatalf("concurrent UpdateConfig iter %d: %v", iter, err)
		}
		_ = srv.Port()
		_ = srv.UDPAddr()
		_ = srv.TCPAddr()
	}

	close(stopQueries)
	wg.Wait()
	select {
	case qErr := <-errCh:
		t.Fatalf("concurrent query error: %v", qErr)
	default:
	}

	// Host-change rebind failure (unbindable IP 192.0.2.1 on same port) rolls back cleanly.
	if err := srv.UpdateConfig(Config{
		ListenHost:  "192.0.2.1",
		ListenPort:  port2,
		UpstreamDNS: upstreamMock.addr,
	}); err == nil {
		t.Fatalf("expected rebind to unbindable host 192.0.2.1 to fail")
	}
	if srv.Port() != port2 || srv.Addr() == "" {
		t.Fatalf("expected rollback to port %d after host-change bind failure, got port=%d addr=%q", port2, srv.Port(), srv.Addr())
	}
	rbResp := exchangeQuery(t, "udp", srv.Addr(), "other.example.com", dns.TypeA, 0)
	if rbResp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected rolled-back server to continue serving, got rcode=%d", rbResp.Rcode)
	}

	// Invalid ApplyProtocolConfig port must fail cleanly.
	if err := srv.ApplyProtocolConfig(protocol.DNSConfig{LocalPort: -1}); err == nil {
		t.Fatalf("expected ApplyProtocolConfig with LocalPort -1 to fail")
	}
	if err := srv.ApplyProtocolConfig(protocol.DNSConfig{LocalPort: 70000}); err == nil {
		t.Fatalf("expected ApplyProtocolConfig with LocalPort 70000 to fail")
	}
}

func TestAllUpstreamsFailReturnsServFail(t *testing.T) {
	closed1 := reserveClosedAddr(t)
	closed2 := reserveClosedAddr(t)

	srv, err := New(Config{
		ListenPort:      0,
		UpstreamDNS:     closed1 + "," + closed2,
		UpstreamTimeout: 150 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })

	resp := exchangeQuery(t, "udp", srv.Addr(), "example.com", dns.TypeA, 0)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL when all upstreams fail, got rcode=%d", resp.Rcode)
	}
}

func TestStopCancelsSlowInFlightQueriesAndNoLeak(t *testing.T) {
	mockStop := make(chan struct{})
	var closeMockOnce sync.Once
	closeMock := func() { closeMockOnce.Do(func() { close(mockStop) }) }

	slow1 := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		select {
		case <-time.After(2500 * time.Millisecond):
		case <-mockStop:
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("1.1.1.1"),
		})
		_ = w.WriteMsg(resp)
	})
	slow2 := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		_ = w.WriteMsg(resp)
	})
	t.Cleanup(closeMock)

	srv, err := New(Config{
		ListenHost:      "127.0.0.1",
		ListenPort:      0,
		UpstreamDNS:     slow1.addr + "," + slow2.addr,
		UpstreamTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })

	addr := srv.Addr()
	port := srv.Port()

	const perProto = 5
	var queryWG sync.WaitGroup
	for i := 0; i < perProto*2; i++ {
		queryWG.Add(1)
		proto := "udp"
		if i%2 == 1 {
			proto = "tcp"
		}
		go func(netProto string) {
			defer queryWG.Done()
			m := new(dns.Msg)
			m.SetQuestion("slow.example.com.", dns.TypeA)
			c := &dns.Client{Net: netProto, UDPSize: dns.DefaultMsgSize, Timeout: 5 * time.Second}
			_, _, _ = c.Exchange(m, addr)
		}(proto)
	}

	// Wait until all 10 queries have reached slow1 and are blocked in ReadMsg().
	waitDeadline := time.Now().Add(2 * time.Second)
	for slow1.Hits() < int64(perProto*2) && time.Now().Before(waitDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if slow1.Hits() < int64(perProto*2) {
		t.Fatalf("expected %d hits at slow1 before Stop, got %d", perProto*2, slow1.Hits())
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer stopCancel()
	stopStart := time.Now()
	if err := srv.Stop(stopCtx); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	stopElapsed := time.Since(stopStart)
	if stopElapsed >= 500*time.Millisecond {
		t.Fatalf("Stop took %v (>= 500ms) while cancelling in-flight queries", stopElapsed)
	}

	// All client query goroutines must finish promptly BEFORE mockStop is closed.
	doneCh := make(chan struct{})
	go func() {
		queryWG.Wait()
		close(doneCh)
	}()
	select {
	case <-doneCh:
	case <-time.After(1 * time.Second):
		t.Fatalf("in-flight client queries did not exit promptly after Stop")
	}

	if slow2.Hits() != 0 {
		t.Fatalf("expected 0 hits on second upstream after cancellation, got %d", slow2.Hits())
	}

	// Confirm both UDP and TCP sockets on port were closed with no leak.
	pc, ln, _, err := bindPairedListeners("127.0.0.1", port)
	if err != nil {
		t.Fatalf("expected port %d to be free after Stop, got: %v", port, err)
	}
	_ = pc.Close()
	_ = ln.Close()

	closeMock()
}

func TestContinuousQueryFloodStopPromptly(t *testing.T) {
	mockStop := make(chan struct{})
	var closeMockOnce sync.Once
	closeMock := func() { closeMockOnce.Do(func() { close(mockStop) }) }

	var udpHits, tcpHits atomic.Int64
	slow := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		if w.RemoteAddr() != nil && strings.HasPrefix(w.RemoteAddr().Network(), "tcp") {
			tcpHits.Add(1)
		} else {
			udpHits.Add(1)
		}
		select {
		case <-time.After(2500 * time.Millisecond):
		case <-mockStop:
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(r)
		_ = w.WriteMsg(resp)
	})
	t.Cleanup(closeMock)

	srv, err := New(Config{
		ListenHost:      "127.0.0.1",
		ListenPort:      0,
		UpstreamDNS:     slow.addr,
		UpstreamTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })

	addr := srv.Addr()
	port := srv.Port()
	if port <= 0 || addr == "" {
		t.Fatalf("expected active addr and positive port, got addr=%q port=%d", addr, port)
	}

	floodCtx, cancelFlood := context.WithCancel(context.Background())
	var floodWG sync.WaitGroup
	cleanupFlood := func() {
		cancelFlood()
		closeMock()
		floodWG.Wait()
	}
	t.Cleanup(cleanupFlood)

	for i := 0; i < 8; i++ {
		floodWG.Add(1)
		proto := "udp"
		if i%2 == 1 {
			proto = "tcp"
		}
		go func(netProto string) {
			defer floodWG.Done()
			c := &dns.Client{Net: netProto, UDPSize: dns.DefaultMsgSize, Timeout: 5 * time.Second}
			for {
				if floodCtx.Err() != nil {
					return
				}
				m := new(dns.Msg)
				m.SetQuestion("flood.example.com.", dns.TypeA)
				if err := exchangeWithCancel(floodCtx, c, m, addr); err != nil {
					return
				}
			}
		}(proto)
	}

	waitDeadline := time.Now().Add(2 * time.Second)
	for (udpHits.Load() < 2 || tcpHits.Load() < 2) && time.Now().Before(waitDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if udpHits.Load() < 2 || tcpHits.Load() < 2 {
		cleanupFlood()
		t.Fatalf("expected UDP and TCP flood queries to reach upstream, got udp=%d tcp=%d", udpHits.Load(), tcpHits.Load())
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	stopStart := time.Now()
	if err := srv.Stop(stopCtx); err != nil {
		cleanupFlood()
		t.Fatalf("Stop during flood failed: %v", err)
	}
	stopElapsed := time.Since(stopStart)
	if stopElapsed >= 500*time.Millisecond {
		cleanupFlood()
		t.Fatalf("Stop during UDP+TCP flood took %v (>= 500ms); possible sequential shutdown or uncancelled context", stopElapsed)
	}

	// Verify server listeners and ports are fully released BEFORE cancelling floodCtx.
	if srv.Port() != 0 || srv.Addr() != "" {
		cleanupFlood()
		t.Fatalf("expected stopped server port=0 addr=\"\" after Stop, got port=%d addr=%q", srv.Port(), srv.Addr())
	}
	pc, ln, _, err := bindPairedListeners("127.0.0.1", port)
	if err != nil {
		cleanupFlood()
		t.Fatalf("expected port %d to be free after Stop, got: %v", port, err)
	}
	_ = pc.Close()
	_ = ln.Close()

	cancelFlood()
	doneCh := make(chan struct{})
	go func() {
		floodWG.Wait()
		close(doneCh)
	}()
	select {
	case <-doneCh:
	case <-time.After(1 * time.Second):
		closeMock()
		t.Fatalf("flood goroutines did not exit promptly after Stop")
	}

	closeMock()
}

func TestApplyProtocolConfigPreservesEphemeralZeroOnRestart(t *testing.T) {
	unlockMock := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("10.10.10.10"),
		})
		_ = w.WriteMsg(resp)
	})
	upstreamMock := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("20.20.20.20"),
		})
		_ = w.WriteMsg(resp)
	})

	srv, err := New(Config{
		ListenHost:  "127.0.0.1",
		ListenPort:  0,
		UpstreamDNS: upstreamMock.addr,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })

	var port1 int
	var occupyLn net.Listener
	for attempt := 0; attempt < 5; attempt++ {
		if err := srv.Start(context.Background()); err != nil {
			t.Fatalf("Start 1 (attempt %d): %v", attempt+1, err)
		}

		port1 = srv.Port()
		if port1 <= 0 {
			t.Fatalf("expected positive ephemeral port1, got %d", port1)
		}

		// ApplyProtocolConfig with LocalPort: 0 must keep active port1 without rebinding
		// AND preserve ListenPort == 0 for future restarts.
		if err := srv.ApplyProtocolConfig(protocol.DNSConfig{
			UnlockEnabled: true,
			UnlockServer:  unlockMock.addr,
			Rules:         []string{"netflix.com"},
			UpstreamDNS:   upstreamMock.addr,
			LocalPort:     0,
		}); err != nil {
			t.Fatalf("ApplyProtocolConfig: %v", err)
		}
		if srv.Port() != port1 {
			t.Fatalf("expected port1 %d preserved, got %d", port1, srv.Port())
		}
		if resp := exchangeQuery(t, "udp", srv.Addr(), "netflix.com", dns.TypeA, 0); resp.Answer[0].(*dns.A).A.String() != "10.10.10.10" {
			t.Fatalf("unexpected unlock answer: %+v", resp.Answer)
		}

		if err := srv.Stop(context.Background()); err != nil {
			t.Fatalf("Stop 1: %v", err)
		}

		// Occupy port1 externally before restarting.
		occupyLn, err = net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port1)))
		if err == nil {
			break
		}
		if !isAddrInUseErr(err) {
			t.Fatalf("occupy port1 %d: %v", port1, err)
		}
	}
	if occupyLn == nil {
		t.Fatalf("occupy port1 %d failed after retries: %v", port1, err)
	}
	defer occupyLn.Close()

	// Start 2 must allocate a fresh ephemeral port != port1 instead of failing on port1.
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start 2 failed (ApplyProtocolConfig likely overwrote ListenPort 0): %v", err)
	}
	port2 := srv.Port()
	if port2 <= 0 || port2 == port1 {
		t.Fatalf("expected new ephemeral port != %d, got %d", port1, port2)
	}
	if resp := exchangeQuery(t, "tcp", srv.Addr(), "netflix.com", dns.TypeA, 0); resp.Answer[0].(*dns.A).A.String() != "10.10.10.10" {
		t.Fatalf("unexpected unlock answer after restart: %+v", resp.Answer)
	}
	if resp := exchangeQuery(t, "udp", srv.Addr(), "example.com", dns.TypeA, 0); resp.Answer[0].(*dns.A).A.String() != "20.20.20.20" {
		t.Fatalf("unexpected upstream answer after restart: %+v", resp.Answer)
	}
}

func TestStartStopStartReuseUpdateWhileStoppedAndEDNS0DOBit(t *testing.T) {
	unlockMock := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("10.20.30.40"),
		})
		_ = w.WriteMsg(resp)
	})
	upstreamMock := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("93.184.216.34"),
		})
		_ = w.WriteMsg(resp)
	})

	srv, err := New(Config{
		ListenHost:  "127.0.0.1",
		ListenPort:  0,
		UpstreamDNS: upstreamMock.addr,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })

	// UpdateConfig while stopped must take effect on next Start.
	if err := srv.UpdateConfig(Config{
		ListenHost:    "127.0.0.1",
		ListenPort:    0,
		UnlockEnabled: true,
		UnlockServer:  unlockMock.addr,
		Rules:         []string{"netflix.com"},
		UpstreamDNS:   upstreamMock.addr,
	}); err != nil {
		t.Fatalf("UpdateConfig while stopped: %v", err)
	}

	// Cycle 1: Start -> query (including EDNS0 DO=true/false NODATA) -> Stop.
	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("Start cycle 1: %v", err)
	}
	rUnlock := exchangeQuery(t, "udp", srv.Addr(), "netflix.com", dns.TypeA, 0)
	if rUnlock.Answer[0].(*dns.A).A.String() != "10.20.30.40" {
		t.Fatalf("expected 10.20.30.40 from unlock after stopped UpdateConfig, got %+v", rUnlock.Answer)
	}

	// Verify EDNS0 DO bit echo in buildEmptyNODATA (DO=true and DO=false).
	for _, doBit := range []bool{true, false} {
		req := new(dns.Msg)
		req.SetQuestion("www.netflix.com.", dns.TypeAAAA)
		req.SetEdns0(4096, doBit)
		c := &dns.Client{Net: "udp", UDPSize: dns.DefaultMsgSize, Timeout: 2 * time.Second}
		resp, _, err := c.Exchange(req, srv.Addr())
		if err != nil {
			t.Fatalf("EDNS0 NODATA DO=%v failed: %v", doBit, err)
		}
		opt := resp.IsEdns0()
		if opt == nil || opt.Do() != doBit {
			t.Fatalf("expected EDNS0 OPT with DO=%v, got opt=%v", doBit, opt)
		}
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 || len(resp.Ns) != 0 {
			t.Fatalf("expected empty NODATA, got rcode=%d ans=%d ns=%d", resp.Rcode, len(resp.Answer), len(resp.Ns))
		}
	}

	if err := srv.Stop(context.Background()); err != nil {
		t.Fatalf("Stop cycle 1: %v", err)
	}

	// UpdateConfig while stopped with an explicit free port.
	var port2 int
	var start2Err error
	for attempt := 0; attempt < 5; attempt++ {
		port2 = reserveFreePort(t)
		if err := srv.UpdateConfig(Config{
			ListenHost:    "127.0.0.1",
			ListenPort:    port2,
			UnlockEnabled: false,
			UpstreamDNS:   upstreamMock.addr,
		}); err != nil {
			t.Fatalf("UpdateConfig explicit port while stopped: %v", err)
		}

		// Cycle 2: Start -> query -> Stop.
		start2Err = srv.Start(context.Background())
		if start2Err == nil {
			break
		}
		if !isAddrInUseErr(start2Err) {
			break
		}
	}
	if start2Err != nil {
		t.Fatalf("Start cycle 2: %v", start2Err)
	}
	if srv.Port() != port2 {
		t.Fatalf("expected port2 %d on cycle 2 Start, got %d", port2, srv.Port())
	}
	for _, proto := range []string{"udp", "tcp"} {
		resp := exchangeQuery(t, proto, srv.Addr(), "netflix.com", dns.TypeA, 0)
		if resp.Answer[0].(*dns.A).A.String() != "93.184.216.34" {
			t.Fatalf("cycle 2 (%s) expected upstream 93.184.216.34, got %+v", proto, resp.Answer)
		}
	}
	if err := srv.Stop(context.Background()); err != nil {
		t.Fatalf("Stop cycle 2: %v", err)
	}
}

func TestDNSProxy_RulePrecedenceAndLengthBoundaries(t *testing.T) {
	t.Run("conflict_precedence_and_inline_comments", func(t *testing.T) {
		m := ParseRules([]string{
			"  ^exactonly.com   # hash comment // after",
			"  @atonly.com      // slash comment # after",
			"  *.subonly.com    # wildcard",
			"  ^combo.com",
			"  *.combo.com",
			"  *.subandbare.com",
			"  subandbare.com",
			"  xn--bcher-kva.example.",
		})

		if !m.MatchDomain("EXACTONLY.COM.") || m.MatchDomain("a.exactonly.com") {
			t.Fatal("exact-only ^ rule mismatch")
		}
		if !m.MatchDomain("atonly.com") || m.MatchDomain("sub.atonly.com") {
			t.Fatal("exact-only @ rule mismatch")
		}
		if m.MatchDomain("subonly.com") || !m.MatchDomain("www.subonly.com") || !m.MatchDomain("a.b.subonly.com") {
			t.Fatal("wildcard *. rule mismatch")
		}
		// Exact + wildcard combined on combo.com matches both root and subdomains.
		if !m.MatchDomain("combo.com") || !m.MatchDomain("api.combo.com") {
			t.Fatal("combined ^ + *. rule should match root and subdomain")
		}
		// Wildcard + bare suffix both loaded matches root and subdomain.
		if !m.MatchDomain("subandbare.com") || !m.MatchDomain("x.subandbare.com") {
			t.Fatal("combined *. + bare rule should match root and subdomain")
		}
		// Punycode + trailing dot.
		if !m.MatchDomain("www.XN--BCHER-KVA.EXAMPLE.") {
			t.Fatal("punycode suffix match failed")
		}
	})

	t.Run("label_63_and_fqdn_253_boundaries", func(t *testing.T) {
		lbl63 := strings.Repeat("a", 63)
		lbl64 := strings.Repeat("a", 64)
		// 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253 bytes total
		fqdn253 := lbl63 + "." + lbl63 + "." + lbl63 + "." + strings.Repeat("b", 61)
		if len(fqdn253) != 253 {
			t.Fatalf("expected 253 bytes, got %d", len(fqdn253))
		}
		fqdn254 := lbl63 + "." + lbl63 + "." + lbl63 + "." + strings.Repeat("b", 62)
		if len(fqdn254) != 254 {
			t.Fatalf("expected 254 bytes, got %d", len(fqdn254))
		}

		if norm, ok := normalizeRuleDomain(lbl63 + ".com"); !ok || norm != lbl63+".com" {
			t.Fatalf("expected 63-byte label accepted, got (%q, %v)", norm, ok)
		}
		if _, ok := normalizeRuleDomain(lbl64 + ".com"); ok {
			t.Fatal("expected 64-byte label rejected")
		}
		if norm, ok := normalizeRuleDomain(fqdn253); !ok || len(norm) != 253 {
			t.Fatalf("expected 253-byte FQDN accepted, got (%d, %v)", len(norm), ok)
		}
		if _, ok := normalizeRuleDomain(fqdn254); ok {
			t.Fatal("expected 254-byte FQDN rejected")
		}
		if _, ok := normalizeRuleDomain("-badlabel.com"); ok {
			t.Fatal("expected leading hyphen label rejected")
		}
		if _, ok := normalizeRuleDomain("badlabel-.com"); ok {
			t.Fatal("expected trailing hyphen label rejected")
		}

		// Query boundary: 253 accepted, 254 rejected.
		m := ParseRules([]string{fqdn253})
		if !m.MatchDomain(fqdn253 + ".") {
			t.Fatal("expected 253-byte query with trailing dot to match")
		}
		if m.MatchDomain(fqdn254) {
			t.Fatal("expected 254-byte query to be rejected")
		}
	})

	t.Run("ipv6_custom_upstream_and_unlock_addrs", func(t *testing.T) {
		for _, tc := range []struct {
			in   string
			want string
		}{
			{"[::1]:5353", "[::1]:5353"},
			{"[::1]", "[::1]:53"},
			{"udp://[::1]:5353", "[::1]:5353"},
			{"tcp://1.1.1.1", "1.1.1.1:53"},
		} {
			got, err := normalizeDNSAddr(tc.in)
			if err != nil || got != tc.want {
				t.Fatalf("normalizeDNSAddr(%q) = (%q, %v), want %q", tc.in, got, err, tc.want)
			}
		}
	})
}

func TestDNSProxy_RawMalformedWireAndConcurrentReload(t *testing.T) {
	unlockMock := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("203.0.113.55"),
		})
		_ = w.WriteMsg(resp)
	})
	normalMock := startMockDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("198.51.100.55"),
		})
		_ = w.WriteMsg(resp)
	})

	srv, err := New(Config{
		ListenHost:    "127.0.0.1",
		ListenPort:    0,
		UnlockEnabled: true,
		UnlockServer:  unlockMock.addr,
		Rules:         []string{"netflix.com"},
		UpstreamDNS:   normalMock.addr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })

	addr := srv.Addr()

	// 1. Send raw malformed UDP frames (1-byte, truncated header, compression pointer loop, >512B payload).
	udpConn, err := net.DialTimeout("udp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	ptrLoop := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01}
	oversizedUDP := make([]byte, 700)
	copy(oversizedUDP, ptrLoop)
	for _, pkt := range [][]byte{
		{0x00},
		{0xaa, 0xbb, 0xcc, 0xdd},
		ptrLoop,
		oversizedUDP,
	} {
		_, _ = udpConn.Write(pkt)
	}

	// 2. Send raw malformed TCP length-prefixed DNS frames (0-byte length, truncated frame, compression loop).
	for _, frame := range [][]byte{
		{0x00, 0x00},
		{0x00, 0x05, 0x01, 0x02}, // truncated
		func() []byte {
			b := make([]byte, 2+len(ptrLoop))
			binary.BigEndian.PutUint16(b[:2], uint16(len(ptrLoop)))
			copy(b[2:], ptrLoop)
			return b
		}(),
	} {
		tc, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_, _ = tc.Write(frame)
			_ = tc.Close()
		}
	}

	// 3. Concurrent ApplyProtocolConfig hot-reloads + concurrent UDP & TCP queries under -race.
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()

	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for ctx.Err() == nil {
			rules := []string{"netflix.com", "disney.com"}
			if i%2 == 1 {
				rules = []string{"netflix.com", "hulu.com"}
			}
			_ = srv.ApplyProtocolConfig(protocol.DNSConfig{
				UnlockEnabled: true,
				UnlockServer:  unlockMock.addr,
				Rules:         rules,
				UpstreamDNS:   normalMock.addr,
				LocalPort:     0,
			})
			i++
			time.Sleep(15 * time.Millisecond)
		}
	}()

	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			proto := "udp"
			if id%2 == 1 {
				proto = "tcp"
			}
			c := &dns.Client{Net: proto, Timeout: time.Second}
			for ctx.Err() == nil {
				m := new(dns.Msg)
				if id%3 == 0 {
					m.SetQuestion("netflix.com.", dns.TypeA)
				} else if id%3 == 1 {
					m.SetQuestion("netflix.com.", dns.TypeAAAA)
				} else {
					m.SetQuestion("example.org.", dns.TypeA)
				}
				resp, _, err := c.Exchange(m, addr)
				if err != nil {
					t.Errorf("concurrent %s query failed: %v", proto, err)
					return
				}
				if resp.Rcode != dns.RcodeSuccess {
					t.Errorf("unexpected rcode %d", resp.Rcode)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	// Final sanity query after stress.
	resp := exchangeQuery(t, "udp", addr, "netflix.com", dns.TypeA, 0)
	if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "203.0.113.55" {
		t.Fatalf("unexpected post-stress answer: %+v", resp.Answer)
	}
}
