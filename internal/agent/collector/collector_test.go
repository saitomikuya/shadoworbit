package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"

	"snell-panel/internal/protocol"
)

type mockStatsHandler interface {
	QueryStats(ctx context.Context, req []byte) ([]byte, error)
}

var testStatsServiceDesc = grpc.ServiceDesc{
	ServiceName: "v2ray.core.app.stats.command.StatsService",
	HandlerType: (*mockStatsHandler)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "QueryStats",
			Handler: func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
				var in []byte
				if err := dec(&in); err != nil {
					return nil, err
				}
				if interceptor == nil {
					return srv.(mockStatsHandler).QueryStats(ctx, in)
				}
				info := &grpc.UnaryServerInfo{
					Server:     srv,
					FullMethod: statsQueryMethod,
				}
				return interceptor(ctx, in, info, func(ctx context.Context, req any) (any, error) {
					return srv.(mockStatsHandler).QueryStats(ctx, req.([]byte))
				})
			},
		},
	},
}

type decodedQueryReq struct {
	Pattern   string
	Reset     bool
	Patterns  []string
	HasRegexp bool
	Regexp    bool
}

type mockStatsServer struct {
	mu           sync.Mutex
	counters     map[string]int64
	calls        atomic.Int64
	lastReq      decodedQueryReq
	includeExtra bool // inject unknown protobuf fields for forward-compat testing
}

func newMockStatsServer() *mockStatsServer {
	return &mockStatsServer{
		counters: make(map[string]int64),
	}
}

func (m *mockStatsServer) SetCounter(name string, val int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counters[name] = val
}

func (m *mockStatsServer) LastRequest() decodedQueryReq {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.lastReq
	out.Patterns = append([]string(nil), m.lastReq.Patterns...)
	return out
}

func (m *mockStatsServer) QueryStats(_ context.Context, rawReq []byte) ([]byte, error) {
	m.calls.Add(1)

	req, err := decodeQueryStatsRequestForTest(rawReq)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastReq = req

	matchers := req.Patterns
	if len(matchers) == 0 && req.Pattern != "" {
		matchers = []string{req.Pattern}
	}

	var matched []rawStat
	for name, val := range m.counters {
		if len(matchers) == 0 {
			matched = append(matched, rawStat{Name: name, Value: val})
			if req.Reset {
				m.counters[name] = 0
			}
			continue
		}
		for _, pat := range matchers {
			if strings.Contains(name, pat) {
				matched = append(matched, rawStat{Name: name, Value: val})
				if req.Reset {
					m.counters[name] = 0
				}
				break
			}
		}
	}

	return encodeQueryStatsResponseForTest(matched, m.includeExtra), nil
}

func decodeQueryStatsRequestForTest(b []byte) (decodedQueryReq, error) {
	var req decodedQueryReq
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return req, protowire.ParseError(n)
		}
		b = b[n:]
		switch {
		case num == 1 && typ == protowire.BytesType:
			v, m := protowire.ConsumeString(b)
			if m < 0 {
				return req, protowire.ParseError(m)
			}
			req.Pattern = v
			b = b[m:]
		case num == 2 && typ == protowire.VarintType:
			v, m := protowire.ConsumeVarint(b)
			if m < 0 {
				return req, protowire.ParseError(m)
			}
			req.Reset = v != 0
			b = b[m:]
		case num == 3 && typ == protowire.BytesType:
			v, m := protowire.ConsumeString(b)
			if m < 0 {
				return req, protowire.ParseError(m)
			}
			req.Patterns = append(req.Patterns, v)
			b = b[m:]
		case num == 4 && typ == protowire.VarintType:
			v, m := protowire.ConsumeVarint(b)
			if m < 0 {
				return req, protowire.ParseError(m)
			}
			req.HasRegexp = true
			req.Regexp = v != 0
			b = b[m:]
		default:
			m := protowire.ConsumeFieldValue(num, typ, b)
			if m < 0 {
				return req, protowire.ParseError(m)
			}
			b = b[m:]
		}
	}
	return req, nil
}

func encodeQueryStatsResponseForTest(stats []rawStat, includeUnknown bool) []byte {
	var resp []byte
	if includeUnknown {
		// Unknown field 99 on QueryStatsResponse
		resp = protowire.AppendTag(resp, 99, protowire.VarintType)
		resp = protowire.AppendVarint(resp, 12345)
	}
	for _, st := range stats {
		var msg []byte
		msg = protowire.AppendTag(msg, 1, protowire.BytesType)
		msg = protowire.AppendString(msg, st.Name)
		msg = protowire.AppendTag(msg, 2, protowire.VarintType)
		msg = protowire.AppendVarint(msg, uint64(st.Value))
		if includeUnknown {
			// Unknown field 7 on Stat
			msg = protowire.AppendTag(msg, 7, protowire.BytesType)
			msg = protowire.AppendString(msg, "extra-meta")
		}
		resp = protowire.AppendTag(resp, 1, protowire.BytesType)
		resp = protowire.AppendBytes(resp, msg)
	}
	return resp
}

func startTestStatsGRPCServer(t *testing.T, srv *mockStatsServer) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	gs := grpc.NewServer(grpc.ForceServerCodec(rawProtoCodec{}))
	gs.RegisterService(&testStatsServiceDesc, srv)
	go func() {
		_ = gs.Serve(lis)
	}()
	t.Cleanup(func() {
		gs.Stop()
		_ = lis.Close()
	})
	return lis.Addr().String()
}

func formatProcNetDev(rows ...struct {
	iface string
	rx    uint64
	tx    uint64
	tight bool
}) string {
	var sb strings.Builder
	sb.WriteString("Inter-|   Receive                                                |  Transmit\n")
	sb.WriteString(" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n")
	for _, r := range rows {
		sep := ": "
		if r.tight {
			sep = ":"
		}
		fmt.Fprintf(&sb, "%6s%s%d 10 0 0 0 0 0 0 %d 20 0 0 0 0 0 0\n", r.iface, sep, r.rx, r.tx)
	}
	return sb.String()
}

func TestNICParsingRouteAutoDetectAndRebootReset(t *testing.T) {
	dir := t.TempDir()
	netDevPath := filepath.Join(dir, "proc_net_dev")
	netRoutePath := filepath.Join(dir, "proc_net_route")

	// eth0 has metric 200, ens5 has metric 100, lo has default route (must be skipped),
	// eth9 has flags 0x0 (down, must be skipped).
	routeContent := strings.Join([]string{
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT",
		"lo\t00000000\t00000000\t0003\t0\t0\t0\t00000000\t0\t0\t0",
		"eth9\t00000000\t0100000A\t0000\t0\t0\t10\t00000000\t0\t0\t0",
		"eth0\t00000000\t0100000A\t0003\t0\t0\t200\t00000000\t0\t0\t0",
		"ens5\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0",
		"ens5\t0000A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0",
	}, "\n") + "\n"
	if err := os.WriteFile(netRoutePath, []byte(routeContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Include tight colon format (no whitespace after ':') on ens5.
	dev1 := formatProcNetDev(
		struct {
			iface string
			rx    uint64
			tx    uint64
			tight bool
		}{"lo", 500, 500, false},
		struct {
			iface string
			rx    uint64
			tx    uint64
			tight bool
		}{"eth0", 1000, 2000, false},
		struct {
			iface string
			rx    uint64
			tx    uint64
			tight bool
		}{"ens5", 9876543210, 1234567890, true},
	)
	if err := os.WriteFile(netDevPath, []byte(dev1), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := New(Options{
		DataDir:          dir,
		ProcNetDevPath:   netDevPath,
		ProcNetRoutePath: netRoutePath,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// First poll establishes baseline -> delta 0.
	if err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce 1: %v", err)
	}
	m1, ack1, err := c.StageMetrics(context.Background(), protocol.AgentHealth{Snell: true})
	if err != nil {
		t.Fatalf("StageMetrics 1: %v", err)
	}
	if m1.NicRxDelta != 0 || m1.NicTxDelta != 0 {
		t.Fatalf("expected 0 initial delta, got rx=%d tx=%d", m1.NicRxDelta, m1.NicTxDelta)
	}
	if m1.UserDeltas == nil || len(m1.UserDeltas) != 0 {
		t.Fatalf("expected non-nil empty UserDeltas, got %#v", m1.UserDeltas)
	}
	if err := ack1(); err != nil {
		t.Fatalf("ack1: %v", err)
	}

	time.Sleep(20 * time.Millisecond)

	// Second poll: ens5 increases by rx=4096, tx=2048.
	dev2 := formatProcNetDev(
		struct {
			iface string
			rx    uint64
			tx    uint64
			tight bool
		}{"lo", 900, 900, false},
		struct {
			iface string
			rx    uint64
			tx    uint64
			tight bool
		}{"eth0", 9999, 9999, false},
		struct {
			iface string
			rx    uint64
			tx    uint64
			tight bool
		}{"ens5", 9876543210 + 4096, 1234567890 + 2048, true},
	)
	if err := os.WriteFile(netDevPath, []byte(dev2), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce 2: %v", err)
	}
	m2, ack2, err := c.StageMetrics(context.Background(), protocol.AgentHealth{Snell: true, SingBox: true})
	if err != nil {
		t.Fatalf("StageMetrics 2: %v", err)
	}
	if m2.NicRxDelta != 4096 || m2.NicTxDelta != 2048 {
		t.Fatalf("expected rx=4096 tx=2048 (ens5), got rx=%d tx=%d", m2.NicRxDelta, m2.NicTxDelta)
	}
	if m2.RxBPS == 0 || m2.TxBPS == 0 {
		t.Fatalf("expected non-zero RxBPS/TxBPS, got rx_bps=%d tx_bps=%d", m2.RxBPS, m2.TxBPS)
	}
	if err := ack2(); err != nil {
		t.Fatalf("ack2: %v", err)
	}

	// Third poll: simulate independent counter reset on RX (reboot) while TX continues increasing.
	dev3 := formatProcNetDev(
		struct {
			iface string
			rx    uint64
			tx    uint64
			tight bool
		}{"ens5", 500, 1234567890 + 2048 + 1000, true},
	)
	if err := os.WriteFile(netDevPath, []byte(dev3), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce 3 (reboot reset): %v", err)
	}
	m3, ack3, err := c.StageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil {
		t.Fatalf("StageMetrics 3: %v", err)
	}
	if m3.NicRxDelta != 0 || m3.NicTxDelta != 1000 {
		t.Fatalf("expected rx=0 (reset) tx=1000, got rx=%d tx=%d", m3.NicRxDelta, m3.NicTxDelta)
	}
	_ = ack3()

	// Fourth poll after reset: RX grows from new baseline 500 -> 800 (+300).
	dev4 := formatProcNetDev(
		struct {
			iface string
			rx    uint64
			tx    uint64
			tight bool
		}{"ens5", 800, 1234567890 + 2048 + 1500, true},
	)
	if err := os.WriteFile(netDevPath, []byte(dev4), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce 4: %v", err)
	}
	m4, ack4, err := c.StageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil {
		t.Fatalf("StageMetrics 4: %v", err)
	}
	if m4.NicRxDelta != 300 || m4.NicTxDelta != 500 {
		t.Fatalf("expected rx=300 tx=500 after baseline reset, got rx=%d tx=%d", m4.NicRxDelta, m4.NicTxDelta)
	}
	_ = ack4()

	// Fifth poll: interface switch in /proc/net/route (ens5 -> eth0 lower metric) resets baseline without spike.
	routeSwitched := strings.Join([]string{
		"Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT",
		"eth0\t00000000\t0100000A\t0003\t0\t0\t50\t00000000\t0\t0\t0",
		"ens5\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0",
	}, "\n") + "\n"
	if err := os.WriteFile(netRoutePath, []byte(routeSwitched), 0o600); err != nil {
		t.Fatal(err)
	}
	dev5 := formatProcNetDev(
		struct {
			iface string
			rx    uint64
			tx    uint64
			tight bool
		}{"eth0", 50000, 60000, false},
		struct {
			iface string
			rx    uint64
			tx    uint64
			tight bool
		}{"ens5", 900, 1234567890 + 2048 + 1600, true},
	)
	if err := os.WriteFile(netDevPath, []byte(dev5), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce 5 (iface switch): %v", err)
	}
	m5, _, err := c.StageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil {
		t.Fatalf("StageMetrics 5: %v", err)
	}
	if m5.NicRxDelta != 0 || m5.NicTxDelta != 0 {
		t.Fatalf("expected 0 delta on interface switch, got rx=%d tx=%d", m5.NicRxDelta, m5.NicTxDelta)
	}
}

func TestNICProcNetDevFallbackWithoutRoute(t *testing.T) {
	dir := t.TempDir()
	netDevPath := filepath.Join(dir, "proc_net_dev")
	missingRoute := filepath.Join(dir, "missing_route")

	if err := os.WriteFile(netDevPath, []byte(formatProcNetDev(
		struct {
			iface string
			rx    uint64
			tx    uint64
			tight bool
		}{"lo", 100, 100, false},
		struct {
			iface string
			rx    uint64
			tx    uint64
			tight bool
		}{"veth123", 200, 200, false},
		struct {
			iface string
			rx    uint64
			tx    uint64
			tight bool
		}{"synthetic0", 1000, 2000, false},
	)), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := New(Options{
		DataDir:          dir,
		ProcNetDevPath:   netDevPath,
		ProcNetRoutePath: missingRoute,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce 1: %v", err)
	}
	if err := os.WriteFile(netDevPath, []byte(formatProcNetDev(
		struct {
			iface string
			rx    uint64
			tx    uint64
			tight bool
		}{"lo", 999, 999, false},
		struct {
			iface string
			rx    uint64
			tx    uint64
			tight bool
		}{"veth123", 999, 999, false},
		struct {
			iface string
			rx    uint64
			tx    uint64
			tight bool
		}{"synthetic0", 1500, 2600, false},
	)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce 2: %v", err)
	}
	m, _, err := c.StageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil {
		t.Fatalf("StageMetrics: %v", err)
	}
	if m.NicRxDelta != 500 || m.NicTxDelta != 600 {
		t.Fatalf("expected synthetic0 fallback delta rx=500 tx=600, got rx=%d tx=%d", m.NicRxDelta, m.NicTxDelta)
	}
}

func TestNICIFACEOverrideAndMissingOverrideError(t *testing.T) {
	dir := t.TempDir()
	netDevPath := filepath.Join(dir, "proc_net_dev")
	netRoutePath := filepath.Join(dir, "proc_net_route")

	if err := os.WriteFile(netRoutePath, []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\nens5\t00000000\t0100000A\t0003\t0\t0\t10\t00000000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dev1 := formatProcNetDev(
		struct {
			iface string
			rx    uint64
			tx    uint64
			tight bool
		}{"ens5", 100, 100, false},
		struct {
			iface string
			rx    uint64
			tx    uint64
			tight bool
		}{"eth0", 1000, 2000, false},
	)
	if err := os.WriteFile(netDevPath, []byte(dev1), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("IFACE", "eth0")
	c, err := New(Options{
		DataDir:          dir,
		ProcNetDevPath:   netDevPath,
		ProcNetRoutePath: netRoutePath,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce 1: %v", err)
	}

	dev2 := formatProcNetDev(
		struct {
			iface string
			rx    uint64
			tx    uint64
			tight bool
		}{"ens5", 9999, 9999, false},
		struct {
			iface string
			rx    uint64
			tx    uint64
			tight bool
		}{"eth0", 1250, 2750, false},
	)
	if err := os.WriteFile(netDevPath, []byte(dev2), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce 2: %v", err)
	}
	m, _, err := c.StageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil {
		t.Fatalf("StageMetrics: %v", err)
	}
	if m.NicRxDelta != 250 || m.NicTxDelta != 750 {
		t.Fatalf("expected IFACE=eth0 delta rx=250 tx=750, got rx=%d tx=%d", m.NicRxDelta, m.NicTxDelta)
	}

	// Explicitly overridden missing ProcNetDevPath must return an error even on darwin.
	cBad, err := New(Options{
		DataDir:        t.TempDir(),
		ProcNetDevPath: filepath.Join(dir, "does_not_exist"),
	})
	if err != nil {
		t.Fatalf("New bad path: %v", err)
	}
	if err := cBad.PollOnce(context.Background()); err == nil {
		t.Fatalf("expected error for missing overridden ProcNetDevPath, got nil")
	}
}

func TestGRPCStatsWireRoundTripAndParsing(t *testing.T) {
	srv := newMockStatsServer()
	srv.includeExtra = true
	srv.SetCounter("user>>>alice>>>traffic>>>uplink", 1024)
	srv.SetCounter("user>>>alice>>>traffic>>>downlink", 2048)
	srv.SetCounter("user>>>alice>bob>>>traffic>>>uplink", 333)
	srv.SetCounter("user>>>a>>>b>>>traffic>>>downlink", 444)
	srv.SetCounter("user>>>ghost>>>traffic>>>uplink", 777)
	srv.SetCounter("user>>>neg>>>traffic>>>uplink", -500) // negative int64 two's complement
	srv.SetCounter("user>>>zero>>>traffic>>>uplink", 0)
	srv.SetCounter("user>>>>>>traffic>>>uplink", 999)         // empty username -> ignored
	srv.SetCounter("inbound>>>ss-in>>>traffic>>>uplink", 888) // non-user -> ignored

	addr := startTestStatsGRPCServer(t, srv)
	dir := t.TempDir()
	c, err := New(Options{
		DataDir:   dir,
		StatsAddr: addr,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Stop()

	c.SetActiveUsers([]protocol.SSUserEntry{
		{UserID: 101, Username: "alice"},
		{UserID: 102, Username: "alice>bob"},
		{UserID: 103, Username: "a>>>b"},
	})

	if err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}

	req := srv.LastRequest()
	if req.Pattern != "user>>>" || !req.Reset {
		t.Fatalf("expected Pattern='user>>>' and Reset=true, got %+v", req)
	}
	if len(req.Patterns) != 1 || req.Patterns[0] != "user>>>" {
		t.Fatalf("expected Patterns=['user>>>'], got %+v", req.Patterns)
	}
	if req.HasRegexp && req.Regexp {
		t.Fatalf("expected Regexp=false/omitted, got %+v", req)
	}

	// Verify server reset matched counters to 0 while leaving non-user counter untouched.
	srv.mu.Lock()
	if srv.counters["user>>>alice>>>traffic>>>uplink"] != 0 {
		t.Fatalf("expected alice uplink reset to 0")
	}
	if srv.counters["inbound>>>ss-in>>>traffic>>>uplink"] != 888 {
		t.Fatalf("expected inbound counter untouched, got %d", srv.counters["inbound>>>ss-in>>>traffic>>>uplink"])
	}
	srv.mu.Unlock()

	m1, err := c.SnapshotAndStageMetrics(context.Background(), protocol.AgentHealth{SingBox: true})
	if err != nil {
		t.Fatalf("SnapshotAndStageMetrics: %v", err)
	}
	byName := make(map[string]protocol.UserTrafficDelta, len(m1.UserDeltas))
	for _, d := range m1.UserDeltas {
		byName[d.Username] = d
	}
	if len(byName) != 4 {
		t.Fatalf("expected 4 users (alice, alice>bob, a>>>b, ghost), got %#v", m1.UserDeltas)
	}
	if d := byName["alice"]; d.UserID != 101 || d.UpBytes != 1024 || d.DownBytes != 2048 {
		t.Fatalf("unexpected alice delta: %+v", d)
	}
	if d := byName["alice>bob"]; d.UserID != 102 || d.UpBytes != 333 || d.DownBytes != 0 {
		t.Fatalf("unexpected alice>bob delta: %+v", d)
	}
	if d := byName["a>>>b"]; d.UserID != 103 || d.UpBytes != 0 || d.DownBytes != 444 {
		t.Fatalf("unexpected a>>>b delta: %+v", d)
	}
	if d := byName["ghost"]; d.UserID != 0 || d.UpBytes != 777 || d.DownBytes != 0 {
		t.Fatalf("unexpected ghost delta: %+v", d)
	}

	// Backfill unknown user ID when SetActiveUsers updates.
	c.SetActiveUsers([]protocol.SSUserEntry{
		{UserID: 101, Username: "alice"},
		{UserID: 999, Username: "ghost"},
	})
	m2, ack2, err := c.StageMetrics(context.Background(), protocol.AgentHealth{SingBox: true})
	if err != nil {
		t.Fatalf("StageMetrics: %v", err)
	}
	foundGhost := false
	for _, d := range m2.UserDeltas {
		if d.Username == "ghost" {
			foundGhost = true
			if d.UserID != 999 || d.UpBytes != 777 {
				t.Fatalf("expected backfilled ghost UserID=999 UpBytes=777, got %+v", d)
			}
		}
	}
	if !foundGhost {
		t.Fatalf("expected ghost in UserDeltas")
	}
	if err := ack2(); err != nil {
		t.Fatalf("ack2: %v", err)
	}

	// SetStatsEnabled(false) must skip gRPC queries.
	callsBefore := srv.calls.Load()
	c.SetStatsEnabled(false)
	srv.SetCounter("user>>>alice>>>traffic>>>uplink", 555)
	if err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce disabled: %v", err)
	}
	if srv.calls.Load() != callsBefore {
		t.Fatalf("expected 0 RPC calls when stats disabled")
	}
}

func TestWALPersistenceCorruptRecoveryAndConcurrency(t *testing.T) {
	dir := t.TempDir()
	walPath := filepath.Join(dir, "pending_traffic.json")
	netDevPath := filepath.Join(dir, "proc_net_dev")

	// 1. Corrupt WAL must be quarantined and Collector starts cleanly.
	if err := os.WriteFile(walPath, []byte(`{"version":1,"nic_rx_delta":`), 0o600); err != nil {
		t.Fatal(err)
	}
	c1, err := New(Options{
		DataDir:        dir,
		WALPath:        walPath,
		ProcNetDevPath: netDevPath,
	})
	if err != nil {
		t.Fatalf("New with corrupt WAL failed: %v", err)
	}
	matches, err := filepath.Glob(walPath + ".corrupt.*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("expected 1 quarantined corrupt WAL file, got %v (err=%v)", matches, err)
	}

	// 2. Accumulate NIC + user deltas without calling ack(), restart Collector, verify persistence.
	srv := newMockStatsServer()
	srv.SetCounter("user>>>alice>>>traffic>>>uplink", 500)
	srv.SetCounter("user>>>alice>>>traffic>>>downlink", 1500)
	addr := startTestStatsGRPCServer(t, srv)

	if err := os.WriteFile(netDevPath, []byte(formatProcNetDev(struct {
		iface string
		rx    uint64
		tx    uint64
		tight bool
	}{"eth0", 1000, 2000, false})), 0o600); err != nil {
		t.Fatal(err)
	}

	c1, err = New(Options{
		DataDir:        dir,
		WALPath:        walPath,
		ProcNetDevPath: netDevPath,
		StatsAddr:      addr,
		Interface:      "eth0",
	})
	if err != nil {
		t.Fatalf("New c1: %v", err)
	}
	c1.SetActiveUsers([]protocol.SSUserEntry{{UserID: 7, Username: "alice"}})
	if err := c1.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce 1: %v", err)
	}
	if err := os.WriteFile(netDevPath, []byte(formatProcNetDev(struct {
		iface string
		rx    uint64
		tx    uint64
		tight bool
	}{"eth0", 1300, 2700, false})), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c1.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce 2: %v", err)
	}
	c1.Stop()

	// Restart Collector from same WALPath.
	c2, err := New(Options{
		DataDir:        dir,
		WALPath:        walPath,
		ProcNetDevPath: netDevPath,
		StatsAddr:      addr,
		Interface:      "eth0",
	})
	if err != nil {
		t.Fatalf("New c2: %v", err)
	}
	defer c2.Stop()

	// SnapshotAndStageMetrics must be non-destructive and must not invalidate subsequent StageMetrics.
	snap, err := c2.SnapshotAndStageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil {
		t.Fatalf("SnapshotAndStageMetrics: %v", err)
	}
	if snap.NicRxDelta != 300 || snap.NicTxDelta != 700 {
		t.Fatalf("expected recovered NIC rx=300 tx=700, got rx=%d tx=%d", snap.NicRxDelta, snap.NicTxDelta)
	}
	if len(snap.UserDeltas) != 1 || snap.UserDeltas[0].UpBytes != 500 || snap.UserDeltas[0].DownBytes != 1500 || snap.UserDeltas[0].UserID != 7 {
		t.Fatalf("expected recovered alice delta, got %#v", snap.UserDeltas)
	}

	// Stage S1, then simulate concurrent PollOnce D2 BEFORE ack1() runs!
	s1, ack1, err := c2.StageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil {
		t.Fatalf("StageMetrics S1: %v", err)
	}
	if s1.NicRxDelta != 300 || s1.NicTxDelta != 700 {
		t.Fatalf("unexpected S1 NIC: rx=%d tx=%d", s1.NicRxDelta, s1.NicTxDelta)
	}

	// Establish c2 NIC baseline first, then produce D2 (NIC rx+100 tx+200, alice up+400).
	if err := c2.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce baseline on c2: %v", err)
	}
	srv.SetCounter("user>>>alice>>>traffic>>>uplink", 400)
	if err := os.WriteFile(netDevPath, []byte(formatProcNetDev(struct {
		iface string
		rx    uint64
		tx    uint64
		tight bool
	}{"eth0", 1400, 2900, false})), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c2.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce D2: %v", err)
	}

	// Calling SnapshotAndStageMetrics while ack1 is pending must NOT invalidate ack1.
	if _, err := c2.SnapshotAndStageMetrics(context.Background(), protocol.AgentHealth{}); err != nil {
		t.Fatalf("SnapshotAndStageMetrics during pending ack1: %v", err)
	}

	// Now ack S1 (and test idempotency by calling ack1 twice).
	if err := ack1(); err != nil {
		t.Fatalf("ack1: %v", err)
	}
	if err := ack1(); err != nil {
		t.Fatalf("ack1 second call: %v", err)
	}

	// Next StageMetrics must return EXACTLY D2 (not 0, not S1+D2).
	s2, ack2, err := c2.StageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil {
		t.Fatalf("StageMetrics S2: %v", err)
	}
	if s2.NicRxDelta != 100 || s2.NicTxDelta != 200 {
		t.Fatalf("expected D2 NIC rx=100 tx=200, got rx=%d tx=%d", s2.NicRxDelta, s2.NicTxDelta)
	}
	if len(s2.UserDeltas) != 1 || s2.UserDeltas[0].UpBytes != 400 || s2.UserDeltas[0].DownBytes != 0 {
		t.Fatalf("expected D2 alice up=400 down=0, got %#v", s2.UserDeltas)
	}

	// Test superseded ack guard: call StageMetrics S3 without acking S2, then call ack2().
	// ack2() must be a no-op because S3 superseded S2; ack3() clears D2 cleanly.
	s3, ack3, err := c2.StageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil {
		t.Fatalf("StageMetrics S3: %v", err)
	}
	if s3.NicRxDelta != 100 {
		t.Fatalf("expected S3 rx=100, got %d", s3.NicRxDelta)
	}
	if err := ack2(); err != nil {
		t.Fatalf("superseded ack2: %v", err)
	}
	// Because ack2 was superseded, D2 is still intact for ack3 to clear once.
	stillThere, err := c2.SnapshotAndStageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil {
		t.Fatalf("SnapshotAndStageMetrics after superseded ack2: %v", err)
	}
	if stillThere.NicRxDelta != 100 {
		t.Fatalf("expected D2 still present after superseded ack2, got %d", stillThere.NicRxDelta)
	}
	if err := ack3(); err != nil {
		t.Fatalf("ack3: %v", err)
	}

	// Verify WAL is now completely drained and JSON marshals empty UserDeltas as [].
	finalM, _, err := c2.StageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil {
		t.Fatalf("final StageMetrics: %v", err)
	}
	if finalM.NicRxDelta != 0 || finalM.NicTxDelta != 0 || finalM.UserDeltas == nil || len(finalM.UserDeltas) != 0 {
		t.Fatalf("expected drained WAL with non-nil empty UserDeltas, got %+v", finalM)
	}
	rawJSON, err := json.Marshal(finalM)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rawJSON), `"user_deltas":[]`) {
		t.Fatalf("expected non-null empty user_deltas JSON array, got %s", string(rawJSON))
	}
}

func TestHostTelemetryFixturesAndHostInfo(t *testing.T) {
	dir := t.TempDir()
	statPath := filepath.Join(dir, "proc_stat")
	memPath := filepath.Join(dir, "proc_meminfo")
	uptimePath := filepath.Join(dir, "proc_uptime")

	if err := os.WriteFile(statPath, []byte("cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 50 0 50 400 0 0 0 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	memContent := strings.Join([]string{
		"MemTotal:        1048576 kB",
		"MemFree:          100000 kB",
		"MemAvailable:     262144 kB",
		"Buffers:           10000 kB",
	}, "\n") + "\n"
	if err := os.WriteFile(memPath, []byte(memContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(uptimePath, []byte("12345.67 98765.43\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := New(Options{
		DataDir:         dir,
		ProcStatPath:    statPath,
		ProcMeminfoPath: memPath,
		ProcUptimePath:  uptimePath,
		DiskPath:        dir,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	osName, arch, cores, totalRAM := c.HostInfo()
	if osName != runtime.GOOS || arch != runtime.GOARCH || cores <= 0 {
		t.Fatalf("unexpected HostInfo: os=%s arch=%s cores=%d", osName, arch, cores)
	}
	if totalRAM != 1048576*1024 {
		t.Fatalf("expected totalRAM=%d, got %d", 1048576*1024, totalRAM)
	}

	// First CPU read establishes baseline -> 0%.
	m1, err := c.SnapshotAndStageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil {
		t.Fatalf("Snapshot 1: %v", err)
	}
	if m1.CPUPercent != 0 {
		t.Fatalf("expected initial CPUPercent=0, got %v", m1.CPUPercent)
	}
	if m1.MemTotalBytes != 1048576*1024 || m1.MemUsedBytes != (1048576-262144)*1024 {
		t.Fatalf("unexpected mem: used=%d total=%d", m1.MemUsedBytes, m1.MemTotalBytes)
	}
	if m1.UptimeSeconds != 12345 {
		t.Fatalf("expected uptime=12345, got %d", m1.UptimeSeconds)
	}
	if m1.DiskUsedPercent < 0 || m1.DiskUsedPercent > 100 {
		t.Fatalf("unexpected disk percent: %v", m1.DiskUsedPercent)
	}

	// Advance /proc/stat: total +1000, idle +250 -> 75% CPU.
	if err := os.WriteFile(statPath, []byte("cpu  600 0 350 1050 0 0 0 0 0 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m2, err := c.SnapshotAndStageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil {
		t.Fatalf("Snapshot 2: %v", err)
	}
	if m2.CPUPercent < 74.9 || m2.CPUPercent > 75.1 {
		t.Fatalf("expected CPUPercent ~75.0, got %v", m2.CPUPercent)
	}

	// Reading again without /proc/stat change preserves last measured CPUPercent.
	m3, err := c.SnapshotAndStageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil {
		t.Fatalf("Snapshot 3: %v", err)
	}
	if m3.CPUPercent < 74.9 || m3.CPUPercent > 75.1 {
		t.Fatalf("expected preserved CPUPercent ~75.0, got %v", m3.CPUPercent)
	}

	// Also test MemAvailable fallback (MemFree + Buffers + Cached + SReclaimable).
	memFallback := strings.Join([]string{
		"MemTotal:        1000000 kB",
		"MemFree:          100000 kB",
		"Buffers:           50000 kB",
		"Cached:           150000 kB",
		"SReclaimable:      50000 kB",
	}, "\n") + "\n"
	if err := os.WriteFile(memPath, []byte(memFallback), 0o600); err != nil {
		t.Fatal(err)
	}
	m4, err := c.SnapshotAndStageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil {
		t.Fatalf("Snapshot 4: %v", err)
	}
	if m4.MemUsedBytes != 650000*1024 || m4.MemTotalBytes != 1000000*1024 {
		t.Fatalf("unexpected fallback mem: used=%d total=%d", m4.MemUsedBytes, m4.MemTotalBytes)
	}

	// Guard against +Inf, -Inf, NaN, and negative values in /proc/uptime.
	for _, badUptime := range []string{"+Inf 0\n", "-Inf 0\n", "NaN 0\n", "-5.0 0\n"} {
		if err := os.WriteFile(uptimePath, []byte(badUptime), 0o600); err != nil {
			t.Fatal(err)
		}
		mBad, err := c.SnapshotAndStageMetrics(context.Background(), protocol.AgentHealth{})
		if err != nil {
			t.Fatalf("Snapshot bad uptime %q: %v", badUptime, err)
		}
		if mBad.UptimeSeconds != 0 {
			t.Fatalf("expected UptimeSeconds=0 for %q, got %d", badUptime, mBad.UptimeSeconds)
		}
	}

	// Verify default platform fallback on host (darwin / linux) returns valid HostInfo & metrics without errors.
	cNative, err := New(Options{DataDir: t.TempDir()})
	if err != nil {
		t.Fatalf("New native: %v", err)
	}
	if err := cNative.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce native: %v", err)
	}
	_, _, nativeCores, nativeRAM := cNative.HostInfo()
	if nativeCores <= 0 || nativeRAM == 0 {
		t.Fatalf("expected positive native cores and RAM, got cores=%d ram=%d", nativeCores, nativeRAM)
	}
	mNative, err := cNative.SnapshotAndStageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil {
		t.Fatalf("Snapshot native: %v", err)
	}
	if mNative.MemTotalBytes == 0 || mNative.UptimeSeconds == 0 {
		t.Fatalf("expected non-zero native mem/uptime, got mem=%d uptime=%d", mNative.MemTotalBytes, mNative.UptimeSeconds)
	}
}

func TestDetectPublicIPs(t *testing.T) {
	v4Invalid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "not-an-ip")
	}))
	defer v4Invalid.Close()

	v4WrongFamily := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "2001:db8::1")
	}))
	defer v4WrongFamily.Close()

	v4Valid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "  203.0.113.10  ")
	}))
	defer v4Valid.Close()

	v6Valid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "2001:db8::42")
	}))
	defer v6Valid.Close()

	v6Timeout := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
		_, _ = fmt.Fprintln(w, "2001:db8::99")
	}))
	defer v6Timeout.Close()

	c, err := New(Options{
		DataDir:             t.TempDir(),
		PublicIPEndpointsV4: []string{v4Invalid.URL, v4WrongFamily.URL, v4Valid.URL},
		PublicIPEndpointsV6: []string{v6Valid.URL},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	v4, v6 := c.DetectPublicIPs(context.Background())
	if v4 != "203.0.113.10" || v6 != "2001:db8::42" {
		t.Fatalf("expected v4=203.0.113.10 v6=2001:db8::42, got v4=%q v6=%q", v4, v6)
	}

	// Verify loopback, RFC1918/ULA private, link-local, zoned, and IPv4-mapped IPv6 addresses are all rejected.
	rejectedV4 := []string{
		"127.0.0.1",
		"10.0.0.1",
		"192.168.1.1",
		"172.16.0.1",
		"169.254.169.254",
		"0.0.0.0",
		"224.0.0.1",
		"::ffff:203.0.113.10",
	}
	for _, bad := range rejectedV4 {
		bad := bad
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprintln(w, bad)
		}))
		cBad, err := New(Options{
			DataDir:             t.TempDir(),
			PublicIPEndpointsV4: []string{srv.URL},
			PublicIPEndpointsV6: []string{},
		})
		if err != nil {
			srv.Close()
			t.Fatalf("New bad v4 %q: %v", bad, err)
		}
		gotV4, _ := cBad.DetectPublicIPs(context.Background())
		srv.Close()
		if gotV4 != "" {
			t.Fatalf("expected non-public v4 %q to be rejected, got %q", bad, gotV4)
		}
	}

	rejectedV6 := []string{
		"::1",
		"fc00::1",
		"fe80::1",
		"fe80::1%eth0",
		"::",
		"ff02::1",
		"::ffff:203.0.113.10",
	}
	for _, bad := range rejectedV6 {
		bad := bad
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprintln(w, bad)
		}))
		cBad, err := New(Options{
			DataDir:             t.TempDir(),
			PublicIPEndpointsV4: []string{},
			PublicIPEndpointsV6: []string{srv.URL},
		})
		if err != nil {
			srv.Close()
			t.Fatalf("New bad v6 %q: %v", bad, err)
		}
		_, gotV6 := cBad.DetectPublicIPs(context.Background())
		srv.Close()
		if gotV6 != "" {
			t.Fatalf("expected non-public v6 %q to be rejected, got %q", bad, gotV6)
		}
	}

	// Verify timeout is non-blocking when context cancels early and empty slice disables family.
	cTimeout, err := New(Options{
		DataDir:             t.TempDir(),
		PublicIPEndpointsV4: []string{},
		PublicIPEndpointsV6: []string{v6Timeout.URL},
	})
	if err != nil {
		t.Fatalf("New timeout: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	v4, v6 = cTimeout.DetectPublicIPs(ctx)
	if time.Since(start) > time.Second {
		t.Fatalf("DetectPublicIPs blocked past context deadline")
	}
	if v4 != "" || v6 != "" {
		t.Fatalf("expected empty IPs on disabled/timed-out endpoints, got v4=%q v6=%q", v4, v6)
	}

	// Verify custom HTTPClient option is honored.
	cCustomClient, err := New(Options{
		DataDir:             t.TempDir(),
		PublicIPEndpointsV4: []string{v4Valid.URL},
		PublicIPEndpointsV6: []string{},
		HTTPClient:          v4Valid.Client(),
	})
	if err != nil {
		t.Fatalf("New custom client: %v", err)
	}
	v4, v6 = cCustomClient.DetectPublicIPs(context.Background())
	if v4 != "203.0.113.10" || v6 != "" {
		t.Fatalf("expected custom HTTPClient v4=203.0.113.10 v6='', got v4=%q v6=%q", v4, v6)
	}
}

func TestStartStopLifecycleUnderRace(t *testing.T) {
	dir := t.TempDir()
	netDevPath := filepath.Join(dir, "proc_net_dev")
	if err := os.WriteFile(netDevPath, []byte(formatProcNetDev(struct {
		iface string
		rx    uint64
		tx    uint64
		tight bool
	}{"eth0", 1000, 2000, false})), 0o600); err != nil {
		t.Fatal(err)
	}

	srv := newMockStatsServer()
	addr := startTestStatsGRPCServer(t, srv)

	c, err := New(Options{
		DataDir:        dir,
		ProcNetDevPath: netDevPath,
		Interface:      "eth0",
		StatsAddr:      addr,
		NICInterval:    15 * time.Millisecond,
		StatsInterval:  20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.SetActiveUsers([]protocol.SSUserEntry{{UserID: 1, Username: "alice"}})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Start(ctx)
	c.Start(ctx) // idempotent Start

	time.Sleep(35 * time.Millisecond)
	srv.SetCounter("user>>>alice>>>traffic>>>uplink", 256)
	if err := os.WriteFile(netDevPath, []byte(formatProcNetDev(struct {
		iface string
		rx    uint64
		tx    uint64
		tight bool
	}{"eth0", 1600, 2400, false})), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(55 * time.Millisecond)

	c.Stop()
	c.Stop() // idempotent Stop

	m, ack, err := c.StageMetrics(context.Background(), protocol.AgentHealth{Snell: true, ShadowTLS: true, SingBox: true})
	if err != nil {
		t.Fatalf("StageMetrics: %v", err)
	}
	if m.NicRxDelta != 600 || m.NicTxDelta != 400 {
		t.Fatalf("expected NIC rx=600 tx=400 from background loop, got rx=%d tx=%d", m.NicRxDelta, m.NicTxDelta)
	}
	if len(m.UserDeltas) != 1 || m.UserDeltas[0].UpBytes != 256 {
		t.Fatalf("expected alice up=256 from background loop, got %#v", m.UserDeltas)
	}
	if err := ack(); err != nil {
		t.Fatalf("ack: %v", err)
	}
}

func TestConcurrentStartStopUnderRace(t *testing.T) {
	dir := t.TempDir()
	netDevPath := filepath.Join(dir, "proc_net_dev")
	if err := os.WriteFile(netDevPath, []byte(formatProcNetDev(struct {
		iface string
		rx    uint64
		tx    uint64
		tight bool
	}{"eth0", 1000, 2000, false})), 0o600); err != nil {
		t.Fatal(err)
	}

	srv := newMockStatsServer()
	addr := startTestStatsGRPCServer(t, srv)

	c, err := New(Options{
		DataDir:        dir,
		ProcNetDevPath: netDevPath,
		Interface:      "eth0",
		StatsAddr:      addr,
		NICInterval:    2 * time.Millisecond,
		StatsInterval:  2 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Stop()

	const workers = 4
	const iterations = 25
	var wg sync.WaitGroup
	wg.Add(workers)
	for g := 0; g < workers; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				ctx, cancel := context.WithCancel(context.Background())
				c.Start(ctx)
				if (id+i)%3 == 0 {
					// Also exercise concurrent parent context cancellation alongside Stop.
					cancel()
				}
				time.Sleep(time.Millisecond)
				c.Stop()
				cancel()
			}
		}(g)
	}
	wg.Wait()

	// Exercise concurrent Stop/Stop while running to confirm both wait for exit cleanly.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.Start(ctx)
	time.Sleep(5 * time.Millisecond)

	var stopWG sync.WaitGroup
	stopWG.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer stopWG.Done()
			c.Stop()
		}()
	}
	stopWG.Wait()
}

type hangingStatsServer struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (h *hangingStatsServer) QueryStats(ctx context.Context, _ []byte) ([]byte, error) {
	h.once.Do(func() { close(h.started) })
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-h.release:
		return nil, nil
	}
}

func TestStopUnblocksHangingGRPC(t *testing.T) {
	h := &hangingStatsServer{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	gs := grpc.NewServer(grpc.ForceServerCodec(rawProtoCodec{}))
	gs.RegisterService(&testStatsServiceDesc, h)
	go func() {
		_ = gs.Serve(lis)
	}()
	t.Cleanup(func() {
		close(h.release)
		gs.Stop()
		_ = lis.Close()
	})

	dir := t.TempDir()
	netDevPath := filepath.Join(dir, "proc_net_dev")
	if err := os.WriteFile(netDevPath, []byte(formatProcNetDev(struct {
		iface string
		rx    uint64
		tx    uint64
		tight bool
	}{"eth0", 1000, 2000, false})), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := New(Options{
		DataDir:        dir,
		ProcNetDevPath: netDevPath,
		Interface:      "eth0",
		StatsAddr:      lis.Addr().String(),
		NICInterval:    50 * time.Millisecond,
		StatsInterval:  50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	pollDone := make(chan error, 1)
	go func() {
		pollDone <- c.PollOnce(context.Background())
	}()

	select {
	case <-h.started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for QueryStats RPC to enter server handler")
	}

	// Stop() must not block on statsMu held by conn.Invoke and must close grpcConn immediately.
	stopStart := time.Now()
	stopDone := make(chan struct{})
	go func() {
		c.Stop()
		close(stopDone)
	}()

	select {
	case <-stopDone:
	case <-time.After(1500 * time.Millisecond):
		t.Fatalf("Stop() blocked too long on hanging gRPC call")
	}
	if elapsed := time.Since(stopStart); elapsed > 1500*time.Millisecond {
		t.Fatalf("Stop() took %v, expected immediate close", elapsed)
	}

	select {
	case err := <-pollDone:
		if err == nil {
			t.Fatalf("expected PollOnce to fail after Stop() closed gRPC connection")
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatalf("PollOnce did not unblock promptly after Stop() closed gRPC connection")
	}

	// Also verify Start/Stop shuts down promptly when background stats loop hits a hanging RPC.
	h2 := &hangingStatsServer{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	lis2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp 2: %v", err)
	}
	gs2 := grpc.NewServer(grpc.ForceServerCodec(rawProtoCodec{}))
	gs2.RegisterService(&testStatsServiceDesc, h2)
	go func() {
		_ = gs2.Serve(lis2)
	}()
	t.Cleanup(func() {
		close(h2.release)
		gs2.Stop()
		_ = lis2.Close()
	})

	c2, err := New(Options{
		DataDir:        t.TempDir(),
		ProcNetDevPath: netDevPath,
		Interface:      "eth0",
		StatsAddr:      lis2.Addr().String(),
		NICInterval:    50 * time.Millisecond,
		StatsInterval:  50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New c2: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c2.Start(ctx)
	select {
	case <-h2.started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for background QueryStats RPC")
	}

	bgStopDone := make(chan struct{})
	go func() {
		c2.Stop()
		close(bgStopDone)
	}()
	select {
	case <-bgStopDone:
	case <-time.After(1500 * time.Millisecond):
		t.Fatalf("background Start/Stop deadlocked or timed out on hanging gRPC call")
	}
}

func TestNICBaselineNotCommittedOnWALError(t *testing.T) {
	dir := t.TempDir()
	netDevPath := filepath.Join(dir, "proc_net_dev")
	walPath := filepath.Join(dir, "pending_traffic.json")

	if err := os.WriteFile(netDevPath, []byte(formatProcNetDev(struct {
		iface string
		rx    uint64
		tx    uint64
		tight bool
	}{"eth0", 1000, 2000, false})), 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := New(Options{
		DataDir:        dir,
		WALPath:        walPath,
		ProcNetDevPath: netDevPath,
		Interface:      "eth0",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// First poll establishes baseline (1000, 2000).
	if err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce baseline: %v", err)
	}

	// Block atomic rename to walPath by placing a non-empty directory at walPath.
	if err := os.MkdirAll(filepath.Join(walPath, "blocker"), 0o750); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(netDevPath, []byte(formatProcNetDev(struct {
		iface string
		rx    uint64
		tx    uint64
		tight bool
	}{"eth0", 1500, 2700, false})), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.PollOnce(context.Background()); err == nil {
		t.Fatalf("expected PollOnce to fail when WAL write fails")
	}

	// Restore walPath writability and advance counters further; full delta from (1000, 2000) must be preserved.
	if err := os.RemoveAll(walPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(netDevPath, []byte(formatProcNetDev(struct {
		iface string
		rx    uint64
		tx    uint64
		tight bool
	}{"eth0", 1800, 3100, false})), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce recovery: %v", err)
	}

	m, ack, err := c.StageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil {
		t.Fatalf("StageMetrics: %v", err)
	}
	if m.NicRxDelta != 800 || m.NicTxDelta != 1100 {
		t.Fatalf("expected preserved NIC delta rx=800 tx=1100 after WAL failure, got rx=%d tx=%d", m.NicRxDelta, m.NicTxDelta)
	}
	if err := ack(); err != nil {
		t.Fatalf("ack: %v", err)
	}
}

func TestCollector_ProcNetDevMissingIfaceAndCounterWrap(t *testing.T) {
	dir := t.TempDir()
	netDevPath := filepath.Join(dir, "proc_net_dev")
	routePath := filepath.Join(dir, "missing_proc_net_route")

	writeDev := func(content string) {
		t.Helper()
		if err := os.WriteFile(netDevPath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// 1. Missing /proc/net/route falls back to first non-loopback non-virtual iface in /proc/net/dev.
	writeDev("Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n" +
		"  lo: 999 0 0 0 0 0 0 0 999 0 0 0 0 0 0 0\n" +
		"  veth123: 100 0 0 0 0 0 0 0 100 0 0 0 0 0 0 0\n" +
		"  ens3: 1000 1 0 0 0 0 0 0 2000 2 0 0 0 0 0 0\n")

	cAuto, err := New(Options{
		DataDir:          filepath.Join(dir, "auto"),
		ProcNetDevPath:   netDevPath,
		ProcNetRoutePath: routePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := cAuto.PollOnce(context.Background()); err != nil {
		t.Fatalf("auto resolve poll failed: %v", err)
	}

	// 2. Explicit configured interface: missing -> error, reappear -> baseline reset, reboot drop -> 0 delta, huge uint64 delta.
	writeDev(formatProcNetDev(struct {
		iface string
		rx    uint64
		tx    uint64
		tight bool
	}{"eth0", 5000, 9000, false}))

	c, err := New(Options{
		DataDir:        filepath.Join(dir, "explicit"),
		ProcNetDevPath: netDevPath,
		Interface:      "eth0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Interface temporarily disappears -> PollOnce returns error without panicking.
	writeDev(formatProcNetDev(struct {
		iface string
		rx    uint64
		tx    uint64
		tight bool
	}{"eth1", 100, 100, false}))
	if err := c.PollOnce(context.Background()); err == nil {
		t.Fatal("expected error when configured interface eth0 disappears")
	}

	// Reboot counter reset (cur < prev): 5000 -> 100 must yield 0 delta (no uint64 underflow!).
	writeDev(formatProcNetDev(struct {
		iface string
		rx    uint64
		tx    uint64
		tight bool
	}{"eth0", 100, 200, false}))
	if err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("poll after reboot drop failed: %v", err)
	}
	m1, ack1, err := c.StageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil || m1.NicRxDelta != 0 || m1.NicTxDelta != 0 {
		t.Fatalf("expected 0 delta on counter drop, got rx=%d tx=%d err=%v", m1.NicRxDelta, m1.NicTxDelta, err)
	}
	_ = ack1()

	// Huge uint64 counter increment (1 << 60).
	const huge = uint64(1) << 60
	writeDev(formatProcNetDev(struct {
		iface string
		rx    uint64
		tx    uint64
		tight bool
	}{"eth0", 100 + huge, 200 + huge, false}))
	if err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("poll huge uint64 failed: %v", err)
	}
	m2, ack2, err := c.StageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil || m2.NicRxDelta != huge || m2.NicTxDelta != huge {
		t.Fatalf("expected huge uint64 delta %d, got rx=%d tx=%d err=%v", huge, m2.NicRxDelta, m2.NicTxDelta, err)
	}
	_ = ack2()

	// 3. Unit tests for pickOSInterface & hasGlobalUnicastIP edge cases.
	if name, ok := pickOSInterface([]net.Interface{
		{Name: "lo0", Flags: net.FlagUp | net.FlagLoopback},
		{Name: "down0", Flags: 0},
		{Name: "missing0", Flags: net.FlagUp},
		{Name: "ppp0", Flags: net.FlagUp | net.FlagPointToPoint},
	}, map[string]procNetDevEntry{
		"lo0":  {iface: "lo0"},
		"ppp0": {iface: "ppp0"},
	}); !ok || name != "ppp0" {
		t.Fatalf("expected fallback to ppp0, got (%q, %v)", name, ok)
	}
	if _, ok := pickOSInterface([]net.Interface{{Name: "lo", Flags: net.FlagUp | net.FlagLoopback}}, map[string]procNetDevEntry{"lo": {}}); ok {
		t.Fatal("expected pickOSInterface to skip loopback-only list")
	}
	if hasGlobalUnicastIP(net.Interface{Index: 999999, Name: "nonexistent-iface-xyz"}) {
		t.Fatal("expected false for nonexistent interface")
	}
}

func TestCollector_WALPartialWriteAndConcurrentStageCommit(t *testing.T) {
	dir := t.TempDir()
	walPath := filepath.Join(dir, "pending_traffic.json")

	// 1. JSON "null" WAL is quarantined and collector initializes clean WAL.
	if err := os.WriteFile(walPath, []byte("  null \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{DataDir: dir, WALPath: walPath})
	if err != nil {
		t.Fatalf("New with null WAL failed: %v", err)
	}
	corruptMatches, _ := filepath.Glob(walPath + ".corrupt.*")
	if len(corruptMatches) != 1 {
		t.Fatalf("expected 1 quarantined null WAL file, got %v", corruptMatches)
	}

	// 2. WAL with version=0, nil user_deltas, zero-delta user entry, and missing Username field normalizes cleanly.
	if err := os.WriteFile(walPath, []byte(`{"version":0,"nic_rx_delta":10,"nic_tx_delta":20,"user_deltas":{"alice":{"user_id":1,"up_bytes":50,"down_bytes":0},"empty_user":{"user_id":2,"up_bytes":0,"down_bytes":0}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c2, err := New(Options{DataDir: dir, WALPath: walPath})
	if err != nil {
		t.Fatalf("New with normalizable WAL failed: %v", err)
	}
	m, ack, err := c2.StageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil {
		t.Fatal(err)
	}
	if m.NicRxDelta != 10 || m.NicTxDelta != 20 || len(m.UserDeltas) != 1 || m.UserDeltas[0].Username != "alice" || m.UserDeltas[0].UpBytes != 50 {
		t.Fatalf("unexpected normalized WAL metrics: %+v", m)
	}
	if err := ack(); err != nil {
		t.Fatal(err)
	}

	// 3. subClamped boundary check.
	if got := subClamped(5, 10); got != 0 {
		t.Fatalf("subClamped(5, 10) = %d, want 0", got)
	}
	if got := subClamped(math.MaxUint64, 1); got != math.MaxUint64-1 {
		t.Fatalf("subClamped max mismatch: %d", got)
	}

	// 4. Concurrent addNICDelta / addUserDeltas + StageMetrics + ack under -race: zero delta loss!
	var expectedNIC uint64
	var expectedUser uint64
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			_ = c.addNICDelta(100, 200)
			expectedNIC += 100
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			_ = c.addUserDeltas(map[string]walUserDelta{
				"bob": {UserID: 7, Username: "bob", UpBytes: 50, DownBytes: 75},
			}, map[string]int64{"bob": 7})
			expectedUser += 50
		}
	}()

	var ackedNIC, ackedUser uint64
	for i := 0; i < 20; i++ {
		st, ackFn, err := c.StageMetrics(context.Background(), protocol.AgentHealth{})
		if err != nil {
			t.Fatal(err)
		}
		if err := ackFn(); err != nil {
			t.Fatal(err)
		}
		ackedNIC += st.NicRxDelta
		for _, u := range st.UserDeltas {
			if u.Username == "bob" {
				ackedUser += u.UpBytes
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	wg.Wait()

	// Final drain.
	st, ackFn, err := c.StageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil {
		t.Fatal(err)
	}
	if err := ackFn(); err != nil {
		t.Fatal(err)
	}
	ackedNIC += st.NicRxDelta
	for _, u := range st.UserDeltas {
		if u.Username == "bob" {
			ackedUser += u.UpBytes
		}
	}

	if ackedNIC != expectedNIC {
		t.Fatalf("concurrent NIC delta mismatch: got %d, want %d", ackedNIC, expectedNIC)
	}
	if ackedUser != expectedUser {
		t.Fatalf("concurrent User delta mismatch: got %d, want %d", ackedUser, expectedUser)
	}
}

type failingStatsServer struct {
	mu      sync.Mutex
	mode    string
	payload []byte
}

func (f *failingStatsServer) QueryStats(_ context.Context, _ []byte) ([]byte, error) {
	f.mu.Lock()
	mode := f.mode
	payload := f.payload
	f.mu.Unlock()

	switch mode {
	case "unavailable":
		return nil, status.Error(codes.Unavailable, "sing-box stats unavailable")
	case "deadline":
		return nil, status.Error(codes.DeadlineExceeded, "stats rpc timeout")
	case "malformed":
		return []byte{0xff, 0xff, 0xff}, nil
	default:
		return payload, nil
	}
}

func TestCollector_GRPCStatsPartialErrorAndResetSemantics(t *testing.T) {
	// Test rawProtoCodec Marshal/Unmarshal edge cases.
	var codec rawProtoCodec
	if b, err := codec.Marshal([]byte("abc")); err != nil || string(b) != "abc" {
		t.Fatalf("Marshal([]byte) = (%q, %v)", b, err)
	}
	ptr := []byte("xyz")
	if b, err := codec.Marshal(&ptr); err != nil || string(b) != "xyz" {
		t.Fatalf("Marshal(*[]byte) = (%q, %v)", b, err)
	}
	var nilPtr *[]byte
	if b, err := codec.Marshal(nilPtr); err != nil || b != nil {
		t.Fatalf("Marshal(nil *[]byte) = (%v, %v)", b, err)
	}
	if _, err := codec.Marshal("unsupported"); err == nil {
		t.Fatal("expected error for unsupported Marshal type")
	}
	if err := codec.Unmarshal([]byte("x"), "bad-target"); err == nil {
		t.Fatal("expected error for unsupported Unmarshal target")
	}

	fs := &failingStatsServer{mode: "unavailable"}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.ForceServerCodec(rawProtoCodec{}))
	gs.RegisterService(&testStatsServiceDesc, fs)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() {
		gs.Stop()
		_ = lis.Close()
	})

	dir := t.TempDir()
	c, err := New(Options{
		DataDir:   dir,
		StatsAddr: lis.Addr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()
	c.SetActiveUsers([]protocol.SSUserEntry{{UserID: 5, Username: "alice"}})

	// Pre-seed pending WAL user delta that MUST NOT be lost on gRPC errors!
	if err := c.addUserDeltas(map[string]walUserDelta{
		"alice": {UserID: 5, Username: "alice", UpBytes: 300, DownBytes: 400},
	}, map[string]int64{"alice": 5}); err != nil {
		t.Fatal(err)
	}

	for _, mode := range []string{"unavailable", "deadline", "malformed"} {
		fs.mu.Lock()
		fs.mode = mode
		fs.mu.Unlock()
		if err := c.pollStats(context.Background()); err == nil {
			t.Fatalf("expected error in gRPC mode %q", mode)
		}
	}

	// Verify existing WAL delta is intact after errors, and subsequent healthy poll adds onto it.
	var statPayload []byte
	statBytes := protowire.AppendTag(nil, 1, protowire.BytesType)
	statBytes = protowire.AppendString(statBytes, "user>>>alice>>>traffic>>>uplink")
	statBytes = protowire.AppendTag(statBytes, 2, protowire.VarintType)
	statBytes = protowire.AppendVarint(statBytes, 200)
	statPayload = protowire.AppendTag(statPayload, 1, protowire.BytesType)
	statPayload = protowire.AppendBytes(statPayload, statBytes)

	fs.mu.Lock()
	fs.mode = "ok"
	fs.payload = statPayload
	fs.mu.Unlock()

	if err := c.pollStats(context.Background()); err != nil {
		t.Fatalf("expected recovery pollStats to succeed, got %v", err)
	}

	m, ack, err := c.StageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.UserDeltas) != 1 || m.UserDeltas[0].UpBytes != 500 || m.UserDeltas[0].DownBytes != 400 {
		t.Fatalf("expected accumulated user delta up=500 down=400, got %+v", m.UserDeltas)
	}
	_ = ack()
}

func TestSnellProcIOMeteringAndWAL(t *testing.T) {
	dir := t.TempDir()
	procRoot := t.TempDir()

	curPID := 101
	writeProcIO := func(pid int, rchar, wchar uint64) {
		p := filepath.Join(procRoot, strconv.Itoa(pid), "io")
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		content := fmt.Sprintf("rchar: %d\nwchar: %d\nsyscr: 1\nsyscw: 1\n", rchar, wchar)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	writeProcIO(101, 5000, 1000)

	c, err := New(Options{
		DataDir:      dir,
		ProcRoot:     procRoot,
		SnellPIDFunc: func() int { return curPID },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop()

	// 1st poll sets baseline -> 0 delta
	c.pollSnellIO()
	m0, ack0, err := c.StageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil || m0.AdminSnellBytes != 0 {
		t.Fatalf("expected 0 delta on baseline poll, got %d err=%v", m0.AdminSnellBytes, err)
	}
	_ = ack0()

	// 2nd poll: rchar +3000, wchar +2500 -> min(3000, 2500) = 2500
	writeProcIO(101, 8000, 3500)
	c.pollSnellIO()
	m1, ack1, err := c.StageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil || m1.AdminSnellBytes != 2500 {
		t.Fatalf("expected AdminSnellBytes=2500, got %d err=%v", m1.AdminSnellBytes, err)
	}
	if err := ack1(); err != nil {
		t.Fatal(err)
	}

	mAfterAck, ack2, err := c.StageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil || mAfterAck.AdminSnellBytes != 0 {
		t.Fatalf("expected AdminSnellBytes=0 after ack, got %d err=%v", mAfterAck.AdminSnellBytes, err)
	}
	_ = ack2()

	// Process restart (PID change) establishes new baseline -> 0 delta
	curPID = 202
	writeProcIO(202, 10000, 9000)
	c.pollSnellIO()
	mRestart, ack3, err := c.StageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil || mRestart.AdminSnellBytes != 0 {
		t.Fatalf("expected 0 delta on PID change baseline, got %d err=%v", mRestart.AdminSnellBytes, err)
	}
	_ = ack3()

	// Subsequent delta after restart counts cleanly
	writeProcIO(202, 11200, 10500)
	c.pollSnellIO()
	m2, ack4, err := c.StageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil || m2.AdminSnellBytes != 1200 {
		t.Fatalf("expected AdminSnellBytes=1200 after restart delta, got %d err=%v", m2.AdminSnellBytes, err)
	}
	_ = ack4()
}

func TestDetectPublicIPsParallelRaceAndSlowEndpoint(t *testing.T) {
	v4Slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(2 * time.Second):
			_, _ = fmt.Fprintln(w, "198.51.100.1")
		}
	}))
	defer v4Slow.Close()

	v4Fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		_, _ = fmt.Fprintln(w, "203.0.113.55")
	}))
	defer v4Fast.Close()

	v6Blackholed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(3 * time.Second):
			_, _ = fmt.Fprintln(w, "2001:db8::99")
		}
	}))
	defer v6Blackholed.Close()

	// 1. Slow endpoint 1 + fast endpoint 2 -> returns in < 400ms instead of stalling 1.5s.
	c1, err := New(Options{
		DataDir:             t.TempDir(),
		PublicIPEndpointsV4: []string{v4Slow.URL, v4Fast.URL},
		PublicIPEndpointsV6: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	start1 := time.Now()
	gotV4, gotV6 := c1.DetectPublicIPs(context.Background())
	elapsed1 := time.Since(start1)
	if gotV4 != "203.0.113.55" || gotV6 != "" {
		t.Fatalf("expected (203.0.113.55, ''), got (%q, %q)", gotV4, gotV6)
	}
	if elapsed1 >= 500*time.Millisecond {
		t.Fatalf("expected parallel race to finish < 500ms, took %v", elapsed1)
	}

	// 2. All V6 endpoints blackholed + fast V4 -> bounded by 1500ms family timeout (< 1.9s vs 3.0s+ before).
	c2, err := New(Options{
		DataDir:             t.TempDir(),
		PublicIPEndpointsV4: []string{v4Fast.URL},
		PublicIPEndpointsV6: []string{v6Blackholed.URL, v6Blackholed.URL},
	})
	if err != nil {
		t.Fatal(err)
	}
	start2 := time.Now()
	gotV4, gotV6 = c2.DetectPublicIPs(context.Background())
	elapsed2 := time.Since(start2)
	if gotV4 != "203.0.113.55" || gotV6 != "" {
		t.Fatalf("expected (203.0.113.55, ''), got (%q, %q)", gotV4, gotV6)
	}
	if elapsed2 >= 1900*time.Millisecond {
		t.Fatalf("expected blackholed IPv6 probe bounded < 1.9s, took %v", elapsed2)
	}
}

func TestCollectorWALSyncThrottlingAndFlush(t *testing.T) {
	dir := t.TempDir()
	netDevPath := filepath.Join(dir, "proc_net_dev")
	procRoot := t.TempDir()
	writeProcIO := func(rchar, wchar uint64) {
		p := filepath.Join(procRoot, "101", "io")
		_ = os.MkdirAll(filepath.Dir(p), 0o750)
		_ = os.WriteFile(p, []byte(fmt.Sprintf("rchar: %d\nwchar: %d\n", rchar, wchar)), 0o600)
	}
	writeDev := func(rx, tx uint64) {
		_ = os.WriteFile(netDevPath, []byte(formatProcNetDev(struct {
			iface string
			rx    uint64
			tx    uint64
			tight bool
		}{"eth0", rx, tx, false})), 0o600)
	}

	writeDev(1000, 2000)
	writeProcIO(500, 500)

	c, err := New(Options{
		DataDir:         dir,
		ProcNetDevPath:  netDevPath,
		ProcRoot:        procRoot,
		Interface:       "eth0",
		SnellPIDFunc:    func() int { return 101 },
		WALSyncInterval: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Baseline poll: 0 writes
	if err := c.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Subsequent 3 coalesced polls: 3 writes (not 6!), only first write fsyncs (2 fsyncs total).
	for i := 1; i <= 3; i++ {
		writeDev(uint64(1000+i*100), uint64(2000+i*200))
		writeProcIO(uint64(500+i*50), uint64(500+i*50))
		if err := c.PollOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	writes, fsyncs := c.WALStats()
	if writes != 3 {
		t.Fatalf("expected 3 coalesced WAL writes, got %d", writes)
	}
	if fsyncs != 2 {
		t.Fatalf("expected 2 initial fsyncs (throttled subsequent), got %d", fsyncs)
	}

	// Stop() must flush pending unsynced WAL to disk with fsync.
	c.Stop()
	_, fsyncsAfterStop := c.WALStats()
	if fsyncsAfterStop != 4 {
		t.Fatalf("expected FlushWAL on Stop() to perform 2 more fsyncs (total 4), got %d", fsyncsAfterStop)
	}

	// Verify WAL on disk reflects all 3 polls.
	raw, err := os.ReadFile(filepath.Join(dir, "pending_traffic.json"))
	if err != nil {
		t.Fatal(err)
	}
	var st walState
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	if st.NICRxDelta != 300 || st.NICTxDelta != 600 || st.AdminSnellBytes != 150 {
		t.Fatalf("unexpected WAL state on disk: %+v", st)
	}
}
