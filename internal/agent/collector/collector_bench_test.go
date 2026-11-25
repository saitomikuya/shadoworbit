package collector

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"

	"snell-panel/internal/protocol"
)

func setupBenchCollectorEnv(b *testing.B, walSyncInterval time.Duration) (*Collector, func(step int)) {
	b.Helper()
	dir := b.TempDir()
	netDevPath := filepath.Join(dir, "proc_net_dev")
	procRoot := filepath.Join(dir, "proc")
	ioPath := filepath.Join(procRoot, "101", "io")
	if err := os.MkdirAll(filepath.Dir(ioPath), 0o750); err != nil {
		b.Fatal(err)
	}

	writeStepFiles := func(step int) {
		rx := uint64(1000 + step*4096)
		tx := uint64(2000 + step*8192)
		dev := fmt.Sprintf(
			"Inter-|   Receive                                                |  Transmit\n"+
				" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"+
				"  eth0: %d 10 0 0 0 0 0 0 %d 10 0 0 0 0 0 0\n",
			rx, tx,
		)
		if err := os.WriteFile(netDevPath, []byte(dev), 0o600); err != nil {
			b.Fatal(err)
		}
		ioContent := fmt.Sprintf("rchar: %d\nwchar: %d\n", 1000+step*512, 1000+step*512)
		if err := os.WriteFile(ioPath, []byte(ioContent), 0o600); err != nil {
			b.Fatal(err)
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	mockSrv := newMockStatsServer()
	grpcSrv := grpc.NewServer(grpc.ForceServerCodec(rawProtoCodec{}))
	grpcSrv.RegisterService(&testStatsServiceDesc, mockSrv)
	go func() {
		_ = grpcSrv.Serve(ln)
	}()
	b.Cleanup(func() {
		grpcSrv.Stop()
		_ = ln.Close()
	})

	writeStepFiles(0)
	c, err := New(Options{
		DataDir:         dir,
		ProcNetDevPath:  netDevPath,
		ProcRoot:        procRoot,
		Interface:       "eth0",
		StatsAddr:       ln.Addr().String(),
		SnellPIDFunc:    func() int { return 101 },
		WALSyncInterval: walSyncInterval,
	})
	if err != nil {
		b.Fatal(err)
	}
	c.SetActiveUsers([]protocol.SSUserEntry{
		{UserID: 1, Username: "alice"},
		{UserID: 2, Username: "bob"},
	})
	b.Cleanup(c.Stop)

	// Baseline poll.
	if err := c.PollOnce(context.Background()); err != nil {
		b.Fatal(err)
	}

	advance := func(step int) {
		writeStepFiles(step)
		mockSrv.SetCounter("user>>>alice>>>traffic>>>uplink", 1024)
		mockSrv.SetCounter("user>>>alice>>>traffic>>>downlink", 2048)
		mockSrv.SetCounter("user>>>bob>>>traffic>>>uplink", 512)
		mockSrv.SetCounter("user>>>bob>>>traffic>>>downlink", 1024)
	}
	return c, advance
}

func BenchmarkCollectorPollAndAckCycle(b *testing.B) {
	b.Run("UncoalescedSyncEveryWrite", func(b *testing.B) {
		c, advance := setupBenchCollectorEnv(b, -1)
		ctx := context.Background()
		w0, f0 := c.WALStats()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 1; i <= b.N; i++ {
			b.StopTimer()
			advance(i)
			b.StartTimer()

			if err := c.pollNIC(); err != nil {
				b.Fatal(err)
			}
			c.pollSnellIO()
			if err := c.pollStats(ctx); err != nil {
				b.Fatal(err)
			}
			_, ack, err := c.StageMetrics(ctx, protocol.AgentHealth{Snell: true, ShadowTLS: true, SingBox: true})
			if err != nil {
				b.Fatal(err)
			}
			if err := ack(); err != nil {
				b.Fatal(err)
			}
		}
		b.StopTimer()
		w1, f1 := c.WALStats()
		b.ReportMetric(float64(w1-w0)/float64(b.N), "wal_writes/op")
		b.ReportMetric(float64(f1-f0)/float64(b.N), "fsyncs/op")
	})

	b.Run("CoalescedThrottled30s", func(b *testing.B) {
		c, advance := setupBenchCollectorEnv(b, 30*time.Second)
		ctx := context.Background()
		w0, f0 := c.WALStats()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 1; i <= b.N; i++ {
			b.StopTimer()
			advance(i)
			b.StartTimer()

			if err := c.PollOnce(ctx); err != nil {
				b.Fatal(err)
			}
			_, ack, err := c.StageMetrics(ctx, protocol.AgentHealth{Snell: true, ShadowTLS: true, SingBox: true})
			if err != nil {
				b.Fatal(err)
			}
			if err := ack(); err != nil {
				b.Fatal(err)
			}
		}
		b.StopTimer()
		w1, f1 := c.WALStats()
		b.ReportMetric(float64(w1-w0)/float64(b.N), "wal_writes/op")
		b.ReportMetric(float64(f1-f0)/float64(b.N), "fsyncs/op")
	})
}

func BenchmarkCollectorHostTick5s(b *testing.B) {
	b.Run("UncoalescedSyncEveryWrite", func(b *testing.B) {
		c, advance := setupBenchCollectorEnv(b, -1)
		ctx := context.Background()
		w0, f0 := c.WALStats()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 1; i <= b.N; i++ {
			b.StopTimer()
			advance(i)
			b.StartTimer()

			if err := c.pollNIC(); err != nil {
				b.Fatal(err)
			}
			c.pollSnellIO()
			_, ack, err := c.StageMetrics(ctx, protocol.AgentHealth{Snell: true, ShadowTLS: true, SingBox: true})
			if err != nil {
				b.Fatal(err)
			}
			if err := ack(); err != nil {
				b.Fatal(err)
			}
		}
		b.StopTimer()
		w1, f1 := c.WALStats()
		b.ReportMetric(float64(w1-w0)/float64(b.N), "wal_writes/op")
		b.ReportMetric(float64(f1-f0)/float64(b.N), "fsyncs/op")
	})

	b.Run("CoalescedThrottled30s", func(b *testing.B) {
		c, advance := setupBenchCollectorEnv(b, 30*time.Second)
		ctx := context.Background()
		w0, f0 := c.WALStats()

		b.ReportAllocs()
		b.ResetTimer()
		for i := 1; i <= b.N; i++ {
			b.StopTimer()
			advance(i)
			b.StartTimer()

			if err := c.pollHostTraffic(); err != nil {
				b.Fatal(err)
			}
			_, ack, err := c.StageMetrics(ctx, protocol.AgentHealth{Snell: true, ShadowTLS: true, SingBox: true})
			if err != nil {
				b.Fatal(err)
			}
			if err := ack(); err != nil {
				b.Fatal(err)
			}
		}
		b.StopTimer()
		w1, f1 := c.WALStats()
		b.ReportMetric(float64(w1-w0)/float64(b.N), "wal_writes/op")
		b.ReportMetric(float64(f1-f0)/float64(b.N), "fsyncs/op")
	})
}

func BenchmarkDetectPublicIPsSlowEndpoint(b *testing.B) {
	v4Slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(500 * time.Millisecond):
			_, _ = fmt.Fprintln(w, "198.51.100.1")
		}
	}))
	defer v4Slow.Close()

	v4Fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "203.0.113.55")
	}))
	defer v4Fast.Close()

	c, err := New(Options{
		DataDir:             b.TempDir(),
		PublicIPEndpointsV4: []string{v4Slow.URL, v4Fast.URL},
		PublicIPEndpointsV6: []string{},
	})
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v4, _ := c.DetectPublicIPs(context.Background())
		if v4 != "203.0.113.55" {
			b.Fatalf("expected 203.0.113.55, got %q", v4)
		}
	}
}
