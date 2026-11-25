package hub

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"snell-panel/internal/panel/auth"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/protocol"
)

func openBenchHubStore(b *testing.B) *store.Store {
	b.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(b.TempDir(), "hub_bench.db")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		b.Fatalf("open store: %v", err)
	}
	b.Cleanup(func() { _ = st.Close() })
	if err := st.SeedDefaults(ctx, store.SeedConfig{}); err != nil {
		b.Fatalf("seed defaults: %v", err)
	}
	return st
}

func createBenchNode(b *testing.B, st *store.Store, name string, groupID *int64) (*store.Node, string) {
	b.Helper()
	rawTok, tokHash, err := auth.GenerateNodeTokenPair()
	if err != nil {
		b.Fatal(err)
	}
	ipsk, err := auth.GenerateIPSKForCipher(protocol.CipherAES128GCM)
	if err != nil {
		b.Fatal(err)
	}
	stlsPwd, err := auth.GenerateShadowTLSPassword()
	if err != nil {
		b.Fatal(err)
	}
	snellPSK, err := auth.GenerateSnellPSK()
	if err != nil {
		b.Fatal(err)
	}
	n := &store.Node{
		Name:                  name,
		RegionTag:             "US",
		TokenHash:             tokHash,
		PublicIP:              "203.0.113.1",
		Enabled:               true,
		Status:                protocol.NodeStatusOffline,
		TrafficLimitBytes:     10000,
		TrafficThresholdBytes: 8500,
		TrafficCountMode:      protocol.TrafficCountBoth,
		ThresholdAction:       protocol.ThresholdActionStopAll,
		BillingResetDay:       1,
		DNSRuleGroupID:        groupID,
		SnellConfig: protocol.SnellConfig{
			Enabled:         true,
			Version:         protocol.SnellVersionV5,
			PublicPort:      443,
			InnerPort:       1443,
			PSK:             snellPSK,
			Obfs:            protocol.SnellObfsOff,
			TFO:             true,
			DNSIPPreference: protocol.DNSIPPrefPreferIPv4,
			STLSPassword:    stlsPwd,
			STLSSNI:         "apple.com",
		},
		SSConfig: protocol.SSConfig{
			Enabled: true,
			TCPPort: 8443,
			UDPPort: 8443,
			Cipher:  protocol.CipherAES128GCM,
			IPSK:    ipsk,
			STLSSNI: "icloud.com",
		},
	}
	if err := st.CreateNode(context.Background(), n); err != nil {
		b.Fatal(err)
	}
	return n, rawTok
}

func BenchmarkSyncAll(b *testing.B) {
	for _, nodeCount := range []int{20, 50} {
		b.Run(fmt.Sprintf("nodes=%d", nodeCount), func(b *testing.B) {
			ctx := context.Background()
			st := openBenchHubStore(b)
			h := NewHub(st, nil, WithPublicDebounce(10*time.Millisecond))
			b.Cleanup(func() { _ = h.Close() })

			grp := &store.DNSRuleGroup{
				Name:  "bench-group",
				Rules: []string{"netflix.com", "disneyplus.com", "openai.com"},
			}
			if err := st.CreateDNSRuleGroup(ctx, grp); err != nil {
				b.Fatal(err)
			}

			mux := http.NewServeMux()
			mux.HandleFunc("/api/v1/agent/ws", h.ServeAgentWS)
			srv := httptest.NewServer(mux)
			b.Cleanup(srv.Close)

			var conns []*websocket.Conn
			drainDone := make(chan struct{})
			for i := 0; i < nodeCount; i++ {
				_, rawTok := createBenchNode(b, st, fmt.Sprintf("bench-node-%d", i), &grp.ID)
				if i%2 == 0 {
					wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/agent/ws"
					hdr := http.Header{"Authorization": {"Bearer " + rawTok}}
					c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: hdr})
					if err != nil {
						b.Fatal(err)
					}
					conns = append(conns, c)
					go func(conn *websocket.Conn) {
						for {
							if _, _, err := conn.Read(ctx); err != nil {
								return
							}
						}
					}(c)
				}
			}
			b.Cleanup(func() {
				close(drainDone)
				for _, c := range conns {
					_ = c.CloseNow()
				}
			})

			// Wait until half the nodes are online in Hub.
			deadline := time.Now().Add(5 * time.Second)
			for len(h.OnlineNodeIDs()) < nodeCount/2 {
				if time.Now().After(deadline) {
					b.Fatalf("timed out waiting for %d online nodes, got %d", nodeCount/2, len(h.OnlineNodeIDs()))
				}
				time.Sleep(10 * time.Millisecond)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := h.SyncAll(ctx); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPublicSnapshot(b *testing.B) {
	ctx := context.Background()
	st := openBenchHubStore(b)
	h := NewHub(st, nil, WithPublicDebounce(10*time.Millisecond))
	b.Cleanup(func() { _ = h.Close() })

	for i := 0; i < 20; i++ {
		_, _ = createBenchNode(b, st, fmt.Sprintf("pub-node-%d", i), nil)
	}

	b.Run("UncachedBuildAndMarshal", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				snap, err := h.BuildPublicSnapshot(ctx)
				if err != nil {
					b.Fatal(err)
				}
				payload, err := json.Marshal(snap)
				if err != nil || len(payload) == 0 {
					b.Fatalf("marshal failed: %v", err)
				}
			}
		})
	})

	b.Run("CachedSingleflight", func(b *testing.B) {
		// Warm up once, then measure concurrent visitor handshakes hitting the shared payload cache.
		if _, err := h.GetPublicSnapshotJSON(ctx); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				payload, err := h.GetPublicSnapshotJSON(ctx)
				if err != nil || len(payload) == 0 {
					b.Fatalf("GetPublicSnapshotJSON failed: %v", err)
				}
			}
		})
	})
}
