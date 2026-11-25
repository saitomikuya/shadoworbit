package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"snell-panel/internal/protocol"
)

func openBenchStore(b *testing.B) *Store {
	b.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(b.TempDir(), "bench.db")
	s, err := Open(ctx, dbPath)
	if err != nil {
		b.Fatalf("Open(%q) failed: %v", dbPath, err)
	}
	b.Cleanup(func() {
		_ = s.Close()
	})
	return s
}

func BenchmarkApplyTrafficDeltasAt(b *testing.B) {
	for _, userCount := range []int{1, 10, 50, 100} {
		b.Run(fmt.Sprintf("users=%d", userCount), func(b *testing.B) {
			ctx := context.Background()
			s := openBenchStore(b)

			node := &Node{
				Name:      "bench-node",
				RegionTag: "SG",
				TokenHash: "hash_bench_node",
				Enabled:   true,
			}
			if err := s.CreateNode(ctx, node); err != nil {
				b.Fatal(err)
			}

			deltas := make([]protocol.UserTrafficDelta, 0, userCount)
			for i := 1; i <= userCount; i++ {
				u := &User{
					Username:        fmt.Sprintf("bench_user_%03d", i),
					Enabled:         true,
					SubToken:        fmt.Sprintf("sub_bench_%03d", i),
					SSUPSK16:        "AAAAAAAAAAAAAAAAAAAAAA==",
					SSUPSK32:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
					STLSPassword:    "pw",
					BillingResetDay: 1,
				}
				if err := s.CreateUser(ctx, u); err != nil {
					b.Fatal(err)
				}
				deltas = append(deltas, protocol.UserTrafficDelta{
					UserID:    u.ID,
					Username:  u.Username,
					UpBytes:   1024,
					DownBytes: 2048,
				})
			}

			// Seed 10,000 rows in traffic_usage_logs so any inline OFFSET 9999 prune cost is faithfully measured.
			if err := s.SetSetting(ctx, "traffic_log_max_entries", "10000"); err != nil {
				b.Fatal(err)
			}
			seedStmt, err := s.DB().PrepareContext(ctx, `
INSERT INTO traffic_usage_logs(node_id, user_id, log_minute, rx_bytes, tx_bytes, updated_at)
VALUES (?, ?, ?, ?, ?, ?)`)
			if err != nil {
				b.Fatal(err)
			}
			baseTime := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
			tx, err := s.DB().BeginTx(ctx, nil)
			if err != nil {
				b.Fatal(err)
			}
			txStmt := tx.StmtContext(ctx, seedStmt)
			for i := 0; i < 10000; i++ {
				ts := baseTime.Add(time.Duration(i) * time.Minute)
				minStr := ts.Format("2006-01-02T15:04:00Z")
				if _, err := txStmt.ExecContext(ctx, node.ID, deltas[0].UserID, minStr, 100, 100, minStr); err != nil {
					_ = tx.Rollback()
					b.Fatal(err)
				}
			}
			if err := tx.Commit(); err != nil {
				b.Fatal(err)
			}
			_ = seedStmt.Close()

			applyStart := baseTime.Add(20000 * time.Minute)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				ts := applyStart.Add(time.Duration(i) * 5 * time.Second)
				if _, err := s.ApplyTrafficDeltasAt(ctx, node.ID, 4096, 8192, deltas, ts); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkQueryTrafficUsageLogs_Merge(b *testing.B) {
	for _, totalRows := range []int{1000, 10000, 50000} {
		b.Run(fmt.Sprintf("rows=%d", totalRows), func(b *testing.B) {
			ctx := context.Background()
			s := openBenchStore(b)

			node := &Node{
				Name:      "bench-query-node",
				RegionTag: "JP",
				TokenHash: "hash_bench_query",
				Enabled:   true,
			}
			if err := s.CreateNode(ctx, node); err != nil {
				b.Fatal(err)
			}
			var userIDs []int64
			for uIdx := 0; uIdx < 5; uIdx++ {
				u := &User{
					Username:        fmt.Sprintf("q_user_%d", uIdx),
					Enabled:         true,
					SubToken:        fmt.Sprintf("q_sub_%d", uIdx),
					SSUPSK16:        "AAAAAAAAAAAAAAAAAAAAAA==",
					SSUPSK32:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
					STLSPassword:    "pw",
					BillingResetDay: 1,
				}
				if err := s.CreateUser(ctx, u); err != nil {
					b.Fatal(err)
				}
				userIDs = append(userIDs, u.ID)
			}

			tx, err := s.DB().BeginTx(ctx, nil)
			if err != nil {
				b.Fatal(err)
			}
			stmt, err := tx.PrepareContext(ctx, `
INSERT INTO traffic_usage_logs(node_id, user_id, log_minute, rx_bytes, tx_bytes, updated_at)
VALUES (?, ?, ?, ?, ?, ?)`)
			if err != nil {
				b.Fatal(err)
			}
			baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			for i := 0; i < totalRows; i++ {
				uid := userIDs[i%len(userIDs)]
				// Create sessions of ~15 minutes separated by 10-minute gaps
				sessionIdx := i / (15 * len(userIDs))
				minuteInSession := (i / len(userIDs)) % 15
				ts := baseTime.Add(time.Duration(sessionIdx*25+minuteInSession) * time.Minute)
				minStr := ts.Format("2006-01-02T15:04:00Z")
				if _, err := stmt.ExecContext(ctx, node.ID, uid, minStr, 1024, 512, minStr); err != nil {
					_ = tx.Rollback()
					b.Fatal(err)
				}
			}
			_ = stmt.Close()
			if err := tx.Commit(); err != nil {
				b.Fatal(err)
			}

			filter := TrafficUsageLogFilter{
				Limit:           500,
				Merge:           true,
				MergeGapMinutes: 5,
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				res, err := s.QueryTrafficUsageLogs(ctx, filter)
				if err != nil {
					b.Fatal(err)
				}
				if len(res) == 0 {
					b.Fatal("expected non-empty merged logs")
				}
			}
		})
	}
}
