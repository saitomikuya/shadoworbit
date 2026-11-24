//go:build e2e

package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func f11_waitConfigSync(t *testing.T, ctx context.Context, conn *websocket.Conn, timeout time.Duration, pred func(ServerConfigSyncPayload) bool, desc string) ServerConfigSyncPayload {
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

func f11_waitNodeState(t *testing.T, client *PanelClient, jwt string, nodeID int64, timeout time.Duration, pred func(NodeDTO) bool, desc string) NodeDTO {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last NodeDTO
	for time.Now().Before(deadline) {
		st, n, _, err := client.GetNode(jwt, nodeID)
		if err == nil && st == http.StatusOK {
			last = n
			if pred(n) {
				return n
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for node %d state (%s), last=%+v", nodeID, desc, last)
	return NodeDTO{}
}

func f11_sendMetricsAndDrain(t *testing.T, ctx context.Context, conn *websocket.Conn, rxDelta, txDelta uint64, userDeltas []UserTrafficDeltaDTO) {
	t.Helper()
	if err := SendWSEnvelope(ctx, conn, "agent.metrics", fmt.Sprintf("m-%d", time.Now().UnixNano()), AgentMetricsPayload{
		TS:         time.Now().Unix(),
		NicRxDelta: rxDelta,
		NicTxDelta: txDelta,
		UserDeltas: userDeltas,
		Health:     AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatalf("SendWSEnvelope(agent.metrics): %v", err)
	}
}

type f11_dailyLogRow struct {
	TargetType string
	TargetID   int64
	NodeID     int64
	UserID     int64
	Date       string
	RxBytes    int64
	TxBytes    int64
}

func f11_fetchDailyLogs(t *testing.T, client *PanelClient, jwt, query string) []f11_dailyLogRow {
	t.Helper()
	path := "/api/v1/admin/traffic/daily"
	if query != "" {
		path += "?" + strings.TrimPrefix(query, "?")
	}
	var rawRows []map[string]any
	st, raw, err := client.DoJSON(context.Background(), http.MethodGet, path, jwt, nil, &rawRows)
	if err != nil || st != http.StatusOK {
		t.Fatalf("GET %s failed: st=%d err=%v body=%s", path, st, err, string(raw))
	}

	toInt64 := func(v any) int64 {
		switch x := v.(type) {
		case float64:
			return int64(x)
		case int64:
			return x
		case int:
			return int64(x)
		default:
			return 0
		}
	}
	toStr := func(v any) string {
		s, _ := v.(string)
		return s
	}

	out := make([]f11_dailyLogRow, 0, len(rawRows))
	for _, m := range rawRows {
		row := f11_dailyLogRow{
			TargetType: toStr(m["target_type"]),
			TargetID:   toInt64(m["target_id"]),
			NodeID:     toInt64(m["node_id"]),
			UserID:     toInt64(m["user_id"]),
			Date:       toStr(m["date"]),
			RxBytes:    toInt64(m["rx_bytes"]),
			TxBytes:    toInt64(m["tx_bytes"]),
		}
		if row.Date == "" {
			row.Date = toStr(m["log_date"])
		}
		if row.TargetType == "node" && row.NodeID == 0 {
			row.NodeID = row.TargetID
		}
		if row.TargetType == "user" && row.UserID == 0 {
			row.UserID = row.TargetID
		}
		out = append(out, row)
	}
	return out
}

func TestF11_Tier1_TrafficCountModes(t *testing.T) {
	cases := []struct {
		name      string
		mode      string
		rx1, tx1  uint64
		wantUsed1 int64
		rx2, tx2  uint64
		wantUsed2 int64
		threshold int64
	}{
		{
			name: "both", mode: "both", threshold: 1000,
			rx1: 300, tx1: 600, wantUsed1: 900,
			rx2: 50, tx2: 50, wantUsed2: 1000,
		},
		{
			name: "tx_only", mode: "tx_only", threshold: 1000,
			rx1: 5000, tx1: 700, wantUsed1: 700,
			rx2: 0, tx2: 300, wantUsed2: 1000,
		},
		{
			name: "rx_only", mode: "rx_only", threshold: 1000,
			rx1: 300, tx1: 5000, wantUsed1: 300,
			rx2: 700, tx2: 0, wantUsed2: 1000,
		},
		{
			name: "max_dir_tx_dominant", mode: "max_dir", threshold: 1000,
			rx1: 800, tx1: 200, wantUsed1: 800,
			rx2: 100, tx2: 900, wantUsed2: 1100,
		},
		{
			name: "max_dir_rx_dominant", mode: "max_dir", threshold: 1000,
			rx1: 200, tx1: 800, wantUsed1: 800,
			rx2: 900, tx2: 100, wantUsed2: 1100,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := NewTestEnv(t)
			panel := StartPanel(env, PanelConfig{})
			client := panel.NewClient()
			jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

			_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
				Name:                  "Mode-" + tc.mode,
				Enabled:               boolPtr(true),
				TrafficLimitBytes:     2000,
				TrafficThresholdBytes: tc.threshold,
				TrafficCountMode:      tc.mode,
				ThresholdAction:       "stop_all",
				SnellConfig:           &SnellConfigDTO{Enabled: true, Version: "v5", PublicPort: 10001, InnerPort: 31001, PSK: "psk"},
				SSConfig:              &SSConfigDTO{Enabled: true, TCPPort: 10002, UDPPort: 10002, Cipher: "2022-blake3-aes-128-gcm", IPSK: "AAAAAAAAAAAAAAAAAAAAAA=="},
			})
			if err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			conn, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.CloseNow()

			_ = SendWSEnvelope(ctx, conn, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
			_ = f11_waitConfigSync(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool { return p.ConfigRevision >= 1 }, "hello sync")

			// Step 1: below threshold -> must NOT pause
			f11_sendMetricsAndDrain(t, ctx, conn, tc.rx1, tc.tx1, nil)
			n1 := f11_waitNodeState(t, client, jwt, node.ID, 5*time.Second, func(n NodeDTO) bool {
				return n.CycleRxBytes == int64(tc.rx1) && n.CycleTxBytes == int64(tc.tx1)
			}, "step1 deltas applied")
			if n1.IsTrafficPaused || n1.Status == "traffic_paused" {
				t.Fatalf("%s step1 should NOT be paused (used=%d < threshold=%d): %+v", tc.mode, tc.wantUsed1, tc.threshold, n1)
			}
			_, snap, _, err := client.GetPublicStatus()
			if err != nil || len(snap.Nodes) != 1 || snap.Nodes[0].TrafficUsedBytes != tc.wantUsed1 {
				t.Fatalf("%s step1 public TrafficUsedBytes want %d, got %+v (err=%v)", tc.mode, tc.wantUsed1, snap.Nodes, err)
			}

			// Step 2: reach threshold -> must pause
			f11_sendMetricsAndDrain(t, ctx, conn, tc.rx2, tc.tx2, nil)
			n2 := f11_waitNodeState(t, client, jwt, node.ID, 5*time.Second, func(n NodeDTO) bool {
				return n.IsTrafficPaused && n.Status == "traffic_paused"
			}, "step2 paused at threshold")
			if n2.CycleRxBytes != int64(tc.rx1+tc.rx2) || n2.CycleTxBytes != int64(tc.tx1+tc.tx2) {
				t.Fatalf("%s step2 counters mismatch: %+v", tc.mode, n2)
			}
		})
	}
}

func TestF11_Tier1_ThresholdActionStopAll(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:                  "StopAllNode",
		Enabled:               boolPtr(true),
		TrafficLimitBytes:     2000,
		TrafficThresholdBytes: 1000,
		TrafficCountMode:      "both",
		ThresholdAction:       "stop_all",
		SnellConfig:           &SnellConfigDTO{Enabled: true, Version: "v5", PublicPort: 11001, InnerPort: 31001, PSK: "psk"},
		SSConfig:              &SSConfigDTO{Enabled: true, TCPPort: 11002, UDPPort: 11002, Cipher: "2022-blake3-aes-128-gcm", IPSK: "AAAAAAAAAAAAAAAAAAAAAA=="},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := client.CreateUser(jwt, CreateUserReq{Username: "stopall_u", NodeIDs: []int64{node.ID}}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	_ = SendWSEnvelope(ctx, conn, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	f11_waitConfigSync(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		return p.Snell.Enabled && p.SS.Enabled && len(p.SS.Users) == 1
	}, "initial both enabled")

	f11_sendMetricsAndDrain(t, ctx, conn, 600, 500, nil) // 1100 >= 1000

	f11_waitConfigSync(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		return !p.Snell.Enabled && !p.SS.Enabled
	}, "stop_all disables both snell and ss")

	f11_waitNodeState(t, client, jwt, node.ID, 5*time.Second, func(n NodeDTO) bool {
		return n.IsTrafficPaused && n.Status == "traffic_paused"
	}, "node status traffic_paused")

	_, snap, _, err := client.GetPublicStatus()
	if err != nil || len(snap.Nodes) != 1 || snap.Nodes[0].Status != "traffic_paused" {
		t.Fatalf("expected public status traffic_paused, got %+v (err=%v)", snap.Nodes, err)
	}
}

func TestF11_Tier1_ThresholdActionStopSSOnly(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:                  "StopSSOnlyNode",
		Enabled:               boolPtr(true),
		TrafficLimitBytes:     2000,
		TrafficThresholdBytes: 1000,
		TrafficCountMode:      "both",
		ThresholdAction:       "stop_ss_only",
		SnellConfig:           &SnellConfigDTO{Enabled: true, Version: "v5", PublicPort: 12001, InnerPort: 31001, PSK: "psk"},
		SSConfig:              &SSConfigDTO{Enabled: true, TCPPort: 12002, UDPPort: 12002, Cipher: "2022-blake3-aes-128-gcm", IPSK: "AAAAAAAAAAAAAAAAAAAAAA=="},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := client.CreateUser(jwt, CreateUserReq{Username: "stopss_u", NodeIDs: []int64{node.ID}}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	_ = SendWSEnvelope(ctx, conn, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	f11_waitConfigSync(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		return p.Snell.Enabled && p.SS.Enabled
	}, "initial both enabled")

	f11_sendMetricsAndDrain(t, ctx, conn, 1000, 100, nil) // 1100 >= 1000

	f11_waitConfigSync(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		return p.Snell.Enabled && !p.SS.Enabled
	}, "stop_ss_only disables ss while preserving snell")

	f11_waitNodeState(t, client, jwt, node.ID, 5*time.Second, func(n NodeDTO) bool {
		return n.IsTrafficPaused && n.Status == "traffic_paused"
	}, "node marked traffic_paused")
}

func TestF11_Tier1_DailyTrafficLogAggregation(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{Name: "DailyLogNode", Enabled: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	_, user, _, err := client.CreateUser(jwt, CreateUserReq{Username: "daily_user", NodeIDs: []int64{node.ID}})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	_ = SendWSEnvelope(ctx, conn, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	_ = f11_waitConfigSync(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool { return p.ConfigRevision >= 1 }, "hello sync")

	f11_sendMetricsAndDrain(t, ctx, conn, 1000, 2000, []UserTrafficDeltaDTO{
		{Username: user.Username, UserID: user.ID, UpBytes: 300, DownBytes: 400},
	})
	f11_sendMetricsAndDrain(t, ctx, conn, 500, 250, []UserTrafficDeltaDTO{
		{Username: user.Username, UserID: user.ID, UpBytes: 100, DownBytes: 200},
	})

	f11_waitNodeState(t, client, jwt, node.ID, 5*time.Second, func(n NodeDTO) bool {
		return n.CycleRxBytes == 1500 && n.CycleTxBytes == 2250
	}, "node counters aggregated")

	// Query all daily traffic logs
	allRows := f11_fetchDailyLogs(t, client, jwt, "")
	var nodeRx, nodeTx, userRx, userTx int64
	var foundNode, foundUser bool
	for _, r := range allRows {
		if r.NodeID == node.ID && (r.TargetType == "" || r.TargetType == "node") {
			nodeRx += r.RxBytes
			nodeTx += r.TxBytes
			foundNode = true
		}
		if r.UserID == user.ID && (r.TargetType == "" || r.TargetType == "user") {
			userRx += r.RxBytes
			userTx += r.TxBytes
			foundUser = true
		}
	}
	if !foundNode || nodeRx != 1500 || nodeTx != 2250 {
		t.Fatalf("node daily traffic mismatch: found=%v rx=%d tx=%d rows=%+v", foundNode, nodeRx, nodeTx, allRows)
	}
	if !foundUser || userRx+userTx != 1000 {
		t.Fatalf("user daily traffic mismatch: found=%v rx=%d tx=%d rows=%+v", foundUser, userRx, userTx, allRows)
	}

	// Query with filter params and verify rows match the requested node_id & date
	today := time.Now().UTC().Format("2006-01-02")
	filteredNodeRows := f11_fetchDailyLogs(t, client, jwt, fmt.Sprintf("target_type=node&target_id=%d&from=%s&to=%s", node.ID, today, today))
	if len(filteredNodeRows) == 0 {
		t.Fatalf("expected non-empty filtered node daily logs for %s", today)
	}
	var filtRx, filtTx int64
	for _, r := range filteredNodeRows {
		if r.NodeID != node.ID || (r.TargetType != "" && r.TargetType != "node") || r.Date != today {
			t.Fatalf("filtered daily log row did not match node_id=%d date=%s: %+v", node.ID, today, r)
		}
		filtRx += r.RxBytes
		filtTx += r.TxBytes
	}
	if filtRx != 1500 || filtTx != 2250 {
		t.Fatalf("filtered node daily traffic mismatch: rx=%d tx=%d rows=%+v", filtRx, filtTx, filteredNodeRows)
	}
}

func TestF11_Tier1_ManualThresholdIncreaseAndResetUnpauseNode(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:                  "UnpauseNode",
		Enabled:               boolPtr(true),
		TrafficLimitBytes:     10000,
		TrafficThresholdBytes: 1000,
		TrafficCountMode:      "both",
		ThresholdAction:       "stop_all",
		BillingResetDay:       1,
		SnellConfig:           &SnellConfigDTO{Enabled: true, Version: "v5", PublicPort: 13001, InnerPort: 31001, PSK: "psk"},
		SSConfig:              &SSConfigDTO{Enabled: true, TCPPort: 13002, UDPPort: 13002, Cipher: "2022-blake3-aes-128-gcm", IPSK: "AAAAAAAAAAAAAAAAAAAAAA=="},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	_ = SendWSEnvelope(ctx, conn, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	_ = f11_waitConfigSync(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool { return p.Snell.Enabled && p.SS.Enabled }, "initial sync")

	// Pause at 1000
	f11_sendMetricsAndDrain(t, ctx, conn, 500, 500, nil)
	f11_waitConfigSync(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool { return !p.Snell.Enabled && !p.SS.Enabled }, "paused at 1000")

	// Part A: Increase threshold above current usage (1000 -> 5000) -> unpauses
	stUpd, _, rawUpd, err := client.UpdateNode(jwt, node.ID, CreateNodeReq{
		Name:                  "UnpauseNode",
		Enabled:               boolPtr(true),
		TrafficLimitBytes:     10000,
		TrafficThresholdBytes: 5000,
		TrafficCountMode:      "both",
		ThresholdAction:       "stop_all",
		BillingResetDay:       1,
		SnellConfig:           &SnellConfigDTO{Enabled: true, Version: "v5", PublicPort: 13001, InnerPort: 31001, PSK: "psk"},
		SSConfig:              &SSConfigDTO{Enabled: true, TCPPort: 13002, UDPPort: 13002, Cipher: "2022-blake3-aes-128-gcm", IPSK: "AAAAAAAAAAAAAAAAAAAAAA=="},
	})
	if err != nil || stUpd != http.StatusOK {
		t.Fatalf("UpdateNode increase threshold failed: st=%d err=%v body=%s", stUpd, err, string(rawUpd))
	}
	f11_waitConfigSync(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		return p.Snell.Enabled && p.SS.Enabled
	}, "re-enabled after threshold increase")
	f11_waitNodeState(t, client, jwt, node.ID, 5*time.Second, func(n NodeDTO) bool {
		return !n.IsTrafficPaused && n.Status == "online"
	}, "node online after threshold increase")

	// Part B: Cross new threshold 5000 -> pauses again; then reset-traffic -> unpauses and zeroes counters
	f11_sendMetricsAndDrain(t, ctx, conn, 2500, 2000, nil) // total = 5500 >= 5000
	f11_waitConfigSync(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool { return !p.Snell.Enabled && !p.SS.Enabled }, "paused at 5500")

	stRes, rawRes, err := client.ResetNodeTraffic(jwt, node.ID)
	if err != nil || stRes < 200 || stRes >= 300 {
		t.Fatalf("ResetNodeTraffic failed: st=%d err=%v body=%s", stRes, err, string(rawRes))
	}
	f11_waitConfigSync(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		return p.Snell.Enabled && p.SS.Enabled
	}, "re-enabled after reset-traffic")
	nReset := f11_waitNodeState(t, client, jwt, node.ID, 5*time.Second, func(n NodeDTO) bool {
		return !n.IsTrafficPaused && n.CycleRxBytes == 0 && n.CycleTxBytes == 0 && n.Status == "online"
	}, "node reset and online")
	if nReset.CycleRxBytes != 0 || nReset.CycleTxBytes != 0 {
		t.Fatalf("expected zeroed counters, got %+v", nReset)
	}
}

func TestF11_Tier2_BillingResetDay29_30_31_AndRestartPersistence(t *testing.T) {
	env := NewTestEnv(t)
	dbPath := filepath.Join(env.RootDir, "panel.db")
	panel := StartPanel(env, PanelConfig{DBPath: dbPath, TZ: "UTC"})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	// Multi-month Feb 28/29 and 30-day calendar rollover without a panel test-clock flag is
	// verified deterministically in internal/panel/scheduler unit tests. Here we verify
	// opaque-box CRUD, updates, SQLite restart durability, PublicNodeView propagation, and
	// 4xx validation across billing_reset_day values {1, 28, 29, 30, 31}.
	validDays := []int{1, 28, 29, 30, 31}
	nodeIDs := make(map[int]int64)
	userIDs := make(map[int]int64)
	for _, day := range validDays {
		st, n, raw, err := client.CreateNode(jwt, CreateNodeReq{
			Name:            fmt.Sprintf("ResetDay-%d", day),
			Enabled:         boolPtr(true),
			BillingResetDay: day,
		})
		if err != nil || (st != http.StatusOK && st != http.StatusCreated) {
			t.Fatalf("CreateNode(billing_reset_day=%d) failed: st=%d err=%v body=%s", day, st, err, string(raw))
		}
		if n.BillingResetDay != day {
			t.Fatalf("CreateNode(billing_reset_day=%d) returned %d", day, n.BillingResetDay)
		}
		nodeIDs[day] = n.ID

		stU, u, rawU, err := client.CreateUser(jwt, CreateUserReq{
			Username:        fmt.Sprintf("reset_day_%d_user", day),
			BillingResetDay: day,
		})
		if err != nil || (stU != http.StatusOK && stU != http.StatusCreated) {
			t.Fatalf("CreateUser(billing_reset_day=%d) failed: st=%d err=%v body=%s", day, stU, err, string(rawU))
		}
		if u.BillingResetDay != day {
			t.Fatalf("CreateUser(billing_reset_day=%d) returned %d", day, u.BillingResetDay)
		}
		userIDs[day] = u.ID
	}

	// Update node & user billing_reset_day (1 -> 29, then 29 -> 31, and back to 1)
	stUpdN, updN, rawUpdN, err := client.UpdateNode(jwt, nodeIDs[1], CreateNodeReq{
		Name:            "ResetDay-Updated",
		Enabled:         boolPtr(true),
		BillingResetDay: 29,
	})
	if err != nil || stUpdN != http.StatusOK || updN.BillingResetDay != 29 {
		t.Fatalf("UpdateNode(billing_reset_day=29) failed: st=%d n=%+v err=%v body=%s", stUpdN, updN, err, string(rawUpdN))
	}
	stUpdU, updU, rawUpdU, err := client.UpdateUser(jwt, userIDs[1], CreateUserReq{
		Username:        "reset_day_1_user",
		Enabled:         boolPtr(true),
		BillingResetDay: 30,
	})
	if err != nil || stUpdU != http.StatusOK || updU.BillingResetDay != 30 {
		t.Fatalf("UpdateUser(billing_reset_day=30) failed: st=%d u=%+v err=%v body=%s", stUpdU, updU, err, string(rawUpdU))
	}

	// Out-of-range billing_reset_day rejected on Create and Update (0, -1, 32 on nodes; -1, 32 on users)
	for _, badDay := range []int{-1, 32, 99} {
		stN, _, rawN, _ := client.CreateNode(jwt, CreateNodeReq{Name: "BadResetDay", BillingResetDay: badDay})
		if stN < 400 || stN >= 500 {
			t.Fatalf("CreateNode(billing_reset_day=%d) expected 4xx, got %d (body=%s)", badDay, stN, string(rawN))
		}
		stU, _, rawBadU, _ := client.CreateUser(jwt, CreateUserReq{Username: fmt.Sprintf("bad_u_%d", badDay), BillingResetDay: badDay})
		if stU < 400 || stU >= 500 {
			t.Fatalf("CreateUser(billing_reset_day=%d) expected 4xx, got %d (body=%s)", badDay, stU, string(rawBadU))
		}
	}
	for _, badDay := range []int{0, -1, 32} {
		stN, _, rawN, _ := client.UpdateNode(jwt, nodeIDs[28], map[string]any{
			"name":              "ResetDay-28",
			"enabled":           true,
			"billing_reset_day": badDay,
		})
		if stN < 400 || stN >= 500 {
			t.Fatalf("UpdateNode(billing_reset_day=%d) expected 4xx, got %d (body=%s)", badDay, stN, string(rawN))
		}
	}
	for _, badDay := range []int{-1, 32} {
		stU, _, rawU, _ := client.UpdateUser(jwt, userIDs[28], map[string]any{
			"username":          "reset_day_28_user",
			"enabled":           true,
			"billing_reset_day": badDay,
		})
		if stU < 400 || stU >= 500 {
			t.Fatalf("UpdateUser(billing_reset_day=%d) expected 4xx, got %d (body=%s)", badDay, stU, string(rawU))
		}
	}

	// Restart panel and verify SQLite durability & PublicNodeView propagation
	if err := panel.Stop(); err != nil {
		t.Fatal(err)
	}

	panel2 := StartPanel(env, PanelConfig{DBPath: dbPath, TZ: "UTC"})
	client2 := panel2.NewClient()
	jwt2 := client2.MustLogin(t, "admin", "change_me_on_first_login")

	expectedNodeDays := map[int64]int{
		nodeIDs[1]:  29,
		nodeIDs[28]: 28,
		nodeIDs[29]: 29,
		nodeIDs[30]: 30,
		nodeIDs[31]: 31,
	}
	for nid, wantDay := range expectedNodeDays {
		_, gotN, _, err := client2.GetNode(jwt2, nid)
		if err != nil || gotN.BillingResetDay != wantDay {
			t.Fatalf("node %d billing_reset_day=%d did not persist across restart: %+v err=%v", nid, wantDay, gotN, err)
		}
	}
	expectedUserDays := map[int64]int{
		userIDs[1]:  30,
		userIDs[28]: 28,
		userIDs[29]: 29,
		userIDs[30]: 30,
		userIDs[31]: 31,
	}
	for uid, wantDay := range expectedUserDays {
		_, gotU, _, err := client2.GetUser(jwt2, uid)
		if err != nil || gotU.BillingResetDay != wantDay {
			t.Fatalf("user %d billing_reset_day=%d did not persist across restart: %+v err=%v", uid, wantDay, gotU, err)
		}
	}

	_, pubSnap, _, err := client2.GetPublicStatus()
	if err != nil {
		t.Fatal(err)
	}
	pubDays := map[int64]int{}
	for _, pn := range pubSnap.Nodes {
		pubDays[pn.ID] = pn.BillingResetDay
	}
	for nid, wantDay := range expectedNodeDays {
		if pubDays[nid] != wantDay {
			t.Fatalf("PublicNodeView.BillingResetDay for node %d mismatch: got %d want %d", nid, pubDays[nid], wantDay)
		}
	}
}

func TestF11_Tier2_UserBillingResetDayZeroDisablesAutoReset(t *testing.T) {
	env := NewTestEnv(t)
	dbPath := filepath.Join(env.RootDir, "panel.db")
	panel := StartPanel(env, PanelConfig{DBPath: dbPath, TZ: "UTC"})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{Name: "NoResetNode", Enabled: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}

	var user UserDTO
	st, raw, err := client.DoJSON(context.Background(), http.MethodPost, "/api/v1/admin/users", jwt, map[string]any{
		"username":          "no_auto_reset_user",
		"billing_reset_day": 0,
		"node_ids":          []int64{node.ID},
	}, &user)
	if err != nil || (st != http.StatusOK && st != http.StatusCreated) {
		t.Fatalf("CreateUser(billing_reset_day=0) failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	if user.BillingResetDay != 0 {
		t.Fatalf("expected billing_reset_day=0, got %d (body=%s)", user.BillingResetDay, string(raw))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	_ = SendWSEnvelope(ctx, conn, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	_ = f11_waitConfigSync(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool { return p.ConfigRevision >= 1 }, "hello sync")
	f11_sendMetricsAndDrain(t, ctx, conn, 0, 0, []UserTrafficDeltaDTO{
		{Username: user.Username, UserID: user.ID, UpBytes: 1234, DownBytes: 5678},
	})

	deadline := time.Now().Add(5 * time.Second)
	persisted := false
	for time.Now().Before(deadline) {
		_, gotU, _, _ := client.GetUser(jwt, user.ID)
		if gotU.UsedUpBytes == 1234 && gotU.UsedDownBytes == 5678 {
			persisted = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !persisted {
		_, gotU, _, _ := client.GetUser(jwt, user.ID)
		t.Fatalf("timed out waiting for user traffic (1234, 5678) to persist, last=%+v", gotU)
	}
	_ = conn.CloseNow()

	if err := panel.Stop(); err != nil {
		t.Fatal(err)
	}

	panel2 := StartPanel(env, PanelConfig{DBPath: dbPath, TZ: "UTC"})
	client2 := panel2.NewClient()
	jwt2 := client2.MustLogin(t, "admin", "change_me_on_first_login")

	// Allow scheduler startup pass to run, then verify user usage was NOT auto-reset
	time.Sleep(500 * time.Millisecond)
	_, gotAfter, _, err := client2.GetUser(jwt2, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotAfter.BillingResetDay != 0 || gotAfter.UsedUpBytes != 1234 || gotAfter.UsedDownBytes != 5678 {
		t.Fatalf("user with billing_reset_day=0 altered across restart: %+v", gotAfter)
	}
}

func TestF11_Tier2_ExactThresholdBoundaryUsedVsThresholdMinusOne(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:                  "ExactBoundaryNode",
		Enabled:               boolPtr(true),
		TrafficLimitBytes:     2000,
		TrafficThresholdBytes: 1000,
		TrafficCountMode:      "both",
		ThresholdAction:       "stop_all",
		SnellConfig:           &SnellConfigDTO{Enabled: true, Version: "v5", PublicPort: 14001, InnerPort: 31001, PSK: "psk"},
		SSConfig:              &SSConfigDTO{Enabled: true, TCPPort: 14002, UDPPort: 14002, Cipher: "2022-blake3-aes-128-gcm", IPSK: "AAAAAAAAAAAAAAAAAAAAAA=="},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	_ = SendWSEnvelope(ctx, conn, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	_ = f11_waitConfigSync(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool { return p.Snell.Enabled && p.SS.Enabled }, "initial sync")

	// used = 999 == threshold - 1 -> stays online & unpaused
	f11_sendMetricsAndDrain(t, ctx, conn, 500, 499, nil)
	nBefore := f11_waitNodeState(t, client, jwt, node.ID, 5*time.Second, func(n NodeDTO) bool {
		return n.CycleRxBytes == 500 && n.CycleTxBytes == 499
	}, "used == threshold - 1")
	if nBefore.IsTrafficPaused || nBefore.Status != "online" {
		t.Fatalf("expected node online and unpaused at threshold-1 (999), got %+v", nBefore)
	}

	// +1 byte -> used == 1000 == threshold -> pauses
	f11_sendMetricsAndDrain(t, ctx, conn, 1, 0, nil)
	f11_waitConfigSync(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		return !p.Snell.Enabled && !p.SS.Enabled
	}, "paused at exact threshold 1000")
	f11_waitNodeState(t, client, jwt, node.ID, 5*time.Second, func(n NodeDTO) bool {
		return n.IsTrafficPaused && n.Status == "traffic_paused"
	}, "node status traffic_paused at 1000")
}

func TestF11_Tier2_WarningThresholdBeforePause(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	hookSrv := StartMockWebhookServer(t)
	stWH, _, rawWH, err := client.CreateWebhook(jwt, WebhookChannelDTO{
		Name:             "TrafficAlertsHook",
		Provider:         "custom",
		URL:              hookSrv.URL(),
		SubscribedEvents: []string{"traffic_warning", "traffic_paused"},
		Enabled:          true,
	})
	if err != nil || (stWH != http.StatusOK && stWH != http.StatusCreated) {
		t.Fatalf("CreateWebhook failed: st=%d err=%v body=%s", stWH, err, string(rawWH))
	}

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:                  "WarningNode",
		Enabled:               boolPtr(true),
		TrafficLimitBytes:     2000,
		TrafficThresholdBytes: 1000,
		TrafficCountMode:      "both",
		ThresholdAction:       "stop_all",
		SnellConfig:           &SnellConfigDTO{Enabled: true, Version: "v5", PublicPort: 15001, InnerPort: 31001, PSK: "psk"},
		SSConfig:              &SSConfigDTO{Enabled: true, TCPPort: 15002, UDPPort: 15002, Cipher: "2022-blake3-aes-128-gcm", IPSK: "AAAAAAAAAAAAAAAAAAAAAA=="},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	_ = SendWSEnvelope(ctx, conn, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	_ = f11_waitConfigSync(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool { return p.ConfigRevision >= 1 }, "hello sync")

	type f11WebhookPayload struct {
		Type       string `json:"type"`
		TargetType string `json:"target_type"`
		TargetName string `json:"target_name"`
		Resolved   bool   `json:"resolved"`
	}

	// Cross 85% warning threshold (850 / 1000) without crossing 100%
	f11_sendMetricsAndDrain(t, ctx, conn, 500, 350, nil)
	reqs1, ok1 := hookSrv.WaitForRequests(1, 5*time.Second)
	if !ok1 {
		t.Fatalf("expected traffic_warning webhook request at 85%% threshold, got %d requests", len(reqs1))
	}
	var p1 f11WebhookPayload
	if err := json.Unmarshal([]byte(reqs1[0].Body), &p1); err != nil {
		t.Fatalf("unmarshal warning webhook payload %q: %v", reqs1[0].Body, err)
	}
	if p1.Type != "traffic_warning" || p1.TargetName != "WarningNode" || p1.TargetType != "node" || p1.Resolved {
		t.Fatalf("unexpected warning webhook payload %+v (raw=%s)", p1, reqs1[0].Body)
	}
	nWarn := f11_waitNodeState(t, client, jwt, node.ID, 5*time.Second, func(n NodeDTO) bool {
		return n.CycleRxBytes == 500 && n.CycleTxBytes == 350
	}, "warning state recorded")
	if nWarn.IsTrafficPaused || nWarn.Status != "online" {
		t.Fatalf("expected node to stay online at warning threshold, got %+v", nWarn)
	}

	// Cross 100% pause threshold (850 + 150 = 1000)
	f11_sendMetricsAndDrain(t, ctx, conn, 150, 0, nil)
	reqs2, ok2 := hookSrv.WaitForRequests(2, 5*time.Second)
	if !ok2 {
		t.Fatalf("expected traffic_paused webhook request at 100%% threshold, got %d requests", len(reqs2))
	}
	var p2 f11WebhookPayload
	if err := json.Unmarshal([]byte(reqs2[1].Body), &p2); err != nil {
		t.Fatalf("unmarshal paused webhook payload %q: %v", reqs2[1].Body, err)
	}
	if p2.Type != "traffic_paused" || p2.TargetName != "WarningNode" || p2.TargetType != "node" || p2.Resolved {
		t.Fatalf("unexpected paused webhook payload %+v (raw=%s)", p2, reqs2[1].Body)
	}
	f11_waitNodeState(t, client, jwt, node.ID, 5*time.Second, func(n NodeDTO) bool {
		return n.IsTrafficPaused && n.Status == "traffic_paused"
	}, "node paused at 100%")
}

func TestF11_Tier2_ZeroTrafficLimitAndThresholdUnlimited(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:                  "UnlimitedNode",
		Enabled:               boolPtr(true),
		TrafficLimitBytes:     0,
		TrafficThresholdBytes: 0,
		TrafficCountMode:      "both",
		SnellConfig:           &SnellConfigDTO{Enabled: true, Version: "v5", PublicPort: 16001, InnerPort: 31001, PSK: "psk"},
		SSConfig:              &SSConfigDTO{Enabled: true, TCPPort: 16002, UDPPort: 16002, Cipher: "2022-blake3-aes-128-gcm", IPSK: "AAAAAAAAAAAAAAAAAAAAAA=="},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	_ = SendWSEnvelope(ctx, conn, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	_ = f11_waitConfigSync(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool { return p.ConfigRevision >= 1 }, "hello sync")

	f11_sendMetricsAndDrain(t, ctx, conn, 100<<30, 200<<30, nil)
	n := f11_waitNodeState(t, client, jwt, node.ID, 5*time.Second, func(n NodeDTO) bool {
		return n.CycleRxBytes == 100<<30 && n.CycleTxBytes == 200<<30
	}, "large unlimited deltas recorded")
	if n.IsTrafficPaused || n.Status != "online" {
		t.Fatalf("unlimited node must never pause, got %+v", n)
	}

	if st, raw, err := client.SyncNode(jwt, node.ID); err != nil || st >= 300 {
		t.Fatalf("SyncNode failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	f11_waitConfigSync(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		return p.Snell.Enabled && p.SS.Enabled
	}, "unlimited node keeps both services enabled")
}
