package scheduler

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"snell-panel/internal/panel/dnsprovider"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/panel/webhook"
	"snell-panel/internal/protocol"
)

type fakeDNSProvider struct {
	mu      sync.Mutex
	zones   []dnsprovider.Zone
	records []dnsprovider.DesiredRecord
	calls   int
}

func (f *fakeDNSProvider) ListPublicZones(_ context.Context) ([]dnsprovider.Zone, error) {
	return f.zones, nil
}

func (f *fakeDNSProvider) ListRecordSets(_ context.Context, _, _, _ string) ([]dnsprovider.RecordSet, error) {
	return nil, nil
}

func (f *fakeDNSProvider) SyncARecords(_ context.Context, _, _ string, _ int, _ bool, desired []dnsprovider.DesiredRecord) ([]dnsprovider.SyncedRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.records = append([]dnsprovider.DesiredRecord(nil), desired...)
	out := make([]dnsprovider.SyncedRecord, 0, len(desired))
	for _, d := range desired {
		out = append(out, dnsprovider.SyncedRecord{
			IP:          d.IP,
			Weight:      d.Weight,
			RecordSetID: "rs-" + d.IP,
		})
	}
	return out, nil
}

func (f *fakeDNSProvider) currentIPs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.records))
	for i, r := range f.records {
		out[i] = r.IP
	}
	return out
}

func openLBTestStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "lb.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.SetSettingsBatch(ctx, map[string]string{
		SettingHuaweiCloudDNSEndpoint: dnsprovider.DefaultHuaweiCloudEndpoint,
		SettingHuaweiCloudDNSAK:       "ak-test",
		SettingHuaweiCloudDNSSK:       "sk-test",
	}); err != nil {
		t.Fatal(err)
	}
	return st
}

func mustCreateLBNode(t *testing.T, st *store.Store, name, tok, ip string, limitBytes, thresholdBytes, cycleRx int64) *store.Node {
	t.Helper()
	n := &store.Node{
		Name:                  name,
		TokenHash:             tok,
		Enabled:               true,
		Status:                protocol.NodeStatusOnline,
		PublicIP:              ip,
		CoreAHealthy:          true,
		CoreBHealthy:          true,
		TrafficLimitBytes:     limitBytes,
		TrafficThresholdBytes: thresholdBytes,
		TrafficCountMode:      protocol.TrafficCountBoth,
		ThresholdAction:       protocol.ThresholdActionStopAll,
		CycleRxBytes:          cycleRx,
		SnellConfig: protocol.SnellConfig{
			Enabled: true, Version: protocol.SnellVersionV5, PublicPort: 18443, InnerPort: 18444 + int(len(name)),
			PSK: "psk", STLSPassword: "stls", STLSSNI: "gateway.icloud.com",
		},
		SSConfig: protocol.SSConfig{
			Enabled: true, TCPPort: 28443, UDPPort: 28444, Cipher: protocol.CipherAES128GCM,
			IPSK: "AAAAAAAAAAAAAAAAAAAAAA==", STLSSNI: "swdist.apple.com",
		},
	}
	if err := st.CreateNode(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestLBSchedulerRemainingBalanceFailoverAndPin(t *testing.T) {
	ctx := context.Background()
	st := openLBTestStore(t)

	const g200 = 200 << 30
	const g190 = 190 << 30
	n1 := mustCreateLBNode(t, st, "Ali-1", "t1", "1.1.1.1", g200, g190, 20<<30)
	n2 := mustCreateLBNode(t, st, "Ali-2", "t2", "2.2.2.2", g200, g190, 25<<30)

	// Confirm threshold takes precedence over limit for NodeEffectiveBudget.
	rem1, hasBudget1, _, budget1 := NodeRemainingTraffic(n1)
	if !hasBudget1 || budget1 != g190 || rem1 != g190-(20<<30) {
		t.Fatalf("unexpected budget calculation: has=%v budget=%d rem=%d", hasBudget1, budget1, rem1)
	}

	grp := &store.LBGroup{
		Name:                     "Aliyun-LB",
		Enabled:                  true,
		DNSZoneID:                "z1",
		DNSZoneName:              "example.com",
		DNSDomain:                "ali.example.com",
		DNSTTL:                   60,
		Strategy:                 protocol.LBStrategyRemainingBalance,
		SwitchDiffBytes:          10 << 30,
		SwitchCooldownMinutes:    10,
		FailoverThresholdPercent: 90,
		SnellConfig:              n1.SnellConfig,
		SSConfig:                 n1.SSConfig,
	}
	if _, err := st.CreateLBGroup(ctx, grp, []int64{n1.ID, n2.ID}); err != nil {
		t.Fatal(err)
	}

	fakeDNS := &fakeDNSProvider{}
	var mu sync.Mutex
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	var events []webhook.AlertEvent
	notifier := &lbTestNotifier{fn: func(e webhook.AlertEvent) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}}

	sched := NewScheduler(st, nil, notifier,
		WithNow(func() time.Time { return now }),
		WithDNSProviderFactory(func(_, _, _ string) (dnsprovider.Provider, error) { return fakeDNS, nil }),
	)

	// 1. Initial pick -> Ali-1 (170G remaining vs 165G).
	res, err := sched.EvaluateLBGroup(ctx, grp.ID, LBEvalOptions{ForceSync: true})
	if err != nil {
		t.Fatalf("initial eval failed: %v", err)
	}
	if res.ActiveNodeID == nil || *res.ActiveNodeID != n1.ID || fakeDNS.currentIPs()[0] != "1.1.1.1" {
		t.Fatalf("expected Ali-1 active, got %+v ips=%v", res.ActiveNodeID, fakeDNS.currentIPs())
	}

	// 2. Ali-1 consumes 12G more (now 158G remaining; Ali-2 leads by 7G < 10G diff) -> stays on Ali-1.
	if err := st.CalibrateNodeTraffic(ctx, n1.ID, 32<<30, 0); err != nil {
		t.Fatal(err)
	}
	res, err = sched.EvaluateLBGroup(ctx, grp.ID, LBEvalOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if *res.ActiveNodeID != n1.ID {
		t.Fatalf("expected Ali-1 retained within diff threshold, got %d", *res.ActiveNodeID)
	}

	// 3. Ali-1 consumes more so Ali-2 leads by 15G, but still within 10m cooldown -> stays on Ali-1.
	if err := st.CalibrateNodeTraffic(ctx, n1.ID, 40<<30, 0); err != nil {
		t.Fatal(err)
	}
	now = now.Add(5 * time.Minute)
	res, err = sched.EvaluateLBGroup(ctx, grp.ID, LBEvalOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if *res.ActiveNodeID != n1.ID {
		t.Fatalf("expected Ali-1 retained during cooldown, got %d", *res.ActiveNodeID)
	}

	// 4. Advance past 10m cooldown -> switches to Ali-2 and fires EventDNSLBSwitched.
	now = now.Add(6 * time.Minute)
	res, err = sched.EvaluateLBGroup(ctx, grp.ID, LBEvalOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if *res.ActiveNodeID != n2.ID || fakeDNS.currentIPs()[0] != "2.2.2.2" {
		t.Fatalf("expected switch to Ali-2, got %d ips=%v", *res.ActiveNodeID, fakeDNS.currentIPs())
	}

	// 5. Ali-2 goes offline -> immediate failover back to Ali-1 (bypassing cooldown!).
	if err := st.SetNodeConnectionStatus(ctx, n2.ID, false, time.Time{}); err != nil {
		t.Fatal(err)
	}
	res, err = sched.EvaluateLBGroup(ctx, grp.ID, LBEvalOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if *res.ActiveNodeID != n1.ID || fakeDNS.currentIPs()[0] != "1.1.1.1" {
		t.Fatalf("expected immediate failover to Ali-1, got %d ips=%v", *res.ActiveNodeID, fakeDNS.currentIPs())
	}

	// 6. Both offline -> exhausted alert fired once, existing DNS preserved.
	if err := st.SetNodeConnectionStatus(ctx, n1.ID, false, time.Time{}); err != nil {
		t.Fatal(err)
	}
	res, err = sched.EvaluateLBGroup(ctx, grp.ID, LBEvalOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsExhausted || fakeDNS.currentIPs()[0] != "1.1.1.1" {
		t.Fatalf("expected exhausted=true and DNS preserved, got exhausted=%v ips=%v", res.IsExhausted, fakeDNS.currentIPs())
	}

	// 7. Manual pin to Ali-2 overrides even if offline (uses known PublicIP) and clears exhausted.
	if err := st.SetLBGroupPinnedNode(ctx, grp.ID, &n2.ID); err != nil {
		t.Fatal(err)
	}
	res, err = sched.EvaluateLBGroup(ctx, grp.ID, LBEvalOptions{ForceSync: true})
	if err != nil {
		t.Fatal(err)
	}
	if *res.ActiveNodeID != n2.ID || fakeDNS.currentIPs()[0] != "2.2.2.2" || res.IsExhausted {
		t.Fatalf("expected pinned Ali-2 active, got active=%v ips=%v exhausted=%v", res.ActiveNodeID, fakeDNS.currentIPs(), res.IsExhausted)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(events) < 3 {
		t.Fatalf("expected switch/failover/exhausted/recovered webhook events, got %d: %+v", len(events), events)
	}
}

func TestLBSchedulerWeightedMulti(t *testing.T) {
	ctx := context.Background()
	st := openLBTestStore(t)

	const g200 = 200 << 30
	n1 := mustCreateLBNode(t, st, "Ali-1", "w1", "1.1.1.1", g200, 0, 50<<30)  // 150G rem
	n2 := mustCreateLBNode(t, st, "Ali-2", "w2", "2.2.2.2", g200, 0, 150<<30) // 50G rem

	grp := &store.LBGroup{
		Name:        "Weighted-LB",
		Enabled:     true,
		DNSZoneID:   "z1",
		DNSDomain:   "w.example.com",
		DNSTTL:      60,
		Strategy:    protocol.LBStrategyWeightedMulti,
		SnellConfig: n1.SnellConfig,
		SSConfig:    n1.SSConfig,
	}
	if _, err := st.CreateLBGroup(ctx, grp, []int64{n1.ID, n2.ID}); err != nil {
		t.Fatal(err)
	}

	fakeDNS := &fakeDNSProvider{}
	sched := NewScheduler(st, nil, nil,
		WithDNSProviderFactory(func(_, _, _ string) (dnsprovider.Provider, error) { return fakeDNS, nil }),
	)

	res, err := sched.EvaluateLBGroup(ctx, grp.ID, LBEvalOptions{ForceSync: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ActiveRecords) != 2 || res.ActiveRecords[0].Weight != 75 || res.ActiveRecords[1].Weight != 25 {
		t.Fatalf("expected 75/25 weights, got %+v", res.ActiveRecords)
	}
}

type lbTestNotifier struct {
	fn func(webhook.AlertEvent)
}

func (n *lbTestNotifier) Notify(_ context.Context, evt webhook.AlertEvent) {
	if n.fn != nil {
		n.fn(evt)
	}
}
