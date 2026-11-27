package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"snell-panel/internal/protocol"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "panel.db")
	s, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open(%q) failed: %v", dbPath, err)
	}
	t.Cleanup(func() {
		_ = s.Close()
	})
	return s
}

func TestOpenAndPragmas(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "sub", "panel.db")

	s, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open file db failed: %v", err)
	}

	var jm string
	if err := s.DB().QueryRowContext(ctx, `PRAGMA journal_mode;`).Scan(&jm); err != nil {
		t.Fatal(err)
	}
	if jm != "wal" {
		t.Fatalf("expected journal_mode=wal, got %q", jm)
	}

	var fk int
	if err := s.DB().QueryRowContext(ctx, `PRAGMA foreign_keys;`).Scan(&fk); err != nil {
		t.Fatal(err)
	}
	if fk != 1 {
		t.Fatalf("expected foreign_keys=1, got %d", fk)
	}

	var bt int
	if err := s.DB().QueryRowContext(ctx, `PRAGMA busy_timeout;`).Scan(&bt); err != nil {
		t.Fatal(err)
	}
	if bt < 5000 {
		t.Fatalf("expected busy_timeout>=5000, got %d", bt)
	}

	if err := s.SetSetting(ctx, "persist_key", "persist_val"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("re-open file db failed: %v", err)
	}
	defer s2.Close()

	got, err := s2.GetSetting(ctx, "persist_key")
	if err != nil {
		t.Fatalf("GetSetting after reopen failed: %v", err)
	}
	if got != "persist_val" {
		t.Fatalf("expected persist_val, got %q", got)
	}

	mem, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open(:memory:) failed: %v", err)
	}
	defer mem.Close()
	if err := mem.DB().QueryRowContext(ctx, `PRAGMA foreign_keys;`).Scan(&fk); err != nil {
		t.Fatal(err)
	}
	if fk != 1 {
		t.Fatalf("expected memory foreign_keys=1, got %d", fk)
	}
}

func TestMigrateIdempotent(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	for i := 0; i < 3; i++ {
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("Migrate iteration %d failed: %v", i, err)
		}
	}

	var migCount int
	if err := s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&migCount); err != nil {
		t.Fatal(err)
	}
	if migCount != len(migrations) {
		t.Fatalf("expected %d migrations recorded, got %d", len(migrations), migCount)
	}

	expectedTables := []string{
		"schema_migrations", "dns_rule_groups", "nodes", "users",
		"user_node_access", "user_node_traffic", "traffic_logs_daily",
		"sub_templates", "webhook_channels", "system_settings",
	}
	for _, tbl := range expectedTables {
		var name string
		err := s.DB().QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name = ?`, tbl).Scan(&name)
		if err != nil {
			t.Fatalf("expected table %q to exist: %v", tbl, err)
		}
	}
}

func TestForeignKeyEnforcement(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	// Invalid user_id / node_id rejected in user_node_access.
	if err := s.SetUserNodes(ctx, 9999, []int64{1}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for unknown user, got %v", err)
	}

	u := &User{
		Username:     "fk_user",
		Enabled:      true,
		SubToken:     "sub_fk_1",
		SSUPSK16:     "AAAAAAAAAAAAAAAAAAAAAA==",
		SSUPSK32:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		STLSPassword: "stls_pwd_fk",
	}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserNodes(ctx, u.ID, []int64{9999}); !errors.Is(err, ErrForeignKey) {
		t.Fatalf("expected ErrForeignKey for unknown node_id, got %v", err)
	}

	// Invalid dns_rule_group_id rejected on node creation.
	badGroupID := int64(9999)
	badNode := &Node{
		Name:           "bad-fk-node",
		TokenHash:      "hash_bad_fk",
		DNSRuleGroupID: &badGroupID,
	}
	if err := s.CreateNode(ctx, badNode); !errors.Is(err, ErrForeignKey) {
		t.Fatalf("expected ErrForeignKey for unknown dns_rule_group_id, got %v", err)
	}

	// Valid group + node -> deleting group sets dns_rule_group_id = NULL without deleting node.
	grp := &DNSRuleGroup{Name: "Streaming", Rules: []string{"netflix.com"}}
	if err := s.CreateDNSRuleGroup(ctx, grp); err != nil {
		t.Fatal(err)
	}
	n := &Node{
		Name:           "hk-fk",
		TokenHash:      "hash_fk_valid",
		Enabled:        true,
		DNSRuleGroupID: &grp.ID,
	}
	if err := s.CreateNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserNodes(ctx, u.ID, []int64{n.ID}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDNSRuleGroup(ctx, grp.ID); err != nil {
		t.Fatal(err)
	}
	gotNode, err := s.GetNodeByID(ctx, n.ID)
	if err != nil {
		t.Fatalf("node should survive DNS group deletion: %v", err)
	}
	if gotNode.DNSRuleGroupID != nil {
		t.Fatalf("expected dns_rule_group_id to be nil after group delete, got %v", *gotNode.DNSRuleGroupID)
	}

	// Deleting node cascades user_node_access.
	if err := s.DeleteNode(ctx, n.ID); err != nil {
		t.Fatal(err)
	}
	ids, err := s.GetUserNodeIDs(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected cascaded delete in user_node_access, got %v", ids)
	}
}

func TestSeedDefaultsIdempotent(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	if err := s.SeedDefaults(ctx, SeedConfig{
		AdminInitialPass: "s3cretPass!",
	}); err != nil {
		t.Fatalf("SeedDefaults failed: %v", err)
	}

	passHash, err := s.GetSetting(ctx, "admin_password_hash")
	if err != nil {
		t.Fatal(err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passHash), []byte("s3cretPass!")); err != nil {
		t.Fatalf("seeded password hash did not verify: %v", err)
	}
	adminSub, err := s.GetSetting(ctx, "admin_sub_token")
	if err != nil || len(adminSub) < 32 {
		t.Fatalf("unexpected admin_sub_token: %q, err=%v", adminSub, err)
	}
	jwtSecret, err := s.GetSetting(ctx, "jwt_secret")
	if err != nil || jwtSecret == "" {
		t.Fatalf("unexpected jwt_secret: %q, err=%v", jwtSecret, err)
	}
	siteTitle, err := s.GetSetting(ctx, "site_title")
	if err != nil || siteTitle != "ShadowOrbit" {
		t.Fatalf("unexpected site_title: %q, err=%v", siteTitle, err)
	}
	dnsGroups, err := s.ListDNSRuleGroups(ctx)
	if err != nil || len(dnsGroups) != 1 || dnsGroups[0].Name != "主流流媒体与 AI 解锁" || len(dnsGroups[0].Rules) < 10 {
		t.Fatalf("expected seeded default DNS rule group, got %+v, err=%v", dnsGroups, err)
	}
	// Deleting the seeded DNS group and calling SeedDefaults again must NOT recreate it.
	if err := s.DeleteDNSRuleGroup(ctx, dnsGroups[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := s.SeedDefaults(ctx, SeedConfig{}); err != nil {
		t.Fatal(err)
	}
	dnsGroupsAfter, err := s.ListDNSRuleGroups(ctx)
	if err != nil || len(dnsGroupsAfter) != 0 {
		t.Fatalf("deleted seeded DNS group should not be recreated: %+v, err=%v", dnsGroupsAfter, err)
	}

	for _, ct := range []string{protocol.ClientTypeSurgeAdmin, protocol.ClientTypeMihomoUser, protocol.ClientTypeSurgeUser} {
		tpl, err := s.GetDefaultSubTemplate(ctx, ct)
		if err != nil {
			t.Fatalf("missing default template for %s: %v", ct, err)
		}
		if tpl.Content == "" {
			t.Fatalf("empty template content for %s", ct)
		}
	}

	// Mutate settings and template; re-seed must NOT overwrite.
	if err := s.SetSetting(ctx, "admin_password_hash", "custom_rotated_hash"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting(ctx, "site_title", "Custom Title"); err != nil {
		t.Fatal(err)
	}
	tpl, err := s.GetDefaultSubTemplate(ctx, protocol.ClientTypeSurgeAdmin)
	if err != nil {
		t.Fatal(err)
	}
	tpl.Content = "# custom content"
	if err := s.UpdateSubTemplate(ctx, tpl); err != nil {
		t.Fatal(err)
	}

	if err := s.SeedDefaults(ctx, SeedConfig{
		AdminInitialPass: "otherPass",
	}); err != nil {
		t.Fatalf("second SeedDefaults failed: %v", err)
	}

	if got, _ := s.GetSetting(ctx, "admin_password_hash"); got != "custom_rotated_hash" {
		t.Fatalf("SeedDefaults overwrote admin_password_hash: %q", got)
	}
	if got, _ := s.GetSetting(ctx, "site_title"); got != "Custom Title" {
		t.Fatalf("SeedDefaults overwrote site_title: %q", got)
	}
	tpl2, err := s.GetDefaultSubTemplate(ctx, protocol.ClientTypeSurgeAdmin)
	if err != nil || tpl2.Content != "# custom content" {
		t.Fatalf("SeedDefaults overwrote template: %+v, err=%v", tpl2, err)
	}
}

func TestConcurrentTrafficUpdatesRace(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	n := &Node{Name: "race-node", TokenHash: "race_hash_1", Enabled: true}
	if err := s.CreateNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	u := &User{
		Username:     "race_user",
		Enabled:      true,
		SubToken:     "race_sub_1",
		SSUPSK16:     "AAAAAAAAAAAAAAAAAAAAAA==",
		SSUPSK32:     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		STLSPassword: "race_stls",
	}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}

	const goroutines = 20
	const iterations = 50
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*iterations*4)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if _, err := s.AddNodeTrafficDelta(ctx, n.ID, 100, 200); err != nil {
					errCh <- err
				}
				if _, err := s.AddUserTrafficDelta(ctx, u.ID, 50, 75); err != nil {
					errCh <- err
				}
				if err := s.UpsertAddDailyTraffic(ctx, "node", n.ID, "2026-11-23", 100, 200); err != nil {
					errCh <- err
				}
				if _, err := s.ListNodes(ctx); err != nil {
					errCh <- err
				}
				if _, err := s.GetUserByID(ctx, u.ID); err != nil {
					errCh <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent operation failed: %v", err)
	}

	gotNode, err := s.GetNodeByID(ctx, n.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantRx := int64(goroutines * iterations * 100)
	wantTx := int64(goroutines * iterations * 200)
	if gotNode.CycleRxBytes != wantRx || gotNode.CycleTxBytes != wantTx {
		t.Fatalf("node traffic mismatch: got (%d, %d), want (%d, %d)", gotNode.CycleRxBytes, gotNode.CycleTxBytes, wantRx, wantTx)
	}

	gotUser, err := s.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantUp := int64(goroutines * iterations * 50)
	wantDown := int64(goroutines * iterations * 75)
	if gotUser.UsedUpBytes != wantUp || gotUser.UsedDownBytes != wantDown {
		t.Fatalf("user traffic mismatch: got (%d, %d), want (%d, %d)", gotUser.UsedUpBytes, gotUser.UsedDownBytes, wantUp, wantDown)
	}

	logs, err := s.QueryDailyTraffic(ctx, DailyTrafficFilter{TargetType: "node", TargetID: n.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || logs[0].RxBytes != wantRx || logs[0].TxBytes != wantTx {
		t.Fatalf("daily traffic mismatch: %+v", logs)
	}
}

func TestNodesCRUDAndLifecycle(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	grp := &DNSRuleGroup{Name: "AI", Rules: []string{"openai.com"}}
	if err := s.CreateDNSRuleGroup(ctx, grp); err != nil {
		t.Fatal(err)
	}

	n1 := &Node{
		Name:            "HK-01",
		RegionTag:       "HK",
		TokenHash:       "tok_hash_1",
		CustomEntryHost: "hk.example.com",
		CustomEntryPort: 8443,
		SortOrder:       2,
		Enabled:         true,
		SnellConfig: protocol.SnellConfig{
			Enabled:    true,
			Version:    protocol.SnellVersionV5,
			PublicPort: 8443,
			InnerPort:  31001,
			PSK:        "psk1",
			Obfs:       protocol.SnellObfsOff,
			TFO:        true,
		},
		SSConfig: protocol.SSConfig{
			Enabled: true,
			TCPPort: 9443,
			UDPPort: 9443,
			Cipher:  protocol.CipherAES128GCM,
			IPSK:    "ipsk1",
			STLSSNI: "gateway.icloud.com",
		},
		DNSUnlockEnabled:      true,
		DNSUnlockServer:       "1.2.3.4:3535",
		DNSRuleGroupID:        &grp.ID,
		DNSExtraRules:         []string{"^ip.sb"},
		TrafficLimitBytes:     1000,
		TrafficThresholdBytes: 850,
		BillingResetDay:       15,
	}
	if err := s.CreateNode(ctx, n1); err != nil {
		t.Fatalf("CreateNode n1 failed: %v", err)
	}

	// Duplicate token_hash -> ErrConflict.
	dup := &Node{Name: "Dup", TokenHash: "tok_hash_1"}
	if err := s.CreateNode(ctx, dup); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate token_hash, got %v", err)
	}

	n2 := &Node{Name: "JP-01", TokenHash: "tok_hash_2", SortOrder: 1, Enabled: true}
	if err := s.CreateNode(ctx, n2); err != nil {
		t.Fatal(err)
	}

	got1, err := s.GetNodeByTokenHash(ctx, "tok_hash_1")
	if err != nil || got1.ID != n1.ID || got1.SnellConfig.PSK != "psk1" || len(got1.DNSExtraRules) != 1 {
		t.Fatalf("GetNodeByTokenHash mismatch: %+v, err=%v", got1, err)
	}

	nodes, err := s.ListNodes(ctx)
	if err != nil || len(nodes) != 2 || nodes[0].ID != n2.ID || nodes[1].ID != n1.ID {
		t.Fatalf("unexpected initial ListNodes order: %+v, err=%v", nodes, err)
	}

	if err := s.ReorderNodes(ctx, []int64{n1.ID, n2.ID}); err != nil {
		t.Fatal(err)
	}
	nodes, _ = s.ListNodes(ctx)
	if nodes[0].ID != n1.ID || nodes[1].ID != n2.ID {
		t.Fatalf("ReorderNodes did not update order: %+v", nodes)
	}

	// Telemetry update sets online + metrics.
	now := time.Now().UTC()
	if err := s.UpdateNodeTelemetry(ctx, n1.ID, NodeTelemetryUpdate{
		PublicIP:      "203.0.113.10",
		CPUPercent:    22.5,
		MemUsedBytes:  500,
		MemTotalBytes: 1000,
		RxBPS:         123,
		TxBPS:         456,
		CoreAHealthy:  true,
		CoreBHealthy:  true,
		LastSeenAt:    now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateNodeVersions(ctx, n1.ID, protocol.AgentVersions{
		SingBox: "1.11.0", SnellServer: "v5.0.0", ShadowTLS: "v0.2.25",
	}, "linux", "arm64", 4, 2); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateNodeReportedRevision(ctx, n1.ID, 3); err != nil {
		t.Fatal(err)
	}

	// Pause & reset cycle traffic.
	if err := s.CalibrateNodeTraffic(ctx, n1.ID, 400, 500); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeTrafficPaused(ctx, n1.ID, true, "threshold reached"); err != nil {
		t.Fatal(err)
	}
	got1, _ = s.GetNodeByID(ctx, n1.ID)
	if !got1.IsTrafficPaused || got1.Status != protocol.NodeStatusTrafficPaused || got1.CycleRxBytes != 400 || got1.CycleTxBytes != 500 {
		t.Fatalf("expected paused state and calibrated bytes, got %+v", got1)
	}

	// Telemetry while paused preserves traffic_paused status.
	if err := s.UpdateNodeTelemetry(ctx, n1.ID, NodeTelemetryUpdate{CPUPercent: 10, LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	got1, _ = s.GetNodeByID(ctx, n1.ID)
	if got1.Status != protocol.NodeStatusTrafficPaused {
		t.Fatalf("telemetry must not clear traffic_paused status, got %q", got1.Status)
	}

	if err := s.ResetNodeCycleTraffic(ctx, n1.ID, now); err != nil {
		t.Fatal(err)
	}
	got1, _ = s.GetNodeByID(ctx, n1.ID)
	if got1.IsTrafficPaused || got1.CycleRxBytes != 0 || got1.CycleTxBytes != 0 || got1.Status != protocol.NodeStatusOnline {
		t.Fatalf("expected ResetNodeCycleTraffic to zero counters and restore online, got %+v", got1)
	}

	rev, err := s.IncrementNodeConfigRevision(ctx, n1.ID)
	if err != nil || rev != 2 {
		t.Fatalf("expected config_revision 2, got %d, err=%v", rev, err)
	}

	// UpdateNode updates config without zeroing telemetry.
	got1.Name = "HK-01-Renamed"
	if err := s.UpdateNode(ctx, got1); err != nil {
		t.Fatal(err)
	}
	got1After, _ := s.GetNodeByID(ctx, n1.ID)
	if got1After.Name != "HK-01-Renamed" || got1After.ReportedVersions.SingBox != "1.11.0" {
		t.Fatalf("UpdateNode mismatch: %+v", got1After)
	}

	revsByGroup, err := s.IncrementConfigRevisionByDNSGroup(ctx, grp.ID)
	if err != nil || len(revsByGroup) != 1 || revsByGroup[0] != n1.ID {
		t.Fatalf("IncrementConfigRevisionByDNSGroup mismatch: %v, err=%v", revsByGroup, err)
	}

	if err := s.DeleteNode(ctx, n2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetNodeByID(ctx, n2.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestUsersAndAccessMatrix(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	nActive := &Node{Name: "N-Active", TokenHash: "h1", Enabled: true, SortOrder: 1}
	nPaused := &Node{Name: "N-Paused", TokenHash: "h2", Enabled: true, IsTrafficPaused: true, Status: protocol.NodeStatusTrafficPaused, SortOrder: 2}
	nDisabled := &Node{Name: "N-Disabled", TokenHash: "h3", Enabled: false, SortOrder: 3}
	for _, n := range []*Node{nActive, nPaused, nDisabled} {
		if err := s.CreateNode(ctx, n); err != nil {
			t.Fatal(err)
		}
	}

	now := time.Now().UTC()
	future := now.Add(24 * time.Hour)
	past := now.Add(-24 * time.Hour)

	mkUser := func(name string, enabled bool, quota, up, down int64, exp *time.Time) *User {
		u := &User{
			Username:          name,
			Enabled:           enabled,
			SubToken:          "sub_" + name,
			SSUPSK16:          "AAAAAAAAAAAAAAAAAAAAAA==",
			SSUPSK32:          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			STLSPassword:      "stls_" + name,
			TrafficQuotaBytes: quota,
			UsedUpBytes:       up,
			UsedDownBytes:     down,
			ExpireAt:          exp,
		}
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser(%s) failed: %v", name, err)
		}
		return u
	}

	uValid := mkUser("valid_unlimited", true, 0, 100, 100, nil)
	uValidFuture := mkUser("valid_future", true, 1000, 400, 500, &future)
	uDisabled := mkUser("disabled", false, 0, 0, 0, nil)
	uExpired := mkUser("expired", true, 0, 0, 0, &past)
	uOverQuota := mkUser("over_quota", true, 1000, 600, 400, nil)
	uUnmapped := mkUser("unmapped", true, 0, 0, 0, nil)

	// Duplicate username / sub_token -> ErrConflict.
	if err := s.CreateUser(ctx, &User{
		Username: "valid_unlimited", SubToken: "uniq_tok", SSUPSK16: "a", SSUPSK32: "b", STLSPassword: "c",
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict for duplicate username, got %v", err)
	}

	// Map all except uUnmapped to nActive (also test dedup).
	for _, u := range []*User{uValid, uValidFuture, uDisabled, uExpired, uOverQuota} {
		if err := s.SetUserNodes(ctx, u.ID, []int64{nActive.ID, nPaused.ID, nDisabled.ID, nActive.ID}); err != nil {
			t.Fatal(err)
		}
	}

	ids, err := s.GetUserNodeIDs(ctx, uValid.ID)
	if err != nil || len(ids) != 3 {
		t.Fatalf("expected 3 deduplicated node IDs, got %v, err=%v", ids, err)
	}

	allMap, err := s.ListAllUserNodeAccess(ctx)
	if err != nil || len(allMap) != 5 {
		t.Fatalf("expected 5 mapped users, got %v, err=%v", allMap, err)
	}

	authUsers, err := s.ListAuthorizedUsersForNode(ctx, nActive.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(authUsers) != 2 || authUsers[0].ID != uValid.ID || authUsers[1].ID != uValidFuture.ID {
		t.Fatalf("unexpected authorized users: %+v", authUsers)
	}
	_ = uUnmapped

	authNodes, err := s.ListAuthorizedNodesForUser(ctx, uValid.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(authNodes) != 1 || authNodes[0].ID != nActive.ID {
		t.Fatalf("expected only enabled non-paused node, got %+v", authNodes)
	}

	// ResetUserKeys rotates only non-empty args.
	if err := s.ResetUserKeys(ctx, uValid.ID, "NEW16", "NEW32", "", ""); err != nil {
		t.Fatal(err)
	}
	gotU, _ := s.GetUserBySubToken(ctx, uValid.SubToken)
	if gotU.SSUPSK16 != "NEW16" || gotU.SSUPSK32 != "NEW32" || gotU.STLSPassword != "stls_valid_unlimited" {
		t.Fatalf("ResetUserKeys partial rotation failed: %+v", gotU)
	}

	// IncrementConfigRevisionByUser bumps all mapped nodes.
	affected, err := s.IncrementConfigRevisionByUser(ctx, uValid.ID)
	if err != nil || len(affected) != 3 {
		t.Fatalf("expected 3 nodes bumped, got %v, err=%v", affected, err)
	}

	// ResetUserTraffic restores over-quota user into authorized set.
	if err := s.ResetUserTraffic(ctx, uOverQuota.ID, now); err != nil {
		t.Fatal(err)
	}
	authUsers, _ = s.ListAuthorizedUsersForNode(ctx, nActive.ID, now)
	if len(authUsers) != 3 {
		t.Fatalf("expected 3 authorized users after ResetUserTraffic, got %d", len(authUsers))
	}

	// GrantNodeToAllUsers idempotently grants a newly created node to every existing user.
	nAutoGrant := &Node{Name: "AutoGrantSS", TokenHash: "tok_auto_grant_test", Enabled: true}
	if err := s.CreateNode(ctx, nAutoGrant); err != nil {
		t.Fatal(err)
	}
	granted1, err := s.GrantNodeToAllUsers(ctx, nAutoGrant.ID)
	if err != nil {
		t.Fatalf("GrantNodeToAllUsers failed: %v", err)
	}
	if granted1 != 6 {
		t.Fatalf("expected 6 existing users granted, got %d", granted1)
	}
	granted2, err := s.GrantNodeToAllUsers(ctx, nAutoGrant.ID)
	if err != nil {
		t.Fatalf("second GrantNodeToAllUsers failed: %v", err)
	}
	if granted2 != 0 {
		t.Fatalf("expected 0 new grants on idempotent second call, got %d", granted2)
	}
	unmappedIDs, err := s.GetUserNodeIDs(ctx, uUnmapped.ID)
	if err != nil || len(unmappedIDs) != 1 || unmappedIDs[0] != nAutoGrant.ID {
		t.Fatalf("expected uUnmapped to receive AutoGrantSS node, got %v, err=%v", unmappedIDs, err)
	}

	if err := s.DeleteUser(ctx, uDisabled.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetUserByUsername(ctx, "disabled"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for deleted user, got %v", err)
	}
}

func TestDNSRuleGroupsSubTemplatesWebhooksSettings(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	// 1. DNS rule groups
	grp := &DNSRuleGroup{Name: "Netflix", Description: "NF", Rules: []string{"netflix.com", "*.nflxvideo.net"}}
	if err := s.CreateDNSRuleGroup(ctx, grp); err != nil {
		t.Fatal(err)
	}
	grp.Rules = append(grp.Rules, "^fast.com")
	if err := s.UpdateDNSRuleGroup(ctx, grp); err != nil {
		t.Fatal(err)
	}
	groups, err := s.ListDNSRuleGroups(ctx)
	if err != nil || len(groups) != 1 || len(groups[0].Rules) != 3 {
		t.Fatalf("DNSRuleGroup mismatch: %+v, err=%v", groups, err)
	}

	// 2. Traffic logs daily (node vs user separation, date filter, invalid type)
	if err := s.UpsertAddDailyTraffic(ctx, "node", 1, "2026-11-20", 10, 20); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertAddDailyTraffic(ctx, "user", 1, "2026-11-20", 30, 40); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertAddDailyTraffic(ctx, "node", 1, "2026-11-22", 50, 60); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertAddDailyTraffic(ctx, "invalid", 1, "2026-11-22", 1, 1); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for invalid target_type, got %v", err)
	}
	nodeLogs, err := s.QueryDailyTraffic(ctx, DailyTrafficFilter{
		TargetType: "node", TargetID: 1, FromDate: "2026-11-21", ToDate: "2026-11-23",
	})
	if err != nil || len(nodeLogs) != 1 || nodeLogs[0].RxBytes != 50 {
		t.Fatalf("QueryDailyTraffic mismatch: %+v, err=%v", nodeLogs, err)
	}

	// 3. Sub templates single-default invariant
	t1 := &SubTemplate{Name: "Mihomo A", ClientType: protocol.ClientTypeMihomoUser, Content: "A", IsDefault: true}
	t2 := &SubTemplate{Name: "Mihomo B", ClientType: protocol.ClientTypeMihomoUser, Content: "B", IsDefault: true}
	tSurge := &SubTemplate{Name: "Surge A", ClientType: protocol.ClientTypeSurgeUser, Content: "S", IsDefault: true}
	for _, tpl := range []*SubTemplate{t1, t2, tSurge} {
		if err := s.CreateSubTemplate(ctx, tpl); err != nil {
			t.Fatal(err)
		}
	}
	gotT1, _ := s.GetSubTemplateByID(ctx, t1.ID)
	if gotT1.IsDefault {
		t.Fatal("creating t2 as default should clear t1.IsDefault")
	}
	gotDefMihomo, _ := s.GetDefaultSubTemplate(ctx, protocol.ClientTypeMihomoUser)
	if gotDefMihomo.ID != t2.ID {
		t.Fatalf("expected t2 as default mihomo_user, got %+v", gotDefMihomo)
	}
	gotDefSurge, _ := s.GetDefaultSubTemplate(ctx, protocol.ClientTypeSurgeUser)
	if gotDefSurge.ID != tSurge.ID {
		t.Fatalf("tSurge default should remain untouched, got %+v", gotDefSurge)
	}
	// Switch default back to t1 via UpdateSubTemplate.
	gotT1.IsDefault = true
	if err := s.UpdateSubTemplate(ctx, gotT1); err != nil {
		t.Fatal(err)
	}
	gotDefMihomo, _ = s.GetDefaultSubTemplate(ctx, protocol.ClientTypeMihomoUser)
	if gotDefMihomo.ID != t1.ID {
		t.Fatalf("expected t1 as default after update, got %+v", gotDefMihomo)
	}
	allMihomo, err := s.ListSubTemplates(ctx, protocol.ClientTypeMihomoUser)
	if err != nil || len(allMihomo) != 2 {
		t.Fatalf("unexpected mihomo templates: %+v, err=%v", allMihomo, err)
	}

	// 4. Webhooks
	wh1 := &WebhookChannel{
		Name:             "Feishu Alerts",
		Provider:         protocol.WebhookProviderFeishu,
		URL:              "https://open.feishu.cn/hook/1",
		Secret:           "sec1",
		SubscribedEvents: []string{"node_offline", "node_paused"},
		Enabled:          true,
	}
	wh2 := &WebhookChannel{
		Name:             "Disabled All",
		Provider:         protocol.WebhookProviderCustom,
		URL:              "https://example.com/hook",
		SubscribedEvents: []string{"*"},
		Enabled:          false,
	}
	if err := s.CreateWebhookChannel(ctx, wh1); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateWebhookChannel(ctx, wh2); err != nil {
		t.Fatal(err)
	}
	matched, err := s.ListEnabledWebhooksByEvent(ctx, "node_offline")
	if err != nil || len(matched) != 1 || matched[0].ID != wh1.ID {
		t.Fatalf("ListEnabledWebhooksByEvent mismatch: %+v, err=%v", matched, err)
	}
	wh1.SubscribedEvents = []string{"*"}
	if err := s.UpdateWebhookChannel(ctx, wh1); err != nil {
		t.Fatal(err)
	}
	matched, _ = s.ListEnabledWebhooksByEvent(ctx, "anything")
	if len(matched) != 1 {
		t.Fatalf("expected wildcard match, got %+v", matched)
	}
	if err := s.DeleteWebhookChannel(ctx, wh2.ID); err != nil {
		t.Fatal(err)
	}

	// 5. Settings & SetSettingIfAbsent
	if _, err := s.GetSetting(ctx, "nonexistent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing setting, got %v", err)
	}
	if def, err := s.GetSettingOrDefault(ctx, "nonexistent", "fallback"); err != nil || def != "fallback" {
		t.Fatalf("GetSettingOrDefault mismatch: %q, err=%v", def, err)
	}
	val, created, err := s.SetSettingIfAbsent(ctx, "atomic_key", "first_val")
	if err != nil || !created || val != "first_val" {
		t.Fatalf("SetSettingIfAbsent first call: val=%q created=%v err=%v", val, created, err)
	}
	val2, created2, err := s.SetSettingIfAbsent(ctx, "atomic_key", "second_val")
	if err != nil || created2 || val2 != "first_val" {
		t.Fatalf("SetSettingIfAbsent second call: val=%q created=%v err=%v", val2, created2, err)
	}
	if err := s.SetSettingsBatch(ctx, map[string]string{"k1": "v1", "k2": "v2"}); err != nil {
		t.Fatal(err)
	}
	allSettings, err := s.GetAllSettings(ctx)
	if err != nil || allSettings["k1"] != "v1" || allSettings["k2"] != "v2" {
		t.Fatalf("GetAllSettings mismatch: %v, err=%v", allSettings, err)
	}

	// Suppress unused fmt import warning if needed
	_ = fmt.Sprint()
}

func TestSeedDefaultsJWTSecretValidation(t *testing.T) {
	ctx := context.Background()

	invalidSecrets := []struct {
		name   string
		secret string
	}{
		{"too short", "short"},
		{"whitespace only", "                                        "},
		{"nul padded short", "a" + string(make([]byte, 35))},
		{"spaces padded", "a                                        "},
		{"newline", "0123456789abcdef0123456789abcdef!\n"},
		{"carriage return", "0123456789abcdef0123456789abcdef!\r"},
		{"16-byte base64", "AAAAAAAAAAAAAAAAAAAAAA=="},
		{"22-byte base64 padded", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=="},
		{"16-byte hex (32 hex chars)", "0123456789abcdef0123456789abcdef"},
	}

	for _, tc := range invalidSecrets {
		t.Run("reject_"+tc.name, func(t *testing.T) {
			s := openTestStore(t)
			err := s.SeedDefaults(ctx, SeedConfig{JWTSecret: tc.secret})
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("expected ErrInvalidArgument for %s (%q), got %v", tc.name, tc.secret, err)
			}
			if _, getErr := s.GetSetting(ctx, "jwt_secret"); !errors.Is(getErr, ErrNotFound) {
				t.Fatalf("expected jwt_secret not persisted after failed SeedDefaults, got %v", getErr)
			}
		})
	}

	validSecrets := []struct {
		name   string
		secret string
	}{
		{"empty auto-generated", ""},
		{"32-byte base64", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="},
		{"32-byte hex", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{"32-byte passphrase", "known-test-secret-for-store-32bytes!"},
	}

	for _, tc := range validSecrets {
		t.Run("accept_"+tc.name, func(t *testing.T) {
			s := openTestStore(t)
			if err := s.SeedDefaults(ctx, SeedConfig{JWTSecret: tc.secret}); err != nil {
				t.Fatalf("expected SeedDefaults to succeed for %s: %v", tc.name, err)
			}
			got, err := s.GetSetting(ctx, "jwt_secret")
			if err != nil || got == "" {
				t.Fatalf("expected persisted jwt_secret, got %q err=%v", got, err)
			}
		})
	}
}

func TestNodeBillingResetDayAndPreservePublicIPs(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	// CreateNode: 0 defaults to 1; out-of-range rejected.
	nDef := &Node{Name: "N-Default", TokenHash: "h_def"}
	if err := s.CreateNode(ctx, nDef); err != nil {
		t.Fatalf("CreateNode default reset day failed: %v", err)
	}
	if nDef.BillingResetDay != 1 {
		t.Fatalf("expected BillingResetDay 1, got %d", nDef.BillingResetDay)
	}

	for _, badDay := range []int{-1, 32} {
		err := s.CreateNode(ctx, &Node{Name: "N-Bad", TokenHash: fmt.Sprintf("h_bad_%d", badDay), BillingResetDay: badDay})
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("CreateNode day=%d: expected ErrInvalidArgument, got %v", badDay, err)
		}
	}

	// Set agent-reported IPs, then UpdateNode with empty PublicIP/PublicIPv6.
	if err := s.UpdateNodePublicIPs(ctx, nDef.ID, "203.0.113.10", "2001:db8::10"); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetNodeByID(ctx, nDef.ID)
	if err != nil {
		t.Fatal(err)
	}

	// UpdateNode must reject 0, -1, 32.
	for _, badDay := range []int{0, -1, 32} {
		bad := *got
		bad.BillingResetDay = badDay
		if err := s.UpdateNode(ctx, &bad); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("UpdateNode day=%d: expected ErrInvalidArgument, got %v", badDay, err)
		}
	}

	upd := *got
	upd.Name = "N-Updated"
	upd.PublicIP = ""
	upd.PublicIPv6 = ""
	upd.BillingResetDay = 31
	if err := s.UpdateNode(ctx, &upd); err != nil {
		t.Fatalf("UpdateNode failed: %v", err)
	}
	if upd.PublicIP != "203.0.113.10" || upd.PublicIPv6 != "2001:db8::10" {
		t.Fatalf("expected UpdateNode struct to preserve IPs, got ipv4=%q ipv6=%q", upd.PublicIP, upd.PublicIPv6)
	}
	reloaded, err := s.GetNodeByID(ctx, nDef.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.PublicIP != "203.0.113.10" || reloaded.PublicIPv6 != "2001:db8::10" || reloaded.BillingResetDay != 31 {
		t.Fatalf("reloaded node mismatch: %+v", reloaded)
	}
}

func TestUpdateNodePublicIPsAndConnectionStatus(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	n := &Node{Name: "Conn-Node", TokenHash: "h_conn", Enabled: true}
	if err := s.CreateNode(ctx, n); err != nil {
		t.Fatal(err)
	}

	if err := s.UpdateNodePublicIPs(ctx, n.ID, "198.51.100.2", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateNodePublicIPs(ctx, n.ID, "", "2001:db8::2"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetNodeByID(ctx, n.ID)
	if got.PublicIP != "198.51.100.2" || got.PublicIPv6 != "2001:db8::2" {
		t.Fatalf("unexpected IPs: ipv4=%q ipv6=%q", got.PublicIP, got.PublicIPv6)
	}

	if err := s.UpdateNodePublicIPs(ctx, 99999, "1.1.1.1", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	if err := s.SetNodeConnectionStatus(ctx, n.ID, true, now); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetNodeByID(ctx, n.ID)
	if got.Status != protocol.NodeStatusOnline || got.LastSeenAt == nil || !got.LastSeenAt.Equal(now) {
		t.Fatalf("expected online with last_seen_at=%v, got status=%q last_seen=%v", now, got.Status, got.LastSeenAt)
	}

	if err := s.SetNodeConnectionStatus(ctx, n.ID, false, time.Time{}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetNodeByID(ctx, n.ID)
	if got.Status != protocol.NodeStatusOffline {
		t.Fatalf("expected offline, got %q", got.Status)
	}

	// When traffic_paused, SetNodeConnectionStatus must preserve traffic_paused.
	if err := s.SetNodeTrafficPaused(ctx, n.ID, true, "quota"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNodeConnectionStatus(ctx, n.ID, true, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetNodeByID(ctx, n.ID)
	if got.Status != protocol.NodeStatusTrafficPaused {
		t.Fatalf("expected traffic_paused preserved on online, got %q", got.Status)
	}
	if err := s.SetNodeConnectionStatus(ctx, n.ID, false, time.Time{}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetNodeByID(ctx, n.ID)
	if got.Status != protocol.NodeStatusTrafficPaused {
		t.Fatalf("expected traffic_paused preserved on offline, got %q", got.Status)
	}

	if err := s.UpdateNodeStatus(ctx, n.ID, "bogus", ""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for invalid status, got %v", err)
	}
}

func TestApplyTrafficDeltasAtomicityAndDeletedUser(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	n := &Node{Name: "Delta-Node", TokenHash: "h_delta", Enabled: true}
	if err := s.CreateNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	u1 := &User{
		Username: "alice", Enabled: true, SubToken: "sub_alice",
		SSUPSK16: "AAAAAAAAAAAAAAAAAAAAAA==", SSUPSK32: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", STLSPassword: "pwd1",
	}
	if err := s.CreateUser(ctx, u1); err != nil {
		t.Fatal(err)
	}

	res, err := s.ApplyTrafficDeltas(ctx, n.ID, 1000, 2000, []protocol.UserTrafficDelta{
		{UserID: u1.ID, Username: "alice", UpBytes: 300, DownBytes: 700},
		{UserID: 99999, Username: "deleted_user", UpBytes: 50, DownBytes: 60},
		{UserID: u1.ID, Username: "alice", UpBytes: 0, DownBytes: 0},
	}, "2026-11-23")
	if err != nil {
		t.Fatalf("ApplyTrafficDeltas failed: %v", err)
	}
	if res.Node == nil || res.Node.CycleRxBytes != 1000 || res.Node.CycleTxBytes != 2000 {
		t.Fatalf("unexpected node traffic: %+v", res.Node)
	}
	if len(res.UpdatedUserIDs) != 1 || res.UpdatedUserIDs[0] != u1.ID {
		t.Fatalf("unexpected UpdatedUserIDs: %v", res.UpdatedUserIDs)
	}
	if len(res.SkippedUserIDs) != 1 || res.SkippedUserIDs[0] != 99999 {
		t.Fatalf("unexpected SkippedUserIDs: %v", res.SkippedUserIDs)
	}

	gotU, _ := s.GetUserByID(ctx, u1.ID)
	if gotU.UsedUpBytes != 300 || gotU.UsedDownBytes != 700 {
		t.Fatalf("unexpected user counters: up=%d down=%d", gotU.UsedUpBytes, gotU.UsedDownBytes)
	}

	userDaily, err := s.QueryDailyTraffic(ctx, DailyTrafficFilter{TargetType: "user", TargetID: u1.ID})
	if err != nil || len(userDaily) != 1 || userDaily[0].RxBytes != 700 || userDaily[0].TxBytes != 300 {
		t.Fatalf("unexpected user daily log: %+v, err=%v", userDaily, err)
	}

	// Missing node fails atomically without updating user.
	if _, err := s.ApplyTrafficDeltas(ctx, 99999, 10, 10, []protocol.UserTrafficDelta{
		{UserID: u1.ID, UpBytes: 999, DownBytes: 999},
	}, "2026-11-23"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing node, got %v", err)
	}
	gotU2, _ := s.GetUserByID(ctx, u1.ID)
	if gotU2.UsedUpBytes != 300 || gotU2.UsedDownBytes != 700 {
		t.Fatalf("expected rollback on failed node update, got up=%d down=%d", gotU2.UsedUpBytes, gotU2.UsedDownBytes)
	}

	// Negative nic delta rejected.
	if _, err := s.ApplyTrafficDeltas(ctx, n.ID, -1, 0, nil, "2026-11-23"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for negative delta, got %v", err)
	}
}

func TestBumpNodesConfigRevisionAndDeleteCleanupSystemSettings(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	n1 := &Node{Name: "N1", TokenHash: "h_b1"}
	n2 := &Node{Name: "N2", TokenHash: "h_b2"}
	if err := s.CreateNode(ctx, n1); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateNode(ctx, n2); err != nil {
		t.Fatal(err)
	}
	u := &User{
		Username: "bob", Enabled: true, SubToken: "sub_bob",
		SSUPSK16: "AAAAAAAAAAAAAAAAAAAAAA==", SSUPSK32: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", STLSPassword: "pwd",
	}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}

	if err := s.BumpNodesConfigRevision(ctx, []int64{n1.ID, n2.ID, n1.ID, 0, -5}); err != nil {
		t.Fatalf("BumpNodesConfigRevision failed: %v", err)
	}
	got1, _ := s.GetNodeByID(ctx, n1.ID)
	got2, _ := s.GetNodeByID(ctx, n2.ID)
	if got1.ConfigRevision != 2 || got2.ConfigRevision != 2 {
		t.Fatalf("expected config_revision=2 on both nodes, got %d and %d", got1.ConfigRevision, got2.ConfigRevision)
	}

	if err := s.SetSetting(ctx, fmt.Sprintf("node_token_enc:%d", n1.ID), "v1:cipher"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting(ctx, fmt.Sprintf("last_node_reset_month:%d", n1.ID), "2026-11"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting(ctx, fmt.Sprintf("last_user_reset_month:%d", u.ID), "2026-11"); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteNode(ctx, n1.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSetting(ctx, fmt.Sprintf("node_token_enc:%d", n1.ID)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected node_token_enc deleted, got %v", err)
	}
	if _, err := s.GetSetting(ctx, fmt.Sprintf("last_node_reset_month:%d", n1.ID)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected last_node_reset_month deleted, got %v", err)
	}

	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSetting(ctx, fmt.Sprintf("last_user_reset_month:%d", u.ID)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected last_user_reset_month deleted, got %v", err)
	}
}

func TestTrafficCumulativeInt64OverflowRollback(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	n := &Node{Name: "Overflow-Node", TokenHash: "h_overflow", Enabled: true}
	if err := s.CreateNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	u := &User{
		Username:      "overflow_user",
		Enabled:       true,
		SubToken:      "sub_overflow",
		SSUPSK16:      "AAAAAAAAAAAAAAAAAAAAAA==",
		SSUPSK32:      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		STLSPassword:  "pwd_overflow",
		UsedUpBytes:   100,
		UsedDownBytes: 200,
	}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserNodes(ctx, u.ID, []int64{n.ID}); err != nil {
		t.Fatal(err)
	}

	assertAllHealthy := func(wantNodeRx, wantNodeTx, wantUserUp, wantUserDown int64) {
		t.Helper()
		gotNode, err := s.GetNodeByID(ctx, n.ID)
		if err != nil {
			t.Fatalf("GetNodeByID failed: %v", err)
		}
		if gotNode.CycleRxBytes != wantNodeRx || gotNode.CycleTxBytes != wantNodeTx {
			t.Fatalf("node counters = (%d, %d), want (%d, %d)", gotNode.CycleRxBytes, gotNode.CycleTxBytes, wantNodeRx, wantNodeTx)
		}

		gotUser, err := s.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID failed: %v", err)
		}
		if gotUser.UsedUpBytes != wantUserUp || gotUser.UsedDownBytes != wantUserDown {
			t.Fatalf("user counters = (%d, %d), want (%d, %d)", gotUser.UsedUpBytes, gotUser.UsedDownBytes, wantUserUp, wantUserDown)
		}

		users, err := s.ListUsers(ctx)
		if err != nil || len(users) != 1 {
			t.Fatalf("ListUsers failed: len=%d err=%v", len(users), err)
		}
		authUsers, err := s.ListAuthorizedUsersForNode(ctx, n.ID, time.Now().UTC())
		if err != nil || len(authUsers) != 1 {
			t.Fatalf("ListAuthorizedUsersForNode failed: len=%d err=%v", len(authUsers), err)
		}
		if _, err := s.QueryDailyTraffic(ctx, DailyTrafficFilter{}); err != nil {
			t.Fatalf("QueryDailyTraffic failed: %v", err)
		}
	}

	// 1. Node cumulative int64 overflow in ApplyTrafficDeltas rolls back atomically.
	if err := s.CalibrateNodeTraffic(ctx, n.ID, math.MaxInt64-10, 50); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertAddDailyTraffic(ctx, "node", n.ID, "2026-11-24", 10, 20); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyTrafficDeltas(ctx, n.ID, 11, 5, []protocol.UserTrafficDelta{
		{UserID: u.ID, UpBytes: 50, DownBytes: 50},
	}, "2026-11-24"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("node cumulative overflow: expected ErrInvalidArgument, got %v", err)
	}
	assertAllHealthy(math.MaxInt64-10, 50, 100, 200)

	// 2. AddNodeTrafficDelta cumulative overflow returns ErrInvalidArgument cleanly.
	if _, err := s.AddNodeTrafficDelta(ctx, n.ID, 11, 0); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("AddNodeTrafficDelta overflow: expected ErrInvalidArgument, got %v", err)
	}
	assertAllHealthy(math.MaxInt64-10, 50, 100, 200)

	// 3. User cumulative int64 overflow (UpBytes and DownBytes) in ApplyTrafficDeltas rolls back atomically.
	if err := s.CalibrateNodeTraffic(ctx, n.ID, 1000, 2000); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyTrafficDeltas(ctx, n.ID, 10, 20, []protocol.UserTrafficDelta{
		{UserID: u.ID, UpBytes: math.MaxInt64, DownBytes: 0},
	}, "2026-11-24"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("user UpBytes cumulative overflow: expected ErrInvalidArgument, got %v", err)
	}
	assertAllHealthy(1000, 2000, 100, 200)

	if _, err := s.ApplyTrafficDeltas(ctx, n.ID, 10, 20, []protocol.UserTrafficDelta{
		{UserID: u.ID, UpBytes: 0, DownBytes: math.MaxInt64},
	}, "2026-11-24"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("user DownBytes cumulative overflow: expected ErrInvalidArgument, got %v", err)
	}
	assertAllHealthy(1000, 2000, 100, 200)

	nodeDaily, err := s.QueryDailyTraffic(ctx, DailyTrafficFilter{TargetType: "node", TargetID: n.ID, FromDate: "2026-11-24", ToDate: "2026-11-24"})
	if err != nil || len(nodeDaily) != 1 || nodeDaily[0].RxBytes != 10 || nodeDaily[0].TxBytes != 20 {
		t.Fatalf("expected node daily traffic rolled back to (10,20), got %+v err=%v", nodeDaily, err)
	}

	// 4. AddUserTrafficDelta cumulative overflow returns ErrInvalidArgument cleanly.
	if _, err := s.AddUserTrafficDelta(ctx, u.ID, math.MaxInt64, 0); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("AddUserTrafficDelta overflow: expected ErrInvalidArgument, got %v", err)
	}
	assertAllHealthy(1000, 2000, 100, 200)

	// 5. traffic_logs_daily cumulative overflow in UpsertAddDailyTraffic and ApplyTrafficDeltas.
	if err := s.UpsertAddDailyTraffic(ctx, "node", n.ID, "2026-11-25", math.MaxInt64-5, 10); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertAddDailyTraffic(ctx, "node", n.ID, "2026-11-25", 6, 0); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("UpsertAddDailyTraffic rx overflow: expected ErrInvalidArgument, got %v", err)
	}
	if err := s.UpsertAddDailyTraffic(ctx, "node", n.ID, "2026-11-25", 0, math.MaxInt64); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("UpsertAddDailyTraffic tx overflow: expected ErrInvalidArgument, got %v", err)
	}

	// Node daily overflow inside ApplyTrafficDeltas rolls back node + user updates.
	if _, err := s.ApplyTrafficDeltas(ctx, n.ID, 6, 1, []protocol.UserTrafficDelta{
		{UserID: u.ID, UpBytes: 5, DownBytes: 5},
	}, "2026-11-25"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("ApplyTrafficDeltas node daily overflow: expected ErrInvalidArgument, got %v", err)
	}
	assertAllHealthy(1000, 2000, 100, 200)

	// User daily overflow inside ApplyTrafficDeltas rolls back node + user + node daily updates.
	if err := s.UpsertAddDailyTraffic(ctx, "user", u.ID, "2026-11-26", 10, math.MaxInt64-5); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyTrafficDeltas(ctx, n.ID, 7, 8, []protocol.UserTrafficDelta{
		{UserID: u.ID, UpBytes: 6, DownBytes: 1},
	}, "2026-11-26"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("ApplyTrafficDeltas user daily overflow: expected ErrInvalidArgument, got %v", err)
	}
	assertAllHealthy(1000, 2000, 100, 200)

	userDaily, err := s.QueryDailyTraffic(ctx, DailyTrafficFilter{TargetType: "user", TargetID: u.ID, FromDate: "2026-11-26", ToDate: "2026-11-26"})
	if err != nil || len(userDaily) != 1 || userDaily[0].RxBytes != 10 || userDaily[0].TxBytes != math.MaxInt64-5 {
		t.Fatalf("expected user daily row intact after rollback, got %+v err=%v", userDaily, err)
	}
	nodeDaily26, err := s.QueryDailyTraffic(ctx, DailyTrafficFilter{TargetType: "node", TargetID: n.ID, FromDate: "2026-11-26", ToDate: "2026-11-26"})
	if err != nil || len(nodeDaily26) != 0 {
		t.Fatalf("expected node daily 2026-11-26 rolled back, got %+v err=%v", nodeDaily26, err)
	}
}

func TestTier5_StoreUncoveredCRUDAndBugB1B2Edges(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	// 1. Bug BUG-B1: SeedDefaults explicitly seeds alert_user_expired & alert_user_quota_exhausted = "true".
	if err := s.SeedDefaults(ctx, SeedConfig{
		AdminInitialPass: "secret1234",
		JWTSecret:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}); err != nil {
		t.Fatalf("SeedDefaults: %v", err)
	}
	for _, key := range []string{"alert_user_expired", "alert_user_quota_exhausted"} {
		val, err := s.GetSetting(ctx, key)
		if err != nil || val != "true" {
			t.Fatalf("expected %s=%q after SeedDefaults, got %q err=%v", key, "true", val, err)
		}
	}

	// 2. Bug BUG-B2: User.IsQuotaExhausted handles large sums without int64 wraparound.
	uNil := (*User)(nil)
	if uNil.IsQuotaExhausted() {
		t.Fatal("nil User should not be quota exhausted")
	}
	if (&User{TrafficQuotaBytes: 0, UsedUpBytes: 999}).IsQuotaExhausted() {
		t.Fatal("unlimited quota (0) should never be exhausted")
	}
	overflowUser := &User{
		TrafficQuotaBytes: math.MaxInt64,
		UsedUpBytes:       5_000_000_000_000_000_000,
		UsedDownBytes:     5_000_000_000_000_000_000,
	}
	if !overflowUser.IsQuotaExhausted() {
		t.Fatal("expected 5e18 + 5e18 >= MaxInt64 to be quota exhausted without int64 wrap")
	}
	if (&User{TrafficQuotaBytes: 100, UsedUpBytes: -50, UsedDownBytes: 99}).IsQuotaExhausted() {
		t.Fatal("negative clamped bytes + 99 < 100 should not be exhausted")
	}

	// 3. UpdateUser: error branches + clearing ExpireAt + conflict.
	if err := s.UpdateUser(ctx, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("UpdateUser(nil): expected ErrInvalidArgument, got %v", err)
	}
	if err := s.UpdateUser(ctx, &User{ID: 999999, Username: "ghost"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateUser missing: expected ErrNotFound, got %v", err)
	}
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	u1 := &User{Username: "u1", Enabled: true, SubToken: "tok1", SSUPSK16: "k16-1", SSUPSK32: "k32-1", STLSPassword: "stls1", BillingResetDay: 1, ExpireAt: &exp}
	u2 := &User{Username: "u2", Enabled: true, SubToken: "tok2", SSUPSK16: "k16-2", SSUPSK32: "k32-2", STLSPassword: "stls2", BillingResetDay: 1}
	if err := s.CreateUser(ctx, u1); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, u2); err != nil {
		t.Fatal(err)
	}
	u1.ExpireAt = nil
	u1.TrafficQuotaBytes = 4096
	if err := s.UpdateUser(ctx, u1); err != nil {
		t.Fatalf("UpdateUser clear ExpireAt: %v", err)
	}
	gotU1, err := s.GetUserByID(ctx, u1.ID)
	if err != nil || gotU1.ExpireAt != nil || gotU1.TrafficQuotaBytes != 4096 {
		t.Fatalf("unexpected u1 after UpdateUser: %+v err=%v", gotU1, err)
	}
	u2.Username = "u1"
	if err := s.UpdateUser(ctx, u2); !errors.Is(err, ErrConflict) {
		t.Fatalf("UpdateUser duplicate username: expected ErrConflict, got %v", err)
	}

	// 4. DeleteSubTemplate: valid delete + ErrNotFound + ErrInvalidArgument.
	tpl := &SubTemplate{Name: "Store-Del-Tpl", ClientType: protocol.ClientTypeSurgeUser, Content: "proxies:\n"}
	if err := s.CreateSubTemplate(ctx, tpl); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSubTemplate(ctx, tpl.ID); err != nil {
		t.Fatalf("DeleteSubTemplate: %v", err)
	}
	if err := s.DeleteSubTemplate(ctx, tpl.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteSubTemplate missing: expected ErrNotFound, got %v", err)
	}

	// 5. GetDNSRuleGroupByID: valid + ErrNotFound + ErrInvalidArgument.
	dg := &DNSRuleGroup{Name: "HK-Rules", Rules: []string{"DOMAIN,a.com,DIRECT"}}
	if err := s.CreateDNSRuleGroup(ctx, dg); err != nil {
		t.Fatal(err)
	}
	gotDG, err := s.GetDNSRuleGroupByID(ctx, dg.ID)
	if err != nil || gotDG.Name != "HK-Rules" || len(gotDG.Rules) != 1 {
		t.Fatalf("GetDNSRuleGroupByID mismatch: %+v err=%v", gotDG, err)
	}
	if _, err := s.GetDNSRuleGroupByID(ctx, 999999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetDNSRuleGroupByID missing: expected ErrNotFound, got %v", err)
	}

	// 6. GetWebhookChannelByID & ListWebhookChannels.
	wh1 := &WebhookChannel{Name: "Hook-A", Provider: protocol.WebhookProviderFeishu, URL: "https://example.com/a", SubscribedEvents: []string{"*"}, Enabled: true}
	wh2 := &WebhookChannel{Name: "Hook-B", Provider: protocol.WebhookProviderCustom, URL: "https://example.com/b", SubscribedEvents: []string{"node_offline"}, Enabled: false}
	if err := s.CreateWebhookChannel(ctx, wh1); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateWebhookChannel(ctx, wh2); err != nil {
		t.Fatal(err)
	}
	gotWH, err := s.GetWebhookChannelByID(ctx, wh1.ID)
	if err != nil || gotWH.Name != "Hook-A" {
		t.Fatalf("GetWebhookChannelByID mismatch: %+v err=%v", gotWH, err)
	}
	if _, err := s.GetWebhookChannelByID(ctx, 999999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetWebhookChannelByID missing: expected ErrNotFound, got %v", err)
	}
	listWH, err := s.ListWebhookChannels(ctx)
	if err != nil || len(listWH) != 2 || listWH[0].Name != "Hook-A" || listWH[1].Name != "Hook-B" {
		t.Fatalf("ListWebhookChannels mismatch: %+v err=%v", listWH, err)
	}

	// 7. UpdateNodeStatus & SetNodeTrafficPaused.
	node := &Node{Name: "Status-Node", TokenHash: "hash-status-node", Enabled: true, BillingResetDay: 1}
	if err := s.CreateNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateNodeStatus(ctx, node.ID, "bogus", "nope"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("UpdateNodeStatus bogus: expected ErrInvalidArgument, got %v", err)
	}
	if err := s.UpdateNodeStatus(ctx, 999999, protocol.NodeStatusOnline, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateNodeStatus missing: expected ErrNotFound, got %v", err)
	}
	if err := s.UpdateNodeStatus(ctx, node.ID, protocol.NodeStatusOnline, ""); err != nil {
		t.Fatalf("UpdateNodeStatus online: %v", err)
	}
	if err := s.SetNodeTrafficPaused(ctx, 999999, true, "reason"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetNodeTrafficPaused missing: expected ErrNotFound, got %v", err)
	}
	if err := s.SetNodeTrafficPaused(ctx, node.ID, true, "limit reached"); err != nil {
		t.Fatalf("SetNodeTrafficPaused true: %v", err)
	}
	gotNode, err := s.GetNodeByID(ctx, node.ID)
	if err != nil || !gotNode.IsTrafficPaused || gotNode.Status != protocol.NodeStatusTrafficPaused || gotNode.PausedReason != "limit reached" {
		t.Fatalf("unexpected node after SetNodeTrafficPaused(true): %+v err=%v", gotNode, err)
	}
	if err := s.SetNodeTrafficPaused(ctx, node.ID, false, ""); err != nil {
		t.Fatalf("SetNodeTrafficPaused false: %v", err)
	}
	gotNode2, _ := s.GetNodeByID(ctx, node.ID)
	if gotNode2.IsTrafficPaused || gotNode2.Status != protocol.NodeStatusOffline || gotNode2.PausedReason != "" {
		t.Fatalf("unexpected node after SetNodeTrafficPaused(false): %+v", gotNode2)
	}
}

func TestTier5_BugB8_UserWithNodesAtomicRollback(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	n1 := &Node{Name: "B8-N1", TokenHash: "hash-b8-n1", Enabled: true, BillingResetDay: 1}
	n2 := &Node{Name: "B8-N2", TokenHash: "hash-b8-n2", Enabled: true, BillingResetDay: 1}
	if err := s.CreateNode(ctx, n1); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateNode(ctx, n2); err != nil {
		t.Fatal(err)
	}

	// 1. CreateUserWithNodes rolls back user creation on FK failure.
	badUser := &User{
		Username:        "b8_bad_create",
		Enabled:         true,
		SubToken:        "sub-b8-bad",
		SSUPSK16:        "k16-b8-bad",
		SSUPSK32:        "k32-b8-bad",
		STLSPassword:    "stls-b8-bad",
		BillingResetDay: 1,
	}
	if _, err := s.CreateUserWithNodes(ctx, badUser, []int64{n1.ID, 999999}); !errors.Is(err, ErrForeignKey) {
		t.Fatalf("CreateUserWithNodes FK: expected ErrForeignKey, got %v", err)
	}
	if badUser.ID != 0 {
		t.Fatalf("expected rolled-back user ID=0, got %d", badUser.ID)
	}
	if _, err := s.GetUserByUsername(ctx, "b8_bad_create"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected rolled-back user absent, got %v", err)
	}

	// 2. Create two valid users on n1.
	alice := &User{
		Username:        "b8_alice",
		Enabled:         true,
		SubToken:        "sub-b8-alice",
		SSUPSK16:        "k16-b8-alice",
		SSUPSK32:        "k32-b8-alice",
		STLSPassword:    "stls-b8-alice",
		BillingResetDay: 1,
	}
	if assigned, err := s.CreateUserWithNodes(ctx, alice, []int64{n1.ID}); err != nil || len(assigned) != 1 || assigned[0] != n1.ID {
		t.Fatalf("CreateUserWithNodes alice: assigned=%v err=%v", assigned, err)
	}

	bob := &User{
		Username:          "b8_bob",
		Enabled:           true,
		SubToken:          "sub-b8-bob",
		SSUPSK16:          "k16-b8-bob",
		SSUPSK32:          "k32-b8-bob",
		STLSPassword:      "stls-b8-bob",
		TrafficQuotaBytes: 1234,
		BillingResetDay:   1,
	}
	if assigned, err := s.CreateUserWithNodes(ctx, bob, []int64{n1.ID, n1.ID}); err != nil || len(assigned) != 1 || assigned[0] != n1.ID {
		t.Fatalf("CreateUserWithNodes bob: assigned=%v err=%v", assigned, err)
	}

	assertBobIntact := func(wantUsername string, wantEnabled bool, wantQuota int64, wantResetDay int, wantNodes []int64) {
		t.Helper()
		got, err := s.GetUserByID(ctx, bob.ID)
		if err != nil {
			t.Fatalf("GetUserByID bob: %v", err)
		}
		if got.Username != wantUsername || got.Enabled != wantEnabled || got.TrafficQuotaBytes != wantQuota || got.BillingResetDay != wantResetDay {
			t.Fatalf("unexpected bob user state: %+v", got)
		}
		gotNodes, err := s.GetUserNodeIDs(ctx, bob.ID)
		if err != nil {
			t.Fatalf("GetUserNodeIDs bob: %v", err)
		}
		if len(gotNodes) != len(wantNodes) {
			t.Fatalf("expected bob nodes %v, got %v", wantNodes, gotNodes)
		}
		for i := range wantNodes {
			if gotNodes[i] != wantNodes[i] {
				t.Fatalf("expected bob nodes %v, got %v", wantNodes, gotNodes)
			}
		}
	}

	// 3. Conflict rollback: duplicate username must NOT mutate user_node_access.
	conflictTry := *bob
	conflictTry.Username = "b8_alice"
	conflictTry.Enabled = false
	conflictTry.TrafficQuotaBytes = 9999
	if _, _, err := s.UpdateUserWithNodes(ctx, &conflictTry, &[]int64{n2.ID}); !errors.Is(err, ErrConflict) {
		t.Fatalf("UpdateUserWithNodes conflict: expected ErrConflict, got %v", err)
	}
	assertBobIntact("b8_bob", true, 1234, 1, []int64{n1.ID})

	// 4. FK rollback: invalid node_id must roll back BOTH users update and user_node_access delete/insert.
	fkTry := *bob
	fkTry.Username = "b8_bob_fk"
	fkTry.Enabled = false
	fkTry.TrafficQuotaBytes = 8888
	fkTry.BillingResetDay = 15
	if _, _, err := s.UpdateUserWithNodes(ctx, &fkTry, &[]int64{n2.ID, 999999}); !errors.Is(err, ErrForeignKey) {
		t.Fatalf("UpdateUserWithNodes FK: expected ErrForeignKey, got %v", err)
	}
	assertBobIntact("b8_bob", true, 1234, 1, []int64{n1.ID})

	// 5. Invalid non-positive node_id rollback.
	negTry := *bob
	negTry.Username = "b8_bob_neg"
	if _, _, err := s.UpdateUserWithNodes(ctx, &negTry, &[]int64{0}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("UpdateUserWithNodes non-positive node_id: expected ErrInvalidArgument, got %v", err)
	}
	assertBobIntact("b8_bob", true, 1234, 1, []int64{n1.ID})

	// 6. ErrNotFound rollback.
	if _, _, err := s.UpdateUserWithNodes(ctx, &User{ID: 999999, Username: "ghost", BillingResetDay: 1}, &[]int64{n1.ID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateUserWithNodes missing: expected ErrNotFound, got %v", err)
	}

	// 7. Successful atomic update replaces nodes and returns old/new node IDs.
	goodTry := *bob
	goodTry.Username = "b8_bob_v2"
	goodTry.Enabled = false
	goodTry.TrafficQuotaBytes = 5000
	goodTry.BillingResetDay = 20
	oldIDs, newIDs, err := s.UpdateUserWithNodes(ctx, &goodTry, &[]int64{n2.ID})
	if err != nil {
		t.Fatalf("UpdateUserWithNodes valid: %v", err)
	}
	if len(oldIDs) != 1 || oldIDs[0] != n1.ID || len(newIDs) != 1 || newIDs[0] != n2.ID {
		t.Fatalf("unexpected old/new node IDs: old=%v new=%v", oldIDs, newIDs)
	}
	assertBobIntact("b8_bob_v2", false, 5000, 20, []int64{n2.ID})

	// 8. ReplaceUserNodes FK rollback preserves existing node access.
	if _, _, err := s.ReplaceUserNodes(ctx, bob.ID, []int64{n1.ID, 999999}); !errors.Is(err, ErrForeignKey) {
		t.Fatalf("ReplaceUserNodes FK: expected ErrForeignKey, got %v", err)
	}
	assertBobIntact("b8_bob_v2", false, 5000, 20, []int64{n2.ID})
}

func TestStoreCloseIdempotentAndConcurrent(t *testing.T) {
	var nilStore *Store
	if err := nilStore.Close(); err != nil {
		t.Fatalf("nil Store.Close() returned error: %v", err)
	}

	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "idempotent_close.db")
	s, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open(%q) failed: %v", dbPath, err)
	}
	if err := s.SetSetting(ctx, "close_test", "1"); err != nil {
		t.Fatalf("SetSetting failed: %v", err)
	}

	const workers = 8
	start := make(chan struct{})
	errs := make([]error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		idx := i
		go func() {
			defer wg.Done()
			<-start
			errs[idx] = s.Close()
		}()
	}
	close(start)
	wg.Wait()

	for i, closeErr := range errs {
		if closeErr != nil {
			t.Fatalf("concurrent Close #%d failed: %v", i, closeErr)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("subsequent Close() failed: %v", err)
	}
}

func TestNodeCumulativeTotalsAndUserNodeBreakdown(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	n1 := &Node{Name: "Node-Small", RegionTag: "HK", TokenHash: "h_tot_1", Enabled: true, Status: protocol.NodeStatusOnline}
	n2 := &Node{Name: "Node-Big", RegionTag: "SG", TokenHash: "h_tot_2", Enabled: true, Status: protocol.NodeStatusOnline}
	if err := s.CreateNode(ctx, n1); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateNode(ctx, n2); err != nil {
		t.Fatal(err)
	}
	u := &User{
		Username:        "user_bk",
		Enabled:         true,
		SubToken:        "sub_u_bk",
		SSUPSK16:        "AAAAAAAAAAAAAAAAAAAAAA==",
		SSUPSK32:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		STLSPassword:    "pw",
		BillingResetDay: 1,
	}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}

	if _, err := s.ApplyTrafficDeltas(ctx, n1.ID, 100, 200, []protocol.UserTrafficDelta{
		{UserID: u.ID, UpBytes: 300, DownBytes: 500},
	}, "2026-11-24"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyTrafficDeltas(ctx, n2.ID, 400, 600, []protocol.UserTrafficDelta{
		{UserID: u.ID, UpBytes: 1200, DownBytes: 3800},
	}, "2026-11-24"); err != nil {
		t.Fatal(err)
	}

	// Resetting cycle traffic preserves total_rx_bytes / total_tx_bytes on nodes.
	if err := s.ResetNodeCycleTraffic(ctx, n1.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	gotN1, err := s.GetNodeByID(ctx, n1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotN1.CycleRxBytes != 0 || gotN1.CycleTxBytes != 0 || gotN1.TotalRxBytes != 100 || gotN1.TotalTxBytes != 200 {
		t.Fatalf("unexpected node totals after cycle reset: %+v", gotN1)
	}

	// User per-node breakdown sorted descending by total bytes.
	entries, err := s.ListUserNodeTraffic(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].NodeID != n2.ID || entries[0].TotalBytes != 5000 ||
		entries[1].NodeID != n1.ID || entries[1].TotalBytes != 800 {
		t.Fatalf("unexpected descending breakdown: %+v", entries)
	}

	// ResetUserTraffic clears per-node breakdown too.
	if err := s.ResetUserTraffic(ctx, u.ID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	entriesAfter, err := s.ListUserNodeTraffic(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(entriesAfter) != 0 {
		t.Fatalf("expected breakdown cleared on ResetUserTraffic, got %+v", entriesAfter)
	}

	// ServerChan webhook creation works against migration v2 schema CHECK constraint.
	whSC := &WebhookChannel{
		Name:             "ServerChan",
		Provider:         protocol.WebhookProviderServerChan,
		URL:              "https://sctapi.ftqq.com/SCT12345.send",
		SubscribedEvents: []string{"*"},
		Enabled:          true,
	}
	if err := s.CreateWebhookChannel(ctx, whSC); err != nil {
		t.Fatalf("CreateWebhookChannel serverchan failed: %v", err)
	}
}

func TestTrafficUsageLogsMinuteAggregationAndRetention(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	n1 := &Node{Name: "Log-Node-1", RegionTag: "SG", TokenHash: "hash_log_n1", Enabled: true}
	n2 := &Node{Name: "Log-Node-2", RegionTag: "JP", TokenHash: "hash_log_n2", Enabled: true}
	if err := s.CreateNode(ctx, n1); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateNode(ctx, n2); err != nil {
		t.Fatal(err)
	}
	u := &User{
		Username:        "log_user",
		Enabled:         true,
		SubToken:        "sub_log_1",
		SSUPSK16:        "AAAAAAAAAAAAAAAAAAAAAA==",
		SSUPSK32:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		STLSPassword:    "pw",
		BillingResetDay: 1,
	}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}

	t1 := time.Date(2026, 11, 24, 10, 5, 12, 0, time.UTC)
	t1SameMin := time.Date(2026, 11, 24, 10, 5, 49, 0, time.UTC)
	t2 := time.Date(2026, 11, 24, 10, 6, 3, 0, time.UTC)

	if _, err := s.ApplyTrafficDeltasAt(ctx, n1.ID, 100, 200, []protocol.UserTrafficDelta{
		{UserID: u.ID, UpBytes: 10, DownBytes: 20},
	}, t1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyTrafficDeltasAt(ctx, n1.ID, 100, 200, []protocol.UserTrafficDelta{
		{UserID: u.ID, UpBytes: 30, DownBytes: 40},
	}, t1SameMin); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyTrafficDeltasAt(ctx, n2.ID, 50, 60, []protocol.UserTrafficDelta{
		{UserID: u.ID, UpBytes: 500, DownBytes: 600},
	}, t2); err != nil {
		t.Fatal(err)
	}

	logs, err := s.QueryTrafficUsageLogs(ctx, TrafficUsageLogFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 2 {
		t.Fatalf("expected 2 merged minute log rows, got %d (%+v)", len(logs), logs)
	}
	if logs[0].NodeID != n2.ID || logs[0].NodeName != "Log-Node-2" || logs[0].Username != "log_user" ||
		logs[0].LogMinute != "2026-11-24T10:06:00Z" || logs[0].RxBytes != 600 || logs[0].TxBytes != 500 {
		t.Fatalf("unexpected newest log row: %+v", logs[0])
	}
	if logs[1].NodeID != n1.ID || logs[1].LogMinute != "2026-11-24T10:05:00Z" || logs[1].RxBytes != 60 || logs[1].TxBytes != 40 {
		t.Fatalf("unexpected merged minute row: %+v", logs[1])
	}

	// Filter by node_id and time window
	n1Only, err := s.QueryTrafficUsageLogs(ctx, TrafficUsageLogFilter{
		NodeID: n1.ID,
		From:   "2026-11-24T10:05:00Z",
		To:     "2026-11-24T10:05:59Z",
	})
	if err != nil || len(n1Only) != 1 || n1Only[0].NodeID != n1.ID {
		t.Fatalf("unexpected filtered query: err=%v logs=%+v", err, n1Only)
	}

	// Automatic pruning respects traffic_log_max_entries setting
	if err := s.SetSetting(ctx, "traffic_log_max_entries", "3"); err != nil {
		t.Fatal(err)
	}
	for m := 7; m <= 9; m++ {
		ts := time.Date(2026, 11, 24, 10, m, 0, 0, time.UTC)
		if _, err := s.ApplyTrafficDeltasAt(ctx, n1.ID, 1, 1, []protocol.UserTrafficDelta{
			{UserID: u.ID, UpBytes: 1, DownBytes: 1},
		}, ts); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.PruneConfiguredTrafficUsageLogs(ctx); err != nil {
		t.Fatal(err)
	}
	cnt, err := s.CountTrafficUsageLogs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cnt != 3 {
		t.Fatalf("expected 3 logs retained after auto-prune, got %d", cnt)
	}
	rem, err := s.QueryTrafficUsageLogs(ctx, TrafficUsageLogFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rem) != 3 || rem[0].LogMinute != "2026-11-24T10:09:00Z" || rem[2].LogMinute != "2026-11-24T10:07:00Z" {
		t.Fatalf("expected newest 3 minute buckets kept, got %+v", rem)
	}

	pruned, err := s.PruneTrafficUsageLogs(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 2 {
		t.Fatalf("expected PruneTrafficUsageLogs(1) to delete 2 rows, deleted %d", pruned)
	}

	// Admin Snell traffic recording + QueryTrafficUsageLogs + ResetAdminTraffic
	tsAdmin := time.Date(2026, 11, 24, 11, 0, 15, 0, time.UTC)
	if err := s.RecordAdminSnellTraffic(ctx, n1.ID, 4096, tsAdmin); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAdminSnellTraffic(ctx, n2.ID, 8192, tsAdmin); err != nil {
		t.Fatal(err)
	}
	adminTotal, adminItems, err := s.ListAdminNodeTraffic(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if adminTotal != 12288 || len(adminItems) != 2 || adminItems[0].NodeID != n2.ID || adminItems[0].TotalBytes != 8192 {
		t.Fatalf("unexpected admin node traffic breakdown: total=%d items=%+v", adminTotal, adminItems)
	}
	logsWithAdmin, err := s.QueryTrafficUsageLogs(ctx, TrafficUsageLogFilter{})
	if err != nil {
		t.Fatal(err)
	}
	foundAdminLog := false
	for _, l := range logsWithAdmin {
		if l.UserID == 0 && l.Username == "管理员 (Snell)" {
			foundAdminLog = true
			break
		}
	}
	if !foundAdminLog {
		t.Fatalf("expected admin usage log entry (user_id=0), got %+v", logsWithAdmin)
	}
	if err := s.ResetAdminTraffic(ctx); err != nil {
		t.Fatal(err)
	}
	adminTotalAfter, adminItemsAfter, err := s.ListAdminNodeTraffic(ctx)
	if err != nil || adminTotalAfter != 0 || len(adminItemsAfter) != 0 {
		t.Fatalf("expected reset admin traffic to zero, got total=%d items=%+v err=%v", adminTotalAfter, adminItemsAfter, err)
	}
}

func TestTrafficUsageLogsUserFilterAndMerge(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	n1 := &Node{Name: "Merge-Node-1", RegionTag: "SG", TokenHash: "hash_merge_n1", Enabled: true}
	n2 := &Node{Name: "Merge-Node-2", RegionTag: "JP", TokenHash: "hash_merge_n2", Enabled: true}
	if err := s.CreateNode(ctx, n1); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateNode(ctx, n2); err != nil {
		t.Fatal(err)
	}

	u1 := &User{
		Username:        "merge_alice",
		Enabled:         true,
		SubToken:        "sub_merge_1",
		SSUPSK16:        "AAAAAAAAAAAAAAAAAAAAAA==",
		SSUPSK32:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		STLSPassword:    "pw",
		BillingResetDay: 1,
	}
	if err := s.CreateUser(ctx, u1); err != nil {
		t.Fatal(err)
	}

	// Session 1 for u1 on n1: 10:00, 10:02, 10:05 (gaps 2m and 3m <= 5m) -> should merge [10:00..10:05]
	// Session 2 for u1 on n1: 10:15 (gap 10m > 5m) -> separate row [10:15..10:15]
	// Different node (n2) for u1 at 10:01 -> must NOT merge with n1
	// Admin Snell (user_id=0) on n1 at 10:01 -> must NOT merge with u1
	base := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	for _, offsetMin := range []int{0, 2, 5, 15} {
		if _, err := s.ApplyTrafficDeltasAt(ctx, n1.ID, 10, 10, []protocol.UserTrafficDelta{
			{UserID: u1.ID, UpBytes: 100, DownBytes: 200},
		}, base.Add(time.Duration(offsetMin)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.ApplyTrafficDeltasAt(ctx, n2.ID, 10, 10, []protocol.UserTrafficDelta{
		{UserID: u1.ID, UpBytes: 50, DownBytes: 60},
	}, base.Add(1*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordAdminSnellTraffic(ctx, n1.ID, 777, base.Add(1*time.Minute)); err != nil {
		t.Fatal(err)
	}

	// Filter by user_id = 0 (Admin Snell)
	var zero int64 = 0
	adminRows, err := s.QueryTrafficUsageLogs(ctx, TrafficUsageLogFilter{UserID: &zero, Merge: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(adminRows) != 1 || adminRows[0].UserID != 0 || adminRows[0].Username != "管理员 (Snell)" || adminRows[0].RxBytes != 777 {
		t.Fatalf("expected 1 admin Snell merged row, got %+v", adminRows)
	}

	// Filter by u1 + n1 + Merge:true -> 2 sessions ordered DESC by end_time
	u1MergedN1, err := s.QueryTrafficUsageLogs(ctx, TrafficUsageLogFilter{
		NodeID: n1.ID,
		UserID: &u1.ID,
		Merge:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(u1MergedN1) != 2 {
		t.Fatalf("expected 2 merged sessions for u1 on n1, got %d (%+v)", len(u1MergedN1), u1MergedN1)
	}
	// Newest session first: [10:15..10:15]
	if u1MergedN1[0].StartTime != "2026-11-25T10:15:00Z" || u1MergedN1[0].EndTime != "2026-11-25T10:15:00Z" ||
		u1MergedN1[0].RxBytes != 200 || u1MergedN1[0].TxBytes != 100 {
		t.Fatalf("unexpected newest merged session: %+v", u1MergedN1[0])
	}
	// Earlier continuous session: [10:00..10:05] with 3 buckets summed (600 RX, 300 TX)
	if u1MergedN1[1].StartTime != "2026-11-25T10:00:00Z" || u1MergedN1[1].EndTime != "2026-11-25T10:05:00Z" ||
		u1MergedN1[1].RxBytes != 600 || u1MergedN1[1].TxBytes != 300 {
		t.Fatalf("unexpected continuous merged session: %+v", u1MergedN1[1])
	}

	// Filter all users & nodes merged -> 4 rows total (2 u1/n1, 1 u1/n2, 1 admin/n1)
	allMerged, err := s.QueryTrafficUsageLogs(ctx, TrafficUsageLogFilter{Merge: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(allMerged) != 4 {
		t.Fatalf("expected 4 total merged rows across nodes/users, got %d (%+v)", len(allMerged), allMerged)
	}
}

func TestQueryTrafficUsageLogs_MergeExceeds5000Rows(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	n1 := &Node{Name: "Merge5k-N1", RegionTag: "HK", TokenHash: "hash_m5k_n1", Enabled: true}
	if err := s.CreateNode(ctx, n1); err != nil {
		t.Fatal(err)
	}
	u1 := &User{
		Username:        "m5k_u1",
		Enabled:         true,
		SubToken:        "sub_m5k_u1",
		SSUPSK16:        "AAAAAAAAAAAAAAAAAAAAAA==",
		SSUPSK32:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		STLSPassword:    "pw",
		BillingResetDay: 1,
	}
	u2 := &User{
		Username:        "m5k_u2",
		Enabled:         true,
		SubToken:        "sub_m5k_u2",
		SSUPSK16:        "AAAAAAAAAAAAAAAAAAAAAA==",
		SSUPSK32:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		STLSPassword:    "pw",
		BillingResetDay: 1,
	}
	if err := s.CreateUser(ctx, u1); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, u2); err != nil {
		t.Fatal(err)
	}

	// Insert:
	// - u1: 1 older session (10 mins) far beyond row 5,000, AND 1 huge continuous session spanning 5,200 consecutive minutes.
	// - u2: 600 distinct sessions (each 2 mins separated by 10m gaps) interleaving across the timeline so we test both
	//   long session spanning >5000 rows and top-outLimit early-stop accuracy.
	tx, err := s.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO traffic_usage_logs(node_id, user_id, log_minute, rx_bytes, tx_bytes, updated_at)
VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		t.Fatal(err)
	}

	var allRaw []TrafficUsageLog
	var nextID int64
	insertRow := func(uid int64, uname string, ts time.Time, rx, txBytes int64) {
		minStr := ts.UTC().Format("2006-01-02T15:04:00Z")
		res, err := stmt.ExecContext(ctx, n1.ID, uid, minStr, rx, txBytes, minStr)
		if err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		nextID = id
		_ = nextID
		allRaw = append(allRaw, TrafficUsageLog{
			ID:        id,
			NodeID:    n1.ID,
			NodeName:  n1.Name,
			RegionTag: n1.RegionTag,
			UserID:    uid,
			Username:  uname,
			LogMinute: minStr,
			RxBytes:   rx,
			TxBytes:   txBytes,
			UpdatedAt: minStr,
		})
	}

	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	// Older u1 session before the 5200-minute session (15-min gap before base+100m).
	for m := 0; m < 10; m++ {
		insertRow(u1.ID, u1.Username, base.Add(time.Duration(m)*time.Minute), 100, 50)
	}
	// Long continuous 5,200-minute session for u1 (starts at base+100m).
	longStart := base.Add(100 * time.Minute)
	for m := 0; m < 5200; m++ {
		insertRow(u1.ID, u1.Username, longStart.Add(time.Duration(m)*time.Minute), 10, 20)
	}
	// 550 distinct sessions for u2 (2 minutes each, 10 minutes apart).
	for sIdx := 0; sIdx < 550; sIdx++ {
		st := longStart.Add(time.Duration(sIdx*10) * time.Minute)
		insertRow(u2.ID, u2.Username, st, 300, 400)
		insertRow(u2.ID, u2.Username, st.Add(time.Minute), 300, 400)
	}
	_ = stmt.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// 1. Query u1 specifically -> must see BOTH sessions (the 5200-minute session intact + the older 10-minute session beyond row 5000).
	u1Got, err := s.QueryTrafficUsageLogs(ctx, TrafficUsageLogFilter{
		UserID:          &u1.ID,
		Limit:           500,
		Merge:           true,
		MergeGapMinutes: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(u1Got) != 2 {
		t.Fatalf("expected 2 merged sessions for u1 across >5200 rows, got %d (%+v)", len(u1Got), u1Got)
	}
	if u1Got[0].RxBytes != 5200*10 || u1Got[0].TxBytes != 5200*20 ||
		u1Got[0].StartTime != longStart.Format("2006-01-02T15:04:00Z") ||
		u1Got[0].EndTime != longStart.Add(5199*time.Minute).Format("2006-01-02T15:04:00Z") {
		t.Fatalf("5200-minute session truncated or mis-merged: %+v", u1Got[0])
	}
	if u1Got[1].RxBytes != 10*100 || u1Got[1].TxBytes != 10*50 {
		t.Fatalf("older session beyond row 5000 lost or mis-merged: %+v", u1Got[1])
	}

	// 2. Query all users with limit=500 and compare against full-memory reference oracle mergeTrafficUsageLogs.
	allGot, err := s.QueryTrafficUsageLogs(ctx, TrafficUsageLogFilter{
		Limit:           500,
		Merge:           true,
		MergeGapMinutes: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantOracle := mergeTrafficUsageLogs(allRaw, 5, 500)
	if len(allGot) != len(wantOracle) || len(allGot) != 500 {
		t.Fatalf("expected 500 merged sessions matching oracle, got len=%d oracle=%d", len(allGot), len(wantOracle))
	}
	for i := range wantOracle {
		if allGot[i] != wantOracle[i] {
			t.Fatalf("mismatch at merged index %d:\n got: %+v\nwant: %+v", i, allGot[i], wantOracle[i])
		}
	}
}

func TestApplyAgentMetricsAt_CombinedAndRollback(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	n := &Node{Name: "Combined-Node", RegionTag: "SG", TokenHash: "hash_comb", Enabled: true}
	if err := s.CreateNode(ctx, n); err != nil {
		t.Fatal(err)
	}
	u := &User{
		Username:        "comb_user",
		Enabled:         true,
		SubToken:        "sub_comb",
		SSUPSK16:        "AAAAAAAAAAAAAAAAAAAAAA==",
		SSUPSK32:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		STLSPassword:    "pw",
		BillingResetDay: 1,
	}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}

	ts := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	// Duplicate user entries for the same user in one slice should coalesce cleanly.
	res, err := s.ApplyAgentMetricsAt(ctx, n.ID, 1000, 2000, []protocol.UserTrafficDelta{
		{UserID: u.ID, UpBytes: 100, DownBytes: 200},
		{Username: u.Username, UpBytes: 50, DownBytes: 25},
		{UserID: 999999, UpBytes: 10, DownBytes: 10}, // deleted user skipped
	}, 4096, &NodeTelemetryUpdate{
		CPUPercent:      33.5,
		MemUsedBytes:    512,
		MemTotalBytes:   1024,
		DiskUsedPercent: 40.0,
		UptimeSeconds:   3600,
		RxBPS:           111,
		TxBPS:           222,
		CoreAHealthy:    true,
		CoreBHealthy:    true,
		LastSeenAt:      ts,
	}, ts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Node.CycleRxBytes != 1000 || res.Node.CycleTxBytes != 2000 || res.Node.CPUPercent != 33.5 || res.Node.Status != protocol.NodeStatusOnline {
		t.Fatalf("unexpected combined node result: %+v", res.Node)
	}
	if len(res.UpdatedUserIDs) != 1 || res.UpdatedUserIDs[0] != u.ID || len(res.SkippedUserIDs) != 1 || res.SkippedUserIDs[0] != 999999 {
		t.Fatalf("unexpected user IDs: updated=%v skipped=%v", res.UpdatedUserIDs, res.SkippedUserIDs)
	}
	gotUser, err := s.GetUserByID(ctx, u.ID)
	if err != nil || gotUser.UsedUpBytes != 150 || gotUser.UsedDownBytes != 225 {
		t.Fatalf("expected coalesced user traffic up=150 down=225, got %+v err=%v", gotUser, err)
	}
	adminTotal, _, err := s.ListAdminNodeTraffic(ctx)
	if err != nil || adminTotal != 4096 {
		t.Fatalf("expected admin Snell traffic=4096, got %d err=%v", adminTotal, err)
	}
}

func TestStoreCloseFastUnderWALReadLockAndCanceledQuery(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "close_fast.db")
	s, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() {
		_ = s.Close()
	}()

	n := &Node{Name: "CloseFastNode", TokenHash: "hash_close_fast", Enabled: true}
	if err := s.CreateNode(ctx, n); err != nil {
		t.Fatalf("CreateNode failed: %v", err)
	}

	// Open a second SQLite reader holding a WAL read snapshot so PRAGMA wal_checkpoint(TRUNCATE)
	// hits _walBusyLock; Store.Close() must not sleep for busy_timeout (5000ms).
	readerDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open reader failed: %v", err)
	}
	defer readerDB.Close()

	tx, err := readerDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatalf("reader BeginTx failed: %v", err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes`).Scan(&count); err != nil {
		_ = tx.Rollback()
		t.Fatalf("reader query failed: %v", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// Write another WAL frame after the reader snapshot started so checkpoint(TRUNCATE) is blocked.
	if err := s.SetSetting(ctx, "wal_frame_after_snapshot", "1"); err != nil {
		t.Fatalf("SetSetting failed: %v", err)
	}

	// Also exercise a canceled query immediately prior to Close().
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	_, _ = s.GetNodeByID(canceledCtx, n.ID)

	start := time.Now()
	if err := s.Close(); err != nil {
		t.Fatalf("Store.Close() failed: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed >= 500*time.Millisecond {
		t.Fatalf("Store.Close() blocked too long under WAL read lock: %s (want < 500ms)", elapsed)
	}
}

func TestUpdateNodeTx_ConcurrentAtomicMerge(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	n := &Node{
		Name:      "AtomicNode",
		TokenHash: "hash_atomic_tx",
		Enabled:   true,
		SnellConfig: protocol.SnellConfig{
			Enabled:    true,
			Version:    protocol.SnellVersionV5,
			PublicPort: 20001,
			InnerPort:  31001,
			PSK:        "psk-atomic",
			TFO:        true,
			STLSSNI:    "init-snell.example.com",
		},
		SSConfig: protocol.SSConfig{
			Enabled: true,
			TCPPort: 20002,
			UDPPort: 20002,
			Cipher:  protocol.CipherAES128GCM,
			IPSK:    "AAAAAAAAAAAAAAAAAAAAAA==",
			TFO:     true,
			STLSSNI: "init-ss.example.com",
		},
		ConfigRevision: 1,
	}
	if err := s.CreateNode(ctx, n); err != nil {
		t.Fatalf("CreateNode failed: %v", err)
	}

	const rounds = 25
	seenRevs := make(map[int64]struct{}, rounds*2)
	for r := 0; r < rounds; r++ {
		wantSnell := fmt.Sprintf("snell-%02d.example.com", r)
		wantSS := fmt.Sprintf("ss-%02d.example.com", r)

		barrier := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)

		var err1, err2 error
		var c1, c2 *Node

		go func() {
			defer wg.Done()
			<-barrier
			c1, err1 = s.UpdateNodeTx(ctx, n.ID, func(existing *Node) (*Node, error) {
				upd := *existing
				upd.SnellConfig.STLSSNI = wantSnell
				upd.ConfigRevision = existing.ConfigRevision + 1
				return &upd, nil
			})
		}()

		go func() {
			defer wg.Done()
			<-barrier
			c2, err2 = s.UpdateNodeTx(ctx, n.ID, func(existing *Node) (*Node, error) {
				upd := *existing
				upd.SSConfig.STLSSNI = wantSS
				upd.ConfigRevision = existing.ConfigRevision + 1
				return &upd, nil
			})
		}()

		close(barrier)
		wg.Wait()

		if err1 != nil || err2 != nil {
			t.Fatalf("round %d UpdateNodeTx failed: err1=%v err2=%v", r, err1, err2)
		}
		if c1.ConfigRevision == c2.ConfigRevision {
			t.Fatalf("round %d duplicate ConfigRevision: %d", r, c1.ConfigRevision)
		}
		if _, dup := seenRevs[c1.ConfigRevision]; dup {
			t.Fatalf("round %d c1 reused ConfigRevision %d", r, c1.ConfigRevision)
		}
		if _, dup := seenRevs[c2.ConfigRevision]; dup {
			t.Fatalf("round %d c2 reused ConfigRevision %d", r, c2.ConfigRevision)
		}
		seenRevs[c1.ConfigRevision] = struct{}{}
		seenRevs[c2.ConfigRevision] = struct{}{}

		got, err := s.GetNodeByID(ctx, n.ID)
		if err != nil {
			t.Fatalf("round %d GetNodeByID failed: %v", r, err)
		}
		if got.SnellConfig.STLSSNI != wantSnell || got.SSConfig.STLSSNI != wantSS {
			t.Fatalf("round %d lost update: got snell=%q (want %q), ss=%q (want %q)",
				r, got.SnellConfig.STLSSNI, wantSnell, got.SSConfig.STLSSNI, wantSS)
		}
		if !got.SnellConfig.TFO || !got.SSConfig.TFO {
			t.Fatalf("round %d lost TFO flags: snell=%v ss=%v", r, got.SnellConfig.TFO, got.SSConfig.TFO)
		}
	}
}
