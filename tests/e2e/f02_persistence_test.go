//go:build e2e

package e2e_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func openSQLiteReadOnly(t *testing.T, dbPath string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	if err != nil {
		t.Fatalf("open sqlite read-only %s: %v", dbPath, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestF02_Tier1_FreshBootstrapAutoMigrationAndSeeds(t *testing.T) {
	env := NewTestEnv(t)
	dbPath := filepath.Join(env.RootDir, "nested", "panel.db")
	panel := StartPanel(env, PanelConfig{DBPath: dbPath})
	client := panel.NewClient()

	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	st, tpls, raw, err := client.ListTemplates(jwt)
	if err != nil || st != http.StatusOK {
		t.Fatalf("ListTemplates failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	seenTypes := map[string]bool{}
	for _, tpl := range tpls {
		seenTypes[tpl.ClientType] = true
	}
	for _, reqType := range []string{"surge_admin", "mihomo_user", "surge_user"} {
		if !seenTypes[reqType] {
			t.Fatalf("missing default template client_type %q; got %+v", reqType, tpls)
		}
	}

	st, settings, raw, err := client.GetSettings(jwt)
	if err != nil || st != http.StatusOK {
		t.Fatalf("GetSettings failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	if settings.AdminSubToken == "" {
		t.Fatalf("expected seeded admin_sub_token, got empty")
	}

	if err := panel.Stop(); err != nil {
		t.Fatalf("panel.Stop: %v", err)
	}

	db := openSQLiteReadOnly(t, dbPath)
	var journalMode string
	if err := db.QueryRow("PRAGMA journal_mode;").Scan(&journalMode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if journalMode != "wal" {
		t.Fatalf("expected WAL journal_mode, got %q", journalMode)
	}

	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table'")
	if err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}
	defer rows.Close()
	tables := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err == nil {
			tables[name] = true
		}
	}
	for _, tbl := range []string{
		"nodes", "users", "user_node_access", "user_node_traffic", "admin_node_traffic", "dns_rule_groups",
		"traffic_logs_daily", "traffic_usage_logs", "sub_templates", "webhook_channels", "system_settings",
	} {
		if !tables[tbl] {
			t.Fatalf("missing expected SQLite table %q (present=%v)", tbl, tables)
		}
	}
}

func TestF02_Tier1_RestartDurabilityAllEntities(t *testing.T) {
	env := NewTestEnv(t)
	dbPath := filepath.Join(env.RootDir, "panel.db")
	panel := StartPanel(env, PanelConfig{DBPath: dbPath})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, dnsGrp, _, err := client.CreateDNSRuleGroup(jwt, "PersistDNS", []string{"netflix.com", "^hulu.com"})
	if err != nil {
		t.Fatal(err)
	}
	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:             "PersistNode",
		RegionTag:        "JP",
		PublicIP:         "203.0.113.50",
		Enabled:          boolPtr(true),
		DNSUnlockEnabled: true,
		DNSUnlockServer:  "198.51.100.10:3535",
		DNSRuleGroupID:   &dnsGrp.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, user, _, err := client.CreateUser(jwt, CreateUserReq{
		Username:          "persist_user",
		TrafficQuotaBytes: 100 << 30,
		BillingResetDay:   15,
		NodeIDs:           []int64{node.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, tpl, _, err := client.CreateTemplate(jwt, SubTemplateDTO{
		Name:       "PersistMihomo",
		ClientType: "mihomo_user",
		Content:    "proxies:\n{{PROXIES}}\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, wh, _, err := client.CreateWebhook(jwt, WebhookChannelDTO{
		Name:             "PersistHook",
		Provider:         "custom",
		URL:              "https://example.invalid/hook",
		SubscribedEvents: []string{"node_offline"},
		Enabled:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	st, raw, err := client.UpdateSettings(jwt, map[string]any{
		"site_title":      "Persisted Panel Title",
		"announcement":    "Scheduled maintenance",
		"percentage_only": true,
	})
	if err != nil || st < 200 || st >= 300 {
		t.Fatalf("UpdateSettings failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	if err := panel.Stop(); err != nil {
		t.Fatalf("panel.Stop: %v", err)
	}

	panel2 := StartPanel(env, PanelConfig{DBPath: dbPath})
	client2 := panel2.NewClient()
	jwt2 := client2.MustLogin(t, "admin", "change_me_on_first_login")

	_, gotNode, _, err := client2.GetNode(jwt2, node.ID)
	if err != nil || gotNode.Name != "PersistNode" || gotNode.DNSRuleGroupID == nil || *gotNode.DNSRuleGroupID != dnsGrp.ID {
		t.Fatalf("node did not persist cleanly: node=%+v err=%v", gotNode, err)
	}
	_, gotUser, _, err := client2.GetUser(jwt2, user.ID)
	if err != nil || gotUser.Username != "persist_user" || gotUser.SubToken != user.SubToken || gotUser.SSUPSK16 != user.SSUPSK16 || gotUser.SSUPSK32 != user.SSUPSK32 {
		t.Fatalf("user credentials did not persist: got=%+v want=%+v err=%v", gotUser, user, err)
	}
	_, grps, _, err := client2.ListDNSRuleGroups(jwt2)
	if err != nil || len(grps) == 0 {
		t.Fatalf("DNS rule groups did not persist: %v", err)
	}
	_, tpls, _, err := client2.ListTemplates(jwt2)
	if err != nil {
		t.Fatal(err)
	}
	foundTpl := false
	for _, x := range tpls {
		if x.ID == tpl.ID && x.Name == "PersistMihomo" {
			foundTpl = true
		}
	}
	if !foundTpl {
		t.Fatalf("custom template %d not persisted across restart", tpl.ID)
	}
	_, hooks, _, err := client2.ListWebhooks(jwt2)
	if err != nil {
		t.Fatal(err)
	}
	foundHook := false
	for _, x := range hooks {
		if x.ID == wh.ID && x.Name == "PersistHook" {
			foundHook = true
		}
	}
	if !foundHook {
		t.Fatalf("webhook channel %d not persisted across restart", wh.ID)
	}
	_, snap, _, err := client2.GetPublicStatus()
	if err != nil || snap.SiteTitle != "Persisted Panel Title" || snap.Announcement != "Scheduled maintenance" || !snap.PercentageOnly {
		t.Fatalf("public settings did not persist: snap=%+v err=%v", snap, err)
	}
}

func TestF02_Tier1_TrafficCountersAndDailyLogsSurviveRestart(t *testing.T) {
	env := NewTestEnv(t)
	dbPath := filepath.Join(env.RootDir, "panel.db")
	panel := StartPanel(env, PanelConfig{DBPath: dbPath})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:              "TrafficPersistNode",
		Enabled:           boolPtr(true),
		TrafficLimitBytes: 10 << 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, user, _, err := client.CreateUser(jwt, CreateUserReq{
		Username: "traffic_user",
		NodeIDs:  []int64{node.ID},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	_ = SendWSEnvelope(ctx, ws, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	_, _, _ = ReadWSEnvelope(ctx, ws, 3*time.Second)

	if err := SendWSEnvelope(ctx, ws, "agent.metrics", "m1", AgentMetricsPayload{
		TS:         time.Now().Unix(),
		NicRxDelta: 1234567,
		NicTxDelta: 2345678,
		UserDeltas: []UserTrafficDeltaDTO{
			{Username: user.Username, UserID: user.ID, UpBytes: 111111, DownBytes: 222222},
		},
		Health: AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}
	_ = ws.CloseNow()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, gotN, _, _ := client.GetNode(jwt, node.ID)
		_, gotU, _, _ := client.GetUser(jwt, user.ID)
		if gotN.CycleRxBytes >= 1234567 && gotN.CycleTxBytes >= 2345678 && gotU.UsedUpBytes >= 111111 && gotU.UsedDownBytes >= 222222 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if err := panel.Stop(); err != nil {
		t.Fatal(err)
	}

	panel2 := StartPanel(env, PanelConfig{DBPath: dbPath})
	client2 := panel2.NewClient()
	jwt2 := client2.MustLogin(t, "admin", "change_me_on_first_login")

	_, gotN, _, err := client2.GetNode(jwt2, node.ID)
	if err != nil || gotN.CycleRxBytes != 1234567 || gotN.CycleTxBytes != 2345678 {
		t.Fatalf("node cycle traffic lost across restart: %+v err=%v", gotN, err)
	}
	_, gotU, _, err := client2.GetUser(jwt2, user.ID)
	if err != nil || gotU.UsedUpBytes != 111111 || gotU.UsedDownBytes != 222222 {
		t.Fatalf("user traffic lost across restart: %+v err=%v", gotU, err)
	}
	st, logs, raw, err := client2.ListDailyTraffic(jwt2, "")
	if err != nil || st != http.StatusOK || len(logs) == 0 {
		t.Fatalf("daily traffic logs missing after restart: st=%d len=%d err=%v body=%s", st, len(logs), err, string(raw))
	}
}

func TestF02_Tier1_ForeignKeyCascadeOnDelete(t *testing.T) {
	env := NewTestEnv(t)
	dbPath := filepath.Join(env.RootDir, "panel.db")
	panel := StartPanel(env, PanelConfig{DBPath: dbPath})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{Name: "CascadeNode", Enabled: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	_, user1, _, err := client.CreateUser(jwt, CreateUserReq{Username: "cascade_u1", NodeIDs: []int64{node.ID}})
	if err != nil {
		t.Fatal(err)
	}
	_, user2, _, err := client.CreateUser(jwt, CreateUserReq{Username: "cascade_u2", NodeIDs: []int64{node.ID}})
	if err != nil {
		t.Fatal(err)
	}

	// Delete user1 -> node remains intact
	if st, raw, err := client.DeleteUser(jwt, user1.ID); err != nil || st >= 300 {
		t.Fatalf("DeleteUser failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	if st, _, _, err := client.GetNode(jwt, node.ID); err != nil || st != http.StatusOK {
		t.Fatalf("GetNode after user delete failed: st=%d err=%v", st, err)
	}

	// Delete node -> user2 remains intact
	if st, raw, err := client.DeleteNode(jwt, node.ID); err != nil || st >= 300 {
		t.Fatalf("DeleteNode failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	if st, _, _, err := client.GetUser(jwt, user2.ID); err != nil || st != http.StatusOK {
		t.Fatalf("GetUser after node delete failed: st=%d err=%v", st, err)
	}

	_ = panel.Stop()
	db := openSQLiteReadOnly(t, dbPath)
	var orphans int
	if err := db.QueryRow("SELECT COUNT(*) FROM user_node_access WHERE user_id = ? OR node_id = ?", user1.ID, node.ID).Scan(&orphans); err != nil {
		t.Fatalf("query user_node_access: %v", err)
	}
	if orphans != 0 {
		t.Fatalf("expected 0 orphan rows in user_node_access, got %d", orphans)
	}
}

func TestF02_Tier1_IdempotentMigrationsPreservesChangedAdminPass(t *testing.T) {
	env := NewTestEnv(t)
	dbPath := filepath.Join(env.RootDir, "panel.db")
	p1 := StartPanel(env, PanelConfig{DBPath: dbPath, AdminPass: "initial_pass_1"})
	c1 := p1.NewClient()
	jwt := c1.MustLogin(t, "admin", "initial_pass_1")

	st, raw, err := c1.UpdatePassword(jwt, "initial_pass_1", "rotated_pass_2")
	if err != nil || st >= 300 {
		t.Fatalf("UpdatePassword failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	_ = p1.Stop()

	for i := 0; i < 2; i++ {
		pN := StartPanel(env, PanelConfig{DBPath: dbPath, AdminPass: "initial_pass_1"})
		cN := pN.NewClient()

		oldSt, _, _, _ := cN.Login("admin", "initial_pass_1")
		if oldSt != http.StatusUnauthorized {
			t.Fatalf("restart #%d: expected old initial_pass_1 to fail with 401, got %d", i+1, oldSt)
		}
		_ = cN.MustLogin(t, "admin", "rotated_pass_2")
		_ = pN.Stop()
	}
}

func TestF02_Tier2_InvalidDBPathFailsCleanly(t *testing.T) {
	env := NewTestEnv(t)
	blocker := filepath.Join(env.RootDir, "not_a_dir")
	if err := os.WriteFile(blocker, []byte("file"), 0o644); err != nil {
		t.Fatal(err)
	}
	badDBPath := filepath.Join(blocker, "panel.db")
	code, logs, err := StartPanelExpectFail(env, PanelConfig{DBPath: badDBPath}, 10*time.Second)
	if err == nil || code == 0 {
		t.Fatalf("expected non-zero exit when DBPath parent is a file, got code=%d logs=%s", code, logs)
	}
}

func TestF02_Tier2_UniqueConstraintConflictReturns4xx(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	st, _, raw, err := client.CreateUser(jwt, CreateUserReq{Username: "unique_alice"})
	if err != nil || st >= 300 {
		t.Fatalf("first CreateUser failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	st2, _, raw2, err := client.CreateUser(jwt, CreateUserReq{Username: "unique_alice"})
	if err != nil {
		t.Fatalf("second CreateUser request error: %v", err)
	}
	if st2 < 400 || st2 >= 500 {
		t.Fatalf("duplicate username expected 4xx, got %d (body=%s)", st2, string(raw2))
	}
	_, users, _, err := client.ListUsers(jwt)
	if err != nil || len(users) != 1 {
		t.Fatalf("expected exactly 1 user after duplicate rejection, got %d (err=%v)", len(users), err)
	}
}

func TestF02_Tier2_InvalidForeignKeyRejected(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	missingGrp := int64(999999)
	st, _, raw, err := client.CreateNode(jwt, CreateNodeReq{
		Name:           "BadFKNode",
		DNSRuleGroupID: &missingGrp,
	})
	if err != nil {
		t.Fatal(err)
	}
	if st < 400 || st >= 500 {
		t.Fatalf("expected 4xx for nonexistent dns_rule_group_id, got %d (body=%s)", st, string(raw))
	}

	_, user, _, err := client.CreateUser(jwt, CreateUserReq{Username: "fk_user"})
	if err != nil {
		t.Fatal(err)
	}
	st2, raw2, err := client.SetUserNodes(jwt, user.ID, []int64{999999})
	if err != nil {
		t.Fatal(err)
	}
	if st2 < 400 || st2 >= 500 {
		t.Fatalf("expected 4xx for nonexistent node_id in user_node_access, got %d (body=%s)", st2, string(raw2))
	}
}

func TestF02_Tier2_ConcurrentReadsAndWritesUnderWAL(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	var wg sync.WaitGroup
	errCh := make(chan error, 200)

	for w := 0; w < 5; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				st, _, raw, err := client.CreateNode(jwt, CreateNodeReq{
					Name:    fmt.Sprintf("WAL-Node-%d-%d", workerID, i),
					Enabled: boolPtr(true),
				})
				if err != nil || st >= 500 || st < 200 {
					errCh <- fmt.Errorf("writer %d iter %d failed: st=%d err=%v body=%s", workerID, i, st, err, string(raw))
					return
				}
			}
		}(w)
	}

	for r := 0; r < 5; r++ {
		wg.Add(1)
		go func(readerID int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				st, _, raw, err := client.GetPublicStatus()
				if err != nil || st != http.StatusOK {
					errCh <- fmt.Errorf("public reader %d iter %d failed: st=%d err=%v body=%s", readerID, i, st, err, string(raw))
					return
				}
				st2, _, raw2, err := client.ListNodes(jwt)
				if err != nil || st2 != http.StatusOK {
					errCh <- fmt.Errorf("admin reader %d iter %d failed: st=%d err=%v body=%s", readerID, i, st2, err, string(raw2))
					return
				}
			}
		}(r)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

func TestF02_Tier2_SIGKILLCrashRecovery(t *testing.T) {
	env := NewTestEnv(t)
	dbPath := filepath.Join(env.RootDir, "panel.db")
	panel := StartPanel(env, PanelConfig{DBPath: dbPath})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{Name: "CrashSurvivor", Enabled: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	_, user, _, err := client.CreateUser(jwt, CreateUserReq{Username: "crash_user", NodeIDs: []int64{node.ID}})
	if err != nil {
		t.Fatal(err)
	}

	if err := panel.Kill(); err != nil {
		t.Logf("panel.Kill returned (expected signal exit): %v", err)
	}

	panel2 := StartPanel(env, PanelConfig{DBPath: dbPath})
	client2 := panel2.NewClient()
	jwt2 := client2.MustLogin(t, "admin", "change_me_on_first_login")

	_, gotNode, _, err := client2.GetNode(jwt2, node.ID)
	if err != nil || gotNode.Name != "CrashSurvivor" {
		t.Fatalf("node lost after SIGKILL recovery: %+v err=%v", gotNode, err)
	}
	_, gotUser, _, err := client2.GetUser(jwt2, user.ID)
	if err != nil || gotUser.Username != "crash_user" {
		t.Fatalf("user lost after SIGKILL recovery: %+v err=%v", gotUser, err)
	}
}
