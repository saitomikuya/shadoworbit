//go:build e2e

package e2e_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func f10_readNextConfigSync(t *testing.T, ctx context.Context, conn *websocket.Conn, timeout time.Duration) ServerConfigSyncPayload {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		rem := time.Until(deadline)
		if rem <= 0 {
			break
		}
		env, raw, err := ReadWSEnvelope(ctx, conn, rem)
		if err != nil {
			t.Fatalf("ReadWSEnvelope(server.config_sync) failed: %v", err)
		}
		if env.Type != "server.config_sync" {
			t.Logf("f10_readNextConfigSync: skipped %q (raw=%s)", env.Type, string(raw))
			continue
		}
		var payload ServerConfigSyncPayload
		if err := json.Unmarshal(env.Payload, &payload); err != nil {
			t.Fatalf("unmarshal server.config_sync: %v (raw=%s)", err, string(env.Payload))
		}
		return payload
	}
	t.Fatalf("timed out waiting for server.config_sync after %s", timeout)
	return ServerConfigSyncPayload{}
}

func f10_waitConfigSyncMatching(t *testing.T, ctx context.Context, conn *websocket.Conn, timeout time.Duration, pred func(ServerConfigSyncPayload) bool, desc string) ServerConfigSyncPayload {
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
			t.Fatalf("waiting for config_sync (%s) failed: %v (last=%+v)", desc, err, last)
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

func f10_findSSUser(users []SSUserEntryDTO, userID int64) (SSUserEntryDTO, bool) {
	for _, u := range users {
		if u.UserID == userID {
			return u, true
		}
	}
	return SSUserEntryDTO{}, false
}

func TestF10_Tier1_UserCRUDAndEnableDisableToggle(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:    "F10-CRUD-Node",
		Enabled: boolPtr(true),
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: 18443, UDPPort: 18443,
			Cipher: "2022-blake3-aes-128-gcm", IPSK: "AAAAAAAAAAAAAAAAAAAAAA==", STLSSNI: "swscan.apple.com",
		},
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
	initSync := f10_readNextConfigSync(t, ctx, conn, 5*time.Second)
	if len(initSync.SS.Users) != 0 {
		t.Fatalf("expected 0 initial SS users, got %+v", initSync.SS.Users)
	}

	stCreate, user, rawCreate, err := client.CreateUser(jwt, CreateUserReq{
		Username:          "alice_f10",
		Enabled:           boolPtr(true),
		TrafficQuotaBytes: 50 << 30,
		BillingResetDay:   10,
		NodeIDs:           []int64{node.ID},
	})
	if err != nil || (stCreate != http.StatusOK && stCreate != http.StatusCreated) {
		t.Fatalf("CreateUser failed: st=%d err=%v body=%s", stCreate, err, string(rawCreate))
	}
	if user.SubToken == "" || user.STLSPassword == "" {
		t.Fatalf("missing generated user tokens: %+v", user)
	}
	if b16, err := base64.StdEncoding.DecodeString(user.SSUPSK16); err != nil || len(b16) != 16 {
		t.Fatalf("invalid ss_upsk_16: %q", user.SSUPSK16)
	}
	if b32, err := base64.StdEncoding.DecodeString(user.SSUPSK32); err != nil || len(b32) != 32 {
		t.Fatalf("invalid ss_upsk_32: %q", user.SSUPSK32)
	}

	// ListUsers & GetUser
	stList, users, _, err := client.ListUsers(jwt)
	if err != nil || stList != http.StatusOK || len(users) != 1 || users[0].ID != user.ID {
		t.Fatalf("ListUsers mismatch: st=%d users=%+v err=%v", stList, users, err)
	}
	stGet, gotUser, _, err := client.GetUser(jwt, user.ID)
	if err != nil || stGet != http.StatusOK || gotUser.Username != "alice_f10" {
		t.Fatalf("GetUser mismatch: st=%d user=%+v err=%v", stGet, gotUser, err)
	}

	// Enabled user synced to agent
	f10_waitConfigSyncMatching(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		entry, ok := f10_findSSUser(p.SS.Users, user.ID)
		return ok && entry.Username == "alice_f10" && entry.UPSK == user.SSUPSK16 && entry.STLSPassword == user.STLSPassword
	}, "user added to ss.users")

	// Disable user -> removed from ss.users
	stDis, disUser, rawDis, err := client.UpdateUser(jwt, user.ID, CreateUserReq{
		Username:          "alice_f10",
		Enabled:           boolPtr(false),
		TrafficQuotaBytes: 50 << 30,
		BillingResetDay:   10,
	})
	if err != nil || stDis != http.StatusOK || disUser.Enabled {
		t.Fatalf("UpdateUser disable failed: st=%d user=%+v err=%v body=%s", stDis, disUser, err, string(rawDis))
	}
	f10_waitConfigSyncMatching(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		_, ok := f10_findSSUser(p.SS.Users, user.ID)
		return !ok
	}, "disabled user removed from ss.users")

	// Re-enable user -> restored to ss.users
	stEn, enUser, rawEn, err := client.UpdateUser(jwt, user.ID, CreateUserReq{
		Username:          "alice_f10",
		Enabled:           boolPtr(true),
		TrafficQuotaBytes: 50 << 30,
		BillingResetDay:   10,
	})
	if err != nil || stEn != http.StatusOK || !enUser.Enabled {
		t.Fatalf("UpdateUser enable failed: st=%d user=%+v err=%v body=%s", stEn, enUser, err, string(rawEn))
	}
	f10_waitConfigSyncMatching(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		_, ok := f10_findSSUser(p.SS.Users, user.ID)
		return ok
	}, "re-enabled user restored to ss.users")

	// Delete user -> 404 and removed from ss.users
	stDel, rawDel, err := client.DeleteUser(jwt, user.ID)
	if err != nil || stDel < 200 || stDel >= 300 {
		t.Fatalf("DeleteUser failed: st=%d err=%v body=%s", stDel, err, string(rawDel))
	}
	if stAfter, _, _, _ := client.GetUser(jwt, user.ID); stAfter != http.StatusNotFound {
		t.Fatalf("expected 404 after DeleteUser, got %d", stAfter)
	}
	f10_waitConfigSyncMatching(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		_, ok := f10_findSSUser(p.SS.Users, user.ID)
		return !ok
	}, "deleted user removed from ss.users")
}

func TestF10_Tier1_UserNodeAccessMatrixSync(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, nodeA, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:    "MatrixNodeA",
		Enabled: boolPtr(true),
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: AllocFreePort(t), UDPPort: AllocFreePort(t),
			Cipher: "2022-blake3-aes-128-gcm", IPSK: "AAAAAAAAAAAAAAAAAAAAAA==", STLSSNI: "swscan.apple.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, nodeB, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:    "MatrixNodeB",
		Enabled: boolPtr(true),
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: AllocFreePort(t), UDPPort: AllocFreePort(t),
			Cipher: "2022-blake3-aes-128-gcm", IPSK: "AQEBAQEBAQEBAQEBAQEBAQ==", STLSSNI: "swscan.apple.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	connA, _, err := client.DialAgentWS(ctx, nodeA.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	defer connA.CloseNow()
	connB, _, err := client.DialAgentWS(ctx, nodeB.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	defer connB.CloseNow()

	_ = SendWSEnvelope(ctx, connA, "agent.hello", "ha", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	_ = f10_readNextConfigSync(t, ctx, connA, 5*time.Second)
	_ = SendWSEnvelope(ctx, connB, "agent.hello", "hb", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	_ = f10_readNextConfigSync(t, ctx, connB, 5*time.Second)

	// Create user granted Node A only
	_, user, _, err := client.CreateUser(jwt, CreateUserReq{
		Username: "matrix_user",
		NodeIDs:  []int64{nodeA.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	f10_waitConfigSyncMatching(t, ctx, connA, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		_, ok := f10_findSSUser(p.SS.Users, user.ID)
		return ok
	}, "nodeA gains matrix_user")

	// Grant Node A + Node B
	if st, raw, err := client.SetUserNodes(jwt, user.ID, []int64{nodeA.ID, nodeB.ID}); err != nil || st >= 300 {
		t.Fatalf("SetUserNodes(A,B) failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	f10_waitConfigSyncMatching(t, ctx, connB, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		_, ok := f10_findSSUser(p.SS.Users, user.ID)
		return ok
	}, "nodeB gains matrix_user")

	// Revoke Node A, keep Node B
	if st, raw, err := client.SetUserNodes(jwt, user.ID, []int64{nodeB.ID}); err != nil || st >= 300 {
		t.Fatalf("SetUserNodes(B) failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	f10_waitConfigSyncMatching(t, ctx, connA, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		_, ok := f10_findSSUser(p.SS.Users, user.ID)
		return !ok
	}, "nodeA revokes matrix_user")

	// Revoke Node B as well
	if st, raw, err := client.SetUserNodes(jwt, user.ID, []int64{}); err != nil || st >= 300 {
		t.Fatalf("SetUserNodes([]) failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	f10_waitConfigSyncMatching(t, ctx, connB, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		_, ok := f10_findSSUser(p.SS.Users, user.ID)
		return !ok
	}, "nodeB revokes matrix_user")
}

func TestF10_Tier1_AdaptiveUPSK16Vs32WithoutResettingCredentials(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:    "AdaptiveCipherNode",
		Enabled: boolPtr(true),
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: 28443, UDPPort: 28443,
			Cipher: "2022-blake3-aes-128-gcm", IPSK: "AAAAAAAAAAAAAAAAAAAAAA==", STLSSNI: "swscan.apple.com",
		},
		BillingResetDay: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, user, _, err := client.CreateUser(jwt, CreateUserReq{
		Username: "adaptive_user",
		NodeIDs:  []int64{node.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	orig16, orig32, origSTLS, origSub := user.SSUPSK16, user.SSUPSK32, user.STLSPassword, user.SubToken

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	_ = SendWSEnvelope(ctx, conn, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	sync128 := f10_waitConfigSyncMatching(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		u, ok := f10_findSSUser(p.SS.Users, user.ID)
		return ok && p.SS.Cipher == "2022-blake3-aes-128-gcm" && u.UPSK == orig16
	}, "aes-128-gcm uses ss_upsk_16")
	decoded16, err := base64.StdEncoding.DecodeString(sync128.SS.Users[0].UPSK)
	if err != nil || len(decoded16) != 16 {
		t.Fatalf("expected 16B uPSK, got %q (len=%d err=%v)", sync128.SS.Users[0].UPSK, len(decoded16), err)
	}

	// Switch node cipher to 2022-blake3-aes-256-gcm
	stUpd, _, rawUpd, err := client.UpdateNode(jwt, node.ID, CreateNodeReq{
		Name:            "AdaptiveCipherNode",
		Enabled:         boolPtr(true),
		BillingResetDay: 1,
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: 28443, UDPPort: 28443,
			Cipher: "2022-blake3-aes-256-gcm", IPSK: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", STLSSNI: "swscan.apple.com",
		},
	})
	if err != nil || stUpd != http.StatusOK {
		t.Fatalf("UpdateNode cipher to aes-256-gcm failed: st=%d err=%v body=%s", stUpd, err, string(rawUpd))
	}

	sync256 := f10_waitConfigSyncMatching(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		u, ok := f10_findSSUser(p.SS.Users, user.ID)
		return ok && p.SS.Cipher == "2022-blake3-aes-256-gcm" && u.UPSK == orig32
	}, "aes-256-gcm uses ss_upsk_32")
	decoded32, err := base64.StdEncoding.DecodeString(sync256.SS.Users[0].UPSK)
	if err != nil || len(decoded32) != 32 {
		t.Fatalf("expected 32B uPSK, got %q (len=%d err=%v)", sync256.SS.Users[0].UPSK, len(decoded32), err)
	}

	// Verify user's stored credentials were NOT reset
	_, gotUser, _, err := client.GetUser(jwt, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotUser.SSUPSK16 != orig16 || gotUser.SSUPSK32 != orig32 || gotUser.STLSPassword != origSTLS || gotUser.SubToken != origSub {
		t.Fatalf("user credentials mutated across cipher switch: got=%+v orig=(%s,%s,%s,%s)", gotUser, orig16, orig32, origSTLS, origSub)
	}

	// Switch back to 128-gcm and verify ss_upsk_16 returns
	_, _, _, err = client.UpdateNode(jwt, node.ID, CreateNodeReq{
		Name:            "AdaptiveCipherNode",
		Enabled:         boolPtr(true),
		BillingResetDay: 1,
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: 28443, UDPPort: 28443,
			Cipher: "2022-blake3-aes-128-gcm", IPSK: "AAAAAAAAAAAAAAAAAAAAAA==", STLSSNI: "swscan.apple.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	f10_waitConfigSyncMatching(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		u, ok := f10_findSSUser(p.SS.Users, user.ID)
		return ok && p.SS.Cipher == "2022-blake3-aes-128-gcm" && u.UPSK == orig16
	}, "switched back to aes-128-gcm uses ss_upsk_16")
}

func TestF10_Tier1_QuotaEnforcementAndTrafficResetRecovery(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:    "QuotaNode",
		Enabled: boolPtr(true),
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: AllocFreePort(t), UDPPort: AllocFreePort(t),
			Cipher: "2022-blake3-aes-128-gcm", IPSK: "AAAAAAAAAAAAAAAAAAAAAA==", STLSSNI: "swscan.apple.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, user, _, err := client.CreateUser(jwt, CreateUserReq{
		Username:          "quota_user",
		TrafficQuotaBytes: 10000,
		NodeIDs:           []int64{node.ID},
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
	f10_waitConfigSyncMatching(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		_, ok := f10_findSSUser(p.SS.Users, user.ID)
		return ok
	}, "initial quota_user active")

	// Boundary: used == quota - 1 (5999 + 4000 == 9999 < 10000) keeps user active
	if err := SendWSEnvelope(ctx, conn, "agent.metrics", "m1", AgentMetricsPayload{
		TS: time.Now().Unix(),
		UserDeltas: []UserTrafficDeltaDTO{
			{Username: user.Username, UserID: user.ID, UpBytes: 5999, DownBytes: 4000},
		},
		Health: AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}
	boundaryDeadline := time.Now().Add(5 * time.Second)
	boundaryRecorded := false
	for time.Now().Before(boundaryDeadline) {
		_, uMid, _, _ := client.GetUser(jwt, user.ID)
		if uMid.UsedUpBytes == 5999 && uMid.UsedDownBytes == 4000 {
			boundaryRecorded = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !boundaryRecorded {
		t.Fatalf("timed out waiting for quota-1 usage (5999, 4000) to persist")
	}
	if stSync, rawSync, err := client.SyncNode(jwt, node.ID); err != nil || stSync >= 300 {
		t.Fatalf("SyncNode at quota-1 failed: st=%d err=%v body=%s", stSync, err, string(rawSync))
	}
	syncAtMinusOne := f10_readNextConfigSync(t, ctx, conn, 5*time.Second)
	if _, ok := f10_findSSUser(syncAtMinusOne.SS.Users, user.ID); !ok {
		t.Fatalf("expected user at used == quota-1 (9999 < 10000) to remain active in ss.users, got %+v", syncAtMinusOne.SS.Users)
	}

	// Report final 1 byte reaching exact quota (6000 + 4000 == 10000) -> removed
	if err := SendWSEnvelope(ctx, conn, "agent.metrics", "m2", AgentMetricsPayload{
		TS: time.Now().Unix(),
		UserDeltas: []UserTrafficDeltaDTO{
			{Username: user.Username, UserID: user.ID, UpBytes: 1, DownBytes: 0},
		},
		Health: AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}

	f10_waitConfigSyncMatching(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		_, ok := f10_findSSUser(p.SS.Users, user.ID)
		return !ok
	}, "over-quota user removed from ss.users")

	_, gotUser, _, err := client.GetUser(jwt, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotUser.UsedUpBytes != 6000 || gotUser.UsedDownBytes != 4000 {
		t.Fatalf("expected used=(6000, 4000), got (%d, %d)", gotUser.UsedUpBytes, gotUser.UsedDownBytes)
	}

	// Reset user traffic -> user restored to ss.users
	stRes, rawRes, err := client.ResetUserTraffic(jwt, user.ID)
	if err != nil || stRes < 200 || stRes >= 300 {
		t.Fatalf("ResetUserTraffic failed: st=%d err=%v body=%s", stRes, err, string(rawRes))
	}
	f10_waitConfigSyncMatching(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		_, ok := f10_findSSUser(p.SS.Users, user.ID)
		return ok
	}, "user restored after reset-traffic")

	_, afterReset, _, err := client.GetUser(jwt, user.ID)
	if err != nil || afterReset.UsedUpBytes != 0 || afterReset.UsedDownBytes != 0 {
		t.Fatalf("expected zeroed user traffic after reset, got %+v err=%v", afterReset, err)
	}
}

func TestF10_Tier1_ExpireAtEnforcementAndRenewalRecovery(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:    "ExpireNode",
		Enabled: boolPtr(true),
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: AllocFreePort(t), UDPPort: AllocFreePort(t),
			Cipher: "2022-blake3-aes-128-gcm", IPSK: "AAAAAAAAAAAAAAAAAAAAAA==", STLSSNI: "swscan.apple.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	future1 := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	_, user, rawCreate, err := client.CreateUser(jwt, CreateUserReq{
		Username: "expire_user",
		ExpireAt: &future1,
		NodeIDs:  []int64{node.ID},
	})
	if err != nil {
		t.Fatalf("CreateUser failed: %v body=%s", err, string(rawCreate))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	_ = SendWSEnvelope(ctx, conn, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	f10_waitConfigSyncMatching(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		_, ok := f10_findSSUser(p.SS.Users, user.ID)
		return ok
	}, "future expire_at user active")

	// Set expire_at to past -> removed
	past := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
	stUpd, _, rawUpd, err := client.UpdateUser(jwt, user.ID, CreateUserReq{
		Username:        "expire_user",
		Enabled:         boolPtr(true),
		BillingResetDay: 1,
		ExpireAt:        &past,
	})
	if err != nil || stUpd != http.StatusOK {
		t.Fatalf("UpdateUser past expire_at failed: st=%d err=%v body=%s", stUpd, err, string(rawUpd))
	}
	f10_waitConfigSyncMatching(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		_, ok := f10_findSSUser(p.SS.Users, user.ID)
		return !ok
	}, "expired user removed from ss.users")

	// Renew expire_at to future -> restored
	future2 := time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339)
	stRen, _, rawRen, err := client.UpdateUser(jwt, user.ID, CreateUserReq{
		Username:        "expire_user",
		Enabled:         boolPtr(true),
		BillingResetDay: 1,
		ExpireAt:        &future2,
	})
	if err != nil || stRen != http.StatusOK {
		t.Fatalf("UpdateUser renew failed: st=%d err=%v body=%s", stRen, err, string(rawRen))
	}
	f10_waitConfigSyncMatching(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		_, ok := f10_findSSUser(p.SS.Users, user.ID)
		return ok
	}, "renewed user restored to ss.users")

	// Non-UTC (+08:00) offset expire_at that is in the past in UTC -> removed
	plus8 := time.FixedZone("UTC+8", 8*3600)
	pastPlus8 := time.Now().UTC().Add(-1 * time.Hour).In(plus8).Format(time.RFC3339)
	stP8, _, rawP8, err := client.UpdateUser(jwt, user.ID, CreateUserReq{
		Username:        "expire_user",
		Enabled:         boolPtr(true),
		BillingResetDay: 1,
		ExpireAt:        &pastPlus8,
	})
	if err != nil || stP8 != http.StatusOK {
		t.Fatalf("UpdateUser(+08:00 past expire_at) failed: st=%d err=%v body=%s", stP8, err, string(rawP8))
	}
	f10_waitConfigSyncMatching(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		_, ok := f10_findSSUser(p.SS.Users, user.ID)
		return !ok
	}, "non-UTC +08:00 past expire_at user removed from ss.users")

	// Clear expire_at back to null (permanent) -> restored and ExpireAt == nil
	stClr, clearedUser, rawClr, err := client.UpdateUser(jwt, user.ID, map[string]any{
		"username":          "expire_user",
		"enabled":           true,
		"billing_reset_day": 1,
		"expire_at":         nil,
	})
	if err != nil || stClr != http.StatusOK {
		t.Fatalf("UpdateUser(expire_at=null) failed: st=%d err=%v body=%s", stClr, err, string(rawClr))
	}
	if clearedUser.ExpireAt != nil {
		t.Fatalf("expected expire_at cleared to nil, got %q", *clearedUser.ExpireAt)
	}
	f10_waitConfigSyncMatching(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		_, ok := f10_findSSUser(p.SS.Users, user.ID)
		return ok
	}, "user with cleared expire_at=null restored to ss.users")
}

func TestF10_Tier2_ExpiredExpireAtImmediateExclusion(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:    "ImmediateExpireNode",
		Enabled: boolPtr(true),
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: AllocFreePort(t), UDPPort: AllocFreePort(t),
			Cipher: "2022-blake3-aes-128-gcm", IPSK: "AAAAAAAAAAAAAAAAAAAAAA==", STLSSNI: "swscan.apple.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	past := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	_, expiredUser, rawExp, err := client.CreateUser(jwt, CreateUserReq{
		Username: "already_expired",
		Enabled:  boolPtr(true),
		ExpireAt: &past,
		NodeIDs:  []int64{node.ID},
	})
	if err != nil {
		t.Fatalf("CreateUser(past expire_at) failed: %v body=%s", err, string(rawExp))
	}
	_, controlUser, rawCtrl, err := client.CreateUser(jwt, CreateUserReq{
		Username: "active_control_user",
		Enabled:  boolPtr(true),
		NodeIDs:  []int64{node.ID},
	})
	if err != nil {
		t.Fatalf("CreateUser(control) failed: %v body=%s", err, string(rawCtrl))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	_ = SendWSEnvelope(ctx, conn, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	initSync := f10_readNextConfigSync(t, ctx, conn, 5*time.Second)
	if !initSync.SS.Enabled {
		t.Fatalf("expected initSync.SS.Enabled to be true, got false (%+v)", initSync.SS)
	}
	if _, ok := f10_findSSUser(initSync.SS.Users, controlUser.ID); !ok {
		t.Fatalf("expected active non-expired control user %d in initial config_sync, got %+v", controlUser.ID, initSync.SS.Users)
	}
	if _, ok := f10_findSSUser(initSync.SS.Users, expiredUser.ID); ok {
		t.Fatalf("expected user created with past expire_at to be immediately excluded from initial config_sync")
	}

	// Invalid expire_at formats rejected with 4xx
	for _, badExp := range []string{"not-a-timestamp", "2026-13-45"} {
		st, _, raw, err := client.CreateUser(jwt, CreateUserReq{
			Username: "bad_exp_" + badExp,
			ExpireAt: &badExp,
		})
		if err != nil {
			t.Fatal(err)
		}
		if st < 400 || st >= 500 {
			t.Fatalf("invalid expire_at %q expected 4xx, got %d (body=%s)", badExp, st, string(raw))
		}
	}
}

func TestF10_Tier2_ZeroQuotaUnlimited(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:    "ZeroQuotaNode",
		Enabled: boolPtr(true),
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: AllocFreePort(t), UDPPort: AllocFreePort(t),
			Cipher: "2022-blake3-aes-128-gcm", IPSK: "AAAAAAAAAAAAAAAAAAAAAA==", STLSSNI: "swscan.apple.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, user, _, err := client.CreateUser(jwt, CreateUserReq{
		Username:          "unlimited_user",
		TrafficQuotaBytes: 0,
		NodeIDs:           []int64{node.ID},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	_ = SendWSEnvelope(ctx, conn, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	f10_waitConfigSyncMatching(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		_, ok := f10_findSSUser(p.SS.Users, user.ID)
		return ok
	}, "zero quota user active")

	if err := SendWSEnvelope(ctx, conn, "agent.metrics", "m1", AgentMetricsPayload{
		TS: time.Now().Unix(),
		UserDeltas: []UserTrafficDeltaDTO{
			{Username: user.Username, UserID: user.ID, UpBytes: 500 << 30, DownBytes: 500 << 30},
		},
		Health: AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}

	// Poll until usage persisted, then trigger manual sync and confirm user remains active
	deadline := time.Now().Add(5 * time.Second)
	usagePersisted := false
	for time.Now().Before(deadline) {
		_, gotU, _, _ := client.GetUser(jwt, user.ID)
		if gotU.UsedUpBytes >= 500<<30 {
			usagePersisted = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !usagePersisted {
		t.Fatalf("timed out waiting for zero-quota usage (>= %d) to persist", 500<<30)
	}

	if st, raw, err := client.SyncNode(jwt, node.ID); err != nil || st >= 300 {
		t.Fatalf("SyncNode failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	syncAfter := f10_readNextConfigSync(t, ctx, conn, 5*time.Second)
	if _, ok := f10_findSSUser(syncAfter.SS.Users, user.ID); !ok {
		t.Fatalf("zero-quota user should stay in ss.users after huge usage, got %+v", syncAfter.SS.Users)
	}
}

func TestF10_Tier2_UnauthorizedUserAbsentFromNodeConfigSync(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, nodeA, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:    "IsoNodeA",
		Enabled: boolPtr(true),
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: AllocFreePort(t), UDPPort: AllocFreePort(t),
			Cipher: "2022-blake3-aes-128-gcm", IPSK: "AAAAAAAAAAAAAAAAAAAAAA==", STLSSNI: "swscan.apple.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, nodeB, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:    "IsoNodeB",
		Enabled: boolPtr(true),
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: AllocFreePort(t), UDPPort: AllocFreePort(t),
			Cipher: "2022-blake3-aes-128-gcm", IPSK: "AQEBAQEBAQEBAQEBAQEBAQ==", STLSSNI: "swscan.apple.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, uA, _, err := client.CreateUser(jwt, CreateUserReq{Username: "only_node_a", NodeIDs: []int64{nodeA.ID}})
	if err != nil {
		t.Fatal(err)
	}
	_, uB, _, err := client.CreateUser(jwt, CreateUserReq{Username: "only_node_b", NodeIDs: []int64{nodeB.ID}})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	connA, _, err := client.DialAgentWS(ctx, nodeA.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	defer connA.CloseNow()
	connB, _, err := client.DialAgentWS(ctx, nodeB.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	defer connB.CloseNow()

	_ = SendWSEnvelope(ctx, connA, "agent.hello", "ha", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	syncA := f10_readNextConfigSync(t, ctx, connA, 5*time.Second)
	_ = SendWSEnvelope(ctx, connB, "agent.hello", "hb", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	syncB := f10_readNextConfigSync(t, ctx, connB, 5*time.Second)

	if _, ok := f10_findSSUser(syncA.SS.Users, uA.ID); !ok {
		t.Fatalf("nodeA missing authorized user uA")
	}
	if _, ok := f10_findSSUser(syncA.SS.Users, uB.ID); ok {
		t.Fatalf("nodeA leaked unauthorized user uB")
	}
	if _, ok := f10_findSSUser(syncB.SS.Users, uB.ID); !ok {
		t.Fatalf("nodeB missing authorized user uB")
	}
	if _, ok := f10_findSSUser(syncB.SS.Users, uA.ID); ok {
		t.Fatalf("nodeB leaked unauthorized user uA")
	}
}

func TestF10_Tier2_DuplicateUsernameAndInvalidRequestsRejected(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	st1, u1, raw1, err := client.CreateUser(jwt, CreateUserReq{Username: "dup_user_f10"})
	if err != nil || (st1 != http.StatusOK && st1 != http.StatusCreated) {
		t.Fatalf("first CreateUser failed: st=%d err=%v body=%s", st1, err, string(raw1))
	}

	// Duplicate username -> 409/4xx
	stDup, _, rawDup, err := client.CreateUser(jwt, CreateUserReq{Username: "dup_user_f10"})
	if err != nil {
		t.Fatal(err)
	}
	if stDup < 400 || stDup >= 500 {
		t.Fatalf("duplicate username expected 4xx, got %d (body=%s)", stDup, string(rawDup))
	}

	// Empty username -> 4xx
	stEmpty, _, rawEmpty, err := client.CreateUser(jwt, CreateUserReq{Username: ""})
	if err != nil {
		t.Fatal(err)
	}
	if stEmpty < 400 || stEmpty >= 500 {
		t.Fatalf("empty username expected 4xx, got %d (body=%s)", stEmpty, string(rawEmpty))
	}

	// Negative quota -> 4xx
	stNegQ, _, rawNegQ, err := client.CreateUser(jwt, CreateUserReq{Username: "neg_q", TrafficQuotaBytes: -100})
	if err != nil {
		t.Fatal(err)
	}
	if stNegQ < 400 || stNegQ >= 500 {
		t.Fatalf("negative quota expected 4xx, got %d (body=%s)", stNegQ, string(rawNegQ))
	}

	// Nonexistent user ID -> 404
	const missingUser int64 = 999999
	stG, _, _, _ := client.GetUser(jwt, missingUser)
	stU, _, _, _ := client.UpdateUser(jwt, missingUser, CreateUserReq{Username: "ghost", BillingResetDay: 1})
	stD, _, _ := client.DeleteUser(jwt, missingUser)
	stRK, _, _, _ := client.ResetUserKeys(jwt, missingUser, map[string]any{"reset_upsk": true})
	stRT, _, _ := client.ResetUserTraffic(jwt, missingUser)
	stSN, _, _ := client.SetUserNodes(jwt, missingUser, []int64{})
	for name, st := range map[string]int{
		"GET":           stG,
		"PUT":           stU,
		"DELETE":        stD,
		"reset-keys":    stRK,
		"reset-traffic": stRT,
		"set-nodes":     stSN,
	} {
		if st != http.StatusNotFound {
			t.Fatalf("missing user %s expected 404, got %d", name, st)
		}
	}

	// Nonexistent node ID in CreateUser & SetUserNodes -> 4xx
	stBadNode1, _, rawBad1, _ := client.CreateUser(jwt, CreateUserReq{Username: "bad_node_ref", NodeIDs: []int64{999999}})
	if stBadNode1 < 400 || stBadNode1 >= 500 {
		t.Fatalf("CreateUser with missing node ID expected 4xx, got %d (body=%s)", stBadNode1, string(rawBad1))
	}
	stBadNode2, rawBad2, _ := client.SetUserNodes(jwt, u1.ID, []int64{999999})
	if stBadNode2 < 400 || stBadNode2 >= 500 {
		t.Fatalf("SetUserNodes with missing node ID expected 4xx, got %d (body=%s)", stBadNode2, string(rawBad2))
	}
}

func TestF10_Tier2_ResetKeysRotationAndWSSync(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	_, node, _, err := client.CreateNode(jwt, CreateNodeReq{
		Name:    "KeyRotateNode",
		Enabled: boolPtr(true),
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: 18443, UDPPort: 18443,
			Cipher: "2022-blake3-aes-128-gcm", IPSK: "AAAAAAAAAAAAAAAAAAAAAA==", STLSSNI: "swscan.apple.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, u1, _, err := client.CreateUser(jwt, CreateUserReq{
		Username: "rotate_ws_user",
		NodeIDs:  []int64{node.ID},
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
	f10_waitConfigSyncMatching(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		e, ok := f10_findSSUser(p.SS.Users, u1.ID)
		return ok && e.UPSK == u1.SSUPSK16 && e.STLSPassword == u1.STLSPassword
	}, "initial keys synced")

	// Rotate uPSK & stls_password only (sub_token must remain unchanged)
	stR1, u2, rawR1, err := client.ResetUserKeys(jwt, u1.ID, map[string]any{
		"reset_upsk":          true,
		"reset_stls_password": true,
	})
	if err != nil || stR1 >= 300 {
		t.Fatalf("ResetUserKeys(upsk+stls) failed: st=%d err=%v body=%s", stR1, err, string(rawR1))
	}
	if u2.SSUPSK16 == u1.SSUPSK16 || u2.SSUPSK32 == u1.SSUPSK32 || u2.STLSPassword == u1.STLSPassword {
		t.Fatalf("expected uPSK16, uPSK32, and stls_password to rotate: old=%+v new=%+v", u1, u2)
	}
	if u2.SubToken != u1.SubToken {
		t.Fatalf("expected sub_token unchanged when reset_sub_token is false: old=%q new=%q", u1.SubToken, u2.SubToken)
	}
	if b16, err := base64.StdEncoding.DecodeString(u2.SSUPSK16); err != nil || len(b16) != 16 {
		t.Fatalf("rotated ss_upsk_16 invalid (expected 16B base64): %q err=%v", u2.SSUPSK16, err)
	}
	if b32, err := base64.StdEncoding.DecodeString(u2.SSUPSK32); err != nil || len(b32) != 32 {
		t.Fatalf("rotated ss_upsk_32 invalid (expected 32B base64): %q err=%v", u2.SSUPSK32, err)
	}

	// Verify WS config_sync pushes new uPSK & stls_password
	f10_waitConfigSyncMatching(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		e, ok := f10_findSSUser(p.SS.Users, u1.ID)
		return ok && e.UPSK == u2.SSUPSK16 && e.STLSPassword == u2.STLSPassword
	}, "rotated keys synced to agent WS")

	// Rotate sub_token (reset_sub_token=true rotates all 4 credentials and pushes updated keys via WS)
	stR2, u3, rawR2, err := client.ResetUserKeys(jwt, u1.ID, map[string]any{
		"reset_sub_token": true,
	})
	if err != nil || stR2 >= 300 {
		t.Fatalf("ResetUserKeys(sub_token) failed: st=%d err=%v body=%s", stR2, err, string(rawR2))
	}
	if u3.SubToken == u2.SubToken || u3.SubToken == "" {
		t.Fatalf("expected sub_token to rotate: old=%q new=%q", u2.SubToken, u3.SubToken)
	}
	if u3.SSUPSK16 == u2.SSUPSK16 || u3.SSUPSK32 == u2.SSUPSK32 || u3.STLSPassword == u2.STLSPassword {
		t.Fatalf("expected uPSK16/uPSK32/stls_password to rotate alongside sub_token: before=%+v after=%+v", u2, u3)
	}
	f10_waitConfigSyncMatching(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		e, ok := f10_findSSUser(p.SS.Users, u1.ID)
		return ok && e.UPSK == u3.SSUPSK16 && e.STLSPassword == u3.STLSPassword
	}, "sub_token reset keys synced to agent WS")
	if stOld, _, bodyOld, errOld := client.GetUserSub(u2.SubToken, "target=mihomo", ""); errOld != nil || stOld < 400 || stOld >= 500 {
		t.Fatalf("expected old sub_token rejected with 4xx after rotation, got st=%d err=%v body=%s", stOld, errOld, bodyOld)
	}
	if stNew, _, _, _ := client.GetUserSub(u3.SubToken, "target=mihomo", ""); stNew != http.StatusOK {
		t.Fatalf("expected new sub_token to work, got %d", stNew)
	}

	// Full 3-flag reset (reset_upsk + reset_stls_password + reset_sub_token) rotates all 4 credentials
	stR3, u4, rawR3, err := client.ResetUserKeys(jwt, u1.ID, map[string]any{
		"reset_upsk":          true,
		"reset_stls_password": true,
		"reset_sub_token":     true,
	})
	if err != nil || stR3 >= 300 {
		t.Fatalf("ResetUserKeys(all 3 flags) failed: st=%d err=%v body=%s", stR3, err, string(rawR3))
	}
	if u4.SSUPSK16 == u3.SSUPSK16 || u4.SSUPSK32 == u3.SSUPSK32 || u4.STLSPassword == u3.STLSPassword || u4.SubToken == u3.SubToken {
		t.Fatalf("expected all 4 credentials to rotate on full reset: old=%+v new=%+v", u3, u4)
	}
	if b16, err := base64.StdEncoding.DecodeString(u4.SSUPSK16); err != nil || len(b16) != 16 {
		t.Fatalf("full-reset ss_upsk_16 invalid (expected 16B base64): %q err=%v", u4.SSUPSK16, err)
	}
	if b32, err := base64.StdEncoding.DecodeString(u4.SSUPSK32); err != nil || len(b32) != 32 {
		t.Fatalf("full-reset ss_upsk_32 invalid (expected 32B base64): %q err=%v", u4.SSUPSK32, err)
	}
	f10_waitConfigSyncMatching(t, ctx, conn, 5*time.Second, func(p ServerConfigSyncPayload) bool {
		e, ok := f10_findSSUser(p.SS.Users, u1.ID)
		return ok && e.UPSK == u4.SSUPSK16 && e.STLSPassword == u4.STLSPassword
	}, "full-reset keys synced to agent WS")
	if stPrev, _, bodyPrev, errPrev := client.GetUserSub(u3.SubToken, "target=mihomo", ""); errPrev != nil || stPrev < 400 || stPrev >= 500 {
		t.Fatalf("expected u3 sub_token rejected with 4xx after full reset, got st=%d err=%v body=%s", stPrev, errPrev, bodyPrev)
	}
	if stLatest, _, _, _ := client.GetUserSub(u4.SubToken, "target=mihomo", ""); stLatest != http.StatusOK {
		t.Fatalf("expected u4 sub_token to work after full reset, got %d", stLatest)
	}
}
