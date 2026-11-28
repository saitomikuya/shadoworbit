package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"snell-panel/internal/protocol"
)

func mustCreateTestNode(t *testing.T, s *Store, name, tokenHash string, innerPort int) *Node {
	t.Helper()
	n := &Node{
		Name:      name,
		TokenHash: tokenHash,
		Enabled:   true,
		PublicIP:  "1.1.1.1",
		SnellConfig: protocol.SnellConfig{
			Enabled:         true,
			Version:         protocol.SnellVersionV5,
			PublicPort:      18443,
			InnerPort:       innerPort,
			PSK:             "old-psk",
			Obfs:            protocol.SnellObfsOff,
			TFO:             true,
			DNSIPPreference: protocol.DNSIPPrefPreferIPv4,
			STLSPassword:    "old-stls",
			STLSSNI:         "old.example.com",
		},
		SSConfig: protocol.SSConfig{
			Enabled: true,
			TCPPort: 28443,
			UDPPort: 28444,
			Cipher:  protocol.CipherAES128GCM,
			IPSK:    "AAAAAAAAAAAAAAAAAAAAAA==",
			STLSSNI: "old-ss.example.com",
			TFO:     true,
		},
	}
	if err := s.CreateNode(context.Background(), n); err != nil {
		t.Fatalf("CreateNode(%s) failed: %v", name, err)
	}
	return n
}

func mustCreateTestUser(t *testing.T, s *Store, username, token string, nodeIDs []int64) *User {
	t.Helper()
	u := &User{
		Username:     username,
		Enabled:      true,
		SubToken:     token,
		SSUPSK16:     "BBBBBBBBBBBBBBBBBBBBBB==",
		SSUPSK32:     "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
		STLSPassword: "user-stls-pass",
	}
	if _, err := s.CreateUserWithNodes(context.Background(), u, nodeIDs); err != nil {
		t.Fatalf("CreateUserWithNodes(%s) failed: %v", username, err)
	}
	return u
}

func TestLBGroupCRUDConfigSyncAndAccessUnion(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	n1 := mustCreateTestNode(t, s, "Ali-1", "tok-1", 19001)
	n2 := mustCreateTestNode(t, s, "Ali-2", "tok-2", 19002)
	n3 := mustCreateTestNode(t, s, "Ali-3", "tok-3", 19003)

	u1 := mustCreateTestUser(t, s, "alice", "sub-alice", []int64{n1.ID})
	u2 := mustCreateTestUser(t, s, "bob", "sub-bob", []int64{n2.ID})

	grp := &LBGroup{
		Name:                     "Aliyun-Group",
		RegionTag:                "CN-HK",
		Enabled:                  true,
		SortOrder:                1,
		DNSZoneID:                "zone-1",
		DNSZoneName:              "example.com",
		DNSDomain:                "ALI.EXAMPLE.COM.",
		DNSTTL:                   60,
		Strategy:                 protocol.LBStrategyRemainingBalance,
		SwitchDiffBytes:          10 << 30,
		SwitchCooldownMinutes:    10,
		FailoverThresholdPercent: 90,
		SnellConfig: protocol.SnellConfig{
			Enabled:      true,
			Version:      protocol.SnellVersionV5,
			PublicPort:   38443,
			PSK:          "group-psk",
			Obfs:         protocol.SnellObfsTLS,
			TFO:          false,
			STLSPassword: "group-stls-password",
			STLSSNI:      "gateway.icloud.com",
		},
		SSConfig: protocol.SSConfig{
			Enabled: true,
			TCPPort: 48443,
			UDPPort: 48444,
			Cipher:  protocol.CipherAES128GCM,
			IPSK:    "DDDDDDDDDDDDDDDDDDDDDD==",
			STLSSNI: "swdist.apple.com",
			TFO:     true,
		},
	}

	affected, err := s.CreateLBGroup(ctx, grp, []int64{n1.ID, n2.ID})
	if err != nil {
		t.Fatalf("CreateLBGroup failed: %v", err)
	}
	if len(affected) != 2 || grp.DNSDomain != "ali.example.com" {
		t.Fatalf("unexpected group create output: affected=%v domain=%q", affected, grp.DNSDomain)
	}

	// Verify node configs synced while preserving InnerPort and DNSIPPreference.
	got1, err := s.GetNodeByID(ctx, n1.ID)
	if err != nil {
		t.Fatal(err)
	}
	got2, err := s.GetNodeByID(ctx, n2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got1.SnellConfig.InnerPort != 19001 || got2.SnellConfig.InnerPort != 19002 {
		t.Fatalf("expected inner_port preserved, got %d / %d", got1.SnellConfig.InnerPort, got2.SnellConfig.InnerPort)
	}
	if got1.SnellConfig.DNSIPPreference != protocol.DNSIPPrefPreferIPv4 {
		t.Fatalf("expected dns_ip_preference preserved, got %q", got1.SnellConfig.DNSIPPreference)
	}
	if got1.SnellConfig.PublicPort != 38443 || got2.SnellConfig.PSK != "group-psk" || got2.SSConfig.TCPPort != 48443 {
		t.Fatalf("expected unified group protocol synced, got node1=%+v node2=%+v", got1.SnellConfig, got2.SSConfig)
	}
	if got1.ConfigRevision != 2 || got2.ConfigRevision != 2 {
		t.Fatalf("expected config_revision bumped to 2, got %d / %d", got1.ConfigRevision, got2.ConfigRevision)
	}

	// Verify user_node_access unioned across both nodes.
	u1Nodes, err := s.GetUserNodeIDs(ctx, u1.ID)
	if err != nil {
		t.Fatal(err)
	}
	u2Nodes, err := s.GetUserNodeIDs(ctx, u2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(u1Nodes) != 2 || len(u2Nodes) != 2 {
		t.Fatalf("expected unioned access [n1,n2] for both users, got u1=%v u2=%v", u1Nodes, u2Nodes)
	}

	// Port collision against preserved inner_port is rejected.
	bad := *grp
	bad.ID = 0
	bad.Name = "Other-Group"
	bad.DNSDomain = "other.example.com"
	bad.SnellConfig.PublicPort = 19003
	if _, err := s.CreateLBGroup(ctx, &bad, []int64{n3.ID}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument on inner_port collision, got %v", err)
	}

	// Node already in another group returns ErrConflict.
	dup := *grp
	dup.ID = 0
	dup.Name = "Dup-Group"
	dup.DNSDomain = "dup.example.com"
	if _, err := s.CreateLBGroup(ctx, &dup, []int64{n1.ID}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict when node already belongs to another group, got %v", err)
	}

	// Pinning rejects non-member and accepts member.
	if err := s.SetLBGroupPinnedNode(ctx, grp.ID, &n3.ID); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument pinning non-member, got %v", err)
	}
	if err := s.SetLBGroupPinnedNode(ctx, grp.ID, &n1.ID); err != nil {
		t.Fatalf("SetLBGroupPinnedNode failed: %v", err)
	}

	// Removing pinned node on update clears pinned_node_id.
	grp.Members = nil
	if _, err := s.UpdateLBGroup(ctx, grp, []int64{n2.ID, n3.ID}); err != nil {
		t.Fatalf("UpdateLBGroup failed: %v", err)
	}
	reloaded, err := s.GetLBGroupByID(ctx, grp.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.PinnedNodeID != nil {
		t.Fatalf("expected pinned_node_id cleared when node removed from group, got %v", *reloaded.PinnedNodeID)
	}
	if len(reloaded.Members) != 2 || reloaded.Members[0].NodeID != n2.ID || reloaded.Members[1].NodeID != n3.ID {
		t.Fatalf("unexpected updated members: %+v", reloaded.Members)
	}

	// ExpandUserNodeIDsForLBGroups expands group access automatically.
	expanded, err := s.ExpandUserNodeIDsForLBGroups(ctx, nil, []int64{n2.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(expanded) != 2 || expanded[0] != n2.ID || expanded[1] != n3.ID {
		t.Fatalf("expected new user group expansion to [%d %d], got %v", n2.ID, n3.ID, expanded)
	}

	// Switch logs prune beyond 100 entries.
	for i := 0; i < 105; i++ {
		if err := s.AppendLBSwitchLog(ctx, &LBSwitchLog{
			GroupID:   grp.ID,
			EventType: "balance_switch",
			Reason:    strings.Repeat("x", 4),
		}); err != nil {
			t.Fatalf("AppendLBSwitchLog(%d) failed: %v", i, err)
		}
	}
	logs, err := s.ListLBSwitchLogs(ctx, grp.ID, 200)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 100 {
		t.Fatalf("expected 100 capped logs, got %d", len(logs))
	}

	// Deleting group keeps member nodes.
	if err := s.DeleteLBGroup(ctx, grp.ID); err != nil {
		t.Fatalf("DeleteLBGroup failed: %v", err)
	}
	if _, err := s.GetNodeByID(ctx, n2.ID); err != nil {
		t.Fatalf("expected member node to remain after deleting group: %v", err)
	}
}
