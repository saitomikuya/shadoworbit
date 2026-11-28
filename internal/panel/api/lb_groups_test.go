package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"snell-panel/internal/panel/auth"
	"snell-panel/internal/panel/dnsprovider"
	"snell-panel/internal/panel/hub"
	"snell-panel/internal/panel/scheduler"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/panel/sub"
	"snell-panel/internal/panel/webhook"
	"snell-panel/internal/protocol"
)

type apiFakeDNSProvider struct {
	zones   []dnsprovider.Zone
	records []dnsprovider.DesiredRecord
}

func (f *apiFakeDNSProvider) ListPublicZones(_ context.Context) ([]dnsprovider.Zone, error) {
	return f.zones, nil
}

func (f *apiFakeDNSProvider) ListRecordSets(_ context.Context, _, _, _ string) ([]dnsprovider.RecordSet, error) {
	return nil, nil
}

func (f *apiFakeDNSProvider) SyncARecords(_ context.Context, _, _ string, _ int, _ bool, desired []dnsprovider.DesiredRecord) ([]dnsprovider.SyncedRecord, error) {
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

func newLBAPITestEnv(t *testing.T) (http.Handler, string, *store.Store, *apiFakeDNSProvider) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "api_lb.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.SeedDefaults(ctx, store.SeedConfig{AdminInitialPass: "secret12345"}); err != nil {
		t.Fatal(err)
	}
	authSvc, err := auth.NewService(ctx, st, auth.Config{})
	if err != nil {
		t.Fatal(err)
	}
	wh := webhook.NewEngine(st, nil)
	t.Cleanup(wh.Close)
	h := hub.NewHub(st, wh)
	t.Cleanup(func() { _ = h.Close() })

	fakeDNS := &apiFakeDNSProvider{
		zones: []dnsprovider.Zone{{ID: "z-1", Name: "example.com", Status: "ACTIVE", TTL: 300}},
	}
	sched := scheduler.NewScheduler(st, h, wh,
		scheduler.WithDNSProviderFactory(func(_, _, _ string) (dnsprovider.Provider, error) {
			return fakeDNS, nil
		}),
	)
	subRenderer := sub.NewRenderer(st)

	handler := NewServer(Dependencies{
		Store:     st,
		Auth:      authSvc,
		Hub:       h,
		Sub:       subRenderer,
		Scheduler: sched,
		Webhook:   wh,
	})

	token, err := authSvc.IssueJWT("admin")
	if err != nil {
		t.Fatal(err)
	}
	return handler, token, st, fakeDNS
}

func doAPIReq(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = httptest.NewRequest(method, path, strings.NewReader(string(b)))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestHuaweiCloudSettingsTestZonesAndLBGroupsAPI(t *testing.T) {
	ctx := context.Background()
	handler, token, st, _ := newLBAPITestEnv(t)

	// 1. Save Huawei Cloud DNS credentials in settings and confirm SK is masked on readback.
	rec := doAPIReq(t, handler, http.MethodPut, "/api/v1/admin/settings", token, map[string]any{
		"huaweicloud_dns_endpoint": "https://dns.ap-southeast-1.myhuaweicloud.com",
		"huaweicloud_dns_ak":       "AK123456",
		"huaweicloud_dns_sk":       "SK-SECRET-9999",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("update settings failed (%d): %s", rec.Code, rec.Body.String())
	}
	var settings safeSettingsDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &settings); err != nil {
		t.Fatal(err)
	}
	if !settings.HuaweiCloudDNSSKConfigured || strings.Contains(rec.Body.String(), "SK-SECRET-9999") {
		t.Fatalf("expected SK masked and never exposed in response: %s", rec.Body.String())
	}

	// 2. Test connection and list zones.
	rec = doAPIReq(t, handler, http.MethodPost, "/api/v1/admin/dns-provider/huaweicloud/test", token, map[string]any{})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"example.com"`) {
		t.Fatalf("test huaweicloud dns failed (%d): %s", rec.Code, rec.Body.String())
	}
	rec = doAPIReq(t, handler, http.MethodGet, "/api/v1/admin/dns-provider/huaweicloud/zones", token, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"z-1"`) {
		t.Fatalf("list zones failed (%d): %s", rec.Code, rec.Body.String())
	}

	// 3. Create 2 nodes & 1 user authorized on node1 only.
	n1 := &store.Node{
		Name: "Ali-1", TokenHash: "tok1", Enabled: true, PublicIP: "1.1.1.1",
		SnellConfig: protocol.SnellConfig{Enabled: true, Version: protocol.SnellVersionV5, PublicPort: 18443, InnerPort: 18444, PSK: "p", STLSPassword: "s", STLSSNI: "gateway.icloud.com"},
		SSConfig:    protocol.SSConfig{Enabled: true, TCPPort: 28443, UDPPort: 28444, Cipher: protocol.CipherAES128GCM, IPSK: "AAAAAAAAAAAAAAAAAAAAAA==", STLSSNI: "swdist.apple.com"},
	}
	n2 := &store.Node{
		Name: "Ali-2", TokenHash: "tok2", Enabled: true, PublicIP: "2.2.2.2",
		SnellConfig: protocol.SnellConfig{Enabled: true, Version: protocol.SnellVersionV5, PublicPort: 18443, InnerPort: 18445, PSK: "p", STLSPassword: "s", STLSSNI: "gateway.icloud.com"},
		SSConfig:    protocol.SSConfig{Enabled: true, TCPPort: 28443, UDPPort: 28444, Cipher: protocol.CipherAES128GCM, IPSK: "AAAAAAAAAAAAAAAAAAAAAA==", STLSSNI: "swdist.apple.com"},
	}
	if err := st.CreateNode(ctx, n1); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateNode(ctx, n2); err != nil {
		t.Fatal(err)
	}
	u := &store.User{
		Username: "alice", Enabled: true, SubToken: "sub-alice",
		SSUPSK16: "BBBBBBBBBBBBBBBBBBBBBB==", SSUPSK32: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=", STLSPassword: "stls",
	}
	if _, err := st.CreateUserWithNodes(ctx, u, []int64{n1.ID}); err != nil {
		t.Fatal(err)
	}

	// 4. Create LB Group -> syncs node configs, unions user access, returns DTO.
	rec = doAPIReq(t, handler, http.MethodPost, "/api/v1/admin/lb-groups", token, map[string]any{
		"name":          "Aliyun-Group",
		"enabled":       true,
		"dns_zone_id":   "z-1",
		"dns_zone_name": "example.com",
		"dns_domain":    "ali.example.com",
		"dns_ttl":       60,
		"strategy":      protocol.LBStrategyRemainingBalance,
		"snell_config": map[string]any{
			"enabled": true, "version": "v5", "public_port": 38443, "psk": "grp-psk",
			"obfs": "off", "tfo": true, "stls_password": "grp-stls", "stls_sni": "gateway.icloud.com",
		},
		"ss_config": map[string]any{
			"enabled": true, "tcp_port": 48443, "udp_port": 48444, "cipher": protocol.CipherAES128GCM,
			"ipsk": "DDDDDDDDDDDDDDDDDDDDDD==", "stls_sni": "swdist.apple.com", "tfo": true,
		},
		"member_node_ids": []int64{n1.ID, n2.ID},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create lb group failed (%d): %s", rec.Code, rec.Body.String())
	}
	var created lbGroupDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if len(created.Members) != 2 || created.DNSDomain != "ali.example.com" {
		t.Fatalf("unexpected created group DTO: %+v", created)
	}

	// 5. Verify nodes endpoint exposes lb_group_id / lb_group_name.
	rec = doAPIReq(t, handler, http.MethodGet, "/api/v1/admin/nodes", token, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"lb_group_name":"Aliyun-Group"`) {
		t.Fatalf("expected lb_group_name on nodes list: %s", rec.Body.String())
	}

	// 6. Pin node, check logs, unpin, delete group.
	rec = doAPIReq(t, handler, http.MethodPost, "/api/v1/admin/lb-groups/1/pin", token, map[string]any{
		"node_id": n2.ID,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("pin failed (%d): %s", rec.Code, rec.Body.String())
	}
	var pinned lbGroupDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &pinned); err != nil {
		t.Fatal(err)
	}
	if pinned.PinnedNodeID == nil || *pinned.PinnedNodeID != n2.ID || pinned.ActiveNodeID == nil || *pinned.ActiveNodeID != n2.ID {
		t.Fatalf("expected pinned and active node %d, got pinned=%v active=%v", n2.ID, pinned.PinnedNodeID, pinned.ActiveNodeID)
	}

	rec = doAPIReq(t, handler, http.MethodGet, "/api/v1/admin/lb-groups/1/logs", token, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"manual_pin"`) {
		t.Fatalf("expected manual_pin in logs (%d): %s", rec.Code, rec.Body.String())
	}

	// User sub returns unified ali.example.com.
	rec = doAPIReq(t, handler, http.MethodGet, "/s/u/"+u.SubToken+"/ShadowOrbit.yaml?target=mihomo&mode=proxy", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "server: ali.example.com") || strings.Contains(rec.Body.String(), "Ali-1") {
		t.Fatalf("unexpected user sub output (%d): %s", rec.Code, rec.Body.String())
	}

	rec = doAPIReq(t, handler, http.MethodDelete, "/api/v1/admin/lb-groups/1", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete lb group failed (%d): %s", rec.Code, rec.Body.String())
	}
}
