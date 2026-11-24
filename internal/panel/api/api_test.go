package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/coder/websocket"

	"snell-panel/internal/panel/api"
	"snell-panel/internal/panel/auth"
	"snell-panel/internal/panel/hub"
	"snell-panel/internal/panel/scheduler"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/panel/sub"
	"snell-panel/internal/panel/webhook"
	"snell-panel/internal/protocol"
)

type testEnv struct {
	t      *testing.T
	store  *store.Store
	auth   *auth.Service
	wh     *webhook.Engine
	sub    *sub.Renderer
	hub    *hub.Hub
	sched  *scheduler.Scheduler
	srv    *httptest.Server
	client *http.Client
	jwt    string
}

func newTestEnv(t *testing.T, staticFS fs.FS, githubURL string) *testEnv {
	t.Helper()
	ctx := context.Background()

	st, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := st.SeedDefaults(ctx, store.SeedConfig{
		AdminUser:        "admin",
		AdminInitialPass: "testpass123",
		JWTSecret:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}); err != nil {
		t.Fatalf("SeedDefaults: %v", err)
	}

	authSvc, err := auth.NewService(ctx, st, auth.Config{BcryptCost: 4})
	if err != nil {
		t.Fatalf("auth.NewService: %v", err)
	}

	wh := webhook.NewEngine(st, nil)
	t.Cleanup(wh.Close)

	subRenderer := sub.NewRenderer(st)

	h := hub.NewHub(st, wh, hub.WithPublicDebounce(10*time.Millisecond))
	t.Cleanup(func() { _ = h.Close() })

	var schedOpts []scheduler.Option
	if githubURL != "" {
		schedOpts = append(schedOpts, scheduler.WithGitHubAPIBaseURL(githubURL))
	}
	sched := scheduler.NewScheduler(st, h, wh, schedOpts...)
	sched.WireHub()

	handler := api.NewServer(api.Dependencies{
		Store:     st,
		Auth:      authSvc,
		Hub:       h,
		Sub:       subRenderer,
		Scheduler: sched,
		Webhook:   wh,
		StaticFS:  staticFS,
	})

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	env := &testEnv{
		t:      t,
		store:  st,
		auth:   authSvc,
		wh:     wh,
		sub:    subRenderer,
		hub:    h,
		sched:  sched,
		srv:    srv,
		client: srv.Client(),
	}
	env.jwt = env.mustLogin("admin", "testpass123")
	return env
}

func (e *testEnv) do(method, path, bearer string, body any) (int, http.Header, []byte) {
	e.t.Helper()
	var r io.Reader
	if body != nil {
		switch v := body.(type) {
		case []byte:
			r = bytes.NewReader(v)
		case string:
			r = strings.NewReader(v)
		default:
			b, err := json.Marshal(v)
			if err != nil {
				e.t.Fatalf("marshal body: %v", err)
			}
			r = bytes.NewReader(b)
		}
	}
	req, err := http.NewRequest(method, e.srv.URL+path, r)
	if err != nil {
		e.t.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s failed: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, resp.Header, raw
}

func (e *testEnv) mustLogin(username, password string) string {
	e.t.Helper()
	st, _, raw := e.do(http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"username": username,
		"password": password,
	})
	if st != http.StatusOK {
		e.t.Fatalf("login failed: status=%d body=%s", st, string(raw))
	}
	var out struct {
		Token    string `json:"token"`
		Username string `json:"username"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		e.t.Fatalf("unmarshal login: %v", err)
	}
	return out.Token
}

func (e *testEnv) dialAgent(nodeToken string) *websocket.Conn {
	e.t.Helper()
	wsURL := "ws" + strings.TrimPrefix(e.srv.URL, "http") + "/api/v1/agent/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + nodeToken}},
	})
	if err != nil {
		e.t.Fatalf("dial agent ws: %v", err)
	}
	e.t.Cleanup(func() { _ = conn.CloseNow() })
	return conn
}

func readEnv(t *testing.T, conn *websocket.Conn) protocol.Envelope {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("ws read: %v", err)
	}
	var env protocol.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	return env
}

func TestHealthAndAuth(t *testing.T) {
	env := newTestEnv(t, nil, "")

	st, hdr, raw := env.do(http.MethodGet, "/healthz", "", nil)
	if st != http.StatusOK || !strings.Contains(hdr.Get("Content-Type"), "application/json") {
		t.Fatalf("unexpected /healthz: st=%d ct=%s body=%s", st, hdr.Get("Content-Type"), string(raw))
	}
	if !strings.Contains(string(raw), `"status":"ok"`) {
		t.Fatalf("unexpected healthz body: %s", string(raw))
	}

	// Malformed JSON -> 400
	st, _, _ = env.do(http.MethodPost, "/api/v1/auth/login", "", "{bad")
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 on malformed JSON, got %d", st)
	}

	// Wrong credentials -> 401
	st, _, _ = env.do(http.MethodPost, "/api/v1/auth/login", "", map[string]string{"username": "admin", "password": "wrong"})
	if st != http.StatusUnauthorized {
		t.Fatalf("expected 401 on wrong password, got %d", st)
	}

	// Valid /auth/me
	st, _, raw = env.do(http.MethodGet, "/api/v1/auth/me", env.jwt, nil)
	if st != http.StatusOK || !strings.Contains(string(raw), `"admin"`) {
		t.Fatalf("unexpected /auth/me: st=%d body=%s", st, string(raw))
	}

	// Unauthorized cases -> 401
	for _, badJWT := range []string{"", "not-a-jwt", env.jwt + "tampered", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImFkbWluIn0."} {
		st, _, _ = env.do(http.MethodGet, "/api/v1/auth/me", badJWT, nil)
		if st != http.StatusUnauthorized {
			t.Fatalf("expected 401 for bad jwt %q, got %d", badJWT, st)
		}
		st, _, _ = env.do(http.MethodGet, "/api/v1/admin/nodes", badJWT, nil)
		if st != http.StatusUnauthorized {
			t.Fatalf("expected 401 on admin route for bad jwt %q, got %d", badJWT, st)
		}
	}

	// Password change: wrong old -> 401; empty/too-long new -> 400; valid -> 200
	st, _, _ = env.do(http.MethodPut, "/api/v1/auth/password", env.jwt, map[string]string{
		"old_password": "wrong",
		"new_password": "newpass123",
	})
	if st != http.StatusUnauthorized {
		t.Fatalf("expected 401 on wrong old password, got %d", st)
	}

	st, _, _ = env.do(http.MethodPut, "/api/v1/auth/password", env.jwt, map[string]string{
		"old_password": "testpass123",
		"new_password": strings.Repeat("a", 73),
	})
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 on >72 byte password, got %d", st)
	}

	st, _, _ = env.do(http.MethodPut, "/api/v1/auth/password", env.jwt, map[string]string{
		"old_password": "testpass123",
		"new_password": "newpass123",
	})
	if st != http.StatusOK {
		t.Fatalf("expected 200 on password change, got %d", st)
	}

	st, _, _ = env.do(http.MethodPost, "/api/v1/auth/login", "", map[string]string{"username": "admin", "password": "testpass123"})
	if st != http.StatusUnauthorized {
		t.Fatalf("expected old password rejected after change, got %d", st)
	}
	_ = env.mustLogin("admin", "newpass123")
}

func TestPublicEndpointsAndRedaction(t *testing.T) {
	env := newTestEnv(t, nil, "")

	// Empty nodes must be [] not null
	st, _, raw := env.do(http.MethodGet, "/api/v1/public/status", "", nil)
	if st != http.StatusOK {
		t.Fatalf("public status failed: %d %s", st, string(raw))
	}
	if !strings.Contains(string(raw), `"nodes":[]`) {
		t.Fatalf("expected empty nodes array [], got %s", string(raw))
	}

	// Method checks -> 405
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		st, _, _ = env.do(m, "/api/v1/public/status", "", nil)
		if st != http.StatusMethodNotAllowed {
			t.Fatalf("%s /api/v1/public/status expected 405, got %d", m, st)
		}
		st, _, _ = env.do(m, "/api/v1/public/ws", "", nil)
		if st != http.StatusMethodNotAllowed {
			t.Fatalf("%s /api/v1/public/ws expected 405, got %d", m, st)
		}
	}

	// Create node with sensitive fields and verify redaction in public status & WS
	st, _, raw = env.do(http.MethodPost, "/api/v1/admin/nodes", env.jwt, map[string]any{
		"name":              "PublicTest",
		"region_tag":        "JP",
		"public_ip":         "203.0.113.55",
		"custom_entry_host": "secret.example.com",
		"custom_entry_port": 443,
		"enabled":           true,
		"snell_config":      protocol.SnellConfig{Enabled: true, Version: "v5", PublicPort: 2443, InnerPort: 31001, PSK: "supersecretpsk"},
	})
	if st != http.StatusCreated {
		t.Fatalf("create node failed: %d %s", st, string(raw))
	}

	st, _, raw = env.do(http.MethodGet, "/api/v1/public/status", "", nil)
	if st != http.StatusOK {
		t.Fatalf("public status failed: %d", st)
	}
	for _, forbidden := range []string{"203.0.113.55", "secret.example.com", "supersecretpsk", "token_hash", "node_token", "snell_config", "ss_config"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("public status leaked forbidden data %q: %s", forbidden, string(raw))
		}
	}

	// Public WS receives snapshot
	wsURL := "ws" + strings.TrimPrefix(env.srv.URL, "http") + "/api/v1/public/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial public ws: %v", err)
	}
	defer conn.CloseNow()
	_, msg, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read public ws: %v", err)
	}
	var snap protocol.PublicStatusSnapshot
	if err := json.Unmarshal(msg, &snap); err != nil {
		t.Fatalf("unmarshal public ws snapshot: %v", err)
	}
	if len(snap.Nodes) != 1 || snap.Nodes[0].Name != "PublicTest" {
		t.Fatalf("unexpected public ws nodes: %+v", snap.Nodes)
	}
}

func TestNodesCRUDValidationActionsAndSync(t *testing.T) {
	var whMu sync.Mutex
	var whBodies []string
	whSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		whMu.Lock()
		whBodies = append(whBodies, string(b))
		whMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer whSrv.Close()

	env := newTestEnv(t, nil, "")

	// Register webhook for traffic_recovered verification
	st, _, raw := env.do(http.MethodPost, "/api/v1/admin/webhooks", env.jwt, map[string]any{
		"name":              "Hook",
		"provider":          "custom",
		"url":               whSrv.URL,
		"subscribed_events": []string{"*"},
		"enabled":           true,
	})
	if st != http.StatusCreated {
		t.Fatalf("create webhook failed: %d %s", st, string(raw))
	}

	// Reject explicit billing_reset_day=0 on node create
	st, _, _ = env.do(http.MethodPost, "/api/v1/admin/nodes", env.jwt, map[string]any{
		"name":              "BadZeroDay",
		"billing_reset_day": 0,
	})
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 for explicit billing_reset_day=0 on node create, got %d", st)
	}

	// Create valid node (omitting billing_reset_day defaults to 1)
	st, _, raw = env.do(http.MethodPost, "/api/v1/admin/nodes", env.jwt, map[string]any{
		"name":                    "Node-1",
		"public_ip":               "198.51.100.10",
		"traffic_limit_bytes":     1000,
		"traffic_threshold_bytes": 500,
		"snell_config":            protocol.SnellConfig{Enabled: true, Version: "v5", PublicPort: 2443, InnerPort: 31001, PSK: "psk1"},
		"ss_config":               protocol.SSConfig{Enabled: true, TCPPort: 3443, UDPPort: 3443, Cipher: protocol.CipherAES128GCM, IPSK: "AAAAAAAAAAAAAAAAAAAAAA=="},
	})
	if st != http.StatusCreated {
		t.Fatalf("create node 1 failed: %d %s", st, string(raw))
	}
	var created1 struct {
		ID              int64  `json:"id"`
		NodeToken       string `json:"node_token"`
		BillingResetDay int    `json:"billing_reset_day"`
		ConfigRevision  int64  `json:"config_revision"`
	}
	if err := json.Unmarshal(raw, &created1); err != nil {
		t.Fatal(err)
	}
	if created1.NodeToken == "" || created1.BillingResetDay != 1 {
		t.Fatalf("unexpected created node: %+v", created1)
	}

	// GET node must redact node_token & token_hash
	st, _, raw = env.do(http.MethodGet, "/api/v1/admin/nodes/1", env.jwt, nil)
	if st != http.StatusOK || strings.Contains(string(raw), created1.NodeToken) || strings.Contains(string(raw), "token_hash") {
		t.Fatalf("GET node leaked token or failed: st=%d body=%s", st, string(raw))
	}

	// install-cmd returns token, docker_run, docker_compose
	st, _, raw = env.do(http.MethodGet, "/api/v1/admin/nodes/1/install-cmd", env.jwt, nil)
	if st != http.StatusOK {
		t.Fatalf("install-cmd failed: %d %s", st, string(raw))
	}
	for _, want := range []string{created1.NodeToken, "PANEL_URL", "NODE_TOKEN", "TZ=Asia/Shanghai", "network_mode: host"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("install-cmd missing %q: %s", want, string(raw))
		}
	}

	// Offline sync returns 200 offline (not 5xx)
	st, _, raw = env.do(http.MethodPost, "/api/v1/admin/nodes/1/sync", env.jwt, nil)
	if st != http.StatusOK || !strings.Contains(string(raw), `"synced":false`) {
		t.Fatalf("offline sync unexpected: st=%d body=%s", st, string(raw))
	}

	// Offline service-ctl returns 409 Conflict
	st, _, _ = env.do(http.MethodPost, "/api/v1/admin/nodes/1/service-ctl", env.jwt, map[string]string{"action": "restart_all"})
	if st != http.StatusConflict {
		t.Fatalf("offline service-ctl expected 409, got %d", st)
	}

	// Connect agent WS and read initial config_sync
	conn := env.dialAgent(created1.NodeToken)
	initEnv := readEnv(t, conn)
	if initEnv.Type != protocol.MsgTypeServerConfigSync {
		t.Fatalf("expected initial server.config_sync, got %s", initEnv.Type)
	}

	// Send agent.hello and agent.metrics, verify telemetry overlay on GET /nodes/1
	helloBytes, _ := json.Marshal(protocol.Envelope{
		Type:    protocol.MsgTypeAgentHello,
		ReqID:   "h1",
		Payload: json.RawMessage(`{"os":"linux","arch":"amd64","cpu_cores":4,"config_revision":2}`),
	})
	_ = conn.Write(context.Background(), websocket.MessageText, helloBytes)

	metricsBytes, _ := json.Marshal(protocol.Envelope{
		Type:    protocol.MsgTypeAgentMetrics,
		ReqID:   "m1",
		Payload: json.RawMessage(`{"ts":1700000000,"cpu_percent":42.5,"rx_bps":1234,"tx_bps":5678,"health":{"snell":true,"shadow_tls":true,"sing_box":true}}`),
	})
	_ = conn.Write(context.Background(), websocket.MessageText, metricsBytes)

	deadline := time.Now().Add(2 * time.Second)
	for {
		_, _, raw = env.do(http.MethodGet, "/api/v1/admin/nodes/1", env.jwt, nil)
		if strings.Contains(string(raw), `"cpu_percent":42.5`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("telemetry overlay did not appear: %s", string(raw))
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Update node: reject billing_reset_day=0; valid update preserves public_ip and bumps config_revision
	st, _, _ = env.do(http.MethodPut, "/api/v1/admin/nodes/1", env.jwt, map[string]any{"name": "Node-1", "billing_reset_day": 0})
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 on UpdateNode billing_reset_day=0, got %d", st)
	}
	st, _, raw = env.do(http.MethodPut, "/api/v1/admin/nodes/1", env.jwt, map[string]any{"name": "Node-1-Renamed"})
	if st != http.StatusOK || !strings.Contains(string(raw), `"public_ip":"198.51.100.10"`) {
		t.Fatalf("update node failed or lost public_ip: st=%d body=%s", st, string(raw))
	}
	syncEnv := readEnv(t, conn)
	if syncEnv.Type != protocol.MsgTypeServerConfigSync {
		t.Fatalf("expected server.config_sync after update, got %s", syncEnv.Type)
	}

	// Online service-ctl
	st, _, _ = env.do(http.MethodPost, "/api/v1/admin/nodes/1/service-ctl", env.jwt, map[string]string{"action": "restart_singbox"})
	if st != http.StatusOK {
		t.Fatalf("online service-ctl expected 200, got %d", st)
	}
	ctlEnv := readEnv(t, conn)
	if ctlEnv.Type != protocol.MsgTypeServerServiceCtl {
		t.Fatalf("expected server.service_ctl, got %s", ctlEnv.Type)
	}

	// Calibrate traffic above threshold -> pauses node & pushes sync
	st, _, _ = env.do(http.MethodPost, "/api/v1/admin/nodes/1/calibrate-traffic", env.jwt, map[string]int64{
		"cycle_rx_bytes": -1,
		"cycle_tx_bytes": 0,
	})
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 on negative calibrate-traffic, got %d", st)
	}
	st, _, raw = env.do(http.MethodPost, "/api/v1/admin/nodes/1/calibrate-traffic", env.jwt, map[string]int64{
		"cycle_rx_bytes": 400,
		"cycle_tx_bytes": 200,
	})
	if st != http.StatusOK || !strings.Contains(string(raw), `"is_traffic_paused":true`) {
		t.Fatalf("expected node paused after calibrate-traffic >= threshold: st=%d body=%s", st, string(raw))
	}
	_ = readEnv(t, conn) // sync for pause

	// Reset traffic on paused node -> clears pause, syncs node, fires traffic_recovered webhook
	st, _, raw = env.do(http.MethodPost, "/api/v1/admin/nodes/1/reset-traffic", env.jwt, nil)
	if st != http.StatusOK || !strings.Contains(string(raw), `"is_traffic_paused":false`) || !strings.Contains(string(raw), `"status":"online"`) {
		t.Fatalf("reset-traffic unexpected: st=%d body=%s", st, string(raw))
	}
	_ = readEnv(t, conn) // sync for recovery
	env.wh.Wait()
	whMu.Lock()
	joined := strings.Join(whBodies, "\n")
	whMu.Unlock()
	if !strings.Contains(joined, `"type":"traffic_recovered"`) || !strings.Contains(joined, `"resolved":true`) {
		t.Fatalf("expected resolved traffic_recovered webhook, got %s", joined)
	}

	// Reorder nodes via both PUT and POST
	st, _, raw = env.do(http.MethodPost, "/api/v1/admin/nodes", env.jwt, map[string]any{"name": "Node-2"})
	if st != http.StatusCreated {
		t.Fatalf("create node 2 failed: %d", st)
	}
	st, _, _ = env.do(http.MethodPut, "/api/v1/admin/nodes/reorder", env.jwt, map[string]any{"ids": []int64{2, 1}})
	if st != http.StatusOK {
		t.Fatalf("PUT reorder failed: %d", st)
	}
	st, _, _ = env.do(http.MethodPost, "/api/v1/admin/nodes/reorder", env.jwt, map[string]any{"node_ids": []int64{1, 2}})
	if st != http.StatusOK {
		t.Fatalf("POST reorder failed: %d", st)
	}
	st, _, _ = env.do(http.MethodPost, "/api/v1/admin/nodes/reorder", env.jwt, map[string]any{"ids": []int64{1, 999}})
	if st != http.StatusNotFound {
		t.Fatalf("reorder with missing ID expected 404, got %d", st)
	}

	// Delete node
	st, _, _ = env.do(http.MethodDelete, "/api/v1/admin/nodes/2", env.jwt, nil)
	if st != http.StatusOK {
		t.Fatalf("delete node 2 failed: %d", st)
	}
	st, _, _ = env.do(http.MethodGet, "/api/v1/admin/nodes/2", env.jwt, nil)
	if st != http.StatusNotFound {
		t.Fatalf("expected 404 for deleted node, got %d", st)
	}
}

func TestUsersLifecycleAccessAndResetKeys(t *testing.T) {
	env := newTestEnv(t, nil, "")

	// Create 2 nodes and connect agent 1
	st, _, raw1 := env.do(http.MethodPost, "/api/v1/admin/nodes", env.jwt, map[string]any{
		"name":      "U-Node-1",
		"ss_config": protocol.SSConfig{Enabled: true, TCPPort: 3443, UDPPort: 3443, Cipher: protocol.CipherAES128GCM, IPSK: "AAAAAAAAAAAAAAAAAAAAAA=="},
	})
	if st != http.StatusCreated {
		t.Fatalf("create node 1: %d %s", st, string(raw1))
	}
	var n1 struct {
		ID        int64  `json:"id"`
		NodeToken string `json:"node_token"`
	}
	_ = json.Unmarshal(raw1, &n1)
	conn1 := env.dialAgent(n1.NodeToken)
	_ = readEnv(t, conn1)

	st, _, _ = env.do(http.MethodPost, "/api/v1/admin/nodes", env.jwt, map[string]any{"name": "U-Node-2"})
	if st != http.StatusCreated {
		t.Fatalf("create node 2: %d", st)
	}

	// Create user with billing_reset_day=0 (valid for users!) and invalid node FK rollback
	st, _, _ = env.do(http.MethodPost, "/api/v1/admin/users", env.jwt, map[string]any{
		"username": "badfk",
		"node_ids": []int64{9999},
	})
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid node_id FK, got %d", st)
	}
	// Ensure badfk was rolled back
	st, _, rawUsers := env.do(http.MethodGet, "/api/v1/admin/users", env.jwt, nil)
	if st != http.StatusOK || strings.Contains(string(rawUsers), "badfk") {
		t.Fatalf("orphan user leaked after FK failure: %s", string(rawUsers))
	}

	st, _, rawU := env.do(http.MethodPost, "/api/v1/admin/users", env.jwt, map[string]any{
		"username":            "alice",
		"billing_reset_day":   0,
		"traffic_quota_bytes": 1000,
		"expire_at":           "2030-01-02T15:04:05+08:00",
		"node_ids":            []int64{n1.ID},
	})
	if st != http.StatusCreated {
		t.Fatalf("create alice failed: %d %s", st, string(rawU))
	}
	var u1 struct {
		ID           int64   `json:"id"`
		SubToken     string  `json:"sub_token"`
		SSUPSK16     string  `json:"ss_upsk_16"`
		SSUPSK32     string  `json:"ss_upsk_32"`
		STLSPassword string  `json:"stls_password"`
		ExpireAt     *string `json:"expire_at"`
	}
	_ = json.Unmarshal(rawU, &u1)
	if u1.ExpireAt == nil || !strings.HasSuffix(*u1.ExpireAt, "Z") {
		t.Fatalf("expected UTC expire_at, got %v", u1.ExpireAt)
	}
	_ = readEnv(t, conn1) // sync from create user

	// Duplicate username -> 409
	st, _, _ = env.do(http.MethodPost, "/api/v1/admin/users", env.jwt, map[string]any{"username": "alice"})
	if st != http.StatusConflict {
		t.Fatalf("expected 409 on duplicate username, got %d", st)
	}

	// reset-keys with empty body: rotates 3 keys, keeps sub_token
	st, _, rawRK := env.do(http.MethodPost, fmt.Sprintf("/api/v1/admin/users/%d/reset-keys", u1.ID), env.jwt, nil)
	if st != http.StatusOK {
		t.Fatalf("reset-keys empty failed: %d %s", st, string(rawRK))
	}
	var u2 struct {
		SubToken     string `json:"sub_token"`
		SSUPSK16     string `json:"ss_upsk_16"`
		SSUPSK32     string `json:"ss_upsk_32"`
		STLSPassword string `json:"stls_password"`
	}
	_ = json.Unmarshal(rawRK, &u2)
	if u2.SubToken != u1.SubToken || u2.SSUPSK16 == u1.SSUPSK16 || u2.SSUPSK32 == u1.SSUPSK32 || u2.STLSPassword == u1.STLSPassword {
		t.Fatalf("expected only 3 keys rotated when reset_sub_token is false: before=%+v after=%+v", u1, u2)
	}
	_ = readEnv(t, conn1)

	// reset-keys with reset_sub_token=true: rotates ALL 4 credentials
	st, _, rawRK2 := env.do(http.MethodPost, fmt.Sprintf("/api/v1/admin/users/%d/reset-keys", u1.ID), env.jwt, map[string]bool{"reset_sub_token": true})
	if st != http.StatusOK {
		t.Fatalf("reset-keys with reset_sub_token=true failed: %d", st)
	}
	var u3 struct {
		SubToken     string `json:"sub_token"`
		SSUPSK16     string `json:"ss_upsk_16"`
		SSUPSK32     string `json:"ss_upsk_32"`
		STLSPassword string `json:"stls_password"`
	}
	_ = json.Unmarshal(rawRK2, &u3)
	if u3.SubToken == u2.SubToken || u3.SSUPSK16 == u2.SSUPSK16 || u3.SSUPSK32 == u2.SSUPSK32 || u3.STLSPassword == u2.STLSPassword {
		t.Fatalf("expected all 4 credentials rotated when reset_sub_token=true")
	}
	_ = readEnv(t, conn1)

	// Update user: omit expire_at (keep), then clear with null
	st, _, rawUpd := env.do(http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d", u1.ID), env.jwt, map[string]any{"enabled": true})
	if st != http.StatusOK || !strings.Contains(string(rawUpd), `"expire_at":"2030-01-02T07:04:05Z"`) {
		t.Fatalf("expected omitted expire_at preserved, got st=%d body=%s", st, string(rawUpd))
	}
	_ = readEnv(t, conn1)

	st, _, rawUpd2 := env.do(http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d", u1.ID), env.jwt, map[string]any{"expire_at": nil})
	if st != http.StatusOK || !strings.Contains(string(rawUpd2), `"expire_at":null`) {
		t.Fatalf("expected null expire_at cleared, got st=%d body=%s", st, string(rawUpd2))
	}
	_ = readEnv(t, conn1)

	// Revoke node 1 via PUT /users/{id}/nodes -> node 1 MUST receive config_sync without alice
	st, _, _ = env.do(http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d/nodes", u1.ID), env.jwt, map[string]any{"node_ids": []int64{2}})
	if st != http.StatusOK {
		t.Fatalf("PUT /users/{id}/nodes failed: %d", st)
	}
	revokeSync := readEnv(t, conn1)
	var syncPayload protocol.ServerConfigSync
	_ = revokeSync.DecodePayload(&syncPayload)
	if len(syncPayload.SS.Users) != 0 {
		t.Fatalf("expected node 1 to drop alice after revoke, got %+v", syncPayload.SS.Users)
	}

	// Clearing user nodes with [] must return {"node_ids":[]} rather than {"node_ids":null}
	st, _, rawCleared := env.do(http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d/nodes", u1.ID), env.jwt, map[string]any{"node_ids": []int64{}})
	if st != http.StatusOK {
		t.Fatalf("PUT /users/{id}/nodes [] failed: %d body=%s", st, string(rawCleared))
	}
	if !strings.Contains(string(rawCleared), `"node_ids":[]`) || strings.Contains(string(rawCleared), `"node_ids":null`) {
		t.Fatalf("expected PUT /users/{id}/nodes [] to return node_ids:[], got %s", string(rawCleared))
	}
	st, _, rawGetEmpty := env.do(http.MethodGet, fmt.Sprintf("/api/v1/admin/users/%d/nodes", u1.ID), env.jwt, nil)
	if st != http.StatusOK || !strings.Contains(string(rawGetEmpty), `"node_ids":[]`) || strings.Contains(string(rawGetEmpty), `"node_ids":null`) {
		t.Fatalf("expected GET /users/{id}/nodes to return node_ids:[], got st=%d body=%s", st, string(rawGetEmpty))
	}

	// Re-grant node 1, then delete user -> node 1 drops alice
	st, _, _ = env.do(http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d/nodes", u1.ID), env.jwt, map[string]any{"node_ids": []int64{1}})
	if st != http.StatusOK {
		t.Fatalf("re-grant failed: %d", st)
	}
	_ = readEnv(t, conn1)

	st, _, _ = env.do(http.MethodDelete, fmt.Sprintf("/api/v1/admin/users/%d", u1.ID), env.jwt, nil)
	if st != http.StatusOK {
		t.Fatalf("delete user failed: %d", st)
	}
	delSync := readEnv(t, conn1)
	_ = delSync.DecodePayload(&syncPayload)
	if len(syncPayload.SS.Users) != 0 {
		t.Fatalf("expected node 1 to drop deleted user, got %+v", syncPayload.SS.Users)
	}
}

func TestSubscriptionsAndForbiddenHeaders(t *testing.T) {
	env := newTestEnv(t, nil, "")

	// Create node supporting both Snell and SS2022
	st, _, rawN := env.do(http.MethodPost, "/api/v1/admin/nodes", env.jwt, map[string]any{
		"name":      "SubNode",
		"public_ip": "198.51.100.20",
		"snell_config": protocol.SnellConfig{
			Enabled: true, Version: "v5", PublicPort: 2443, InnerPort: 31001, PSK: "snellpsk", STLSPassword: "stlspwd", STLSSNI: "gateway.icloud.com",
		},
		"ss_config": protocol.SSConfig{
			Enabled: true, TCPPort: 3443, UDPPort: 3444, Cipher: protocol.CipherAES128GCM, IPSK: "AAAAAAAAAAAAAAAAAAAAAA==", STLSSNI: "swscan.apple.com",
		},
	})
	if st != http.StatusCreated {
		t.Fatalf("create node: %d %s", st, string(rawN))
	}

	// Create user with exhausted quota (used >= quota)
	st, _, rawU := env.do(http.MethodPost, "/api/v1/admin/users", env.jwt, map[string]any{
		"username":            "bob",
		"traffic_quota_bytes": 1000,
		"node_ids":            []int64{1},
	})
	if st != http.StatusCreated {
		t.Fatalf("create user: %d %s", st, string(rawU))
	}
	var user struct {
		ID       int64  `json:"id"`
		SubToken string `json:"sub_token"`
	}
	_ = json.Unmarshal(rawU, &user)

	// Get admin_sub_token from settings
	st, _, rawS := env.do(http.MethodGet, "/api/v1/admin/settings", env.jwt, nil)
	if st != http.StatusOK {
		t.Fatalf("get settings: %d", st)
	}
	var settings struct {
		AdminSubToken string `json:"admin_sub_token"`
	}
	_ = json.Unmarshal(rawS, &settings)

	// Admin sub valid
	st, _, rawSub := env.do(http.MethodGet, "/s/admin/"+settings.AdminSubToken+"?mode=full", "", nil)
	if st != http.StatusOK || !strings.HasPrefix(string(rawSub), "#!MANAGED-CONFIG ") || !strings.Contains(string(rawSub), "snell, 198.51.100.20, 2443") {
		t.Fatalf("unexpected admin sub: st=%d body=%s", st, string(rawSub))
	}
	// Invalid tpl -> 400; missing tpl -> 404; user token on admin track -> 401
	st, _, _ = env.do(http.MethodGet, "/s/admin/"+settings.AdminSubToken+"?tpl=abc", "", nil)
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid tpl, got %d", st)
	}
	st, _, _ = env.do(http.MethodGet, "/s/admin/"+settings.AdminSubToken+"?tpl=9999", "", nil)
	if st != http.StatusNotFound {
		t.Fatalf("expected 404 on missing tpl, got %d", st)
	}
	st, _, _ = env.do(http.MethodGet, "/s/admin/"+user.SubToken, "", nil)
	if st != http.StatusUnauthorized {
		t.Fatalf("expected 401 for user token on admin track, got %d", st)
	}

	// User sub valid (Mihomo)
	st, hdr, rawUserSub := env.do(http.MethodGet, "/s/u/"+user.SubToken+"?target=mihomo", "", nil)
	if st != http.StatusOK || !strings.Contains(hdr.Get("Subscription-Userinfo"), "total=1000") || hdr.Get("Profile-Update-Interval") != "12" {
		t.Fatalf("unexpected user sub: st=%d hdr=%v body=%s", st, hdr, string(rawUserSub))
	}

	// Exhaust quota -> 403 MUST still include Subscription-Userinfo & Profile-Update-Interval!
	if _, err := env.store.AddUserTrafficDelta(context.Background(), user.ID, 600, 500); err != nil {
		t.Fatal(err)
	}
	st, hdr, _ = env.do(http.MethodGet, "/s/u/"+user.SubToken+"?target=mihomo", "", nil)
	if st != http.StatusForbidden {
		t.Fatalf("expected 403 for exhausted user, got %d", st)
	}
	if !strings.Contains(hdr.Get("Subscription-Userinfo"), "upload=600; download=500; total=1000;") || hdr.Get("Profile-Update-Interval") != "12" {
		t.Fatalf("expected Subscription-Userinfo headers even on 403, got %v", hdr)
	}

	// Reset user traffic -> 200 again
	st, _, _ = env.do(http.MethodPost, "/api/v1/admin/users/1/reset-traffic", env.jwt, nil)
	if st != http.StatusOK {
		t.Fatalf("reset user traffic: %d", st)
	}
	st, _, _ = env.do(http.MethodGet, "/s/u/"+user.SubToken+"?target=mihomo", "", nil)
	if st != http.StatusOK {
		t.Fatalf("expected 200 after user traffic reset, got %d", st)
	}
}

func TestDNSRulesTemplatesKernelsWebhooksTrafficSettings(t *testing.T) {
	ghFail := false
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ghFail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "SagerNet/sing-box") {
			_, _ = w.Write([]byte(`[{"tag_name":"v1.11.0","name":"v1.11.0","published_at":"2026-01-01T00:00:00Z","assets":[{"name":"sing-box-1.11.0-linux-amd64.tar.gz","browser_download_url":"https://example.com/sing-box-amd64.tar.gz","size":100}]}]`))
			return
		}
		_, _ = w.Write([]byte(`[{"tag_name":"v0.2.29","name":"v0.2.29","published_at":"2026-01-01T00:00:00Z","assets":[{"name":"shadow-tls-x86_64-unknown-linux-musl","browser_download_url":"https://example.com/shadow-tls-amd64","size":50}]}]`))
	}))
	defer ghSrv.Close()

	env := newTestEnv(t, nil, ghSrv.URL)

	// DNS Rule Group + node link + PUT/DELETE sync
	st, _, rawGrp := env.do(http.MethodPost, "/api/v1/admin/dns-rules", env.jwt, map[string]any{
		"name":  "Streaming",
		"rules": []string{"netflix.com"},
	})
	if st != http.StatusCreated {
		t.Fatalf("create dns group: %d %s", st, string(rawGrp))
	}
	var createdGrp struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rawGrp, &createdGrp); err != nil {
		t.Fatalf("unmarshal dns group: %v", err)
	}
	st, _, rawNode := env.do(http.MethodPost, "/api/v1/admin/nodes", env.jwt, map[string]any{
		"name":               "DNSNode",
		"dns_unlock_enabled": true,
		"dns_rule_group_id":  createdGrp.ID,
	})
	if st != http.StatusCreated {
		t.Fatalf("create node: %d %s", st, string(rawNode))
	}
	var node struct {
		ID        int64  `json:"id"`
		NodeToken string `json:"node_token"`
	}
	_ = json.Unmarshal(rawNode, &node)
	conn := env.dialAgent(node.NodeToken)
	_ = readEnv(t, conn)

	st, _, _ = env.do(http.MethodPut, fmt.Sprintf("/api/v1/admin/dns-rules/%d", createdGrp.ID), env.jwt, map[string]any{
		"name":  "Streaming",
		"rules": []string{"netflix.com", "disneyplus.com"},
	})
	if st != http.StatusOK {
		t.Fatalf("update dns group: %d", st)
	}
	_ = readEnv(t, conn)
	st, _, _ = env.do(http.MethodDelete, fmt.Sprintf("/api/v1/admin/dns-rules/%d", createdGrp.ID), env.jwt, nil)
	if st != http.StatusOK {
		t.Fatalf("delete dns group: %d", st)
	}
	_ = readEnv(t, conn)

	// Templates CRUD
	st, _, _ = env.do(http.MethodPost, "/api/v1/admin/templates", env.jwt, map[string]any{
		"name":        "BadTpl",
		"client_type": "invalid",
	})
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid client_type, got %d", st)
	}
	st, _, rawTpl := env.do(http.MethodPost, "/api/v1/admin/templates", env.jwt, map[string]any{
		"name":        "CustomMihomo",
		"client_type": "mihomo_user",
		"content":     "proxies:\n{{PROXIES}}\n",
		"is_default":  false,
	})
	if st != http.StatusCreated {
		t.Fatalf("create template: %d %s", st, string(rawTpl))
	}

	// Kernels
	st, _, _ = env.do(http.MethodPost, "/api/v1/admin/kernels/sync", env.jwt, nil)
	if st != http.StatusOK {
		t.Fatalf("kernel sync: %d", st)
	}
	ghFail = true
	st, _, _ = env.do(http.MethodPost, "/api/v1/admin/kernels/sync", env.jwt, nil)
	if st != http.StatusBadGateway {
		t.Fatalf("expected 502 on upstream failure, got %d", st)
	}
	st, _, _ = env.do(http.MethodPost, "/api/v1/admin/kernels/snell-versions", env.jwt, map[string]any{
		"version": "v5.0.2",
		"urls":    map[string]string{"amd64": "https://example.com/snell-amd64.zip"},
	})
	if st != http.StatusCreated {
		t.Fatalf("add snell version: %d", st)
	}
	st, _, _ = env.do(http.MethodDelete, "/api/v1/admin/kernels/snell-versions/v5.0.2", env.jwt, nil)
	if st != http.StatusOK {
		t.Fatalf("delete snell version: %d", st)
	}

	// Empty download_url with missing catalog match -> 400!
	st, _, rawKU := env.do(http.MethodPost, "/api/v1/admin/kernels/update", env.jwt, map[string]any{
		"node_ids":     []int64{node.ID},
		"kernel":       "sing-box",
		"version":      "1.99.99",
		"download_url": "",
	})
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 for unresolvable empty download_url, got %d body=%s", st, string(rawKU))
	}

	// Webhooks validation & test
	st, _, _ = env.do(http.MethodPost, "/api/v1/admin/webhooks", env.jwt, map[string]any{
		"name":     "BadHost",
		"provider": "custom",
		"url":      "https://example.com/hook",
		"secret":   `{"headers":{"Host":"evil.com"}}`,
	})
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 for forbidden Host header, got %d", st)
	}

	// Daily traffic DTO fields
	if err := env.store.UpsertAddDailyTraffic(context.Background(), "node", node.ID, "2026-11-23", 100, 200); err != nil {
		t.Fatal(err)
	}
	st, _, rawDaily := env.do(http.MethodGet, "/api/v1/admin/traffic/daily?target_type=node&target_id=1", env.jwt, nil)
	if st != http.StatusOK || !strings.Contains(string(rawDaily), `"node_id":1`) || !strings.Contains(string(rawDaily), `"date":"2026-11-23"`) || !strings.Contains(string(rawDaily), `"log_date":"2026-11-23"`) {
		t.Fatalf("unexpected daily traffic response: st=%d body=%s", st, string(rawDaily))
	}

	// Settings filtering, mapping, validation, and DNS sync
	st, _, rawSet := env.do(http.MethodGet, "/api/v1/admin/settings", env.jwt, nil)
	if st != http.StatusOK {
		t.Fatalf("get settings: %d", st)
	}
	for _, secretKey := range []string{"admin_password_hash", "jwt_secret", "node_token_enc", "kernel_versions_cache", "custom_snell_versions"} {
		if strings.Contains(string(rawSet), secretKey) {
			t.Fatalf("settings leaked internal key %q: %s", secretKey, string(rawSet))
		}
	}
	st, _, _ = env.do(http.MethodPut, "/api/v1/admin/settings", env.jwt, map[string]any{"jwt_secret": "hacked"})
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 writing internal key jwt_secret, got %d", st)
	}
	st, _, _ = env.do(http.MethodPut, "/api/v1/admin/settings", env.jwt, map[string]any{"offline_timeout_seconds": 0})
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 on offline_timeout_seconds=0, got %d", st)
	}
	st, _, rawSetUpd := env.do(http.MethodPut, "/api/v1/admin/settings", env.jwt, map[string]any{
		"percentage_only":        true,
		"default_local_dns_port": "15354",
		"default_upstream_dns":   "8.8.8.8:53",
	})
	if st != http.StatusOK || !strings.Contains(string(rawSetUpd), `"percentage_only":true`) || !strings.Contains(string(rawSetUpd), `"default_local_dns_port":15354`) {
		t.Fatalf("settings update unexpected: st=%d body=%s", st, string(rawSetUpd))
	}
	// Connected node should receive config_sync with new DNS defaults
	dnsSyncEnv := readEnv(t, conn)
	var dnsSync protocol.ServerConfigSync
	_ = dnsSyncEnv.DecodePayload(&dnsSync)
	if dnsSync.DNS.LocalPort != 15354 || dnsSync.DNS.UpstreamDNS != "8.8.8.8:53" {
		t.Fatalf("expected updated DNS defaults synced to node, got %+v", dnsSync.DNS)
	}
}

func TestStaticFSAndSPAFallback(t *testing.T) {
	staticFS := fstest.MapFS{
		"index.html":       {Data: []byte("<!doctype html><html><body>SPA</body></html>")},
		"assets/app.js":    {Data: []byte("console.log('ok');")},
		"assets/style.css": {Data: []byte("body{}")},
		"favicon.ico":      {Data: []byte("ico")},
	}
	env := newTestEnv(t, staticFS, "")

	for _, p := range []string{"/", "/admin", "/admin/", "/admin/nodes"} {
		st, hdr, raw := env.do(http.MethodGet, p, "", nil)
		if st != http.StatusOK || !strings.Contains(hdr.Get("Content-Type"), "text/html") || !strings.Contains(string(raw), "SPA") {
			t.Fatalf("SPA route %s unexpected: st=%d hdr=%v body=%s", p, st, hdr, string(raw))
		}
		if strings.Contains(strings.ToLower(hdr.Get("Cache-Control")), "immutable") {
			t.Fatalf("index.html must not have immutable cache-control: %s", hdr.Get("Cache-Control"))
		}
	}

	st, _, _ := env.do(http.MethodPost, "/", "", nil)
	if st != http.StatusMethodNotAllowed {
		t.Fatalf("POST / expected 405, got %d", st)
	}

	st, hdr, _ := env.do(http.MethodGet, "/assets/app.js", "", nil)
	if st != http.StatusOK || !strings.Contains(hdr.Get("Cache-Control"), "immutable") {
		t.Fatalf("/assets/app.js unexpected: st=%d hdr=%v", st, hdr)
	}

	// Missing asset -> 404, NOT SPA HTML
	st, _, raw := env.do(http.MethodGet, "/assets/missing.js", "", nil)
	if st != http.StatusNotFound || strings.Contains(string(raw), "SPA") {
		t.Fatalf("missing asset expected 404 non-HTML, got st=%d body=%s", st, string(raw))
	}

	// Unmatched /api/* -> 404 JSON, NOT SPA HTML
	st, hdr, raw = env.do(http.MethodGet, "/api/v1/unknown", "", nil)
	if st != http.StatusNotFound || !strings.Contains(hdr.Get("Content-Type"), "application/json") || strings.Contains(string(raw), "SPA") {
		t.Fatalf("unmatched /api/ expected 404 JSON, got st=%d ct=%s body=%s", st, hdr.Get("Content-Type"), string(raw))
	}

	// Unmatched /s/* -> 404, NOT SPA HTML
	st, _, raw = env.do(http.MethodGet, "/s/unknown", "", nil)
	if st != http.StatusNotFound || strings.Contains(string(raw), "SPA") {
		t.Fatalf("unmatched /s/ expected 404 non-HTML, got st=%d body=%s", st, string(raw))
	}

	// Traversal -> non-200, never leaks files
	st, _, raw = env.do(http.MethodGet, "/assets/../../go.mod", "", nil)
	if st == http.StatusOK || strings.Contains(string(raw), "snell-panel") {
		t.Fatalf("traversal leaked or returned 200: st=%d body=%s", st, string(raw))
	}
}

func TestSettingsUpdateBroadcastsPublicWS(t *testing.T) {
	env := newTestEnv(t, nil, "")

	st, _, rawN := env.do(http.MethodPost, "/api/v1/admin/nodes", env.jwt, map[string]any{
		"name":         "BroadcastNode",
		"region_tag":   "SG",
		"public_ip":    "203.0.113.88",
		"enabled":      true,
		"snell_config": protocol.SnellConfig{Enabled: true, Version: "v5", PublicPort: 2443, InnerPort: 31001, PSK: "secret-ws-psk"},
	})
	if st != http.StatusCreated {
		t.Fatalf("create node failed: %d %s", st, string(rawN))
	}

	wsURL := "ws" + strings.TrimPrefix(env.srv.URL, "http") + "/api/v1/public/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial public ws: %v", err)
	}
	defer conn.CloseNow()

	// Drain initial snapshot frame
	_, initMsg, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read initial public ws frame: %v", err)
	}
	var initSnap protocol.PublicStatusSnapshot
	if err := json.Unmarshal(initMsg, &initSnap); err != nil {
		t.Fatalf("unmarshal initial snapshot: %v", err)
	}
	if initSnap.PercentageOnly {
		t.Fatalf("expected initial percentage_only=false, got true")
	}

	// Update public-facing settings via PUT /api/v1/admin/settings
	st, _, rawUpd := env.do(http.MethodPut, "/api/v1/admin/settings", env.jwt, map[string]any{
		"site_title":      "Live Updated Panel",
		"announcement":    "Maintenance at 04:00 UTC",
		"percentage_only": true,
	})
	if st != http.StatusOK {
		t.Fatalf("PUT /settings failed: %d %s", st, string(rawUpd))
	}

	readCtx, readCancel := context.WithTimeout(ctx, 2*time.Second)
	_, pushedMsg, err := conn.Read(readCtx)
	readCancel()
	if err != nil {
		t.Fatalf("expected immediate public ws broadcast after settings update: %v", err)
	}
	for _, forbidden := range []string{"203.0.113.88", "secret-ws-psk", "jwt_secret", "admin_sub_token"} {
		if strings.Contains(string(pushedMsg), forbidden) {
			t.Fatalf("pushed public ws frame leaked forbidden data %q: %s", forbidden, string(pushedMsg))
		}
	}
	var pushedSnap protocol.PublicStatusSnapshot
	if err := json.Unmarshal(pushedMsg, &pushedSnap); err != nil {
		t.Fatalf("unmarshal pushed snapshot: %v", err)
	}
	if pushedSnap.SiteTitle != "Live Updated Panel" || pushedSnap.Announcement != "Maintenance at 04:00 UTC" || !pushedSnap.PercentageOnly {
		t.Fatalf("unexpected pushed snapshot after settings update: %+v", pushedSnap)
	}

	// Update via public_percentage_only=false and clear announcement
	st, _, rawUpd2 := env.do(http.MethodPut, "/api/v1/admin/settings", env.jwt, map[string]any{
		"announcement":           "",
		"public_percentage_only": false,
	})
	if st != http.StatusOK {
		t.Fatalf("second PUT /settings failed: %d %s", st, string(rawUpd2))
	}

	readCtx2, readCancel2 := context.WithTimeout(ctx, 2*time.Second)
	_, pushedMsg2, err := conn.Read(readCtx2)
	readCancel2()
	if err != nil {
		t.Fatalf("expected immediate public ws broadcast after second settings update: %v", err)
	}
	var pushedSnap2 protocol.PublicStatusSnapshot
	if err := json.Unmarshal(pushedMsg2, &pushedSnap2); err != nil {
		t.Fatalf("unmarshal second pushed snapshot: %v", err)
	}
	if pushedSnap2.Announcement != "" || pushedSnap2.PercentageOnly {
		t.Fatalf("expected cleared announcement and percentage_only=false, got %+v", pushedSnap2)
	}
}

func TestTier5_AdminCRUDAndCoverageEndpoints(t *testing.T) {
	env := newTestEnv(t, nil, "")

	// 1. Create a node with valid SS2022 config + DNS rule group, then hit ListNodes.
	st, _, rawG := env.do(http.MethodPost, "/api/v1/admin/dns-rules", env.jwt, map[string]any{
		"name":  "JP-DNS",
		"rules": []string{"DOMAIN-SUFFIX,jp,direct"},
	})
	if st != http.StatusCreated {
		t.Fatalf("create dns-rules failed: %d %s", st, string(rawG))
	}
	var dnsGroup struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(rawG, &dnsGroup); err != nil {
		t.Fatal(err)
	}

	st, _, rawListG := env.do(http.MethodGet, "/api/v1/admin/dns-rules", env.jwt, nil)
	if st != http.StatusOK || !strings.Contains(string(rawListG), "JP-DNS") {
		t.Fatalf("GET /dns-rules failed: %d %s", st, string(rawListG))
	}
	st, _, rawGetG := env.do(http.MethodGet, fmt.Sprintf("/api/v1/admin/dns-rules/%d", dnsGroup.ID), env.jwt, nil)
	if st != http.StatusOK || !strings.Contains(string(rawGetG), "DOMAIN-SUFFIX,jp,direct") {
		t.Fatalf("GET /dns-rules/%d failed: %d %s", dnsGroup.ID, st, string(rawGetG))
	}
	st, _, _ = env.do(http.MethodGet, "/api/v1/admin/dns-rules/999999", env.jwt, nil)
	if st != http.StatusNotFound {
		t.Fatalf("expected 404 for missing dns rule group, got %d", st)
	}

	st, _, rawNode := env.do(http.MethodPost, "/api/v1/admin/nodes", env.jwt, map[string]any{
		"name":              "T5-Node",
		"entry_ip":          "198.51.100.11",
		"billing_reset_day": 15,
		"dns_rule_group_id": dnsGroup.ID,
		"snell_config": protocol.SnellConfig{
			Enabled:    true,
			Version:    "v5",
			PublicPort: 2443,
			InnerPort:  31001,
			PSK:        "snell-psk-1",
		},
		"ss_config": protocol.SSConfig{
			Enabled: true,
			TCPPort: 25443,
			UDPPort: 25443,
			Cipher:  "2022-blake3-aes-128-gcm",
			IPSK:    "Q0FOQVJZX1NTX0lQU0tfMQ==",
		},
	})
	if st != http.StatusCreated {
		t.Fatalf("create node failed: %d %s", st, string(rawNode))
	}
	var nodeResp struct {
		ID            int64  `json:"id"`
		Name          string `json:"name"`
		DNSRuleGroup  *int64 `json:"dns_rule_group_id"`
		ReportedToken string `json:"node_token"`
	}
	if err := json.Unmarshal(rawNode, &nodeResp); err != nil {
		t.Fatal(err)
	}

	// optionalInt64.UnmarshalJSON: null clears dns_rule_group_id; string fails 400.
	st, _, rawBadClear := env.do(http.MethodPut, fmt.Sprintf("/api/v1/admin/nodes/%d", nodeResp.ID), env.jwt, map[string]any{
		"dns_rule_group_id": "not-an-int",
	})
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid dns_rule_group_id string, got %d %s", st, string(rawBadClear))
	}
	st, _, rawClear := env.do(http.MethodPut, fmt.Sprintf("/api/v1/admin/nodes/%d", nodeResp.ID), env.jwt, map[string]any{
		"dns_rule_group_id": nil,
	})
	if st != http.StatusOK {
		t.Fatalf("expected 200 clearing dns_rule_group_id with null, got %d %s", st, string(rawClear))
	}

	st, _, rawListN := env.do(http.MethodGet, "/api/v1/admin/nodes", env.jwt, nil)
	if st != http.StatusOK || !strings.Contains(string(rawListN), "T5-Node") {
		t.Fatalf("GET /admin/nodes failed: %d %s", st, string(rawListN))
	}

	// Delete DNS rule group works cleanly after unlinking node.
	st, _, rawDelG := env.do(http.MethodDelete, fmt.Sprintf("/api/v1/admin/dns-rules/%d", dnsGroup.ID), env.jwt, nil)
	if st != http.StatusOK && st != http.StatusNoContent {
		t.Fatalf("DELETE /dns-rules failed: %d %s", st, string(rawDelG))
	}

	// 2. User CRUD: GetUser (found & 404), optionalTime.UnmarshalJSON (valid, null, invalid).
	st, _, rawU := env.do(http.MethodPost, "/api/v1/admin/users", env.jwt, map[string]any{
		"username":            "tier5user",
		"traffic_quota_bytes": 1000000,
		"node_ids":            []int64{nodeResp.ID},
	})
	if st != http.StatusCreated {
		t.Fatalf("create user failed: %d %s", st, string(rawU))
	}
	var userResp struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rawU, &userResp); err != nil {
		t.Fatal(err)
	}

	st, _, rawGetU := env.do(http.MethodGet, fmt.Sprintf("/api/v1/admin/users/%d", userResp.ID), env.jwt, nil)
	if st != http.StatusOK || !strings.Contains(string(rawGetU), "tier5user") {
		t.Fatalf("GET /admin/users/%d failed: %d %s", userResp.ID, st, string(rawGetU))
	}
	st, _, _ = env.do(http.MethodGet, "/api/v1/admin/users/999999", env.jwt, nil)
	if st != http.StatusNotFound {
		t.Fatalf("expected 404 for missing user, got %d", st)
	}
	st, _, rawBadExp := env.do(http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d", userResp.ID), env.jwt, map[string]any{
		"expire_at": "invalid-rfc3339",
	})
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid expire_at, got %d %s", st, string(rawBadExp))
	}
	st, _, rawSetExp := env.do(http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d", userResp.ID), env.jwt, map[string]any{
		"expire_at": "2030-01-01T00:00:00Z",
	})
	if st != http.StatusOK || !strings.Contains(string(rawSetExp), "2030-01-01T00:00:00Z") {
		t.Fatalf("expected 200 setting expire_at, got %d %s", st, string(rawSetExp))
	}
	st, _, rawClrExp := env.do(http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d", userResp.ID), env.jwt, map[string]any{
		"expire_at": nil,
	})
	if st != http.StatusOK || !strings.Contains(string(rawClrExp), `"expire_at":null`) {
		t.Fatalf("expected 200 clearing expire_at with null, got %d %s", st, string(rawClrExp))
	}

	// 3. Templates CRUD (List, Get, Update, Delete, 404).
	st, _, rawTpl := env.do(http.MethodPost, "/api/v1/admin/templates", env.jwt, map[string]any{
		"name":        "T5-Template",
		"client_type": protocol.ClientTypeMihomoUser,
		"content":     "proxies:\n  {{PROXY_NAMES}}",
	})
	if st != http.StatusCreated {
		t.Fatalf("create template failed: %d %s", st, string(rawTpl))
	}
	var tplResp struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rawTpl, &tplResp); err != nil {
		t.Fatal(err)
	}
	st, _, rawListTpl := env.do(http.MethodGet, "/api/v1/admin/templates", env.jwt, nil)
	if st != http.StatusOK || !strings.Contains(string(rawListTpl), "T5-Template") {
		t.Fatalf("GET /templates failed: %d %s", st, string(rawListTpl))
	}
	st, _, rawGetTpl := env.do(http.MethodGet, fmt.Sprintf("/api/v1/admin/templates/%d", tplResp.ID), env.jwt, nil)
	if st != http.StatusOK || !strings.Contains(string(rawGetTpl), "T5-Template") {
		t.Fatalf("GET /templates/%d failed: %d %s", tplResp.ID, st, string(rawGetTpl))
	}
	st, _, rawUpdTpl := env.do(http.MethodPut, fmt.Sprintf("/api/v1/admin/templates/%d", tplResp.ID), env.jwt, map[string]any{
		"name":        "T5-Template-Renamed",
		"client_type": protocol.ClientTypeMihomoUser,
		"content":     "proxies:\n  [{{PROXY_NAMES}}]",
	})
	if st != http.StatusOK || !strings.Contains(string(rawUpdTpl), "T5-Template-Renamed") {
		t.Fatalf("PUT /templates/%d failed: %d %s", tplResp.ID, st, string(rawUpdTpl))
	}
	st, _, _ = env.do(http.MethodDelete, fmt.Sprintf("/api/v1/admin/templates/%d", tplResp.ID), env.jwt, nil)
	if st != http.StatusOK && st != http.StatusNoContent {
		t.Fatalf("DELETE /templates/%d failed: %d", st, st)
	}
	st, _, _ = env.do(http.MethodGet, fmt.Sprintf("/api/v1/admin/templates/%d", tplResp.ID), env.jwt, nil)
	if st != http.StatusNotFound {
		t.Fatalf("expected 404 after deleting template, got %d", st)
	}

	// 4. Kernels list & snell-versions list.
	st, _, _ = env.do(http.MethodGet, "/api/v1/admin/kernels", env.jwt, nil)
	if st != http.StatusOK {
		t.Fatalf("GET /kernels failed: %d", st)
	}
	st, _, rawSV := env.do(http.MethodGet, "/api/v1/admin/kernels/snell-versions", env.jwt, nil)
	if st != http.StatusOK || !strings.Contains(string(rawSV), "v5") {
		t.Fatalf("GET /kernels/snell-versions failed: %d %s", st, string(rawSV))
	}

	// 5. Bug BUG-B1: Settings defaults include alert_user_expired=true & alert_user_quota_exhausted=true.
	st, _, rawSet := env.do(http.MethodGet, "/api/v1/admin/settings", env.jwt, nil)
	if st != http.StatusOK {
		t.Fatalf("GET /settings failed: %d %s", st, string(rawSet))
	}
	var settingsResp struct {
		AlertUserExpired        bool `json:"alert_user_expired"`
		AlertUserQuotaExhausted bool `json:"alert_user_quota_exhausted"`
	}
	if err := json.Unmarshal(rawSet, &settingsResp); err != nil {
		t.Fatal(err)
	}
	if !settingsResp.AlertUserExpired || !settingsResp.AlertUserQuotaExhausted {
		t.Fatalf("expected alert_user_expired & alert_user_quota_exhausted default true, got %+v", settingsResp)
	}

	// 6. Webhooks CRUD + Test + provider switch clears stale custom_template.
	whHits := 0
	whSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		whHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer whSrv.Close()

	st, _, rawWH := env.do(http.MethodPost, "/api/v1/admin/webhooks", env.jwt, map[string]any{
		"name":              "Custom-Hook",
		"provider":          "custom",
		"url":               whSrv.URL,
		"subscribed_events": []string{"*"},
		"enabled":           true,
		"custom_template":   `{"target": {{jsonQuote .TargetName}}, "msg": {{jsonQuote .Message}}}`,
	})
	if st != http.StatusCreated {
		t.Fatalf("create custom webhook failed: %d %s", st, string(rawWH))
	}
	var whResp struct {
		ID             int64  `json:"id"`
		Provider       string `json:"provider"`
		CustomTemplate string `json:"custom_template"`
	}
	if err := json.Unmarshal(rawWH, &whResp); err != nil {
		t.Fatal(err)
	}
	if whResp.CustomTemplate == "" {
		t.Fatalf("expected custom_template populated on create, got empty")
	}

	st, _, rawListWH := env.do(http.MethodGet, "/api/v1/admin/webhooks", env.jwt, nil)
	if st != http.StatusOK || !strings.Contains(string(rawListWH), "Custom-Hook") {
		t.Fatalf("GET /webhooks failed: %d %s", st, string(rawListWH))
	}
	st, _, rawGetWH := env.do(http.MethodGet, fmt.Sprintf("/api/v1/admin/webhooks/%d", whResp.ID), env.jwt, nil)
	if st != http.StatusOK || !strings.Contains(string(rawGetWH), "Custom-Hook") {
		t.Fatalf("GET /webhooks/%d failed: %d %s", whResp.ID, st, string(rawGetWH))
	}
	st, _, rawTestWH := env.do(http.MethodPost, fmt.Sprintf("/api/v1/admin/webhooks/%d/test", whResp.ID), env.jwt, nil)
	if st != http.StatusOK || whHits != 1 {
		t.Fatalf("POST /webhooks/%d/test failed: status=%d hits=%d body=%s", whResp.ID, st, whHits, string(rawTestWH))
	}

	// Switch provider custom -> feishu: custom_template must be cleared and not resurrected on switch back.
	st, _, rawSw1 := env.do(http.MethodPut, fmt.Sprintf("/api/v1/admin/webhooks/%d", whResp.ID), env.jwt, map[string]any{
		"name":              "Custom-Hook",
		"provider":          "feishu",
		"url":               whSrv.URL,
		"subscribed_events": []string{"*"},
		"enabled":           true,
	})
	if st != http.StatusOK {
		t.Fatalf("switch webhook to feishu failed: %d %s", st, string(rawSw1))
	}
	var sw1 struct {
		Provider       string `json:"provider"`
		CustomTemplate string `json:"custom_template"`
	}
	if err := json.Unmarshal(rawSw1, &sw1); err != nil {
		t.Fatal(err)
	}
	if sw1.Provider != "feishu" || sw1.CustomTemplate != "" {
		t.Fatalf("expected custom_template cleared on feishu switch, got %+v", sw1)
	}
	st, _, rawSw2 := env.do(http.MethodPut, fmt.Sprintf("/api/v1/admin/webhooks/%d", whResp.ID), env.jwt, map[string]any{
		"name":              "Custom-Hook",
		"provider":          "custom",
		"url":               whSrv.URL,
		"subscribed_events": []string{"*"},
		"enabled":           true,
	})
	if st != http.StatusOK {
		t.Fatalf("switch webhook back to custom failed: %d %s", st, string(rawSw2))
	}
	var sw2 struct {
		CustomTemplate string `json:"custom_template"`
	}
	if err := json.Unmarshal(rawSw2, &sw2); err != nil {
		t.Fatal(err)
	}
	if sw2.CustomTemplate != "" {
		t.Fatalf("expected stale custom_template NOT resurrected when switching back to custom, got %q", sw2.CustomTemplate)
	}

	st, _, _ = env.do(http.MethodDelete, fmt.Sprintf("/api/v1/admin/webhooks/%d", whResp.ID), env.jwt, nil)
	if st != http.StatusOK && st != http.StatusNoContent {
		t.Fatalf("DELETE /webhooks/%d failed: %d", whResp.ID, st)
	}

	// 7. Daily traffic endpoint validation & date boundary branches.
	if err := env.store.UpsertAddDailyTraffic(context.Background(), "node", nodeResp.ID, "2026-11-20", 123, 456); err != nil {
		t.Fatal(err)
	}
	st, _, _ = env.do(http.MethodGet, "/api/v1/admin/traffic/daily?target_id=abc", env.jwt, nil)
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-numeric target_id, got %d", st)
	}
	st, _, _ = env.do(http.MethodGet, "/api/v1/admin/traffic/daily?target_id=-5", env.jwt, nil)
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 for negative target_id, got %d", st)
	}
	st, _, rawOut := env.do(http.MethodGet, "/api/v1/admin/traffic/daily?from_date=2099-01-01", env.jwt, nil)
	if st != http.StatusOK || strings.TrimSpace(string(rawOut)) != "[]" {
		t.Fatalf("expected empty 200 [] for out-of-range from_date, got %d %s", st, string(rawOut))
	}
	st, _, rawIn := env.do(http.MethodGet, fmt.Sprintf("/api/v1/admin/traffic/daily?target_type=node&target_id=%d&from=2026-11-20&to=2026-11-20", nodeResp.ID), env.jwt, nil)
	if st != http.StatusOK || !strings.Contains(string(rawIn), `"rx_bytes":123`) {
		t.Fatalf("expected matching daily traffic row for boundary date, got %d %s", st, string(rawIn))
	}
}

func TestTier5_BugB5_SS2022ValidationRejectsBadCipherAndIPSK(t *testing.T) {
	env := newTestEnv(t, nil, "")

	cases := []struct {
		name string
		ss   protocol.SSConfig
	}{
		{
			name: "empty cipher",
			ss: protocol.SSConfig{
				Enabled: true, TCPPort: 25001, UDPPort: 25001,
				Cipher: "", IPSK: "Q0FOQVJZX1NTX0lQU0tfMQ==",
			},
		},
		{
			name: "unsupported cipher",
			ss: protocol.SSConfig{
				Enabled: true, TCPPort: 25002, UDPPort: 25002,
				Cipher: "aes-256-gcm", IPSK: "Q0FOQVJZX1NTX0lQU0tfMQ==",
			},
		},
		{
			name: "non-base64 ipsk",
			ss: protocol.SSConfig{
				Enabled: true, TCPPort: 25003, UDPPort: 25003,
				Cipher: "2022-blake3-aes-128-gcm", IPSK: "not-base64-ipsk",
			},
		},
		{
			name: "16B ipsk for aes-256-gcm",
			ss: protocol.SSConfig{
				Enabled: true, TCPPort: 25004, UDPPort: 25004,
				Cipher: "2022-blake3-aes-256-gcm", IPSK: "Q0FOQVJZX1NTX0lQU0tfMQ==",
			},
		},
		{
			name: "32B ipsk for aes-128-gcm",
			ss: protocol.SSConfig{
				Enabled: true, TCPPort: 25005, UDPPort: 25005,
				Cipher: "2022-blake3-aes-128-gcm", IPSK: "Q0FOQVJZX0YxNV9TU19JUFNLXzMyQllURVNfMDAwMDE=",
			},
		},
	}

	for _, tc := range cases {
		st, _, raw := env.do(http.MethodPost, "/api/v1/admin/nodes", env.jwt, map[string]any{
			"name":              "bad-" + tc.name,
			"entry_ip":          "198.51.100.55",
			"billing_reset_day": 1,
			"ss_config":         tc.ss,
		})
		if st != http.StatusBadRequest {
			t.Fatalf("%s: expected 400 on POST node, got %d %s", tc.name, st, string(raw))
		}
	}

	// Create valid node, then verify PUT rejects bad SS2022 key too.
	st, _, rawOK := env.do(http.MethodPost, "/api/v1/admin/nodes", env.jwt, map[string]any{
		"name":              "valid-ss",
		"entry_ip":          "198.51.100.56",
		"billing_reset_day": 1,
		"ss_config": protocol.SSConfig{
			Enabled: true, TCPPort: 25010, UDPPort: 25010,
			Cipher: "2022-blake3-aes-256-gcm",
			IPSK:   "Q0FOQVJZX0YxNV9TU19JUFNLXzMyQllURVNfMDAwMDE=",
		},
	})
	if st != http.StatusCreated {
		t.Fatalf("expected 201 for valid 32B SS2022 node, got %d %s", st, string(rawOK))
	}
	var created struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rawOK, &created); err != nil {
		t.Fatal(err)
	}
	st, _, rawPutBad := env.do(http.MethodPut, fmt.Sprintf("/api/v1/admin/nodes/%d", created.ID), env.jwt, map[string]any{
		"ss_config": protocol.SSConfig{
			Enabled: true, TCPPort: 25010, UDPPort: 25010,
			Cipher: "2022-blake3-aes-256-gcm",
			IPSK:   "wrong-length-or-not-base64",
		},
	})
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 on PUT invalid SS2022 iPSK, got %d %s", st, string(rawPutBad))
	}
}

func TestTier5_BugB7_CustomWebhookTemplateRejectsUnescapedJSONInterpolation(t *testing.T) {
	env := newTestEnv(t, nil, "")

	badTemplates := []string{
		`{"target": "{{.TargetName}}"}`,
		`{"title": "{{.Title}}"}`,
		`{"msg": "{{.Message}}"}`,
		`{"detail": "{{.Detail}}"}`,
	}
	for _, tpl := range badTemplates {
		st, _, raw := env.do(http.MethodPost, "/api/v1/admin/webhooks", env.jwt, map[string]any{
			"name":              "Bad-Tpl",
			"provider":          "custom",
			"url":               "https://example.com/hook",
			"subscribed_events": []string{"*"},
			"enabled":           true,
			"custom_template":   tpl,
		})
		if st != http.StatusBadRequest {
			t.Fatalf("expected 400 for unescaped template %s, got %d %s", tpl, st, string(raw))
		}
		if !strings.Contains(string(raw), "jsonEscape") {
			t.Fatalf("expected jsonEscape hint in error for %s, got %s", tpl, string(raw))
		}
	}

	// Proper escaping with jsonEscape / jsonQuote must be accepted.
	st, _, rawGood := env.do(http.MethodPost, "/api/v1/admin/webhooks", env.jwt, map[string]any{
		"name":              "Good-Tpl",
		"provider":          "custom",
		"url":               "https://example.com/hook",
		"subscribed_events": []string{"*"},
		"enabled":           true,
		"custom_template":   `{"target":"{{jsonEscape .TargetName}}","title":{{jsonQuote .Title}},"msg":"{{jsonEscape .Message}}","detail":{{jsonQuote .Detail}}}`,
	})
	if st != http.StatusCreated {
		t.Fatalf("expected 201 for properly escaped custom template, got %d %s", st, string(rawGood))
	}
}

func TestTier5_BugB4_DeleteNodeEvictsActiveAgentWS(t *testing.T) {
	env := newTestEnv(t, nil, "")

	st, _, rawN := env.do(http.MethodPost, "/api/v1/admin/nodes", env.jwt, map[string]any{
		"name":              "Evict-Node",
		"entry_ip":          "198.51.100.77",
		"billing_reset_day": 1,
		"snell_config": protocol.SnellConfig{
			Enabled: true, Version: "v5", PublicPort: 2443, InnerPort: 31001, PSK: "evict-psk",
		},
	})
	if st != http.StatusCreated {
		t.Fatalf("create node failed: %d %s", st, string(rawN))
	}
	var node struct {
		ID        int64  `json:"id"`
		NodeToken string `json:"node_token"`
	}
	if err := json.Unmarshal(rawN, &node); err != nil {
		t.Fatal(err)
	}

	wsURL := "ws" + strings.TrimPrefix(env.srv.URL, "http") + "/api/v1/agent/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + node.NodeToken}},
	})
	if err != nil {
		t.Fatalf("dial agent ws: %v", err)
	}
	defer conn.CloseNow()

	// Wait until hub registers the online session.
	deadline := time.Now().Add(2 * time.Second)
	for !env.hub.IsOnline(node.ID) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !env.hub.IsOnline(node.ID) {
		t.Fatal("expected node to register online on hub")
	}

	// Read initial sync frame so connection setup finishes before deletion.
	if _, _, err := conn.Read(ctx); err != nil {
		t.Fatalf("read initial sync frame: %v", err)
	}

	// Read frames until deletion closes the WS.
	closedCh := make(chan error, 1)
	go func() {
		for {
			_, _, rerr := conn.Read(ctx)
			if rerr != nil {
				closedCh <- rerr
				return
			}
		}
	}()

	st, _, rawDel := env.do(http.MethodDelete, fmt.Sprintf("/api/v1/admin/nodes/%d", node.ID), env.jwt, nil)
	if st != http.StatusOK && st != http.StatusNoContent {
		t.Fatalf("DELETE /admin/nodes/%d failed: %d %s", node.ID, st, string(rawDel))
	}

	if env.hub.IsOnline(node.ID) {
		t.Fatalf("expected node %d to be immediately evicted from hub after DELETE", node.ID)
	}
	select {
	case rerr := <-closedCh:
		if rerr == nil {
			t.Fatal("expected non-nil read error after eviction")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for deleted node WS connection to close")
	}
}

func TestTier5_BugB8_UpdateUserConflictDoesNotMutateNodeAccess(t *testing.T) {
	env := newTestEnv(t, nil, "")

	createNode := func(name string, port int) (int64, string) {
		t.Helper()
		st, _, raw := env.do(http.MethodPost, "/api/v1/admin/nodes", env.jwt, map[string]any{
			"name":              name,
			"entry_ip":          "198.51.100.88",
			"billing_reset_day": 1,
			"ss_config": protocol.SSConfig{
				Enabled: true, TCPPort: port, UDPPort: port,
				Cipher: "2022-blake3-aes-128-gcm",
				IPSK:   "Q0FOQVJZX1NTX0lQU0tfMQ==",
			},
		})
		if st != http.StatusCreated {
			t.Fatalf("create node %s: %d %s", name, st, string(raw))
		}
		var resp struct {
			ID        int64  `json:"id"`
			NodeToken string `json:"node_token"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			t.Fatal(err)
		}
		return resp.ID, resp.NodeToken
	}

	n1ID, n1Tok := createNode("B8-Node-1", 26001)
	n2ID, n2Tok := createNode("B8-Node-2", 26002)

	conn1 := env.dialAgent(n1Tok)
	conn2 := env.dialAgent(n2Tok)
	_ = readEnv(t, conn1) // initial sync on connect
	_ = readEnv(t, conn2) // initial sync on connect

	createUser := func(username string, quota int64, nodeIDs []int64) int64 {
		t.Helper()
		st, _, raw := env.do(http.MethodPost, "/api/v1/admin/users", env.jwt, map[string]any{
			"username":            username,
			"traffic_quota_bytes": quota,
			"node_ids":            nodeIDs,
		})
		if st != http.StatusCreated {
			t.Fatalf("create user %s: %d %s", username, st, string(raw))
		}
		var u struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(raw, &u); err != nil {
			t.Fatal(err)
		}
		return u.ID
	}

	_ = createUser("alice", 1024, []int64{n1ID})
	_ = readEnv(t, conn1) // config_sync after alice created
	bobID := createUser("bob", 2048, []int64{n1ID})
	_ = readEnv(t, conn1) // config_sync after bob created

	// Continuous readers on conn1/conn2 to verify no spurious config_sync on failed PUTs.
	readCh := func(conn *websocket.Conn) <-chan protocol.Envelope {
		ch := make(chan protocol.Envelope, 8)
		go func() {
			for {
				_, data, err := conn.Read(context.Background())
				if err != nil {
					return
				}
				var envMsg protocol.Envelope
				if err := json.Unmarshal(data, &envMsg); err == nil {
					ch <- envMsg
				}
			}
		}()
		return ch
	}
	ch1 := readCh(conn1)
	ch2 := readCh(conn2)

	n1Before, err := env.store.GetNodeByID(context.Background(), n1ID)
	if err != nil {
		t.Fatal(err)
	}
	n2Before, err := env.store.GetNodeByID(context.Background(), n2ID)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Conflicting username + modified node_ids -> 409 Conflict, node access must NOT change.
	st, _, rawConflict := env.do(http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d", bobID), env.jwt, map[string]any{
		"username": "alice",
		"node_ids": []int64{n2ID},
	})
	if st != http.StatusConflict {
		t.Fatalf("expected 409 Conflict on duplicate username, got %d %s", st, string(rawConflict))
	}

	st, _, rawNodes := env.do(http.MethodGet, fmt.Sprintf("/api/v1/admin/users/%d/nodes", bobID), env.jwt, nil)
	if st != http.StatusOK {
		t.Fatalf("GET /admin/users/%d/nodes failed: %d %s", bobID, st, string(rawNodes))
	}
	var nodesResp struct {
		NodeIDs []int64 `json:"node_ids"`
	}
	if err := json.Unmarshal(rawNodes, &nodesResp); err != nil {
		t.Fatal(err)
	}
	if len(nodesResp.NodeIDs) != 1 || nodesResp.NodeIDs[0] != n1ID {
		t.Fatalf("expected bob node_ids preserved as [%d] after 409 conflict, got %v", n1ID, nodesResp.NodeIDs)
	}

	// 2. Invalid node_id FK + modified user fields -> 400 Bad Request, user fields AND node_ids preserved.
	st, _, rawFK := env.do(http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d", bobID), env.jwt, map[string]any{
		"username":            "bob-should-rollback",
		"traffic_quota_bytes": 99999,
		"node_ids":            []int64{999999},
	})
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 on invalid node_ids FK, got %d %s", st, string(rawFK))
	}
	st, _, rawBob := env.do(http.MethodGet, fmt.Sprintf("/api/v1/admin/users/%d", bobID), env.jwt, nil)
	if st != http.StatusOK {
		t.Fatalf("GET /admin/users/%d failed: %d %s", bobID, st, string(rawBob))
	}
	var bobResp struct {
		Username          string  `json:"username"`
		TrafficQuotaBytes int64   `json:"traffic_quota_bytes"`
		NodeIDs           []int64 `json:"node_ids"`
	}
	if err := json.Unmarshal(rawBob, &bobResp); err != nil {
		t.Fatal(err)
	}
	if bobResp.Username != "bob" || bobResp.TrafficQuotaBytes != 2048 || len(bobResp.NodeIDs) != 1 || bobResp.NodeIDs[0] != n1ID {
		t.Fatalf("expected bob fully intact after FK rollback, got %+v", bobResp)
	}

	// Neither node's config_revision should bump and neither WS should receive config_sync.
	n1AfterFail, _ := env.store.GetNodeByID(context.Background(), n1ID)
	n2AfterFail, _ := env.store.GetNodeByID(context.Background(), n2ID)
	if n1AfterFail.ConfigRevision != n1Before.ConfigRevision || n2AfterFail.ConfigRevision != n2Before.ConfigRevision {
		t.Fatalf("expected config_revision unchanged on rejected PUTs: n1 %d->%d n2 %d->%d",
			n1Before.ConfigRevision, n1AfterFail.ConfigRevision, n2Before.ConfigRevision, n2AfterFail.ConfigRevision)
	}
	select {
	case msg := <-ch1:
		t.Fatalf("unexpected WS frame on node 1 after rejected PUT: %+v", msg)
	case msg := <-ch2:
		t.Fatalf("unexpected WS frame on node 2 after rejected PUT: %+v", msg)
	case <-time.After(100 * time.Millisecond):
	}

	// 3. Valid PUT updates username + node_ids atomically and syncs both old (n1) and new (n2) nodes.
	st, _, rawOK := env.do(http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d", bobID), env.jwt, map[string]any{
		"username": "bob-v2",
		"node_ids": []int64{n2ID},
	})
	if st != http.StatusOK {
		t.Fatalf("expected 200 on valid PUT, got %d %s", st, string(rawOK))
	}
	if err := json.Unmarshal(rawOK, &bobResp); err != nil {
		t.Fatal(err)
	}
	if bobResp.Username != "bob-v2" || len(bobResp.NodeIDs) != 1 || bobResp.NodeIDs[0] != n2ID {
		t.Fatalf("unexpected updated bob DTO: %+v", bobResp)
	}

	n1AfterOK, _ := env.store.GetNodeByID(context.Background(), n1ID)
	n2AfterOK, _ := env.store.GetNodeByID(context.Background(), n2ID)
	if n1AfterOK.ConfigRevision != n1Before.ConfigRevision+1 || n2AfterOK.ConfigRevision != n2Before.ConfigRevision+1 {
		t.Fatalf("expected config_revision incremented on both n1 and n2: n1 %d->%d n2 %d->%d",
			n1Before.ConfigRevision, n1AfterOK.ConfigRevision, n2Before.ConfigRevision, n2AfterOK.ConfigRevision)
	}

	var sync1, sync2 protocol.ServerConfigSync
	select {
	case msg := <-ch1:
		if err := msg.DecodePayload(&sync1); err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for config_sync on node 1")
	}
	select {
	case msg := <-ch2:
		if err := msg.DecodePayload(&sync2); err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for config_sync on node 2")
	}
	if len(sync1.SS.Users) != 1 || sync1.SS.Users[0].Username != "alice" {
		t.Fatalf("expected node 1 to only have alice after move, got %+v", sync1.SS.Users)
	}
	if len(sync2.SS.Users) != 1 || sync2.SS.Users[0].Username != "bob-v2" {
		t.Fatalf("expected node 2 to have bob-v2 after move, got %+v", sync2.SS.Users)
	}
}

func TestUserTrafficBreakdownAndServerChanWebhookAPI(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, nil, "")

	n1 := &store.Node{Name: "Node-Small", RegionTag: "HK", TokenHash: "h_bk_1", Enabled: true, Status: protocol.NodeStatusOnline}
	n2 := &store.Node{Name: "Node-Large", RegionTag: "SG", TokenHash: "h_bk_2", Enabled: true, Status: protocol.NodeStatusOnline}
	if err := env.store.CreateNode(ctx, n1); err != nil {
		t.Fatal(err)
	}
	if err := env.store.CreateNode(ctx, n2); err != nil {
		t.Fatal(err)
	}
	u := &store.User{
		Username:        "alice_bk",
		Enabled:         true,
		SubToken:        "sub_bk_1",
		SSUPSK16:        "AAAAAAAAAAAAAAAAAAAAAA==",
		SSUPSK32:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		STLSPassword:    "pw",
		BillingResetDay: 1,
	}
	if err := env.store.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}

	if _, err := env.store.ApplyTrafficDeltas(ctx, n1.ID, 100, 200, []protocol.UserTrafficDelta{
		{UserID: u.ID, UpBytes: 300, DownBytes: 700},
	}, "2026-11-24"); err != nil {
		t.Fatal(err)
	}
	if _, err := env.store.ApplyTrafficDeltas(ctx, n2.ID, 500, 600, []protocol.UserTrafficDelta{
		{UserID: u.ID, UpBytes: 2000, DownBytes: 8000},
	}, "2026-11-24"); err != nil {
		t.Fatal(err)
	}

	st, _, rawBk := env.do(http.MethodGet, fmt.Sprintf("/api/v1/admin/users/%d/traffic-breakdown", u.ID), env.jwt, nil)
	if st != http.StatusOK {
		t.Fatalf("GET traffic-breakdown failed: %d %s", st, string(rawBk))
	}
	var bkResp struct {
		UserID     int64                        `json:"user_id"`
		Username   string                       `json:"username"`
		TotalBytes int64                        `json:"total_bytes"`
		Items      []store.UserNodeTrafficEntry `json:"items"`
	}
	if err := json.Unmarshal(rawBk, &bkResp); err != nil {
		t.Fatal(err)
	}
	if bkResp.UserID != u.ID || bkResp.Username != "alice_bk" || bkResp.TotalBytes != 11000 {
		t.Fatalf("unexpected breakdown header: %+v", bkResp)
	}
	if len(bkResp.Items) != 2 || bkResp.Items[0].NodeID != n2.ID || bkResp.Items[0].TotalBytes != 10000 ||
		bkResp.Items[1].NodeID != n1.ID || bkResp.Items[1].TotalBytes != 1000 {
		t.Fatalf("expected descending per-node breakdown [Node-Large(10000), Node-Small(1000)], got %+v", bkResp.Items)
	}

	// Reset clears user breakdown too.
	st, _, _ = env.do(http.MethodPost, fmt.Sprintf("/api/v1/admin/users/%d/reset-traffic", u.ID), env.jwt, nil)
	if st != http.StatusOK {
		t.Fatalf("reset traffic failed: %d", st)
	}
	st, _, rawBkAfter := env.do(http.MethodGet, fmt.Sprintf("/api/v1/admin/users/%d/traffic-breakdown", u.ID), env.jwt, nil)
	if st != http.StatusOK {
		t.Fatalf("GET breakdown after reset failed: %d", st)
	}
	if err := json.Unmarshal(rawBkAfter, &bkResp); err != nil {
		t.Fatal(err)
	}
	if len(bkResp.Items) != 0 {
		t.Fatalf("expected empty breakdown after reset, got %+v", bkResp.Items)
	}

	// ServerChan webhook creation via API
	st, _, rawWh := env.do(http.MethodPost, "/api/v1/admin/webhooks", env.jwt, map[string]any{
		"name":              "ServerChanAlert",
		"provider":          "serverchan",
		"url":               "https://sctapi.ftqq.com/SCT123.send",
		"secret":            "ShadowOrbit",
		"subscribed_events": []string{"*"},
		"enabled":           true,
	})
	if st != http.StatusCreated {
		t.Fatalf("create serverchan webhook failed: %d %s", st, string(rawWh))
	}
}

func TestTrafficLogsAndDockerImageSettingsAPI(t *testing.T) {
	env := newTestEnv(t, nil, "")
	ctx := context.Background()

	// Seed defaults verification via GET /api/v1/admin/settings
	st, _, rawSet := env.do(http.MethodGet, "/api/v1/admin/settings", env.jwt, nil)
	if st != http.StatusOK {
		t.Fatalf("GET settings: %d %s", st, string(rawSet))
	}
	var setDTO struct {
		AgentDockerImage     string `json:"agent_docker_image"`
		TrafficLogMaxEntries int    `json:"traffic_log_max_entries"`
	}
	if err := json.Unmarshal(rawSet, &setDTO); err != nil {
		t.Fatal(err)
	}
	if setDTO.AgentDockerImage != "saitomikuya/shadoworbit-agent:latest" || setDTO.TrafficLogMaxEntries != 10000 {
		t.Fatalf("unexpected default docker/log settings: %+v", setDTO)
	}

	// Reject invalid docker image / log cap
	st, _, _ = env.do(http.MethodPut, "/api/v1/admin/settings", env.jwt, map[string]any{"agent_docker_image": "bad image; rm -rf /"})
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid agent_docker_image, got %d", st)
	}
	st, _, _ = env.do(http.MethodPut, "/api/v1/admin/settings", env.jwt, map[string]any{"traffic_log_max_entries": 50})
	if st != http.StatusBadRequest {
		t.Fatalf("expected 400 for traffic_log_max_entries=50, got %d", st)
	}

	// Update custom agent_docker_image and verify reflected in node install-cmd
	customImage := "registry.example.com/saitomikuya/shadoworbit-agent:v2"
	st, _, rawUpd := env.do(http.MethodPut, "/api/v1/admin/settings", env.jwt, map[string]any{
		"agent_docker_image": customImage,
	})
	if st != http.StatusOK || !strings.Contains(string(rawUpd), customImage) {
		t.Fatalf("PUT agent_docker_image failed: %d %s", st, string(rawUpd))
	}

	st, _, rawNode := env.do(http.MethodPost, "/api/v1/admin/nodes", env.jwt, map[string]any{"name": "Docker-Node", "region_tag": "SG", "enabled": true})
	if st != http.StatusCreated {
		t.Fatalf("create node failed: %d %s", st, string(rawNode))
	}
	var createdNode struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(rawNode, &createdNode)

	st, _, rawCmd := env.do(http.MethodGet, fmt.Sprintf("/api/v1/admin/nodes/%d/install-cmd", createdNode.ID), env.jwt, nil)
	if st != http.StatusOK || !strings.Contains(string(rawCmd), customImage) {
		t.Fatalf("install-cmd did not reflect custom docker image: %d %s", st, string(rawCmd))
	}

	// Populate per-minute traffic logs across 2 nodes and verify /api/v1/admin/traffic/logs + pruning on limit lower
	st, _, rawNode2 := env.do(http.MethodPost, "/api/v1/admin/nodes", env.jwt, map[string]any{"name": "Log-Node-B", "region_tag": "JP", "enabled": true})
	if st != http.StatusCreated {
		t.Fatalf("create node2 failed: %d %s", st, string(rawNode2))
	}
	var node2 struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal(rawNode2, &node2)

	u := &store.User{
		Username:        "alice_logs",
		Enabled:         true,
		SubToken:        "sub_logs_1",
		SSUPSK16:        "AAAAAAAAAAAAAAAAAAAAAA==",
		SSUPSK32:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		STLSPassword:    "pw",
		BillingResetDay: 1,
	}
	if err := env.store.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}

	for m := 0; m < 105; m++ {
		ts := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC).Add(time.Duration(m) * time.Minute)
		targetNID := createdNode.ID
		if m%2 == 1 {
			targetNID = node2.ID
		}
		if _, err := env.store.ApplyTrafficDeltasAt(ctx, targetNID, 10, 20, []protocol.UserTrafficDelta{
			{UserID: u.ID, UpBytes: 100, DownBytes: 200},
		}, ts); err != nil {
			t.Fatal(err)
		}
	}

	st, _, rawLogs := env.do(http.MethodGet, fmt.Sprintf("/api/v1/admin/traffic/logs?node_id=%d", node2.ID), env.jwt, nil)
	if st != http.StatusOK {
		t.Fatalf("GET traffic/logs failed: %d %s", st, string(rawLogs))
	}
	var logsResp struct {
		Items       []store.TrafficUsageLog `json:"items"`
		MaxEntries  int                     `json:"max_entries"`
		TotalStored int64                   `json:"total_stored"`
	}
	if err := json.Unmarshal(rawLogs, &logsResp); err != nil {
		t.Fatal(err)
	}
	if logsResp.TotalStored != 105 || logsResp.MaxEntries != 10000 || len(logsResp.Items) == 0 {
		t.Fatalf("unexpected traffic logs response: total=%d max=%d len=%d", logsResp.TotalStored, logsResp.MaxEntries, len(logsResp.Items))
	}
	for _, item := range logsResp.Items {
		if item.NodeID != node2.ID || item.NodeName != "Log-Node-B" || item.Username != "alice_logs" {
			t.Fatalf("unexpected item in node2 filter: %+v", item)
		}
	}

	// Lower limit to 100 and verify immediate pruning on settings update
	st, _, _ = env.do(http.MethodPut, "/api/v1/admin/settings", env.jwt, map[string]any{"traffic_log_max_entries": 100})
	if st != http.StatusOK {
		t.Fatalf("PUT traffic_log_max_entries=100 failed: %d", st)
	}
	st, _, rawLogsAfter := env.do(http.MethodGet, "/api/v1/admin/traffic/logs?limit=10", env.jwt, nil)
	if st != http.StatusOK {
		t.Fatalf("GET traffic/logs after prune failed: %d", st)
	}
	_ = json.Unmarshal(rawLogsAfter, &logsResp)
	if logsResp.TotalStored != 100 || logsResp.MaxEntries != 100 || len(logsResp.Items) != 10 {
		t.Fatalf("expected total_stored=100, max=100, len=10 after prune, got %+v", logsResp)
	}

	// Admin Snell traffic API & reset
	tsAdmin := time.Date(2026, 11, 24, 12, 0, 5, 0, time.UTC)
	if err := env.store.RecordAdminSnellTraffic(ctx, node2.ID, 65536, tsAdmin); err != nil {
		t.Fatal(err)
	}
	st, _, rawAdminTraffic := env.do(http.MethodGet, "/api/v1/admin/admin-traffic", env.jwt, nil)
	if st != http.StatusOK {
		t.Fatalf("GET admin-traffic failed: %d %s", st, string(rawAdminTraffic))
	}
	var adminTrafficResp struct {
		Username   string                        `json:"username"`
		TotalBytes int64                         `json:"total_bytes"`
		Items      []store.AdminNodeTrafficEntry `json:"items"`
	}
	if err := json.Unmarshal(rawAdminTraffic, &adminTrafficResp); err != nil {
		t.Fatal(err)
	}
	if adminTrafficResp.Username != "admin" || adminTrafficResp.TotalBytes != 65536 ||
		len(adminTrafficResp.Items) != 1 || adminTrafficResp.Items[0].NodeID != node2.ID {
		t.Fatalf("unexpected GET admin-traffic response: %+v", adminTrafficResp)
	}

	st, _, _ = env.do(http.MethodPost, "/api/v1/admin/admin-traffic/reset", env.jwt, nil)
	if st != http.StatusOK {
		t.Fatalf("POST admin-traffic/reset failed: %d", st)
	}
	st, _, rawAdminReset := env.do(http.MethodGet, "/api/v1/admin/admin-traffic", env.jwt, nil)
	if st != http.StatusOK {
		t.Fatal(st)
	}
	_ = json.Unmarshal(rawAdminReset, &adminTrafficResp)
	if adminTrafficResp.TotalBytes != 0 || len(adminTrafficResp.Items) != 0 {
		t.Fatalf("expected admin traffic 0 after reset, got %+v", adminTrafficResp)
	}
}
