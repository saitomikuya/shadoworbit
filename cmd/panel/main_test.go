package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/coder/websocket"

	"snell-panel/internal/protocol"
	"snell-panel/web"
)

func TestParseConfig(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, err := ParseConfig(nil, nil)
		if err != nil {
			t.Fatalf("ParseConfig failed: %v", err)
		}
		if cfg.ListenAddr != ":8080" || cfg.DBPath != "./data/panel.db" || cfg.AdminUser != "admin" || cfg.WebhookBlockPrivateIPs {
			t.Fatalf("unexpected defaults: %+v", cfg)
		}
	})

	t.Run("port fallback and listen_addr precedence", func(t *testing.T) {
		cfg, err := ParseConfig(nil, func(k string) string {
			if k == "PORT" {
				return "9191"
			}
			return ""
		})
		if err != nil || cfg.ListenAddr != ":9191" {
			t.Fatalf("expected :9191 from PORT, got %+v err=%v", cfg, err)
		}

		cfg2, err := ParseConfig(nil, func(k string) string {
			if k == "PORT" {
				return "9191"
			}
			if k == "LISTEN_ADDR" {
				return "127.0.0.1:8181"
			}
			return ""
		})
		if err != nil || cfg2.ListenAddr != "127.0.0.1:8181" {
			t.Fatalf("expected LISTEN_ADDR to override PORT, got %+v err=%v", cfg2, err)
		}
	})

	t.Run("env and flag precedence", func(t *testing.T) {
		env := map[string]string{
			"LISTEN_ADDR":               ":9090",
			"DB_PATH":                   "/tmp/env.db",
			"ADMIN_USER":                "envadmin",
			"ADMIN_INITIAL_PASS":        "envpass",
			"JWT_SECRET":                "0123456789abcdef0123456789abcdef",
			"GITHUB_API_URL":            "https://gh.example.com",
			"WEBHOOK_BLOCK_PRIVATE_IPS": "true",
		}
		cfg, err := ParseConfig([]string{"-listen", "127.0.0.1:7070", "-db", "/tmp/flag.db"}, func(k string) string {
			return env[k]
		})
		if err != nil {
			t.Fatalf("ParseConfig failed: %v", err)
		}
		if cfg.ListenAddr != "127.0.0.1:7070" || cfg.DBPath != "/tmp/flag.db" || cfg.AdminUser != "envadmin" || cfg.AdminInitialPass != "envpass" || cfg.GitHubAPIURL != "https://gh.example.com" || !cfg.WebhookBlockPrivateIPs {
			t.Fatalf("unexpected merged config: %+v", cfg)
		}
	})

	t.Run("validation errors", func(t *testing.T) {
		if _, err := ParseConfig([]string{"-listen", "  "}, nil); err == nil {
			t.Fatal("expected error for empty listen address")
		}
		if _, err := ParseConfig([]string{"-db", ""}, nil); err == nil {
			t.Fatal("expected error for empty db path")
		}
		if _, err := ParseConfig(nil, func(k string) string {
			if k == "WEBHOOK_BLOCK_PRIVATE_IPS" {
				return "not-a-bool"
			}
			return ""
		}); err == nil {
			t.Fatal("expected error for invalid WEBHOOK_BLOCK_PRIVATE_IPS")
		}
	})

	t.Run("version flag", func(t *testing.T) {
		cfg, err := ParseConfig([]string{"-version"}, nil)
		if err != nil {
			t.Fatalf("ParseConfig -version failed: %v", err)
		}
		if !cfg.ShowVersion {
			t.Fatal("expected ShowVersion=true")
		}
		var out bytes.Buffer
		if err := run(context.Background(), cfg, &out); err != nil {
			t.Fatalf("run -version failed: %v", err)
		}
		if !strings.Contains(out.String(), "snell-panel version=") {
			t.Fatalf("unexpected version output: %q", out.String())
		}
	})
}

func TestRunHealthzAndGracefulShutdown(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "panel.db")
	staticFS := fstest.MapFS{
		"index.html": {Data: []byte("<html>panel-spa</html>")},
	}
	cfg := Config{
		ListenAddr:       "127.0.0.1:0",
		DBPath:           dbPath,
		AdminUser:        "admin",
		AdminInitialPass: "paneltestpass",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readyAddr := make(chan string, 1)
	errCh := make(chan error, 1)
	var out bytes.Buffer
	go func() {
		errCh <- runWithReadyAndFS(ctx, cfg, staticFS, &out, readyAddr)
	}()

	var addr string
	select {
	case addr = <-readyAddr:
	case err := <-errCh:
		t.Fatalf("server exited prematurely: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server ready")
	}

	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Fatalf("unexpected healthz body: %v", body)
	}

	// Public API and SPA work simultaneously
	pubResp, err := http.Get("http://" + addr + "/api/v1/public/status")
	if err != nil {
		t.Fatalf("GET /api/v1/public/status failed: %v", err)
	}
	pubResp.Body.Close()
	if pubResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on public status, got %d", pubResp.StatusCode)
	}

	spaResp, err := http.Get("http://" + addr + "/admin/nodes")
	if err != nil {
		t.Fatalf("GET /admin/nodes failed: %v", err)
	}
	spaResp.Body.Close()
	if spaResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on SPA /admin/nodes, got %d", spaResp.StatusCode)
	}

	// Open a live public WS connection and verify shutdown still completes quickly
	wsCtx, wsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer wsCancel()
	wsConn, _, err := websocket.Dial(wsCtx, "ws://"+addr+"/api/v1/public/ws", nil)
	if err != nil {
		t.Fatalf("dial public ws: %v", err)
	}
	defer wsConn.CloseNow()

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("expected clean shutdown, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server shutdown with active WS")
	}
}

func TestEmbeddedDistFS(t *testing.T) {
	if web.DistFS == nil {
		t.Fatal("web.DistFS is nil")
	}
	indexBytes, err := fs.ReadFile(web.DistFS, "index.html")
	if err != nil {
		t.Fatalf("read embedded index.html: %v", err)
	}
	if len(indexBytes) == 0 || !strings.Contains(string(indexBytes), "<script") {
		t.Fatalf("unexpected embedded index.html content: %q", string(indexBytes))
	}

	entries, err := fs.ReadDir(web.DistFS, "assets")
	if err != nil {
		t.Fatalf("read embedded assets dir: %v", err)
	}
	var jsFound, cssFound bool
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".js") {
			data, err := fs.ReadFile(web.DistFS, "assets/"+entry.Name())
			if err != nil || len(data) == 0 {
				t.Fatalf("invalid embedded js asset %s: err=%v len=%d", entry.Name(), err, len(data))
			}
			jsFound = true
		}
		if strings.HasSuffix(entry.Name(), ".css") {
			data, err := fs.ReadFile(web.DistFS, "assets/"+entry.Name())
			if err != nil || len(data) == 0 {
				t.Fatalf("invalid embedded css asset %s: err=%v len=%d", entry.Name(), err, len(data))
			}
			cssFound = true
		}
	}
	if !jsFound || !cssFound {
		t.Fatalf("expected both .js and .css in embedded assets (js=%v css=%v)", jsFound, cssFound)
	}
}

func TestRunWithEmbeddedDistFS(t *testing.T) {
	indexBytes, err := fs.ReadFile(web.DistFS, "index.html")
	if err != nil {
		t.Fatalf("read embedded index.html: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "panel.db")
	cfg := Config{
		ListenAddr:       "127.0.0.1:0",
		DBPath:           dbPath,
		AdminUser:        "admin",
		AdminInitialPass: "paneltestpass",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readyAddr := make(chan string, 1)
	errCh := make(chan error, 1)
	var out bytes.Buffer
	go func() {
		errCh <- runWithReadyAndFS(ctx, cfg, web.DistFS, &out, readyAddr)
	}()

	var addr string
	select {
	case addr = <-readyAddr:
	case err := <-errCh:
		t.Fatalf("server exited prematurely: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server ready")
	}

	base := "http://" + addr

	// Verify SPA routes serve identical index.html with no-cache
	for _, p := range []string{"/", "/admin", "/admin/nodes"} {
		resp, err := http.Get(base + p)
		if err != nil {
			t.Fatalf("GET %s failed: %v", p, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", p, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
			t.Fatalf("GET %s Content-Type = %q, want text/html", p, ct)
		}
		if cc := resp.Header.Get("Cache-Control"); cc != "no-cache" {
			t.Fatalf("GET %s Cache-Control = %q, want no-cache", p, cc)
		}
		if !bytes.Equal(body, indexBytes) {
			t.Fatalf("GET %s body does not match embedded index.html", p)
		}
	}

	// Verify every /assets/* referenced in index.html returns 200 + immutable + expected MIME
	assetRe := regexp.MustCompile(`(?:src|href)="(/assets/[^"]+)"`)
	matches := assetRe.FindAllStringSubmatch(string(indexBytes), -1)
	if len(matches) == 0 {
		t.Fatalf("no /assets/* references found in index.html")
	}
	for _, m := range matches {
		assetPath := m[1]
		resp, err := http.Get(base + assetPath)
		if err != nil {
			t.Fatalf("GET %s failed: %v", assetPath, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK || len(body) == 0 {
			t.Fatalf("GET %s status=%d len=%d", assetPath, resp.StatusCode, len(body))
		}
		if cc := resp.Header.Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
			t.Fatalf("GET %s Cache-Control = %q", assetPath, cc)
		}
		ct := resp.Header.Get("Content-Type")
		if strings.HasSuffix(assetPath, ".js") && !strings.Contains(ct, "javascript") {
			t.Fatalf("GET %s Content-Type = %q, want javascript", assetPath, ct)
		}
		if strings.HasSuffix(assetPath, ".css") && !strings.Contains(ct, "text/css") {
			t.Fatalf("GET %s Content-Type = %q, want text/css", assetPath, ct)
		}
	}

	// Verify missing assets and directory listing return 404 without HTML fallback
	for _, p := range []string{"/assets/does-not-exist.js", "/assets/"} {
		resp, err := http.Get(base + p)
		if err != nil {
			t.Fatalf("GET %s failed: %v", p, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s status = %d, want 404", p, resp.StatusCode)
		}
		if strings.Contains(string(body), "<html") {
			t.Fatalf("GET %s unexpectedly returned HTML fallback", p)
		}
	}

	// Verify /api/ and /s/ 404 isolation
	for _, p := range []string{"/api/v1/unknown", "/s/unknown"} {
		resp, err := http.Get(base + p)
		if err != nil {
			t.Fatalf("GET %s failed: %v", p, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s status = %d, want 404", p, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Fatalf("GET %s Content-Type = %q, want application/json", p, ct)
		}
		if strings.Contains(string(body), "<html") {
			t.Fatalf("GET %s unexpectedly returned HTML fallback", p)
		}
	}

	// Verify POST / returns 405
	postResp, err := http.Post(base+"/", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST / failed: %v", err)
	}
	postResp.Body.Close()
	if postResp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST / status = %d, want 405", postResp.StatusCode)
	}

	// Verify /healthz returns 200 ok
	hzResp, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	var hzBody map[string]string
	_ = json.NewDecoder(hzResp.Body).Decode(&hzBody)
	hzResp.Body.Close()
	if hzResp.StatusCode != http.StatusOK || hzBody["status"] != "ok" {
		t.Fatalf("GET /healthz status=%d body=%v", hzResp.StatusCode, hzBody)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("expected clean shutdown, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for shutdown")
	}
}

func TestRunGracefulShutdownWithIdleStateNewConnection(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "panel.db")
	staticFS := fstest.MapFS{
		"index.html": {Data: []byte("<html>panel-spa</html>")},
	}
	cfg := Config{
		ListenAddr:       "127.0.0.1:0",
		DBPath:           dbPath,
		AdminUser:        "admin",
		AdminInitialPass: "paneltestpass",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readyAddr := make(chan string, 1)
	errCh := make(chan error, 1)
	var out bytes.Buffer
	go func() {
		errCh <- runWithReadyAndFS(ctx, cfg, staticFS, &out, readyAddr)
	}()

	var addr string
	select {
	case addr = <-readyAddr:
	case err := <-errCh:
		t.Fatalf("server exited prematurely: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server ready")
	}

	// Open a raw TCP connection without sending any bytes so the server keeps it in http.StateNew.
	rawConn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("raw tcp dial %s failed: %v", addr, err)
	}
	defer rawConn.Close()

	// Allow Accept + ConnState(StateNew) to register before initiating shutdown.
	time.Sleep(50 * time.Millisecond)

	shutdownStart := time.Now()
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("expected clean shutdown with idle StateNew conn, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out (>2s) waiting for server shutdown with idle StateNew connection")
	}
	if elapsed := time.Since(shutdownStart); elapsed >= 2*time.Second {
		t.Fatalf("expected shutdown in <2s, took %s", elapsed)
	}
}

func TestTier5_Main_ParseConfigAndRunEdgeCases(t *testing.T) {
	// 1. Invalid WEBHOOK_BLOCK_PRIVATE_IPS returns clear error.
	if _, err := ParseConfig(nil, func(k string) string {
		if k == "WEBHOOK_BLOCK_PRIVATE_IPS" {
			return "maybe"
		}
		return ""
	}); err == nil || !strings.Contains(err.Error(), "WEBHOOK_BLOCK_PRIVATE_IPS") {
		t.Fatalf("expected ParseConfig error for invalid WEBHOOK_BLOCK_PRIVATE_IPS, got %v", err)
	}

	// 2. Bind failure when listen address is already occupied.
	occupiedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupiedLn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bindErr := runWithReady(ctx, Config{
		ListenAddr: occupiedLn.Addr().String(),
		DBPath:     filepath.Join(t.TempDir(), "bindfail.db"),
		AdminUser:  "admin",
	}, io.Discard, nil)
	if bindErr == nil || !strings.Contains(bindErr.Error(), "listen") {
		t.Fatalf("expected listen bind error, got %v", bindErr)
	}

	// 3. runWithReady starts cleanly without FS, serves /healthz, and drains idle HTTP keep-alive connection.
	readyAddr := make(chan string, 1)
	errCh := make(chan error, 1)
	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()

	go func() {
		errCh <- runWithReady(runCtx, Config{
			ListenAddr: "127.0.0.1:0",
			DBPath:     filepath.Join(t.TempDir(), "ready.db"),
			AdminUser:  "admin",
		}, io.Discard, readyAddr)
	}()

	var addr string
	select {
	case addr = <-readyAddr:
	case err := <-errCh:
		t.Fatalf("runWithReady exited prematurely: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for runWithReady readyAddr")
	}

	keepAliveClient := &http.Client{
		Transport: &http.Transport{DisableKeepAlives: false},
	}
	defer keepAliveClient.CloseIdleConnections()

	resp, err := keepAliveClient.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /healthz, got %d", resp.StatusCode)
	}

	runCancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("expected clean shutdown draining keep-alive conn, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for graceful shutdown with idle keep-alive connection")
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestRunGracefulShutdownUnderConcurrentWSAndStateActiveConn(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "panel.db")
	staticFS := fstest.MapFS{
		"index.html": {Data: []byte("<html>panel-spa</html>")},
	}
	cfg := Config{
		ListenAddr:       "127.0.0.1:0",
		DBPath:           dbPath,
		AdminUser:        "admin",
		AdminInitialPass: "paneltestpass",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readyAddr := make(chan string, 1)
	errCh := make(chan error, 1)
	var out syncBuffer
	go func() {
		errCh <- runWithReadyAndFS(ctx, cfg, staticFS, &out, readyAddr)
	}()

	var addr string
	select {
	case addr = <-readyAddr:
	case err := <-errCh:
		t.Fatalf("server exited prematurely: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server ready")
	}

	baseURL := "http://" + addr
	httpClient := &http.Client{Timeout: 5 * time.Second}
	defer httpClient.CloseIdleConnections()

	// 1. Authenticate as admin to obtain JWT.
	loginResp, err := httpClient.Post(
		baseURL+"/api/v1/auth/login",
		"application/json",
		strings.NewReader(`{"username":"admin","password":"paneltestpass"}`),
	)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	var loginBody struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(loginResp.Body).Decode(&loginBody); err != nil {
		loginResp.Body.Close()
		t.Fatalf("decode login response: %v", err)
	}
	loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK || loginBody.Token == "" {
		t.Fatalf("unexpected login response status=%d token_empty=%v", loginResp.StatusCode, loginBody.Token == "")
	}

	// 2. Create a node to obtain its agent NODE_TOKEN.
	createReq, err := http.NewRequest(
		http.MethodPost,
		baseURL+"/api/v1/admin/nodes",
		strings.NewReader(`{"name":"shutdown-race-node"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	createReq.Header.Set("Authorization", "Bearer "+loginBody.Token)
	createReq.Header.Set("Content-Type", "application/json")
	createResp, err := httpClient.Do(createReq)
	if err != nil {
		t.Fatalf("create node failed: %v", err)
	}
	var nodeBody struct {
		ID        int64  `json:"id"`
		NodeToken string `json:"node_token"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&nodeBody); err != nil {
		createResp.Body.Close()
		t.Fatalf("decode create node response: %v", err)
	}
	createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated || nodeBody.NodeToken == "" {
		t.Fatalf("unexpected create node status=%d token_empty=%v", createResp.StatusCode, nodeBody.NodeToken == "")
	}

	// 3. Connect /api/v1/agent/ws, read initial config_sync, send agent.hello, and stream agent.metrics.
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	wsConn, _, err := websocket.Dial(dialCtx, "ws://"+addr+"/api/v1/agent/ws", &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + nodeBody.NodeToken}},
	})
	if err != nil {
		t.Fatalf("dial agent ws: %v", err)
	}
	defer wsConn.CloseNow()

	if _, _, err := wsConn.Read(dialCtx); err != nil {
		t.Fatalf("read initial config_sync: %v", err)
	}

	helloBytes, err := protocol.MarshalEnvelope(protocol.MsgTypeAgentHello, "h-1", protocol.AgentHello{
		OS:             "linux",
		Arch:           "amd64",
		CPUCores:       2,
		ConfigRevision: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := wsConn.Write(dialCtx, websocket.MessageText, helloBytes); err != nil {
		t.Fatalf("send agent.hello: %v", err)
	}

	metricsStop := make(chan struct{})
	var metricsWg sync.WaitGroup
	metricsWg.Add(1)
	go func() {
		defer metricsWg.Done()
		seq := 0
		for {
			select {
			case <-metricsStop:
				return
			default:
			}
			seq++
			frame, mErr := protocol.MarshalEnvelope(protocol.MsgTypeAgentMetrics, "m", protocol.AgentMetrics{
				TS:         time.Now().Unix(),
				CPUPercent: float64(seq % 100),
				Health:     protocol.AgentHealth{Snell: true, ShadowTLS: true, SingBox: true},
			})
			if mErr != nil {
				return
			}
			wctx, wcancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			wErr := wsConn.Write(wctx, websocket.MessageText, frame)
			wcancel()
			if wErr != nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	// 4. Open both an idle StateNew TCP conn and a stalled StateActive TCP conn
	// (complete headers + incomplete body so ConnState transitions past StateNew into StateActive).
	stateNewConn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial StateNew conn: %v", err)
	}
	defer stateNewConn.Close()

	stateActiveConn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial StateActive conn: %v", err)
	}
	defer stateActiveConn.Close()
	if _, err := stateActiveConn.Write([]byte("POST /api/v1/auth/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"username\":\"admin\"")); err != nil {
		t.Fatalf("write partial body request to trigger StateActive: %v", err)
	}

	// Let StateNew/StateActive transitions and agent.metrics writes overlap.
	time.Sleep(60 * time.Millisecond)

	// 5. Cancel ctx concurrently with wsConn.CloseNow() and verify bounded <3.5s clean exit.
	shutdownStart := time.Now()
	barrier := make(chan struct{})
	var closeWg sync.WaitGroup
	closeWg.Add(2)
	go func() {
		defer closeWg.Done()
		<-barrier
		cancel()
	}()
	go func() {
		defer closeWg.Done()
		<-barrier
		_ = wsConn.CloseNow()
	}()
	close(barrier)

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("expected clean shutdown (nil error), got %v", err)
		}
	case <-time.After(3500 * time.Millisecond):
		t.Fatalf("timed out (>3.5s) waiting for graceful shutdown; logs:\n%s", out.String())
	}
	elapsed := time.Since(shutdownStart)
	if elapsed >= 3500*time.Millisecond {
		t.Fatalf("expected shutdown in <3.5s, took %s", elapsed)
	}

	close(metricsStop)
	metricsWg.Wait()
	closeWg.Wait()

	logs := out.String()
	if !strings.Contains(logs, "panel server stopped") {
		t.Fatalf("expected logs to contain %q, got:\n%s", "panel server stopped", logs)
	}
	if !strings.Contains(logs, "http server graceful shutdown timed out; forcing close") {
		t.Fatalf("expected logs to contain forced close warning for StateActive conn, got:\n%s", logs)
	}
}
