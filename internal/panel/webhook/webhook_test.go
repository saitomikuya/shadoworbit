package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"snell-panel/internal/panel/store"
	"snell-panel/internal/protocol"
)

func openWebhookTestStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "webhook.db"))
	if err != nil {
		t.Fatalf("store.Open failed: %v", err)
	}
	t.Cleanup(func() {
		_ = st.Close()
	})
	return st
}

type capturedReq struct {
	Method  string
	Path    string
	Query   string
	Headers http.Header
	Body    []byte
}

func TestFeishuCardAndSignature(t *testing.T) {
	ctx := context.Background()
	fixedNow := time.Date(2026, 11, 23, 14, 30, 0, 0, time.UTC)

	var (
		mu       sync.Mutex
		requests []capturedReq
		respBody = `{"code":0,"msg":"ok"}`
		respCode = http.StatusOK
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		requests = append(requests, capturedReq{
			Method:  r.Method,
			Headers: r.Header.Clone(),
			Body:    body,
		})
		rc := respCode
		rb := respBody
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rc)
		_, _ = w.Write([]byte(rb))
	}))
	defer srv.Close()

	eng := NewEngine(nil, srv.Client(), WithNow(func() time.Time { return fixedNow }))
	defer eng.Close()

	// 1. Unsigned SendTest -> blue template, timestamp/sign omitted.
	if err := eng.SendTest(ctx, store.WebhookChannel{
		ID: 1, Name: "Feishu-Unsigned", Provider: protocol.WebhookProviderFeishu, URL: srv.URL,
	}); err != nil {
		t.Fatalf("SendTest unsigned failed: %v", err)
	}

	mu.Lock()
	if len(requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(requests))
	}
	var payload1 map[string]any
	if err := json.Unmarshal(requests[0].Body, &payload1); err != nil {
		t.Fatal(err)
	}
	mu.Unlock()

	if payload1["msg_type"] != "interactive" {
		t.Fatalf("expected msg_type=interactive, got %v", payload1["msg_type"])
	}
	if _, ok := payload1["timestamp"]; ok {
		t.Fatalf("expected timestamp omitted when secret empty, got %v", payload1["timestamp"])
	}
	if _, ok := payload1["sign"]; ok {
		t.Fatalf("expected sign omitted when secret empty, got %v", payload1["sign"])
	}
	card := payload1["card"].(map[string]any)
	header := card["header"].(map[string]any)
	if header["template"] != "blue" {
		t.Fatalf("expected blue header for info test event, got %v", header["template"])
	}

	// 2. Severity template colors & HMAC-SHA256 signing via deliverOne.
	secret := "feishu-secret-key"
	cases := []struct {
		severity string
		resolved bool
		wantTpl  string
	}{
		{SeverityCritical, false, "red"},
		{SeverityWarning, false, "orange"},
		{SeverityInfo, false, "blue"},
		{SeverityCritical, true, "green"},
	}
	for _, tc := range cases {
		evt := normalizeEvent(AlertEvent{
			Type:       EventNodeOffline,
			Severity:   tc.severity,
			TargetType: TargetTypeNode,
			TargetID:   7,
			TargetName: "HK-01",
			Title:      "Node Offline: HK-01",
			Message:    "Heartbeat timeout",
			Resolved:   tc.resolved,
		}, func() time.Time { return fixedNow })

		err := eng.deliverOne(ctx, store.WebhookChannel{
			ID: 2, Name: "Feishu-Signed", Provider: protocol.WebhookProviderFeishu, URL: srv.URL, Secret: secret,
		}, evt)
		if err != nil {
			t.Fatalf("deliverOne failed (%+v): %v", tc, err)
		}

		mu.Lock()
		last := requests[len(requests)-1]
		mu.Unlock()

		var p struct {
			Timestamp string `json:"timestamp"`
			Sign      string `json:"sign"`
			Card      struct {
				Header struct {
					Template string `json:"template"`
				} `json:"header"`
			} `json:"card"`
		}
		if err := json.Unmarshal(last.Body, &p); err != nil {
			t.Fatal(err)
		}
		if p.Card.Header.Template != tc.wantTpl {
			t.Fatalf("case %+v: expected template %q, got %q", tc, tc.wantTpl, p.Card.Header.Template)
		}
		wantTS := strconv.FormatInt(fixedNow.Unix(), 10)
		mac := hmac.New(sha256.New, []byte(wantTS+"\n"+secret))
		wantSign := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		if p.Timestamp != wantTS || p.Sign != wantSign {
			t.Fatalf("signature mismatch: got ts=%q sign=%q, want ts=%q sign=%q", p.Timestamp, p.Sign, wantTS, wantSign)
		}
	}

	// 3. Error responses: HTTP 500, code != 0, StatusCode != 0.
	errorCases := []struct {
		status int
		body   string
	}{
		{http.StatusInternalServerError, `internal error`},
		{http.StatusOK, `{"code":19001,"msg":"bad token"}`},
		{http.StatusOK, `{"StatusCode":19021,"StatusMessage":"sign match fail"}`},
	}
	for _, ec := range errorCases {
		mu.Lock()
		respCode = ec.status
		respBody = ec.body
		mu.Unlock()
		err := eng.SendTest(ctx, store.WebhookChannel{
			ID: 3, Name: "Feishu-Err", Provider: protocol.WebhookProviderFeishu, URL: srv.URL,
		})
		if !errors.Is(err, ErrProviderResponse) {
			t.Fatalf("case (%d, %s): expected ErrProviderResponse, got %v", ec.status, ec.body, err)
		}
	}
}

func TestDingTalkMarkdownAndURLSign(t *testing.T) {
	ctx := context.Background()
	fixedNow := time.Date(2026, 11, 23, 14, 30, 0, 123000000, time.UTC)

	var (
		mu       sync.Mutex
		lastReq  capturedReq
		respBody = `{"errcode":0,"errmsg":"ok"}`
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		lastReq = capturedReq{
			Method: r.Method,
			Query:  r.URL.RawQuery,
			Body:   body,
		}
		rb := respBody
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(rb))
	}))
	defer srv.Close()

	eng := NewEngine(nil, srv.Client(), WithNow(func() time.Time { return fixedNow }))
	defer eng.Close()

	secret := "SECtest123"
	ch := store.WebhookChannel{
		ID:       10,
		Name:     "DingTalk-Main",
		Provider: protocol.WebhookProviderDingTalk,
		URL:      srv.URL + "/robot/send?access_token=abc",
		Secret:   secret,
	}
	if err := eng.SendTest(ctx, ch); err != nil {
		t.Fatalf("DingTalk SendTest failed: %v", err)
	}

	mu.Lock()
	req := lastReq
	mu.Unlock()

	parsedURL, err := http.NewRequest(http.MethodPost, "http://example.com?"+req.Query, nil)
	if err != nil {
		t.Fatal(err)
	}
	q := parsedURL.URL.Query()
	if q.Get("access_token") != "abc" {
		t.Fatalf("expected existing access_token preserved, got %q", q.Get("access_token"))
	}
	wantTS := strconv.FormatInt(fixedNow.UnixMilli(), 10)
	if q.Get("timestamp") != wantTS {
		t.Fatalf("expected timestamp=%q, got %q", wantTS, q.Get("timestamp"))
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(wantTS + "\n" + secret))
	wantSign := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if q.Get("sign") != wantSign {
		t.Fatalf("expected sign=%q, got %q", wantSign, q.Get("sign"))
	}

	var body dingTalkPayload
	if err := json.Unmarshal(req.Body, &body); err != nil {
		t.Fatal(err)
	}
	if body.MsgType != "markdown" || body.Markdown.Title == "" || !strings.Contains(body.Markdown.Text, "DingTalk-Main") {
		t.Fatalf("unexpected dingtalk markdown payload: %+v", body)
	}

	mu.Lock()
	respBody = `{"errcode":310000,"errmsg":"sign not match"}`
	mu.Unlock()
	if err := eng.SendTest(ctx, ch); !errors.Is(err, ErrProviderResponse) {
		t.Fatalf("expected ErrProviderResponse on dingtalk errcode!=0, got %v", err)
	}
}

func TestWeComMarkdownAndUTF8Truncation(t *testing.T) {
	ctx := context.Background()
	fixedNow := time.Date(2026, 11, 23, 14, 30, 0, 0, time.UTC)

	var (
		mu       sync.Mutex
		requests []capturedReq
		respBody = `{"errcode":0,"errmsg":"ok"}`
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		requests = append(requests, capturedReq{Body: body})
		rb := respBody
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(rb))
	}))
	defer srv.Close()

	eng := NewEngine(nil, srv.Client(), WithNow(func() time.Time { return fixedNow }))
	defer eng.Close()

	ch := store.WebhookChannel{
		ID: 20, Name: "WeCom-Ops", Provider: protocol.WebhookProviderWeCom, URL: srv.URL,
	}

	// Firing warning color + > 4096 byte multi-byte UTF-8 truncation.
	hugeDetail := strings.Repeat("中", 2000) // 6000 bytes
	firingEvt := normalizeEvent(AlertEvent{
		Type:       EventTrafficWarning,
		Severity:   SeverityWarning,
		TargetType: TargetTypeNode,
		TargetID:   1,
		TargetName: "JP-01",
		Title:      "Traffic Warning",
		Message:    "Approaching threshold",
		Detail:     hugeDetail,
	}, func() time.Time { return fixedNow })

	if err := eng.deliverOne(ctx, ch, firingEvt); err != nil {
		t.Fatalf("WeCom firing deliverOne failed: %v", err)
	}

	resolvedEvt := normalizeEvent(AlertEvent{
		Type:       EventTrafficRecovered,
		Severity:   SeverityInfo,
		TargetType: TargetTypeNode,
		TargetID:   1,
		TargetName: "JP-01",
		Title:      "Traffic Recovered",
		Message:    "Cycle reset",
		Resolved:   true,
	}, func() time.Time { return fixedNow })
	if err := eng.deliverOne(ctx, ch, resolvedEvt); err != nil {
		t.Fatalf("WeCom resolved deliverOne failed: %v", err)
	}

	mu.Lock()
	if len(requests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(requests))
	}
	var p1, p2 wecomPayload
	_ = json.Unmarshal(requests[0].Body, &p1)
	_ = json.Unmarshal(requests[1].Body, &p2)
	mu.Unlock()

	if p1.MsgType != "markdown" || !strings.Contains(p1.Markdown.Content, `<font color="warning">`) {
		t.Fatalf("expected warning color in firing wecom payload: %s", p1.Markdown.Content)
	}
	if len(p1.Markdown.Content) > wecomMaxMarkdownBytes {
		t.Fatalf("expected wecom content <= %d bytes, got %d", wecomMaxMarkdownBytes, len(p1.Markdown.Content))
	}
	if !utf8.ValidString(p1.Markdown.Content) || !strings.HasSuffix(p1.Markdown.Content, "...") {
		t.Fatalf("expected valid UTF-8 truncated with ..., valid=%v", utf8.ValidString(p1.Markdown.Content))
	}
	if !strings.Contains(p2.Markdown.Content, `<font color="info">`) {
		t.Fatalf("expected info color in resolved wecom payload: %s", p2.Markdown.Content)
	}

	mu.Lock()
	respBody = `{"errcode":40058,"errmsg":"exceed max length"}`
	mu.Unlock()
	if err := eng.SendTest(ctx, ch); !errors.Is(err, ErrProviderResponse) {
		t.Fatalf("expected ErrProviderResponse on wecom errcode!=0, got %v", err)
	}
}

func TestCustomWebhookHeadersTemplatesAndSettingsFallback(t *testing.T) {
	ctx := context.Background()
	st := openWebhookTestStore(t)
	fixedNow := time.Date(2026, 11, 23, 14, 30, 0, 0, time.UTC)

	var (
		mu       sync.Mutex
		requests []capturedReq
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		requests = append(requests, capturedReq{
			Headers: r.Header.Clone(),
			Body:    body,
		})
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	eng := NewEngine(st, srv.Client(), WithNow(func() time.Time { return fixedNow }))
	defer eng.Close()

	// 1. Empty secret -> default JSON payload.
	if err := eng.SendTest(ctx, store.WebhookChannel{
		ID: 1, Name: "Custom-Default", Provider: protocol.WebhookProviderCustom, URL: srv.URL,
	}); err != nil {
		t.Fatalf("custom default failed: %v", err)
	}

	// 2. Flat headers JSON -> custom headers + default JSON (or settings fallback template).
	if err := eng.SendTest(ctx, store.WebhookChannel{
		ID:       2,
		Name:     "Custom-Flat",
		Provider: protocol.WebhookProviderCustom,
		URL:      srv.URL,
		Secret:   `{"Authorization":"Bearer tok123","X-Env":"prod"}`,
	}); err != nil {
		t.Fatalf("custom flat headers failed: %v", err)
	}

	// 3. Structured config with template + jsonEscape + jsonQuote + HTML chars + quotes/newlines.
	structuredSecret := `{"headers":{"X-Api-Key":"k1","Content-Type":"application/vnd.custom+json"},"template":"{\"event\":{{jsonQuote .Type}},\"msg\":\"{{jsonEscape .Message}}\",\"status\":\"{{.Status}}\",\"ok\":{{.Resolved}},\"ts\":{{.TimestampUnix}}}"}`
	evt := normalizeEvent(AlertEvent{
		Type:    EventConfigError,
		Title:   "Config Error",
		Message: "bad \"quote\"\nline2\\slash <tag>&amp;",
	}, func() time.Time { return fixedNow })
	if err := eng.deliverOne(ctx, store.WebhookChannel{
		ID: 3, Name: "Custom-Template", Provider: protocol.WebhookProviderCustom, URL: srv.URL, Secret: structuredSecret,
	}, evt); err != nil {
		t.Fatalf("custom structured template failed: %v", err)
	}

	// 4. system_settings fallback template: webhook_custom_template:<id>.
	if err := st.SetSetting(ctx, "webhook_custom_template:44", `{"kind":"settings_tpl","title":{{jsonQuote .Title}}}`); err != nil {
		t.Fatal(err)
	}
	if err := eng.SendTest(ctx, store.WebhookChannel{
		ID: 44, Name: "Custom-Settings-Tpl", Provider: protocol.WebhookProviderCustom, URL: srv.URL,
		Secret: `{"X-From":"settings"}`,
	}); err != nil {
		t.Fatalf("custom settings fallback template failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 4 {
		t.Fatalf("expected 4 requests, got %d", len(requests))
	}
	if requests[1].Headers.Get("Authorization") != "Bearer tok123" || requests[1].Headers.Get("X-Env") != "prod" {
		t.Fatalf("flat custom headers missing: %v", requests[1].Headers)
	}
	if requests[2].Headers.Get("X-Api-Key") != "k1" || requests[2].Headers.Get("Content-Type") != "application/vnd.custom+json" {
		t.Fatalf("structured custom headers mismatch: %v", requests[2].Headers)
	}
	if !json.Valid(requests[2].Body) {
		t.Fatalf("rendered template JSON invalid: %s", string(requests[2].Body))
	}
	var decoded map[string]any
	if err := json.Unmarshal(requests[2].Body, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["msg"] != evt.Message || decoded["status"] != "firing" {
		t.Fatalf("unexpected decoded template body: %v", decoded)
	}
	if !strings.Contains(string(requests[2].Body), "<tag>&amp;") {
		t.Fatalf("expected SetEscapeHTML(false) to preserve <tag>&amp; verbatim, got %s", string(requests[2].Body))
	}

	var decodedSettings map[string]any
	if err := json.Unmarshal(requests[3].Body, &decodedSettings); err != nil || decodedSettings["kind"] != "settings_tpl" {
		t.Fatalf("expected settings fallback template body, got %s err=%v", string(requests[3].Body), err)
	}

	// 5. Reject invalid template syntax, invalid rendered JSON, CRLF/NUL headers, Host/Content-Length overrides, non-JSON secret.
	badSecrets := []string{
		`not-json`,
		`{"headers":{"X-Bad":"val\r\ninjected"}}`,
		`{"headers":{"X-Bad":"val\u0000nul"}}`,
		`{"headers":{"X-Bad\u0000":"val"}}`,
		`{"headers":{"Host":"evil.com"}}`,
		`{"headers":{"Content-Length":"10"}}`,
		`{"template":"{{.Unclosed"}`,
		`{"template":"{not valid json}"}`,
	}
	for _, bs := range badSecrets {
		err := eng.SendTest(ctx, store.WebhookChannel{
			ID: 99, Name: "Custom-Bad", Provider: protocol.WebhookProviderCustom, URL: srv.URL, Secret: bs,
		})
		if !errors.Is(err, ErrInvalidSecretConfig) {
			t.Fatalf("secret %q: expected ErrInvalidSecretConfig, got %v", bs, err)
		}
	}
}

func TestWebhookRoutingAndPairedResolvedMatching(t *testing.T) {
	ctx := context.Background()
	st := openWebhookTestStore(t)

	var (
		mu       sync.Mutex
		received = make(map[string][]AlertEvent)
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var evt AlertEvent
		_ = json.Unmarshal(body, &evt)
		mu.Lock()
		received[r.URL.Path] = append(received[r.URL.Path], evt)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	channels := []*store.WebhookChannel{
		{Name: "disabled", Provider: protocol.WebhookProviderCustom, URL: srv.URL + "/disabled", SubscribedEvents: []string{"*"}, Enabled: false},
		{Name: "star", Provider: protocol.WebhookProviderCustom, URL: srv.URL + "/star", SubscribedEvents: []string{"*"}, Enabled: true},
		{Name: "all", Provider: protocol.WebhookProviderCustom, URL: srv.URL + "/all", SubscribedEvents: []string{"all"}, Enabled: true},
		{Name: "node-off-only", Provider: protocol.WebhookProviderCustom, URL: srv.URL + "/node-off", SubscribedEvents: []string{EventNodeOffline}, Enabled: true},
		{Name: "traffic-paused-only", Provider: protocol.WebhookProviderCustom, URL: srv.URL + "/traffic-paused", SubscribedEvents: []string{EventTrafficPaused}, Enabled: true},
		{Name: "both-node", Provider: protocol.WebhookProviderCustom, URL: srv.URL + "/both-node", SubscribedEvents: []string{EventNodeOffline, EventNodeOnline}, Enabled: true},
	}
	for _, ch := range channels {
		if err := st.CreateWebhookChannel(ctx, ch); err != nil {
			t.Fatal(err)
		}
	}

	eng := NewEngine(st, srv.Client())
	defer eng.Close()

	eng.Notify(ctx, AlertEvent{
		Type: EventNodeOnline, TargetType: TargetTypeNode, TargetID: 1, TargetName: "HK-1", Resolved: true,
	})
	eng.Notify(ctx, AlertEvent{
		Type: EventTrafficRecovered, TargetType: TargetTypeNode, TargetID: 2, TargetName: "JP-1", Resolved: true,
	})
	eng.Wait()

	mu.Lock()
	defer mu.Unlock()

	if len(received["/disabled"]) != 0 {
		t.Fatalf("disabled channel must not receive alerts, got %v", received["/disabled"])
	}
	if len(received["/star"]) != 2 || len(received["/all"]) != 2 {
		t.Fatalf("expected /star and /all to receive 2 events each, got star=%d all=%d", len(received["/star"]), len(received["/all"]))
	}
	if len(received["/node-off"]) != 1 || received["/node-off"][0].Type != EventNodeOnline {
		t.Fatalf("expected node_offline subscriber to receive paired node_online, got %+v", received["/node-off"])
	}
	if len(received["/traffic-paused"]) != 1 || received["/traffic-paused"][0].Type != EventTrafficRecovered {
		t.Fatalf("expected traffic_paused subscriber to receive paired traffic_recovered, got %+v", received["/traffic-paused"])
	}
	if len(received["/both-node"]) != 1 {
		t.Fatalf("expected channel subscribed to both node_offline and node_online to receive node_online once, got %d", len(received["/both-node"]))
	}
}

func TestWebhookCooldownAndResolvedClosure(t *testing.T) {
	ctx := context.Background()
	st := openWebhookTestStore(t)

	var (
		mu       sync.Mutex
		countMap = make(map[string]int)
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var evt AlertEvent
		_ = json.Unmarshal(body, &evt)
		mu.Lock()
		countMap[r.URL.Path+":"+evt.Type]++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ch1 := &store.WebhookChannel{Name: "C1", Provider: protocol.WebhookProviderCustom, URL: srv.URL + "/c1", SubscribedEvents: []string{"*"}, Enabled: true}
	ch2 := &store.WebhookChannel{Name: "C2", Provider: protocol.WebhookProviderCustom, URL: srv.URL + "/c2", SubscribedEvents: []string{"*"}, Enabled: true}
	if err := st.CreateWebhookChannel(ctx, ch1); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateWebhookChannel(ctx, ch2); err != nil {
		t.Fatal(err)
	}

	var nowMu sync.Mutex
	curNow := time.Date(2026, 11, 23, 15, 0, 0, 0, time.UTC)
	getNow := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return curNow
	}
	advance := func(d time.Duration) {
		nowMu.Lock()
		curNow = curNow.Add(d)
		nowMu.Unlock()
	}

	eng := NewEngine(st, srv.Client(), WithNow(getNow))
	defer eng.Close()

	// Set alert_cooldown_minutes = "5".
	if err := st.SetSetting(ctx, SettingCooldownMinutes, "5"); err != nil {
		t.Fatal(err)
	}

	// t = 0: node_offline for target 1 -> delivers to C1 and C2.
	eng.Notify(ctx, AlertEvent{Type: EventNodeOffline, TargetType: TargetTypeNode, TargetID: 1})
	eng.Wait()

	// t = 4m59s: repeat node_offline for target 1 -> suppressed; target 2 -> delivers.
	advance(4*time.Minute + 59*time.Second)
	eng.Notify(ctx, AlertEvent{Type: EventNodeOffline, TargetType: TargetTypeNode, TargetID: 1})
	eng.Notify(ctx, AlertEvent{Type: EventNodeOffline, TargetType: TargetTypeNode, TargetID: 2})
	eng.Wait()

	mu.Lock()
	if countMap["/c1:node_offline"] != 2 || countMap["/c2:node_offline"] != 2 {
		t.Fatalf("expected 2 deliveries (target 1 + target 2) before cooldown expiry, got %v", countMap)
	}
	mu.Unlock()

	// t = 5m00s: cooldown expired for target 1 -> delivers.
	advance(1 * time.Second)
	eng.Notify(ctx, AlertEvent{Type: EventNodeOffline, TargetType: TargetTypeNode, TargetID: 1})
	eng.Wait()

	mu.Lock()
	if countMap["/c1:node_offline"] != 3 {
		t.Fatalf("expected 3 deliveries after 5m expiry, got %v", countMap)
	}
	mu.Unlock()

	// t = 6m: node_online (Resolved: true) bypasses cooldown AND clears node_offline cooldown for target 1.
	advance(1 * time.Minute)
	eng.Notify(ctx, AlertEvent{Type: EventNodeOnline, TargetType: TargetTypeNode, TargetID: 1, Resolved: true})
	eng.Wait()

	// t = 7m: new node_offline for target 1 fires immediately!
	advance(1 * time.Minute)
	eng.Notify(ctx, AlertEvent{Type: EventNodeOffline, TargetType: TargetTypeNode, TargetID: 1})
	eng.Wait()

	mu.Lock()
	if countMap["/c1:node_online"] != 1 || countMap["/c1:node_offline"] != 4 {
		t.Fatalf("expected resolved closure to clear node_offline cooldown, got %v", countMap)
	}
	mu.Unlock()

	// Same paired clear for traffic_paused / traffic_warning -> traffic_recovered.
	eng.Notify(ctx, AlertEvent{Type: EventTrafficWarning, TargetType: TargetTypeNode, TargetID: 9})
	eng.Notify(ctx, AlertEvent{Type: EventTrafficPaused, TargetType: TargetTypeNode, TargetID: 9})
	eng.Wait()
	advance(30 * time.Second)
	eng.Notify(ctx, AlertEvent{Type: EventTrafficRecovered, TargetType: TargetTypeNode, TargetID: 9, Resolved: true})
	eng.Wait()
	advance(30 * time.Second)
	eng.Notify(ctx, AlertEvent{Type: EventTrafficPaused, TargetType: TargetTypeNode, TargetID: 9})
	eng.Wait()

	mu.Lock()
	if countMap["/c1:traffic_paused"] != 2 || countMap["/c1:traffic_recovered"] != 1 {
		t.Fatalf("expected traffic_recovered to clear traffic_paused cooldown, got %v", countMap)
	}
	mu.Unlock()

	// alert_cooldown_minutes = "0" disables cooldown.
	if err := st.SetSetting(ctx, SettingCooldownMinutes, "0"); err != nil {
		t.Fatal(err)
	}
	eng.Notify(ctx, AlertEvent{Type: EventProcessCrashed, TargetType: TargetTypeNode, TargetID: 3})
	eng.Wait()
	advance(1 * time.Second)
	eng.Notify(ctx, AlertEvent{Type: EventProcessCrashed, TargetType: TargetTypeNode, TargetID: 3})
	eng.Wait()

	mu.Lock()
	if countMap["/c1:process_crashed"] != 2 {
		t.Fatalf("expected cooldown=0 to allow immediate repeat, got %v", countMap)
	}
	mu.Unlock()

	// Invalid / negative setting falls back to DefaultCooldownMinutes (5).
	if err := st.SetSetting(ctx, SettingCooldownMinutes, "-3"); err != nil {
		t.Fatal(err)
	}
	if d := eng.loadCooldownDuration(ctx); d != 5*time.Minute {
		t.Fatalf("expected fallback 5m for invalid negative setting, got %v", d)
	}
	if err := st.SetSetting(ctx, SettingCooldownMinutes, "not-an-int"); err != nil {
		t.Fatal(err)
	}
	if d := eng.loadCooldownDuration(ctx); d != 5*time.Minute {
		t.Fatalf("expected fallback 5m for non-integer setting, got %v", d)
	}
}

func TestWebhookConcurrencyLifecycleLimitsAndSSRF(t *testing.T) {
	ctx := context.Background()
	st := openWebhookTestStore(t)

	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		// Send > 64 KiB (2 MiB) to verify bounded io.LimitReader works without error.
		if r.URL.Path == "/huge" {
			chunk := strings.Repeat("A", 32*1024)
			for i := 0; i < 64; i++ {
				_, _ = w.Write([]byte(chunk))
			}
			return
		}
		_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	defer srv.Close()

	if err := st.CreateWebhookChannel(ctx, &store.WebhookChannel{
		Name: "Concurrent-Hook", Provider: protocol.WebhookProviderWeCom, URL: srv.URL,
		SubscribedEvents: []string{"*"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting(ctx, SettingCooldownMinutes, "0"); err != nil {
		t.Fatal(err)
	}

	eng := NewEngine(st, srv.Client(), WithMaxConcurrency(4))
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int64) {
			defer wg.Done()
			eng.Notify(ctx, AlertEvent{
				Type: EventHighResourceUsage, TargetType: TargetTypeNode, TargetID: id,
			})
		}(int64(i + 1))
	}
	wg.Wait()
	eng.Wait()

	if got := hits.Load(); got != 50 {
		t.Fatalf("expected 50 concurrent webhook deliveries, got %d", got)
	}

	// Huge 2 MiB response capped cleanly at MaxResponseBodyBytes.
	if err := eng.SendTest(ctx, store.WebhookChannel{
		ID: 1, Name: "Huge", Provider: protocol.WebhookProviderCustom, URL: srv.URL + "/huge",
	}); err != nil {
		t.Fatalf("SendTest on huge response failed: %v", err)
	}

	// Close idempotency and Notify-after-Close no-op.
	eng.Close()
	eng.Close()
	before := hits.Load()
	eng.Notify(ctx, AlertEvent{Type: EventNodeOffline, TargetType: TargetTypeNode, TargetID: 99})
	eng.Wait()
	if hits.Load() != before {
		t.Fatalf("Notify after Close must be a no-op")
	}

	// SSRF private IP blocking with default HTTP client (httpClient == nil).
	ssrfEng := NewEngine(nil, nil, WithBlockPrivateIPs(true), WithDeliveryTimeout(2*time.Second))
	defer ssrfEng.Close()
	err := ssrfEng.SendTest(ctx, store.WebhookChannel{
		ID: 2, Name: "Loopback", Provider: protocol.WebhookProviderCustom, URL: srv.URL,
	})
	if !errors.Is(err, ErrPrivateIPBlocked) {
		t.Fatalf("expected ErrPrivateIPBlocked for 127.0.0.1 with WithBlockPrivateIPs(true), got %v", err)
	}
}

func TestWebhookURLAndTypeValidation(t *testing.T) {
	if len(AllEventTypes()) != 14 {
		t.Fatalf("expected 14 canonical event types, got %d", len(AllEventTypes()))
	}
	for _, ev := range AllEventTypes() {
		if !IsValidEventType(ev) || !IsValidSubscriptionEvent(ev) {
			t.Fatalf("expected canonical event %q to be valid", ev)
		}
	}
	if IsValidEventType(EventTest) {
		t.Fatalf("synthetic EventTest must not be a canonical subscribable event")
	}
	if !IsValidSubscriptionEvent("*") || !IsValidSubscriptionEvent("all") || IsValidSubscriptionEvent("bogus") {
		t.Fatal("unexpected IsValidSubscriptionEvent results")
	}
	if !IsValidSeverity(SeverityInfo) || !IsValidSeverity(SeverityWarning) || !IsValidSeverity(SeverityCritical) || IsValidSeverity("fatal") {
		t.Fatal("unexpected IsValidSeverity results")
	}

	validURLs := []string{"http://example.com/hook", "https://open.feishu.cn:443/open-apis/bot/v2/hook/abc"}
	for _, u := range validURLs {
		if err := ValidateWebhookURL(u); err != nil {
			t.Fatalf("expected URL %q valid, got %v", u, err)
		}
	}

	invalidURLs := []string{
		"",
		"file:///etc/passwd",
		"ftp://example.com/hook",
		"https:///no-host",
		"https://example.com/hook\n",
		"https://example.com:99999/hook",
	}
	for _, u := range invalidURLs {
		if err := ValidateWebhookURL(u); !errors.Is(err, ErrInvalidURL) {
			t.Fatalf("expected ErrInvalidURL for %q, got %v", u, err)
		}
	}
}

func TestWebhookStalledChannelDoesNotStarveRemainingChannels(t *testing.T) {
	ctx := context.Background()
	st := openWebhookTestStore(t)

	var (
		slowHits atomic.Int64
		mu       sync.Mutex
		fastEvts []AlertEvent
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			slowHits.Add(1)
			select {
			case <-r.Context().Done():
			case <-time.After(1 * time.Second):
			}
			return
		}
		body, _ := io.ReadAll(r.Body)
		var evt AlertEvent
		_ = json.Unmarshal(body, &evt)
		mu.Lock()
		fastEvts = append(fastEvts, evt)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := st.CreateWebhookChannel(ctx, &store.WebhookChannel{
		Name: "Slow-Channel", Provider: protocol.WebhookProviderCustom,
		URL: srv.URL + "/slow", SubscribedEvents: []string{"*"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateWebhookChannel(ctx, &store.WebhookChannel{
		Name: "Fast-Channel", Provider: protocol.WebhookProviderCustom,
		URL: srv.URL + "/fast", SubscribedEvents: []string{"*"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	eng := NewEngine(st, srv.Client(), WithDeliveryTimeout(150*time.Millisecond))
	defer eng.Close()

	eng.Notify(ctx, AlertEvent{
		Type: EventNodeOffline, Severity: SeverityCritical,
		TargetType: TargetTypeNode, TargetID: 42, TargetName: "SG-1",
	})
	eng.Wait()

	if slowHits.Load() != 1 {
		t.Fatalf("expected slow channel to be attempted once, got %d", slowHits.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(fastEvts) != 1 || fastEvts[0].Type != EventNodeOffline || fastEvts[0].TargetID != 42 {
		t.Fatalf("expected fast channel to receive event after slow channel timeout, got %+v", fastEvts)
	}
}

func TestTier5_Webhook_SSRFBlockingAndRedirectProtection(t *testing.T) {
	ctx := context.Background()

	// 1. Direct SSRF targets blocked under WithBlockPrivateIPs(true) without any dial.
	eng := NewEngine(nil, nil, WithBlockPrivateIPs(true), WithDeliveryTimeout(2*time.Second))
	defer eng.Close()

	blockedTargets := []string{
		"http://127.0.0.1:8080/hook",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::ffff:127.0.0.1]:8080/hook",
		"http://100.64.0.1:9000/hook",
		"http://10.0.0.1:80/hook",
		"http://[::1]:8080/hook",
	}
	for _, target := range blockedTargets {
		err := eng.SendTest(ctx, store.WebhookChannel{
			Name: "SSRF-Block", Provider: protocol.WebhookProviderCustom,
			URL: target, SubscribedEvents: []string{"*"}, Enabled: true,
		})
		if !errors.Is(err, ErrPrivateIPBlocked) {
			t.Fatalf("expected ErrPrivateIPBlocked for %q, got %v", target, err)
		}
	}

	// Verify public IPs pass rejectPrivateIPControl while CGNAT/mapped/link-local fail.
	if err := rejectPrivateIPControl("", "8.8.8.8:443", nil); err != nil {
		t.Fatalf("expected public IPv4 8.8.8.8 allowed, got %v", err)
	}
	if err := rejectPrivateIPControl("", "[2606:4700:4700::1111]:443", nil); err != nil {
		t.Fatalf("expected public IPv6 allowed, got %v", err)
	}
	for _, addr := range []string{"127.0.0.1:80", "169.254.169.254:80", "[::ffff:10.0.0.1]:80", "100.127.255.254:80", "0.0.0.0:80", "224.0.0.1:80"} {
		if err := rejectPrivateIPControl("", addr, nil); !errors.Is(err, ErrPrivateIPBlocked) {
			t.Fatalf("expected ErrPrivateIPBlocked for %q, got %v", addr, err)
		}
	}

	// 2. 302 redirect from an allowed initial server to internal SSRF targets must be blocked by Dialer.Control.
	var ssrfSinkHits atomic.Int64
	ssrfSink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ssrfSinkHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ssrfSink.Close()

	redirectTarget := ""
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget, http.StatusFound)
	}))
	defer redirector.Close()
	redirectorHost := strings.TrimPrefix(redirector.URL, "http://")

	var hopCount atomic.Int64
	protectedDialer := &net.Dialer{Timeout: 2 * time.Second, Control: rejectPrivateIPControl}
	plainDialer := &net.Dialer{Timeout: 2 * time.Second}
	redirectClient := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
				// Allow only the initial hop to the test redirector; enforce rejectPrivateIPControl on redirect hops.
				if hopCount.Add(1) == 1 && addr == redirectorHost {
					return plainDialer.DialContext(dctx, network, addr)
				}
				return protectedDialer.DialContext(dctx, network, addr)
			},
		},
	}

	redirEng := NewEngine(nil, redirectClient)
	defer redirEng.Close()

	for _, redirURL := range []string{
		ssrfSink.URL,
		"http://169.254.169.254/latest/meta-data/",
		"http://[::ffff:127.0.0.1]:80/internal",
		"http://100.64.0.5/internal",
	} {
		hopCount.Store(0)
		redirectTarget = redirURL
		err := redirEng.SendTest(ctx, store.WebhookChannel{
			Name: "Redirect-SSRF", Provider: protocol.WebhookProviderCustom,
			URL: redirector.URL, SubscribedEvents: []string{"*"}, Enabled: true,
		})
		if !errors.Is(err, ErrPrivateIPBlocked) {
			t.Fatalf("expected 302 redirect to %q blocked by ErrPrivateIPBlocked, got %v", redirURL, err)
		}
	}
	if ssrfSinkHits.Load() != 0 {
		t.Fatalf("SSRF sink should never be dialed across 302 redirect, got %d hits", ssrfSinkHits.Load())
	}
}

func TestTier5_Webhook_OversizedResponseTruncationSendTestErrorsAndCooldownPruneRace(t *testing.T) {
	ctx := context.Background()

	// 1. Oversized multibyte UTF-8 500 body is truncated cleanly to <= MaxResponseBodyBytes without invalid UTF-8.
	hugeBody := strings.Repeat("警", MaxResponseBodyBytes) // 3 * MaxResponseBodyBytes bytes
	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, hugeBody)
	}))
	defer errSrv.Close()

	eng := NewEngine(nil, errSrv.Client())
	defer eng.Close()

	err := eng.SendTest(ctx, store.WebhookChannel{
		Name: "Huge-Err", Provider: protocol.WebhookProviderCustom,
		URL: errSrv.URL, SubscribedEvents: []string{"*"}, Enabled: true,
	})
	if err == nil {
		t.Fatal("expected error for 500 webhook response")
	}
	if !utf8.ValidString(err.Error()) {
		t.Fatalf("expected valid UTF-8 in truncated error, got %q", err.Error())
	}
	if len(err.Error()) > MaxResponseBodyBytes+256 {
		t.Fatalf("expected bounded error message, got len=%d", len(err.Error()))
	}

	// SendTest error branches: unsupported provider, invalid URL, invalid custom secret.
	if err := eng.SendTest(ctx, store.WebhookChannel{
		Provider: "slack", URL: errSrv.URL,
	}); !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatalf("expected ErrUnsupportedProvider, got %v", err)
	}
	if err := eng.SendTest(ctx, store.WebhookChannel{
		Provider: protocol.WebhookProviderCustom, URL: "ftp://bad.example.com",
	}); !errors.Is(err, ErrInvalidURL) {
		t.Fatalf("expected ErrInvalidURL, got %v", err)
	}
	if err := eng.SendTest(ctx, store.WebhookChannel{
		Provider: protocol.WebhookProviderCustom, URL: errSrv.URL, Secret: "not-json",
	}); !errors.Is(err, ErrInvalidSecretConfig) {
		t.Fatalf("expected ErrInvalidSecretConfig, got %v", err)
	}

	// 2. >1024 cooldown entries pruning race check.
	st := openWebhookTestStore(t)
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer okSrv.Close()

	if err := st.CreateWebhookChannel(ctx, &store.WebhookChannel{
		Name: "Cooldown-Chan", Provider: protocol.WebhookProviderCustom,
		URL: okSrv.URL, SubscribedEvents: []string{"*"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting(ctx, "alert_cooldown_minutes", "1"); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	raceEng := NewEngine(st, okSrv.Client(),
		WithMaxConcurrency(16),
		WithNow(func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return now
		}),
	)
	defer raceEng.Close()

	// Phase A: populate >1100 cooldown keys concurrently under -race.
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < 150; i++ {
				raceEng.Notify(ctx, AlertEvent{
					Type: EventNodeOffline, Severity: SeverityCritical,
					TargetType: TargetTypeNode, TargetID: int64(base*150 + i + 1),
					TargetName: fmt.Sprintf("n-%d", base*150+i+1),
				})
			}
		}(g)
	}
	wg.Wait()
	raceEng.Wait()

	raceEng.cooldownMu.Lock()
	countBefore := len(raceEng.cooldown)
	raceEng.cooldownMu.Unlock()
	if countBefore <= 1024 {
		t.Fatalf("expected >1024 cooldown keys before expiry prune, got %d", countBefore)
	}

	// Advance clock past cooldown (2m > 1m) and trigger pruning on next Notify.
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	raceEng.Notify(ctx, AlertEvent{
		Type: EventNodeOffline, Severity: SeverityCritical,
		TargetType: TargetTypeNode, TargetID: 99999, TargetName: "prune-trigger",
	})
	raceEng.Wait()

	raceEng.cooldownMu.Lock()
	countAfter := len(raceEng.cooldown)
	raceEng.cooldownMu.Unlock()
	if countAfter != 1 {
		t.Fatalf("expected stale >1024 cooldown keys pruned down to 1, got %d", countAfter)
	}
}

func TestServerChanDeliveryAndValidation(t *testing.T) {
	ctx := context.Background()
	fixedNow := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

	var (
		mu       sync.Mutex
		requests []capturedReq
		respBody = `{"code":0,"message":"success"}`
		respCode = http.StatusOK
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		requests = append(requests, capturedReq{
			Method:  r.Method,
			Headers: r.Header.Clone(),
			Body:    body,
		})
		rc := respCode
		rb := respBody
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rc)
		_, _ = w.Write([]byte(rb))
	}))
	defer srv.Close()

	eng := NewEngine(nil, srv.Client(), WithNow(func() time.Time { return fixedNow }))
	defer eng.Close()

	// 1. Success delivery with long title truncation & secret tags
	if err := eng.deliverOne(ctx, store.WebhookChannel{
		Name:     "ServerChan",
		Provider: protocol.WebhookProviderServerChan,
		URL:      srv.URL + "/SCT12345.send",
		Secret:   `{"channel":"9","tags":"ShadowOrbit"}`,
	}, AlertEvent{
		Type:       EventNodeOffline,
		Severity:   SeverityCritical,
		TargetType: TargetTypeNode,
		TargetID:   1,
		TargetName: "SG-01-Super-Long-Node-Name-Exceeds-Limit",
		Title:      "节点离线告警标题需要自动截断到三十二个字符以内避免被服务端拒绝",
		Message:    "Node stopped responding",
		Timestamp:  fixedNow,
	}); err != nil {
		t.Fatalf("ServerChan deliverOne failed: %v", err)
	}

	mu.Lock()
	if len(requests) != 1 {
		mu.Unlock()
		t.Fatalf("expected 1 request, got %d", len(requests))
	}
	reqBody := requests[0].Body
	mu.Unlock()

	var payload map[string]any
	if err := json.Unmarshal(reqBody, &payload); err != nil {
		t.Fatalf("invalid serverchan json payload: %v", err)
	}
	title, _ := payload["title"].(string)
	if len([]rune(title)) > 32 {
		t.Fatalf("expected ServerChan title truncated to <= 32 runes, got %d (%q)", len([]rune(title)), title)
	}
	if payload["channel"] != "9" || payload["tags"] != "ShadowOrbit" {
		t.Fatalf("unexpected optional options in serverchan payload: %+v", payload)
	}
	desp, _ := payload["desp"].(string)
	if !strings.Contains(desp, "Node stopped responding") || !strings.Contains(desp, "SG-01") || !strings.Contains(desp, "告警状态") || !strings.Contains(desp, "事件类型") || !strings.Contains(desp, "影响对象") || !strings.Contains(desp, "触发时间") {
		t.Fatalf("unexpected serverchan desp: %q", desp)
	}

	// 2. Non-zero code returns ErrProviderResponse
	mu.Lock()
	respBody = `{"code":40001,"message":"invalid sendkey"}`
	mu.Unlock()
	if err := eng.SendTest(ctx, store.WebhookChannel{
		Name:     "BadChan",
		Provider: protocol.WebhookProviderServerChan,
		URL:      srv.URL + "/BAD.send",
	}); !errors.Is(err, ErrProviderResponse) {
		t.Fatalf("expected ErrProviderResponse on non-zero code, got %v", err)
	}

	// 3. Invalid JSON secret returns ErrInvalidSecretConfig
	if err := eng.SendTest(ctx, store.WebhookChannel{
		Name:     "BadSecret",
		Provider: protocol.WebhookProviderServerChan,
		URL:      srv.URL + "/OK.send",
		Secret:   `{invalid-json`,
	}); !errors.Is(err, ErrInvalidSecretConfig) {
		t.Fatalf("expected ErrInvalidSecretConfig on malformed JSON secret, got %v", err)
	}
}

func TestChineseFormattingHelpers(t *testing.T) {
	if got := FormatBytes(0); got != "0 B" {
		t.Fatalf("FormatBytes(0) = %q", got)
	}
	if got := FormatBytes(50 * 1024 * 1024 * 1024); got != "50.0 GB" {
		t.Fatalf("FormatBytes(50GiB) = %q", got)
	}
	if got := FormatDuration(10*time.Minute + 5*time.Second); got != "10 分钟" {
		t.Fatalf("FormatDuration(10m5s) = %q", got)
	}
	if got := FormatDuration(2*time.Hour + 15*time.Minute); got != "2 小时 15 分钟" {
		t.Fatalf("FormatDuration(2h15m) = %q", got)
	}
	if got := formatAlertHeaderTitle(AlertEvent{Type: EventNodeOffline, Severity: SeverityCritical, Title: "节点离线：HK-01"}); got != "【严重】节点离线：HK-01" {
		t.Fatalf("formatAlertHeaderTitle firing = %q", got)
	}
	if got := formatAlertHeaderTitle(AlertEvent{Type: EventNodeOnline, Severity: SeverityInfo, Resolved: true, Title: "节点恢复上线：HK-01"}); got != "【已恢复】节点恢复上线：HK-01" {
		t.Fatalf("formatAlertHeaderTitle resolved = %q", got)
	}
}
