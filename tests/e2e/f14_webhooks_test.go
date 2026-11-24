//go:build e2e

package e2e_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func f14_boolPtr(v bool) *bool { return &v }

func f14_dialAgentHelloAndSync(t *testing.T, ctx context.Context, client *PanelClient, nodeToken string) *websocket.Conn {
	t.Helper()
	conn, wsSt, err := client.DialAgentWS(ctx, nodeToken)
	if err != nil {
		t.Fatalf("DialAgentWS failed (http=%d): %v", wsSt, err)
	}
	t.Cleanup(func() { _ = conn.CloseNow() })

	if err := SendWSEnvelope(ctx, conn, "agent.hello", "f14-hello", AgentHelloPayload{
		OS:         "linux",
		Arch:       "amd64",
		CPUCores:   2,
		Versions:   AgentVersionsDTO{SingBox: "1.11.4", SnellServer: "5.0.0", ShadowTLS: "0.2.25"},
		PublicIPv4: "203.0.113.14",
	}); err != nil {
		t.Fatalf("send agent.hello: %v", err)
	}
	env, raw, err := ReadWSEnvelope(ctx, conn, 5*time.Second)
	if err != nil || env.Type != "server.config_sync" {
		t.Fatalf("expected server.config_sync, got env=%+v err=%v raw=%s", env, err, string(raw))
	}
	return conn
}

func TestF14_Tier1_WebhookCRUDAndTestPush(t *testing.T) {
	whSrv := StartMockWebhookServer(t)
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	// Create
	st, created, raw, err := client.CreateWebhook(jwt, WebhookChannelDTO{
		Name:             "F14 CRUD Hook",
		Provider:         "custom",
		URL:              whSrv.URL() + "/hook",
		SubscribedEvents: []string{"node_offline", "node_online"},
		Enabled:          true,
	})
	if err != nil || (st != http.StatusOK && st != http.StatusCreated) {
		t.Fatalf("CreateWebhook failed: st=%d err=%v body=%s", st, err, string(raw))
	}
	if created.ID <= 0 || created.Name != "F14 CRUD Hook" || created.Provider != "custom" {
		t.Fatalf("unexpected created webhook: %+v", created)
	}

	// List
	st, list, listRaw, err := client.ListWebhooks(jwt)
	if err != nil || st != http.StatusOK || len(list) != 1 || list[0].ID != created.ID {
		t.Fatalf("ListWebhooks failed: st=%d err=%v list=%+v body=%s", st, err, list, string(listRaw))
	}

	// Get single
	var single WebhookChannelDTO
	st, singleRaw, err := client.DoJSON(context.Background(), http.MethodGet, fmt.Sprintf("/api/v1/admin/webhooks/%d", created.ID), jwt, nil, &single)
	if err != nil || st != http.StatusOK || single.ID != created.ID {
		t.Fatalf("GET /webhooks/{id} failed: st=%d err=%v single=%+v body=%s", st, err, single, string(singleRaw))
	}

	// Update
	var updated WebhookChannelDTO
	st, updRaw, err := client.DoJSON(context.Background(), http.MethodPut, fmt.Sprintf("/api/v1/admin/webhooks/%d", created.ID), jwt, WebhookChannelDTO{
		Name:             "F14 Updated Hook",
		Provider:         "custom",
		URL:              whSrv.URL() + "/hook-v2",
		SubscribedEvents: []string{"*"},
		Enabled:          true,
	}, &updated)
	if err != nil || st != http.StatusOK || updated.Name != "F14 Updated Hook" {
		t.Fatalf("PUT /webhooks/{id} failed: st=%d err=%v updated=%+v body=%s", st, err, updated, string(updRaw))
	}

	// Test push
	st, testRaw, err := client.TestWebhook(jwt, created.ID)
	if err != nil || st < 200 || st >= 300 {
		t.Fatalf("POST /webhooks/{id}/test failed: st=%d err=%v body=%s", st, err, string(testRaw))
	}
	reqs, ok := whSrv.WaitForRequests(1, 5*time.Second)
	if !ok || len(reqs) != 1 || reqs[0].Path != "/hook-v2" {
		t.Fatalf("expected 1 test request to /hook-v2, got %+v", reqs)
	}

	// Delete
	st, delRaw, err := client.DoJSON(context.Background(), http.MethodDelete, fmt.Sprintf("/api/v1/admin/webhooks/%d", created.ID), jwt, nil, nil)
	if err != nil || st < 200 || st >= 300 {
		t.Fatalf("DELETE /webhooks/{id} failed: st=%d err=%v body=%s", st, err, string(delRaw))
	}
	stListAfter, listAfter, listAfterRaw, err := client.ListWebhooks(jwt)
	if err != nil || stListAfter != http.StatusOK {
		t.Fatalf("ListWebhooks after delete failed: st=%d err=%v body=%s", stListAfter, err, string(listAfterRaw))
	}
	if len(listAfter) != 0 {
		t.Fatalf("expected 0 webhooks after delete, got %+v", listAfter)
	}
	stGetDel, getDelRaw, err := client.DoJSON(context.Background(), http.MethodGet, fmt.Sprintf("/api/v1/admin/webhooks/%d", created.ID), jwt, nil, nil)
	if err != nil {
		t.Fatalf("GET deleted webhook error: %v", err)
	}
	if stGetDel != http.StatusNotFound {
		t.Fatalf("expected 404 after deleting webhook, got %d (body=%s)", stGetDel, string(getDelRaw))
	}
}

func TestF14_Tier1_FeishuInteractiveCardAndHMACSignature(t *testing.T) {
	whSrv := StartMockWebhookServer(t)
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	secret := "feishu_hmac_secret_2026"
	st, wh, raw, err := client.CreateWebhook(jwt, WebhookChannelDTO{
		Name:             "Feishu Channel",
		Provider:         "feishu",
		URL:              whSrv.URL() + "/open-apis/bot/v2/hook/test",
		Secret:           secret,
		SubscribedEvents: []string{"*"},
		Enabled:          true,
	})
	if err != nil || st >= 300 {
		t.Fatalf("CreateWebhook feishu failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	st, testRaw, err := client.TestWebhook(jwt, wh.ID)
	if err != nil || st < 200 || st >= 300 {
		t.Fatalf("TestWebhook feishu failed: st=%d err=%v body=%s", st, err, string(testRaw))
	}

	reqs, ok := whSrv.WaitForRequests(1, 5*time.Second)
	if !ok || len(reqs) == 0 {
		t.Fatalf("expected feishu webhook delivery")
	}

	var payload struct {
		Timestamp string `json:"timestamp"`
		Sign      string `json:"sign"`
		MsgType   string `json:"msg_type"`
		Card      struct {
			Config struct {
				WideScreenMode bool `json:"wide_screen_mode"`
			} `json:"config"`
			Header struct {
				Template string `json:"template"`
				Title    struct {
					Tag     string `json:"tag"`
					Content string `json:"content"`
				} `json:"title"`
			} `json:"header"`
			Elements []struct {
				Tag     string `json:"tag"`
				Content string `json:"content"`
			} `json:"elements"`
		} `json:"card"`
	}
	if err := json.Unmarshal([]byte(reqs[0].Body), &payload); err != nil {
		t.Fatalf("decode feishu payload: %v (body=%s)", err, reqs[0].Body)
	}
	if payload.MsgType != "interactive" || !payload.Card.Config.WideScreenMode {
		t.Fatalf("expected interactive wide_screen_mode card, got %+v", payload)
	}
	if payload.Card.Header.Template == "" || payload.Card.Header.Title.Tag != "plain_text" || len(payload.Card.Elements) == 0 {
		t.Fatalf("incomplete feishu card structure: %+v", payload.Card)
	}
	if payload.Timestamp == "" || payload.Sign == "" {
		t.Fatalf("expected non-empty Feishu timestamp and sign, got ts=%q sign=%q", payload.Timestamp, payload.Sign)
	}
	tsVal, err := strconv.ParseInt(payload.Timestamp, 10, 64)
	if err != nil || tsVal <= 0 {
		t.Fatalf("invalid feishu timestamp %q: %v", payload.Timestamp, err)
	}

	// Verify exact Feishu HMAC-SHA256 signature: key = ts + "\n" + secret, msg = ""
	stringToSign := payload.Timestamp + "\n" + secret
	mac := hmac.New(sha256.New, []byte(stringToSign))
	expectedSign := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if payload.Sign != expectedSign {
		t.Fatalf("feishu sign mismatch: got=%q want=%q", payload.Sign, expectedSign)
	}
}

func TestF14_Tier1_DingTalkMarkdownAndSECQuerySign(t *testing.T) {
	whSrv := StartMockWebhookServer(t)
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	secret := "SEC_dingtalk_e2e_secret"
	st, wh, raw, err := client.CreateWebhook(jwt, WebhookChannelDTO{
		Name:             "DingTalk Channel",
		Provider:         "dingtalk",
		URL:              whSrv.URL() + "/robot/send?access_token=ding_tok_123",
		Secret:           secret,
		SubscribedEvents: []string{"*"},
		Enabled:          true,
	})
	if err != nil || st >= 300 {
		t.Fatalf("CreateWebhook dingtalk failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	st, testRaw, err := client.TestWebhook(jwt, wh.ID)
	if err != nil || st < 200 || st >= 300 {
		t.Fatalf("TestWebhook dingtalk failed: st=%d err=%v body=%s", st, err, string(testRaw))
	}

	reqs, ok := whSrv.WaitForRequests(1, 5*time.Second)
	if !ok || len(reqs) == 0 {
		t.Fatalf("expected dingtalk webhook delivery")
	}

	u, err := url.ParseRequestURI(reqs[0].Path)
	if err != nil {
		t.Fatalf("parse dingtalk request URI %q: %v", reqs[0].Path, err)
	}
	q := u.Query()
	if q.Get("access_token") != "ding_tok_123" {
		t.Fatalf("expected preserved access_token=ding_tok_123, got %q", q.Get("access_token"))
	}
	tsStr := q.Get("timestamp")
	gotSign := q.Get("sign")
	if tsStr == "" || gotSign == "" {
		t.Fatalf("expected timestamp & sign query params, got %q", reqs[0].Path)
	}
	tsMillis, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil || tsMillis < 1_700_000_000_000 {
		t.Fatalf("expected DingTalk millisecond timestamp, got %q", tsStr)
	}

	// Verify exact DingTalk HMAC-SHA256 signature: key = secret, msg = ts + "\n" + secret
	stringToSign := tsStr + "\n" + secret
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(stringToSign))
	expectedSign := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if gotSign != expectedSign {
		t.Fatalf("dingtalk sign mismatch: got=%q want=%q", gotSign, expectedSign)
	}

	var body struct {
		MsgType  string `json:"msgtype"`
		Markdown struct {
			Title string `json:"title"`
			Text  string `json:"text"`
		} `json:"markdown"`
	}
	if err := json.Unmarshal([]byte(reqs[0].Body), &body); err != nil {
		t.Fatalf("decode dingtalk payload: %v (body=%s)", err, reqs[0].Body)
	}
	if body.MsgType != "markdown" || body.Markdown.Title == "" || body.Markdown.Text == "" {
		t.Fatalf("unexpected dingtalk markdown body: %+v", body)
	}
}

func TestF14_Tier1_WeComMarkdownPayload(t *testing.T) {
	whSrv := StartMockWebhookServer(t)
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	st, wh, raw, err := client.CreateWebhook(jwt, WebhookChannelDTO{
		Name:             "WeCom Channel",
		Provider:         "wecom",
		URL:              whSrv.URL() + "/cgi-bin/webhook/send?key=wc_key_1",
		SubscribedEvents: []string{"*"},
		Enabled:          true,
	})
	if err != nil || st >= 300 {
		t.Fatalf("CreateWebhook wecom failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	st, testRaw, err := client.TestWebhook(jwt, wh.ID)
	if err != nil || st < 200 || st >= 300 {
		t.Fatalf("TestWebhook wecom failed: st=%d err=%v body=%s", st, err, string(testRaw))
	}

	reqs, ok := whSrv.WaitForRequests(1, 5*time.Second)
	if !ok || len(reqs) == 0 {
		t.Fatalf("expected wecom webhook delivery")
	}

	var body struct {
		MsgType  string `json:"msgtype"`
		Markdown struct {
			Content string `json:"content"`
		} `json:"markdown"`
	}
	if err := json.Unmarshal([]byte(reqs[0].Body), &body); err != nil {
		t.Fatalf("decode wecom payload: %v (body=%s)", err, reqs[0].Body)
	}
	if body.MsgType != "markdown" || !strings.Contains(body.Markdown.Content, "<font color=") {
		t.Fatalf("unexpected wecom markdown payload: %+v", body)
	}
}

func TestF14_Tier1_CustomJSONTemplateAndCustomHeaders(t *testing.T) {
	whSrv := StartMockWebhookServer(t)
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	secretCfg := `{"headers":{"Authorization":"Bearer custom-secret-token","X-Alert-Source":"snell-e2e"},"template":"{\"event\":{{jsonQuote .Type}},\"target\":{{jsonQuote .TargetName}},\"status\":{{jsonQuote .Status}},\"resolved\":{{.Resolved}}}"}`
	st, wh, raw, err := client.CreateWebhook(jwt, WebhookChannelDTO{
		Name:             "Custom Template Hook",
		Provider:         "custom",
		URL:              whSrv.URL() + "/custom-notify",
		Secret:           secretCfg,
		SubscribedEvents: []string{"*"},
		Enabled:          true,
	})
	if err != nil || st >= 300 {
		t.Fatalf("CreateWebhook custom failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	st, testRaw, err := client.TestWebhook(jwt, wh.ID)
	if err != nil || st < 200 || st >= 300 {
		t.Fatalf("TestWebhook custom failed: st=%d err=%v body=%s", st, err, string(testRaw))
	}

	reqs, ok := whSrv.WaitForRequests(1, 5*time.Second)
	if !ok || len(reqs) == 0 {
		t.Fatalf("expected custom webhook delivery")
	}

	if reqs[0].Header.Get("Authorization") != "Bearer custom-secret-token" {
		t.Fatalf("expected custom Authorization header, got %q", reqs[0].Header.Get("Authorization"))
	}
	if reqs[0].Header.Get("X-Alert-Source") != "snell-e2e" {
		t.Fatalf("expected custom X-Alert-Source header, got %q", reqs[0].Header.Get("X-Alert-Source"))
	}
	var rendered struct {
		Event    string `json:"event"`
		Target   string `json:"target"`
		Status   string `json:"status"`
		Resolved bool   `json:"resolved"`
	}
	if err := json.Unmarshal([]byte(reqs[0].Body), &rendered); err != nil {
		t.Fatalf("decode rendered custom template JSON: %v (body=%s)", err, reqs[0].Body)
	}
	if rendered.Event != "test" || rendered.Status != "firing" || rendered.Resolved {
		t.Fatalf("unexpected custom rendered payload: %+v", rendered)
	}
}

func TestF14_Tier1_RealTrafficPauseAndResolvedClosureNotification(t *testing.T) {
	whSrv := StartMockWebhookServer(t)
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	st, raw, err := client.UpdateSettings(jwt, map[string]any{"alert_cooldown_minutes": 10})
	if err != nil || st >= 300 {
		t.Fatalf("UpdateSettings failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	stWH, _, whRaw, err := client.CreateWebhook(jwt, WebhookChannelDTO{
		Name:             "Feishu Traffic Lifecycle",
		Provider:         "feishu",
		URL:              whSrv.URL() + "/feishu",
		SubscribedEvents: []string{"traffic_paused", "traffic_recovered"},
		Enabled:          true,
	})
	if err != nil || (stWH != http.StatusOK && stWH != http.StatusCreated) {
		t.Fatalf("CreateWebhook failed: st=%d err=%v body=%s", stWH, err, string(whRaw))
	}

	stN, node, rawN, err := client.CreateNode(jwt, CreateNodeReq{
		Name:                  "F14 Traffic Node",
		Enabled:               f14_boolPtr(true),
		TrafficLimitBytes:     100000,
		TrafficThresholdBytes: 50000,
		TrafficCountMode:      "both",
		ThresholdAction:       "stop_all",
	})
	if err != nil || (stN != http.StatusOK && stN != http.StatusCreated) {
		t.Fatalf("CreateNode failed: st=%d err=%v body=%s", stN, err, string(rawN))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn := f14_dialAgentHelloAndSync(t, ctx, client, node.EffectiveToken())

	// Push traffic exceeding threshold -> fires traffic_paused alert
	if err := SendWSEnvelope(ctx, conn, "agent.metrics", "m-over", AgentMetricsPayload{
		TS:         time.Now().Unix(),
		NicRxDelta: 35000,
		NicTxDelta: 25000,
		Health:     AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}

	reqs, ok := whSrv.WaitForRequests(1, 5*time.Second)
	if !ok || len(reqs) < 1 {
		t.Fatalf("expected traffic_paused webhook notification, got %d", len(reqs))
	}
	if !strings.Contains(reqs[0].Body, "traffic_paused") {
		t.Fatalf("expected traffic_paused event in first webhook, got: %s", reqs[0].Body)
	}
	if !strings.Contains(reqs[0].Body, `"template":"red"`) && !strings.Contains(reqs[0].Body, `"template":"orange"`) {
		t.Fatalf("expected non-green alert header for firing traffic_paused, got: %s", reqs[0].Body)
	}

	// Reset node traffic -> fires resolved traffic_recovered notification (green card)
	st, resetRaw, err := client.ResetNodeTraffic(jwt, node.ID)
	if err != nil || st >= 300 {
		t.Fatalf("ResetNodeTraffic failed: st=%d err=%v body=%s", st, err, string(resetRaw))
	}

	reqs, ok = whSrv.WaitForRequests(2, 5*time.Second)
	if !ok || len(reqs) < 2 {
		t.Fatalf("expected traffic_recovered resolved webhook notification, got %d requests", len(reqs))
	}
	if !strings.Contains(reqs[1].Body, "traffic_recovered") || !strings.Contains(reqs[1].Body, `"template":"green"`) {
		t.Fatalf("expected green traffic_recovered card in second webhook, got: %s", reqs[1].Body)
	}
}

func TestF14_Tier2_CooldownSuppressesDuplicateBurstAlerts(t *testing.T) {
	whSrv := StartMockWebhookServer(t)
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	// Explicitly set cooldown so default value (5 vs 15) is deterministic
	st, raw, err := client.UpdateSettings(jwt, map[string]any{"alert_cooldown_minutes": 15})
	if err != nil || st >= 300 {
		t.Fatalf("UpdateSettings cooldown failed: st=%d err=%v body=%s", st, err, string(raw))
	}

	stWH, _, whRaw, err := client.CreateWebhook(jwt, WebhookChannelDTO{
		Name:             "Cooldown Hook",
		Provider:         "custom",
		URL:              whSrv.URL(),
		SubscribedEvents: []string{"process_crashed"},
		Enabled:          true,
	})
	if err != nil || (stWH != http.StatusOK && stWH != http.StatusCreated) {
		t.Fatalf("CreateWebhook failed: st=%d err=%v body=%s", stWH, err, string(whRaw))
	}

	stN, node, rawN, err := client.CreateNode(jwt, CreateNodeReq{Name: "F14 Cooldown Node", Enabled: f14_boolPtr(true)})
	if err != nil || (stN != http.StatusOK && stN != http.StatusCreated) {
		t.Fatalf("CreateNode failed: st=%d err=%v body=%s", stN, err, string(rawN))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn := f14_dialAgentHelloAndSync(t, ctx, client, node.EffectiveToken())

	for i := 1; i <= 3; i++ {
		if err := SendWSEnvelope(ctx, conn, "agent.event", fmt.Sprintf("crash-%d", i), AgentEventPayload{
			Event:   "process_crashed",
			Kernel:  "sing-box",
			Status:  "crashed",
			Message: fmt.Sprintf("sing-box exited unexpectedly #%d", i),
		}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	reqs, ok := whSrv.WaitForRequests(1, 5*time.Second)
	if !ok || len(reqs) != 1 {
		t.Fatalf("expected 1st process_crashed alert, got %d", len(reqs))
	}
	time.Sleep(600 * time.Millisecond)
	if got := len(whSrv.Requests()); got != 1 {
		t.Fatalf("expected cooldown to suppress duplicate burst alerts (want 1, got %d)", got)
	}
}

func TestF14_Tier2_ResolvedEventBypassesActiveCooldown(t *testing.T) {
	whSrv := StartMockWebhookServer(t)
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	stSet, rawSet, err := client.UpdateSettings(jwt, map[string]any{"alert_cooldown_minutes": 60})
	if err != nil || stSet < 200 || stSet >= 300 {
		t.Fatalf("UpdateSettings failed: st=%d err=%v body=%s", stSet, err, string(rawSet))
	}
	stWH, _, whRaw, err := client.CreateWebhook(jwt, WebhookChannelDTO{
		Name:             "Bypass Cooldown Hook",
		Provider:         "custom",
		URL:              whSrv.URL(),
		SubscribedEvents: []string{"traffic_paused"}, // resolved pair traffic_recovered also matches
		Enabled:          true,
	})
	if err != nil || (stWH != http.StatusOK && stWH != http.StatusCreated) {
		t.Fatalf("CreateWebhook failed: st=%d err=%v body=%s", stWH, err, string(whRaw))
	}

	stN, node, rawN, err := client.CreateNode(jwt, CreateNodeReq{
		Name:                  "F14 Bypass Node",
		Enabled:               f14_boolPtr(true),
		TrafficLimitBytes:     10000,
		TrafficThresholdBytes: 5000,
		TrafficCountMode:      "both",
	})
	if err != nil || (stN != http.StatusOK && stN != http.StatusCreated) {
		t.Fatalf("CreateNode failed: st=%d err=%v body=%s", stN, err, string(rawN))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn := f14_dialAgentHelloAndSync(t, ctx, client, node.EffectiveToken())

	if err := SendWSEnvelope(ctx, conn, "agent.metrics", "m-trip", AgentMetricsPayload{
		TS: time.Now().Unix(), NicRxDelta: 6000, Health: AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatalf("send agent.metrics: %v", err)
	}
	if _, ok := whSrv.WaitForRequests(1, 5*time.Second); !ok {
		t.Fatalf("expected traffic_paused alert")
	}

	// Immediately reset traffic within 60m cooldown -> resolved event must fire immediately
	st, raw, err := client.ResetNodeTraffic(jwt, node.ID)
	if err != nil || st >= 300 {
		t.Fatalf("ResetNodeTraffic: st=%d err=%v body=%s", st, err, string(raw))
	}

	reqs, ok := whSrv.WaitForRequests(2, 5*time.Second)
	if !ok || len(reqs) < 2 {
		t.Fatalf("expected resolved traffic_recovered to bypass 60m cooldown, got %d requests", len(reqs))
	}
	var resolvedPayload struct {
		Type     string `json:"type"`
		Resolved bool   `json:"resolved"`
	}
	if err := json.Unmarshal([]byte(reqs[1].Body), &resolvedPayload); err != nil {
		t.Fatalf("decode resolved payload: %v (body=%s)", err, reqs[1].Body)
	}
	if resolvedPayload.Type != "traffic_recovered" || !resolvedPayload.Resolved {
		t.Fatalf("expected traffic_recovered resolved=true, got %+v", resolvedPayload)
	}
}

func TestF14_Tier2_DisabledChannelAndUnsubscribedEventReceiveZero(t *testing.T) {
	whDisabled := StartMockWebhookServer(t)
	whUnsub := StartMockWebhookServer(t)
	whActive := StartMockWebhookServer(t)

	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	for _, req := range []WebhookChannelDTO{
		{Name: "Disabled", Provider: "custom", URL: whDisabled.URL(), SubscribedEvents: []string{"*"}, Enabled: false},
		{Name: "OtherEvent", Provider: "custom", URL: whUnsub.URL(), SubscribedEvents: []string{"user_expired"}, Enabled: true},
		{Name: "ActiveConfigErr", Provider: "custom", URL: whActive.URL(), SubscribedEvents: []string{"config_error"}, Enabled: true},
	} {
		st, _, raw, err := client.CreateWebhook(jwt, req)
		if err != nil || (st != http.StatusOK && st != http.StatusCreated) {
			t.Fatalf("CreateWebhook(%s) failed: st=%d err=%v body=%s", req.Name, st, err, string(raw))
		}
	}

	stN, node, rawN, err := client.CreateNode(jwt, CreateNodeReq{Name: "F14 Filter Node", Enabled: f14_boolPtr(true)})
	if err != nil || (stN != http.StatusOK && stN != http.StatusCreated) {
		t.Fatalf("CreateNode failed: st=%d err=%v body=%s", stN, err, string(rawN))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn := f14_dialAgentHelloAndSync(t, ctx, client, node.EffectiveToken())

	if err := SendWSEnvelope(ctx, conn, "agent.event", "cfg-err-1", AgentEventPayload{
		Event:   "config_error",
		Kernel:  "sing-box",
		Status:  "failed",
		Message: "invalid sing-box json",
	}); err != nil {
		t.Fatal(err)
	}

	if reqs, ok := whActive.WaitForRequests(1, 5*time.Second); !ok || len(reqs) != 1 {
		t.Fatalf("expected subscribed active channel to receive 1 config_error alert, got %d", len(reqs))
	}
	time.Sleep(300 * time.Millisecond)
	if len(whDisabled.Requests()) != 0 {
		t.Fatalf("disabled channel must receive 0 requests, got %d", len(whDisabled.Requests()))
	}
	if len(whUnsub.Requests()) != 0 {
		t.Fatalf("unsubscribed channel must receive 0 requests, got %d", len(whUnsub.Requests()))
	}
}

func TestF14_Tier2_InvalidProviderURLTemplateAndForbiddenHeadersRejected(t *testing.T) {
	whSrv := StartMockWebhookServer(t)
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	// Precondition + positive control: prove /api/v1/admin/webhooks is mounted and functional
	if stList, _, listRaw, err := client.ListWebhooks(jwt); err != nil || stList != http.StatusOK {
		t.Fatalf("precondition GET /api/v1/admin/webhooks expected 200 OK, got st=%d err=%v body=%s", stList, err, string(listRaw))
	}
	stCtrl, ctrlWH, rawCtrl, err := client.CreateWebhook(jwt, WebhookChannelDTO{
		Name:             "ValidControlHook",
		Provider:         "custom",
		URL:              whSrv.URL() + "/valid-control",
		SubscribedEvents: []string{"*"},
		Enabled:          true,
	})
	if err != nil || (stCtrl != http.StatusOK && stCtrl != http.StatusCreated) || ctrlWH.ID <= 0 {
		t.Fatalf("positive-control CreateWebhook failed: st=%d err=%v wh=%+v body=%s", stCtrl, err, ctrlWH, string(rawCtrl))
	}
	if stT, rawT, errT := client.TestWebhook(jwt, ctrlWH.ID); errT != nil || stT < 200 || stT >= 300 {
		t.Fatalf("positive-control TestWebhook failed: st=%d err=%v body=%s", stT, errT, string(rawT))
	}
	if reqs, ok := whSrv.WaitForRequests(1, 5*time.Second); !ok || len(reqs) < 1 {
		t.Fatalf("positive-control TestWebhook did not deliver request")
	}
	if stD, rawD, errD := client.DoJSON(context.Background(), http.MethodDelete, fmt.Sprintf("/api/v1/admin/webhooks/%d", ctrlWH.ID), jwt, nil, nil); errD != nil || stD < 200 || stD >= 300 {
		t.Fatalf("positive-control DELETE webhook failed: st=%d err=%v body=%s", stD, errD, string(rawD))
	}
	whSrv.Reset()

	// 1. Invalid provider and invalid URL must be rejected on create (non-404 4xx)
	for _, bad := range []struct {
		name string
		req  WebhookChannelDTO
	}{
		{"invalid_provider", WebhookChannelDTO{Name: "BadProv", Provider: "slack", URL: whSrv.URL(), Enabled: true}},
		{"ftp_url", WebhookChannelDTO{Name: "BadScheme", Provider: "custom", URL: "ftp://example.com/hook", Enabled: true}},
		{"empty_url", WebhookChannelDTO{Name: "EmptyURL", Provider: "custom", URL: "", Enabled: true}},
	} {
		st, _, raw, err := client.CreateWebhook(jwt, bad.req)
		if err != nil {
			t.Fatalf("%s error: %v", bad.name, err)
		}
		if st == http.StatusNotFound || st < 400 || st >= 500 {
			t.Fatalf("expected non-404 4xx on create for %s, got %d body=%s", bad.name, st, string(raw))
		}
	}

	// 2. Invalid template, non-JSON secret, forbidden Host / Content-Length headers rejected on create OR test push (never 404, never 200 both, never 500)
	badSecrets := []struct {
		name   string
		secret string
	}{
		{"non_json_secret", "not-a-json-object"},
		{"broken_go_template", `{"template":"{\"x\":{{.Broken"}`},
		{"non_json_rendered_output", `{"template":"not-valid-json {{.Type}}"}`},
		{"forbidden_host_header", `{"headers":{"Host":"evil.example.com"}}`},
		{"forbidden_content_length_header", `{"headers":{"Content-Length":"999"}}`},
	}

	for _, tc := range badSecrets {
		t.Run(tc.name, func(t *testing.T) {
			whSrv.Reset()
			stCreate, created, rawCreate, err := client.CreateWebhook(jwt, WebhookChannelDTO{
				Name:             tc.name,
				Provider:         "custom",
				URL:              whSrv.URL(),
				Secret:           tc.secret,
				SubscribedEvents: []string{"*"},
				Enabled:          true,
			})
			if err != nil {
				t.Fatalf("create HTTP err: %v", err)
			}
			if stCreate == http.StatusNotFound || stCreate >= 500 {
				t.Fatalf("create must not 404 or 500 for %s: st=%d body=%s", tc.name, stCreate, string(rawCreate))
			}
			if stCreate >= 400 && stCreate < 500 {
				return
			}
			// If create stored it, TestWebhook must reject with non-404 4xx (not 200, not 404, not 500) and send nothing
			stTest, rawTest, err := client.TestWebhook(jwt, created.ID)
			if err != nil {
				t.Fatalf("test HTTP err: %v", err)
			}
			if stTest == http.StatusNotFound || stTest < 400 || stTest >= 500 {
				t.Fatalf("expected non-404 4xx on test push for %s, got st=%d body=%s", tc.name, stTest, string(rawTest))
			}
			if len(whSrv.Requests()) != 0 {
				t.Fatalf("invalid secret config %s should not dispatch HTTP request", tc.name)
			}
		})
	}
}

func TestF14_Tier2_FailingAndSlowReceiverDoesNotBlockHealthyChannel(t *testing.T) {
	failSrv := StartMockWebhookServer(t)
	failSrv.SetResponse(http.StatusInternalServerError, `{"err":"downstream down"}`)

	slowSrv := StartMockWebhookServer(t)
	slowSrv.SetDelay(1500 * time.Millisecond)

	healthySrv := StartMockWebhookServer(t)

	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	for _, req := range []WebhookChannelDTO{
		{Name: "Failing", Provider: "custom", URL: failSrv.URL(), SubscribedEvents: []string{"process_crashed"}, Enabled: true},
		{Name: "Slow", Provider: "custom", URL: slowSrv.URL(), SubscribedEvents: []string{"process_crashed"}, Enabled: true},
		{Name: "Healthy", Provider: "custom", URL: healthySrv.URL(), SubscribedEvents: []string{"process_crashed"}, Enabled: true},
	} {
		st, _, raw, err := client.CreateWebhook(jwt, req)
		if err != nil || (st != http.StatusOK && st != http.StatusCreated) {
			t.Fatalf("CreateWebhook(%s) failed: st=%d err=%v body=%s", req.Name, st, err, string(raw))
		}
	}

	stN, node, rawN, err := client.CreateNode(jwt, CreateNodeReq{Name: "F14 Fault Isolation", Enabled: f14_boolPtr(true)})
	if err != nil || (stN != http.StatusOK && stN != http.StatusCreated) {
		t.Fatalf("CreateNode failed: st=%d err=%v body=%s", stN, err, string(rawN))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn := f14_dialAgentHelloAndSync(t, ctx, client, node.EffectiveToken())

	if err := SendWSEnvelope(ctx, conn, "agent.event", "crash-iso", AgentEventPayload{
		Event: "process_crashed", Kernel: "snell-server", Status: "crashed", Message: "boom",
	}); err != nil {
		t.Fatal(err)
	}

	// Panel HTTP must remain responsive immediately while slowSrv is delaying
	pubCtx, pubCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	stPub, _, pubRaw, pubErr := client.DoRaw(pubCtx, http.MethodGet, "/api/v1/public/status", nil, nil)
	pubCancel()
	if pubErr != nil || stPub != http.StatusOK {
		t.Fatalf("panel HTTP blocked/unhealthy during slow webhook delivery: st=%d err=%v body=%s", stPub, pubErr, string(pubRaw))
	}

	// All channels (failing, slow, and healthy) must complete without starving Healthy
	if reqsFail, ok := failSrv.WaitForRequests(1, 3*time.Second); !ok || len(reqsFail) < 1 {
		t.Fatalf("failing channel did not receive expected request, got %d", len(reqsFail))
	}
	if reqsSlow, ok := slowSrv.WaitForRequests(1, 3*time.Second); !ok || len(reqsSlow) < 1 {
		t.Fatalf("slow channel did not receive expected request, got %d", len(reqsSlow))
	}
	reqs, ok := healthySrv.WaitForRequests(1, 6*time.Second)
	if !ok || len(reqs) != 1 {
		t.Fatalf("healthy channel blocked/starved by failing or slow channel (got=%d)", len(reqs))
	}
	if !strings.Contains(reqs[0].Body, "process_crashed") || !strings.Contains(reqs[0].Body, "boom") {
		t.Fatalf("healthy channel received unexpected body: %s", reqs[0].Body)
	}

	// Panel remains completely healthy after all deliveries complete
	st, _, _, err := client.GetPublicStatus()
	if err != nil || st != http.StatusOK {
		t.Fatalf("panel unhealthy after webhook errors: st=%d err=%v", st, err)
	}
}

func TestF14_Tier2_WebhookAuthAndNotFound(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	for _, ep := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/admin/webhooks"},
		{http.MethodPost, "/api/v1/admin/webhooks"},
		{http.MethodGet, "/api/v1/admin/webhooks/1"},
		{http.MethodPut, "/api/v1/admin/webhooks/1"},
		{http.MethodDelete, "/api/v1/admin/webhooks/1"},
		{http.MethodPost, "/api/v1/admin/webhooks/1/test"},
	} {
		st, _, err := client.DoJSON(context.Background(), ep.method, ep.path, "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if st != http.StatusUnauthorized {
			t.Fatalf("expected 401 unauthenticated for %s %s, got %d", ep.method, ep.path, st)
		}
	}

	// Precondition: prove webhook routes are mounted when authenticated
	if stList, _, listRaw, err := client.ListWebhooks(jwt); err != nil || stList != http.StatusOK {
		t.Fatalf("precondition GET /api/v1/admin/webhooks expected 200 OK, got st=%d err=%v body=%s", stList, err, string(listRaw))
	}

	for _, ep := range []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, "/api/v1/admin/webhooks/999999", nil},
		{http.MethodPut, "/api/v1/admin/webhooks/999999", WebhookChannelDTO{Name: "x", Provider: "custom", URL: "https://example.com", Enabled: true}},
		{http.MethodDelete, "/api/v1/admin/webhooks/999999", nil},
		{http.MethodPost, "/api/v1/admin/webhooks/999999/test", nil},
	} {
		headers := map[string]string{
			"Authorization": "Bearer " + jwt,
		}
		var bodyBytes []byte
		if ep.body != nil {
			var err error
			bodyBytes, err = json.Marshal(ep.body)
			if err != nil {
				t.Fatal(err)
			}
			headers["Content-Type"] = "application/json"
		}
		st, hdr, raw, err := client.DoRaw(context.Background(), ep.method, ep.path, headers, bodyBytes)
		if err != nil {
			t.Fatal(err)
		}
		if st != http.StatusNotFound {
			t.Fatalf("expected 404 for nonexistent webhook %s %s, got %d body=%s", ep.method, ep.path, st, string(raw))
		}
		if !strings.Contains(strings.ToLower(hdr.Get("Content-Type")), "application/json") {
			t.Fatalf("expected JSON Content-Type for 404 on %s %s, got %q (body=%s)", ep.method, ep.path, hdr.Get("Content-Type"), string(raw))
		}
		if !json.Valid(raw) {
			t.Fatalf("expected valid JSON body for 404 on %s %s, got %s", ep.method, ep.path, string(raw))
		}
	}
}
