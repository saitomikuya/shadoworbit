package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/template"
	"time"
	"unicode/utf8"

	"snell-panel/internal/panel/store"
	"snell-panel/internal/protocol"
)

const (
	wecomMaxMarkdownBytes = 4096
	customTemplatePrefix  = "webhook_custom_template:"
)

func (e *Engine) deliverOne(ctx context.Context, ch store.WebhookChannel, evt AlertEvent) error {
	if !protocol.IsValidWebhookProvider(ch.Provider) {
		return fmt.Errorf("%w: %q", ErrUnsupportedProvider, ch.Provider)
	}
	if err := ValidateWebhookURL(ch.URL); err != nil {
		return err
	}

	var (
		req *http.Request
		err error
	)
	switch ch.Provider {
	case protocol.WebhookProviderFeishu:
		req, err = e.buildFeishuRequest(ctx, ch, evt)
	case protocol.WebhookProviderDingTalk:
		req, err = e.buildDingTalkRequest(ctx, ch, evt)
	case protocol.WebhookProviderWeCom:
		req, err = e.buildWeComRequest(ctx, ch, evt)
	case protocol.WebhookProviderServerChan:
		req, err = e.buildServerChanRequest(ctx, ch, evt)
	case protocol.WebhookProviderCustom:
		req, err = e.buildCustomRequest(ctx, ch, evt)
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedProvider, ch.Provider)
	}
	if err != nil {
		return err
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBodyBytes))
	if err != nil {
		return fmt.Errorf("webhook: read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%w: HTTP %d: %s", ErrProviderResponse, resp.StatusCode, truncateSnippet(body))
	}

	switch ch.Provider {
	case protocol.WebhookProviderFeishu:
		return validateFeishuResponse(body)
	case protocol.WebhookProviderDingTalk, protocol.WebhookProviderWeCom:
		return validateWeComDingTalkResponse(body)
	case protocol.WebhookProviderServerChan:
		return validateServerChanResponse(body)
	default:
		return nil
	}
}

func truncateSnippet(body []byte) string {
	s := strings.TrimSpace(string(body))
	if len(s) > 256 {
		return truncateUTF8(s, 256)
	}
	return s
}

// FormatBytes formats a byte count into a human-readable string using base-1024 units.
func FormatBytes(b uint64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	units := []string{"B", "KB", "MB", "GB", "TB", "PB", "EB"}
	val := float64(b)
	idx := 0
	for val >= 1024 && idx < len(units)-1 {
		val /= 1024
		idx++
	}
	switch {
	case val >= 100:
		return fmt.Sprintf("%.0f %s", val, units[idx])
	case val >= 10:
		return fmt.Sprintf("%.1f %s", val, units[idx])
	default:
		return fmt.Sprintf("%.2f %s", val, units[idx])
	}
}

// FormatDuration formats a duration into concise Chinese units.
func FormatDuration(d time.Duration) string {
	if d <= 0 {
		return "0 秒"
	}
	totalSecs := int64(math.Round(d.Seconds()))
	if totalSecs <= 0 {
		return "0 秒"
	}
	days := totalSecs / 86400
	hours := (totalSecs % 86400) / 3600
	mins := (totalSecs % 3600) / 60
	secs := totalSecs % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%d 天 %d 小时", days, hours)
	case hours > 0:
		return fmt.Sprintf("%d 小时 %d 分钟", hours, mins)
	case mins > 0:
		return fmt.Sprintf("%d 分钟", mins)
	default:
		return fmt.Sprintf("%d 秒", secs)
	}
}

// FormatLocalTime formats ts in local timezone with timezone abbreviation.
func FormatLocalTime(ts time.Time) string {
	if ts.IsZero() {
		return "-"
	}
	return ts.In(time.Local).Format("2006-01-02 15:04:05 MST")
}

func formatSeverityTag(evt AlertEvent) string {
	if evt.Resolved {
		return "已恢复"
	}
	switch evt.Severity {
	case SeverityCritical:
		return "严重"
	case SeverityWarning:
		return "警告"
	case SeverityInfo:
		return "通知"
	default:
		return "警告"
	}
}

func formatEventTypeLabel(eventType string) string {
	switch eventType {
	case EventNodeOffline:
		return "节点离线"
	case EventNodeOnline:
		return "节点上线恢复"
	case EventProcessCrashed:
		return "内核进程异常退出"
	case EventKernelUpdate:
		return "内核版本更新"
	case EventConfigError:
		return "节点配置异常"
	case EventTrafficWarning:
		return "节点流量预警"
	case EventTrafficPaused:
		return "节点流量超限暂停"
	case EventTrafficRecovered:
		return "节点流量恢复正常"
	case EventUserQuotaExhausted:
		return "用户流量配额耗尽"
	case EventUserExpired:
		return "用户账号已到期"
	case EventHighResourceUsage:
		return "节点资源占用过高"
	case EventTest:
		return "告警通道测试"
	default:
		if eventType == "" {
			return "未知事件"
		}
		return eventType
	}
}

func formatProviderLabel(provider string) string {
	switch provider {
	case protocol.WebhookProviderFeishu:
		return "飞书"
	case protocol.WebhookProviderDingTalk:
		return "钉钉"
	case protocol.WebhookProviderWeCom:
		return "企业微信"
	case protocol.WebhookProviderServerChan:
		return "Server酱"
	case protocol.WebhookProviderCustom:
		return "自定义 Webhook"
	default:
		return provider
	}
}

func formatAlertHeaderTitle(evt AlertEvent) string {
	tag := formatSeverityTag(evt)
	title := strings.TrimSpace(evt.Title)
	if title == "" {
		title = formatEventTypeLabel(evt.Type)
	}
	return fmt.Sprintf("【%s】%s", tag, title)
}

func formatTargetLine(evt AlertEvent) string {
	targetTypeLabel := evt.TargetType
	switch evt.TargetType {
	case TargetTypeNode:
		targetTypeLabel = "节点"
	case TargetTypeUser:
		targetTypeLabel = "用户"
	case TargetTypeSystem:
		targetTypeLabel = "系统通道"
	}

	switch {
	case targetTypeLabel != "" && evt.TargetName != "" && evt.TargetID > 0:
		return fmt.Sprintf("%s %s (#%d)", targetTypeLabel, evt.TargetName, evt.TargetID)
	case targetTypeLabel != "" && evt.TargetName != "":
		return fmt.Sprintf("%s %s", targetTypeLabel, evt.TargetName)
	case evt.TargetName != "":
		return evt.TargetName
	case targetTypeLabel != "" && evt.TargetID > 0:
		return fmt.Sprintf("%s (#%d)", targetTypeLabel, evt.TargetID)
	case targetTypeLabel != "":
		return targetTypeLabel
	default:
		return "-"
	}
}

func formatStatusLabel(evt AlertEvent) string {
	if evt.Type == EventTest {
		return "测试推送"
	}
	if evt.Resolved {
		return "已恢复"
	}
	switch evt.Severity {
	case SeverityCritical:
		return "严重告警"
	case SeverityWarning:
		return "预警通知"
	default:
		return "系统通知"
	}
}

func formatEventDisplay(evt AlertEvent) string {
	label := formatEventTypeLabel(evt.Type)
	if evt.Type == "" {
		return label
	}
	return fmt.Sprintf("%s (`%s`)", label, evt.Type)
}

// --- Feishu ---

type feishuCardPayload struct {
	Timestamp string     `json:"timestamp,omitempty"`
	Sign      string     `json:"sign,omitempty"`
	MsgType   string     `json:"msg_type"`
	Card      feishuCard `json:"card"`
}

type feishuCard struct {
	Config   feishuCardConfig    `json:"config"`
	Header   feishuCardHeader    `json:"header"`
	Elements []feishuCardElement `json:"elements"`
}

type feishuCardConfig struct {
	WideScreenMode bool `json:"wide_screen_mode"`
}

type feishuCardHeader struct {
	Template string          `json:"template"`
	Title    feishuPlainText `json:"title"`
}

type feishuPlainText struct {
	Tag     string `json:"tag"`
	Content string `json:"content"`
}

type feishuCardElement struct {
	Tag     string `json:"tag"`
	Content string `json:"content"`
}

func feishuHeaderTemplate(evt AlertEvent) string {
	if evt.Resolved {
		return "green"
	}
	switch evt.Severity {
	case SeverityCritical:
		return "red"
	case SeverityWarning:
		return "orange"
	default:
		return "blue"
	}
}

func (e *Engine) buildFeishuRequest(ctx context.Context, ch store.WebhookChannel, evt AlertEvent) (*http.Request, error) {
	var lines []string
	lines = append(lines, fmt.Sprintf("**告警状态**：%s", formatStatusLabel(evt)))
	lines = append(lines, fmt.Sprintf("**事件类型**：%s", formatEventDisplay(evt)))
	lines = append(lines, fmt.Sprintf("**影响对象**：%s", formatTargetLine(evt)))
	if evt.Message != "" {
		lines = append(lines, fmt.Sprintf("**告警内容**：%s", evt.Message))
	}
	if evt.Detail != "" {
		lines = append(lines, fmt.Sprintf("**详细信息**：%s", evt.Detail))
	}
	lines = append(lines, fmt.Sprintf("**触发时间**：%s", FormatLocalTime(evt.Timestamp)))

	payload := feishuCardPayload{
		MsgType: "interactive",
		Card: feishuCard{
			Config: feishuCardConfig{WideScreenMode: true},
			Header: feishuCardHeader{
				Template: feishuHeaderTemplate(evt),
				Title: feishuPlainText{
					Tag:     "plain_text",
					Content: formatAlertHeaderTitle(evt),
				},
			},
			Elements: []feishuCardElement{
				{
					Tag:     "markdown",
					Content: strings.Join(lines, "\n"),
				},
			},
		},
	}

	if ch.Secret != "" {
		tsStr := strconv.FormatInt(e.now().UTC().Unix(), 10)
		stringToSign := tsStr + "\n" + ch.Secret
		mac := hmac.New(sha256.New, []byte(stringToSign))
		payload.Timestamp = tsStr
		payload.Sign = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("webhook: marshal feishu payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ch.URL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("webhook: build feishu request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	return req, nil
}

func validateFeishuResponse(body []byte) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	var resp struct {
		Code          int    `json:"code"`
		Msg           string `json:"msg"`
		StatusCode    int    `json:"StatusCode"`
		StatusMessage string `json:"StatusMessage"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("%w: invalid feishu JSON response: %v", ErrProviderResponse, err)
	}
	if resp.Code != 0 {
		return fmt.Errorf("%w: feishu code=%d msg=%q", ErrProviderResponse, resp.Code, resp.Msg)
	}
	if resp.StatusCode != 0 {
		return fmt.Errorf("%w: feishu StatusCode=%d StatusMessage=%q", ErrProviderResponse, resp.StatusCode, resp.StatusMessage)
	}
	return nil
}

// --- DingTalk ---

type dingTalkPayload struct {
	MsgType  string           `json:"msgtype"`
	Markdown dingTalkMarkdown `json:"markdown"`
}

type dingTalkMarkdown struct {
	Title string `json:"title"`
	Text  string `json:"text"`
}

func (e *Engine) buildDingTalkRequest(ctx context.Context, ch store.WebhookChannel, evt AlertEvent) (*http.Request, error) {
	targetURL := ch.URL
	if ch.Secret != "" {
		u, err := url.Parse(ch.URL)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidURL, err)
		}
		tsStr := strconv.FormatInt(e.now().UTC().UnixMilli(), 10)
		stringToSign := tsStr + "\n" + ch.Secret
		mac := hmac.New(sha256.New, []byte(ch.Secret))
		mac.Write([]byte(stringToSign))
		sign := base64.StdEncoding.EncodeToString(mac.Sum(nil))

		q := u.Query()
		q.Set("timestamp", tsStr)
		q.Set("sign", sign)
		u.RawQuery = q.Encode()
		targetURL = u.String()
	}

	headerTitle := formatAlertHeaderTitle(evt)
	var lines []string
	lines = append(lines, "### "+headerTitle)
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("- **告警状态**：%s", formatStatusLabel(evt)))
	lines = append(lines, fmt.Sprintf("- **事件类型**：%s", formatEventDisplay(evt)))
	lines = append(lines, fmt.Sprintf("- **影响对象**：%s", formatTargetLine(evt)))
	if evt.Message != "" {
		lines = append(lines, fmt.Sprintf("- **告警内容**：%s", evt.Message))
	}
	if evt.Detail != "" {
		lines = append(lines, fmt.Sprintf("- **详细信息**：%s", evt.Detail))
	}
	lines = append(lines, fmt.Sprintf("- **触发时间**：%s", FormatLocalTime(evt.Timestamp)))

	payload := dingTalkPayload{
		MsgType: "markdown",
		Markdown: dingTalkMarkdown{
			Title: headerTitle,
			Text:  strings.Join(lines, "\n"),
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("webhook: marshal dingtalk payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("webhook: build dingtalk request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	return req, nil
}

// --- WeCom ---

type wecomPayload struct {
	MsgType  string        `json:"msgtype"`
	Markdown wecomMarkdown `json:"markdown"`
}

type wecomMarkdown struct {
	Content string `json:"content"`
}

func (e *Engine) buildWeComRequest(ctx context.Context, ch store.WebhookChannel, evt AlertEvent) (*http.Request, error) {
	statusColor := "warning"
	if evt.Resolved {
		statusColor = "info"
	}
	var lines []string
	lines = append(lines, "### "+formatAlertHeaderTitle(evt))
	lines = append(lines, fmt.Sprintf(`> **告警状态**：<font color="%s">%s</font>`, statusColor, formatStatusLabel(evt)))
	lines = append(lines, fmt.Sprintf("> **事件类型**：%s", formatEventDisplay(evt)))
	lines = append(lines, fmt.Sprintf("> **影响对象**：%s", formatTargetLine(evt)))
	if evt.Message != "" {
		lines = append(lines, fmt.Sprintf("> **告警内容**：%s", evt.Message))
	}
	if evt.Detail != "" {
		lines = append(lines, fmt.Sprintf("> **详细信息**：%s", evt.Detail))
	}
	lines = append(lines, fmt.Sprintf("> **触发时间**：%s", FormatLocalTime(evt.Timestamp)))

	content := truncateUTF8(strings.Join(lines, "\n"), wecomMaxMarkdownBytes)
	payload := wecomPayload{
		MsgType:  "markdown",
		Markdown: wecomMarkdown{Content: content},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("webhook: marshal wecom payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ch.URL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("webhook: build wecom request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	return req, nil
}

func validateWeComDingTalkResponse(body []byte) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	var resp struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("%w: invalid provider JSON response: %v", ErrProviderResponse, err)
	}
	if resp.ErrCode != 0 {
		return fmt.Errorf("%w: errcode=%d errmsg=%q", ErrProviderResponse, resp.ErrCode, resp.ErrMsg)
	}
	return nil
}

// --- ServerChan ---

func truncateRunes(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	if maxRunes <= 1 {
		return string(runes[:maxRunes])
	}
	return string(runes[:maxRunes-1]) + "…"
}

func (e *Engine) buildServerChanRequest(ctx context.Context, ch store.WebhookChannel, evt AlertEvent) (*http.Request, error) {
	title := truncateRunes(formatAlertHeaderTitle(evt), 32)
	var lines []string
	lines = append(lines, fmt.Sprintf("- **告警状态**：%s", formatStatusLabel(evt)))
	lines = append(lines, fmt.Sprintf("- **事件类型**：%s", formatEventDisplay(evt)))
	lines = append(lines, fmt.Sprintf("- **影响对象**：%s", formatTargetLine(evt)))
	if evt.Message != "" {
		lines = append(lines, fmt.Sprintf("- **告警内容**：%s", evt.Message))
	}
	if evt.Detail != "" {
		lines = append(lines, fmt.Sprintf("- **详细信息**：%s", evt.Detail))
	}
	lines = append(lines, fmt.Sprintf("- **触发时间**：%s", FormatLocalTime(evt.Timestamp)))

	payload := map[string]any{
		"title": title,
		"desp":  strings.Join(lines, "\n"),
	}
	if evt.Message != "" {
		payload["short"] = truncateRunes(evt.Message, 64)
	}

	if secret := strings.TrimSpace(ch.Secret); secret != "" {
		if strings.HasPrefix(secret, "{") {
			var opts map[string]any
			if err := json.Unmarshal([]byte(secret), &opts); err != nil {
				return nil, fmt.Errorf("%w: invalid serverchan secret JSON: %v", ErrInvalidSecretConfig, err)
			}
			for _, key := range []string{"channel", "tags", "noip", "openid", "short"} {
				if v, ok := opts[key]; ok {
					payload[key] = v
				}
			}
		} else {
			payload["tags"] = secret
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("webhook: marshal serverchan payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ch.URL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("webhook: build serverchan request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	return req, nil
}

func validateServerChanResponse(body []byte) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	var resp struct {
		Code    *int   `json:"code"`
		Message string `json:"message"`
		ErrNo   *int   `json:"errno"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("%w: invalid serverchan JSON response: %v", ErrProviderResponse, err)
	}
	if resp.Code != nil && *resp.Code != 0 {
		return fmt.Errorf("%w: code=%d message=%q", ErrProviderResponse, *resp.Code, resp.Message)
	}
	if resp.ErrNo != nil && *resp.ErrNo != 0 {
		return fmt.Errorf("%w: errno=%d errmsg=%q", ErrProviderResponse, *resp.ErrNo, resp.ErrMsg)
	}
	return nil
}

func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	if maxBytes <= 3 {
		for maxBytes > 0 && !utf8.ValidString(s[:maxBytes]) {
			maxBytes--
		}
		return s[:maxBytes]
	}
	limit := maxBytes - 3
	for limit > 0 && !utf8.ValidString(s[:limit]) {
		limit--
	}
	return s[:limit] + "..."
}

// --- Custom ---

type customConfig struct {
	Headers  map[string]string
	Template string
}

type customTemplateData struct {
	AlertEvent
	Status           string
	TimestampRFC3339 string
	TimestampUnix    int64
}

func parseCustomConfig(secret string) (customConfig, error) {
	trimmed := strings.TrimSpace(secret)
	if trimmed == "" {
		return customConfig{}, nil
	}
	if !strings.HasPrefix(trimmed, "{") {
		return customConfig{}, fmt.Errorf("%w: custom secret must be empty or a JSON object", ErrInvalidSecretConfig)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		return customConfig{}, fmt.Errorf("%w: parse custom secret JSON: %v", ErrInvalidSecretConfig, err)
	}

	isStructured := len(raw) > 0
	hasStructuredType := false
	for k, v := range raw {
		if k != "headers" && k != "template" {
			isStructured = false
			break
		}
		tv := bytes.TrimSpace(v)
		if (k == "headers" && len(tv) > 0 && tv[0] == '{') ||
			(k == "template" && len(tv) > 0 && tv[0] == '"') {
			hasStructuredType = true
		}
	}

	var cfg customConfig
	if isStructured && hasStructuredType {
		var structured struct {
			Headers  map[string]string `json:"headers"`
			Template string            `json:"template"`
		}
		if err := json.Unmarshal([]byte(trimmed), &structured); err != nil {
			return customConfig{}, fmt.Errorf("%w: decode structured custom config: %v", ErrInvalidSecretConfig, err)
		}
		cfg.Headers = structured.Headers
		cfg.Template = structured.Template
	} else {
		var flatHeaders map[string]string
		if err := json.Unmarshal([]byte(trimmed), &flatHeaders); err != nil {
			return customConfig{}, fmt.Errorf("%w: decode custom headers JSON: %v", ErrInvalidSecretConfig, err)
		}
		cfg.Headers = flatHeaders
	}

	if err := validateCustomHeaders(cfg.Headers); err != nil {
		return customConfig{}, err
	}
	return cfg, nil
}

func validateCustomHeaders(headers map[string]string) error {
	for k, v := range headers {
		trimmedKey := strings.TrimSpace(k)
		if trimmedKey == "" || strings.ContainsAny(k, "\r\n\x00") || strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("%w: invalid header name or value", ErrInvalidSecretConfig)
		}
		if strings.EqualFold(trimmedKey, "Host") || strings.EqualFold(trimmedKey, "Content-Length") {
			return fmt.Errorf("%w: forbidden header %q", ErrInvalidSecretConfig, k)
		}
	}
	return nil
}

func customTemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"jsonEscape": func(v any) (string, error) {
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(fmt.Sprint(v)); err != nil {
				return "", err
			}
			s := strings.TrimSuffix(buf.String(), "\n")
			if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
				s = s[1 : len(s)-1]
			}
			return s, nil
		},
		"jsonQuote": encodeJSONNoEscape,
		"toJSON":    encodeJSONNoEscape,
	}
}

func encodeJSONNoEscape(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

func (e *Engine) buildCustomRequest(ctx context.Context, ch store.WebhookChannel, evt AlertEvent) (*http.Request, error) {
	cfg, err := parseCustomConfig(ch.Secret)
	if err != nil {
		return nil, err
	}
	if cfg.Template == "" && e.store != nil && ch.ID > 0 {
		tplStr, err := e.store.GetSettingOrDefault(ctx, customTemplatePrefix+strconv.FormatInt(ch.ID, 10), "")
		if err != nil {
			return nil, fmt.Errorf("webhook: load custom template setting: %w", err)
		}
		cfg.Template = tplStr
	}

	var body []byte
	if strings.TrimSpace(cfg.Template) != "" {
		tpl, err := template.New("custom").Option("missingkey=zero").Funcs(customTemplateFuncs()).Parse(cfg.Template)
		if err != nil {
			return nil, fmt.Errorf("%w: parse custom template: %v", ErrInvalidSecretConfig, err)
		}
		status := "firing"
		if evt.Resolved {
			status = "resolved"
		}
		data := customTemplateData{
			AlertEvent:       evt,
			Status:           status,
			TimestampRFC3339: evt.Timestamp.UTC().Format(time.RFC3339),
			TimestampUnix:    evt.Timestamp.UTC().Unix(),
		}
		var buf bytes.Buffer
		if err := tpl.Execute(&buf, data); err != nil {
			return nil, fmt.Errorf("%w: execute custom template: %v", ErrInvalidSecretConfig, err)
		}
		body = buf.Bytes()
		if !json.Valid(body) {
			return nil, fmt.Errorf("%w: rendered custom template is not valid JSON", ErrInvalidSecretConfig)
		}
	} else {
		payload := struct {
			Type       string `json:"type"`
			Severity   string `json:"severity"`
			TargetType string `json:"target_type"`
			TargetID   int64  `json:"target_id"`
			TargetName string `json:"target_name"`
			Title      string `json:"title"`
			Message    string `json:"message"`
			Detail     string `json:"detail"`
			Resolved   bool   `json:"resolved"`
			Timestamp  string `json:"timestamp"`
		}{
			Type:       evt.Type,
			Severity:   evt.Severity,
			TargetType: evt.TargetType,
			TargetID:   evt.TargetID,
			TargetName: evt.TargetName,
			Title:      evt.Title,
			Message:    evt.Message,
			Detail:     evt.Detail,
			Resolved:   evt.Resolved,
			Timestamp:  evt.Timestamp.UTC().Format(time.RFC3339),
		}
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("webhook: marshal custom payload: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ch.URL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("webhook: build custom request: %w", err)
	}
	hasContentType := false
	for k, v := range cfg.Headers {
		if strings.EqualFold(strings.TrimSpace(k), "Content-Type") {
			hasContentType = true
		}
		req.Header.Set(k, v)
	}
	if !hasContentType {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	return req, nil
}
