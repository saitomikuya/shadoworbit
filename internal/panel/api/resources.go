package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"text/template"
	"time"

	"snell-panel/internal/panel/auth"
	"snell-panel/internal/panel/hub"
	"snell-panel/internal/panel/scheduler"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/panel/webhook"
	"snell-panel/internal/protocol"
)

// --- DNS Rule Groups ---

type dnsRuleGroupRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Rules       []string `json:"rules"`
}

func (s *server) handleListDNSRuleGroups(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	groups, err := s.store.ListDNSRuleGroups(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list dns rule groups")
		return
	}
	if groups == nil {
		groups = []store.DNSRuleGroup{}
	}
	for i := range groups {
		if groups[i].Rules == nil {
			groups[i].Rules = []string{}
		}
	}
	writeJSON(w, http.StatusOK, groups)
}

func (s *server) handleCreateDNSRuleGroup(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	var req dnsRuleGroupRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "name cannot be empty")
		return
	}
	rules := req.Rules
	if rules == nil {
		rules = []string{}
	}
	grp := &store.DNSRuleGroup{
		Name:        name,
		Description: req.Description,
		Rules:       rules,
	}
	if err := s.store.CreateDNSRuleGroup(r.Context(), grp); err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			writeError(w, http.StatusConflict, "dns rule group name already exists")
		case errors.Is(err, store.ErrInvalidArgument):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "failed to create dns rule group")
		}
		return
	}
	writeJSON(w, http.StatusCreated, grp)
}

func (s *server) handleGetDNSRuleGroup(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid dns rule group id")
		return
	}
	grp, err := s.store.GetDNSRuleGroupByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "dns rule group not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to get dns rule group")
		return
	}
	if grp.Rules == nil {
		grp.Rules = []string{}
	}
	writeJSON(w, http.StatusOK, grp)
}

func (s *server) handleUpdateDNSRuleGroup(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid dns rule group id")
		return
	}
	var req dnsRuleGroupRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "name cannot be empty")
		return
	}
	rules := req.Rules
	if rules == nil {
		rules = []string{}
	}
	grp := &store.DNSRuleGroup{
		ID:          id,
		Name:        name,
		Description: req.Description,
		Rules:       rules,
	}
	if err := s.store.UpdateDNSRuleGroup(r.Context(), grp); err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "dns rule group not found")
		case errors.Is(err, store.ErrConflict):
			writeError(w, http.StatusConflict, "dns rule group name already exists")
		case errors.Is(err, store.ErrInvalidArgument):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "failed to update dns rule group")
		}
		return
	}

	affected, err := s.store.IncrementConfigRevisionByDNSGroup(r.Context(), id)
	if err != nil {
		s.logger.Warn("increment config_revision by dns group failed", "group_id", id, "err", err)
	} else {
		s.syncNodeIDs(r.Context(), affected)
	}

	updated, err := s.store.GetDNSRuleGroupByID(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusOK, grp)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *server) handleDeleteDNSRuleGroup(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid dns rule group id")
		return
	}

	affected, err := s.store.IncrementConfigRevisionByDNSGroup(r.Context(), id)
	if err != nil {
		s.logger.Warn("capture/bump nodes before deleting dns group failed", "group_id", id, "err", err)
	}

	if err := s.store.DeleteDNSRuleGroup(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "dns rule group not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete dns rule group")
		return
	}

	s.syncNodeIDs(r.Context(), affected)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- Subscription Templates ---

type templateRequest struct {
	Name       string `json:"name"`
	ClientType string `json:"client_type"`
	Content    string `json:"content"`
	IsDefault  bool   `json:"is_default"`
}

func (s *server) handleListTemplates(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	clientType := strings.TrimSpace(r.URL.Query().Get("client_type"))
	if clientType != "" && !protocol.IsValidClientType(clientType) {
		writeError(w, http.StatusBadRequest, "invalid client_type")
		return
	}
	tpls, err := s.store.ListSubTemplates(r.Context(), clientType)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list templates")
		return
	}
	if tpls == nil {
		tpls = []store.SubTemplate{}
	}
	writeJSON(w, http.StatusOK, tpls)
}

func (s *server) handleCreateTemplate(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	var req templateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	name := strings.TrimSpace(req.Name)
	clientType := strings.TrimSpace(req.ClientType)
	if name == "" {
		writeError(w, http.StatusBadRequest, "name cannot be empty")
		return
	}
	if !protocol.IsValidClientType(clientType) {
		writeError(w, http.StatusBadRequest, "invalid client_type")
		return
	}
	tpl := &store.SubTemplate{
		Name:       name,
		ClientType: clientType,
		Content:    req.Content,
		IsDefault:  req.IsDefault,
	}
	if err := s.store.CreateSubTemplate(r.Context(), tpl); err != nil {
		switch {
		case errors.Is(err, store.ErrInvalidArgument):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, store.ErrConflict):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "failed to create template")
		}
		return
	}
	writeJSON(w, http.StatusCreated, tpl)
}

func (s *server) handleGetTemplate(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid template id")
		return
	}
	tpl, err := s.store.GetSubTemplateByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "template not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to get template")
		return
	}
	writeJSON(w, http.StatusOK, tpl)
}

func (s *server) handleUpdateTemplate(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid template id")
		return
	}
	var req templateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	name := strings.TrimSpace(req.Name)
	clientType := strings.TrimSpace(req.ClientType)
	if name == "" {
		writeError(w, http.StatusBadRequest, "name cannot be empty")
		return
	}
	if !protocol.IsValidClientType(clientType) {
		writeError(w, http.StatusBadRequest, "invalid client_type")
		return
	}
	tpl := &store.SubTemplate{
		ID:         id,
		Name:       name,
		ClientType: clientType,
		Content:    req.Content,
		IsDefault:  req.IsDefault,
	}
	if err := s.store.UpdateSubTemplate(r.Context(), tpl); err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "template not found")
		case errors.Is(err, store.ErrInvalidArgument):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, store.ErrConflict):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "failed to update template")
		}
		return
	}
	updated, err := s.store.GetSubTemplateByID(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusOK, tpl)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *server) handleDeleteTemplate(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid template id")
		return
	}
	if err := s.store.DeleteSubTemplate(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "template not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete template")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- Kernels ---

type addSnellVersionRequest struct {
	Version  string            `json:"version"`
	URLs     map[string]string `json:"urls"`
	AMD64URL string            `json:"amd64_url"`
	ARM64URL string            `json:"arm64_url"`
}

type deleteSnellVersionRequest struct {
	Version string `json:"version"`
}

func (s *server) handleListKernels(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	cat, err := s.sched.ListKernels(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list kernels")
		return
	}
	writeJSON(w, http.StatusOK, cat)
}

func (s *server) handleSyncKernels(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	cat, err := s.sched.SyncKernels(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("kernel sync failed: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, cat)
}

func (s *server) handleListSnellVersions(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	versions, err := s.sched.ListSnellVersions(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list snell versions")
		return
	}
	if versions == nil {
		versions = []scheduler.SnellVersionEntry{}
	}
	writeJSON(w, http.StatusOK, versions)
}

func (s *server) handleAddSnellVersion(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	var req addSnellVersionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	urls := req.URLs
	if len(urls) == 0 {
		urls = map[string]string{}
		if strings.TrimSpace(req.AMD64URL) != "" {
			urls["amd64"] = strings.TrimSpace(req.AMD64URL)
		}
		if strings.TrimSpace(req.ARM64URL) != "" {
			urls["arm64"] = strings.TrimSpace(req.ARM64URL)
		}
	}

	entry, err := s.sched.AddCustomSnellVersion(r.Context(), req.Version, urls)
	if err != nil {
		if errors.Is(err, scheduler.ErrInvalidArgument) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to add custom snell version")
		return
	}
	writeJSON(w, http.StatusCreated, entry)
}

func (s *server) handleDeleteSnellVersion(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	ver := strings.TrimSpace(r.PathValue("version"))
	if ver == "" {
		ver = strings.TrimSpace(r.URL.Query().Get("version"))
	}
	if ver == "" {
		var req deleteSnellVersionRequest
		if err := decodeOptionalJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON payload")
			return
		}
		ver = strings.TrimSpace(req.Version)
	}

	if err := s.sched.DeleteCustomSnellVersion(r.Context(), ver); err != nil {
		switch {
		case errors.Is(err, scheduler.ErrInvalidArgument):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, scheduler.ErrNotFound):
			writeError(w, http.StatusNotFound, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "failed to delete custom snell version")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "version": ver})
}

func (s *server) handleKernelUpdate(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	var req scheduler.KernelUpdateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	res, err := s.sched.DispatchKernelUpdate(r.Context(), req)
	if err != nil {
		if errors.Is(err, scheduler.ErrInvalidArgument) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to dispatch kernel update")
		return
	}

	if strings.TrimSpace(req.DownloadURL) == "" && len(res.Dispatched) == 0 {
		writeJSON(w, http.StatusBadRequest, res)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// --- Webhooks ---

type webhookChannelDTO struct {
	store.WebhookChannel
	CustomTemplate string `json:"custom_template,omitempty"`
}

type webhookChannelRequest struct {
	Name             string   `json:"name"`
	Provider         string   `json:"provider"`
	URL              string   `json:"url"`
	Secret           string   `json:"secret"`
	SubscribedEvents []string `json:"subscribed_events"`
	Enabled          *bool    `json:"enabled"`
	CustomTemplate   *string  `json:"custom_template"`
}

func validateCustomWebhookSecretAndTemplate(secret string, customTpl *string) error {
	trimmed := strings.TrimSpace(secret)
	var tplText string

	if trimmed != "" {
		if !strings.HasPrefix(trimmed, "{") {
			return errors.New("custom secret must be empty or a JSON object")
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
			return fmt.Errorf("invalid custom secret JSON: %w", err)
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

		var headers map[string]string
		if isStructured && hasStructuredType {
			var structured struct {
				Headers  map[string]string `json:"headers"`
				Template string            `json:"template"`
			}
			if err := json.Unmarshal([]byte(trimmed), &structured); err != nil {
				return fmt.Errorf("invalid structured custom secret: %w", err)
			}
			headers = structured.Headers
			tplText = structured.Template
		} else {
			if err := json.Unmarshal([]byte(trimmed), &headers); err != nil {
				return fmt.Errorf("invalid custom headers JSON: %w", err)
			}
		}

		for k, v := range headers {
			tk := strings.TrimSpace(k)
			if tk == "" || strings.ContainsAny(k, "\r\n\x00") || strings.ContainsAny(v, "\r\n\x00") {
				return errors.New("invalid custom header name or value")
			}
			if strings.EqualFold(tk, "Host") || strings.EqualFold(tk, "Content-Length") {
				return fmt.Errorf("forbidden custom header %q", k)
			}
		}
	}

	if tplText == "" && customTpl != nil {
		tplText = *customTpl
	}
	if strings.TrimSpace(tplText) != "" {
		if err := validateCustomGoTemplate(tplText); err != nil {
			return err
		}
	}
	return nil
}

func validateCustomGoTemplate(tplText string) error {
	funcs := template.FuncMap{
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
		"jsonQuote": func(v any) (string, error) {
			b, err := json.Marshal(v)
			return string(b), err
		},
		"toJSON": func(v any) (string, error) {
			b, err := json.Marshal(v)
			return string(b), err
		},
	}

	tpl, err := template.New("custom").Option("missingkey=zero").Funcs(funcs).Parse(tplText)
	if err != nil {
		return fmt.Errorf("invalid custom template syntax: %w", err)
	}

	sample := struct {
		webhook.AlertEvent
		Status           string
		TimestampRFC3339 string
		TimestampUnix    int64
	}{
		AlertEvent: webhook.AlertEvent{
			Type:       webhook.EventTest,
			Severity:   webhook.SeverityInfo,
			TargetType: webhook.TargetTypeSystem,
			TargetID:   1,
			TargetName: "node \"alpha\" \\ beta",
			Title:      "alert \"title\" \\ line\nnext",
			Message:    "msg with \"quotes\", \\backslash, and\nnewline",
			Detail:     "detail \"quoted\" \\ path\nline2",
			Resolved:   false,
			Timestamp:  time.Unix(1700000000, 0).UTC(),
		},
		Status:           "firing",
		TimestampRFC3339: "2023-11-14T22:13:20Z",
		TimestampUnix:    1700000000,
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, sample); err != nil {
		return fmt.Errorf("custom template execution failed: %w", err)
	}
	if !json.Valid(buf.Bytes()) {
		return errors.New("custom template must render valid JSON (hint: wrap string fields with jsonEscape or use jsonQuote)")
	}
	return nil
}

func validateWebhookRequest(req webhookChannelRequest) error {
	if strings.TrimSpace(req.Name) == "" {
		return errors.New("name cannot be empty")
	}
	if !protocol.IsValidWebhookProvider(req.Provider) {
		return fmt.Errorf("unsupported webhook provider %q", req.Provider)
	}
	if err := webhook.ValidateWebhookURL(req.URL); err != nil {
		return err
	}
	for _, ev := range req.SubscribedEvents {
		if !webhook.IsValidSubscriptionEvent(ev) {
			return fmt.Errorf("invalid subscribed event %q", ev)
		}
	}
	if req.Provider == protocol.WebhookProviderCustom {
		if err := validateCustomWebhookSecretAndTemplate(req.Secret, req.CustomTemplate); err != nil {
			return err
		}
	} else if req.Provider == protocol.WebhookProviderServerChan {
		if trimmed := strings.TrimSpace(req.Secret); strings.HasPrefix(trimmed, "{") && !json.Valid([]byte(trimmed)) {
			return errors.New("serverchan secret JSON must be valid JSON")
		}
	}
	return nil
}

func (s *server) toWebhookDTO(r *http.Request, ch store.WebhookChannel) webhookChannelDTO {
	if ch.SubscribedEvents == nil {
		ch.SubscribedEvents = []string{}
	}
	var tpl string
	if ch.Provider == protocol.WebhookProviderCustom {
		tpl, _ = s.store.GetSettingOrDefault(r.Context(), fmt.Sprintf("webhook_custom_template:%d", ch.ID), "")
	}
	return webhookChannelDTO{
		WebhookChannel: ch,
		CustomTemplate: tpl,
	}
}

func (s *server) handleListWebhooks(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	channels, err := s.store.ListWebhookChannels(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list webhooks")
		return
	}
	out := make([]webhookChannelDTO, 0, len(channels))
	for _, ch := range channels {
		out = append(out, s.toWebhookDTO(r, ch))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) handleCreateWebhook(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	var req webhookChannelRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	if err := validateWebhookRequest(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	events := req.SubscribedEvents
	if events == nil {
		events = []string{}
	}

	ch := &store.WebhookChannel{
		Name:             strings.TrimSpace(req.Name),
		Provider:         req.Provider,
		URL:              strings.TrimSpace(req.URL),
		Secret:           req.Secret,
		SubscribedEvents: events,
		Enabled:          enabled,
	}
	if err := s.store.CreateWebhookChannel(r.Context(), ch); err != nil {
		switch {
		case errors.Is(err, store.ErrInvalidArgument):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, store.ErrConflict):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "failed to create webhook channel")
		}
		return
	}

	if req.CustomTemplate != nil {
		key := fmt.Sprintf("webhook_custom_template:%d", ch.ID)
		if err := s.store.SetSetting(r.Context(), key, *req.CustomTemplate); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save webhook custom template")
			return
		}
	}

	writeJSON(w, http.StatusCreated, s.toWebhookDTO(r, *ch))
}

func (s *server) handleGetWebhook(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid webhook id")
		return
	}
	ch, err := s.store.GetWebhookChannelByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "webhook channel not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to get webhook channel")
		return
	}
	writeJSON(w, http.StatusOK, s.toWebhookDTO(r, *ch))
}

func (s *server) handleUpdateWebhook(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid webhook id")
		return
	}
	var req webhookChannelRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	existing, err := s.store.GetWebhookChannelByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "webhook channel not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to load webhook channel")
		return
	}

	if req.Provider == protocol.WebhookProviderCustom && req.CustomTemplate == nil {
		if existingTpl, err := s.store.GetSettingOrDefault(r.Context(), fmt.Sprintf("webhook_custom_template:%d", id), ""); err == nil && existingTpl != "" {
			req.CustomTemplate = &existingTpl
		}
	}

	if err := validateWebhookRequest(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	enabled := existing.Enabled
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	events := req.SubscribedEvents
	if events == nil {
		events = []string{}
	}

	ch := &store.WebhookChannel{
		ID:               id,
		Name:             strings.TrimSpace(req.Name),
		Provider:         req.Provider,
		URL:              strings.TrimSpace(req.URL),
		Secret:           req.Secret,
		SubscribedEvents: events,
		Enabled:          enabled,
	}
	if err := s.store.UpdateWebhookChannel(r.Context(), ch); err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "webhook channel not found")
		case errors.Is(err, store.ErrInvalidArgument):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "failed to update webhook channel")
		}
		return
	}

	tplKey := fmt.Sprintf("webhook_custom_template:%d", id)
	if req.Provider != protocol.WebhookProviderCustom {
		if err := s.store.SetSetting(r.Context(), tplKey, ""); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to clear webhook custom template")
			return
		}
	} else if req.CustomTemplate != nil {
		if err := s.store.SetSetting(r.Context(), tplKey, *req.CustomTemplate); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to save webhook custom template")
			return
		}
	}

	updated, err := s.store.GetWebhookChannelByID(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusOK, s.toWebhookDTO(r, *ch))
		return
	}
	writeJSON(w, http.StatusOK, s.toWebhookDTO(r, *updated))
}

func (s *server) handleDeleteWebhook(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid webhook id")
		return
	}
	if err := s.store.DeleteWebhookChannel(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "webhook channel not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete webhook channel")
		return
	}
	_ = s.store.SetSetting(r.Context(), fmt.Sprintf("webhook_custom_template:%d", id), "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *server) handleTestWebhook(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid webhook id")
		return
	}
	ch, err := s.store.GetWebhookChannelByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "webhook channel not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to load webhook channel")
		return
	}

	if err := s.webhook.SendTest(r.Context(), *ch); err != nil {
		switch {
		case errors.Is(err, webhook.ErrInvalidSecretConfig),
			errors.Is(err, webhook.ErrInvalidURL),
			errors.Is(err, webhook.ErrUnsupportedProvider):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeError(w, http.StatusBadGateway, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- Minute-Level Node Usage Traffic Logs ---

func parseTrafficLogTimeBound(raw string, endOfDay bool) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	if len(trimmed) == 10 {
		if _, err := time.Parse("2006-01-02", trimmed); err == nil {
			if endOfDay {
				return trimmed + "T23:59:59Z", nil
			}
			return trimmed + "T00:00:00Z", nil
		}
	}
	if t, err := time.Parse(time.RFC3339Nano, trimmed); err == nil {
		return t.UTC().Format("2006-01-02T15:04:05Z"), nil
	}
	return "", fmt.Errorf("invalid time filter %q", raw)
}

func (s *server) handleListTrafficLogs(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	q := r.URL.Query()
	var filter store.TrafficUsageLogFilter

	if rawNodeID := strings.TrimSpace(q.Get("node_id")); rawNodeID != "" {
		nid, err := strconv.ParseInt(rawNodeID, 10, 64)
		if err != nil || nid <= 0 {
			writeError(w, http.StatusBadRequest, "invalid node_id")
			return
		}
		filter.NodeID = nid
	}

	rawFrom := q.Get("from")
	if strings.TrimSpace(rawFrom) == "" {
		rawFrom = q.Get("from_date")
	}
	fromBound, err := parseTrafficLogTimeBound(rawFrom, false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	filter.From = fromBound

	rawTo := q.Get("to")
	if strings.TrimSpace(rawTo) == "" {
		rawTo = q.Get("to_date")
	}
	toBound, err := parseTrafficLogTimeBound(rawTo, true)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	filter.To = toBound

	if rawLimit := strings.TrimSpace(q.Get("limit")); rawLimit != "" {
		lim, err := strconv.Atoi(rawLimit)
		if err != nil || lim <= 0 {
			writeError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		filter.Limit = lim
	}

	items, err := s.store.QueryTrafficUsageLogs(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query traffic logs")
		return
	}
	if items == nil {
		items = []store.TrafficUsageLog{}
	}

	totalStored, err := s.store.CountTrafficUsageLogs(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to count traffic logs")
		return
	}

	maxEntries := store.DefaultTrafficLogMaxEntries
	if rawMax, err := s.store.GetSettingOrDefault(r.Context(), "traffic_log_max_entries", strconv.Itoa(store.DefaultTrafficLogMaxEntries)); err == nil {
		if parsed, err := strconv.Atoi(strings.TrimSpace(rawMax)); err == nil && parsed > 0 {
			maxEntries = parsed
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items":        items,
		"max_entries":  maxEntries,
		"total_stored": totalStored,
	})
}

// --- Daily Traffic ---

type dailyTrafficDTO struct {
	ID         int64  `json:"id"`
	TargetType string `json:"target_type"`
	TargetID   int64  `json:"target_id"`
	NodeID     int64  `json:"node_id,omitempty"`
	UserID     int64  `json:"user_id,omitempty"`
	Date       string `json:"date"`
	LogDate    string `json:"log_date"`
	RxBytes    int64  `json:"rx_bytes"`
	TxBytes    int64  `json:"tx_bytes"`
}

func (s *server) handleListDailyTraffic(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	q := r.URL.Query()
	filter := store.DailyTrafficFilter{
		TargetType: strings.TrimSpace(q.Get("target_type")),
	}
	if rawTID := strings.TrimSpace(q.Get("target_id")); rawTID != "" {
		tid, err := strconv.ParseInt(rawTID, 10, 64)
		if err != nil || tid <= 0 {
			writeError(w, http.StatusBadRequest, "invalid target_id")
			return
		}
		filter.TargetID = tid
	}
	filter.FromDate = strings.TrimSpace(q.Get("from_date"))
	if filter.FromDate == "" {
		filter.FromDate = strings.TrimSpace(q.Get("from"))
	}
	filter.ToDate = strings.TrimSpace(q.Get("to_date"))
	if filter.ToDate == "" {
		filter.ToDate = strings.TrimSpace(q.Get("to"))
	}

	rows, err := s.store.QueryDailyTraffic(r.Context(), filter)
	if err != nil {
		if errors.Is(err, store.ErrInvalidArgument) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to query daily traffic")
		return
	}

	out := make([]dailyTrafficDTO, 0, len(rows))
	for _, row := range rows {
		dto := dailyTrafficDTO{
			ID:         row.ID,
			TargetType: row.TargetType,
			TargetID:   row.TargetID,
			Date:       row.LogDate,
			LogDate:    row.LogDate,
			RxBytes:    row.RxBytes,
			TxBytes:    row.TxBytes,
		}
		switch row.TargetType {
		case "node":
			dto.NodeID = row.TargetID
		case "user":
			dto.UserID = row.TargetID
		}
		out = append(out, dto)
	}
	writeJSON(w, http.StatusOK, out)
}

// --- Settings ---

type safeSettingsDTO struct {
	SiteTitle               string `json:"site_title"`
	Announcement            string `json:"announcement"`
	PercentageOnly          bool   `json:"percentage_only"`
	AdminSubToken           string `json:"admin_sub_token"`
	AlertCooldownMinutes    int    `json:"alert_cooldown_minutes"`
	WarningThresholdPercent int    `json:"warning_threshold_percent"`
	OfflineTimeoutSeconds   int    `json:"offline_timeout_seconds"`
	DefaultUpstreamDNS      string `json:"default_upstream_dns"`
	DefaultLocalDNSPort     int    `json:"default_local_dns_port"`
	AgentDockerImage        string `json:"agent_docker_image"`
	TrafficLogMaxEntries    int    `json:"traffic_log_max_entries"`
	AlertUserExpired        bool   `json:"alert_user_expired"`
	AlertUserQuotaExhausted bool   `json:"alert_user_quota_exhausted"`
}

func buildSafeSettingsDTO(all map[string]string) safeSettingsDTO {
	parseBool := func(key string, def bool) bool {
		v, ok := all[key]
		if !ok || strings.TrimSpace(v) == "" {
			return def
		}
		trimmed := strings.ToLower(strings.TrimSpace(v))
		switch trimmed {
		case "off":
			return false
		case "on":
			return true
		}
		b, err := strconv.ParseBool(trimmed)
		if err != nil {
			return def
		}
		return b
	}
	parseInt := func(key string, def int) int {
		v, ok := all[key]
		if !ok || strings.TrimSpace(v) == "" {
			return def
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return def
		}
		return n
	}

	siteTitle := all["site_title"]
	if strings.TrimSpace(siteTitle) == "" {
		siteTitle = "ShadowOrbit"
	}
	upstreamDNS := all["default_upstream_dns"]
	if strings.TrimSpace(upstreamDNS) == "" {
		upstreamDNS = "1.1.1.1:53"
	}
	agentDockerImage := strings.TrimSpace(all["agent_docker_image"])
	if agentDockerImage == "" {
		agentDockerImage = "saitomikuya/shadoworbit-agent:latest"
	}
	logMaxEntries := parseInt("traffic_log_max_entries", store.DefaultTrafficLogMaxEntries)
	if logMaxEntries <= 0 {
		logMaxEntries = store.DefaultTrafficLogMaxEntries
	}

	return safeSettingsDTO{
		SiteTitle:               siteTitle,
		Announcement:            all["announcement"],
		PercentageOnly:          parseBool("public_percentage_only", false),
		AdminSubToken:           all["admin_sub_token"],
		AlertCooldownMinutes:    parseInt("alert_cooldown_minutes", 15),
		WarningThresholdPercent: parseInt("warning_threshold_percent", 85),
		OfflineTimeoutSeconds:   parseInt("offline_timeout_seconds", 60),
		DefaultUpstreamDNS:      upstreamDNS,
		DefaultLocalDNSPort:     parseInt("default_local_dns_port", 15353),
		AgentDockerImage:        agentDockerImage,
		TrafficLogMaxEntries:    logMaxEntries,
		AlertUserExpired:        parseBool("alert_user_expired", true),
		AlertUserQuotaExhausted: parseBool("alert_user_quota_exhausted", true),
	}
}

func parseFlexibleBool(raw json.RawMessage) (bool, error) {
	trimmed := strings.TrimSpace(string(raw))
	var b bool
	if err := json.Unmarshal([]byte(trimmed), &b); err == nil {
		return b, nil
	}
	var s string
	if err := json.Unmarshal([]byte(trimmed), &s); err == nil {
		return strconv.ParseBool(strings.TrimSpace(s))
	}
	return false, errors.New("expected boolean")
}

func parseFlexibleInt(raw json.RawMessage) (int, error) {
	trimmed := strings.TrimSpace(string(raw))
	var n int
	if err := json.Unmarshal([]byte(trimmed), &n); err == nil {
		return n, nil
	}
	var s string
	if err := json.Unmarshal([]byte(trimmed), &s); err == nil {
		return strconv.Atoi(strings.TrimSpace(s))
	}
	return 0, errors.New("expected integer")
}

func parseFlexibleString(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", errors.New("expected string")
	}
	return s, nil
}

func (s *server) handleGetSettings(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	all, err := s.store.GetAllSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load settings")
		return
	}
	writeJSON(w, http.StatusOK, buildSafeSettingsDTO(all))
}

func (s *server) handleUpdateSettings(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	var payload map[string]json.RawMessage
	if err := decodeJSON(r, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	if payload == nil {
		writeError(w, http.StatusBadRequest, "settings payload cannot be null")
		return
	}

	existing, err := s.store.GetAllSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load settings")
		return
	}

	updates := make(map[string]string)
	dnsChanged := false
	publicChanged := false
	logLimitChanged := false
	newLogLimit := 0

	for key, rawVal := range payload {
		switch key {
		case "site_title":
			v, err := parseFlexibleString(rawVal)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid site_title")
				return
			}
			if v != existing["site_title"] {
				publicChanged = true
			}
			updates["site_title"] = v
		case "announcement":
			v, err := parseFlexibleString(rawVal)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid announcement")
				return
			}
			if v != existing["announcement"] {
				publicChanged = true
			}
			updates["announcement"] = v
		case "percentage_only", "public_percentage_only":
			v, err := parseFlexibleBool(rawVal)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid percentage_only")
				return
			}
			sVal := strconv.FormatBool(v)
			if sVal != existing["public_percentage_only"] {
				publicChanged = true
			}
			updates["public_percentage_only"] = sVal
		case "admin_sub_token":
			v, err := parseFlexibleString(rawVal)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid admin_sub_token")
				return
			}
			v = strings.TrimSpace(v)
			if v == "" || strings.ContainsAny(v, " \t\r\n\x00") {
				writeError(w, http.StatusBadRequest, "admin_sub_token cannot be empty or contain whitespace")
				return
			}
			updates["admin_sub_token"] = v
		case "alert_cooldown_minutes", "alert_cooldown_mins":
			v, err := parseFlexibleInt(rawVal)
			if err != nil || v < 0 {
				writeError(w, http.StatusBadRequest, "alert_cooldown_minutes must be >= 0")
				return
			}
			updates["alert_cooldown_minutes"] = strconv.Itoa(v)
		case "warning_threshold_percent":
			v, err := parseFlexibleInt(rawVal)
			if err != nil || v < 0 || v > 100 {
				writeError(w, http.StatusBadRequest, "warning_threshold_percent must be between 0 and 100")
				return
			}
			updates["warning_threshold_percent"] = strconv.Itoa(v)
		case "offline_timeout_seconds":
			v, err := parseFlexibleInt(rawVal)
			if err != nil || v < 1 {
				writeError(w, http.StatusBadRequest, "offline_timeout_seconds must be >= 1")
				return
			}
			updates["offline_timeout_seconds"] = strconv.Itoa(v)
		case "default_upstream_dns":
			v, err := parseFlexibleString(rawVal)
			if err != nil || strings.TrimSpace(v) == "" {
				writeError(w, http.StatusBadRequest, "default_upstream_dns cannot be empty")
				return
			}
			v = strings.TrimSpace(v)
			if v != existing["default_upstream_dns"] {
				dnsChanged = true
			}
			updates["default_upstream_dns"] = v
		case "default_local_dns_port":
			v, err := parseFlexibleInt(rawVal)
			if err != nil || v < 1 || v > 65535 {
				writeError(w, http.StatusBadRequest, "default_local_dns_port must be between 1 and 65535")
				return
			}
			sVal := strconv.Itoa(v)
			if sVal != existing["default_local_dns_port"] {
				dnsChanged = true
			}
			updates["default_local_dns_port"] = sVal
		case "agent_docker_image":
			v, err := parseFlexibleString(rawVal)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid agent_docker_image")
				return
			}
			v = strings.TrimSpace(v)
			if v == "" || len(v) > 255 || strings.ContainsAny(v, " \t\r\n\x00'\"`;|&$<>\\") {
				writeError(w, http.StatusBadRequest, "agent_docker_image must be a valid non-empty image reference without whitespace or shell characters")
				return
			}
			updates["agent_docker_image"] = v
		case "traffic_log_max_entries":
			v, err := parseFlexibleInt(rawVal)
			if err != nil || v < store.MinTrafficLogMaxEntries || v > store.MaxTrafficLogMaxEntries {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("traffic_log_max_entries must be between %d and %d", store.MinTrafficLogMaxEntries, store.MaxTrafficLogMaxEntries))
				return
			}
			updates["traffic_log_max_entries"] = strconv.Itoa(v)
			logLimitChanged = true
			newLogLimit = v
		case "alert_user_expired":
			v, err := parseFlexibleBool(rawVal)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid alert_user_expired")
				return
			}
			updates["alert_user_expired"] = strconv.FormatBool(v)
		case "alert_user_quota_exhausted":
			v, err := parseFlexibleBool(rawVal)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid alert_user_quota_exhausted")
				return
			}
			updates["alert_user_quota_exhausted"] = strconv.FormatBool(v)
		default:
			writeError(w, http.StatusBadRequest, fmt.Sprintf("setting key %q is not writable", key))
			return
		}
	}

	if len(updates) > 0 {
		if err := s.store.SetSettingsBatch(r.Context(), updates); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update settings")
			return
		}
	}

	if logLimitChanged {
		if _, err := s.store.PruneTrafficUsageLogs(r.Context(), newLogLimit); err != nil {
			s.logger.Warn("prune traffic usage logs after settings update failed", "max_entries", newLogLimit, "err", err)
		}
	}

	if dnsChanged {
		nodes, err := s.store.ListNodes(r.Context())
		if err == nil && len(nodes) > 0 {
			ids := make([]int64, 0, len(nodes))
			for _, n := range nodes {
				ids = append(ids, n.ID)
			}
			if err := s.store.BumpNodesConfigRevision(r.Context(), ids); err != nil {
				s.logger.Warn("bump nodes revision after dns settings update failed", "err", err)
			}
		}
		if err := s.hub.SyncAll(r.Context()); err != nil && !errors.Is(err, hub.ErrHubClosed) {
			s.logger.Warn("sync all nodes after dns settings update failed", "err", err)
		}
	}
	if publicChanged {
		s.hub.BroadcastPublicStatus()
	}

	latest, err := s.store.GetAllSettings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to reload settings")
		return
	}
	writeJSON(w, http.StatusOK, buildSafeSettingsDTO(latest))
}
