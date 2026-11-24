package sub

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"snell-panel/internal/panel/store"
	"snell-panel/internal/protocol"
)

func hasControlChars(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b == 0x7f {
			return true
		}
	}
	return false
}

func stripControlChars(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

func validateMode(raw string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(raw))
	if mode == "" {
		return ModeFull, nil
	}
	if mode != ModeFull && mode != ModeProxy {
		return "", fmt.Errorf("%w: %q", ErrInvalidMode, raw)
	}
	return mode, nil
}

func validateBaseURL(raw string) (string, error) {
	if strings.ContainsAny(raw, "\r\n\x00") {
		return "", fmt.Errorf("%w: control characters in base URL", ErrInvalidBaseURL)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	if hasControlChars(trimmed) || strings.ContainsAny(trimmed, " \t") {
		return "", fmt.Errorf("%w: whitespace or control characters in base URL", ErrInvalidBaseURL)
	}
	trimmed = strings.TrimRight(trimmed, "/")
	if trimmed == "" {
		return "", nil
	}
	if strings.ContainsAny(trimmed, "?#") {
		return "", fmt.Errorf("%w: query or fragment not allowed in base URL", ErrInvalidBaseURL)
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidBaseURL, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("%w: must be an http/https URL with host and without userinfo/query/fragment", ErrInvalidBaseURL)
	}
	return trimmed, nil
}

func resolveTarget(explicitTarget, userAgent string) (string, error) {
	target := strings.ToLower(strings.TrimSpace(explicitTarget))
	if target != "" {
		switch target {
		case protocol.SubTargetMihomo, protocol.SubTargetSurge, protocol.SubTargetShadowrocket:
			return target, nil
		default:
			return "", fmt.Errorf("%w: %q", ErrInvalidTarget, explicitTarget)
		}
	}

	ua := strings.ToLower(userAgent)
	switch {
	case strings.Contains(ua, "shadowrocket"):
		return protocol.SubTargetShadowrocket, nil
	case strings.Contains(ua, "surge"):
		return protocol.SubTargetSurge, nil
	default:
		return protocol.SubTargetMihomo, nil
	}
}

func resolveEntryHost(n store.Node) (string, bool) {
	candidates := []string{n.CustomEntryHost, n.PublicIP, n.PublicIPv6}
	for _, cand := range candidates {
		h := strings.TrimSpace(cand)
		if h == "" {
			continue
		}
		if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") && len(h) >= 2 {
			h = h[1 : len(h)-1]
		}
		if h == "" || hasControlChars(h) || strings.IndexFunc(h, unicode.IsSpace) != -1 || strings.ContainsAny(h, ",=#;[]/?@\\") {
			return "", false
		}
		if strings.Contains(h, ":") && net.ParseIP(h) == nil {
			return "", false
		}
		return h, true
	}
	return "", false
}

func normalizeSNIHost(raw string) (string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || hasControlChars(trimmed) || strings.IndexFunc(trimmed, unicode.IsSpace) != -1 {
		return "", false
	}

	if h, pStr, err := net.SplitHostPort(trimmed); err == nil {
		h = strings.TrimSpace(h)
		if h == "" || hasControlChars(h) || strings.IndexFunc(h, unicode.IsSpace) != -1 || strings.ContainsAny(h, ",=#;[]/?@\\") {
			return "", false
		}
		if strings.Contains(h, ":") && net.ParseIP(h) == nil {
			return "", false
		}
		p, pErr := strconv.Atoi(pStr)
		if pErr != nil || p < 1 || p > 65535 {
			return "", false
		}
		return h, true
	} else if !strings.Contains(err.Error(), "missing port in address") {
		return "", false
	}

	h := trimmed
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") && len(h) >= 2 {
		h = h[1 : len(h)-1]
	}
	if h == "" || hasControlChars(h) || strings.IndexFunc(h, unicode.IsSpace) != -1 || strings.ContainsAny(h, ",=#;[]/?@\\") {
		return "", false
	}
	if strings.Contains(h, ":") && net.ParseIP(h) == nil {
		return "", false
	}
	return h, true
}

func sanitizeSurgeName(raw string, nodeID int64) string {
	s := stripControlChars(raw)
	s = strings.ReplaceAll(s, ",", "-")
	s = strings.ReplaceAll(s, "=", "-")
	s = strings.TrimSpace(s)
	s = strings.TrimLeft(s, "#;[ \t")
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Sprintf("Node-%d", nodeID)
	}
	return s
}

func sanitizePlainName(raw string, nodeID int64) string {
	s := strings.TrimSpace(stripControlChars(raw))
	if s == "" {
		return fmt.Sprintf("Node-%d", nodeID)
	}
	return s
}

func dedupName(candidate string, used map[string]int) string {
	if _, exists := used[candidate]; !exists {
		used[candidate] = 1
		return candidate
	}
	n := used[candidate] + 1
	for {
		next := fmt.Sprintf("%s (%d)", candidate, n)
		if _, exists := used[next]; !exists {
			used[candidate] = n
			used[next] = 1
			return next
		}
		n++
	}
}

func resolveTemplate(ctx context.Context, st subStore, templateID int64, expectedClientType string) (*store.SubTemplate, error) {
	if templateID < 0 {
		return nil, fmt.Errorf("%w: template_id must be non-negative", ErrInvalidArgument)
	}
	if templateID > 0 {
		tpl, err := st.GetSubTemplateByID(ctx, templateID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, fmt.Errorf("%w: id=%d", ErrTemplateNotFound, templateID)
			}
			return nil, err
		}
		if tpl.ClientType != expectedClientType {
			return nil, fmt.Errorf("%w: expected %q, got %q", ErrTemplateMismatch, expectedClientType, tpl.ClientType)
		}
		return tpl, nil
	}

	tpl, err := st.GetDefaultSubTemplate(ctx, expectedClientType)
	if err == nil {
		return tpl, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	list, listErr := st.ListSubTemplates(ctx, expectedClientType)
	if listErr != nil {
		return nil, listErr
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("%w: client_type=%s", ErrTemplateNotFound, expectedClientType)
	}
	return &list[0], nil
}

func renderSurgeFull(tplContent, managedLine string, proxyLines, proxyNames []string) string {
	out := strings.ReplaceAll(tplContent, "\r\n", "\n")
	out = strings.ReplaceAll(out, "\r", "\n")
	out = strings.ReplaceAll(out, "{{MANAGED_CONFIG_HEADER}}", managedLine)

	if len(proxyLines) == 0 {
		out = removeStandalonePlaceholderLine(out, "{{PROXIES}}")
		out = strings.ReplaceAll(out, "{{PROXIES}}", "")
		out = strings.ReplaceAll(out, "{{PROXY_NAMES}}", "DIRECT")
		out = collapseSurgeDirectDuplicates(out)
	} else {
		out = strings.ReplaceAll(out, "{{PROXIES}}", strings.Join(proxyLines, "\n"))
		out = strings.ReplaceAll(out, "{{PROXY_NAMES}}", strings.Join(proxyNames, ", "))
	}

	out = ensureManagedConfigLine1(out, managedLine)
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return out
}

func removeStandalonePlaceholderLine(content, placeholder string) string {
	lines := strings.Split(content, "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == placeholder {
			continue
		}
		filtered = append(filtered, line)
	}
	return strings.Join(filtered, "\n")
}

func collapseSurgeDirectDuplicates(content string) string {
	for strings.Contains(content, ", DIRECT, DIRECT") {
		content = strings.ReplaceAll(content, ", DIRECT, DIRECT", ", DIRECT")
	}
	return content
}

func ensureManagedConfigLine1(content, managedLine string) string {
	normalized := strings.ReplaceAll(content, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	lines := strings.Split(normalized, "\n")

	start := 0
	for start < len(lines) && strings.TrimSpace(lines[start]) == "" {
		start++
	}
	lines = lines[start:]
	if len(lines) == 0 {
		return managedLine + "\n"
	}

	out := make([]string, 0, len(lines)+1)
	out = append(out, managedLine)
	bodyStart := 0
	if strings.HasPrefix(strings.TrimSpace(lines[0]), "#!MANAGED-CONFIG") {
		bodyStart = 1
	}
	for i := bodyStart; i < len(lines); i++ {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "#!MANAGED-CONFIG") {
			continue
		}
		out = append(out, lines[i])
	}
	return strings.Join(out, "\n")
}

func buildUserHeaders(user *store.User) http.Header {
	var expireUnix int64
	if user.ExpireAt != nil {
		expireUnix = user.ExpireAt.UTC().Unix()
	}
	h := make(http.Header)
	h.Set("Subscription-Userinfo", fmt.Sprintf(
		"upload=%d; download=%d; total=%d; expire=%d",
		user.UsedUpBytes, user.UsedDownBytes, user.TrafficQuotaBytes, expireUnix,
	))
	h.Set("Profile-Update-Interval", DefaultProfileUpdateInterval)
	return h
}
