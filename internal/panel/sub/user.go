package sub

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"snell-panel/internal/panel/auth"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/protocol"
)

type mihomoProxy struct {
	Name              string              `yaml:"name"`
	Type              string              `yaml:"type"`
	Server            string              `yaml:"server"`
	Port              int                 `yaml:"port"`
	Cipher            string              `yaml:"cipher"`
	Password          string              `yaml:"password"`
	UDP               bool                `yaml:"udp"`
	UDPOverTCP        bool                `yaml:"udp-over-tcp"`
	UDPOverTCPVersion int                 `yaml:"udp-over-tcp-version"`
	ClientFingerprint string              `yaml:"client-fingerprint"`
	Plugin            string              `yaml:"plugin"`
	PluginOpts        mihomoShadowTLSOpts `yaml:"plugin-opts"`
}

type mihomoShadowTLSOpts struct {
	Host     string `yaml:"host"`
	Password string `yaml:"password"`
	Version  int    `yaml:"version"`
}

type userNodeEntry struct {
	node    store.Node
	host    string
	tcpPort int
	udpPort int
	cipher  string
	iPSK    string
	uPSK    string
	stlsPwd string
	sni     string
}

// RenderUser renders a user subscription for Mihomo, Surge, or Shadowrocket.
// User subscriptions strictly output SS2022 + ShadowTLS v3 nodes and never reference Snell.
func (r *Renderer) RenderUser(ctx context.Context, token string, userAgent string, opts UserRenderOptions) (*RenderResult, error) {
	if r == nil || r.store == nil {
		return nil, fmt.Errorf("%w: renderer store is nil", ErrInvalidArgument)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if token == "" || hasControlChars(token) {
		return nil, ErrUnauthorized
	}

	user, err := r.store.GetUserBySubToken(ctx, token)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrUnauthorized
		}
		return nil, err
	}

	headers := buildUserHeaders(user)

	target, err := resolveTarget(opts.Target, userAgent)
	if err != nil {
		return nil, err
	}
	mode, err := validateMode(opts.Mode)
	if err != nil {
		return nil, err
	}
	baseURL, err := validateBaseURL(opts.BaseURL)
	if err != nil {
		return nil, err
	}

	now := r.now().UTC()
	if !user.Enabled {
		return &RenderResult{Headers: headers, Target: target}, ErrUserDisabled
	}
	if user.ExpireAt != nil && !user.ExpireAt.After(now) {
		return &RenderResult{Headers: headers, Target: target}, ErrUserExpired
	}
	if user.IsQuotaExhausted() {
		return &RenderResult{Headers: headers, Target: target}, ErrUserQuotaExhausted
	}

	if opts.TemplateID < 0 {
		return nil, fmt.Errorf("%w: template_id must be non-negative", ErrInvalidArgument)
	}
	if target == protocol.SubTargetShadowrocket && opts.TemplateID > 0 {
		return nil, fmt.Errorf("%w: shadowrocket target does not support templates", ErrTemplateMismatch)
	}

	nodes, err := r.store.ListAuthorizedNodesForUser(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	entries := filterUserNodes(nodes, user)

	switch target {
	case protocol.SubTargetMihomo:
		return r.renderUserMihomo(ctx, entries, mode, opts.TemplateID, headers)
	case protocol.SubTargetSurge:
		return r.renderUserSurge(ctx, token, entries, mode, opts.TemplateID, baseURL, headers)
	case protocol.SubTargetShadowrocket:
		return renderUserShadowrocket(entries, headers)
	default:
		return nil, fmt.Errorf("%w: %q", ErrInvalidTarget, target)
	}
}

func filterUserNodes(nodes []store.Node, user *store.User) []userNodeEntry {
	out := make([]userNodeEntry, 0, len(nodes))
	if user.STLSPassword == "" || hasControlChars(user.STLSPassword) {
		return out
	}

	for _, n := range nodes {
		if !n.Enabled || n.IsTrafficPaused || !n.SSConfig.Enabled {
			continue
		}

		var uPSK string
		switch n.SSConfig.Cipher {
		case protocol.CipherAES128GCM:
			uPSK = user.SSUPSK16
		case protocol.CipherAES256GCM:
			uPSK = user.SSUPSK32
		default:
			continue
		}

		if err := auth.ValidateSS2022Key(n.SSConfig.IPSK, n.SSConfig.Cipher); err != nil {
			continue
		}
		if err := auth.ValidateSS2022Key(uPSK, n.SSConfig.Cipher); err != nil {
			continue
		}

		sni, ok := normalizeSNIHost(n.SSConfig.STLSSNI)
		if !ok {
			continue
		}

		host, ok := resolveEntryHost(n)
		if !ok {
			continue
		}

		tcpPort := n.CustomEntryPort
		if tcpPort <= 0 {
			tcpPort = n.SSConfig.TCPPort
		}
		if tcpPort < 1 || tcpPort > 65535 {
			continue
		}

		udpPort := n.SSConfig.UDPPort
		if udpPort <= 0 || (n.CustomEntryPort > 0 && n.SSConfig.UDPPort == n.SSConfig.TCPPort) {
			udpPort = tcpPort
		}
		if udpPort < 1 || udpPort > 65535 {
			continue
		}

		out = append(out, userNodeEntry{
			node:    n,
			host:    host,
			tcpPort: tcpPort,
			udpPort: udpPort,
			cipher:  n.SSConfig.Cipher,
			iPSK:    n.SSConfig.IPSK,
			uPSK:    uPSK,
			stlsPwd: user.STLSPassword,
			sni:     sni,
		})
	}
	return out
}

func (r *Renderer) renderUserMihomo(ctx context.Context, entries []userNodeEntry, mode string, templateID int64, headers map[string][]string) (*RenderResult, error) {
	usedNames := make(map[string]int, len(entries))
	proxies := make([]mihomoProxy, 0, len(entries))
	proxyNames := make([]string, 0, len(entries))

	for _, e := range entries {
		name := dedupName(sanitizePlainName(e.node.Name, e.node.ID), usedNames)
		proxies = append(proxies, mihomoProxy{
			Name:              name,
			Type:              "ss",
			Server:            e.host,
			Port:              e.tcpPort,
			Cipher:            e.cipher,
			Password:          e.iPSK + ":" + e.uPSK,
			UDP:               true,
			UDPOverTCP:        true,
			UDPOverTCPVersion: 2,
			ClientFingerprint: "chrome",
			Plugin:            "shadow-tls",
			PluginOpts: mihomoShadowTLSOpts{
				Host:     e.sni,
				Password: e.stlsPwd,
				Version:  3,
			},
		})
		proxyNames = append(proxyNames, name)
	}

	if mode == ModeProxy {
		payload := struct {
			Proxies []mihomoProxy `yaml:"proxies"`
		}{
			Proxies: proxies,
		}
		raw, err := yaml.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("sub: marshal mihomo proxies: %w", err)
		}
		return &RenderResult{
			Body:        string(raw),
			ContentType: "text/yaml; charset=utf-8",
			Headers:     headers,
			Target:      protocol.SubTargetMihomo,
			NodeCount:   len(proxies),
		}, nil
	}

	tpl, err := resolveTemplate(ctx, r.store, templateID, protocol.ClientTypeMihomoUser)
	if err != nil {
		return nil, err
	}

	body, err := renderMihomoFull(tpl.Content, proxies, proxyNames)
	if err != nil {
		return nil, err
	}

	return &RenderResult{
		Body:        body,
		ContentType: "text/yaml; charset=utf-8",
		Headers:     headers,
		Target:      protocol.SubTargetMihomo,
		NodeCount:   len(proxies),
	}, nil
}

func renderMihomoFull(tplContent string, proxies []mihomoProxy, proxyNames []string) (string, error) {
	normalized := strings.ReplaceAll(tplContent, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	tplLines := strings.Split(normalized, "\n")

	var proxiesBlock string
	if len(proxies) > 0 {
		raw, err := yaml.Marshal(proxies)
		if err != nil {
			return "", fmt.Errorf("sub: marshal mihomo proxies: %w", err)
		}
		proxiesBlock = strings.TrimRight(string(raw), "\n")
	}

	outLines := make([]string, 0, len(tplLines))
	for i := 0; i < len(tplLines); i++ {
		line := tplLines[i]
		trimmed := strings.TrimSpace(line)

		if len(proxies) == 0 && trimmed == "proxies:" && i+1 < len(tplLines) && strings.TrimSpace(tplLines[i+1]) == "{{PROXIES}}" {
			ws := leadingWhitespace(line)
			outLines = append(outLines, ws+"proxies: []")
			i++
			continue
		}

		if strings.Contains(line, "{{PROXIES}}") {
			if len(proxies) == 0 {
				indent := leadingWhitespace(line)
				if indent == "" {
					indent = "  "
				}
				outLines = append(outLines, indent+"[]")
			} else if trimmed == "{{PROXIES}}" {
				indent := leadingWhitespace(line)
				if indent == "" {
					indent = "  "
				}
				for _, pl := range strings.Split(proxiesBlock, "\n") {
					if pl == "" {
						outLines = append(outLines, "")
					} else {
						outLines = append(outLines, indent+pl)
					}
				}
			} else {
				outLines = append(outLines, strings.ReplaceAll(line, "{{PROXIES}}", proxiesBlock))
			}
			continue
		}

		if strings.Contains(line, "{{PROXY_NAMES_YAML}}") {
			indent := resolveProxyNamesYAMLIndent(tplLines, i, leadingWhitespace(line))
			if len(proxyNames) == 0 {
				outLines = append(outLines, indent+"- DIRECT")
			} else {
				for _, name := range proxyNames {
					itemBytes, err := yaml.Marshal([]string{name})
					if err != nil {
						return "", fmt.Errorf("sub: marshal mihomo proxy name %q: %w", name, err)
					}
					item := strings.TrimRight(string(itemBytes), "\n")
					outLines = append(outLines, indent+item)
				}
			}
			continue
		}

		outLines = append(outLines, line)
	}

	if len(proxyNames) == 0 {
		outLines = collapseConsecutiveYAMLDirect(outLines)
	}

	rendered := strings.Join(outLines, "\n")
	if len(proxyNames) == 0 {
		rendered = strings.ReplaceAll(rendered, "{{PROXY_NAMES}}", "DIRECT")
	} else {
		quotedNames := make([]string, 0, len(proxyNames))
		for _, name := range proxyNames {
			quoted, err := encodeSingleLineYAMLScalar(name)
			if err != nil {
				return "", fmt.Errorf("sub: marshal mihomo proxy name %q: %w", name, err)
			}
			quotedNames = append(quotedNames, quoted)
		}
		rendered = strings.ReplaceAll(rendered, "{{PROXY_NAMES}}", strings.Join(quotedNames, ", "))
	}
	if rendered != "" && !strings.HasSuffix(rendered, "\n") {
		rendered += "\n"
	}

	var doc any
	if err := yaml.Unmarshal([]byte(rendered), &doc); err != nil {
		return "", fmt.Errorf("%w: invalid rendered mihomo YAML: %v", ErrInvalidArgument, err)
	}
	var typedDoc struct {
		Proxies     []mihomoProxy `yaml:"proxies"`
		ProxyGroups []struct {
			Name    string   `yaml:"name"`
			Type    string   `yaml:"type"`
			Proxies []string `yaml:"proxies"`
		} `yaml:"proxy-groups"`
	}
	if err := yaml.Unmarshal([]byte(rendered), &typedDoc); err != nil {
		return "", fmt.Errorf("%w: invalid rendered mihomo structure: %v", ErrInvalidArgument, err)
	}
	return rendered, nil
}

func encodeSingleLineYAMLScalar(s string) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

func leadingWhitespace(s string) string {
	trimmed := strings.TrimLeft(s, " \t")
	return s[:len(s)-len(trimmed)]
}

func isYAMLListItem(trimmed string) bool {
	return strings.HasPrefix(trimmed, "- ") || trimmed == "-"
}

func isYAMLKeyLine(trimmed string) bool {
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || isYAMLListItem(trimmed) {
		return false
	}
	return strings.HasSuffix(trimmed, ":") || strings.Contains(trimmed, ": ")
}

func resolveProxyNamesYAMLIndent(lines []string, idx int, lineIndent string) string {
	parentIndent := ""
	hasParent := false
	minListIndent := -1
	for j := idx - 1; j >= 0; j-- {
		t := strings.TrimSpace(lines[j])
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		ind := leadingWhitespace(lines[j])
		if isYAMLKeyLine(t) {
			if minListIndent == -1 || len(ind) <= minListIndent {
				parentIndent = ind
				hasParent = true
				break
			}
			continue
		}
		if minListIndent == -1 || len(ind) < minListIndent {
			minListIndent = len(ind)
		}
	}

	for j := idx + 1; j < len(lines); j++ {
		t := strings.TrimSpace(lines[j])
		if t == "" {
			break
		}
		if strings.HasPrefix(t, "#") {
			continue
		}
		ind := leadingWhitespace(lines[j])
		if hasParent && len(ind) < len(parentIndent) {
			break
		}
		if isYAMLListItem(t) {
			return ind
		}
		break
	}

	for j := idx - 1; j >= 0; j-- {
		t := strings.TrimSpace(lines[j])
		if t == "" {
			break
		}
		if strings.HasPrefix(t, "#") {
			continue
		}
		ind := leadingWhitespace(lines[j])
		if hasParent && len(ind) < len(parentIndent) {
			break
		}
		if isYAMLListItem(t) {
			return ind
		}
		break
	}

	if hasParent {
		return parentIndent + "  "
	}
	if lineIndent != "" {
		return lineIndent
	}
	return "      "
}

func collapseConsecutiveYAMLDirect(lines []string) []string {
	out := make([]string, 0, len(lines))
	prevDirect := false
	for _, line := range lines {
		isDirect := strings.TrimSpace(line) == "- DIRECT"
		if isDirect && prevDirect {
			continue
		}
		out = append(out, line)
		prevDirect = isDirect
	}
	return out
}

func (r *Renderer) renderUserSurge(ctx context.Context, token string, entries []userNodeEntry, mode string, templateID int64, baseURL string, headers map[string][]string) (*RenderResult, error) {
	usedNames := make(map[string]int, len(entries))
	proxyLines := make([]string, 0, len(entries))
	proxyNames := make([]string, 0, len(entries))

	for _, e := range entries {
		if strings.Contains(e.iPSK, ",") || strings.Contains(e.uPSK, ",") || strings.Contains(e.stlsPwd, ",") {
			continue
		}
		name := dedupName(sanitizeSurgeName(e.node.Name, e.node.ID), usedNames)
		line := fmt.Sprintf(
			"%s = ss, %s, %d, encrypt-method=%s, password=%s:%s, shadow-tls-password=%s, shadow-tls-sni=%s, shadow-tls-version=3, udp-relay=true, udp-port=%d, tfo=true",
			name, e.host, e.tcpPort, e.cipher, e.iPSK, e.uPSK, e.stlsPwd, e.sni, e.udpPort,
		)
		proxyLines = append(proxyLines, line)
		proxyNames = append(proxyNames, name)
	}

	if mode == ModeProxy {
		body := strings.Join(proxyLines, "\n")
		if len(proxyLines) > 0 {
			body += "\n"
		}
		return &RenderResult{
			Body:        body,
			ContentType: "text/plain; charset=utf-8",
			Headers:     headers,
			Target:      protocol.SubTargetSurge,
			NodeCount:   len(proxyLines),
		}, nil
	}

	tpl, err := resolveTemplate(ctx, r.store, templateID, protocol.ClientTypeSurgeUser)
	if err != nil {
		return nil, err
	}

	updateURL := baseURL + "/s/u/" + token + "?target=surge"
	if templateID > 0 {
		updateURL += fmt.Sprintf("&tpl=%d", templateID)
	}
	managedLine := fmt.Sprintf("#!MANAGED-CONFIG %s interval=%d strict=false", updateURL, DefaultManagedConfigInterval)
	body := renderSurgeFull(tpl.Content, managedLine, proxyLines, proxyNames)

	return &RenderResult{
		Body:        body,
		ContentType: "text/plain; charset=utf-8",
		Headers:     headers,
		Target:      protocol.SubTargetSurge,
		NodeCount:   len(proxyLines),
	}, nil
}

func renderUserShadowrocket(entries []userNodeEntry, headers map[string][]string) (*RenderResult, error) {
	usedNames := make(map[string]int, len(entries))
	uris := make([]string, 0, len(entries))

	for _, e := range entries {
		name := dedupName(sanitizePlainName(e.node.Name, e.node.ID), usedNames)
		userInfo := base64.RawURLEncoding.EncodeToString([]byte(e.cipher + ":" + e.iPSK + ":" + e.uPSK))

		stlsJSON, err := json.Marshal(struct {
			Version  string `json:"version"`
			Password string `json:"password"`
			Host     string `json:"host"`
		}{
			Version:  "3",
			Password: e.stlsPwd,
			Host:     e.sni,
		})
		if err != nil {
			return nil, fmt.Errorf("sub: marshal shadowrocket shadow-tls params: %w", err)
		}
		stlsB64 := base64.StdEncoding.EncodeToString(stlsJSON)

		uri := fmt.Sprintf(
			"ss://%s@%s?shadow-tls=%s&uot=1#%s",
			userInfo,
			net.JoinHostPort(e.host, strconv.Itoa(e.tcpPort)),
			url.QueryEscape(stlsB64),
			url.PathEscape(name),
		)
		uris = append(uris, uri)
	}

	body := ""
	if len(uris) > 0 {
		body = base64.StdEncoding.EncodeToString([]byte(strings.Join(uris, "\n")))
	}

	return &RenderResult{
		Body:        body,
		ContentType: "text/plain; charset=utf-8",
		Headers:     headers,
		Target:      protocol.SubTargetShadowrocket,
		NodeCount:   len(uris),
	}, nil
}
