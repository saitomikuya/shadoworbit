package sub

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"snell-panel/internal/panel/store"
	"snell-panel/internal/protocol"
)

// RenderAdmin renders the admin-only Surge Snell + ShadowTLS v3 subscription.
func (r *Renderer) RenderAdmin(ctx context.Context, token string, opts AdminRenderOptions) (*RenderResult, error) {
	if r == nil || r.store == nil {
		return nil, fmt.Errorf("%w: renderer store is nil", ErrInvalidArgument)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if err := r.verifyAdminToken(ctx, token); err != nil {
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

	nodes, err := r.store.ListNodes(ctx)
	if err != nil {
		return nil, err
	}

	usedNames := make(map[string]int, len(nodes))
	proxyLines := make([]string, 0, len(nodes))
	proxyNames := make([]string, 0, len(nodes))

	for _, n := range nodes {
		if !n.Enabled || !n.SnellConfig.Enabled {
			continue
		}
		if n.IsTrafficPaused && n.ThresholdAction != protocol.ThresholdActionStopSSOnly {
			continue
		}

		host, ok := resolveEntryHost(n)
		if !ok {
			continue
		}

		port := n.CustomEntryPort
		if port <= 0 {
			port = n.SnellConfig.PublicPort
		}
		if port < 1 || port > 65535 {
			continue
		}

		var snellVer int
		switch n.SnellConfig.Version {
		case protocol.SnellVersionV4:
			snellVer = 4
		case protocol.SnellVersionV5:
			snellVer = 5
		default:
			continue
		}

		psk := n.SnellConfig.PSK
		stlsPwd := n.SnellConfig.STLSPassword
		if psk == "" || stlsPwd == "" ||
			hasControlChars(psk) || strings.Contains(psk, ",") ||
			hasControlChars(stlsPwd) || strings.Contains(stlsPwd, ",") {
			continue
		}

		sni, ok := normalizeSNIHost(n.SnellConfig.STLSSNI)
		if !ok {
			continue
		}

		obfs := strings.ToLower(strings.TrimSpace(n.SnellConfig.Obfs))
		switch obfs {
		case "", protocol.SnellObfsOff, protocol.SnellObfsHTTP, protocol.SnellObfsTLS:
		default:
			continue
		}

		name := dedupName(sanitizeSurgeName(n.Name, n.ID), usedNames)
		line := fmt.Sprintf(
			"%s = snell, %s, %d, psk=%s, version=%d, reuse=true, tfo=%t, shadow-tls-password=%s, shadow-tls-sni=%s, shadow-tls-version=3",
			name, host, port, psk, snellVer, n.SnellConfig.TFO, stlsPwd, sni,
		)
		if obfs == protocol.SnellObfsHTTP || obfs == protocol.SnellObfsTLS {
			line += ", obfs=" + obfs
		}

		proxyLines = append(proxyLines, line)
		proxyNames = append(proxyNames, name)
	}

	headers := make(http.Header)
	headers.Set("Profile-Update-Interval", DefaultProfileUpdateInterval)

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

	tpl, err := resolveTemplate(ctx, r.store, opts.TemplateID, protocol.ClientTypeSurgeAdmin)
	if err != nil {
		return nil, err
	}

	updateURL := baseURL + "/s/admin/" + token
	if opts.TemplateID > 0 {
		updateURL += fmt.Sprintf("?tpl=%d", opts.TemplateID)
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

func (r *Renderer) verifyAdminToken(ctx context.Context, token string) error {
	if token == "" || hasControlChars(token) {
		return ErrUnauthorized
	}
	expected, err := r.store.GetSetting(ctx, "admin_sub_token")
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrUnauthorized
		}
		return err
	}
	if strings.TrimSpace(expected) == "" {
		return ErrUnauthorized
	}

	sumToken := sha256.Sum256([]byte(token))
	sumExpected := sha256.Sum256([]byte(expected))
	if subtle.ConstantTimeCompare(sumToken[:], sumExpected[:]) != 1 {
		return ErrUnauthorized
	}
	return nil
}
