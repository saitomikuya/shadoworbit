package sub

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"snell-panel/internal/panel/store"
	"snell-panel/internal/protocol"
)

type adminProxyCandidate struct {
	sortOrder int
	isGroup   bool
	id        int64
	rawName   string
	host      string
	port      int
	snellVer  int
	tfo       bool
	psk       string
	stlsPwd   string
	sni       string
	obfs      string
}

func buildAdminSnellCandidate(
	id int64,
	sortOrder int,
	isGroup bool,
	rawName string,
	host string,
	port int,
	cfg protocol.SnellConfig,
) (adminProxyCandidate, bool) {
	if !cfg.Enabled || port < 1 || port > 65535 {
		return adminProxyCandidate{}, false
	}

	var snellVer int
	switch cfg.Version {
	case protocol.SnellVersionV4:
		snellVer = 4
	case protocol.SnellVersionV5:
		snellVer = 5
	default:
		return adminProxyCandidate{}, false
	}

	psk := cfg.PSK
	stlsPwd := cfg.STLSPassword
	if psk == "" || stlsPwd == "" ||
		hasControlChars(psk) || strings.Contains(psk, ",") ||
		hasControlChars(stlsPwd) || strings.Contains(stlsPwd, ",") {
		return adminProxyCandidate{}, false
	}

	sni, ok := normalizeSNIHost(cfg.STLSSNI)
	if !ok {
		return adminProxyCandidate{}, false
	}

	obfs := strings.ToLower(strings.TrimSpace(cfg.Obfs))
	switch obfs {
	case "", protocol.SnellObfsOff, protocol.SnellObfsHTTP, protocol.SnellObfsTLS:
	default:
		return adminProxyCandidate{}, false
	}

	return adminProxyCandidate{
		sortOrder: sortOrder,
		isGroup:   isGroup,
		id:        id,
		rawName:   rawName,
		host:      host,
		port:      port,
		snellVer:  snellVer,
		tfo:       cfg.TFO,
		psk:       psk,
		stlsPwd:   stlsPwd,
		sni:       sni,
		obfs:      obfs,
	}, true
}

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
	lbGroups, err := r.store.ListLBGroups(ctx)
	if err != nil {
		return nil, err
	}

	nodeByID := make(map[int64]store.Node, len(nodes))
	for _, n := range nodes {
		nodeByID[n.ID] = n
	}

	hiddenNodeIDs := make(map[int64]bool)
	for _, g := range lbGroups {
		if !g.Enabled {
			continue
		}
		for _, m := range g.Members {
			hiddenNodeIDs[m.NodeID] = true
		}
	}

	candidates := make([]adminProxyCandidate, 0, len(nodes)+len(lbGroups))
	for _, n := range nodes {
		if hiddenNodeIDs[n.ID] {
			continue
		}
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

		cand, ok := buildAdminSnellCandidate(n.ID, n.SortOrder, false, n.Name, host, port, n.SnellConfig)
		if !ok {
			continue
		}
		candidates = append(candidates, cand)
	}

	for _, g := range lbGroups {
		if !g.Enabled || !g.SnellConfig.Enabled || strings.TrimSpace(g.DNSDomain) == "" {
			continue
		}
		hasAvailableMember := false
		for _, m := range g.Members {
			n, exists := nodeByID[m.NodeID]
			if !exists || !n.Enabled {
				continue
			}
			if n.IsTrafficPaused && n.ThresholdAction != protocol.ThresholdActionStopSSOnly {
				continue
			}
			hasAvailableMember = true
			break
		}
		if !hasAvailableMember {
			continue
		}

		host, ok := resolveEntryHost(store.Node{CustomEntryHost: g.DNSDomain})
		if !ok {
			continue
		}
		cand, ok := buildAdminSnellCandidate(g.ID, g.SortOrder, true, g.Name, host, g.SnellConfig.PublicPort, g.SnellConfig)
		if !ok {
			continue
		}
		candidates = append(candidates, cand)
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].sortOrder != candidates[j].sortOrder {
			return candidates[i].sortOrder < candidates[j].sortOrder
		}
		if candidates[i].isGroup != candidates[j].isGroup {
			return !candidates[i].isGroup
		}
		return candidates[i].id < candidates[j].id
	})

	usedNames := make(map[string]int, len(candidates))
	proxyLines := make([]string, 0, len(candidates))
	proxyNames := make([]string, 0, len(candidates))

	for _, c := range candidates {
		name := dedupName(sanitizeSurgeName(c.rawName, c.id), usedNames)
		line := fmt.Sprintf(
			"%s = snell, %s, %d, psk=%s, version=%d, reuse=true, tfo=%t, shadow-tls-password=%s, shadow-tls-sni=%s, shadow-tls-version=3",
			name, c.host, c.port, c.psk, c.snellVer, c.tfo, c.stlsPwd, c.sni,
		)
		if c.obfs == protocol.SnellObfsHTTP || c.obfs == protocol.SnellObfsTLS {
			line += ", obfs=" + c.obfs
		}

		proxyLines = append(proxyLines, line)
		proxyNames = append(proxyNames, name)
	}

	headers := make(http.Header)
	headers.Set("Profile-Update-Interval", DefaultProfileUpdateInterval)
	headers.Set("Content-Disposition", `attachment; filename="ShadowOrbit.conf"; filename*=UTF-8''ShadowOrbit.conf`)

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

	updateURL := baseURL + "/s/admin/" + token + "/ShadowOrbit.conf"
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
