package hub

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"snell-panel/internal/panel/auth"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/protocol"
)

const (
	defaultUpstreamDNS  = "1.1.1.1:53"
	defaultLocalDNSPort = 15353
)

type syncBuildCache struct {
	upstreamDNS    string
	localDNSPort   int
	hasDNSSettings bool
	dnsGroups      map[int64][]string
}

func (h *Hub) newSyncBuildCache(ctx context.Context) (*syncBuildCache, error) {
	upstreamDNS, err := h.store.GetSettingOrDefault(ctx, "default_upstream_dns", defaultUpstreamDNS)
	if err != nil {
		return nil, err
	}
	upstreamDNS = strings.TrimSpace(upstreamDNS)
	if upstreamDNS == "" {
		upstreamDNS = defaultUpstreamDNS
	}

	localPortStr, err := h.store.GetSettingOrDefault(ctx, "default_local_dns_port", strconv.Itoa(defaultLocalDNSPort))
	if err != nil {
		return nil, err
	}
	localPort := defaultLocalDNSPort
	if p, convErr := strconv.Atoi(strings.TrimSpace(localPortStr)); convErr == nil && p > 0 && p <= 65535 {
		localPort = p
	}

	return &syncBuildCache{
		upstreamDNS:    upstreamDNS,
		localDNSPort:   localPort,
		hasDNSSettings: true,
		dnsGroups:      make(map[int64][]string),
	}, nil
}

// BuildConfigSync compiles the full desired ServerConfigSync payload for nodeID.
func (h *Hub) BuildConfigSync(ctx context.Context, nodeID int64) (protocol.ServerConfigSync, error) {
	return h.buildConfigSyncWithCache(ctx, nodeID, nil)
}

func (h *Hub) buildConfigSyncWithCache(ctx context.Context, nodeID int64, cache *syncBuildCache) (protocol.ServerConfigSync, error) {
	if h.store == nil {
		return protocol.ServerConfigSync{}, errors.New("hub: nil store")
	}
	if ctx == nil {
		ctx = h.baseCtx
	}

	node, err := h.store.GetNodeByID(ctx, nodeID)
	if err != nil {
		return protocol.ServerConfigSync{}, err
	}

	snell := node.SnellConfig
	ss := node.SSConfig

	if !node.Enabled {
		snell.Enabled = false
		ss.Enabled = false
	} else if node.IsTrafficPaused {
		switch node.ThresholdAction {
		case protocol.ThresholdActionStopSSOnly:
			ss.Enabled = false
		default:
			snell.Enabled = false
			ss.Enabled = false
		}
	}

	ss.Users = []protocol.SSUserEntry{}
	if ss.Enabled {
		users, err := h.store.ListAuthorizedUsersForNode(ctx, nodeID, h.now().UTC())
		if err != nil {
			return protocol.ServerConfigSync{}, err
		}
		for _, u := range users {
			var upsk string
			switch ss.Cipher {
			case protocol.CipherAES128GCM:
				upsk = u.SSUPSK16
			case protocol.CipherAES256GCM:
				upsk = u.SSUPSK32
			}
			if u.Username == "" || u.STLSPassword == "" || upsk == "" {
				continue
			}
			if err := auth.ValidateSS2022Key(upsk, ss.Cipher); err != nil {
				continue
			}
			ss.Users = append(ss.Users, protocol.SSUserEntry{
				UserID:       u.ID,
				Username:     u.Username,
				UPSK:         upsk,
				STLSPassword: u.STLSPassword,
			})
		}
	}

	var groupRules []string
	if node.DNSRuleGroupID != nil && *node.DNSRuleGroupID > 0 {
		gid := *node.DNSRuleGroupID
		if cache != nil && cache.dnsGroups != nil {
			if cachedRules, ok := cache.dnsGroups[gid]; ok {
				groupRules = cachedRules
			} else {
				grp, err := h.store.GetDNSRuleGroupByID(ctx, gid)
				if err == nil {
					groupRules = grp.Rules
					cache.dnsGroups[gid] = grp.Rules
				} else if errors.Is(err, store.ErrNotFound) {
					cache.dnsGroups[gid] = nil
				} else {
					return protocol.ServerConfigSync{}, err
				}
			}
		} else {
			grp, err := h.store.GetDNSRuleGroupByID(ctx, gid)
			if err == nil {
				groupRules = grp.Rules
			} else if !errors.Is(err, store.ErrNotFound) {
				return protocol.ServerConfigSync{}, err
			}
		}
	}
	rules := mergeAndDedupDNSRules(groupRules, node.DNSExtraRules)

	var upstreamDNS string
	var localPort int
	if cache != nil && cache.hasDNSSettings {
		upstreamDNS = cache.upstreamDNS
		localPort = cache.localDNSPort
	} else {
		var err error
		upstreamDNS, err = h.store.GetSettingOrDefault(ctx, "default_upstream_dns", defaultUpstreamDNS)
		if err != nil {
			return protocol.ServerConfigSync{}, err
		}
		upstreamDNS = strings.TrimSpace(upstreamDNS)
		if upstreamDNS == "" {
			upstreamDNS = defaultUpstreamDNS
		}

		localPortStr, err := h.store.GetSettingOrDefault(ctx, "default_local_dns_port", strconv.Itoa(defaultLocalDNSPort))
		if err != nil {
			return protocol.ServerConfigSync{}, err
		}
		localPort = defaultLocalDNSPort
		if p, convErr := strconv.Atoi(strings.TrimSpace(localPortStr)); convErr == nil && p > 0 && p <= 65535 {
			localPort = p
		}
	}

	return protocol.ServerConfigSync{
		ConfigRevision: node.ConfigRevision,
		Snell:          snell,
		SS:             ss,
		DNS: protocol.DNSConfig{
			UnlockEnabled: node.DNSUnlockEnabled,
			UnlockServer:  node.DNSUnlockServer,
			Rules:         rules,
			UpstreamDNS:   upstreamDNS,
			LocalPort:     localPort,
		},
	}, nil
}

// SyncNode compiles and dispatches server.config_sync to an online node.
func (h *Hub) SyncNode(ctx context.Context, nodeID int64) error {
	return h.syncNodeWithCache(ctx, nodeID, nil)
}

func (h *Hub) syncNodeWithCache(ctx context.Context, nodeID int64, cache *syncBuildCache) error {
	if h.isClosed() {
		return ErrHubClosed
	}
	if ctx == nil {
		ctx = h.baseCtx
	}

	sess := h.getSession(nodeID)
	if sess == nil {
		if h.store != nil {
			if _, err := h.store.GetNodeByID(ctx, nodeID); err != nil {
				return err
			}
		}
		return ErrNodeOffline
	}

	for {
		sess.syncMu.Lock()
		if h.isClosed() {
			sess.syncMu.Unlock()
			return ErrHubClosed
		}
		cur := h.getSession(nodeID)
		if cur == nil {
			sess.syncMu.Unlock()
			return ErrNodeOffline
		}
		if cur.id != sess.id {
			sess.syncMu.Unlock()
			sess = cur
			continue
		}

		cfg, err := h.buildConfigSyncWithCache(ctx, nodeID, cache)
		if err != nil {
			sess.syncMu.Unlock()
			return err
		}

		frame, err := protocol.MarshalEnvelope(protocol.MsgTypeServerConfigSync, h.nextReqID(), cfg)
		if err != nil {
			sess.syncMu.Unlock()
			return err
		}
		if err := sess.enqueue(frame); err != nil {
			sess.syncMu.Unlock()
			return err
		}
		sess.lastSyncedRev = cfg.ConfigRevision
		sess.syncMu.Unlock()
		return nil
	}
}

// SyncNodesForUser pushes config_sync to every online node authorized for userID.
func (h *Hub) SyncNodesForUser(ctx context.Context, userID int64) error {
	if h.isClosed() {
		return ErrHubClosed
	}
	if h.store == nil {
		return errors.New("hub: nil store")
	}
	if ctx == nil {
		ctx = h.baseCtx
	}

	nodeIDs, err := h.store.GetUserNodeIDs(ctx, userID)
	if err != nil {
		return err
	}

	var cache *syncBuildCache
	for _, nid := range nodeIDs {
		if h.getSession(nid) == nil {
			continue
		}
		if cache == nil {
			cache, err = h.newSyncBuildCache(ctx)
			if err != nil {
				return err
			}
		}
		if err := h.syncNodeWithCache(ctx, nid, cache); err != nil && !errors.Is(err, ErrNodeOffline) {
			return err
		}
	}
	return nil
}

// SyncAll pushes config_sync to every online node in the system.
func (h *Hub) SyncAll(ctx context.Context) error {
	if h.isClosed() {
		return ErrHubClosed
	}
	if h.store == nil {
		return errors.New("hub: nil store")
	}
	if ctx == nil {
		ctx = h.baseCtx
	}

	nodes, err := h.store.ListNodes(ctx)
	if err != nil {
		return err
	}

	var cache *syncBuildCache
	for _, n := range nodes {
		if h.getSession(n.ID) == nil {
			continue
		}
		if cache == nil {
			cache, err = h.newSyncBuildCache(ctx)
			if err != nil {
				return err
			}
		}
		if err := h.syncNodeWithCache(ctx, n.ID, cache); err != nil && !errors.Is(err, ErrNodeOffline) {
			return err
		}
	}
	return nil
}

// SendKernelUpdate validates cmd and dispatches server.kernel_update to an online node.
func (h *Hub) SendKernelUpdate(ctx context.Context, nodeID int64, cmd protocol.ServerKernelUpdate) error {
	if h.isClosed() {
		return ErrHubClosed
	}
	if err := validateKernelUpdateCommand(cmd); err != nil {
		return err
	}

	sess := h.getSession(nodeID)
	if sess == nil {
		return ErrNodeOffline
	}

	frame, err := protocol.MarshalEnvelope(protocol.MsgTypeServerKernelUpdate, h.nextReqID(), cmd)
	if err != nil {
		return err
	}
	return sess.enqueue(frame)
}

// SendServiceCtl validates cmd and dispatches server.service_ctl to an online node.
func (h *Hub) SendServiceCtl(ctx context.Context, nodeID int64, cmd protocol.ServerServiceCtl) error {
	if h.isClosed() {
		return ErrHubClosed
	}
	if !protocol.IsValidServiceAction(cmd.Action) {
		return fmt.Errorf("%w: invalid service action %q", ErrInvalidCommand, cmd.Action)
	}

	sess := h.getSession(nodeID)
	if sess == nil {
		return ErrNodeOffline
	}

	frame, err := protocol.MarshalEnvelope(protocol.MsgTypeServerServiceCtl, h.nextReqID(), cmd)
	if err != nil {
		return err
	}
	return sess.enqueue(frame)
}

func validateKernelUpdateCommand(cmd protocol.ServerKernelUpdate) error {
	if !protocol.IsValidKernel(cmd.Kernel) {
		return fmt.Errorf("%w: invalid kernel %q", ErrInvalidCommand, cmd.Kernel)
	}
	if strings.TrimSpace(cmd.Version) == "" {
		return fmt.Errorf("%w: kernel version is required", ErrInvalidCommand)
	}
	rawURL := strings.TrimSpace(cmd.DownloadURL)
	if rawURL == "" {
		return fmt.Errorf("%w: download_url is required", ErrInvalidCommand)
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%w: invalid download_url %q", ErrInvalidCommand, cmd.DownloadURL)
	}
	if sha := strings.TrimSpace(cmd.SHA256); sha != "" {
		if len(sha) != 64 {
			return fmt.Errorf("%w: sha256 must be 64 hex characters", ErrInvalidCommand)
		}
		if _, err := hex.DecodeString(sha); err != nil {
			return fmt.Errorf("%w: invalid sha256 hex: %v", ErrInvalidCommand, err)
		}
	}
	return nil
}

func mergeAndDedupDNSRules(groupRules, extraRules []string) []string {
	out := make([]string, 0, len(groupRules)+len(extraRules))
	seen := make(map[string]struct{}, len(groupRules)+len(extraRules))

	appendList := func(items []string) {
		for _, item := range items {
			for _, rawLine := range strings.Split(item, "\n") {
				line := strings.TrimSpace(strings.TrimRight(rawLine, "\r"))
				if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
					continue
				}
				key := strings.ToLower(line)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, line)
			}
		}
	}

	appendList(groupRules)
	appendList(extraRules)
	return out
}
