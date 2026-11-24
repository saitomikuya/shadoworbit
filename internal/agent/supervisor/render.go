package supervisor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"snell-panel/internal/protocol"
)

var semverRegex = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)`)

func effectiveSnellObfs(obfs string) string {
	trimmed := strings.TrimSpace(obfs)
	if trimmed == "" {
		return protocol.SnellObfsOff
	}
	return trimmed
}

func effectiveSnellDNSIPPref(cfg protocol.ServerConfigSync) string {
	pref := strings.TrimSpace(cfg.Snell.DNSIPPreference)
	if pref == "" && cfg.DNS.UnlockEnabled {
		return protocol.DNSIPPrefPreferIPv4
	}
	return pref
}

func renderSnellConf(cfg protocol.ServerConfigSync, effectiveDNSPort, effectiveInnerPort int) string {
	obfs := effectiveSnellObfs(cfg.Snell.Obfs)
	pref := effectiveSnellDNSIPPref(cfg)

	var b strings.Builder
	b.WriteString("[snell-server]\n")
	fmt.Fprintf(&b, "listen = 127.0.0.1:%d\n", effectiveInnerPort)
	fmt.Fprintf(&b, "psk = %s\n", cfg.Snell.PSK)
	fmt.Fprintf(&b, "obfs = %s\n", obfs)
	fmt.Fprintf(&b, "tfo = %t\n", cfg.Snell.TFO)
	if effectiveDNSPort == 53 {
		b.WriteString("dns = 127.0.0.1\n")
	}

	switch cfg.Snell.Version {
	case protocol.SnellVersionV4:
		ipv6 := true
		if pref == protocol.DNSIPPrefIPv4Only || pref == protocol.DNSIPPrefPreferIPv4 || cfg.DNS.UnlockEnabled {
			ipv6 = false
		}
		fmt.Fprintf(&b, "ipv6 = %t\n", ipv6)
	case protocol.SnellVersionV5:
		if pref != "" {
			fmt.Fprintf(&b, "dns-ip-preference = %s\n", pref)
		}
	}
	return b.String()
}

func shadowTLSArgs(cfg protocol.SnellConfig, effectiveInnerPort int) ([]string, error) {
	_, _, tlsTarget, err := normalizeSTLSSNI(cfg.STLSSNI)
	if err != nil {
		return nil, err
	}
	return []string{
		"--v3",
		"--strict",
		"--fastopen",
		"server",
		"--listen", fmt.Sprintf("[::]:%d", cfg.PublicPort),
		"--server", fmt.Sprintf("127.0.0.1:%d", effectiveInnerPort),
		"--tls", tlsTarget,
		"--password", cfg.STLSPassword,
	}, nil
}

func parseSingBoxVersionGTE112(versionOut string) bool {
	m := semverRegex.FindStringSubmatch(versionOut)
	if len(m) != 4 {
		return false
	}
	major, err1 := strconv.Atoi(m[1])
	minor, err2 := strconv.Atoi(m[2])
	if err1 != nil || err2 != nil {
		return false
	}
	return major > 1 || (major == 1 && minor >= 12)
}

func parseSingBoxHasV2RayAPI(versionOut string) bool {
	for _, line := range strings.Split(versionOut, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if !strings.HasPrefix(lower, "tags:") {
			continue
		}
		rawTags := strings.TrimSpace(trimmed[len("tags:"):])
		for _, tag := range strings.Split(rawTags, ",") {
			if strings.EqualFold(strings.TrimSpace(tag), "with_v2ray_api") {
				return true
			}
		}
		return false
	}
	return true
}

type sbLogConfig struct {
	Level     string `json:"level"`
	Timestamp bool   `json:"timestamp"`
}

type sbDNSServerLegacy struct {
	Tag     string `json:"tag"`
	Address string `json:"address"`
	Detour  string `json:"detour"`
}

type sbDNSServerTyped struct {
	Tag        string `json:"tag"`
	Type       string `json:"type"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
}

type sbDNSConfig struct {
	Servers []any  `json:"servers"`
	Final   string `json:"final"`
}

type sbSTLSUser struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type sbSTLSHandshake struct {
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
}

type sbSSUser struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type sbRouteConfig struct {
	Final                 string `json:"final"`
	DefaultDomainResolver string `json:"default_domain_resolver,omitempty"`
}

type sbV2RayStatsConfig struct {
	Enabled   bool     `json:"enabled"`
	Inbounds  []string `json:"inbounds"`
	Outbounds []string `json:"outbounds"`
	Users     []string `json:"users"`
}

type sbV2RayAPIConfig struct {
	Listen string             `json:"listen"`
	Stats  sbV2RayStatsConfig `json:"stats"`
}

type sbExperimentalConfig struct {
	V2RayAPI sbV2RayAPIConfig `json:"v2ray_api"`
}

type sbConfig struct {
	Log          sbLogConfig           `json:"log"`
	DNS          sbDNSConfig           `json:"dns"`
	Inbounds     []map[string]any      `json:"inbounds"`
	Outbounds    []map[string]any      `json:"outbounds"`
	Route        sbRouteConfig         `json:"route"`
	Experimental *sbExperimentalConfig `json:"experimental,omitempty"`
}

func renderSingBoxJSON(cfg protocol.SSConfig, effectiveDNSPort, statsPort, effectiveSSInnerTCPPort int, useTypedDNS bool, includeV2RayAPI bool) ([]byte, error) {
	sniHost, sniPort, _, err := normalizeSTLSSNI(cfg.STLSSNI)
	if err != nil {
		return nil, err
	}

	stlsUsers := make([]sbSTLSUser, 0, len(cfg.Users))
	ssUsers := make([]sbSSUser, 0, len(cfg.Users))
	statUsers := make([]string, 0, len(cfg.Users))

	for _, u := range cfg.Users {
		stlsUsers = append(stlsUsers, sbSTLSUser{
			Name:     u.Username,
			Password: u.STLSPassword,
		})
		ssUsers = append(ssUsers, sbSSUser{
			Name:     u.Username,
			Password: u.UPSK,
		})
		statUsers = append(statUsers, u.Username)
	}

	if len(stlsUsers) == 0 {
		sum := sha256.Sum256([]byte("snell-panel-idle-stls:" + cfg.IPSK))
		stlsUsers = append(stlsUsers, sbSTLSUser{
			Name:     "__idle__",
			Password: hex.EncodeToString(sum[:]),
		})
	}

	var dnsServers []any
	var defaultDomainResolver string
	if useTypedDNS {
		dnsServers = []any{
			sbDNSServerTyped{
				Tag:        "local-dns",
				Type:       "udp",
				Server:     "127.0.0.1",
				ServerPort: effectiveDNSPort,
			},
		}
		defaultDomainResolver = "local-dns"
	} else {
		dnsServers = []any{
			sbDNSServerLegacy{
				Tag:     "local-dns",
				Address: fmt.Sprintf("udp://127.0.0.1:%d", effectiveDNSPort),
				Detour:  "direct",
			},
		}
	}

	doc := sbConfig{
		Log: sbLogConfig{
			Level:     "info",
			Timestamp: true,
		},
		DNS: sbDNSConfig{
			Servers: dnsServers,
			Final:   "local-dns",
		},
		Inbounds: []map[string]any{
			{
				"type":        "shadowtls",
				"tag":         "stls-in",
				"listen":      "::",
				"listen_port": cfg.TCPPort,
				"version":     3,
				"strict_mode": true,
				"users":       stlsUsers,
				"handshake": sbSTLSHandshake{
					Server:     sniHost,
					ServerPort: sniPort,
				},
				"detour": "ss-tcp-in",
			},
			{
				"type":        "shadowsocks",
				"tag":         "ss-tcp-in",
				"listen":      "127.0.0.1",
				"listen_port": effectiveSSInnerTCPPort,
				"network":     "tcp",
				"method":      cfg.Cipher,
				"password":    cfg.IPSK,
				"users":       ssUsers,
			},
			{
				"type":        "shadowsocks",
				"tag":         "ss-udp-in",
				"listen":      "::",
				"listen_port": cfg.UDPPort,
				"network":     "udp",
				"method":      cfg.Cipher,
				"password":    cfg.IPSK,
				"users":       ssUsers,
			},
		},
		Outbounds: []map[string]any{
			{
				"type": "direct",
				"tag":  "direct",
			},
		},
		Route: sbRouteConfig{
			Final:                 "direct",
			DefaultDomainResolver: defaultDomainResolver,
		},
	}
	if includeV2RayAPI {
		doc.Experimental = &sbExperimentalConfig{
			V2RayAPI: sbV2RayAPIConfig{
				Listen: fmt.Sprintf("127.0.0.1:%d", statsPort),
				Stats: sbV2RayStatsConfig{
					Enabled:   true,
					Inbounds:  []string{"stls-in", "ss-tcp-in", "ss-udp-in"},
					Outbounds: []string{"direct"},
					Users:     statUsers,
				},
			},
		}
	}

	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal sing-box config: %w", err)
	}
	return append(b, '\n'), nil
}
