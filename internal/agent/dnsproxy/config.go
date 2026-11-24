package dnsproxy

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	DefaultListenHost      = "127.0.0.1"
	DefaultListenPort      = 1053
	DefaultUpstreamDNS     = "1.1.1.1:53,8.8.8.8:53"
	DefaultUpstreamTimeout = 3 * time.Second
)

var (
	ErrAlreadyStarted = errors.New("dnsproxy: server already started")
	ErrInvalidConfig  = errors.New("dnsproxy: invalid config")
)

// Config defines settings for the built-in miekg/dns loopback unlock dispatcher.
type Config struct {
	ListenHost      string
	ListenPort      int
	UnlockEnabled   bool
	UnlockServer    string
	Rules           []string
	UpstreamDNS     string
	UpstreamTimeout time.Duration
}

// DefaultConfig returns the standard production defaults for dnsproxy.
func DefaultConfig() Config {
	return Config{
		ListenHost:      DefaultListenHost,
		ListenPort:      DefaultListenPort,
		UpstreamDNS:     DefaultUpstreamDNS,
		UpstreamTimeout: DefaultUpstreamTimeout,
	}
}

type runtimeState struct {
	cfg           Config
	unlockEnabled bool
	unlockServer  string
	matcher       *RuleMatcher
	upstreams     []string
	timeout       time.Duration
}

func compileState(cfg Config, fallbackHost string) (*runtimeState, error) {
	normalized := cfg
	normalized.Rules = slices.Clone(cfg.Rules)

	host := strings.TrimSpace(cfg.ListenHost)
	if host == "" {
		if fallbackHost != "" {
			host = fallbackHost
		} else {
			host = DefaultListenHost
		}
	}
	normalized.ListenHost = host

	if cfg.ListenPort < 0 || cfg.ListenPort > 65535 {
		return nil, fmt.Errorf("%w: listen port %d must be between 0 and 65535", ErrInvalidConfig, cfg.ListenPort)
	}

	upstreamRaw := strings.TrimSpace(cfg.UpstreamDNS)
	if upstreamRaw == "" {
		upstreamRaw = DefaultUpstreamDNS
	}
	normalized.UpstreamDNS = upstreamRaw

	upstreams, err := parseUpstreams(upstreamRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid upstream_dns: %v", ErrInvalidConfig, err)
	}

	var unlockAddr string
	if rawUnlock := strings.TrimSpace(cfg.UnlockServer); rawUnlock != "" {
		unlockAddr, err = normalizeDNSAddr(rawUnlock)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid unlock_server %q: %v", ErrInvalidConfig, cfg.UnlockServer, err)
		}
		normalized.UnlockServer = unlockAddr
	} else {
		normalized.UnlockServer = ""
	}

	timeout := cfg.UpstreamTimeout
	if timeout <= 0 {
		timeout = DefaultUpstreamTimeout
	}
	normalized.UpstreamTimeout = timeout

	matcher := ParseRules(normalized.Rules)

	return &runtimeState{
		cfg:           normalized,
		unlockEnabled: normalized.UnlockEnabled,
		unlockServer:  unlockAddr,
		matcher:       matcher,
		upstreams:     upstreams,
		timeout:       timeout,
	}, nil
}

func parseUpstreams(raw string) ([]string, error) {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || unicode.IsSpace(r)
	})
	if len(fields) == 0 {
		return nil, errors.New("empty upstream list")
	}

	out := make([]string, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		addr, err := normalizeDNSAddr(f)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", f, err)
		}
		if _, ok := seen[addr]; !ok {
			seen[addr] = struct{}{}
			out = append(out, addr)
		}
	}
	return out, nil
}

func normalizeDNSAddr(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("empty address")
	}

	// Strip optional udp:// or tcp:// scheme prefix (case-insensitive).
	if len(s) >= 6 {
		lowerPrefix := strings.ToLower(s[:6])
		if lowerPrefix == "udp://" || lowerPrefix == "tcp://" {
			s = strings.TrimSpace(s[6:])
		}
	}
	if s == "" {
		return "", errors.New("empty address after scheme")
	}
	if strings.ContainsAny(s, "/\\ \t\r\n") {
		return "", errors.New("invalid characters in address")
	}

	// Case 1: Bracketed or host:port form parseable by net.SplitHostPort.
	if host, portStr, err := net.SplitHostPort(s); err == nil {
		if host == "" {
			return "", errors.New("missing host")
		}
		if _, err := validatePortString(portStr); err != nil {
			return "", err
		}
		return net.JoinHostPort(host, portStr), nil
	}

	// Case 2: Bare IPv4 or bare IPv6 (e.g. "1.2.3.4" or "::1").
	if ip := net.ParseIP(s); ip != nil {
		return net.JoinHostPort(s, "53"), nil
	}

	// Case 3: Bracketed IPv6 without port (e.g. "[::1]").
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		inner := s[1 : len(s)-1]
		if ip := net.ParseIP(inner); ip != nil {
			return net.JoinHostPort(inner, "53"), nil
		}
		return "", errors.New("invalid bracketed IPv6 address")
	}

	// Case 4: Contains ':' (or brackets) but failed SplitHostPort and ParseIP -> malformed port/host.
	if strings.ContainsAny(s, ":[]") {
		return "", errors.New("malformed host:port")
	}

	// Case 5: Bare hostname -> default port 53.
	return net.JoinHostPort(s, "53"), nil
}

func validatePortString(portStr string) (int, error) {
	if portStr == "" {
		return 0, errors.New("missing port")
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("port %q must be between 1 and 65535", portStr)
	}
	return p, nil
}
