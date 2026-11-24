package supervisor

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"snell-panel/internal/protocol"
)

func hasForbiddenControlChars(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func isValidSnellPSK(psk string) bool {
	if psk == "" || hasForbiddenControlChars(psk) {
		return false
	}
	for _, r := range psk {
		if unicode.IsSpace(r) || r == ';' || r == '#' {
			return false
		}
	}
	return true
}

func normalizeSTLSSNI(raw string) (host string, port int, joined string, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", 0, "", errors.New("stls_sni cannot be empty")
	}
	if hasForbiddenControlChars(trimmed) || strings.ContainsAny(trimmed, " \t") {
		return "", 0, "", fmt.Errorf("stls_sni %q contains invalid characters", raw)
	}

	if h, pStr, splitErr := net.SplitHostPort(trimmed); splitErr == nil {
		h = strings.TrimSpace(h)
		if h == "" || hasForbiddenControlChars(h) || strings.ContainsAny(h, " \t[]") {
			return "", 0, "", fmt.Errorf("invalid stls_sni host in %q", raw)
		}
		if strings.HasPrefix(trimmed, "[") && net.ParseIP(h) == nil {
			return "", 0, "", fmt.Errorf("invalid bracketed stls_sni %q: interior must be an IP address", raw)
		}
		p, err := strconv.Atoi(pStr)
		if err != nil || p < 1 || p > 65535 {
			return "", 0, "", fmt.Errorf("invalid stls_sni port in %q: must be 1..65535", raw)
		}
		return h, p, net.JoinHostPort(h, strconv.Itoa(p)), nil
	} else if !strings.Contains(splitErr.Error(), "missing port in address") {
		return "", 0, "", fmt.Errorf("invalid stls_sni %q: %w", raw, splitErr)
	}

	// No port present; strip surrounding brackets ONLY if interior parses as a valid IP literal (e.g., "[::1]").
	h := trimmed
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		inner := h[1 : len(h)-1]
		if net.ParseIP(inner) == nil {
			return "", 0, "", fmt.Errorf("invalid bracketed stls_sni %q: interior must be an IP address", raw)
		}
		h = inner
	}
	if h == "" || strings.ContainsAny(h, "[]") || (strings.Contains(h, ":") && net.ParseIP(h) == nil) {
		return "", 0, "", fmt.Errorf("invalid stls_sni %q", raw)
	}
	return h, 443, net.JoinHostPort(h, "443"), nil
}

type validationError struct {
	kernel string
	err    error
}

func (e *validationError) Error() string {
	return e.err.Error()
}

func (e *validationError) Unwrap() error {
	return e.err
}

func newValidationError(kernel string, format string, args ...any) error {
	return &validationError{
		kernel: kernel,
		err:    fmt.Errorf("%w: "+format, append([]any{ErrValidation}, args...)...),
	}
}

func validationErrKernel(err error) string {
	var ve *validationError
	if errors.As(err, &ve) {
		return ve.kernel
	}
	return ""
}

func isValidDNSIPPref(pref string) bool {
	switch pref {
	case "",
		protocol.DNSIPPrefPreferIPv4,
		protocol.DNSIPPrefPreferIPv6,
		protocol.DNSIPPrefIPv4Only,
		protocol.DNSIPPrefAuto:
		return true
	default:
		return false
	}
}

func validatePort(port int, name, kernel string) error {
	if port < 1 || port > 65535 {
		return newValidationError(kernel, "invalid %s %d: must be 1..65535", name, port)
	}
	return nil
}

func validateSS2022Key(cipher, key, label string) error {
	if strings.TrimSpace(key) == "" {
		return newValidationError(protocol.KernelSingBox, "%s cannot be empty", label)
	}
	if hasForbiddenControlChars(key) {
		return newValidationError(protocol.KernelSingBox, "%s contains forbidden control characters", label)
	}
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return newValidationError(protocol.KernelSingBox, "%s must be valid base64: %v", label, err)
	}
	expectedLen := 16
	if cipher == protocol.CipherAES256GCM {
		expectedLen = 32
	}
	if len(raw) != expectedLen {
		return newValidationError(protocol.KernelSingBox, "%s must decode to %d bytes for cipher %s, got %d", label, expectedLen, cipher, len(raw))
	}
	return nil
}

func isLoopbackTCPPortFree(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

func pickFreeTCPPort(start int, used map[int]string) (int, error) {
	for p := start; p <= 65535; p++ {
		if _, busy := used[p]; !busy && isLoopbackTCPPortFree(p) {
			return p, nil
		}
	}
	for p := 1024; p < start; p++ {
		if _, busy := used[p]; !busy && isLoopbackTCPPortFree(p) {
			return p, nil
		}
	}
	return 0, errors.New("no available internal TCP port")
}

func validateAndResolve(cfg protocol.ServerConfigSync, opts Options, prevPorts resolvedPorts, hasPrev bool) (resolvedPorts, error) {
	if cfg.DNS.LocalPort < 0 || cfg.DNS.LocalPort > 65535 {
		return resolvedPorts{}, newValidationError("", "invalid dns.local_port %d: must be 0 or 1..65535", cfg.DNS.LocalPort)
	}
	effectiveDNSPort := opts.LocalDNSPort
	if cfg.DNS.LocalPort > 0 {
		effectiveDNSPort = cfg.DNS.LocalPort
	}
	if err := validatePort(effectiveDNSPort, "effective dns local_port", ""); err != nil {
		return resolvedPorts{}, err
	}
	if err := validatePort(opts.StatsPort, "stats_port", protocol.KernelSingBox); err != nil {
		return resolvedPorts{}, err
	}
	if effectiveDNSPort == opts.StatsPort {
		return resolvedPorts{}, newValidationError(protocol.KernelSingBox, "effective dns port (%d) cannot equal stats port (%d)", effectiveDNSPort, opts.StatsPort)
	}

	// Validate Snell fields first if enabled.
	if cfg.Snell.Enabled {
		if !protocol.IsValidSnellVersion(cfg.Snell.Version) {
			return resolvedPorts{}, newValidationError(protocol.KernelSnellServer, "invalid snell version %q", cfg.Snell.Version)
		}
		if cfg.Snell.Obfs != "" && !protocol.IsValidSnellObfs(cfg.Snell.Obfs) {
			return resolvedPorts{}, newValidationError(protocol.KernelSnellServer, "invalid snell obfs %q", cfg.Snell.Obfs)
		}
		if !isValidDNSIPPref(cfg.Snell.DNSIPPreference) {
			return resolvedPorts{}, newValidationError(protocol.KernelSnellServer, "invalid snell dns_ip_preference %q", cfg.Snell.DNSIPPreference)
		}
		if err := validatePort(cfg.Snell.PublicPort, "snell.public_port", protocol.KernelShadowTLS); err != nil {
			return resolvedPorts{}, err
		}
		if cfg.Snell.InnerPort != 0 {
			if err := validatePort(cfg.Snell.InnerPort, "snell.inner_port", protocol.KernelSnellServer); err != nil {
				return resolvedPorts{}, err
			}
		}
		if !isValidSnellPSK(cfg.Snell.PSK) {
			return resolvedPorts{}, newValidationError(protocol.KernelSnellServer, "snell.psk must be non-empty without whitespace, control characters, or INI comment chars")
		}
		if strings.TrimSpace(cfg.Snell.STLSPassword) == "" || hasForbiddenControlChars(cfg.Snell.STLSPassword) {
			return resolvedPorts{}, newValidationError(protocol.KernelShadowTLS, "snell.stls_password must be non-empty without control characters")
		}
		if _, _, _, err := normalizeSTLSSNI(cfg.Snell.STLSSNI); err != nil {
			return resolvedPorts{}, newValidationError(protocol.KernelShadowTLS, "snell.stls_sni invalid: %v", err)
		}
	}

	// Validate SS fields if enabled.
	if cfg.SS.Enabled {
		if err := validatePort(cfg.SS.TCPPort, "ss.tcp_port", protocol.KernelSingBox); err != nil {
			return resolvedPorts{}, err
		}
		if err := validatePort(cfg.SS.UDPPort, "ss.udp_port", protocol.KernelSingBox); err != nil {
			return resolvedPorts{}, err
		}
		if !protocol.IsValidCipher(cfg.SS.Cipher) {
			return resolvedPorts{}, newValidationError(protocol.KernelSingBox, "invalid ss.cipher %q", cfg.SS.Cipher)
		}
		if _, _, _, err := normalizeSTLSSNI(cfg.SS.STLSSNI); err != nil {
			return resolvedPorts{}, newValidationError(protocol.KernelSingBox, "ss.stls_sni invalid: %v", err)
		}
		if err := validateSS2022Key(cfg.SS.Cipher, cfg.SS.IPSK, "ss.ipsk"); err != nil {
			return resolvedPorts{}, err
		}
		seenUsers := make(map[string]struct{}, len(cfg.SS.Users))
		for i, u := range cfg.SS.Users {
			if strings.TrimSpace(u.Username) == "" || hasForbiddenControlChars(u.Username) {
				return resolvedPorts{}, newValidationError(protocol.KernelSingBox, "ss.users[%d].username must be non-empty without control characters", i)
			}
			if _, dup := seenUsers[u.Username]; dup {
				return resolvedPorts{}, newValidationError(protocol.KernelSingBox, "duplicate ss.users username %q", u.Username)
			}
			seenUsers[u.Username] = struct{}{}
			if strings.TrimSpace(u.STLSPassword) == "" || hasForbiddenControlChars(u.STLSPassword) {
				return resolvedPorts{}, newValidationError(protocol.KernelSingBox, "ss.users[%d].stls_password must be non-empty without control characters", i)
			}
			if err := validateSS2022Key(cfg.SS.Cipher, u.UPSK, fmt.Sprintf("ss.users[%d].upsk", i)); err != nil {
				return resolvedPorts{}, err
			}
		}
	}

	// Protocol-separated port collision matrix:
	// TCP listeners and UDP listeners are independent, so SS.TCPPort == SS.UDPPort is valid,
	// whereas SS.UDPPort == effectiveDNSPort (which binds both UDP and TCP) is rejected.
	tcpPorts := map[int]string{
		effectiveDNSPort: "dns.local_port",
		opts.StatsPort:   "stats_port",
	}
	udpPorts := map[int]string{
		effectiveDNSPort: "dns.local_port",
	}

	claimTCP := func(port int, owner, kernel string) error {
		if existing, exists := tcpPorts[port]; exists {
			return newValidationError(kernel, "TCP port collision on %d between %s and %s", port, existing, owner)
		}
		tcpPorts[port] = owner
		return nil
	}
	claimUDP := func(port int, owner, kernel string) error {
		if existing, exists := udpPorts[port]; exists {
			return newValidationError(kernel, "UDP port collision on %d between %s and %s", port, existing, owner)
		}
		udpPorts[port] = owner
		return nil
	}

	// Claim explicitly fixed ports first so auto-picked internal ports avoid them.
	if cfg.Snell.Enabled {
		if err := claimTCP(cfg.Snell.PublicPort, "snell.public_port", protocol.KernelShadowTLS); err != nil {
			return resolvedPorts{}, err
		}
		if cfg.Snell.InnerPort > 0 {
			if err := claimTCP(cfg.Snell.InnerPort, "snell.inner_port", protocol.KernelSnellServer); err != nil {
				return resolvedPorts{}, err
			}
		}
	}
	if cfg.SS.Enabled {
		if err := claimTCP(cfg.SS.TCPPort, "ss.tcp_port", protocol.KernelSingBox); err != nil {
			return resolvedPorts{}, err
		}
		if err := claimUDP(cfg.SS.UDPPort, "ss.udp_port", protocol.KernelSingBox); err != nil {
			return resolvedPorts{}, err
		}
		if opts.SSInnerTCPPort > 0 {
			if err := claimTCP(opts.SSInnerTCPPort, "ss.inner_tcp_port", protocol.KernelSingBox); err != nil {
				return resolvedPorts{}, err
			}
		}
	}

	res := resolvedPorts{
		EffectiveDNSPort: effectiveDNSPort,
		StatsPort:        opts.StatsPort,
	}

	if cfg.Snell.Enabled {
		if cfg.Snell.InnerPort > 0 {
			res.SnellInnerPort = cfg.Snell.InnerPort
		} else {
			start := defaultSnellInnerStart
			if hasPrev && prevPorts.SnellInnerPort > 0 {
				if _, busy := tcpPorts[prevPorts.SnellInnerPort]; !busy {
					res.SnellInnerPort = prevPorts.SnellInnerPort
				}
			}
			if res.SnellInnerPort == 0 {
				picked, err := pickFreeTCPPort(start, tcpPorts)
				if err != nil {
					return resolvedPorts{}, newValidationError(protocol.KernelSnellServer, "select snell inner port: %v", err)
				}
				res.SnellInnerPort = picked
			}
			tcpPorts[res.SnellInnerPort] = "snell.inner_port"
		}
	}

	if cfg.SS.Enabled {
		if opts.SSInnerTCPPort > 0 {
			res.SSInnerTCPPort = opts.SSInnerTCPPort
		} else {
			if hasPrev && prevPorts.SSInnerTCPPort > 0 {
				if _, busy := tcpPorts[prevPorts.SSInnerTCPPort]; !busy {
					res.SSInnerTCPPort = prevPorts.SSInnerTCPPort
				}
			}
			if res.SSInnerTCPPort == 0 {
				picked, err := pickFreeTCPPort(defaultSSInnerStart, tcpPorts)
				if err != nil {
					return resolvedPorts{}, newValidationError(protocol.KernelSingBox, "select ss inner tcp port: %v", err)
				}
				res.SSInnerTCPPort = picked
			}
			tcpPorts[res.SSInnerTCPPort] = "ss.inner_tcp_port"
		}
	}

	return res, nil
}

func checkExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%q is a directory", path)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%q is not executable", path)
	}
	return nil
}

func (s *Supervisor) runStagedValidation(
	ctx context.Context,
	cfg protocol.ServerConfigSync,
	adminChanged bool,
	ssChanged bool,
	snellBytes []byte,
	singBoxBytes []byte,
) error {
	if s.opts.Validator == nil && s.opts.DisableBinaryValidation {
		return nil
	}

	stagingDir, err := os.MkdirTemp(s.configsDir, ".staging-*")
	if err != nil {
		return newValidationError("", "create staging dir: %v", err)
	}
	defer os.RemoveAll(stagingDir)

	var stagedSnellPath string
	if cfg.Snell.Enabled && adminChanged {
		stagedSnellPath = filepath.Join(stagingDir, "snell-server.conf")
		if err := atomicWriteFile(stagedSnellPath, snellBytes, 0o600); err != nil {
			return newValidationError(protocol.KernelSnellServer, "stage snell-server.conf: %v", err)
		}
	}

	var stagedSingBoxPath string
	if cfg.SS.Enabled && ssChanged {
		stagedSingBoxPath = filepath.Join(stagingDir, "sing-box.json")
		if err := atomicWriteFile(stagedSingBoxPath, singBoxBytes, 0o600); err != nil {
			return newValidationError(protocol.KernelSingBox, "stage sing-box.json: %v", err)
		}
	}

	if s.opts.Validator != nil {
		if stagedSnellPath != "" {
			if err := s.opts.Validator(ctx, protocol.KernelSnellServer, stagedSnellPath); err != nil {
				return newValidationError(protocol.KernelSnellServer, "custom validator failed: %v", err)
			}
		}
		if stagedSingBoxPath != "" {
			if err := s.opts.Validator(ctx, protocol.KernelSingBox, stagedSingBoxPath); err != nil {
				return newValidationError(protocol.KernelSingBox, "custom validator failed: %v", err)
			}
		}
		return nil
	}

	if cfg.Snell.Enabled && adminChanged {
		snellPath, err := s.BinaryPath(protocol.KernelSnellServer)
		if err != nil {
			return newValidationError(protocol.KernelSnellServer, "binary missing: %v", err)
		}
		if err := checkExecutable(snellPath); err != nil {
			return newValidationError(protocol.KernelSnellServer, "binary check failed: %v", err)
		}
		stlsPath, err := s.BinaryPath(protocol.KernelShadowTLS)
		if err != nil {
			return newValidationError(protocol.KernelShadowTLS, "binary missing: %v", err)
		}
		if err := checkExecutable(stlsPath); err != nil {
			return newValidationError(protocol.KernelShadowTLS, "binary check failed: %v", err)
		}
	}

	if cfg.SS.Enabled && ssChanged {
		sbPath, err := s.BinaryPath(protocol.KernelSingBox)
		if err != nil {
			return newValidationError(protocol.KernelSingBox, "binary missing: %v", err)
		}
		if err := checkExecutable(sbPath); err != nil {
			return newValidationError(protocol.KernelSingBox, "binary check failed: %v", err)
		}
		vctx, cancel := context.WithTimeout(ctx, defaultCheckTimeout)
		defer cancel()
		cmd := exec.CommandContext(vctx, sbPath, "check", "-c", stagedSingBoxPath)
		out, err := cmd.CombinedOutput()
		if err != nil {
			msg := strings.TrimSpace(string(out))
			if msg == "" {
				msg = err.Error()
			}
			return newValidationError(protocol.KernelSingBox, "sing-box check failed: %s", msg)
		}
	}

	return nil
}
