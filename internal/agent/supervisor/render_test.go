package supervisor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"snell-panel/internal/protocol"
)

func b64Key(n int, fill byte) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = fill + byte(i)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func validSyncConfig() protocol.ServerConfigSync {
	return protocol.ServerConfigSync{
		ConfigRevision: 1,
		Snell: protocol.SnellConfig{
			Enabled:         true,
			Version:         protocol.SnellVersionV5,
			PublicPort:      20001,
			InnerPort:       31001,
			PSK:             "snell-secret-psk",
			Obfs:            protocol.SnellObfsTLS,
			TFO:             true,
			DNSIPPreference: "",
			STLSPassword:    "snell-stls-pass",
			STLSSNI:         "gateway.icloud.com",
		},
		SS: protocol.SSConfig{
			Enabled: true,
			TCPPort: 20002,
			UDPPort: 20002, // deliberately same port as TCPPort
			Cipher:  protocol.CipherAES256GCM,
			IPSK:    b64Key(32, 1),
			STLSSNI: "swscan.apple.com:443",
			Users: []protocol.SSUserEntry{
				{
					UserID:       101,
					Username:     "alice",
					UPSK:         b64Key(32, 10),
					STLSPassword: "alice-stls-password",
				},
				{
					UserID:       102,
					Username:     "bob",
					UPSK:         b64Key(32, 20),
					STLSPassword: "bob-stls-password",
				},
			},
		},
		DNS: protocol.DNSConfig{
			UnlockEnabled: true,
			UnlockServer:  "1.2.3.4:3535",
			Rules:         []string{"netflix.com"},
			UpstreamDNS:   "1.1.1.1:53",
			LocalPort:     15353,
		},
	}
}

func TestNewOptionsValidation(t *testing.T) {
	t.Run("missing DataDir", func(t *testing.T) {
		if _, err := New(Options{}); err == nil {
			t.Fatal("expected error for empty DataDir")
		}
	})

	t.Run("StatsPort equals LocalDNSPort", func(t *testing.T) {
		_, err := New(Options{
			DataDir:      t.TempDir(),
			StatsPort:    1053,
			LocalDNSPort: 1053,
		})
		if err == nil {
			t.Fatal("expected error when StatsPort == LocalDNSPort")
		}
	})

	t.Run("out of range ports", func(t *testing.T) {
		if _, err := New(Options{DataDir: t.TempDir(), StatsPort: 70000}); err == nil {
			t.Fatal("expected error for out of range StatsPort")
		}
		if _, err := New(Options{DataDir: t.TempDir(), LocalDNSPort: -1}); err == nil {
			t.Fatal("expected error for negative LocalDNSPort")
		}
		if _, err := New(Options{DataDir: t.TempDir(), SSInnerTCPPort: 65536}); err == nil {
			t.Fatal("expected error for out of range SSInnerTCPPort")
		}
	})

	t.Run("defaults populated", func(t *testing.T) {
		sup, err := New(Options{DataDir: t.TempDir()})
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		defer sup.Stop(context.Background())

		if sup.opts.SnellBin != "snell-server" || sup.opts.ShadowTLSBin != "shadow-tls" || sup.opts.SingBoxBin != "sing-box" {
			t.Fatalf("unexpected binary defaults: %+v", sup.opts)
		}
		if sup.opts.StatsPort != 18080 || sup.opts.LocalDNSPort != 1053 {
			t.Fatalf("unexpected port defaults: stats=%d dns=%d", sup.opts.StatsPort, sup.opts.LocalDNSPort)
		}
		if sup.opts.StartupGrace <= 0 || sup.opts.StopTimeout <= 0 || sup.opts.CrashBackoffBase <= 0 || sup.opts.CrashBackoffMax <= 0 || sup.opts.StabilityWindow <= 0 {
			t.Fatalf("expected positive timing defaults: %+v", sup.opts)
		}
	})
}

func TestRenderSnellConf(t *testing.T) {
	t.Run("v5 unlock default prefer-ipv4", func(t *testing.T) {
		cfg := validSyncConfig()
		cfg.Snell.Version = protocol.SnellVersionV5
		cfg.Snell.Obfs = ""
		cfg.Snell.DNSIPPreference = ""
		cfg.DNS.UnlockEnabled = true

		got := renderSnellConf(cfg, 15353, 31001)
		for _, want := range []string{
			"[snell-server]",
			"listen = 127.0.0.1:31001",
			"psk = snell-secret-psk",
			"obfs = off",
			"tfo = true",
			"dns-ip-preference = prefer-ipv4",
		} {
			if !strings.Contains(got, want) {
				t.Fatalf("missing %q in:\n%s", want, got)
			}
		}
		if strings.Contains(got, "dns = ") {
			t.Fatalf("must omit dns = when local dns port is not 53:\n%s", got)
		}
		if strings.Contains(got, "ipv6 =") {
			t.Fatalf("v5 config should not emit ipv6 line:\n%s", got)
		}
	})

	t.Run("port 53 emits bare loopback dns IP", func(t *testing.T) {
		cfg := validSyncConfig()
		got := renderSnellConf(cfg, 53, 31001)
		if !strings.Contains(got, "dns = 127.0.0.1\n") {
			t.Fatalf("expected bare loopback dns = 127.0.0.1 in:\n%s", got)
		}
		if strings.Contains(got, "127.0.0.1:53") {
			t.Fatalf("must not include :53 port in snell dns line:\n%s", got)
		}
	})

	t.Run("v4 emits ipv6 and omits dns-ip-preference", func(t *testing.T) {
		cfg := validSyncConfig()
		cfg.Snell.Version = protocol.SnellVersionV4
		cfg.Snell.TFO = false
		cfg.DNS.UnlockEnabled = true

		got := renderSnellConf(cfg, 1053, 31001)
		if !strings.Contains(got, "ipv6 = false") {
			t.Fatalf("expected ipv6 = false for v4 with unlock:\n%s", got)
		}
		if strings.Contains(got, "dns-ip-preference") {
			t.Fatalf("v4 must not emit dns-ip-preference:\n%s", got)
		}

		cfg.DNS.UnlockEnabled = false
		cfg.Snell.DNSIPPreference = protocol.DNSIPPrefPreferIPv6
		got2 := renderSnellConf(cfg, 1053, 31001)
		if !strings.Contains(got2, "ipv6 = true") {
			t.Fatalf("expected ipv6 = true for v4 prefer-ipv6:\n%s", got2)
		}
	})
}

func TestShadowTLSArgsAndSNINormalization(t *testing.T) {
	cfg := validSyncConfig().Snell
	cfg.STLSSNI = "gateway.icloud.com"
	args, err := shadowTLSArgs(cfg, 31001)
	if err != nil {
		t.Fatalf("shadowTLSArgs failed: %v", err)
	}
	joined := strings.Join(args, " ")
	want := "--v3 --strict --fastopen server --listen [::]:20001 --server 127.0.0.1:31001 --tls gateway.icloud.com:443 --password snell-stls-pass"
	if joined != want {
		t.Fatalf("shadow-tls args mismatch:\n got: %s\nwant: %s", joined, want)
	}

	cfg.STLSSNI = "gateway.icloud.com:8443"
	args2, err := shadowTLSArgs(cfg, 31001)
	if err != nil {
		t.Fatalf("shadowTLSArgs with port failed: %v", err)
	}
	if !strings.Contains(strings.Join(args2, " "), "--tls gateway.icloud.com:8443 ") {
		t.Fatalf("expected preserved custom port, got: %v", args2)
	}
}

func TestRenderSingBoxJSON(t *testing.T) {
	cfg := validSyncConfig().SS

	t.Run("legacy <1.12 DNS and stats", func(t *testing.T) {
		raw, err := renderSingBoxJSON(cfg, 15353, 18080, 31002, false, true)
		if err != nil {
			t.Fatalf("renderSingBoxJSON failed: %v", err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("invalid json: %v\n%s", err, raw)
		}
		s := string(raw)
		if strings.Contains(s, `"block"`) {
			t.Fatalf("must omit deprecated block outbound:\n%s", s)
		}
		if strings.Contains(s, `"multiplex"`) {
			t.Fatalf("must omit multiplex:\n%s", s)
		}
		if !strings.Contains(s, `"address": "udp://127.0.0.1:15353"`) {
			t.Fatalf("expected legacy udp:// address:\n%s", s)
		}
		if !strings.Contains(s, `"listen": "127.0.0.1:18080"`) {
			t.Fatalf("expected v2ray_api listen:\n%s", s)
		}
		if !strings.Contains(s, `"alice"`) || !strings.Contains(s, `"bob"`) {
			t.Fatalf("expected users in sing-box json:\n%s", s)
		}
	})

	t.Run("typed >=1.12 DNS and route resolver", func(t *testing.T) {
		raw, err := renderSingBoxJSON(cfg, 15353, 18080, 31002, true, true)
		if err != nil {
			t.Fatalf("renderSingBoxJSON failed: %v", err)
		}
		s := string(raw)
		if !strings.Contains(s, `"type": "udp"`) || !strings.Contains(s, `"server_port": 15353`) {
			t.Fatalf("expected typed dns server for >=1.12:\n%s", s)
		}
		if !strings.Contains(s, `"default_domain_resolver": "local-dns"`) {
			t.Fatalf("expected route.default_domain_resolver for >=1.12:\n%s", s)
		}
	})

	t.Run("empty users renders placeholder in stls-in and non-nil empty arrays elsewhere", func(t *testing.T) {
		emptyCfg := cfg
		emptyCfg.Users = nil
		raw, err := renderSingBoxJSON(emptyCfg, 15353, 18080, 31002, false, true)
		if err != nil {
			t.Fatalf("renderSingBoxJSON empty users failed: %v", err)
		}
		if strings.Contains(string(raw), ": null") {
			t.Fatalf("expected no null arrays in JSON:\n%s", raw)
		}
		raw2, err := renderSingBoxJSON(emptyCfg, 15353, 18080, 31002, false, true)
		if err != nil {
			t.Fatalf("second renderSingBoxJSON empty users failed: %v", err)
		}
		if string(raw) != string(raw2) {
			t.Fatalf("expected deterministic idle stls-in output:\n%s\nvs\n%s", raw, raw2)
		}
		var doc struct {
			Inbounds []struct {
				Tag   string `json:"tag"`
				Users []struct {
					Name     string `json:"name"`
					Password string `json:"password"`
				} `json:"users"`
			} `json:"inbounds"`
			Experimental *struct {
				V2RayAPI struct {
					Stats struct {
						Users []string `json:"users"`
					} `json:"stats"`
				} `json:"v2ray_api"`
			} `json:"experimental"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("unmarshal rendered json: %v", err)
		}
		for _, inb := range doc.Inbounds {
			switch inb.Tag {
			case "stls-in":
				if len(inb.Users) != 1 || inb.Users[0].Name != "__idle__" || inb.Users[0].Password == "" {
					t.Fatalf("expected __idle__ placeholder in stls-in, got %+v", inb.Users)
				}
			case "ss-tcp-in", "ss-udp-in":
				if inb.Users == nil || len(inb.Users) != 0 {
					t.Fatalf("expected empty non-nil users in %s, got %+v", inb.Tag, inb.Users)
				}
			}
		}
		if doc.Experimental == nil || doc.Experimental.V2RayAPI.Stats.Users == nil || len(doc.Experimental.V2RayAPI.Stats.Users) != 0 {
			t.Fatalf("expected empty non-nil v2ray_api stats.users, got %+v", doc.Experimental)
		}
	})

	t.Run("includeV2RayAPI false omits experimental section", func(t *testing.T) {
		raw, err := renderSingBoxJSON(cfg, 15353, 18080, 31002, true, false)
		if err != nil {
			t.Fatalf("renderSingBoxJSON includeV2RayAPI=false failed: %v", err)
		}
		s := string(raw)
		if strings.Contains(s, `"experimental"`) || strings.Contains(s, `"v2ray_api"`) {
			t.Fatalf("expected experimental/v2ray_api omitted:\n%s", s)
		}
	})
}

func TestParseSingBoxHasV2RayAPI(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{
			name: "official release tags without with_v2ray_api",
			in:   "sing-box version 1.14.4\n\nEnvironment: go1.26.10 linux/amd64\nTags: with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_purego\n",
			want: false,
		},
		{
			name: "custom build tags with with_v2ray_api",
			in:   "sing-box version 1.14.4\nTags: with_gvisor, with_v2ray_api, with_utls\n",
			want: true,
		},
		{
			name: "single line mock version output without Tags line",
			in:   "sing-box version 1.14.4",
			want: true,
		},
		{
			name: "empty output",
			in:   "",
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseSingBoxHasV2RayAPI(tc.in); got != tc.want {
				t.Errorf("parseSingBoxHasV2RayAPI() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseSingBoxVersionGTE112(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"sing-box version 1.11.4", false},
		{"sing-box version 1.10.7", false},
		{"sing-box version 1.12.0", true},
		{"1.13.2", true},
		{"v2.0.0", true},
		{"unknown", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := parseSingBoxVersionGTE112(tc.in); got != tc.want {
			t.Errorf("parseSingBoxVersionGTE112(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestStructuralValidationAndPortCollisions(t *testing.T) {
	opts := Options{
		DataDir:        t.TempDir(),
		StatsPort:      18080,
		LocalDNSPort:   1053,
		SSInnerTCPPort: 0,
	}

	t.Run("valid config with SS.TCPPort == SS.UDPPort passes", func(t *testing.T) {
		cfg := validSyncConfig()
		ports, err := validateAndResolve(cfg, opts, resolvedPorts{}, false)
		if err != nil {
			t.Fatalf("expected valid config, got: %v", err)
		}
		if ports.EffectiveDNSPort != 15353 || ports.SSInnerTCPPort < defaultSSInnerStart || ports.SSInnerTCPPort > 65535 {
			t.Fatalf("unexpected resolved ports: %+v", ports)
		}
	})

	t.Run("empty SS.Users allowed structurally", func(t *testing.T) {
		cfg := validSyncConfig()
		cfg.SS.Users = nil
		if _, err := validateAndResolve(cfg, opts, resolvedPorts{}, false); err != nil {
			t.Fatalf("expected empty users to pass structurally, got: %v", err)
		}
	})

	t.Run("SS.UDPPort == Snell.PublicPort allowed", func(t *testing.T) {
		cfg := validSyncConfig()
		cfg.SS.UDPPort = cfg.Snell.PublicPort
		if _, err := validateAndResolve(cfg, opts, resolvedPorts{}, false); err != nil {
			t.Fatalf("expected UDPPort == Snell.PublicPort to pass, got: %v", err)
		}
	})

	badCases := []struct {
		name   string
		mutate func(*protocol.ServerConfigSync)
	}{
		{"SS.UDPPort == effectiveDNSPort", func(c *protocol.ServerConfigSync) {
			c.SS.UDPPort = c.DNS.LocalPort
		}},
		{"SS.TCPPort == Snell.PublicPort", func(c *protocol.ServerConfigSync) {
			c.SS.TCPPort = c.Snell.PublicPort
		}},
		{"Snell.InnerPort == StatsPort", func(c *protocol.ServerConfigSync) {
			c.Snell.InnerPort = opts.StatsPort
		}},
		{"DNS.LocalPort == StatsPort", func(c *protocol.ServerConfigSync) {
			c.DNS.LocalPort = opts.StatsPort
		}},
		{"negative DNS.LocalPort", func(c *protocol.ServerConfigSync) {
			c.DNS.LocalPort = -5
		}},
		{"out of range DNS.LocalPort", func(c *protocol.ServerConfigSync) {
			c.DNS.LocalPort = 70000
		}},
		{"Snell.PublicPort out of range", func(c *protocol.ServerConfigSync) {
			c.Snell.PublicPort = 70000
		}},
		{"invalid snell version", func(c *protocol.ServerConfigSync) {
			c.Snell.Version = "v3"
		}},
		{"invalid snell obfs", func(c *protocol.ServerConfigSync) {
			c.Snell.Obfs = "ws"
		}},
		{"invalid dns_ip_preference", func(c *protocol.ServerConfigSync) {
			c.Snell.DNSIPPreference = "ipv6-only"
		}},
		{"empty snell psk", func(c *protocol.ServerConfigSync) {
			c.Snell.PSK = ""
		}},
		{"newline in snell psk", func(c *protocol.ServerConfigSync) {
			c.Snell.PSK = "abc\ndef"
		}},
		{"empty snell stls_sni", func(c *protocol.ServerConfigSync) {
			c.Snell.STLSSNI = ""
		}},
		{"invalid cipher", func(c *protocol.ServerConfigSync) {
			c.SS.Cipher = "aes-256-gcm"
		}},
		{"invalid base64 ipsk", func(c *protocol.ServerConfigSync) {
			c.SS.IPSK = "not-valid-base64!"
		}},
		{"wrong key length for aes-256-gcm", func(c *protocol.ServerConfigSync) {
			c.SS.Cipher = protocol.CipherAES256GCM
			c.SS.IPSK = b64Key(16, 1)
		}},
		{"wrong user key length for aes-128-gcm", func(c *protocol.ServerConfigSync) {
			c.SS.Cipher = protocol.CipherAES128GCM
			c.SS.IPSK = b64Key(16, 1)
			c.SS.Users[0].UPSK = b64Key(32, 2)
			c.SS.Users[1].UPSK = b64Key(16, 3)
		}},
		{"duplicate username", func(c *protocol.ServerConfigSync) {
			c.SS.Users[1].Username = "alice"
		}},
		{"empty username", func(c *protocol.ServerConfigSync) {
			c.SS.Users[0].Username = "  "
		}},
		{"empty user stls_password", func(c *protocol.ServerConfigSync) {
			c.SS.Users[0].STLSPassword = ""
		}},
	}

	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validSyncConfig()
			tc.mutate(&cfg)
			_, err := validateAndResolve(cfg, opts, resolvedPorts{}, false)
			if err == nil {
				t.Fatalf("expected validation error for %s", tc.name)
			}
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("expected ErrValidation, got: %v", err)
			}
		})
	}
}

func TestSupervisor_ConfigRenderAdversarialMatrix(t *testing.T) {
	t.Run("normalizeSTLSSNI_ipv6_and_non_ip_brackets", func(t *testing.T) {
		// Valid IPv6 literals (with and without explicit port).
		h, p, joined, err := normalizeSTLSSNI("[::1]")
		if err != nil || h != "::1" || p != 443 || joined != "[::1]:443" {
			t.Fatalf("normalizeSTLSSNI([::1]) = (%q, %d, %q, %v)", h, p, joined, err)
		}
		h, p, joined, err = normalizeSTLSSNI("[2001:db8::1]:8443")
		if err != nil || h != "2001:db8::1" || p != 8443 || joined != "[2001:db8::1]:8443" {
			t.Fatalf("normalizeSTLSSNI([2001:db8::1]:8443) = (%q, %d, %q, %v)", h, p, joined, err)
		}

		// Invalid bracketed non-IPs and malformed SNIs (BUG-A7).
		for _, bad := range []string{
			"[gateway.icloud.com]",
			"[gateway.icloud.com]:443",
			"gateway[.icloud.com",
			"gateway].icloud.com",
			"[]",
			"[]:443",
			"example.com:0",
			"example.com:65536",
			"example\t.com",
			"2001:db8::1", // unbracketed IPv6 without port
		} {
			if h, p, j, err := normalizeSTLSSNI(bad); err == nil {
				t.Fatalf("normalizeSTLSSNI(%q) unexpectedly succeeded: (%q, %d, %q)", bad, h, p, j)
			}
		}
	})

	t.Run("snell_psk_and_control_char_hardening", func(t *testing.T) {
		opts := Options{
			DataDir:      t.TempDir(),
			StatsPort:    18080,
			LocalDNSPort: 1053,
		}
		for _, badPSK := range []string{
			"psk\twith\ttab",
			" leading-space",
			"trailing-space ",
			"space inside",
			"psk;comment",
			"psk#hash",
			"psk\x7fdel",
			"psk\x00nul",
		} {
			cfg := validSyncConfig()
			cfg.Snell.PSK = badPSK
			if _, err := validateAndResolve(cfg, opts, resolvedPorts{}, false); err == nil {
				t.Fatalf("expected Snell.PSK %q to be rejected", badPSK)
			}
		}
		// Valid complex PSK without whitespace/INI comments passes.
		cfgOK := validSyncConfig()
		cfgOK.Snell.PSK = "AbCdEf0123456789-_+/="
		if _, err := validateAndResolve(cfgOK, opts, resolvedPorts{}, false); err != nil {
			t.Fatalf("expected valid PSK to pass, got: %v", err)
		}
	})

	t.Run("snell_v4_v5_obfs_tfo_and_ss_cipher_matrix", func(t *testing.T) {
		for _, ver := range []string{protocol.SnellVersionV4, protocol.SnellVersionV5} {
			for _, obfs := range []string{protocol.SnellObfsOff, protocol.SnellObfsHTTP, protocol.SnellObfsTLS} {
				for _, tfo := range []bool{false, true} {
					cfg := validSyncConfig()
					cfg.Snell.Version = ver
					cfg.Snell.Obfs = obfs
					cfg.Snell.TFO = tfo
					conf := renderSnellConf(cfg, 1053, 31001)
					if !strings.Contains(conf, "obfs = "+obfs) {
						t.Fatalf("missing obfs=%s in:\n%s", obfs, conf)
					}
					if ver == protocol.SnellVersionV4 && strings.Contains(conf, "dns-ip-preference") {
						t.Fatalf("v4 must not emit dns-ip-preference:\n%s", conf)
					}
				}
			}
		}

		// Empty SS.Users with SS.Enabled=true and cipher 128 <-> 256 switch.
		ss128 := protocol.SSConfig{
			Enabled: true,
			TCPPort: 20002,
			UDPPort: 20003,
			Cipher:  protocol.CipherAES128GCM,
			IPSK:    b64Key(16, 1),
			STLSSNI: "[2001:db8::1]",
			Users:   nil,
		}
		raw, err := renderSingBoxJSON(ss128, 1053, 18080, 31002, true, true)
		if err != nil {
			t.Fatalf("renderSingBoxJSON IPv6 SNI + empty users failed: %v", err)
		}
		if !strings.Contains(string(raw), `"server": "2001:db8::1"`) || strings.Contains(string(raw), ": null") {
			t.Fatalf("unexpected rendered sing-box json:\n%s", string(raw))
		}
	})
}
