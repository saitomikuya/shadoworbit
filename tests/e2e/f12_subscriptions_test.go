//go:build e2e

package e2e_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func f12_makeIPSK16(t *testing.T, seed string) string {
	t.Helper()
	if len(seed) != 16 {
		t.Fatalf("f12_makeIPSK16 requires 16-byte seed, got %d (%q)", len(seed), seed)
	}
	enc := base64.StdEncoding.EncodeToString([]byte(seed))
	dec, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(dec) != 16 {
		t.Fatalf("invalid generated 16B IPSK %q: err=%v len=%d", enc, err, len(dec))
	}
	return enc
}

func f12_makeIPSK32(t *testing.T, seed string) string {
	t.Helper()
	if len(seed) != 32 {
		t.Fatalf("f12_makeIPSK32 requires 32-byte seed, got %d (%q)", len(seed), seed)
	}
	enc := base64.StdEncoding.EncodeToString([]byte(seed))
	dec, err := base64.StdEncoding.DecodeString(enc)
	if err != nil || len(dec) != 32 {
		t.Fatalf("invalid generated 32B IPSK %q: err=%v len=%d", enc, err, len(dec))
	}
	return enc
}

func f12_mustCreateNode(t *testing.T, client *PanelClient, jwt string, req CreateNodeReq) NodeDTO {
	t.Helper()
	st, node, raw, err := client.CreateNode(jwt, req)
	if err != nil || (st != http.StatusOK && st != http.StatusCreated) {
		t.Fatalf("CreateNode(%q) failed: st=%d err=%v body=%s", req.Name, st, err, string(raw))
	}
	return node
}

func f12_mustCreateUser(t *testing.T, client *PanelClient, jwt string, req CreateUserReq) UserDTO {
	t.Helper()
	st, user, raw, err := client.CreateUser(jwt, req)
	if err != nil || (st != http.StatusOK && st != http.StatusCreated) {
		t.Fatalf("CreateUser(%q) failed: st=%d err=%v body=%s", req.Username, st, err, string(raw))
	}
	return user
}

func f12_getTemplate(t *testing.T, client *PanelClient, jwt string, id int64) (int, SubTemplateDTO, []byte) {
	t.Helper()
	var out SubTemplateDTO
	st, raw, err := client.DoJSON(context.Background(), http.MethodGet, fmt.Sprintf("/api/v1/admin/templates/%d", id), jwt, nil, &out)
	if err != nil {
		t.Fatalf("GET /api/v1/admin/templates/%d error: %v (body=%s)", id, err, string(raw))
	}
	return st, out, raw
}

func f12_updateTemplate(t *testing.T, client *PanelClient, jwt string, id int64, req SubTemplateDTO) (int, SubTemplateDTO, []byte) {
	t.Helper()
	var out SubTemplateDTO
	st, raw, err := client.DoJSON(context.Background(), http.MethodPut, fmt.Sprintf("/api/v1/admin/templates/%d", id), jwt, req, &out)
	if err != nil {
		t.Fatalf("PUT /api/v1/admin/templates/%d error: %v (body=%s)", id, err, string(raw))
	}
	return st, out, raw
}

func f12_deleteTemplate(t *testing.T, client *PanelClient, jwt string, id int64) (int, []byte) {
	t.Helper()
	st, raw, err := client.DoJSON(context.Background(), http.MethodDelete, fmt.Sprintf("/api/v1/admin/templates/%d", id), jwt, nil, nil)
	if err != nil {
		t.Fatalf("DELETE /api/v1/admin/templates/%d error: %v (body=%s)", id, err, string(raw))
	}
	return st, raw
}

func f12_decodeBase64Flexible(s string) ([]byte, error) {
	trimmed := strings.TrimSpace(s)
	if b, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(trimmed); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(trimmed)
}

func f12_getAdminSubToken(t *testing.T, client *PanelClient, jwt string) string {
	t.Helper()
	st, settings, raw, err := client.GetSettings(jwt)
	if err != nil || st != http.StatusOK || settings.AdminSubToken == "" {
		t.Fatalf("GetSettings failed: st=%d err=%v settings=%+v body=%s", st, err, settings, string(raw))
	}
	return settings.AdminSubToken
}

func TestF12_Tier1_AdminSurgeSubFullProxyAndCustomTemplate(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	f12_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:            "Admin-Node-V5",
		RegionTag:       "JP",
		PublicIP:        "203.0.113.10",
		CustomEntryHost: "edge1.example.com",
		CustomEntryPort: 9443,
		Enabled:         boolPtr(true),
		SnellConfig: &SnellConfigDTO{
			Enabled: true, Version: "v5", PublicPort: 8443, InnerPort: 31001,
			PSK: "snell_psk_v5", Obfs: "off", TFO: true,
			STLSPassword: "stls_pwd_v5", STLSSNI: "gateway.icloud.com",
		},
	})
	f12_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:      "Admin-Node-V4",
		RegionTag: "US",
		PublicIP:  "203.0.113.20",
		Enabled:   boolPtr(true),
		SnellConfig: &SnellConfigDTO{
			Enabled: true, Version: "v4", PublicPort: 7443, InnerPort: 31002,
			PSK: "snell_psk_v4", Obfs: "http", TFO: false,
			STLSPassword: "stls_pwd_v4", STLSSNI: "itunes.apple.com",
		},
	})

	adminToken := f12_getAdminSubToken(t, client, jwt)

	// Full managed config
	stFull, _, bodyFull, err := client.GetAdminSub(adminToken, "")
	if err != nil || stFull != http.StatusOK {
		t.Fatalf("GET /s/admin full failed: st=%d err=%v body=%s", stFull, err, bodyFull)
	}
	lines := strings.Split(strings.TrimLeft(bodyFull, "\r\n"), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "#!MANAGED-CONFIG ") || !strings.Contains(lines[0], "/s/admin/"+adminToken) {
		t.Fatalf("expected #!MANAGED-CONFIG header on line 1, got:\n%s", bodyFull)
	}
	for _, want := range []string{
		"snell", "edge1.example.com", "9443", "203.0.113.20", "7443",
		"psk=snell_psk_v5", "psk=snell_psk_v4", "version=5", "version=4",
		"shadow-tls-password=stls_pwd_v5", "shadow-tls-sni=gateway.icloud.com", "shadow-tls-version=3",
		"[Proxy]", "[Proxy Group]", "[Rule]",
	} {
		if !strings.Contains(bodyFull, want) {
			t.Fatalf("admin full sub missing %q:\n%s", want, bodyFull)
		}
	}

	// Proxy list mode
	stProxy, _, bodyProxy, err := client.GetAdminSub(adminToken, "mode=proxy")
	if err != nil || stProxy != http.StatusOK {
		t.Fatalf("GET /s/admin?mode=proxy failed: st=%d err=%v body=%s", stProxy, err, bodyProxy)
	}
	if strings.Contains(bodyProxy, "#!MANAGED-CONFIG") || strings.Contains(bodyProxy, "[Rule]") {
		t.Fatalf("proxy mode should not include MANAGED-CONFIG or [Rule]:\n%s", bodyProxy)
	}
	if !strings.Contains(bodyProxy, "psk=snell_psk_v5") || !strings.Contains(bodyProxy, "psk=snell_psk_v4") {
		t.Fatalf("proxy mode missing snell nodes:\n%s", bodyProxy)
	}

	// Custom surge_admin template
	stTpl, tpl, rawTpl, err := client.CreateTemplate(jwt, SubTemplateDTO{
		Name:       "Custom Admin Surge",
		ClientType: "surge_admin",
		Content:    "{{MANAGED_CONFIG_HEADER}}\n# CUSTOM_ADMIN_TPL_MARKER\n[Proxy]\n{{PROXIES}}\n[Proxy Group]\nG = select, {{PROXY_NAMES}}\n[Rule]\nFINAL,G\n",
	})
	if err != nil || (stTpl != http.StatusOK && stTpl != http.StatusCreated) {
		t.Fatalf("CreateTemplate failed: st=%d err=%v body=%s", stTpl, err, string(rawTpl))
	}
	stCust, _, bodyCust, err := client.GetAdminSub(adminToken, fmt.Sprintf("tpl=%d", tpl.ID))
	if err != nil || stCust != http.StatusOK {
		t.Fatalf("GET /s/admin?tpl=%d failed: st=%d err=%v body=%s", tpl.ID, stCust, err, bodyCust)
	}
	if !strings.Contains(bodyCust, "# CUSTOM_ADMIN_TPL_MARKER") || !strings.Contains(bodyCust, "#!MANAGED-CONFIG ") || !strings.Contains(bodyCust, "psk=snell_psk_v5") {
		t.Fatalf("custom admin template did not render properly:\n%s", bodyCust)
	}
}

func TestF12_Tier1_UserMihomoYAMLAndAdaptiveUPSK(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	ipsk128 := f12_makeIPSK16(t, "f12-mihomo-128!!")
	ipsk256 := f12_makeIPSK32(t, "f12-mihomo-256-key-32bytes-long!")

	node128 := f12_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:            "HK-AES128",
		RegionTag:       "HK",
		PublicIP:        "198.51.100.11",
		CustomEntryHost: "u-edge.example.com",
		CustomEntryPort: 20443,
		Enabled:         boolPtr(true),
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: 10443, UDPPort: 10443,
			Cipher: "2022-blake3-aes-128-gcm", IPSK: ipsk128, STLSSNI: "swscan.apple.com",
		},
	})
	node256 := f12_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:      "SG-AES256",
		RegionTag: "SG",
		PublicIP:  "198.51.100.22",
		Enabled:   boolPtr(true),
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: 11443, UDPPort: 11443,
			Cipher: "2022-blake3-aes-256-gcm", IPSK: ipsk256, STLSSNI: "cdn.jsdelivr.net",
		},
	})

	user := f12_mustCreateUser(t, client, jwt, CreateUserReq{
		Username: "mihomo_user",
		NodeIDs:  []int64{node128.ID, node256.ID},
	})

	for _, modeQuery := range []string{"target=mihomo", "target=mihomo&mode=proxy"} {
		st, _, body, err := client.GetUserSub(user.SubToken, modeQuery, "")
		if err != nil || st != http.StatusOK {
			t.Fatalf("GetUserSub(%s) failed: st=%d err=%v body=%s", modeQuery, st, err, body)
		}

		var doc struct {
			Proxies []struct {
				Name              string         `yaml:"name"`
				Type              string         `yaml:"type"`
				Server            string         `yaml:"server"`
				Port              int            `yaml:"port"`
				Cipher            string         `yaml:"cipher"`
				Password          string         `yaml:"password"`
				UDP               bool           `yaml:"udp"`
				UDPOverTCP        bool           `yaml:"udp-over-tcp"`
				UDPOverTCPVersion int            `yaml:"udp-over-tcp-version"`
				ClientFingerprint string         `yaml:"client-fingerprint"`
				Plugin            string         `yaml:"plugin"`
				PluginOpts        map[string]any `yaml:"plugin-opts"`
			} `yaml:"proxies"`
		}
		if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
			t.Fatalf("invalid Mihomo YAML for %s: %v\nBody:\n%s", modeQuery, err, body)
		}
		if len(doc.Proxies) != 2 {
			t.Fatalf("expected 2 proxies in Mihomo YAML (%s), got %d:\n%s", modeQuery, len(doc.Proxies), body)
		}

		p1, p2 := doc.Proxies[0], doc.Proxies[1]
		if p1.Type != "ss" || p1.Server != "u-edge.example.com" || p1.Port != 20443 || p1.Cipher != "2022-blake3-aes-128-gcm" {
			t.Fatalf("unexpected node128 Mihomo entry: %+v", p1)
		}
		if p1.Password != ipsk128+":"+user.SSUPSK16 {
			t.Fatalf("node128 adaptive password mismatch: got %q want %q", p1.Password, ipsk128+":"+user.SSUPSK16)
		}
		if !p1.UDP || !p1.UDPOverTCP || p1.UDPOverTCPVersion != 2 || p1.ClientFingerprint != "chrome" || p1.Plugin != "shadow-tls" {
			t.Fatalf("node128 missing UoT/client-fingerprint/shadow-tls fields: %+v", p1)
		}
		if fmt.Sprint(p1.PluginOpts["version"]) != "3" || p1.PluginOpts["host"] != "swscan.apple.com" || p1.PluginOpts["password"] != user.STLSPassword {
			t.Fatalf("node128 plugin-opts mismatch: %+v", p1.PluginOpts)
		}

		if p2.Server != "198.51.100.22" || p2.Port != 11443 || p2.Cipher != "2022-blake3-aes-256-gcm" {
			t.Fatalf("unexpected node256 Mihomo entry: %+v", p2)
		}
		if p2.Password != ipsk256+":"+user.SSUPSK32 {
			t.Fatalf("node256 adaptive password mismatch: got %q", p2.Password)
		}
		if p2.ClientFingerprint != "chrome" {
			t.Fatalf("node256 expected client-fingerprint chrome, got %q", p2.ClientFingerprint)
		}
		if p2.PluginOpts["password"] != user.STLSPassword || p2.PluginOpts["host"] != "cdn.jsdelivr.net" {
			t.Fatalf("node256 plugin-opts mismatch: %+v", p2.PluginOpts)
		}
	}
}

func TestF12_Tier1_UserSurgeAndShadowrocketFormats(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	ipskFmt := f12_makeIPSK16(t, "f12-format-16byt")
	node := f12_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name:      "UserFormatsNode",
		RegionTag: "US",
		PublicIP:  "203.0.113.55",
		Enabled:   boolPtr(true),
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: 8443, UDPPort: 9443,
			Cipher: "2022-blake3-aes-128-gcm", IPSK: ipskFmt, STLSSNI: "gateway.icloud.com",
		},
	})
	user := f12_mustCreateUser(t, client, jwt, CreateUserReq{
		Username: "formats_user",
		NodeIDs:  []int64{node.ID},
	})

	// Surge full & proxy
	stSF, _, bodySF, err := client.GetUserSub(user.SubToken, "target=surge", "")
	if err != nil || stSF != http.StatusOK {
		t.Fatalf("GetUserSub(surge) failed: st=%d err=%v body=%s", stSF, err, bodySF)
	}
	if !strings.HasPrefix(strings.TrimLeft(bodySF, "\r\n"), "#!MANAGED-CONFIG ") {
		t.Fatalf("user surge full mode missing #!MANAGED-CONFIG:\n%s", bodySF)
	}
	for _, want := range []string{
		"ss, 203.0.113.55, 8443",
		"encrypt-method=2022-blake3-aes-128-gcm",
		"password=" + ipskFmt + ":" + user.SSUPSK16,
		"shadow-tls-password=" + user.STLSPassword,
		"shadow-tls-sni=gateway.icloud.com",
		"shadow-tls-version=3",
		"udp-relay=true",
		"udp-port=9443",
	} {
		if !strings.Contains(bodySF, want) {
			t.Fatalf("user surge output missing %q:\n%s", want, bodySF)
		}
	}

	stSP, _, bodySP, err := client.GetUserSub(user.SubToken, "target=surge&mode=proxy", "")
	if err != nil || stSP != http.StatusOK || strings.Contains(bodySP, "#!MANAGED-CONFIG") || !strings.Contains(bodySP, "udp-port=9443") {
		t.Fatalf("GetUserSub(surge&mode=proxy) unexpected: st=%d body=%s err=%v", stSP, bodySP, err)
	}

	// Shadowrocket Base64 ss:// with shadow-tls= & uot=1
	stSR, _, bodySR, err := client.GetUserSub(user.SubToken, "target=shadowrocket", "")
	if err != nil || stSR != http.StatusOK {
		t.Fatalf("GetUserSub(shadowrocket) failed: st=%d err=%v body=%s", stSR, err, bodySR)
	}
	decodedBytes, err := f12_decodeBase64Flexible(bodySR)
	if err != nil {
		t.Fatalf("shadowrocket body is not valid base64: %v (raw=%q)", err, bodySR)
	}
	decoded := strings.TrimSpace(string(decodedBytes))
	if !strings.HasPrefix(decoded, "ss://") {
		t.Fatalf("decoded shadowrocket body expected ss:// URI, got %q", decoded)
	}
	parsedURI, err := url.Parse(strings.Split(decoded, "\n")[0])
	if err != nil {
		t.Fatalf("parse ss:// URI %q: %v", decoded, err)
	}
	q := parsedURI.Query()
	if q.Get("uot") != "1" {
		t.Fatalf("expected uot=1 in shadowrocket URI, got %q", decoded)
	}
	stlsB64 := q.Get("shadow-tls")
	if stlsB64 == "" {
		t.Fatalf("missing shadow-tls query param in %q", decoded)
	}
	stlsJSONBytes, err := f12_decodeBase64Flexible(stlsB64)
	if err != nil {
		t.Fatalf("decode shadow-tls base64 %q: %v", stlsB64, err)
	}
	var stlsObj map[string]any
	if err := json.Unmarshal(stlsJSONBytes, &stlsObj); err != nil {
		t.Fatalf("unmarshal shadow-tls JSON %q: %v", string(stlsJSONBytes), err)
	}
	if fmt.Sprint(stlsObj["version"]) != "3" || stlsObj["password"] != user.STLSPassword || stlsObj["host"] != "gateway.icloud.com" {
		t.Fatalf("unexpected shadow-tls JSON params: %+v", stlsObj)
	}
	credRaw, err := f12_decodeBase64Flexible(parsedURI.User.Username())
	if err != nil {
		t.Fatalf("decode ss:// userinfo %q: %v", parsedURI.User.Username(), err)
	}
	wantCred := "2022-blake3-aes-128-gcm:" + ipskFmt + ":" + user.SSUPSK16
	if string(credRaw) != wantCred {
		t.Fatalf("shadowrocket ss:// userinfo mismatch: got %q want %q", string(credRaw), wantCred)
	}
}

func TestF12_Tier1_UADetectionAndUserinfoHeaders(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	node := f12_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name: "UANode", PublicIP: "203.0.113.66", Enabled: boolPtr(true),
		SSConfig: &SSConfigDTO{Enabled: true, TCPPort: 8443, UDPPort: 8443, Cipher: "2022-blake3-aes-128-gcm", IPSK: f12_makeIPSK16(t, "f12-ua-ipsk-16by"), STLSSNI: "gateway.icloud.com"},
	})
	expTime := time.Now().UTC().Add(72 * time.Hour).Truncate(time.Second)
	expStr := expTime.Format(time.RFC3339)
	user := f12_mustCreateUser(t, client, jwt, CreateUserReq{
		Username:          "ua_user",
		TrafficQuotaBytes: 100000,
		ExpireAt:          &expStr,
		NodeIDs:           []int64{node.ID},
	})

	// Report user traffic so upload/download are non-zero
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	_ = SendWSEnvelope(ctx, conn, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	_, _, _ = ReadWSEnvelope(ctx, conn, 3*time.Second)
	_ = SendWSEnvelope(ctx, conn, "agent.metrics", "m1", AgentMetricsPayload{
		TS: time.Now().Unix(),
		UserDeltas: []UserTrafficDeltaDTO{
			{Username: user.Username, UserID: user.ID, UpBytes: 1234, DownBytes: 5678},
		},
		Health: AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	})

	deadline := time.Now().Add(5 * time.Second)
	persisted := false
	for time.Now().Before(deadline) {
		_, gotU, _, _ := client.GetUser(jwt, user.ID)
		if gotU.UsedUpBytes == 1234 && gotU.UsedDownBytes == 5678 {
			persisted = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !persisted {
		_, gotU, _, _ := client.GetUser(jwt, user.ID)
		t.Fatalf("timed out waiting for user traffic (1234, 5678) to persist, last=%+v", gotU)
	}
	_ = conn.CloseNow()

	cases := []struct {
		ua     string
		verify func(t *testing.T, body string)
	}{
		{
			ua: "ClashMetaForAndroid/2.10 mihomo/1.18",
			verify: func(t *testing.T, body string) {
				if !strings.Contains(body, "proxies:") || !strings.Contains(body, "udp-over-tcp: true") {
					t.Fatalf("expected Mihomo YAML for Clash/Mihomo UA, got:\n%s", body)
				}
			},
		},
		{
			ua: "Surge iOS/3050",
			verify: func(t *testing.T, body string) {
				if !strings.Contains(body, "= ss,") || !strings.Contains(body, "udp-relay=true") {
					t.Fatalf("expected Surge INI for Surge UA, got:\n%s", body)
				}
			},
		},
		{
			ua: "Shadowrocket/2100 CFNetwork/1400",
			verify: func(t *testing.T, body string) {
				dec, err := f12_decodeBase64Flexible(body)
				if err != nil || !strings.Contains(string(dec), "ss://") {
					t.Fatalf("expected Base64 ss:// for Shadowrocket UA, err=%v raw=%q", err, body)
				}
			},
		},
		{
			ua: "CustomCurlClient/1.0",
			verify: func(t *testing.T, body string) {
				if !strings.Contains(body, "proxies:") {
					t.Fatalf("expected unknown UA fallback to Mihomo YAML, got:\n%s", body)
				}
			},
		},
	}

	wantUserinfo := fmt.Sprintf("upload=1234; download=5678; total=100000; expire=%d", expTime.Unix())
	for _, tc := range cases {
		st, hdr, body, err := client.GetUserSub(user.SubToken, "", tc.ua)
		if err != nil || st != http.StatusOK {
			t.Fatalf("GetUserSub(UA=%q) failed: st=%d err=%v body=%s", tc.ua, st, err, body)
		}
		tc.verify(t, body)
		if hdr.Get("Profile-Update-Interval") != "12" {
			t.Fatalf("UA=%q expected Profile-Update-Interval: 12, got %q", tc.ua, hdr.Get("Profile-Update-Interval"))
		}
		ui := hdr.Get("Subscription-Userinfo")
		if ui != wantUserinfo {
			t.Fatalf("UA=%q Subscription-Userinfo mismatch: got %q want %q", tc.ua, ui, wantUserinfo)
		}
	}
}

func TestF12_Tier1_CustomTemplateCRUDAndRendering(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	node := f12_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name: "TplRenderNode", PublicIP: "203.0.113.77", Enabled: boolPtr(true),
		SSConfig: &SSConfigDTO{Enabled: true, TCPPort: 8443, UDPPort: 8443, Cipher: "2022-blake3-aes-128-gcm", IPSK: f12_makeIPSK16(t, "f12-tpl-ipsk-16b"), STLSSNI: "gateway.icloud.com"},
	})
	user := f12_mustCreateUser(t, client, jwt, CreateUserReq{Username: "tpl_user", NodeIDs: []int64{node.ID}})

	// Default templates seeded
	stList, defaults, _, err := client.ListTemplates(jwt)
	if err != nil || stList != http.StatusOK || len(defaults) < 3 {
		t.Fatalf("ListTemplates failed: st=%d len=%d err=%v", stList, len(defaults), err)
	}

	// Create custom mihomo_user template
	stCreate, tpl, rawCreate, err := client.CreateTemplate(jwt, SubTemplateDTO{
		Name:       "MyMihomoTpl",
		ClientType: "mihomo_user",
		Content:    "custom-marker-v1: true\nproxies:\n{{PROXIES}}\nproxy-groups:\n  - name: CustomSel\n    type: select\n    proxies:\n{{PROXY_NAMES_YAML}}\nrules:\n  - MATCH,CustomSel\n",
	})
	if err != nil || (stCreate != http.StatusOK && stCreate != http.StatusCreated) {
		t.Fatalf("CreateTemplate failed: st=%d err=%v body=%s", stCreate, err, string(rawCreate))
	}

	// Get by ID
	stGet, gotTpl, _ := f12_getTemplate(t, client, jwt, tpl.ID)
	if stGet != http.StatusOK || gotTpl.Name != "MyMihomoTpl" {
		t.Fatalf("GetTemplate failed: st=%d got=%+v", stGet, gotTpl)
	}

	// Render with ?tpl=<id> and validate valid YAML
	stR1, _, bodyR1, err := client.GetUserSub(user.SubToken, fmt.Sprintf("target=mihomo&tpl=%d", tpl.ID), "")
	if err != nil || stR1 != http.StatusOK || !strings.Contains(bodyR1, "custom-marker-v1: true") {
		t.Fatalf("render custom mihomo tpl v1 failed: st=%d err=%v body=%s", stR1, err, bodyR1)
	}
	var yDoc1 map[string]any
	if err := yaml.Unmarshal([]byte(bodyR1), &yDoc1); err != nil {
		t.Fatalf("custom mihomo tpl v1 rendered invalid YAML: %v\n%s", err, bodyR1)
	}

	// Update template
	stUpd, updTpl, rawUpd := f12_updateTemplate(t, client, jwt, tpl.ID, SubTemplateDTO{
		Name:       "MyMihomoTplV2",
		ClientType: "mihomo_user",
		Content:    "custom-marker-v2: true\nproxies:\n{{PROXIES}}\nproxy-groups:\n  - name: CustomSel\n    type: select\n    proxies:\n{{PROXY_NAMES_YAML}}\nrules:\n  - MATCH,CustomSel\n",
	})
	if stUpd != http.StatusOK || updTpl.Name != "MyMihomoTplV2" {
		t.Fatalf("UpdateTemplate failed: st=%d upd=%+v body=%s", stUpd, updTpl, string(rawUpd))
	}
	stR2, _, bodyR2, err := client.GetUserSub(user.SubToken, fmt.Sprintf("target=mihomo&tpl=%d", tpl.ID), "")
	if err != nil || stR2 != http.StatusOK || !strings.Contains(bodyR2, "custom-marker-v2: true") {
		t.Fatalf("render custom mihomo tpl v2 failed: st=%d err=%v body=%s", stR2, err, bodyR2)
	}
	var yDoc2 map[string]any
	if err := yaml.Unmarshal([]byte(bodyR2), &yDoc2); err != nil {
		t.Fatalf("custom mihomo tpl v2 rendered invalid YAML: %v\n%s", err, bodyR2)
	}

	// Also test custom surge_user template
	stSurgeTpl, surgeTpl, _, err := client.CreateTemplate(jwt, SubTemplateDTO{
		Name:       "MySurgeUserTpl",
		ClientType: "surge_user",
		Content:    "{{MANAGED_CONFIG_HEADER}}\n# CUSTOM_SURGE_USER_MARKER\n[Proxy]\n{{PROXIES}}\n[Proxy Group]\nG = select, {{PROXY_NAMES}}\n[Rule]\nFINAL,G\n",
	})
	if err != nil || (stSurgeTpl != http.StatusOK && stSurgeTpl != http.StatusCreated) {
		t.Fatal(err)
	}
	stRS, _, bodyRS, err := client.GetUserSub(user.SubToken, fmt.Sprintf("target=surge&tpl=%d", surgeTpl.ID), "")
	if err != nil || stRS != http.StatusOK || !strings.Contains(bodyRS, "# CUSTOM_SURGE_USER_MARKER") {
		t.Fatalf("render custom surge_user tpl failed: st=%d err=%v body=%s", stRS, err, bodyRS)
	}

	// Delete template
	stDel, rawDel := f12_deleteTemplate(t, client, jwt, tpl.ID)
	if stDel < 200 || stDel >= 300 {
		t.Fatalf("DeleteTemplate failed: st=%d body=%s", stDel, string(rawDel))
	}
	stAfter, _, _ := f12_getTemplate(t, client, jwt, tpl.ID)
	if stAfter != http.StatusNotFound {
		t.Fatalf("expected 404 after DeleteTemplate, got %d", stAfter)
	}
}

func TestF12_Tier2_StrictDualTrackProtocolIsolation(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	userIPSK := f12_makeIPSK16(t, "f12-iso-canary16")
	node := f12_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name: "DualIsolationNode", PublicIP: "203.0.113.88", Enabled: boolPtr(true),
		SnellConfig: &SnellConfigDTO{
			Enabled: true, Version: "v5", PublicPort: 41111, InnerPort: 31001,
			PSK: "CANARY_ADMIN_SNELL_PSK", Obfs: "off", TFO: true,
			STLSPassword: "CANARY_ADMIN_STLS_PWD", STLSSNI: "admin-only.sni.internal",
		},
		SSConfig: &SSConfigDTO{
			Enabled: true, TCPPort: 42222, UDPPort: 42223,
			Cipher: "2022-blake3-aes-128-gcm", IPSK: userIPSK, STLSSNI: "user-only.sni.internal",
		},
	})
	user := f12_mustCreateUser(t, client, jwt, CreateUserReq{Username: "iso_user", NodeIDs: []int64{node.ID}})
	adminToken := f12_getAdminSubToken(t, client, jwt)

	// User subscription must render SS2022+ShadowTLS AND NEVER leak Snell or admin secrets
	adminSecrets := []string{
		"snell", "CANARY_ADMIN_SNELL_PSK", "CANARY_ADMIN_STLS_PWD",
		"41111", "admin-only.sni.internal", adminToken,
	}
	for _, q := range []string{
		"target=mihomo", "target=mihomo&mode=proxy",
		"target=surge", "target=surge&mode=proxy",
		"target=shadowrocket",
	} {
		st, _, body, err := client.GetUserSub(user.SubToken, q, "")
		if err != nil || st != http.StatusOK {
			t.Fatalf("GetUserSub(%s) failed: st=%d err=%v", q, st, err)
		}
		checkText := body
		if strings.Contains(q, "shadowrocket") {
			dec, err := f12_decodeBase64Flexible(body)
			if err != nil {
				t.Fatalf("decode shadowrocket sub failed: %v (raw=%q)", err, body)
			}
			decodedURI := string(dec)
			checkText += "\n" + decodedURI
			if parsed, err := url.Parse(strings.TrimSpace(strings.Split(decodedURI, "\n")[0])); err == nil {
				if cred, err := f12_decodeBase64Flexible(parsed.User.Username()); err == nil {
					checkText += "\n" + string(cred)
				}
				if stlsParam := parsed.Query().Get("shadow-tls"); stlsParam != "" {
					if stlsDec, err := f12_decodeBase64Flexible(stlsParam); err == nil {
						checkText += "\n" + string(stlsDec)
					}
				}
			}
		}
		for _, want := range []string{"DualIsolationNode", "42222", "user-only.sni.internal", user.SSUPSK16, user.STLSPassword} {
			if !strings.Contains(checkText, want) {
				t.Fatalf("user sub (%s) missing expected SS2022 node/credential %q:\n%s", q, want, checkText)
			}
		}
		lower := strings.ToLower(checkText)
		for _, sec := range adminSecrets {
			if strings.Contains(checkText, sec) || strings.Contains(lower, strings.ToLower(sec)) {
				t.Fatalf("PROTOCOL LEAK in user sub (%s): found %q in:\n%s", q, sec, checkText)
			}
		}
	}

	// Admin subscription must render Snell+ShadowTLS AND NEVER leak SS2022 or user secrets
	userSecrets := []string{
		"2022-blake3", userIPSK, "42222", "42223",
		"user-only.sni.internal", user.SSUPSK16, user.SSUPSK32, user.STLSPassword, user.SubToken,
	}
	for _, q := range []string{"", "mode=proxy"} {
		st, _, body, err := client.GetAdminSub(adminToken, q)
		if err != nil || st != http.StatusOK {
			t.Fatalf("GetAdminSub(%s) failed: st=%d err=%v", q, st, err)
		}
		for _, want := range []string{"DualIsolationNode", "snell", "41111", "CANARY_ADMIN_SNELL_PSK", "CANARY_ADMIN_STLS_PWD", "admin-only.sni.internal"} {
			if !strings.Contains(body, want) {
				t.Fatalf("admin sub (%s) missing expected Snell field %q:\n%s", q, want, body)
			}
		}
		for _, sec := range userSecrets {
			if strings.Contains(body, sec) {
				t.Fatalf("PROTOCOL LEAK in admin sub (%s): found %q in:\n%s", q, sec, body)
			}
		}
	}
}

func TestF12_Tier2_DisabledExpiredOverQuotaUserRejected(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	node := f12_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name: "SubRejectNode", PublicIP: "203.0.113.90", Enabled: boolPtr(true),
		SSConfig: &SSConfigDTO{Enabled: true, TCPPort: 8443, UDPPort: 8443, Cipher: "2022-blake3-aes-128-gcm", IPSK: f12_makeIPSK16(t, "f12-rej-ipsk-16b"), STLSSNI: "gateway.icloud.com"},
	})

	// 1. Disabled user
	disUser := f12_mustCreateUser(t, client, jwt, CreateUserReq{
		Username: "disabled_sub", Enabled: boolPtr(false), NodeIDs: []int64{node.ID},
	})
	if st, _, body, _ := client.GetUserSub(disUser.SubToken, "target=mihomo", ""); st != http.StatusForbidden && st != http.StatusNotFound {
		t.Fatalf("disabled user sub expected 403/404, got %d (body=%s)", st, body)
	}

	// 2. Expired user
	past := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
	expUser := f12_mustCreateUser(t, client, jwt, CreateUserReq{
		Username: "expired_sub", Enabled: boolPtr(true), ExpireAt: &past, NodeIDs: []int64{node.ID},
	})
	if st, _, body, _ := client.GetUserSub(expUser.SubToken, "target=mihomo", ""); st != http.StatusForbidden && st != http.StatusNotFound {
		t.Fatalf("expired user sub expected 403/404, got %d (body=%s)", st, body)
	}

	// 3. Over-quota user
	quotaUser := f12_mustCreateUser(t, client, jwt, CreateUserReq{
		Username: "overquota_sub", Enabled: boolPtr(true), TrafficQuotaBytes: 1000, NodeIDs: []int64{node.ID},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, _, err := client.DialAgentWS(ctx, node.EffectiveToken())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	_ = SendWSEnvelope(ctx, conn, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
	_, _, _ = ReadWSEnvelope(ctx, conn, 3*time.Second)
	_ = SendWSEnvelope(ctx, conn, "agent.metrics", "m1", AgentMetricsPayload{
		TS:         time.Now().Unix(),
		UserDeltas: []UserTrafficDeltaDTO{{Username: quotaUser.Username, UserID: quotaUser.ID, UpBytes: 600, DownBytes: 400}},
		Health:     AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
	})

	deadline := time.Now().Add(5 * time.Second)
	quotaPersisted := false
	for time.Now().Before(deadline) {
		_, gotU, _, _ := client.GetUser(jwt, quotaUser.ID)
		if gotU.UsedUpBytes+gotU.UsedDownBytes >= 1000 {
			quotaPersisted = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !quotaPersisted {
		_, gotU, _, _ := client.GetUser(jwt, quotaUser.ID)
		t.Fatalf("timed out waiting for quotaUser traffic >= 1000, last=%+v", gotU)
	}
	_ = conn.CloseNow()
	if st, _, body, _ := client.GetUserSub(quotaUser.SubToken, "target=mihomo", ""); st != http.StatusForbidden && st != http.StatusNotFound {
		t.Fatalf("over-quota user sub expected 403/404, got %d (body=%s)", st, body)
	}
}

func TestF12_Tier2_InvalidAndCrossTrackTokensRejected(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	user := f12_mustCreateUser(t, client, jwt, CreateUserReq{Username: "token_check_user"})
	adminToken := f12_getAdminSubToken(t, client, jwt)

	checks := []struct {
		name string
		fn   func() (int, http.Header, string, error)
	}{
		{"unknown_user_token", func() (int, http.Header, string, error) { return client.GetUserSub("unknown_sub_token_999", "", "") }},
		{"unknown_admin_token", func() (int, http.Header, string, error) { return client.GetAdminSub("unknown_admin_token_999", "") }},
		{"admin_token_on_user_route", func() (int, http.Header, string, error) { return client.GetUserSub(adminToken, "", "") }},
		{"user_token_on_admin_route", func() (int, http.Header, string, error) { return client.GetAdminSub(user.SubToken, "") }},
	}
	for _, tc := range checks {
		st, _, body, err := tc.fn()
		if err != nil {
			t.Fatal(err)
		}
		if st != http.StatusUnauthorized && st != http.StatusForbidden && st != http.StatusNotFound {
			t.Fatalf("%s expected 401/403/404, got %d (body=%s)", tc.name, st, body)
		}
	}

	// Deleted user's sub_token rejected
	deletedSubTok := user.SubToken
	if stDel, _, err := client.DeleteUser(jwt, user.ID); err != nil || stDel >= 300 {
		t.Fatal(err)
	}
	stAfter, _, bodyAfter, _ := client.GetUserSub(deletedSubTok, "", "")
	if stAfter != http.StatusUnauthorized && stAfter != http.StatusForbidden && stAfter != http.StatusNotFound {
		t.Fatalf("deleted user sub_token expected 401/403/404, got %d (body=%s)", stAfter, bodyAfter)
	}
}

func TestF12_Tier2_TrafficPausedNodeSubscriptionFiltering(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	nStopAll := f12_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name: "Sub-StopAll-Node", PublicIP: "203.0.113.101", Enabled: boolPtr(true),
		TrafficLimitBytes: 2000, TrafficThresholdBytes: 1000, TrafficCountMode: "both", ThresholdAction: "stop_all",
		SnellConfig: &SnellConfigDTO{Enabled: true, Version: "v5", PublicPort: 21001, InnerPort: 31001, PSK: "PSK_STOP_ALL", STLSPassword: "STLS_STOP_ALL", STLSSNI: "gateway.icloud.com"},
		SSConfig:    &SSConfigDTO{Enabled: true, TCPPort: 21002, UDPPort: 21002, Cipher: "2022-blake3-aes-128-gcm", IPSK: f12_makeIPSK16(t, "f12-stopall-16by"), STLSSNI: "swscan.apple.com"},
	})
	nStopSS := f12_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name: "Sub-StopSSOnly-Node", PublicIP: "203.0.113.102", Enabled: boolPtr(true),
		TrafficLimitBytes: 2000, TrafficThresholdBytes: 1000, TrafficCountMode: "both", ThresholdAction: "stop_ss_only",
		SnellConfig: &SnellConfigDTO{Enabled: true, Version: "v5", PublicPort: 22001, InnerPort: 31002, PSK: "PSK_STOP_SS_ONLY", STLSPassword: "STLS_STOP_SS", STLSSNI: "gateway.icloud.com"},
		SSConfig:    &SSConfigDTO{Enabled: true, TCPPort: 22002, UDPPort: 22002, Cipher: "2022-blake3-aes-128-gcm", IPSK: f12_makeIPSK16(t, "f12-stopss-16byt"), STLSSNI: "swscan.apple.com"},
	})
	nHealthy := f12_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name: "Sub-Healthy-Node", PublicIP: "203.0.113.103", Enabled: boolPtr(true),
		TrafficLimitBytes: 0, TrafficThresholdBytes: 0,
		SnellConfig: &SnellConfigDTO{Enabled: true, Version: "v5", PublicPort: 23001, InnerPort: 31003, PSK: "PSK_HEALTHY", STLSPassword: "STLS_HEALTHY", STLSSNI: "gateway.icloud.com"},
		SSConfig:    &SSConfigDTO{Enabled: true, TCPPort: 23002, UDPPort: 23002, Cipher: "2022-blake3-aes-128-gcm", IPSK: f12_makeIPSK16(t, "f12-healthy-16by"), STLSSNI: "swscan.apple.com"},
	})

	user := f12_mustCreateUser(t, client, jwt, CreateUserReq{
		Username: "paused_filter_user",
		NodeIDs:  []int64{nStopAll.ID, nStopSS.ID, nHealthy.ID},
	})

	// Pause nStopAll and nStopSS; keep WS connections open until polling confirms DB pause state
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, n := range []NodeDTO{nStopAll, nStopSS} {
		conn, _, err := client.DialAgentWS(ctx, n.EffectiveToken())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.CloseNow()
		_ = SendWSEnvelope(ctx, conn, "agent.hello", "h1", AgentHelloPayload{OS: "linux", Arch: "amd64"})
		_, _, _ = ReadWSEnvelope(ctx, conn, 3*time.Second)
		_ = SendWSEnvelope(ctx, conn, "agent.metrics", "m1", AgentMetricsPayload{
			TS: time.Now().Unix(), NicRxDelta: 600, NicTxDelta: 600,
			Health: AgentHealthDTO{Snell: true, ShadowTLS: true, SingBox: true},
		})
	}

	deadline := time.Now().Add(5 * time.Second)
	bothPaused := false
	for time.Now().Before(deadline) {
		_, g1, _, _ := client.GetNode(jwt, nStopAll.ID)
		_, g2, _, _ := client.GetNode(jwt, nStopSS.ID)
		if g1.IsTrafficPaused && g2.IsTrafficPaused {
			bothPaused = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !bothPaused {
		_, g1, _, _ := client.GetNode(jwt, nStopAll.ID)
		_, g2, _, _ := client.GetNode(jwt, nStopSS.ID)
		t.Fatalf("timed out waiting for nStopAll and nStopSS to pause: g1=%+v g2=%+v", g1, g2)
	}

	// Admin sub: omits stop_all node, KEEPS stop_ss_only node and healthy node
	adminToken := f12_getAdminSubToken(t, client, jwt)
	stAdm, _, bodyAdm, err := client.GetAdminSub(adminToken, "mode=proxy")
	if err != nil || stAdm != http.StatusOK {
		t.Fatalf("GetAdminSub failed: st=%d err=%v", stAdm, err)
	}
	if strings.Contains(bodyAdm, "Sub-StopAll-Node") || strings.Contains(bodyAdm, "PSK_STOP_ALL") {
		t.Fatalf("admin sub must omit stop_all paused node:\n%s", bodyAdm)
	}
	if !strings.Contains(bodyAdm, "Sub-StopSSOnly-Node") || !strings.Contains(bodyAdm, "Sub-Healthy-Node") {
		t.Fatalf("admin sub must keep stop_ss_only and healthy nodes:\n%s", bodyAdm)
	}

	// User sub: omits BOTH stop_all and stop_ss_only nodes, keeps healthy node
	for _, q := range []string{"target=mihomo", "target=surge", "target=shadowrocket"} {
		stU, _, bodyU, err := client.GetUserSub(user.SubToken, q, "")
		if err != nil || stU != http.StatusOK {
			t.Fatalf("GetUserSub(%s) failed: st=%d err=%v", q, stU, err)
		}
		checkText := bodyU
		if q == "target=shadowrocket" {
			dec, err := f12_decodeBase64Flexible(bodyU)
			if err != nil {
				t.Fatal(err)
			}
			checkText = string(dec)
		}
		if strings.Contains(checkText, "Sub-StopAll-Node") || strings.Contains(checkText, "Sub-StopSSOnly-Node") {
			t.Fatalf("user sub (%s) must omit both stop_all and stop_ss_only paused nodes:\n%s", q, checkText)
		}
		if !strings.Contains(checkText, "Sub-Healthy-Node") {
			t.Fatalf("user sub (%s) missing healthy node:\n%s", q, checkText)
		}
	}
}

func TestF12_Tier2_InvalidTargetAndDeletedTemplateFallback(t *testing.T) {
	env := NewTestEnv(t)
	panel := StartPanel(env, PanelConfig{})
	client := panel.NewClient()
	jwt := client.MustLogin(t, "admin", "change_me_on_first_login")

	fbIPSK := f12_makeIPSK16(t, "f12-fallback-16b")
	node := f12_mustCreateNode(t, client, jwt, CreateNodeReq{
		Name: "FallbackNode", PublicIP: "203.0.113.110", Enabled: boolPtr(true),
		SnellConfig: &SnellConfigDTO{Enabled: true, Version: "v5", PublicPort: 24001, InnerPort: 31001, PSK: "PSK_FB", STLSPassword: "STLS_FB", STLSSNI: "gateway.icloud.com"},
		SSConfig:    &SSConfigDTO{Enabled: true, TCPPort: 24002, UDPPort: 24002, Cipher: "2022-blake3-aes-128-gcm", IPSK: fbIPSK, STLSSNI: "swscan.apple.com"},
	})
	user := f12_mustCreateUser(t, client, jwt, CreateUserReq{Username: "fb_user", NodeIDs: []int64{node.ID}})
	zeroNodeUser := f12_mustCreateUser(t, client, jwt, CreateUserReq{Username: "zero_nodes_user"})
	adminToken := f12_getAdminSubToken(t, client, jwt)

	assertSubFallbackOrRejected := func(desc string, st int, body string) {
		switch st {
		case http.StatusOK:
			if strings.TrimSpace(body) == "" {
				t.Fatalf("%s returned 200 with empty body", desc)
			}
		case http.StatusBadRequest, http.StatusNotFound:
		default:
			t.Fatalf("%s expected 200 (valid fallback), 400, or 404, got %d (body=%s)", desc, st, body)
		}
	}

	// Invalid target must return 400/404 or 200 with valid fallback (never 3xx/401/403/405/5xx)
	stBadTarget, _, bodyBadTarget, err := client.GetUserSub(user.SubToken, "target=unknown_client", "")
	if err != nil {
		t.Fatal(err)
	}
	assertSubFallbackOrRejected("invalid target", stBadTarget, bodyBadTarget)

	// Deleted & nonexistent template must return 400/404 or 200 with valid fallback
	_, tmpTpl, _, err := client.CreateTemplate(jwt, SubTemplateDTO{
		Name: "EphemeralTpl", ClientType: "mihomo_user", Content: "proxies:\n{{PROXIES}}\n",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f12_deleteTemplate(t, client, jwt, tmpTpl.ID)

	for _, q := range []string{
		fmt.Sprintf("target=mihomo&tpl=%d", tmpTpl.ID),
		"target=mihomo&tpl=99999",
		"target=surge&tpl=99999",
	} {
		st, _, body, err := client.GetUserSub(user.SubToken, q, "")
		if err != nil {
			t.Fatal(err)
		}
		assertSubFallbackOrRejected("user sub ("+q+")", st, body)
	}
	stAdmTpl, _, bodyAdmTpl, err := client.GetAdminSub(adminToken, "tpl=99999")
	if err != nil {
		t.Fatal(err)
	}
	assertSubFallbackOrRejected("admin sub (tpl=99999)", stAdmTpl, bodyAdmTpl)

	// User with 0 authorized nodes returns clean 200 without leaking FallbackNode
	for _, target := range []string{"mihomo", "surge", "shadowrocket"} {
		stZ, _, bodyZ, err := client.GetUserSub(zeroNodeUser.SubToken, "target="+target, "")
		if err != nil {
			t.Fatal(err)
		}
		if stZ != http.StatusOK {
			t.Fatalf("zero-node user sub (target=%s) expected 200, got %d (body=%s)", target, stZ, bodyZ)
		}
		if strings.Contains(bodyZ, "FallbackNode") || strings.Contains(bodyZ, fbIPSK) {
			t.Fatalf("zero-node user sub leaked unauthorized node: %s", bodyZ)
		}
	}
}
