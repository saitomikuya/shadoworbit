package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"snell-panel/internal/protocol"
)

// SeedConfig controls initial insert-if-missing database seeding on startup.
type SeedConfig struct {
	AdminInitialPass string // defaults to "admin123" if empty
	JWTSecret        string // optional; random 32-byte base64 generated if empty & unset in DB
}

// SeedDefaults inserts default system_settings and sub_templates if missing.
// Existing values (including rotated passwords or edited templates) are never overwritten.
func (s *Store) SeedDefaults(ctx context.Context, cfg SeedConfig) error {
	if cfg.JWTSecret != "" {
		if err := validateJWTSecret(cfg.JWTSecret); err != nil {
			return err
		}
	}

	adminPass := cfg.AdminInitialPass
	if adminPass == "" {
		adminPass = "admin123"
	}

	now := FormatSQLiteTime(time.Now().UTC())

	return s.withTx(ctx, func(tx *sql.Tx) error {
		insertIfMissing := func(key, value string) error {
			_, err := tx.ExecContext(ctx,
				`INSERT OR IGNORE INTO system_settings(key, value, updated_at) VALUES (?, ?, ?)`,
				key, value, now,
			)
			return err
		}

		// Check admin_password_hash existence before computing bcrypt hash.
		var existingPassHash string
		err := tx.QueryRowContext(ctx,
			`SELECT value FROM system_settings WHERE key = 'admin_password_hash'`,
		).Scan(&existingPassHash)
		if err == sql.ErrNoRows || existingPassHash == "" {
			hashed, hashErr := bcrypt.GenerateFromPassword([]byte(adminPass), bcrypt.DefaultCost)
			if hashErr != nil {
				return fmt.Errorf("store: hash initial admin password: %w", hashErr)
			}
			if err == sql.ErrNoRows {
				if err := insertIfMissing("admin_password_hash", string(hashed)); err != nil {
					return err
				}
			} else {
				if _, err := tx.ExecContext(ctx,
					`UPDATE system_settings SET value = ?, updated_at = ? WHERE key = 'admin_password_hash' AND value = ''`,
					string(hashed), now,
				); err != nil {
					return err
				}
			}
		} else if err != nil {
			return fmt.Errorf("store: check admin_password_hash: %w", err)
		}

		adminSubToken, err := randomHex(24)
		if err != nil {
			return fmt.Errorf("store: generate admin_sub_token: %w", err)
		}

		jwtSecret := cfg.JWTSecret
		if jwtSecret == "" {
			jwtSecret, err = randomBase64(32)
			if err != nil {
				return fmt.Errorf("store: generate jwt_secret: %w", err)
			}
		}

		defaultSettings := []struct {
			key   string
			value string
		}{
			{"admin_sub_token", "adm_" + adminSubToken},
			{"jwt_secret", jwtSecret},
			{"site_title", "ShadowOrbit"},
			{"announcement", ""},
			{"public_percentage_only", "false"},
			{"alert_cooldown_minutes", "15"},
			{"warning_threshold_percent", "85"},
			{"offline_timeout_seconds", "60"},
			{"alert_user_expired", "true"},
			{"alert_user_quota_exhausted", "true"},
			{"default_upstream_dns", "1.1.1.1:53"},
			{"default_local_dns_port", "15353"},
			{"agent_docker_image", "saitomikuya/shadoworbit-agent:latest"},
			{"traffic_log_max_entries", "10000"},
			{"kernel_versions_cache", "{}"},
		}

		for _, kv := range defaultSettings {
			if err := insertIfMissing(kv.key, kv.value); err != nil {
				return fmt.Errorf("store: seed setting %s: %w", kv.key, err)
			}
		}

		defaultTemplates := []struct {
			name       string
			clientType string
			content    string
		}{
			{
				name:       "管理员 Surge 机场规则模板",
				clientType: protocol.ClientTypeSurgeAdmin,
				content:    defaultSurgeAdminTemplate,
			},
			{
				name:       "用户 Clash / Mihomo 机场规则模板",
				clientType: protocol.ClientTypeMihomoUser,
				content:    defaultMihomoUserTemplate,
			},
			{
				name:       "用户 Surge 机场规则模板",
				clientType: protocol.ClientTypeSurgeUser,
				content:    defaultSurgeUserTemplate,
			},
		}

		for _, tpl := range defaultTemplates {
			var count int
			if err := tx.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM sub_templates WHERE client_type = ?`,
				tpl.clientType,
			).Scan(&count); err != nil {
				return fmt.Errorf("store: count templates for %s: %w", tpl.clientType, err)
			}
			if count == 0 {
				if _, err := tx.ExecContext(ctx,
					`INSERT INTO sub_templates(name, client_type, content, is_default, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)`,
					tpl.name, tpl.clientType, tpl.content, now, now,
				); err != nil {
					return fmt.Errorf("store: seed template %s: %w", tpl.clientType, err)
				}
			}
		}

		var dnsSeeded string
		_ = tx.QueryRowContext(ctx, `SELECT value FROM system_settings WHERE key = 'seeded_default_dns_rules'`).Scan(&dnsSeeded)
		if dnsSeeded == "" {
			var dnsCount int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM dns_rule_groups`).Scan(&dnsCount); err != nil {
				return fmt.Errorf("store: count dns_rule_groups: %w", err)
			}
			if dnsCount == 0 {
				if _, err := tx.ExecContext(ctx,
					`INSERT INTO dns_rule_groups(name, description, rules, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
					"主流流媒体与 AI 解锁",
					"覆盖 Netflix、Disney+、YouTube、ChatGPT/OpenAI、Claude、Gemini、TikTok、Spotify 等常用流媒体与 AI 服务域名",
					defaultDNSUnlockRulesJSON,
					now,
					now,
				); err != nil {
					return fmt.Errorf("store: seed default dns rule group: %w", err)
				}
			}
			if err := insertIfMissing("seeded_default_dns_rules", "1"); err != nil {
				return fmt.Errorf("store: mark seeded_default_dns_rules: %w", err)
			}
		}

		return nil
	})
}

func validateJWTSecret(raw string) error {
	if raw == "" || strings.TrimSpace(raw) == "" || strings.ContainsAny(raw, "\r\n\x00") {
		return fmt.Errorf("%w: jwt_secret must be non-empty single-line", ErrInvalidArgument)
	}
	if decoded, err := hex.DecodeString(raw); err == nil {
		if len(decoded) < 32 {
			return fmt.Errorf("%w: hex jwt_secret must decode to at least 32 bytes (got %d)", ErrInvalidArgument, len(decoded))
		}
		return nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil {
		if len(decoded) < 32 {
			return fmt.Errorf("%w: base64 jwt_secret must decode to at least 32 bytes (got %d)", ErrInvalidArgument, len(decoded))
		}
		return nil
	}
	if len(strings.TrimSpace(raw)) >= 32 && len(raw) >= 32 {
		return nil
	}
	return fmt.Errorf("%w: jwt_secret must be at least 32 bytes (raw, base64-decoded, or hex-decoded)", ErrInvalidArgument)
}

func randomHex(nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func randomBase64(nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

const defaultDNSUnlockRulesJSON = `["netflix.com","netflix.net","nflximg.net","nflximg.com","nflxvideo.net","nflxso.net","nflxext.com","fast.com","disneyplus.com","disney-plus.net","disneystreaming.com","dssott.com","bamgrid.com","youtube.com","youtu.be","ytimg.com","googlevideo.com","yt.be","youtubei.googleapis.com","openai.com","chatgpt.com","oaistatic.com","oaiusercontent.com","auth0.com","ai.com","claude.ai","anthropic.com","gemini.google.com","aistudio.google.com","makersuite.google.com","generativelanguage.googleapis.com","geller-pa.googleapis.com","proactivebackend-pa.googleapis.com","tiktok.com","tiktokv.com","tiktokcdn.com","musical.ly","byteoversea.com","spotify.com","scdn.co","bahamut.com.tw","gamer.com.tw","max.com","hbomax.com","hulu.com"]`

const defaultSurgeAdminTemplate = `{{MANAGED_CONFIG_HEADER}}
[General]
loglevel = notify
bypass-system = true
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local
dns-server = 223.5.5.5, 119.29.29.29, system
encrypted-dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query
ipv6 = true
show-error-page-for-reject = true
proxy-test-url = http://www.gstatic.com/generate_204
internet-test-url = http://connectivitycheck.platform.hicloud.com/generate_204
test-timeout = 3

[Proxy]
{{PROXIES}}

[Proxy Group]
🚀 节点选择 = select, ♻️ 自动选择, 🔯 故障转移, {{PROXY_NAMES}}, DIRECT
♻️ 自动选择 = url-test, {{PROXY_NAMES}}, url = http://www.gstatic.com/generate_204, interval = 300, tolerance = 50
🔯 故障转移 = fallback, {{PROXY_NAMES}}, url = http://www.gstatic.com/generate_204, interval = 300
🤖 AI 服务 = select, 🚀 节点选择, ♻️ 自动选择, {{PROXY_NAMES}}, DIRECT
🎬 国际媒体 = select, 🚀 节点选择, ♻️ 自动选择, {{PROXY_NAMES}}, DIRECT
🎵 TikTok = select, 🚀 节点选择, ♻️ 自动选择, {{PROXY_NAMES}}, DIRECT
🎶 Spotify = select, 🚀 节点选择, ♻️ 自动选择, {{PROXY_NAMES}}, DIRECT
📲 Telegram = select, 🚀 节点选择, ♻️ 自动选择, {{PROXY_NAMES}}, DIRECT
🍎 苹果服务 = select, 🎯 全球直连, 🚀 节点选择, ♻️ 自动选择
🔍 谷歌服务 = select, 🚀 节点选择, ♻️ 自动选择, {{PROXY_NAMES}}, DIRECT
🛑 广告拦截 = select, REJECT, DIRECT
🎯 全球直连 = select, DIRECT, 🚀 节点选择
🐟 漏网之鱼 = select, 🚀 节点选择, ♻️ 自动选择, DIRECT

[Rule]
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Lan/Lan.list,🎯 全球直连
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/AdvertisingLite/AdvertisingLite.list,🛑 广告拦截
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/OpenAI/OpenAI.list,🤖 AI 服务
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Claude/Claude.list,🤖 AI 服务
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Gemini/Gemini.list,🤖 AI 服务
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/YouTube/YouTube.list,🎬 国际媒体
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Netflix/Netflix.list,🎬 国际媒体
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Disney/Disney.list,🎬 国际媒体
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/TikTok/TikTok.list,🎵 TikTok
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Spotify/Spotify.list,🎶 Spotify
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Telegram/Telegram.list,📲 Telegram
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Apple/Apple.list,🍎 苹果服务
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Google/Google.list,🔍 谷歌服务
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Global/Global.list,🚀 节点选择
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/ChinaMax/ChinaMax.list,🎯 全球直连
GEOIP,CN,🎯 全球直连
FINAL,🐟 漏网之鱼,dns-failed
`

const defaultMihomoUserTemplate = `mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
ipv6: true
unified-delay: true
tcp-concurrent: true
find-process-mode: strict
geodata-mode: true

dns:
  enable: true
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  proxy-server-nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query
  fallback-filter:
    geoip: true
    geoip-code: CN

proxies:
{{PROXIES}}

proxy-groups:
  - name: 🚀 节点选择
    type: select
    proxies:
      - ♻️ 自动选择
      - 🔯 故障转移
{{PROXY_NAMES_YAML}}
      - DIRECT
  - name: ♻️ 自动选择
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    proxies:
{{PROXY_NAMES_YAML}}
  - name: 🔯 故障转移
    type: fallback
    url: http://www.gstatic.com/generate_204
    interval: 300
    proxies:
{{PROXY_NAMES_YAML}}
  - name: 🤖 AI 服务
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
{{PROXY_NAMES_YAML}}
      - DIRECT
  - name: 🎬 国际媒体
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
{{PROXY_NAMES_YAML}}
      - DIRECT
  - name: 🎵 TikTok
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
{{PROXY_NAMES_YAML}}
      - DIRECT
  - name: 🎶 Spotify
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
{{PROXY_NAMES_YAML}}
      - DIRECT
  - name: 📲 Telegram
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
{{PROXY_NAMES_YAML}}
      - DIRECT
  - name: 🍎 苹果服务
    type: select
    proxies:
      - 🎯 全球直连
      - 🚀 节点选择
      - ♻️ 自动选择
  - name: 🔍 谷歌服务
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
{{PROXY_NAMES_YAML}}
      - DIRECT
  - name: 🛑 广告拦截
    type: select
    proxies:
      - REJECT
      - DIRECT
  - name: 🎯 全球直连
    type: select
    proxies:
      - DIRECT
      - 🚀 节点选择
  - name: 🐟 漏网之鱼
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
      - DIRECT

rule-providers:
  Lan:
    type: http
    behavior: classical
    url: https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Lan/Lan.yaml
    path: ./ruleset/Lan.yaml
    interval: 86400
  Advertising:
    type: http
    behavior: classical
    url: https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/AdvertisingLite/AdvertisingLite_Classical.yaml
    path: ./ruleset/AdvertisingLite.yaml
    interval: 86400
  OpenAI:
    type: http
    behavior: classical
    url: https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/OpenAI/OpenAI.yaml
    path: ./ruleset/OpenAI.yaml
    interval: 86400
  Claude:
    type: http
    behavior: classical
    url: https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Claude/Claude.yaml
    path: ./ruleset/Claude.yaml
    interval: 86400
  Gemini:
    type: http
    behavior: classical
    url: https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Gemini/Gemini.yaml
    path: ./ruleset/Gemini.yaml
    interval: 86400
  YouTube:
    type: http
    behavior: classical
    url: https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/YouTube/YouTube.yaml
    path: ./ruleset/YouTube.yaml
    interval: 86400
  Netflix:
    type: http
    behavior: classical
    url: https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Netflix/Netflix.yaml
    path: ./ruleset/Netflix.yaml
    interval: 86400
  Disney:
    type: http
    behavior: classical
    url: https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Disney/Disney.yaml
    path: ./ruleset/Disney.yaml
    interval: 86400
  TikTok:
    type: http
    behavior: classical
    url: https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/TikTok/TikTok.yaml
    path: ./ruleset/TikTok.yaml
    interval: 86400
  Spotify:
    type: http
    behavior: classical
    url: https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Spotify/Spotify.yaml
    path: ./ruleset/Spotify.yaml
    interval: 86400
  Telegram:
    type: http
    behavior: classical
    url: https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Telegram/Telegram.yaml
    path: ./ruleset/Telegram.yaml
    interval: 86400
  Apple:
    type: http
    behavior: classical
    url: https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Apple/Apple.yaml
    path: ./ruleset/Apple.yaml
    interval: 86400
  Google:
    type: http
    behavior: classical
    url: https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Google/Google.yaml
    path: ./ruleset/Google.yaml
    interval: 86400
  Global:
    type: http
    behavior: classical
    url: https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Global/Global_Classical.yaml
    path: ./ruleset/Global.yaml
    interval: 86400
  ChinaMax:
    type: http
    behavior: classical
    url: https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/ChinaMax/ChinaMax_Classical.yaml
    path: ./ruleset/ChinaMax.yaml
    interval: 86400

rules:
  - RULE-SET,Lan,🎯 全球直连,no-resolve
  - RULE-SET,Advertising,🛑 广告拦截
  - RULE-SET,OpenAI,🤖 AI 服务
  - RULE-SET,Claude,🤖 AI 服务
  - RULE-SET,Gemini,🤖 AI 服务
  - RULE-SET,YouTube,🎬 国际媒体
  - RULE-SET,Netflix,🎬 国际媒体
  - RULE-SET,Disney,🎬 国际媒体
  - RULE-SET,TikTok,🎵 TikTok
  - RULE-SET,Spotify,🎶 Spotify
  - RULE-SET,Telegram,📲 Telegram
  - RULE-SET,Apple,🍎 苹果服务
  - RULE-SET,Google,🔍 谷歌服务
  - RULE-SET,Global,🚀 节点选择
  - RULE-SET,ChinaMax,🎯 全球直连
  - GEOIP,CN,🎯 全球直连
  - MATCH,🐟 漏网之鱼
`

const defaultSurgeUserTemplate = `{{MANAGED_CONFIG_HEADER}}
[General]
loglevel = notify
bypass-system = true
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local
dns-server = 223.5.5.5, 119.29.29.29, system
encrypted-dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query
ipv6 = true
show-error-page-for-reject = true
proxy-test-url = http://www.gstatic.com/generate_204
internet-test-url = http://connectivitycheck.platform.hicloud.com/generate_204
test-timeout = 3

[Proxy]
{{PROXIES}}

[Proxy Group]
🚀 节点选择 = select, ♻️ 自动选择, 🔯 故障转移, {{PROXY_NAMES}}, DIRECT
♻️ 自动选择 = url-test, {{PROXY_NAMES}}, url = http://www.gstatic.com/generate_204, interval = 300, tolerance = 50
🔯 故障转移 = fallback, {{PROXY_NAMES}}, url = http://www.gstatic.com/generate_204, interval = 300
🤖 AI 服务 = select, 🚀 节点选择, ♻️ 自动选择, {{PROXY_NAMES}}, DIRECT
🎬 国际媒体 = select, 🚀 节点选择, ♻️ 自动选择, {{PROXY_NAMES}}, DIRECT
🎵 TikTok = select, 🚀 节点选择, ♻️ 自动选择, {{PROXY_NAMES}}, DIRECT
🎶 Spotify = select, 🚀 节点选择, ♻️ 自动选择, {{PROXY_NAMES}}, DIRECT
📲 Telegram = select, 🚀 节点选择, ♻️ 自动选择, {{PROXY_NAMES}}, DIRECT
🍎 苹果服务 = select, 🎯 全球直连, 🚀 节点选择, ♻️ 自动选择
🔍 谷歌服务 = select, 🚀 节点选择, ♻️ 自动选择, {{PROXY_NAMES}}, DIRECT
🛑 广告拦截 = select, REJECT, DIRECT
🎯 全球直连 = select, DIRECT, 🚀 节点选择
🐟 漏网之鱼 = select, 🚀 节点选择, ♻️ 自动选择, DIRECT

[Rule]
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Lan/Lan.list,🎯 全球直连
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/AdvertisingLite/AdvertisingLite.list,🛑 广告拦截
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/OpenAI/OpenAI.list,🤖 AI 服务
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Claude/Claude.list,🤖 AI 服务
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Gemini/Gemini.list,🤖 AI 服务
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/YouTube/YouTube.list,🎬 国际媒体
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Netflix/Netflix.list,🎬 国际媒体
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Disney/Disney.list,🎬 国际媒体
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/TikTok/TikTok.list,🎵 TikTok
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Spotify/Spotify.list,🎶 Spotify
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Telegram/Telegram.list,📲 Telegram
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Apple/Apple.list,🍎 苹果服务
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Google/Google.list,🔍 谷歌服务
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/Global/Global.list,🚀 节点选择
RULE-SET,https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Surge/ChinaMax/ChinaMax.list,🎯 全球直连
GEOIP,CN,🎯 全球直连
FINAL,🐟 漏网之鱼,dns-failed
`
