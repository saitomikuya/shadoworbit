package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type migration struct {
	version int
	name    string
	ddl     string
}

var migrations = []migration{
	{
		version: 1,
		name:    "001_initial_schema",
		ddl: `
CREATE TABLE IF NOT EXISTS dns_rule_groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    rules       TEXT NOT NULL DEFAULT '[]',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now'))
);

CREATE TABLE IF NOT EXISTS nodes (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    name                     TEXT NOT NULL,
    region_tag               TEXT NOT NULL DEFAULT '',
    token_hash               TEXT NOT NULL UNIQUE,
    public_ip                TEXT NOT NULL DEFAULT '',
    public_ipv6              TEXT NOT NULL DEFAULT '',
    custom_entry_host        TEXT NOT NULL DEFAULT '',
    custom_entry_port        INTEGER NOT NULL DEFAULT 0 CHECK (custom_entry_port BETWEEN 0 AND 65535),
    sort_order               INTEGER NOT NULL DEFAULT 0,
    enabled                  INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    status                   TEXT NOT NULL DEFAULT 'offline' CHECK (status IN ('online', 'offline', 'traffic_paused')),
    paused_reason            TEXT NOT NULL DEFAULT '',
    snell_config             TEXT NOT NULL DEFAULT '{}',
    ss_config                TEXT NOT NULL DEFAULT '{}',
    dns_unlock_enabled       INTEGER NOT NULL DEFAULT 0 CHECK (dns_unlock_enabled IN (0, 1)),
    dns_unlock_server        TEXT NOT NULL DEFAULT '',
    dns_rule_group_id        INTEGER REFERENCES dns_rule_groups(id) ON DELETE SET NULL,
    dns_extra_rules          TEXT NOT NULL DEFAULT '[]',
    traffic_limit_bytes      INTEGER NOT NULL DEFAULT 0 CHECK (traffic_limit_bytes >= 0),
    traffic_threshold_bytes  INTEGER NOT NULL DEFAULT 0 CHECK (traffic_threshold_bytes >= 0),
    traffic_count_mode       TEXT NOT NULL DEFAULT 'both' CHECK (traffic_count_mode IN ('both', 'tx_only', 'rx_only', 'max_dir')),
    threshold_action         TEXT NOT NULL DEFAULT 'stop_all' CHECK (threshold_action IN ('stop_all', 'stop_ss_only')),
    billing_reset_day        INTEGER NOT NULL DEFAULT 1 CHECK (billing_reset_day BETWEEN 0 AND 31),
    cycle_rx_bytes           INTEGER NOT NULL DEFAULT 0 CHECK (cycle_rx_bytes >= 0),
    cycle_tx_bytes           INTEGER NOT NULL DEFAULT 0 CHECK (cycle_tx_bytes >= 0),
    last_reset_at            TEXT,
    is_traffic_paused        INTEGER NOT NULL DEFAULT 0 CHECK (is_traffic_paused IN (0, 1)),
    config_revision          INTEGER NOT NULL DEFAULT 1 CHECK (config_revision >= 0),
    reported_config_revision INTEGER NOT NULL DEFAULT 0 CHECK (reported_config_revision >= 0),
    reported_versions        TEXT NOT NULL DEFAULT '{}',
    agent_os                 TEXT NOT NULL DEFAULT '',
    agent_arch               TEXT NOT NULL DEFAULT '',
    cpu_cores                INTEGER NOT NULL DEFAULT 0 CHECK (cpu_cores >= 0),
    last_seen_at             TEXT,
    cpu_percent              REAL NOT NULL DEFAULT 0,
    mem_used_bytes           INTEGER NOT NULL DEFAULT 0 CHECK (mem_used_bytes >= 0),
    mem_total_bytes          INTEGER NOT NULL DEFAULT 0 CHECK (mem_total_bytes >= 0),
    disk_used_percent        REAL NOT NULL DEFAULT 0,
    uptime_seconds           INTEGER NOT NULL DEFAULT 0 CHECK (uptime_seconds >= 0),
    rx_bps                   INTEGER NOT NULL DEFAULT 0 CHECK (rx_bps >= 0),
    tx_bps                   INTEGER NOT NULL DEFAULT 0 CHECK (tx_bps >= 0),
    core_a_healthy           INTEGER NOT NULL DEFAULT 0 CHECK (core_a_healthy IN (0, 1)),
    core_b_healthy           INTEGER NOT NULL DEFAULT 0 CHECK (core_b_healthy IN (0, 1)),
    created_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now')),
    updated_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_nodes_sort_order ON nodes(sort_order ASC, id ASC);
CREATE INDEX IF NOT EXISTS idx_nodes_dns_rule_group_id ON nodes(dns_rule_group_id);

CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    username            TEXT NOT NULL UNIQUE,
    enabled             INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    sub_token           TEXT NOT NULL UNIQUE,
    ss_upsk_16          TEXT NOT NULL,
    ss_upsk_32          TEXT NOT NULL,
    stls_password       TEXT NOT NULL,
    traffic_quota_bytes INTEGER NOT NULL DEFAULT 0 CHECK (traffic_quota_bytes >= 0),
    billing_reset_day   INTEGER NOT NULL DEFAULT 1 CHECK (billing_reset_day BETWEEN 0 AND 31),
    used_up_bytes       INTEGER NOT NULL DEFAULT 0 CHECK (used_up_bytes >= 0),
    used_down_bytes     INTEGER NOT NULL DEFAULT 0 CHECK (used_down_bytes >= 0),
    last_reset_at       TEXT,
    expire_at           TEXT,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now')),
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now'))
);

CREATE TABLE IF NOT EXISTS user_node_access (
    user_id    INTEGER NOT NULL,
    node_id    INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now')),
    PRIMARY KEY (user_id, node_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_user_node_access_node_id ON user_node_access(node_id);

CREATE TABLE IF NOT EXISTS traffic_logs_daily (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type TEXT NOT NULL CHECK (target_type IN ('node', 'user')),
    target_id   INTEGER NOT NULL,
    log_date    TEXT NOT NULL,
    rx_bytes    INTEGER NOT NULL DEFAULT 0 CHECK (rx_bytes >= 0),
    tx_bytes    INTEGER NOT NULL DEFAULT 0 CHECK (tx_bytes >= 0)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_traffic_logs_daily_unique
    ON traffic_logs_daily(target_type, target_id, log_date);
CREATE INDEX IF NOT EXISTS idx_traffic_logs_daily_date
    ON traffic_logs_daily(log_date);

CREATE TABLE IF NOT EXISTS sub_templates (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    client_type TEXT NOT NULL CHECK (client_type IN ('surge_admin', 'mihomo_user', 'surge_user')),
    content     TEXT NOT NULL,
    is_default  INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0, 1)),
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_sub_templates_client_type ON sub_templates(client_type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sub_templates_one_default_per_client
    ON sub_templates(client_type) WHERE is_default = 1;

CREATE TABLE IF NOT EXISTS webhook_channels (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL,
    provider          TEXT NOT NULL CHECK (provider IN ('feishu', 'dingtalk', 'wecom', 'custom')),
    url               TEXT NOT NULL,
    secret            TEXT NOT NULL DEFAULT '',
    subscribed_events TEXT NOT NULL DEFAULT '[]',
    enabled           INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now')),
    updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now'))
);

CREATE TABLE IF NOT EXISTS system_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now'))
);
`,
	},
	{
		version: 2,
		name:    "002_totals_breakdown_serverchan",
		ddl: `
ALTER TABLE nodes ADD COLUMN total_rx_bytes INTEGER NOT NULL DEFAULT 0 CHECK (total_rx_bytes >= 0);
ALTER TABLE nodes ADD COLUMN total_tx_bytes INTEGER NOT NULL DEFAULT 0 CHECK (total_tx_bytes >= 0);
UPDATE nodes SET total_rx_bytes = cycle_rx_bytes, total_tx_bytes = cycle_tx_bytes WHERE total_rx_bytes = 0 AND total_tx_bytes = 0;

CREATE TABLE IF NOT EXISTS user_node_traffic (
    user_id    INTEGER NOT NULL,
    node_id    INTEGER NOT NULL,
    up_bytes   INTEGER NOT NULL DEFAULT 0 CHECK (up_bytes >= 0),
    down_bytes INTEGER NOT NULL DEFAULT 0 CHECK (down_bytes >= 0),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now')),
    PRIMARY KEY (user_id, node_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_user_node_traffic_node_id ON user_node_traffic(node_id);

CREATE TABLE webhook_channels_new (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    name              TEXT NOT NULL,
    provider          TEXT NOT NULL CHECK (provider IN ('feishu', 'dingtalk', 'wecom', 'serverchan', 'custom')),
    url               TEXT NOT NULL,
    secret            TEXT NOT NULL DEFAULT '',
    subscribed_events TEXT NOT NULL DEFAULT '[]',
    enabled           INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now')),
    updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now'))
);
INSERT INTO webhook_channels_new(id, name, provider, url, secret, subscribed_events, enabled, created_at, updated_at)
SELECT id, name, provider, url, secret, subscribed_events, enabled, created_at, updated_at FROM webhook_channels;
DROP TABLE webhook_channels;
ALTER TABLE webhook_channels_new RENAME TO webhook_channels;
`,
	},
	{
		version: 3,
		name:    "003_traffic_usage_logs",
		ddl: `
CREATE TABLE IF NOT EXISTS traffic_usage_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id    INTEGER NOT NULL,
    user_id    INTEGER NOT NULL DEFAULT 0,
    log_minute TEXT NOT NULL,
    rx_bytes   INTEGER NOT NULL DEFAULT 0 CHECK (rx_bytes >= 0),
    tx_bytes   INTEGER NOT NULL DEFAULT 0 CHECK (tx_bytes >= 0),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now')),
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_traffic_usage_logs_unique
    ON traffic_usage_logs(node_id, user_id, log_minute);
CREATE INDEX IF NOT EXISTS idx_traffic_usage_logs_minute
    ON traffic_usage_logs(log_minute DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_traffic_usage_logs_node_minute
    ON traffic_usage_logs(node_id, log_minute DESC);

CREATE TABLE IF NOT EXISTS admin_node_traffic (
    node_id    INTEGER PRIMARY KEY,
    bytes      INTEGER NOT NULL DEFAULT 0 CHECK (bytes >= 0),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now')),
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

UPDATE sub_templates
SET content = REPLACE(
    REPLACE(
        REPLACE(content, char(13) || char(10), char(10)),
        char(10) || 'DIRECT = direct' || char(10), char(10)
    ),
    char(10) || 'REJECT = reject' || char(10), char(10)
)
WHERE client_type IN ('surge_admin', 'surge_user')
  AND (content LIKE '%DIRECT = direct%' OR content LIKE '%REJECT = reject%');

UPDATE sub_templates
SET content = REPLACE(
    content,
    'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/',
    'https://fastly.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/'
)
WHERE content LIKE '%https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/%';
`,
	},
	{
		version: 4,
		name:    "004_lb_groups",
		ddl: `
CREATE TABLE IF NOT EXISTS lb_groups (
    id                         INTEGER PRIMARY KEY AUTOINCREMENT,
    name                       TEXT NOT NULL UNIQUE,
    region_tag                 TEXT NOT NULL DEFAULT '',
    enabled                    INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    sort_order                 INTEGER NOT NULL DEFAULT 0,
    dns_zone_id                TEXT NOT NULL DEFAULT '',
    dns_zone_name              TEXT NOT NULL DEFAULT '',
    dns_domain                 TEXT NOT NULL UNIQUE,
    dns_ttl                    INTEGER NOT NULL DEFAULT 60 CHECK (dns_ttl BETWEEN 1 AND 86400),
    strategy                   TEXT NOT NULL DEFAULT 'remaining_balance' CHECK (strategy IN ('remaining_balance', 'failover', 'weighted_multi')),
    switch_diff_bytes          INTEGER NOT NULL DEFAULT 10737418240 CHECK (switch_diff_bytes >= 0),
    switch_cooldown_minutes    INTEGER NOT NULL DEFAULT 10 CHECK (switch_cooldown_minutes >= 0),
    failover_threshold_percent INTEGER NOT NULL DEFAULT 90 CHECK (failover_threshold_percent BETWEEN 1 AND 100),
    snell_config               TEXT NOT NULL DEFAULT '{}',
    ss_config                  TEXT NOT NULL DEFAULT '{}',
    pinned_node_id             INTEGER REFERENCES nodes(id) ON DELETE SET NULL,
    active_node_id             INTEGER REFERENCES nodes(id) ON DELETE SET NULL,
    active_records_json        TEXT NOT NULL DEFAULT '[]',
    last_switch_at             TEXT,
    last_sync_at               TEXT,
    last_sync_error            TEXT NOT NULL DEFAULT '',
    is_exhausted               INTEGER NOT NULL DEFAULT 0 CHECK (is_exhausted IN (0, 1)),
    created_at                 TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now')),
    updated_at                 TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_lb_groups_sort_order ON lb_groups(sort_order ASC, id ASC);

CREATE TABLE IF NOT EXISTS lb_group_members (
    group_id   INTEGER NOT NULL REFERENCES lb_groups(id) ON DELETE CASCADE,
    node_id    INTEGER NOT NULL UNIQUE REFERENCES nodes(id) ON DELETE CASCADE,
    priority   INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now')),
    PRIMARY KEY (group_id, node_id)
);
CREATE INDEX IF NOT EXISTS idx_lb_group_members_group_priority
    ON lb_group_members(group_id, priority ASC, node_id ASC);

CREATE TABLE IF NOT EXISTS lb_switch_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id     INTEGER NOT NULL REFERENCES lb_groups(id) ON DELETE CASCADE,
    event_type   TEXT NOT NULL,
    from_node_id INTEGER,
    to_node_id   INTEGER,
    from_ips     TEXT NOT NULL DEFAULT '',
    to_ips       TEXT NOT NULL DEFAULT '',
    reason       TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_lb_switch_logs_group_created
    ON lb_switch_logs(group_id, id DESC);
`,
	},
}

// Migrate applies all pending schema migrations idempotently.
func (s *Store) Migrate(ctx context.Context) error {
	const createMigrationsTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f000000Z', 'now'))
);`
	if _, err := s.db.ExecContext(ctx, createMigrationsTable); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}

	applied := make(map[int]bool)
	rows, err := s.db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("store: query schema_migrations: %w", err)
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			_ = rows.Close()
			return fmt.Errorf("store: scan schema_migrations: %w", err)
		}
		applied[v] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("store: iterate schema_migrations: %w", err)
	}
	_ = rows.Close()

	for _, m := range migrations {
		if applied[m.version] {
			continue
		}
		if err := s.withTx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, m.ddl); err != nil {
				return fmt.Errorf("store: execute migration %d (%s): %w", m.version, m.name, err)
			}
			now := FormatSQLiteTime(time.Now().UTC())
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)`,
				m.version, m.name, now,
			); err != nil {
				return fmt.Errorf("store: record migration %d (%s): %w", m.version, m.name, err)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}
