package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"snell-panel/internal/protocol"
)

const nodeColumns = `
id, name, region_tag, token_hash, public_ip, public_ipv6,
custom_entry_host, custom_entry_port, sort_order, enabled, status, paused_reason,
snell_config, ss_config, dns_unlock_enabled, dns_unlock_server, dns_rule_group_id, dns_extra_rules,
traffic_limit_bytes, traffic_threshold_bytes, traffic_count_mode, threshold_action, billing_reset_day,
cycle_rx_bytes, cycle_tx_bytes, total_rx_bytes, total_tx_bytes, last_reset_at, is_traffic_paused,
config_revision, reported_config_revision, reported_versions, agent_os, agent_arch, cpu_cores,
last_seen_at, cpu_percent, mem_used_bytes, mem_total_bytes, disk_used_percent, uptime_seconds,
rx_bps, tx_bps, core_a_healthy, core_b_healthy, created_at, updated_at`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanNode(row rowScanner) (*Node, error) {
	var (
		n              Node
		enabledInt     int
		dnsUnlockInt   int
		isPausedInt    int
		coreAInt       int
		coreBInt       int
		dnsGroupID     sql.NullInt64
		snellJSON      string
		ssJSON         string
		extraRulesJSON string
		versionsJSON   string
		lastResetStr   sql.NullString
		lastSeenStr    sql.NullString
		createdAtStr   string
		updatedAtStr   string
	)

	err := row.Scan(
		&n.ID, &n.Name, &n.RegionTag, &n.TokenHash, &n.PublicIP, &n.PublicIPv6,
		&n.CustomEntryHost, &n.CustomEntryPort, &n.SortOrder, &enabledInt, &n.Status, &n.PausedReason,
		&snellJSON, &ssJSON, &dnsUnlockInt, &n.DNSUnlockServer, &dnsGroupID, &extraRulesJSON,
		&n.TrafficLimitBytes, &n.TrafficThresholdBytes, &n.TrafficCountMode, &n.ThresholdAction, &n.BillingResetDay,
		&n.CycleRxBytes, &n.CycleTxBytes, &n.TotalRxBytes, &n.TotalTxBytes, &lastResetStr, &isPausedInt,
		&n.ConfigRevision, &n.ReportedConfigRevision, &versionsJSON, &n.AgentOS, &n.AgentArch, &n.CPUCores,
		&lastSeenStr, &n.CPUPercent, &n.MemUsedBytes, &n.MemTotalBytes, &n.DiskUsedPercent, &n.UptimeSeconds,
		&n.RxBPS, &n.TxBPS, &coreAInt, &coreBInt, &createdAtStr, &updatedAtStr,
	)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}

	n.Enabled = enabledInt == 1
	n.DNSUnlockEnabled = dnsUnlockInt == 1
	n.IsTrafficPaused = isPausedInt == 1
	n.CoreAHealthy = coreAInt == 1
	n.CoreBHealthy = coreBInt == 1

	if dnsGroupID.Valid {
		v := dnsGroupID.Int64
		n.DNSRuleGroupID = &v
	}

	if snellJSON != "" && snellJSON != "{}" {
		if err := json.Unmarshal([]byte(snellJSON), &n.SnellConfig); err != nil {
			return nil, fmt.Errorf("store: decode snell_config for node %d: %w", n.ID, err)
		}
	}
	if ssJSON != "" && ssJSON != "{}" {
		if err := json.Unmarshal([]byte(ssJSON), &n.SSConfig); err != nil {
			return nil, fmt.Errorf("store: decode ss_config for node %d: %w", n.ID, err)
		}
	}
	if extraRulesJSON != "" {
		if err := json.Unmarshal([]byte(extraRulesJSON), &n.DNSExtraRules); err != nil {
			return nil, fmt.Errorf("store: decode dns_extra_rules for node %d: %w", n.ID, err)
		}
	}
	if n.DNSExtraRules == nil {
		n.DNSExtraRules = []string{}
	}
	if versionsJSON != "" && versionsJSON != "{}" {
		if err := json.Unmarshal([]byte(versionsJSON), &n.ReportedVersions); err != nil {
			return nil, fmt.Errorf("store: decode reported_versions for node %d: %w", n.ID, err)
		}
	}

	var errTime error
	if n.LastResetAt, errTime = parseNullableTime(lastResetStr); errTime != nil {
		return nil, errTime
	}
	if n.LastSeenAt, errTime = parseNullableTime(lastSeenStr); errTime != nil {
		return nil, errTime
	}
	if n.CreatedAt, errTime = ParseSQLiteTime(createdAtStr); errTime != nil {
		return nil, errTime
	}
	if n.UpdatedAt, errTime = ParseSQLiteTime(updatedAtStr); errTime != nil {
		return nil, errTime
	}
	return &n, nil
}

// CreateNode inserts a new node and populates its generated ID and timestamps.
func (s *Store) CreateNode(ctx context.Context, node *Node) error {
	if node == nil {
		return fmt.Errorf("%w: nil node", ErrInvalidArgument)
	}
	if node.Name == "" || node.TokenHash == "" {
		return fmt.Errorf("%w: node name and token_hash are required", ErrInvalidArgument)
	}
	if node.Status == "" {
		node.Status = protocol.NodeStatusOffline
	}
	if node.TrafficCountMode == "" {
		node.TrafficCountMode = protocol.TrafficCountBoth
	}
	if node.ThresholdAction == "" {
		node.ThresholdAction = protocol.ThresholdActionStopAll
	}
	if node.BillingResetDay == 0 {
		node.BillingResetDay = 1
	}
	if node.BillingResetDay < 1 || node.BillingResetDay > 31 {
		return fmt.Errorf("%w: billing_reset_day must be between 1 and 31", ErrInvalidArgument)
	}
	if node.ConfigRevision <= 0 {
		node.ConfigRevision = 1
	}
	if node.DNSExtraRules == nil {
		node.DNSExtraRules = []string{}
	}

	now := time.Now().UTC()
	if node.LastResetAt == nil {
		t := now
		node.LastResetAt = &t
	}
	node.CreatedAt = now
	node.UpdatedAt = now

	snellBytes, err := json.Marshal(node.SnellConfig)
	if err != nil {
		return fmt.Errorf("store: marshal snell_config: %w", err)
	}
	// Strip transient users slice before persisting node ss_config.
	ssToStore := node.SSConfig
	ssToStore.Users = nil
	ssBytes, err := json.Marshal(ssToStore)
	if err != nil {
		return fmt.Errorf("store: marshal ss_config: %w", err)
	}
	extraRulesBytes, err := json.Marshal(node.DNSExtraRules)
	if err != nil {
		return fmt.Errorf("store: marshal dns_extra_rules: %w", err)
	}
	versionsBytes, err := json.Marshal(node.ReportedVersions)
	if err != nil {
		return fmt.Errorf("store: marshal reported_versions: %w", err)
	}

	var dnsGroupArg sql.NullInt64
	if node.DNSRuleGroupID != nil {
		dnsGroupArg = sql.NullInt64{Int64: *node.DNSRuleGroupID, Valid: true}
	}

	res, err := s.db.ExecContext(ctx, `
INSERT INTO nodes (
    name, region_tag, token_hash, public_ip, public_ipv6,
    custom_entry_host, custom_entry_port, sort_order, enabled, status, paused_reason,
    snell_config, ss_config, dns_unlock_enabled, dns_unlock_server, dns_rule_group_id, dns_extra_rules,
    traffic_limit_bytes, traffic_threshold_bytes, traffic_count_mode, threshold_action, billing_reset_day,
    cycle_rx_bytes, cycle_tx_bytes, total_rx_bytes, total_tx_bytes, last_reset_at, is_traffic_paused,
    config_revision, reported_config_revision, reported_versions, agent_os, agent_arch, cpu_cores,
    last_seen_at, cpu_percent, mem_used_bytes, mem_total_bytes, disk_used_percent, uptime_seconds,
    rx_bps, tx_bps, core_a_healthy, core_b_healthy, created_at, updated_at
) VALUES (
    ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?,
    ?, ?, ?, ?, ?, ?
)`,
		node.Name, node.RegionTag, node.TokenHash, node.PublicIP, node.PublicIPv6,
		node.CustomEntryHost, node.CustomEntryPort, node.SortOrder, boolToInt(node.Enabled), node.Status, node.PausedReason,
		string(snellBytes), string(ssBytes), boolToInt(node.DNSUnlockEnabled), node.DNSUnlockServer, dnsGroupArg, string(extraRulesBytes),
		node.TrafficLimitBytes, node.TrafficThresholdBytes, node.TrafficCountMode, node.ThresholdAction, node.BillingResetDay,
		node.CycleRxBytes, node.CycleTxBytes, node.TotalRxBytes, node.TotalTxBytes, formatNullableTime(node.LastResetAt), boolToInt(node.IsTrafficPaused),
		node.ConfigRevision, node.ReportedConfigRevision, string(versionsBytes), node.AgentOS, node.AgentArch, node.CPUCores,
		formatNullableTime(node.LastSeenAt), node.CPUPercent, node.MemUsedBytes, node.MemTotalBytes, node.DiskUsedPercent, node.UptimeSeconds,
		node.RxBPS, node.TxBPS, boolToInt(node.CoreAHealthy), boolToInt(node.CoreBHealthy), FormatSQLiteTime(node.CreatedAt), FormatSQLiteTime(node.UpdatedAt),
	)
	if err != nil {
		return mapSQLiteErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("store: node LastInsertId: %w", err)
	}
	node.ID = id
	return nil
}

// GetNodeByID fetches a node by primary key.
func (s *Store) GetNodeByID(ctx context.Context, id int64) (*Node, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM nodes WHERE id = ?`, id)
	return scanNode(row)
}

// GetNodeByTokenHash fetches a node by its SHA-256 token hash.
func (s *Store) GetNodeByTokenHash(ctx context.Context, tokenHash string) (*Node, error) {
	if tokenHash == "" {
		return nil, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM nodes WHERE token_hash = ?`, tokenHash)
	return scanNode(row)
}

// ListNodes returns all nodes ordered by sort_order ASC, id ASC.
func (s *Store) ListNodes(ctx context.Context) ([]Node, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+nodeColumns+` FROM nodes ORDER BY sort_order ASC, id ASC`)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	defer rows.Close()

	var out []Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *n)
	}
	if err := rows.Err(); err != nil {
		return nil, mapSQLiteErr(err)
	}
	return out, nil
}

// UpdateNode updates configuration and metadata fields of a node while preserving
// runtime telemetry and cycle traffic counters.
func (s *Store) UpdateNode(ctx context.Context, node *Node) error {
	if node == nil || node.ID <= 0 {
		return fmt.Errorf("%w: invalid node", ErrInvalidArgument)
	}
	if node.Name == "" {
		return fmt.Errorf("%w: node name cannot be empty", ErrInvalidArgument)
	}
	if node.BillingResetDay < 1 || node.BillingResetDay > 31 {
		return fmt.Errorf("%w: billing_reset_day must be between 1 and 31", ErrInvalidArgument)
	}
	if node.DNSExtraRules == nil {
		node.DNSExtraRules = []string{}
	}

	snellBytes, err := json.Marshal(node.SnellConfig)
	if err != nil {
		return fmt.Errorf("store: marshal snell_config: %w", err)
	}
	ssToStore := node.SSConfig
	ssToStore.Users = nil
	ssBytes, err := json.Marshal(ssToStore)
	if err != nil {
		return fmt.Errorf("store: marshal ss_config: %w", err)
	}
	extraRulesBytes, err := json.Marshal(node.DNSExtraRules)
	if err != nil {
		return fmt.Errorf("store: marshal dns_extra_rules: %w", err)
	}

	var dnsGroupArg sql.NullInt64
	if node.DNSRuleGroupID != nil {
		dnsGroupArg = sql.NullInt64{Int64: *node.DNSRuleGroupID, Valid: true}
	}

	now := time.Now().UTC()
	node.UpdatedAt = now

	var keptIPv4, keptIPv6 string
	err = s.db.QueryRowContext(ctx, `
UPDATE nodes SET
    name = ?,
    region_tag = ?,
    token_hash = COALESCE(NULLIF(?, ''), token_hash),
    public_ip = COALESCE(NULLIF(?, ''), public_ip),
    public_ipv6 = COALESCE(NULLIF(?, ''), public_ipv6),
    custom_entry_host = ?,
    custom_entry_port = ?,
    sort_order = ?,
    enabled = ?,
    snell_config = ?,
    ss_config = ?,
    dns_unlock_enabled = ?,
    dns_unlock_server = ?,
    dns_rule_group_id = ?,
    dns_extra_rules = ?,
    traffic_limit_bytes = ?,
    traffic_threshold_bytes = ?,
    traffic_count_mode = ?,
    threshold_action = ?,
    billing_reset_day = ?,
    config_revision = ?,
    updated_at = ?
WHERE id = ?
RETURNING public_ip, public_ipv6`,
		node.Name, node.RegionTag, node.TokenHash, node.PublicIP, node.PublicIPv6,
		node.CustomEntryHost, node.CustomEntryPort, node.SortOrder, boolToInt(node.Enabled),
		string(snellBytes), string(ssBytes), boolToInt(node.DNSUnlockEnabled), node.DNSUnlockServer, dnsGroupArg, string(extraRulesBytes),
		node.TrafficLimitBytes, node.TrafficThresholdBytes, node.TrafficCountMode, node.ThresholdAction, node.BillingResetDay,
		node.ConfigRevision, FormatSQLiteTime(now), node.ID,
	).Scan(&keptIPv4, &keptIPv6)
	if err != nil {
		return mapSQLiteErr(err)
	}
	node.PublicIP = keptIPv4
	node.PublicIPv6 = keptIPv6
	return nil
}

// DeleteNode deletes a node, its daily traffic logs, and per-node system_settings atomically.
func (s *Store) DeleteNode(ctx context.Context, id int64) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM traffic_logs_daily WHERE target_type = 'node' AND target_id = ?`, id); err != nil {
			return mapSQLiteErr(err)
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM system_settings WHERE key IN (?, ?)`,
			fmt.Sprintf("node_token_enc:%d", id),
			fmt.Sprintf("last_node_reset_month:%d", id),
		); err != nil {
			return mapSQLiteErr(err)
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM nodes WHERE id = ?`, id)
		if err != nil {
			return mapSQLiteErr(err)
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// ReorderNodes sets sort_order = index for each node ID in orderedIDs.
func (s *Store) ReorderNodes(ctx context.Context, orderedIDs []int64) error {
	now := FormatSQLiteTime(time.Now().UTC())
	return s.withTx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `UPDATE nodes SET sort_order = ?, updated_at = ? WHERE id = ?`)
		if err != nil {
			return mapSQLiteErr(err)
		}
		defer stmt.Close()

		for idx, id := range orderedIDs {
			res, err := stmt.ExecContext(ctx, idx, now, id)
			if err != nil {
				return mapSQLiteErr(err)
			}
			affected, err := res.RowsAffected()
			if err != nil {
				return err
			}
			if affected == 0 {
				return ErrNotFound
			}
		}
		return nil
	})
}

// UpdateNodeTelemetry updates live metrics reported by the agent.
func (s *Store) UpdateNodeTelemetry(ctx context.Context, id int64, upd NodeTelemetryUpdate) error {
	lastSeen := upd.LastSeenAt
	if lastSeen.IsZero() {
		lastSeen = time.Now().UTC()
	}
	now := FormatSQLiteTime(time.Now().UTC())
	res, err := s.db.ExecContext(ctx, `
UPDATE nodes SET
    public_ip = CASE WHEN ? != '' THEN ? ELSE public_ip END,
    public_ipv6 = CASE WHEN ? != '' THEN ? ELSE public_ipv6 END,
    cpu_percent = ?,
    mem_used_bytes = ?,
    mem_total_bytes = ?,
    disk_used_percent = ?,
    uptime_seconds = ?,
    rx_bps = ?,
    tx_bps = ?,
    core_a_healthy = ?,
    core_b_healthy = ?,
    last_seen_at = ?,
    status = CASE WHEN is_traffic_paused = 1 THEN 'traffic_paused' ELSE 'online' END,
    updated_at = ?
WHERE id = ?`,
		upd.PublicIP, upd.PublicIP,
		upd.PublicIPv6, upd.PublicIPv6,
		upd.CPUPercent, upd.MemUsedBytes, upd.MemTotalBytes,
		upd.DiskUsedPercent, upd.UptimeSeconds, upd.RxBPS, upd.TxBPS,
		boolToInt(upd.CoreAHealthy), boolToInt(upd.CoreBHealthy),
		FormatSQLiteTime(lastSeen), now, id,
	)
	if err != nil {
		return mapSQLiteErr(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateNodeVersions updates agent OS/arch/cores, installed kernel versions, and reported config revision.
func (s *Store) UpdateNodeVersions(ctx context.Context, id int64, versions protocol.AgentVersions, agentOS, agentArch string, cpuCores int, reportedRev int64) error {
	versionsBytes, err := json.Marshal(versions)
	if err != nil {
		return fmt.Errorf("store: marshal reported_versions: %w", err)
	}
	now := FormatSQLiteTime(time.Now().UTC())
	res, err := s.db.ExecContext(ctx, `
UPDATE nodes SET
    reported_versions = ?,
    agent_os = ?,
    agent_arch = ?,
    cpu_cores = ?,
    reported_config_revision = ?,
    updated_at = ?
WHERE id = ?`,
		string(versionsBytes), agentOS, agentArch, cpuCores, reportedRev, now, id,
	)
	if err != nil {
		return mapSQLiteErr(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateNodeReportedRevision records the latest config revision confirmed by the agent.
func (s *Store) UpdateNodeReportedRevision(ctx context.Context, id int64, reportedRev int64) error {
	now := FormatSQLiteTime(time.Now().UTC())
	res, err := s.db.ExecContext(ctx, `
UPDATE nodes SET reported_config_revision = ?, updated_at = ? WHERE id = ?`,
		reportedRev, now, id,
	)
	if err != nil {
		return mapSQLiteErr(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateNodePublicIPs updates non-empty public IPv4/IPv6 addresses reported by the node agent.
func (s *Store) UpdateNodePublicIPs(ctx context.Context, id int64, ipv4, ipv6 string) error {
	if id <= 0 {
		return fmt.Errorf("%w: invalid node id", ErrInvalidArgument)
	}
	now := FormatSQLiteTime(time.Now().UTC())
	res, err := s.db.ExecContext(ctx, `
UPDATE nodes SET
    public_ip = CASE WHEN ? != '' THEN ? ELSE public_ip END,
    public_ipv6 = CASE WHEN ? != '' THEN ? ELSE public_ipv6 END,
    updated_at = ?
WHERE id = ?`,
		ipv4, ipv4, ipv6, ipv6, now, id,
	)
	if err != nil {
		return mapSQLiteErr(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// SetNodeConnectionStatus marks a node online or offline without overwriting traffic_paused state.
// When online is true and lastSeenAt is non-zero (or defaults to now UTC), last_seen_at is updated.
func (s *Store) SetNodeConnectionStatus(ctx context.Context, id int64, online bool, lastSeenAt time.Time) error {
	if id <= 0 {
		return fmt.Errorf("%w: invalid node id", ErrInvalidArgument)
	}
	now := time.Now().UTC()
	nowStr := FormatSQLiteTime(now)
	var (
		res sql.Result
		err error
	)
	if online {
		if lastSeenAt.IsZero() {
			lastSeenAt = now
		}
		res, err = s.db.ExecContext(ctx, `
UPDATE nodes SET
    last_seen_at = ?,
    status = CASE WHEN is_traffic_paused = 1 THEN 'traffic_paused' ELSE 'online' END,
    updated_at = ?
WHERE id = ?`,
			FormatSQLiteTime(lastSeenAt), nowStr, id,
		)
	} else {
		res, err = s.db.ExecContext(ctx, `
UPDATE nodes SET
    status = CASE WHEN is_traffic_paused = 1 THEN 'traffic_paused' ELSE 'offline' END,
    updated_at = ?
WHERE id = ?`,
			nowStr, id,
		)
	}
	if err != nil {
		return mapSQLiteErr(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateNodeStatus updates the node status and paused_reason.
func (s *Store) UpdateNodeStatus(ctx context.Context, id int64, status, pausedReason string) error {
	if !protocol.IsValidNodeStatus(status) {
		return fmt.Errorf("%w: invalid node status %q", ErrInvalidArgument, status)
	}
	now := FormatSQLiteTime(time.Now().UTC())
	res, err := s.db.ExecContext(ctx, `
UPDATE nodes SET status = ?, paused_reason = ?, updated_at = ? WHERE id = ?`,
		status, pausedReason, now, id,
	)
	if err != nil {
		return mapSQLiteErr(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// AddNodeTrafficDelta atomically adds rxDelta and txDelta to a node's cycle counters
// and returns the updated node row.
func (s *Store) AddNodeTrafficDelta(ctx context.Context, id int64, rxDelta, txDelta int64) (*Node, error) {
	if rxDelta < 0 || txDelta < 0 {
		return nil, fmt.Errorf("%w: traffic deltas must be non-negative", ErrInvalidArgument)
	}
	var updated *Node
	now := FormatSQLiteTime(time.Now().UTC())
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var curRx, curTx, curTotalRx, curTotalTx int64
		err := tx.QueryRowContext(ctx, `SELECT cycle_rx_bytes, cycle_tx_bytes, total_rx_bytes, total_tx_bytes FROM nodes WHERE id = ?`, id).Scan(&curRx, &curTx, &curTotalRx, &curTotalTx)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return mapSQLiteErr(err)
		}
		if curRx > math.MaxInt64-rxDelta || curTx > math.MaxInt64-txDelta ||
			curTotalRx > math.MaxInt64-rxDelta || curTotalTx > math.MaxInt64-txDelta {
			return fmt.Errorf("%w: node traffic counter overflow", ErrInvalidArgument)
		}

		if _, err := tx.ExecContext(ctx, `
UPDATE nodes SET
    cycle_rx_bytes = cycle_rx_bytes + ?,
    cycle_tx_bytes = cycle_tx_bytes + ?,
    total_rx_bytes = total_rx_bytes + ?,
    total_tx_bytes = total_tx_bytes + ?,
    updated_at = ?
WHERE id = ?`,
			rxDelta, txDelta, rxDelta, txDelta, now, id,
		); err != nil {
			return mapSQLiteErr(err)
		}
		updated, err = scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM nodes WHERE id = ?`, id))
		return err
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// ResetNodeCycleTraffic zeroes cycle traffic counters, clears traffic pause state,
// and updates last_reset_at.
func (s *Store) ResetNodeCycleTraffic(ctx context.Context, id int64, resetAt time.Time) error {
	if resetAt.IsZero() {
		resetAt = time.Now().UTC()
	}
	now := time.Now().UTC()
	recentCutoff := FormatSQLiteTime(now.Add(-2 * time.Minute))

	res, err := s.db.ExecContext(ctx, `
UPDATE nodes SET
    cycle_rx_bytes = 0,
    cycle_tx_bytes = 0,
    is_traffic_paused = 0,
    paused_reason = '',
    status = CASE
        WHEN status = 'traffic_paused' THEN
            CASE WHEN last_seen_at IS NOT NULL AND last_seen_at >= ? THEN 'online' ELSE 'offline' END
        ELSE status
    END,
    last_reset_at = ?,
    updated_at = ?
WHERE id = ?`,
		recentCutoff, FormatSQLiteTime(resetAt), FormatSQLiteTime(now), id,
	)
	if err != nil {
		return mapSQLiteErr(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// CalibrateNodeTraffic sets cycle_rx_bytes and cycle_tx_bytes explicitly.
func (s *Store) CalibrateNodeTraffic(ctx context.Context, id int64, rxBytes, txBytes int64) error {
	if rxBytes < 0 || txBytes < 0 {
		return fmt.Errorf("%w: calibrated traffic bytes must be non-negative", ErrInvalidArgument)
	}
	now := FormatSQLiteTime(time.Now().UTC())
	res, err := s.db.ExecContext(ctx, `
UPDATE nodes SET cycle_rx_bytes = ?, cycle_tx_bytes = ?, updated_at = ? WHERE id = ?`,
		rxBytes, txBytes, now, id,
	)
	if err != nil {
		return mapSQLiteErr(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// SetNodeTrafficPaused toggles a node's traffic_paused state and reason.
func (s *Store) SetNodeTrafficPaused(ctx context.Context, id int64, paused bool, reason string) error {
	now := time.Now().UTC()
	nowStr := FormatSQLiteTime(now)
	if paused {
		res, err := s.db.ExecContext(ctx, `
UPDATE nodes SET
    is_traffic_paused = 1,
    status = 'traffic_paused',
    paused_reason = ?,
    updated_at = ?
WHERE id = ?`,
			reason, nowStr, id,
		)
		if err != nil {
			return mapSQLiteErr(err)
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			return ErrNotFound
		}
		return nil
	}

	recentCutoff := FormatSQLiteTime(now.Add(-2 * time.Minute))
	res, err := s.db.ExecContext(ctx, `
UPDATE nodes SET
    is_traffic_paused = 0,
    paused_reason = '',
    status = CASE
        WHEN status = 'traffic_paused' THEN
            CASE WHEN last_seen_at IS NOT NULL AND last_seen_at >= ? THEN 'online' ELSE 'offline' END
        ELSE status
    END,
    updated_at = ?
WHERE id = ?`,
		recentCutoff, nowStr, id,
	)
	if err != nil {
		return mapSQLiteErr(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// IncrementNodeConfigRevision bumps a node's config_revision by 1 and returns the new revision.
func (s *Store) IncrementNodeConfigRevision(ctx context.Context, id int64) (int64, error) {
	var rev int64
	now := FormatSQLiteTime(time.Now().UTC())
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
UPDATE nodes SET config_revision = config_revision + 1, updated_at = ? WHERE id = ?`,
			now, id,
		)
		if err != nil {
			return mapSQLiteErr(err)
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			return ErrNotFound
		}
		return mapSQLiteErr(tx.QueryRowContext(ctx, `SELECT config_revision FROM nodes WHERE id = ?`, id).Scan(&rev))
	})
	return rev, err
}

// IncrementConfigRevisionByUser bumps config_revision on all nodes authorized for userID.
func (s *Store) IncrementConfigRevisionByUser(ctx context.Context, userID int64) ([]int64, error) {
	var nodeIDs []int64
	now := FormatSQLiteTime(time.Now().UTC())
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT node_id FROM user_node_access WHERE user_id = ? ORDER BY node_id ASC`, userID)
		if err != nil {
			return mapSQLiteErr(err)
		}
		for rows.Next() {
			var nid int64
			if err := rows.Scan(&nid); err != nil {
				_ = rows.Close()
				return mapSQLiteErr(err)
			}
			nodeIDs = append(nodeIDs, nid)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return mapSQLiteErr(err)
		}
		_ = rows.Close()

		if len(nodeIDs) == 0 {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE nodes SET config_revision = config_revision + 1, updated_at = ?
WHERE id IN (SELECT node_id FROM user_node_access WHERE user_id = ?)`,
			now, userID,
		); err != nil {
			return mapSQLiteErr(err)
		}
		return nil
	})
	return nodeIDs, err
}

// IncrementConfigRevisionByDNSGroup bumps config_revision on all nodes linked to groupID.
func (s *Store) IncrementConfigRevisionByDNSGroup(ctx context.Context, groupID int64) ([]int64, error) {
	var nodeIDs []int64
	now := FormatSQLiteTime(time.Now().UTC())
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id FROM nodes WHERE dns_rule_group_id = ? ORDER BY id ASC`, groupID)
		if err != nil {
			return mapSQLiteErr(err)
		}
		for rows.Next() {
			var nid int64
			if err := rows.Scan(&nid); err != nil {
				_ = rows.Close()
				return mapSQLiteErr(err)
			}
			nodeIDs = append(nodeIDs, nid)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return mapSQLiteErr(err)
		}
		_ = rows.Close()

		if len(nodeIDs) == 0 {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `
UPDATE nodes SET config_revision = config_revision + 1, updated_at = ?
WHERE dns_rule_group_id = ?`,
			now, groupID,
		); err != nil {
			return mapSQLiteErr(err)
		}
		return nil
	})
	return nodeIDs, err
}

// BumpNodesConfigRevision increments config_revision by 1 for all specified positive node IDs.
func (s *Store) BumpNodesConfigRevision(ctx context.Context, nodeIDs []int64) error {
	seen := make(map[int64]struct{}, len(nodeIDs))
	unique := make([]int64, 0, len(nodeIDs))
	for _, id := range nodeIDs {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	if len(unique) == 0 {
		return nil
	}

	now := FormatSQLiteTime(time.Now().UTC())
	return s.withTx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `UPDATE nodes SET config_revision = config_revision + 1, updated_at = ? WHERE id = ?`)
		if err != nil {
			return mapSQLiteErr(err)
		}
		defer stmt.Close()

		for _, id := range unique {
			if _, err := stmt.ExecContext(ctx, now, id); err != nil {
				return mapSQLiteErr(err)
			}
		}
		return nil
	})
}
