package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"snell-panel/internal/protocol"
)

const lbGroupColumns = `
id, name, region_tag, enabled, sort_order,
dns_zone_id, dns_zone_name, dns_domain, dns_ttl,
strategy, switch_diff_bytes, switch_cooldown_minutes, failover_threshold_percent,
snell_config, ss_config, pinned_node_id, active_node_id, active_records_json,
last_switch_at, last_sync_at, last_sync_error, is_exhausted, created_at, updated_at`

func normalizeLBDomain(raw string) string {
	s := strings.TrimSpace(strings.ToLower(raw))
	s = strings.TrimSuffix(s, ".")
	return s
}

func ensureOneRowAffected(res sql.Result) error {
	affected, err := res.RowsAffected()
	if err != nil {
		return mapSQLiteErr(err)
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func scanLBGroup(row rowScanner) (*LBGroup, error) {
	var (
		g                 LBGroup
		enabledInt        int
		isExhaustedInt    int
		snellJSON         string
		ssJSON            string
		pinnedNodeID      sql.NullInt64
		activeNodeID      sql.NullInt64
		activeRecordsJSON string
		lastSwitchStr     sql.NullString
		lastSyncStr       sql.NullString
		createdAtStr      string
		updatedAtStr      string
	)

	err := row.Scan(
		&g.ID, &g.Name, &g.RegionTag, &enabledInt, &g.SortOrder,
		&g.DNSZoneID, &g.DNSZoneName, &g.DNSDomain, &g.DNSTTL,
		&g.Strategy, &g.SwitchDiffBytes, &g.SwitchCooldownMinutes, &g.FailoverThresholdPercent,
		&snellJSON, &ssJSON, &pinnedNodeID, &activeNodeID, &activeRecordsJSON,
		&lastSwitchStr, &lastSyncStr, &g.LastSyncError, &isExhaustedInt, &createdAtStr, &updatedAtStr,
	)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}

	g.Enabled = enabledInt == 1
	g.IsExhausted = isExhaustedInt == 1

	if pinnedNodeID.Valid {
		v := pinnedNodeID.Int64
		g.PinnedNodeID = &v
	}
	if activeNodeID.Valid {
		v := activeNodeID.Int64
		g.ActiveNodeID = &v
	}

	if snellJSON != "" && snellJSON != "{}" {
		if err := json.Unmarshal([]byte(snellJSON), &g.SnellConfig); err != nil {
			return nil, fmt.Errorf("store: decode lb_group %d snell_config: %w", g.ID, err)
		}
	}
	if ssJSON != "" && ssJSON != "{}" {
		if err := json.Unmarshal([]byte(ssJSON), &g.SSConfig); err != nil {
			return nil, fmt.Errorf("store: decode lb_group %d ss_config: %w", g.ID, err)
		}
	}
	g.SSConfig.Users = nil

	if activeRecordsJSON != "" {
		if err := json.Unmarshal([]byte(activeRecordsJSON), &g.ActiveRecords); err != nil {
			return nil, fmt.Errorf("store: decode lb_group %d active_records_json: %w", g.ID, err)
		}
	}
	if g.ActiveRecords == nil {
		g.ActiveRecords = []LBActiveRecord{}
	}
	g.Members = []LBGroupMember{}

	var errTime error
	if g.LastSwitchAt, errTime = parseNullableTime(lastSwitchStr); errTime != nil {
		return nil, errTime
	}
	if g.LastSyncAt, errTime = parseNullableTime(lastSyncStr); errTime != nil {
		return nil, errTime
	}
	if g.CreatedAt, errTime = ParseSQLiteTime(createdAtStr); errTime != nil {
		return nil, errTime
	}
	if g.UpdatedAt, errTime = ParseSQLiteTime(updatedAtStr); errTime != nil {
		return nil, errTime
	}

	return &g, nil
}

func validateLBGroupForStore(grp *LBGroup) error {
	if grp == nil {
		return fmt.Errorf("%w: nil lb group", ErrInvalidArgument)
	}
	grp.Name = strings.TrimSpace(grp.Name)
	if grp.Name == "" {
		return fmt.Errorf("%w: lb group name cannot be empty", ErrInvalidArgument)
	}
	grp.DNSDomain = normalizeLBDomain(grp.DNSDomain)
	if grp.DNSDomain == "" {
		return fmt.Errorf("%w: dns_domain cannot be empty", ErrInvalidArgument)
	}
	if grp.DNSTTL == 0 {
		grp.DNSTTL = 60
	}
	if grp.DNSTTL < 1 || grp.DNSTTL > 86400 {
		return fmt.Errorf("%w: dns_ttl must be between 1 and 86400", ErrInvalidArgument)
	}
	if grp.Strategy == "" {
		grp.Strategy = protocol.LBStrategyRemainingBalance
	}
	if !protocol.IsValidLBStrategy(grp.Strategy) {
		return fmt.Errorf("%w: invalid lb strategy %q", ErrInvalidArgument, grp.Strategy)
	}
	if grp.SwitchDiffBytes < 0 {
		return fmt.Errorf("%w: switch_diff_bytes must be >= 0", ErrInvalidArgument)
	}
	if grp.SwitchCooldownMinutes < 0 {
		return fmt.Errorf("%w: switch_cooldown_minutes must be >= 0", ErrInvalidArgument)
	}
	if grp.FailoverThresholdPercent == 0 {
		grp.FailoverThresholdPercent = 90
	}
	if grp.FailoverThresholdPercent < 1 || grp.FailoverThresholdPercent > 100 {
		return fmt.Errorf("%w: failover_threshold_percent must be between 1 and 100", ErrInvalidArgument)
	}
	return nil
}

func dedupPositiveNodeIDs(ids []int64) ([]int64, error) {
	seen := make(map[int64]struct{}, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			return nil, fmt.Errorf("%w: member node_id must be positive", ErrInvalidArgument)
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

func loadLBGroupMembersTx(ctx context.Context, tx *sql.Tx, groupID int64) ([]LBGroupMember, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT group_id, node_id, priority, created_at
FROM lb_group_members
WHERE group_id = ?
ORDER BY priority ASC, node_id ASC`, groupID)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	defer rows.Close()

	out := []LBGroupMember{}
	for rows.Next() {
		var m LBGroupMember
		var createdStr string
		if err := rows.Scan(&m.GroupID, &m.NodeID, &m.Priority, &createdStr); err != nil {
			return nil, mapSQLiteErr(err)
		}
		t, err := ParseSQLiteTime(createdStr)
		if err != nil {
			return nil, err
		}
		m.CreatedAt = t
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, mapSQLiteErr(err)
	}
	return out, nil
}

func applyLBGroupMembersAndSyncTx(
	ctx context.Context,
	tx *sql.Tx,
	groupID int64,
	snellCfg protocol.SnellConfig,
	ssCfg protocol.SSConfig,
	memberNodeIDs []int64,
	nowStr string,
) ([]int64, error) {
	cleanIDs, err := dedupPositiveNodeIDs(memberNodeIDs)
	if err != nil {
		return nil, err
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM lb_group_members WHERE group_id = ?`, groupID); err != nil {
		return nil, mapSQLiteErr(err)
	}

	if len(cleanIDs) == 0 {
		return []int64{}, nil
	}

	// Verify nodes exist and sync unified Snell/SS configurations while preserving per-node fields.
	for idx, nid := range cleanIDs {
		var (
			nodeName  string
			snellJSON string
			ssJSON    string
		)
		err := tx.QueryRowContext(ctx, `SELECT name, snell_config, ss_config FROM nodes WHERE id = ?`, nid).
			Scan(&nodeName, &snellJSON, &ssJSON)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fmt.Errorf("%w: node %d does not exist", ErrInvalidArgument, nid)
			}
			return nil, mapSQLiteErr(err)
		}

		if _, err := tx.ExecContext(ctx,
			`INSERT INTO lb_group_members(group_id, node_id, priority, created_at) VALUES (?, ?, ?, ?)`,
			groupID, nid, idx, nowStr,
		); err != nil {
			return nil, mapSQLiteErr(err)
		}

		var curSnell protocol.SnellConfig
		if snellJSON != "" && snellJSON != "{}" {
			if err := json.Unmarshal([]byte(snellJSON), &curSnell); err != nil {
				return nil, fmt.Errorf("store: decode node %d snell_config: %w", nid, err)
			}
		}

		// Check port collisions against the node's preserved InnerPort.
		if snellCfg.Enabled && snellCfg.PublicPort > 0 && curSnell.InnerPort > 0 && snellCfg.PublicPort == curSnell.InnerPort {
			return nil, fmt.Errorf("%w: snell_config.public_port (%d) collides with node %q (#%d) inner_port (%d)", ErrInvalidArgument, snellCfg.PublicPort, nodeName, nid, curSnell.InnerPort)
		}
		if snellCfg.Enabled && ssCfg.Enabled && ssCfg.TCPPort > 0 && curSnell.InnerPort > 0 && ssCfg.TCPPort == curSnell.InnerPort {
			return nil, fmt.Errorf("%w: ss_config.tcp_port (%d) collides with node %q (#%d) inner_port (%d)", ErrInvalidArgument, ssCfg.TCPPort, nodeName, nid, curSnell.InnerPort)
		}

		mergedSnell := curSnell
		mergedSnell.Enabled = snellCfg.Enabled
		mergedSnell.Version = snellCfg.Version
		mergedSnell.PublicPort = snellCfg.PublicPort
		mergedSnell.PSK = snellCfg.PSK
		mergedSnell.Obfs = snellCfg.Obfs
		mergedSnell.TFO = snellCfg.TFO
		mergedSnell.STLSPassword = snellCfg.STLSPassword
		mergedSnell.STLSSNI = snellCfg.STLSSNI

		mergedSS := ssCfg
		mergedSS.Users = nil

		snellBytes, err := json.Marshal(mergedSnell)
		if err != nil {
			return nil, fmt.Errorf("store: marshal merged snell_config: %w", err)
		}
		ssBytes, err := json.Marshal(mergedSS)
		if err != nil {
			return nil, fmt.Errorf("store: marshal merged ss_config: %w", err)
		}

		if _, err := tx.ExecContext(ctx, `
UPDATE nodes
SET snell_config = ?, ss_config = ?, config_revision = config_revision + 1, updated_at = ?
WHERE id = ?`,
			string(snellBytes), string(ssBytes), nowStr, nid,
		); err != nil {
			return nil, mapSQLiteErr(err)
		}
	}

	// Union user_node_access across all members of the group so every member authorizes the same users.
	placeholders := strings.Repeat("?,", len(cleanIDs))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, len(cleanIDs))
	for i, nid := range cleanIDs {
		args[i] = nid
	}
	userRows, err := tx.QueryContext(ctx,
		`SELECT DISTINCT user_id FROM user_node_access WHERE node_id IN (`+placeholders+`)`,
		args...,
	)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	var userIDs []int64
	for userRows.Next() {
		var uid int64
		if err := userRows.Scan(&uid); err != nil {
			_ = userRows.Close()
			return nil, mapSQLiteErr(err)
		}
		userIDs = append(userIDs, uid)
	}
	if err := userRows.Err(); err != nil {
		_ = userRows.Close()
		return nil, mapSQLiteErr(err)
	}
	_ = userRows.Close()

	if len(userIDs) > 0 {
		stmt, err := tx.PrepareContext(ctx,
			`INSERT OR IGNORE INTO user_node_access(user_id, node_id, created_at) VALUES (?, ?, ?)`,
		)
		if err != nil {
			return nil, mapSQLiteErr(err)
		}
		defer stmt.Close()
		for _, uid := range userIDs {
			for _, nid := range cleanIDs {
				if _, err := stmt.ExecContext(ctx, uid, nid, nowStr); err != nil {
					return nil, mapSQLiteErr(err)
				}
			}
		}
	}

	return cleanIDs, nil
}

// CreateLBGroup creates a load-balancing group, assigns members, syncs unified configs,
// unions user_node_access, and returns the affected member node IDs.
func (s *Store) CreateLBGroup(ctx context.Context, grp *LBGroup, memberNodeIDs []int64) ([]int64, error) {
	if err := validateLBGroupForStore(grp); err != nil {
		return nil, err
	}
	snellBytes, err := json.Marshal(grp.SnellConfig)
	if err != nil {
		return nil, fmt.Errorf("store: marshal lb_group snell_config: %w", err)
	}
	ssToStore := grp.SSConfig
	ssToStore.Users = nil
	ssBytes, err := json.Marshal(ssToStore)
	if err != nil {
		return nil, fmt.Errorf("store: marshal lb_group ss_config: %w", err)
	}
	if grp.ActiveRecords == nil {
		grp.ActiveRecords = []LBActiveRecord{}
	}
	activeBytes, err := json.Marshal(grp.ActiveRecords)
	if err != nil {
		return nil, fmt.Errorf("store: marshal lb_group active_records: %w", err)
	}

	now := time.Now().UTC()
	nowStr := FormatSQLiteTime(now)
	var affected []int64

	err = s.withTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
INSERT INTO lb_groups (
    name, region_tag, enabled, sort_order,
    dns_zone_id, dns_zone_name, dns_domain, dns_ttl,
    strategy, switch_diff_bytes, switch_cooldown_minutes, failover_threshold_percent,
    snell_config, ss_config, pinned_node_id, active_node_id, active_records_json,
    last_switch_at, last_sync_at, last_sync_error, is_exhausted, created_at, updated_at
) VALUES (
    ?, ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?, NULL, NULL, ?,
    NULL, NULL, '', 0, ?, ?
)`,
			grp.Name, grp.RegionTag, boolToInt(grp.Enabled), grp.SortOrder,
			grp.DNSZoneID, grp.DNSZoneName, grp.DNSDomain, grp.DNSTTL,
			grp.Strategy, grp.SwitchDiffBytes, grp.SwitchCooldownMinutes, grp.FailoverThresholdPercent,
			string(snellBytes), string(ssBytes), string(activeBytes),
			nowStr, nowStr,
		)
		if err != nil {
			return mapSQLiteErr(err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("store: lb_group LastInsertId: %w", err)
		}
		grp.ID = id
		grp.CreatedAt = now
		grp.UpdatedAt = now

		affected, err = applyLBGroupMembersAndSyncTx(ctx, tx, id, grp.SnellConfig, ssToStore, memberNodeIDs, nowStr)
		if err != nil {
			return err
		}
		members, err := loadLBGroupMembersTx(ctx, tx, id)
		if err != nil {
			return err
		}
		grp.Members = members
		return nil
	})
	if err != nil {
		return nil, err
	}
	return affected, nil
}

// UpdateLBGroup updates a load-balancing group, replaces its members, syncs unified configs,
// unions user_node_access, and returns the affected member node IDs.
func (s *Store) UpdateLBGroup(ctx context.Context, grp *LBGroup, memberNodeIDs []int64) ([]int64, error) {
	if grp == nil || grp.ID <= 0 {
		return nil, fmt.Errorf("%w: valid lb group id required", ErrInvalidArgument)
	}
	if err := validateLBGroupForStore(grp); err != nil {
		return nil, err
	}
	snellBytes, err := json.Marshal(grp.SnellConfig)
	if err != nil {
		return nil, fmt.Errorf("store: marshal lb_group snell_config: %w", err)
	}
	ssToStore := grp.SSConfig
	ssToStore.Users = nil
	ssBytes, err := json.Marshal(ssToStore)
	if err != nil {
		return nil, fmt.Errorf("store: marshal lb_group ss_config: %w", err)
	}

	now := time.Now().UTC()
	nowStr := FormatSQLiteTime(now)
	var affected []int64

	err = s.withTx(ctx, func(tx *sql.Tx) error {
		var curPinned, curActive sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT pinned_node_id, active_node_id FROM lb_groups WHERE id = ?`, grp.ID).
			Scan(&curPinned, &curActive); err != nil {
			return mapSQLiteErr(err)
		}

		cleanIDs, err := dedupPositiveNodeIDs(memberNodeIDs)
		if err != nil {
			return err
		}
		memberSet := make(map[int64]struct{}, len(cleanIDs))
		for _, id := range cleanIDs {
			memberSet[id] = struct{}{}
		}
		var nextPinned sql.NullInt64
		if curPinned.Valid {
			if _, ok := memberSet[curPinned.Int64]; ok {
				nextPinned = curPinned
			}
		}
		var nextActive sql.NullInt64
		if curActive.Valid {
			if _, ok := memberSet[curActive.Int64]; ok {
				nextActive = curActive
			}
		}

		res, err := tx.ExecContext(ctx, `
UPDATE lb_groups SET
    name = ?, region_tag = ?, enabled = ?, sort_order = ?,
    dns_zone_id = ?, dns_zone_name = ?, dns_domain = ?, dns_ttl = ?,
    strategy = ?, switch_diff_bytes = ?, switch_cooldown_minutes = ?, failover_threshold_percent = ?,
    snell_config = ?, ss_config = ?, pinned_node_id = ?, active_node_id = ?, updated_at = ?
WHERE id = ?`,
			grp.Name, grp.RegionTag, boolToInt(grp.Enabled), grp.SortOrder,
			grp.DNSZoneID, grp.DNSZoneName, grp.DNSDomain, grp.DNSTTL,
			grp.Strategy, grp.SwitchDiffBytes, grp.SwitchCooldownMinutes, grp.FailoverThresholdPercent,
			string(snellBytes), string(ssBytes), nextPinned, nextActive, nowStr,
			grp.ID,
		)
		if err != nil {
			return mapSQLiteErr(err)
		}
		if err := ensureOneRowAffected(res); err != nil {
			return err
		}

		affected, err = applyLBGroupMembersAndSyncTx(ctx, tx, grp.ID, grp.SnellConfig, ssToStore, cleanIDs, nowStr)
		if err != nil {
			return err
		}
		members, err := loadLBGroupMembersTx(ctx, tx, grp.ID)
		if err != nil {
			return err
		}
		grp.Members = members
		grp.UpdatedAt = now
		return nil
	})
	if err != nil {
		return nil, err
	}
	return affected, nil
}

// GetLBGroupByID fetches one load-balancing group and its ordered members.
func (s *Store) GetLBGroupByID(ctx context.Context, id int64) (*LBGroup, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+lbGroupColumns+` FROM lb_groups WHERE id = ?`, id)
	grp, err := scanLBGroup(row)
	if err != nil {
		return nil, err
	}
	members, err := s.listLBGroupMembers(ctx, grp.ID)
	if err != nil {
		return nil, err
	}
	grp.Members = members
	return grp, nil
}

// GetLBGroupByNodeID fetches the load-balancing group containing nodeID, or ErrNotFound.
func (s *Store) GetLBGroupByNodeID(ctx context.Context, nodeID int64) (*LBGroup, error) {
	if nodeID <= 0 {
		return nil, ErrNotFound
	}
	var groupID int64
	err := s.db.QueryRowContext(ctx, `SELECT group_id FROM lb_group_members WHERE node_id = ?`, nodeID).Scan(&groupID)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	return s.GetLBGroupByID(ctx, groupID)
}

func (s *Store) listLBGroupMembers(ctx context.Context, groupID int64) ([]LBGroupMember, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT group_id, node_id, priority, created_at
FROM lb_group_members
WHERE group_id = ?
ORDER BY priority ASC, node_id ASC`, groupID)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	defer rows.Close()

	out := []LBGroupMember{}
	for rows.Next() {
		var m LBGroupMember
		var createdStr string
		if err := rows.Scan(&m.GroupID, &m.NodeID, &m.Priority, &createdStr); err != nil {
			return nil, mapSQLiteErr(err)
		}
		t, err := ParseSQLiteTime(createdStr)
		if err != nil {
			return nil, err
		}
		m.CreatedAt = t
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, mapSQLiteErr(err)
	}
	return out, nil
}

// ListLBGroups returns all load-balancing groups ordered by sort_order ASC, id ASC with members.
func (s *Store) ListLBGroups(ctx context.Context) ([]LBGroup, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+lbGroupColumns+` FROM lb_groups ORDER BY sort_order ASC, id ASC`)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	defer rows.Close()

	groups := []LBGroup{}
	byID := make(map[int64]int)
	for rows.Next() {
		g, err := scanLBGroup(rows)
		if err != nil {
			return nil, err
		}
		byID[g.ID] = len(groups)
		groups = append(groups, *g)
	}
	if err := rows.Err(); err != nil {
		return nil, mapSQLiteErr(err)
	}
	_ = rows.Close()

	if len(groups) == 0 {
		return groups, nil
	}

	mRows, err := s.db.QueryContext(ctx, `
SELECT group_id, node_id, priority, created_at
FROM lb_group_members
ORDER BY group_id ASC, priority ASC, node_id ASC`)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	defer mRows.Close()

	for mRows.Next() {
		var m LBGroupMember
		var createdStr string
		if err := mRows.Scan(&m.GroupID, &m.NodeID, &m.Priority, &createdStr); err != nil {
			return nil, mapSQLiteErr(err)
		}
		t, err := ParseSQLiteTime(createdStr)
		if err != nil {
			return nil, err
		}
		m.CreatedAt = t
		if idx, ok := byID[m.GroupID]; ok {
			groups[idx].Members = append(groups[idx].Members, m)
		}
	}
	if err := mRows.Err(); err != nil {
		return nil, mapSQLiteErr(err)
	}
	return groups, nil
}

// ListNodeLBGroupMembership returns a map of node_id -> LBGroupSummary for quick lookup.
func (s *Store) ListNodeLBGroupMembership(ctx context.Context) (map[int64]LBGroupSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT m.node_id, g.id, g.name, g.enabled
FROM lb_group_members m
INNER JOIN lb_groups g ON g.id = m.group_id`)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	defer rows.Close()

	out := make(map[int64]LBGroupSummary)
	for rows.Next() {
		var nodeID int64
		var sum LBGroupSummary
		var enabledInt int
		if err := rows.Scan(&nodeID, &sum.ID, &sum.Name, &enabledInt); err != nil {
			return nil, mapSQLiteErr(err)
		}
		sum.Enabled = enabledInt == 1
		out[nodeID] = sum
	}
	if err := rows.Err(); err != nil {
		return nil, mapSQLiteErr(err)
	}
	return out, nil
}

// DeleteLBGroup removes a load-balancing group (cascades member links and switch logs; nodes remain).
func (s *Store) DeleteLBGroup(ctx context.Context, id int64) error {
	if id <= 0 {
		return fmt.Errorf("%w: invalid lb group id", ErrInvalidArgument)
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM lb_groups WHERE id = ?`, id)
	if err != nil {
		return mapSQLiteErr(err)
	}
	return ensureOneRowAffected(res)
}

// SetLBGroupPinnedNode sets or clears the manually pinned node for a group.
func (s *Store) SetLBGroupPinnedNode(ctx context.Context, groupID int64, nodeID *int64) error {
	if groupID <= 0 {
		return fmt.Errorf("%w: invalid lb group id", ErrInvalidArgument)
	}
	nowStr := FormatSQLiteTime(time.Now().UTC())
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM lb_groups WHERE id = ?`, groupID).Scan(&exists); err != nil {
			return mapSQLiteErr(err)
		}
		var arg sql.NullInt64
		if nodeID != nil {
			if *nodeID <= 0 {
				return fmt.Errorf("%w: node_id must be positive", ErrInvalidArgument)
			}
			var inGroup int
			if err := tx.QueryRowContext(ctx,
				`SELECT 1 FROM lb_group_members WHERE group_id = ? AND node_id = ?`,
				groupID, *nodeID,
			).Scan(&inGroup); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return fmt.Errorf("%w: node %d is not a member of group %d", ErrInvalidArgument, *nodeID, groupID)
				}
				return mapSQLiteErr(err)
			}
			arg = sql.NullInt64{Int64: *nodeID, Valid: true}
		}
		_, err := tx.ExecContext(ctx,
			`UPDATE lb_groups SET pinned_node_id = ?, updated_at = ? WHERE id = ?`,
			arg, nowStr, groupID,
		)
		return mapSQLiteErr(err)
	})
}

// UpdateLBGroupSyncState persists active DNS resolution state after an LB evaluation.
func (s *Store) UpdateLBGroupSyncState(ctx context.Context, groupID int64, st LBGroupSyncState) error {
	if groupID <= 0 {
		return fmt.Errorf("%w: invalid lb group id", ErrInvalidArgument)
	}
	records := st.ActiveRecords
	if records == nil {
		records = []LBActiveRecord{}
	}
	recordsBytes, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("store: marshal active_records: %w", err)
	}

	var activeArg sql.NullInt64
	if st.ActiveNodeID != nil && *st.ActiveNodeID > 0 {
		activeArg = sql.NullInt64{Int64: *st.ActiveNodeID, Valid: true}
	}

	nowStr := FormatSQLiteTime(time.Now().UTC())
	res, err := s.db.ExecContext(ctx, `
UPDATE lb_groups SET
    active_node_id = ?,
    active_records_json = ?,
    last_switch_at = ?,
    last_sync_at = ?,
    last_sync_error = ?,
    is_exhausted = ?,
    updated_at = ?
WHERE id = ?`,
		activeArg,
		string(recordsBytes),
		formatNullableTime(st.LastSwitchAt),
		formatNullableTime(st.LastSyncAt),
		st.LastSyncError,
		boolToInt(st.IsExhausted),
		nowStr,
		groupID,
	)
	if err != nil {
		return mapSQLiteErr(err)
	}
	return ensureOneRowAffected(res)
}

// AppendLBSwitchLog appends a switch/failover/pin/error log entry and keeps at most 100 logs per group.
func (s *Store) AppendLBSwitchLog(ctx context.Context, entry *LBSwitchLog) error {
	if entry == nil || entry.GroupID <= 0 || strings.TrimSpace(entry.EventType) == "" {
		return fmt.Errorf("%w: valid group_id and event_type required", ErrInvalidArgument)
	}
	created := entry.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	created = created.UTC()

	var fromArg, toArg sql.NullInt64
	if entry.FromNodeID != nil && *entry.FromNodeID > 0 {
		fromArg = sql.NullInt64{Int64: *entry.FromNodeID, Valid: true}
	}
	if entry.ToNodeID != nil && *entry.ToNodeID > 0 {
		toArg = sql.NullInt64{Int64: *entry.ToNodeID, Valid: true}
	}

	return s.withTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
INSERT INTO lb_switch_logs(group_id, event_type, from_node_id, to_node_id, from_ips, to_ips, reason, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			entry.GroupID, strings.TrimSpace(entry.EventType), fromArg, toArg,
			entry.FromIPs, entry.ToIPs, entry.Reason, FormatSQLiteTime(created),
		)
		if err != nil {
			return mapSQLiteErr(err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("store: lb_switch_log LastInsertId: %w", err)
		}
		entry.ID = id
		entry.CreatedAt = created

		_, err = tx.ExecContext(ctx, `
DELETE FROM lb_switch_logs
WHERE group_id = ? AND id NOT IN (
    SELECT id FROM lb_switch_logs WHERE group_id = ? ORDER BY id DESC LIMIT 100
)`, entry.GroupID, entry.GroupID)
		return mapSQLiteErr(err)
	})
}

// ListLBSwitchLogs lists switch logs for a group ordered newest first.
func (s *Store) ListLBSwitchLogs(ctx context.Context, groupID int64, limit int) ([]LBSwitchLog, error) {
	if groupID <= 0 {
		return nil, fmt.Errorf("%w: invalid lb group id", ErrInvalidArgument)
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, group_id, event_type, from_node_id, to_node_id, from_ips, to_ips, reason, created_at
FROM lb_switch_logs
WHERE group_id = ?
ORDER BY id DESC
LIMIT ?`, groupID, limit)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	defer rows.Close()

	out := []LBSwitchLog{}
	for rows.Next() {
		var item LBSwitchLog
		var fromID, toID sql.NullInt64
		var createdStr string
		if err := rows.Scan(
			&item.ID, &item.GroupID, &item.EventType,
			&fromID, &toID, &item.FromIPs, &item.ToIPs, &item.Reason, &createdStr,
		); err != nil {
			return nil, mapSQLiteErr(err)
		}
		if fromID.Valid {
			v := fromID.Int64
			item.FromNodeID = &v
		}
		if toID.Valid {
			v := toID.Int64
			item.ToNodeID = &v
		}
		t, err := ParseSQLiteTime(createdStr)
		if err != nil {
			return nil, err
		}
		item.CreatedAt = t
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, mapSQLiteErr(err)
	}
	return out, nil
}

// ExpandUserNodeIDsForLBGroups ensures user_node_access stays consistent across LB group members.
// When oldNodeIDs is nil (new user), any group with >=1 requested member expands to all members.
// When updating an existing user (oldNodeIDs != nil), adding any group member expands to all members,
// while removing any group member removes all members unless every member remains selected.
func (s *Store) ExpandUserNodeIDsForLBGroups(ctx context.Context, oldNodeIDs, requestedNodeIDs []int64) ([]int64, error) {
	groups, err := s.ListLBGroups(ctx)
	if err != nil {
		return nil, err
	}
	reqSet := make(map[int64]struct{}, len(requestedNodeIDs))
	for _, id := range requestedNodeIDs {
		if id > 0 {
			reqSet[id] = struct{}{}
		}
	}
	if len(groups) == 0 {
		out := make([]int64, 0, len(reqSet))
		for id := range reqSet {
			out = append(out, id)
		}
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		return out, nil
	}

	oldSet := make(map[int64]struct{}, len(oldNodeIDs))
	for _, id := range oldNodeIDs {
		oldSet[id] = struct{}{}
	}

	for _, g := range groups {
		if len(g.Members) == 0 {
			continue
		}
		anyReq := false
		allReq := true
		anyAdded := false
		for _, m := range g.Members {
			_, inReq := reqSet[m.NodeID]
			_, inOld := oldSet[m.NodeID]
			if inReq {
				anyReq = true
				if !inOld {
					anyAdded = true
				}
			} else {
				allReq = false
			}
		}

		if oldNodeIDs == nil {
			if anyReq {
				for _, m := range g.Members {
					reqSet[m.NodeID] = struct{}{}
				}
			}
			continue
		}

		if anyAdded {
			for _, m := range g.Members {
				reqSet[m.NodeID] = struct{}{}
			}
		} else if !allReq {
			for _, m := range g.Members {
				delete(reqSet, m.NodeID)
			}
		}
	}

	out := make([]int64, 0, len(reqSet))
	for id := range reqSet {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}
