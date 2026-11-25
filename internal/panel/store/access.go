package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func getUserNodeIDsTx(ctx context.Context, tx *sql.Tx, userID int64) ([]int64, error) {
	rows, err := tx.QueryContext(ctx, `SELECT node_id FROM user_node_access WHERE user_id = ? ORDER BY node_id ASC`, userID)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	defer rows.Close()

	out := []int64{}
	for rows.Next() {
		var nid int64
		if err := rows.Scan(&nid); err != nil {
			return nil, mapSQLiteErr(err)
		}
		out = append(out, nid)
	}
	if err := rows.Err(); err != nil {
		return nil, mapSQLiteErr(err)
	}
	return out, nil
}

func insertUserNodesTx(ctx context.Context, tx *sql.Tx, userID int64, nodeIDs []int64, nowStr string) error {
	if len(nodeIDs) == 0 {
		return nil
	}

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO user_node_access(user_id, node_id, created_at) VALUES (?, ?, ?)`)
	if err != nil {
		return mapSQLiteErr(err)
	}
	defer stmt.Close()

	seen := make(map[int64]struct{}, len(nodeIDs))
	for _, nid := range nodeIDs {
		if nid <= 0 {
			return fmt.Errorf("%w: node_id must be positive", ErrInvalidArgument)
		}
		if _, ok := seen[nid]; ok {
			continue
		}
		seen[nid] = struct{}{}
		if _, err := stmt.ExecContext(ctx, userID, nid, nowStr); err != nil {
			return mapSQLiteErr(err)
		}
	}
	return nil
}

func replaceUserNodesTx(ctx context.Context, tx *sql.Tx, userID int64, nodeIDs []int64, nowStr string) ([]int64, []int64, error) {
	oldIDs, err := getUserNodeIDsTx(ctx, tx, userID)
	if err != nil {
		return nil, nil, err
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM user_node_access WHERE user_id = ?`, userID); err != nil {
		return nil, nil, mapSQLiteErr(err)
	}

	if err := insertUserNodesTx(ctx, tx, userID, nodeIDs, nowStr); err != nil {
		return nil, nil, err
	}

	if len(nodeIDs) == 0 {
		return oldIDs, []int64{}, nil
	}
	newIDs, err := getUserNodeIDsTx(ctx, tx, userID)
	if err != nil {
		return nil, nil, err
	}
	return oldIDs, newIDs, nil
}

// ReplaceUserNodes atomically replaces the authorized node list for userID
// and returns the sorted previous and new node IDs.
func (s *Store) ReplaceUserNodes(ctx context.Context, userID int64, nodeIDs []int64) ([]int64, []int64, error) {
	if userID <= 0 {
		return nil, nil, fmt.Errorf("%w: invalid user_id", ErrInvalidArgument)
	}
	nowStr := FormatSQLiteTime(time.Now().UTC())
	var oldIDs, newIDs []int64
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE id = ?`, userID).Scan(&exists); err != nil {
			return mapSQLiteErr(err)
		}
		var err error
		oldIDs, newIDs, err = replaceUserNodesTx(ctx, tx, userID, nodeIDs, nowStr)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return oldIDs, newIDs, nil
}

// SetUserNodes atomically replaces the authorized node list for userID.
func (s *Store) SetUserNodes(ctx context.Context, userID int64, nodeIDs []int64) error {
	_, _, err := s.ReplaceUserNodes(ctx, userID, nodeIDs)
	return err
}

// GrantNodeToAllUsers idempotently grants access to nodeID for every existing user.
func (s *Store) GrantNodeToAllUsers(ctx context.Context, nodeID int64) (int64, error) {
	if nodeID <= 0 {
		return 0, fmt.Errorf("%w: invalid node_id", ErrInvalidArgument)
	}
	nowStr := FormatSQLiteTime(time.Now().UTC())
	var affected int64
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO user_node_access(user_id, node_id, created_at)
SELECT id, ?, ? FROM users`,
			nodeID, nowStr,
		)
		if err != nil {
			return mapSQLiteErr(err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return mapSQLiteErr(err)
		}
		affected = n
		return nil
	})
	if err != nil {
		return 0, err
	}
	return affected, nil
}

// GetUserNodeIDs returns the authorized node IDs for userID ordered by node_id ASC.
func (s *Store) GetUserNodeIDs(ctx context.Context, userID int64) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id FROM user_node_access WHERE user_id = ? ORDER BY node_id ASC`, userID)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	defer rows.Close()

	var out []int64
	for rows.Next() {
		var nid int64
		if err := rows.Scan(&nid); err != nil {
			return nil, mapSQLiteErr(err)
		}
		out = append(out, nid)
	}
	if err := rows.Err(); err != nil {
		return nil, mapSQLiteErr(err)
	}
	return out, nil
}

// ListAllUserNodeAccess returns a map from user_id to sorted authorized node IDs.
func (s *Store) ListAllUserNodeAccess(ctx context.Context) (map[int64][]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT user_id, node_id FROM user_node_access ORDER BY user_id ASC, node_id ASC`)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	defer rows.Close()

	out := make(map[int64][]int64)
	for rows.Next() {
		var uid, nid int64
		if err := rows.Scan(&uid, &nid); err != nil {
			return nil, mapSQLiteErr(err)
		}
		out[uid] = append(out[uid], nid)
	}
	if err := rows.Err(); err != nil {
		return nil, mapSQLiteErr(err)
	}
	return out, nil
}

// ListAuthorizedUsersForNode returns enabled, unexpired, within-quota users authorized on nodeID.
func (s *Store) ListAuthorizedUsersForNode(ctx context.Context, nodeID int64, now time.Time) ([]User, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nowStr := FormatSQLiteTime(now)

	rows, err := s.db.QueryContext(ctx, `
SELECT u.id, u.username, u.enabled, u.sub_token, u.ss_upsk_16, u.ss_upsk_32, u.stls_password,
       u.traffic_quota_bytes, u.billing_reset_day, u.used_up_bytes, u.used_down_bytes,
       u.last_reset_at, u.expire_at, u.created_at, u.updated_at
FROM users u
INNER JOIN user_node_access una ON una.user_id = u.id
WHERE una.node_id = ?
  AND u.enabled = 1
  AND (u.expire_at IS NULL OR u.expire_at > ?)
  AND (u.traffic_quota_bytes = 0 OR (u.used_up_bytes + u.used_down_bytes) < u.traffic_quota_bytes)
ORDER BY u.id ASC`,
		nodeID, nowStr,
	)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	if err := rows.Err(); err != nil {
		return nil, mapSQLiteErr(err)
	}
	return out, nil
}

// ListAuthorizedNodesForUser returns enabled, non-paused nodes authorized for userID,
// ordered by sort_order ASC, id ASC.
func (s *Store) ListAuthorizedNodesForUser(ctx context.Context, userID int64) ([]Node, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT n.id, n.name, n.region_tag, n.token_hash, n.public_ip, n.public_ipv6,
       n.custom_entry_host, n.custom_entry_port, n.sort_order, n.enabled, n.status, n.paused_reason,
       n.snell_config, n.ss_config, n.dns_unlock_enabled, n.dns_unlock_server, n.dns_rule_group_id, n.dns_extra_rules,
       n.traffic_limit_bytes, n.traffic_threshold_bytes, n.traffic_count_mode, n.threshold_action, n.billing_reset_day,
       n.cycle_rx_bytes, n.cycle_tx_bytes, n.total_rx_bytes, n.total_tx_bytes, n.last_reset_at, n.is_traffic_paused,
       n.config_revision, n.reported_config_revision, n.reported_versions, n.agent_os, n.agent_arch, n.cpu_cores,
       n.last_seen_at, n.cpu_percent, n.mem_used_bytes, n.mem_total_bytes, n.disk_used_percent, n.uptime_seconds,
       n.rx_bps, n.tx_bps, n.core_a_healthy, n.core_b_healthy, n.created_at, n.updated_at
FROM nodes n
INNER JOIN user_node_access una ON una.node_id = n.id
WHERE una.user_id = ?
  AND n.enabled = 1
  AND n.is_traffic_paused = 0
ORDER BY n.sort_order ASC, n.id ASC`,
		userID,
	)
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
