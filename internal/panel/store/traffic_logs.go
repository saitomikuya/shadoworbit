package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"snell-panel/internal/protocol"
)

const (
	DefaultTrafficLogMaxEntries      = 10000
	MinTrafficLogMaxEntries          = 100
	MaxTrafficLogMaxEntries          = 1000000
	DefaultTrafficLogMergeGapMinutes = 5
	MaxTrafficLogMergeGapMinutes     = 1440
)

// TrafficApplyResult summarizes the post-commit state after ApplyTrafficDeltas.
type TrafficApplyResult struct {
	Node           *Node
	UpdatedUserIDs []int64
	SkippedUserIDs []int64
}

// ApplyTrafficDeltas atomically applies node NIC deltas, per-user deltas, and daily/minute traffic logs
// in a single SQLite transaction. Non-existent users in userDeltas (e.g. recently deleted while
// agent stats were in flight) are skipped without aborting node or remaining user accounting.
func (s *Store) ApplyTrafficDeltas(
	ctx context.Context,
	nodeID int64,
	nicRxDelta, nicTxDelta int64,
	userDeltas []protocol.UserTrafficDelta,
	logDate string,
) (*TrafficApplyResult, error) {
	trimmedDate := strings.TrimSpace(logDate)
	if nodeID <= 0 || trimmedDate == "" {
		return nil, fmt.Errorf("%w: node_id and log_date are required", ErrInvalidArgument)
	}
	nowUTC := time.Now().UTC()
	logMinute := nowUTC.Truncate(time.Minute).Format("2006-01-02T15:04:00Z")
	if len(trimmedDate) == 10 && trimmedDate != nowUTC.Format("2006-01-02") {
		logMinute = trimmedDate + "T" + nowUTC.Format("15:04") + ":00Z"
	}
	return s.applyTrafficDeltas(ctx, nodeID, nicRxDelta, nicTxDelta, userDeltas, trimmedDate, logMinute)
}

// ApplyTrafficDeltasAt atomically applies traffic deltas using the provided timestamp for daily and minute buckets.
func (s *Store) ApplyTrafficDeltasAt(
	ctx context.Context,
	nodeID int64,
	nicRxDelta, nicTxDelta int64,
	userDeltas []protocol.UserTrafficDelta,
	at time.Time,
) (*TrafficApplyResult, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	utc := at.UTC()
	return s.applyTrafficDeltas(
		ctx,
		nodeID,
		nicRxDelta,
		nicTxDelta,
		userDeltas,
		utc.Format("2006-01-02"),
		utc.Truncate(time.Minute).Format("2006-01-02T15:04:00Z"),
	)
}

func (s *Store) applyTrafficDeltas(
	ctx context.Context,
	nodeID int64,
	nicRxDelta, nicTxDelta int64,
	userDeltas []protocol.UserTrafficDelta,
	logDate string,
	logMinute string,
) (*TrafficApplyResult, error) {
	if nodeID <= 0 || strings.TrimSpace(logDate) == "" {
		return nil, fmt.Errorf("%w: node_id and log_date are required", ErrInvalidArgument)
	}
	if nicRxDelta < 0 || nicTxDelta < 0 {
		return nil, fmt.Errorf("%w: traffic deltas must be non-negative", ErrInvalidArgument)
	}
	for _, ud := range userDeltas {
		if ud.UpBytes > math.MaxInt64 || ud.DownBytes > math.MaxInt64 {
			return nil, fmt.Errorf("%w: user traffic delta exceeds int64 max", ErrInvalidArgument)
		}
	}

	now := FormatSQLiteTime(time.Now().UTC())
	res := &TrafficApplyResult{}

	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var curNodeRx, curNodeTx, curTotalRx, curTotalTx int64
		err := tx.QueryRowContext(ctx, `SELECT cycle_rx_bytes, cycle_tx_bytes, total_rx_bytes, total_tx_bytes FROM nodes WHERE id = ?`, nodeID).Scan(&curNodeRx, &curNodeTx, &curTotalRx, &curTotalTx)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return mapSQLiteErr(err)
		}
		if curNodeRx > math.MaxInt64-nicRxDelta || curNodeTx > math.MaxInt64-nicTxDelta ||
			curTotalRx > math.MaxInt64-nicRxDelta || curTotalTx > math.MaxInt64-nicTxDelta {
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
			nicRxDelta, nicTxDelta, nicRxDelta, nicTxDelta, now, nodeID,
		); err != nil {
			return mapSQLiteErr(err)
		}

		if nicRxDelta > 0 || nicTxDelta > 0 {
			if err := upsertAddDailyTrafficTx(ctx, tx, "node", nodeID, logDate, nicRxDelta, nicTxDelta); err != nil {
				return err
			}
		}

		userStmt, err := tx.PrepareContext(ctx, `
UPDATE users SET
    used_up_bytes = used_up_bytes + ?,
    used_down_bytes = used_down_bytes + ?,
    updated_at = ?
WHERE id = ?`)
		if err != nil {
			return mapSQLiteErr(err)
		}
		defer userStmt.Close()

		wroteUsageLog := false
		for _, ud := range userDeltas {
			if ud.UpBytes == 0 && ud.DownBytes == 0 {
				continue
			}
			uid := ud.UserID
			if uid <= 0 && ud.Username != "" {
				err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE username = ?`, ud.Username).Scan(&uid)
				if errors.Is(err, sql.ErrNoRows) {
					continue
				}
				if err != nil {
					return mapSQLiteErr(err)
				}
			}
			if uid <= 0 {
				continue
			}

			upBytes := int64(ud.UpBytes)
			downBytes := int64(ud.DownBytes)

			var curUp, curDown int64
			err := tx.QueryRowContext(ctx, `SELECT used_up_bytes, used_down_bytes FROM users WHERE id = ?`, uid).Scan(&curUp, &curDown)
			if errors.Is(err, sql.ErrNoRows) {
				res.SkippedUserIDs = append(res.SkippedUserIDs, uid)
				continue
			}
			if err != nil {
				return mapSQLiteErr(err)
			}
			if curUp > math.MaxInt64-upBytes || curDown > math.MaxInt64-downBytes {
				return fmt.Errorf("%w: user traffic counter overflow", ErrInvalidArgument)
			}

			if _, err := userStmt.ExecContext(ctx, upBytes, downBytes, now, uid); err != nil {
				return mapSQLiteErr(err)
			}
			if err := upsertAddDailyTrafficTx(ctx, tx, "user", uid, logDate, downBytes, upBytes); err != nil {
				return err
			}
			if err := upsertAddUserNodeTrafficTx(ctx, tx, uid, nodeID, upBytes, downBytes, now); err != nil {
				return err
			}
			if err := upsertAddTrafficUsageLogTx(ctx, tx, nodeID, uid, logMinute, downBytes, upBytes, now); err != nil {
				return err
			}
			wroteUsageLog = true
			res.UpdatedUserIDs = append(res.UpdatedUserIDs, uid)
		}

		if wroteUsageLog {
			maxEntries := DefaultTrafficLogMaxEntries
			var rawMax string
			if err := tx.QueryRowContext(ctx, `SELECT value FROM system_settings WHERE key = 'traffic_log_max_entries'`).Scan(&rawMax); err == nil {
				if parsed, convErr := strconv.Atoi(strings.TrimSpace(rawMax)); convErr == nil && parsed > 0 {
					maxEntries = parsed
				}
			}
			if _, err := pruneTrafficUsageLogsTx(ctx, tx, maxEntries); err != nil {
				return err
			}
		}

		updatedNode, err := scanNode(tx.QueryRowContext(ctx, `SELECT `+nodeColumns+` FROM nodes WHERE id = ?`, nodeID))
		if err != nil {
			return err
		}
		res.Node = updatedNode
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func upsertAddDailyTrafficTx(ctx context.Context, tx *sql.Tx, targetType string, targetID int64, logDate string, rxDelta, txDelta int64) error {
	var curRx, curTx int64
	err := tx.QueryRowContext(ctx, `
SELECT rx_bytes, tx_bytes FROM traffic_logs_daily
WHERE target_type = ? AND target_id = ? AND log_date = ?`,
		targetType, targetID, logDate,
	).Scan(&curRx, &curTx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return mapSQLiteErr(err)
	}
	if err == nil {
		if curRx > math.MaxInt64-rxDelta || curTx > math.MaxInt64-txDelta {
			return fmt.Errorf("%w: daily traffic counter overflow", ErrInvalidArgument)
		}
	}

	_, err = tx.ExecContext(ctx, `
INSERT INTO traffic_logs_daily(target_type, target_id, log_date, rx_bytes, tx_bytes)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(target_type, target_id, log_date) DO UPDATE SET
    rx_bytes = traffic_logs_daily.rx_bytes + excluded.rx_bytes,
    tx_bytes = traffic_logs_daily.tx_bytes + excluded.tx_bytes`,
		targetType, targetID, logDate, rxDelta, txDelta,
	)
	return mapSQLiteErr(err)
}

// UpsertAddDailyTraffic atomically accumulates daily traffic deltas for a node or user.
func (s *Store) UpsertAddDailyTraffic(ctx context.Context, targetType string, targetID int64, logDate string, rxDelta, txDelta int64) error {
	if targetType != "node" && targetType != "user" {
		return fmt.Errorf("%w: invalid target_type %q", ErrInvalidArgument, targetType)
	}
	if targetID <= 0 || strings.TrimSpace(logDate) == "" {
		return fmt.Errorf("%w: target_id and log_date are required", ErrInvalidArgument)
	}
	if rxDelta < 0 || txDelta < 0 {
		return fmt.Errorf("%w: traffic deltas must be non-negative", ErrInvalidArgument)
	}

	return s.withTx(ctx, func(tx *sql.Tx) error {
		return upsertAddDailyTrafficTx(ctx, tx, targetType, targetID, logDate, rxDelta, txDelta)
	})
}

func upsertAddUserNodeTrafficTx(ctx context.Context, tx *sql.Tx, userID, nodeID int64, upDelta, downDelta int64, now string) error {
	var curUp, curDown int64
	err := tx.QueryRowContext(ctx, `
SELECT up_bytes, down_bytes FROM user_node_traffic
WHERE user_id = ? AND node_id = ?`,
		userID, nodeID,
	).Scan(&curUp, &curDown)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return mapSQLiteErr(err)
	}
	if err == nil {
		if curUp > math.MaxInt64-upDelta || curDown > math.MaxInt64-downDelta {
			return fmt.Errorf("%w: user node traffic counter overflow", ErrInvalidArgument)
		}
	}

	_, err = tx.ExecContext(ctx, `
INSERT INTO user_node_traffic(user_id, node_id, up_bytes, down_bytes, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(user_id, node_id) DO UPDATE SET
    up_bytes = user_node_traffic.up_bytes + excluded.up_bytes,
    down_bytes = user_node_traffic.down_bytes + excluded.down_bytes,
    updated_at = excluded.updated_at`,
		userID, nodeID, upDelta, downDelta, now,
	)
	return mapSQLiteErr(err)
}

// ListUserNodeTraffic returns per-node cumulative traffic for userID sorted descending by total bytes.
func (s *Store) ListUserNodeTraffic(ctx context.Context, userID int64) ([]UserNodeTrafficEntry, error) {
	if userID <= 0 {
		return nil, fmt.Errorf("%w: user_id must be positive", ErrInvalidArgument)
	}
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT 1 FROM users WHERE id = ?`, userID).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, mapSQLiteErr(err)
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT n.id, n.name, n.region_tag, unt.up_bytes, unt.down_bytes
FROM user_node_traffic unt
JOIN nodes n ON n.id = unt.node_id
WHERE unt.user_id = ? AND (unt.up_bytes > 0 OR unt.down_bytes > 0)
ORDER BY (unt.up_bytes + unt.down_bytes) DESC, n.id ASC`,
		userID,
	)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	defer rows.Close()

	out := make([]UserNodeTrafficEntry, 0)
	for rows.Next() {
		var e UserNodeTrafficEntry
		if err := rows.Scan(&e.NodeID, &e.NodeName, &e.RegionTag, &e.UpBytes, &e.DownBytes); err != nil {
			return nil, mapSQLiteErr(err)
		}
		e.TotalBytes = e.UpBytes + e.DownBytes
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, mapSQLiteErr(err)
	}
	return out, nil
}

func upsertAddTrafficUsageLogTx(ctx context.Context, tx *sql.Tx, nodeID, userID int64, logMinute string, rxDelta, txDelta int64, now string) error {
	var curRx, curTx int64
	err := tx.QueryRowContext(ctx, `
SELECT rx_bytes, tx_bytes FROM traffic_usage_logs
WHERE node_id = ? AND user_id = ? AND log_minute = ?`,
		nodeID, userID, logMinute,
	).Scan(&curRx, &curTx)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return mapSQLiteErr(err)
	}
	if err == nil {
		if curRx > math.MaxInt64-rxDelta || curTx > math.MaxInt64-txDelta {
			return fmt.Errorf("%w: minute traffic usage counter overflow", ErrInvalidArgument)
		}
	}

	_, err = tx.ExecContext(ctx, `
INSERT INTO traffic_usage_logs(node_id, user_id, log_minute, rx_bytes, tx_bytes, updated_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(node_id, user_id, log_minute) DO UPDATE SET
    rx_bytes = traffic_usage_logs.rx_bytes + excluded.rx_bytes,
    tx_bytes = traffic_usage_logs.tx_bytes + excluded.tx_bytes,
    updated_at = excluded.updated_at`,
		nodeID, userID, logMinute, rxDelta, txDelta, now,
	)
	return mapSQLiteErr(err)
}

func pruneTrafficUsageLogsTx(ctx context.Context, tx *sql.Tx, maxEntries int) (int64, error) {
	if maxEntries <= 0 {
		return 0, nil
	}
	var cutoffMinute string
	var cutoffID int64
	err := tx.QueryRowContext(ctx, `
SELECT log_minute, id FROM traffic_usage_logs
ORDER BY log_minute DESC, id DESC
LIMIT 1 OFFSET ?`,
		maxEntries-1,
	).Scan(&cutoffMinute, &cutoffID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, mapSQLiteErr(err)
	}

	res, err := tx.ExecContext(ctx, `
DELETE FROM traffic_usage_logs
WHERE log_minute < ? OR (log_minute = ? AND id < ?)`,
		cutoffMinute, cutoffMinute, cutoffID,
	)
	if err != nil {
		return 0, mapSQLiteErr(err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return affected, nil
}

// PruneTrafficUsageLogs deletes the oldest traffic_usage_logs rows exceeding maxEntries.
func (s *Store) PruneTrafficUsageLogs(ctx context.Context, maxEntries int) (int64, error) {
	if maxEntries <= 0 {
		return 0, fmt.Errorf("%w: max_entries must be positive", ErrInvalidArgument)
	}
	var pruned int64
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		n, err := pruneTrafficUsageLogsTx(ctx, tx, maxEntries)
		if err != nil {
			return err
		}
		pruned = n
		return nil
	})
	if err != nil {
		return 0, err
	}
	return pruned, nil
}

// QueryTrafficUsageLogs returns per-minute node+user traffic records sorted descending by time.
// When filter.Merge is true, consecutive minutes for the same node and user within MergeGapMinutes are combined.
func (s *Store) QueryTrafficUsageLogs(ctx context.Context, filter TrafficUsageLogFilter) ([]TrafficUsageLog, error) {
	var (
		clauses []string
		args    []any
	)
	if filter.NodeID > 0 {
		clauses = append(clauses, "l.node_id = ?")
		args = append(args, filter.NodeID)
	}
	if filter.UserID != nil {
		clauses = append(clauses, "l.user_id = ?")
		args = append(args, *filter.UserID)
	}
	if filter.From != "" {
		clauses = append(clauses, "l.log_minute >= ?")
		args = append(args, filter.From)
	}
	if filter.To != "" {
		clauses = append(clauses, "l.log_minute <= ?")
		args = append(args, filter.To)
	}

	outLimit := filter.Limit
	if outLimit <= 0 {
		outLimit = 500
	}
	if outLimit > 5000 {
		outLimit = 5000
	}
	sqlLimit := outLimit
	if filter.Merge {
		sqlLimit = 5000
	}

	clauses = append(clauses, "(l.user_id = 0 OR u.id IS NOT NULL)")

	query := `
SELECT l.id, l.node_id, n.name, n.region_tag, l.user_id, COALESCE(u.username, ''), l.log_minute, l.rx_bytes, l.tx_bytes, l.updated_at
FROM traffic_usage_logs l
JOIN nodes n ON n.id = l.node_id
LEFT JOIN users u ON u.id = l.user_id`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY l.log_minute DESC, l.id DESC LIMIT ?"
	args = append(args, sqlLimit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	defer rows.Close()

	out := make([]TrafficUsageLog, 0)
	for rows.Next() {
		var row TrafficUsageLog
		if err := rows.Scan(
			&row.ID, &row.NodeID, &row.NodeName, &row.RegionTag,
			&row.UserID, &row.Username, &row.LogMinute,
			&row.RxBytes, &row.TxBytes, &row.UpdatedAt,
		); err != nil {
			return nil, mapSQLiteErr(err)
		}
		if row.UserID == 0 {
			row.Username = "管理员 (Snell)"
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, mapSQLiteErr(err)
	}
	if filter.Merge {
		return mergeTrafficUsageLogs(out, filter.MergeGapMinutes, outLimit), nil
	}
	return out, nil
}

func parseTrafficLogTime(raw string) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}

func mergeTrafficUsageLogs(rows []TrafficUsageLog, gapMinutes, outLimit int) []TrafficUsageLog {
	if len(rows) == 0 {
		return rows
	}
	if gapMinutes <= 0 {
		gapMinutes = DefaultTrafficLogMergeGapMinutes
	}
	if gapMinutes > MaxTrafficLogMergeGapMinutes {
		gapMinutes = MaxTrafficLogMergeGapMinutes
	}
	maxGap := time.Duration(gapMinutes) * time.Minute

	type groupKey struct {
		nodeID int64
		userID int64
	}
	grouped := make(map[groupKey][]TrafficUsageLog)
	for _, r := range rows {
		k := groupKey{nodeID: r.NodeID, userID: r.UserID}
		grouped[k] = append(grouped[k], r)
	}

	merged := make([]TrafficUsageLog, 0, len(rows))
	for _, items := range grouped {
		sort.Slice(items, func(i, j int) bool {
			if items[i].LogMinute != items[j].LogMinute {
				return items[i].LogMinute < items[j].LogMinute
			}
			return items[i].ID < items[j].ID
		})

		cur := items[0]
		cur.StartTime = cur.LogMinute
		cur.EndTime = cur.LogMinute
		curEndTime, curHasTime := parseTrafficLogTime(cur.EndTime)

		for i := 1; i < len(items); i++ {
			next := items[i]
			nextTime, nextHasTime := parseTrafficLogTime(next.LogMinute)
			shouldMerge := false
			if curHasTime && nextHasTime {
				diff := nextTime.Sub(curEndTime)
				shouldMerge = diff >= 0 && diff <= maxGap
			} else if next.LogMinute == cur.EndTime {
				shouldMerge = true
			}

			if shouldMerge {
				cur.RxBytes += next.RxBytes
				cur.TxBytes += next.TxBytes
				cur.EndTime = next.LogMinute
				cur.LogMinute = next.LogMinute
				cur.ID = next.ID
				cur.UpdatedAt = next.UpdatedAt
				if nextHasTime {
					curEndTime = nextTime
					curHasTime = true
				}
			} else {
				merged = append(merged, cur)
				cur = next
				cur.StartTime = cur.LogMinute
				cur.EndTime = cur.LogMinute
				curEndTime, curHasTime = parseTrafficLogTime(cur.EndTime)
			}
		}
		merged = append(merged, cur)
	}

	sort.Slice(merged, func(i, j int) bool {
		if merged[i].EndTime != merged[j].EndTime {
			return merged[i].EndTime > merged[j].EndTime
		}
		if merged[i].StartTime != merged[j].StartTime {
			return merged[i].StartTime > merged[j].StartTime
		}
		return merged[i].ID > merged[j].ID
	})

	if outLimit > 0 && len(merged) > outLimit {
		merged = merged[:outLimit]
	}
	return merged
}

// RecordAdminSnellTraffic atomically records Snell admin channel traffic for nodeID.
func (s *Store) RecordAdminSnellTraffic(ctx context.Context, nodeID int64, deltaBytes int64, at time.Time) error {
	if nodeID <= 0 || deltaBytes <= 0 {
		return fmt.Errorf("%w: node_id and positive delta_bytes are required", ErrInvalidArgument)
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	utc := at.UTC()
	logMinute := utc.Truncate(time.Minute).Format("2006-01-02T15:04:00Z")
	now := FormatSQLiteTime(utc)

	return s.withTx(ctx, func(tx *sql.Tx) error {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM nodes WHERE id = ?`, nodeID).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return mapSQLiteErr(err)
		}

		var curBytes int64
		err := tx.QueryRowContext(ctx, `SELECT bytes FROM admin_node_traffic WHERE node_id = ?`, nodeID).Scan(&curBytes)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return mapSQLiteErr(err)
		}
		if err == nil && curBytes > math.MaxInt64-deltaBytes {
			return fmt.Errorf("%w: admin node traffic counter overflow", ErrInvalidArgument)
		}

		if _, err := tx.ExecContext(ctx, `
INSERT INTO admin_node_traffic(node_id, bytes, updated_at)
VALUES (?, ?, ?)
ON CONFLICT(node_id) DO UPDATE SET
    bytes = admin_node_traffic.bytes + excluded.bytes,
    updated_at = excluded.updated_at`,
			nodeID, deltaBytes, now,
		); err != nil {
			return mapSQLiteErr(err)
		}

		if err := upsertAddTrafficUsageLogTx(ctx, tx, nodeID, 0, logMinute, deltaBytes, 0, now); err != nil {
			return err
		}

		maxEntries := DefaultTrafficLogMaxEntries
		var rawMax string
		if err := tx.QueryRowContext(ctx, `SELECT value FROM system_settings WHERE key = 'traffic_log_max_entries'`).Scan(&rawMax); err == nil {
			if parsed, convErr := strconv.Atoi(strings.TrimSpace(rawMax)); convErr == nil && parsed > 0 {
				maxEntries = parsed
			}
		}
		_, err = pruneTrafficUsageLogsTx(ctx, tx, maxEntries)
		return err
	})
}

// ListAdminNodeTraffic returns total admin Snell traffic and per-node breakdown sorted descending.
func (s *Store) ListAdminNodeTraffic(ctx context.Context) (int64, []AdminNodeTrafficEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT n.id, n.name, n.region_tag, ant.bytes
FROM admin_node_traffic ant
JOIN nodes n ON n.id = ant.node_id
WHERE ant.bytes > 0
ORDER BY ant.bytes DESC, n.id ASC`)
	if err != nil {
		return 0, nil, mapSQLiteErr(err)
	}
	defer rows.Close()

	var total int64
	items := make([]AdminNodeTrafficEntry, 0)
	for rows.Next() {
		var e AdminNodeTrafficEntry
		if err := rows.Scan(&e.NodeID, &e.NodeName, &e.RegionTag, &e.TotalBytes); err != nil {
			return 0, nil, mapSQLiteErr(err)
		}
		total += e.TotalBytes
		items = append(items, e)
	}
	if err := rows.Err(); err != nil {
		return 0, nil, mapSQLiteErr(err)
	}
	return total, items, nil
}

// ResetAdminTraffic clears cumulative admin Snell node traffic counters.
func (s *Store) ResetAdminTraffic(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM admin_node_traffic`)
	return mapSQLiteErr(err)
}

// CountTrafficUsageLogs returns the total number of stored per-minute usage log entries.
func (s *Store) CountTrafficUsageLogs(ctx context.Context) (int64, error) {
	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM traffic_usage_logs`).Scan(&total); err != nil {
		return 0, mapSQLiteErr(err)
	}
	return total, nil
}

// QueryDailyTraffic queries daily traffic logs using optional filter criteria.
func (s *Store) QueryDailyTraffic(ctx context.Context, filter DailyTrafficFilter) ([]TrafficLogDaily, error) {
	var (
		clauses []string
		args    []any
	)
	if filter.TargetType != "" {
		clauses = append(clauses, "target_type = ?")
		args = append(args, filter.TargetType)
	}
	if filter.TargetID > 0 {
		clauses = append(clauses, "target_id = ?")
		args = append(args, filter.TargetID)
	}
	if filter.FromDate != "" {
		clauses = append(clauses, "log_date >= ?")
		args = append(args, filter.FromDate)
	}
	if filter.ToDate != "" {
		clauses = append(clauses, "log_date <= ?")
		args = append(args, filter.ToDate)
	}

	query := `SELECT id, target_type, target_id, log_date, rx_bytes, tx_bytes FROM traffic_logs_daily`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY log_date ASC, target_type ASC, target_id ASC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	defer rows.Close()

	var out []TrafficLogDaily
	for rows.Next() {
		var row TrafficLogDaily
		if err := rows.Scan(&row.ID, &row.TargetType, &row.TargetID, &row.LogDate, &row.RxBytes, &row.TxBytes); err != nil {
			return nil, mapSQLiteErr(err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, mapSQLiteErr(err)
	}
	return out, nil
}
