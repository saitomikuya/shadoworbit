package store

import (
	"container/heap"
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

	trafficDeltaBatchSize = 200
	maxInt64SQL           = "9223372036854775807"
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
	return s.applyTrafficDeltas(ctx, nodeID, nicRxDelta, nicTxDelta, userDeltas, 0, nil, trimmedDate, logMinute, nowUTC)
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
		0,
		nil,
		utc.Format("2006-01-02"),
		utc.Truncate(time.Minute).Format("2006-01-02T15:04:00Z"),
		utc,
	)
}

// ApplyAgentMetricsAt atomically applies node NIC deltas, per-user deltas, optional admin Snell traffic,
// and optional node telemetry in a single SQLite transaction.
func (s *Store) ApplyAgentMetricsAt(
	ctx context.Context,
	nodeID int64,
	nicRxDelta, nicTxDelta int64,
	userDeltas []protocol.UserTrafficDelta,
	adminSnellBytes int64,
	telemetry *NodeTelemetryUpdate,
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
		adminSnellBytes,
		telemetry,
		utc.Format("2006-01-02"),
		utc.Truncate(time.Minute).Format("2006-01-02T15:04:00Z"),
		utc,
	)
}

type coalescedUserDelta struct {
	userID    int64
	upBytes   int64
	downBytes int64
}

func (s *Store) applyTrafficDeltas(
	ctx context.Context,
	nodeID int64,
	nicRxDelta, nicTxDelta int64,
	userDeltas []protocol.UserTrafficDelta,
	adminSnellBytes int64,
	telemetry *NodeTelemetryUpdate,
	logDate string,
	logMinute string,
	at time.Time,
) (*TrafficApplyResult, error) {
	if nodeID <= 0 || strings.TrimSpace(logDate) == "" {
		return nil, fmt.Errorf("%w: node_id and log_date are required", ErrInvalidArgument)
	}
	if nicRxDelta < 0 || nicTxDelta < 0 || adminSnellBytes < 0 {
		return nil, fmt.Errorf("%w: traffic deltas must be non-negative", ErrInvalidArgument)
	}

	byID := make(map[int64]*coalescedUserDelta, len(userDeltas))
	idOrder := make([]int64, 0, len(userDeltas))
	var byName map[string]*coalescedUserDelta
	var nameOrder []string

	for _, ud := range userDeltas {
		if ud.UpBytes > math.MaxInt64 || ud.DownBytes > math.MaxInt64 {
			return nil, fmt.Errorf("%w: user traffic delta exceeds int64 max", ErrInvalidArgument)
		}
		if ud.UpBytes == 0 && ud.DownBytes == 0 {
			continue
		}
		up := int64(ud.UpBytes)
		dn := int64(ud.DownBytes)
		if ud.UserID > 0 {
			acc, ok := byID[ud.UserID]
			if !ok {
				acc = &coalescedUserDelta{userID: ud.UserID}
				byID[ud.UserID] = acc
				idOrder = append(idOrder, ud.UserID)
			}
			if acc.upBytes > math.MaxInt64-up || acc.downBytes > math.MaxInt64-dn {
				return nil, fmt.Errorf("%w: user traffic delta exceeds int64 max", ErrInvalidArgument)
			}
			acc.upBytes += up
			acc.downBytes += dn
			continue
		}
		if ud.Username != "" {
			if byName == nil {
				byName = make(map[string]*coalescedUserDelta)
			}
			acc, ok := byName[ud.Username]
			if !ok {
				acc = &coalescedUserDelta{}
				byName[ud.Username] = acc
				nameOrder = append(nameOrder, ud.Username)
			}
			if acc.upBytes > math.MaxInt64-up || acc.downBytes > math.MaxInt64-dn {
				return nil, fmt.Errorf("%w: user traffic delta exceeds int64 max", ErrInvalidArgument)
			}
			acc.upBytes += up
			acc.downBytes += dn
		}
	}

	now := FormatSQLiteTime(time.Now().UTC())
	res := &TrafficApplyResult{}

	err := s.withTx(ctx, func(tx *sql.Tx) error {
		// Resolve rare username-only deltas inside the transaction and merge into byID.
		if len(nameOrder) > 0 {
			placeholders := strings.Repeat("?,", len(nameOrder))
			placeholders = placeholders[:len(placeholders)-1]
			args := make([]any, len(nameOrder))
			for i, uname := range nameOrder {
				args[i] = uname
			}
			rows, err := tx.QueryContext(ctx, `SELECT id, username FROM users WHERE username IN (`+placeholders+`)`, args...)
			if err != nil {
				return mapSQLiteErr(err)
			}
			resolved := make(map[string]int64, len(nameOrder))
			for rows.Next() {
				var uid int64
				var uname string
				if err := rows.Scan(&uid, &uname); err != nil {
					_ = rows.Close()
					return mapSQLiteErr(err)
				}
				resolved[uname] = uid
			}
			if err := rows.Err(); err != nil {
				_ = rows.Close()
				return mapSQLiteErr(err)
			}
			_ = rows.Close()

			for _, uname := range nameOrder {
				uid, ok := resolved[uname]
				if !ok || uid <= 0 {
					continue
				}
				src := byName[uname]
				acc, exists := byID[uid]
				if !exists {
					acc = &coalescedUserDelta{userID: uid}
					byID[uid] = acc
					idOrder = append(idOrder, uid)
				}
				if acc.upBytes > math.MaxInt64-src.upBytes || acc.downBytes > math.MaxInt64-src.downBytes {
					return fmt.Errorf("%w: user traffic delta exceeds int64 max", ErrInvalidArgument)
				}
				acc.upBytes += src.upBytes
				acc.downBytes += src.downBytes
			}
		}

		// 1. Single-statement node update + CHECK(>=0) overflow guard + optional telemetry + RETURNING readback.
		var updatedNode *Node
		var nodeErr error
		if telemetry != nil {
			lastSeen := telemetry.LastSeenAt
			if lastSeen.IsZero() {
				lastSeen = at
			}
			if lastSeen.IsZero() {
				lastSeen = time.Now().UTC()
			}
			updatedNode, nodeErr = scanNode(tx.QueryRowContext(ctx, `
UPDATE nodes SET
    cycle_rx_bytes = CASE WHEN cycle_rx_bytes > ? THEN -1 ELSE cycle_rx_bytes + ? END,
    cycle_tx_bytes = CASE WHEN cycle_tx_bytes > ? THEN -1 ELSE cycle_tx_bytes + ? END,
    total_rx_bytes = CASE WHEN total_rx_bytes > ? THEN -1 ELSE total_rx_bytes + ? END,
    total_tx_bytes = CASE WHEN total_tx_bytes > ? THEN -1 ELSE total_tx_bytes + ? END,
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
WHERE id = ?
RETURNING `+nodeColumns,
				math.MaxInt64-nicRxDelta, nicRxDelta,
				math.MaxInt64-nicTxDelta, nicTxDelta,
				math.MaxInt64-nicRxDelta, nicRxDelta,
				math.MaxInt64-nicTxDelta, nicTxDelta,
				telemetry.PublicIP, telemetry.PublicIP,
				telemetry.PublicIPv6, telemetry.PublicIPv6,
				telemetry.CPUPercent, telemetry.MemUsedBytes, telemetry.MemTotalBytes,
				telemetry.DiskUsedPercent, telemetry.UptimeSeconds, telemetry.RxBPS, telemetry.TxBPS,
				boolToInt(telemetry.CoreAHealthy), boolToInt(telemetry.CoreBHealthy),
				FormatSQLiteTime(lastSeen), now, nodeID,
			))
		} else {
			updatedNode, nodeErr = scanNode(tx.QueryRowContext(ctx, `
UPDATE nodes SET
    cycle_rx_bytes = CASE WHEN cycle_rx_bytes > ? THEN -1 ELSE cycle_rx_bytes + ? END,
    cycle_tx_bytes = CASE WHEN cycle_tx_bytes > ? THEN -1 ELSE cycle_tx_bytes + ? END,
    total_rx_bytes = CASE WHEN total_rx_bytes > ? THEN -1 ELSE total_rx_bytes + ? END,
    total_tx_bytes = CASE WHEN total_tx_bytes > ? THEN -1 ELSE total_tx_bytes + ? END,
    updated_at = ?
WHERE id = ?
RETURNING `+nodeColumns,
				math.MaxInt64-nicRxDelta, nicRxDelta,
				math.MaxInt64-nicTxDelta, nicTxDelta,
				math.MaxInt64-nicRxDelta, nicRxDelta,
				math.MaxInt64-nicTxDelta, nicTxDelta,
				now, nodeID,
			))
		}
		if nodeErr != nil {
			if errors.Is(nodeErr, sql.ErrNoRows) {
				return ErrNotFound
			}
			return nodeErr
		}
		res.Node = updatedNode

		// 2. Node daily traffic upsert with CHECK(>=0) overflow guard.
		if nicRxDelta > 0 || nicTxDelta > 0 {
			if err := upsertAddDailyTrafficTx(ctx, tx, "node", nodeID, logDate, nicRxDelta, nicTxDelta); err != nil {
				return err
			}
		}

		// 3. Optional admin Snell traffic inside the same transaction.
		if adminSnellBytes > 0 {
			adminAt := FormatSQLiteTime(at.UTC())
			if at.IsZero() {
				adminAt = now
			}
			if _, err := tx.ExecContext(ctx, `
INSERT INTO admin_node_traffic(node_id, bytes, updated_at)
VALUES (?, ?, ?)
ON CONFLICT(node_id) DO UPDATE SET
    bytes = CASE WHEN admin_node_traffic.bytes > `+maxInt64SQL+` - excluded.bytes THEN -1 ELSE admin_node_traffic.bytes + excluded.bytes END,
    updated_at = excluded.updated_at`,
				nodeID, adminSnellBytes, adminAt,
			); err != nil {
				return mapSQLiteErr(err)
			}
			if err := upsertAddTrafficUsageLogTx(ctx, tx, nodeID, 0, logMinute, adminSnellBytes, 0, adminAt); err != nil {
				return err
			}
		}

		// 4. Batched user updates + daily/node/minute upserts (chunked at trafficDeltaBatchSize).
		for start := 0; start < len(idOrder); start += trafficDeltaBatchSize {
			end := start + trafficDeltaBatchSize
			if end > len(idOrder) {
				end = len(idOrder)
			}
			chunkIDs := idOrder[start:end]

			var valuesBuf strings.Builder
			updateArgs := make([]any, 0, len(chunkIDs)*5+1)
			for i, uid := range chunkIDs {
				if i > 0 {
					valuesBuf.WriteByte(',')
				}
				valuesBuf.WriteString("(?, ?, ?, ?, ?)")
				acc := byID[uid]
				updateArgs = append(updateArgs, uid, acc.upBytes, acc.downBytes, math.MaxInt64-acc.upBytes, math.MaxInt64-acc.downBytes)
			}
			updateArgs = append(updateArgs, now)

			uQuery := `
WITH d(id, up_delta, down_delta, max_up, max_down) AS (VALUES ` + valuesBuf.String() + `)
UPDATE users SET
    used_up_bytes = CASE WHEN users.used_up_bytes > d.max_up THEN -1 ELSE users.used_up_bytes + d.up_delta END,
    used_down_bytes = CASE WHEN users.used_down_bytes > d.max_down THEN -1 ELSE users.used_down_bytes + d.down_delta END,
    updated_at = ?
FROM d
WHERE users.id = d.id
RETURNING users.id`

			rows, err := tx.QueryContext(ctx, uQuery, updateArgs...)
			if err != nil {
				return mapSQLiteErr(err)
			}
			updatedSet := make(map[int64]struct{}, len(chunkIDs))
			for rows.Next() {
				var uid int64
				if err := rows.Scan(&uid); err != nil {
					_ = rows.Close()
					return mapSQLiteErr(err)
				}
				updatedSet[uid] = struct{}{}
			}
			if err := rows.Err(); err != nil {
				_ = rows.Close()
				return mapSQLiteErr(err)
			}
			_ = rows.Close()

			validItems := make([]*coalescedUserDelta, 0, len(updatedSet))
			for _, uid := range chunkIDs {
				if _, ok := updatedSet[uid]; ok {
					res.UpdatedUserIDs = append(res.UpdatedUserIDs, uid)
					validItems = append(validItems, byID[uid])
				} else {
					res.SkippedUserIDs = append(res.SkippedUserIDs, uid)
				}
			}
			if len(validItems) == 0 {
				continue
			}

			// Batch traffic_logs_daily ("user").
			var dailyVals strings.Builder
			dailyArgs := make([]any, 0, len(validItems)*4)
			var untVals strings.Builder
			untArgs := make([]any, 0, len(validItems)*5)
			var logVals strings.Builder
			logArgs := make([]any, 0, len(validItems)*6)

			for i, item := range validItems {
				if i > 0 {
					dailyVals.WriteByte(',')
					untVals.WriteByte(',')
					logVals.WriteByte(',')
				}
				dailyVals.WriteString("('user', ?, ?, ?, ?)")
				dailyArgs = append(dailyArgs, item.userID, logDate, item.downBytes, item.upBytes)

				untVals.WriteString("(?, ?, ?, ?, ?)")
				untArgs = append(untArgs, item.userID, nodeID, item.upBytes, item.downBytes, now)

				logVals.WriteString("(?, ?, ?, ?, ?, ?)")
				logArgs = append(logArgs, nodeID, item.userID, logMinute, item.downBytes, item.upBytes, now)
			}

			if _, err := tx.ExecContext(ctx, `
INSERT INTO traffic_logs_daily(target_type, target_id, log_date, rx_bytes, tx_bytes)
VALUES `+dailyVals.String()+`
ON CONFLICT(target_type, target_id, log_date) DO UPDATE SET
    rx_bytes = CASE WHEN traffic_logs_daily.rx_bytes > `+maxInt64SQL+` - excluded.rx_bytes THEN -1 ELSE traffic_logs_daily.rx_bytes + excluded.rx_bytes END,
    tx_bytes = CASE WHEN traffic_logs_daily.tx_bytes > `+maxInt64SQL+` - excluded.tx_bytes THEN -1 ELSE traffic_logs_daily.tx_bytes + excluded.tx_bytes END`,
				dailyArgs...,
			); err != nil {
				return mapSQLiteErr(err)
			}

			if _, err := tx.ExecContext(ctx, `
INSERT INTO user_node_traffic(user_id, node_id, up_bytes, down_bytes, updated_at)
VALUES `+untVals.String()+`
ON CONFLICT(user_id, node_id) DO UPDATE SET
    up_bytes = CASE WHEN user_node_traffic.up_bytes > `+maxInt64SQL+` - excluded.up_bytes THEN -1 ELSE user_node_traffic.up_bytes + excluded.up_bytes END,
    down_bytes = CASE WHEN user_node_traffic.down_bytes > `+maxInt64SQL+` - excluded.down_bytes THEN -1 ELSE user_node_traffic.down_bytes + excluded.down_bytes END,
    updated_at = excluded.updated_at`,
				untArgs...,
			); err != nil {
				return mapSQLiteErr(err)
			}

			if _, err := tx.ExecContext(ctx, `
INSERT INTO traffic_usage_logs(node_id, user_id, log_minute, rx_bytes, tx_bytes, updated_at)
VALUES `+logVals.String()+`
ON CONFLICT(node_id, user_id, log_minute) DO UPDATE SET
    rx_bytes = CASE WHEN traffic_usage_logs.rx_bytes > `+maxInt64SQL+` - excluded.rx_bytes THEN -1 ELSE traffic_usage_logs.rx_bytes + excluded.rx_bytes END,
    tx_bytes = CASE WHEN traffic_usage_logs.tx_bytes > `+maxInt64SQL+` - excluded.tx_bytes THEN -1 ELSE traffic_usage_logs.tx_bytes + excluded.tx_bytes END,
    updated_at = excluded.updated_at`,
				logArgs...,
			); err != nil {
				return mapSQLiteErr(err)
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func upsertAddDailyTrafficTx(ctx context.Context, tx *sql.Tx, targetType string, targetID int64, logDate string, rxDelta, txDelta int64) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO traffic_logs_daily(target_type, target_id, log_date, rx_bytes, tx_bytes)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(target_type, target_id, log_date) DO UPDATE SET
    rx_bytes = CASE WHEN traffic_logs_daily.rx_bytes > `+maxInt64SQL+` - excluded.rx_bytes THEN -1 ELSE traffic_logs_daily.rx_bytes + excluded.rx_bytes END,
    tx_bytes = CASE WHEN traffic_logs_daily.tx_bytes > `+maxInt64SQL+` - excluded.tx_bytes THEN -1 ELSE traffic_logs_daily.tx_bytes + excluded.tx_bytes END`,
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
	_, err := tx.ExecContext(ctx, `
INSERT INTO traffic_usage_logs(node_id, user_id, log_minute, rx_bytes, tx_bytes, updated_at)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(node_id, user_id, log_minute) DO UPDATE SET
    rx_bytes = CASE WHEN traffic_usage_logs.rx_bytes > `+maxInt64SQL+` - excluded.rx_bytes THEN -1 ELSE traffic_usage_logs.rx_bytes + excluded.rx_bytes END,
    tx_bytes = CASE WHEN traffic_usage_logs.tx_bytes > `+maxInt64SQL+` - excluded.tx_bytes THEN -1 ELSE traffic_usage_logs.tx_bytes + excluded.tx_bytes END,
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

// PruneConfiguredTrafficUsageLogs reads traffic_log_max_entries (defaulting to DefaultTrafficLogMaxEntries)
// and deletes older rows exceeding that limit in a single transaction.
func (s *Store) PruneConfiguredTrafficUsageLogs(ctx context.Context) (int64, error) {
	var pruned int64
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		maxEntries := DefaultTrafficLogMaxEntries
		var rawMax string
		if err := tx.QueryRowContext(ctx, `SELECT value FROM system_settings WHERE key = 'traffic_log_max_entries'`).Scan(&rawMax); err == nil {
			if parsed, convErr := strconv.Atoi(strings.TrimSpace(rawMax)); convErr == nil && parsed > 0 {
				maxEntries = parsed
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return mapSQLiteErr(err)
		}
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

type mergeGroupKey struct {
	nodeID int64
	userID int64
}

type activeMergeSession struct {
	row       TrafficUsageLog
	startTime time.Time
	hasTime   bool
}

type trafficLogMinHeap []TrafficUsageLog

func trafficLogBetter(a, b TrafficUsageLog) bool {
	if a.EndTime != b.EndTime {
		return a.EndTime > b.EndTime
	}
	if a.StartTime != b.StartTime {
		return a.StartTime > b.StartTime
	}
	return a.ID > b.ID
}

func (h trafficLogMinHeap) Len() int           { return len(h) }
func (h trafficLogMinHeap) Less(i, j int) bool { return trafficLogBetter(h[j], h[i]) }
func (h trafficLogMinHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *trafficLogMinHeap) Push(x any)        { *h = append(*h, x.(TrafficUsageLog)) }
func (h *trafficLogMinHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

func pushTopMergedSession(top *trafficLogMinHeap, outLimit int, item TrafficUsageLog) {
	if outLimit <= 0 {
		return
	}
	if top.Len() < outLimit {
		heap.Push(top, item)
		return
	}
	if trafficLogBetter(item, (*top)[0]) {
		(*top)[0] = item
		heap.Fix(top, 0)
	}
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

	clauses = append(clauses, "(l.user_id = 0 OR u.id IS NOT NULL)")

	query := `
SELECT l.id, l.node_id, n.name, n.region_tag, l.user_id, COALESCE(u.username, ''), l.log_minute, l.rx_bytes, l.tx_bytes, l.updated_at
FROM traffic_usage_logs l
JOIN nodes n ON n.id = l.node_id
LEFT JOIN users u ON u.id = l.user_id`
	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY l.log_minute DESC, l.id DESC"
	if !filter.Merge {
		query += " LIMIT ?"
		args = append(args, outLimit)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	defer rows.Close()

	if !filter.Merge {
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
		return out, nil
	}

	gapMinutes := filter.MergeGapMinutes
	if gapMinutes <= 0 {
		gapMinutes = DefaultTrafficLogMergeGapMinutes
	}
	if gapMinutes > MaxTrafficLogMergeGapMinutes {
		gapMinutes = MaxTrafficLogMergeGapMinutes
	}
	maxGap := time.Duration(gapMinutes) * time.Minute

	active := make(map[mergeGroupKey]*activeMergeSession)
	top := make(trafficLogMinHeap, 0, min(outLimit, 64))
	var lastSweepMinute string

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

		rTime, rHasTime := parseTrafficLogTime(row.LogMinute)
		gk := mergeGroupKey{nodeID: row.NodeID, userID: row.UserID}
		if act, ok := active[gk]; ok {
			shouldMerge := false
			if act.hasTime && rHasTime {
				diff := act.startTime.Sub(rTime)
				shouldMerge = diff >= 0 && diff <= maxGap
			} else if row.LogMinute == act.row.StartTime {
				shouldMerge = true
			}
			if shouldMerge {
				act.row.RxBytes += row.RxBytes
				act.row.TxBytes += row.TxBytes
				act.row.StartTime = row.LogMinute
				act.startTime = rTime
				act.hasTime = rHasTime
			} else {
				pushTopMergedSession(&top, outLimit, act.row)
				row.StartTime = row.LogMinute
				row.EndTime = row.LogMinute
				active[gk] = &activeMergeSession{
					row:       row,
					startTime: rTime,
					hasTime:   rHasTime,
				}
			}
		} else {
			row.StartTime = row.LogMinute
			row.EndTime = row.LogMinute
			active[gk] = &activeMergeSession{
				row:       row,
				startTime: rTime,
				hasTime:   rHasTime,
			}
		}

		if rHasTime && row.LogMinute != lastSweepMinute {
			lastSweepMinute = row.LogMinute
			for k, act := range active {
				if act.hasTime && act.startTime.Sub(rTime) > maxGap && act.row.StartTime > row.LogMinute {
					pushTopMergedSession(&top, outLimit, act.row)
					delete(active, k)
				}
			}
			if top.Len() >= outLimit {
				kth := top[0]
				if kth.EndTime > row.LogMinute {
					anyActiveCanBeat := false
					for _, act := range active {
						if act.row.EndTime >= kth.EndTime {
							anyActiveCanBeat = true
							break
						}
					}
					if !anyActiveCanBeat {
						break
					}
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, mapSQLiteErr(err)
	}

	for _, act := range active {
		pushTopMergedSession(&top, outLimit, act.row)
	}

	merged := []TrafficUsageLog(top)
	sort.Slice(merged, func(i, j int) bool {
		return trafficLogBetter(merged[i], merged[j])
	})
	return merged, nil
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

		if _, err := tx.ExecContext(ctx, `
INSERT INTO admin_node_traffic(node_id, bytes, updated_at)
VALUES (?, ?, ?)
ON CONFLICT(node_id) DO UPDATE SET
    bytes = CASE WHEN admin_node_traffic.bytes > `+maxInt64SQL+` - excluded.bytes THEN -1 ELSE admin_node_traffic.bytes + excluded.bytes END,
    updated_at = excluded.updated_at`,
			nodeID, deltaBytes, now,
		); err != nil {
			return mapSQLiteErr(err)
		}

		return upsertAddTrafficUsageLogTx(ctx, tx, nodeID, 0, logMinute, deltaBytes, 0, now)
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
