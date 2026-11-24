package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"
)

const userColumns = `
id, username, enabled, sub_token, ss_upsk_16, ss_upsk_32, stls_password,
traffic_quota_bytes, billing_reset_day, used_up_bytes, used_down_bytes,
last_reset_at, expire_at, created_at, updated_at`

func scanUser(row rowScanner) (*User, error) {
	var (
		u            User
		enabledInt   int
		lastResetStr sql.NullString
		expireAtStr  sql.NullString
		createdAtStr string
		updatedAtStr string
	)
	err := row.Scan(
		&u.ID, &u.Username, &enabledInt, &u.SubToken, &u.SSUPSK16, &u.SSUPSK32, &u.STLSPassword,
		&u.TrafficQuotaBytes, &u.BillingResetDay, &u.UsedUpBytes, &u.UsedDownBytes,
		&lastResetStr, &expireAtStr, &createdAtStr, &updatedAtStr,
	)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	u.Enabled = enabledInt == 1

	var errTime error
	if u.LastResetAt, errTime = parseNullableTime(lastResetStr); errTime != nil {
		return nil, errTime
	}
	if u.ExpireAt, errTime = parseNullableTime(expireAtStr); errTime != nil {
		return nil, errTime
	}
	if u.CreatedAt, errTime = ParseSQLiteTime(createdAtStr); errTime != nil {
		return nil, errTime
	}
	if u.UpdatedAt, errTime = ParseSQLiteTime(updatedAtStr); errTime != nil {
		return nil, errTime
	}
	return &u, nil
}

// CreateUser inserts a new user and populates ID and timestamps.
func (s *Store) CreateUser(ctx context.Context, user *User) error {
	_, err := s.CreateUserWithNodes(ctx, user, nil)
	return err
}

// CreateUserWithNodes atomically inserts a new user and assigns authorized nodes
// inside a single SQLite transaction. Any failure rolls back the entire operation.
func (s *Store) CreateUserWithNodes(ctx context.Context, user *User, nodeIDs []int64) ([]int64, error) {
	if user == nil {
		return nil, fmt.Errorf("%w: nil user", ErrInvalidArgument)
	}
	if user.Username == "" || user.SubToken == "" || user.SSUPSK16 == "" || user.SSUPSK32 == "" || user.STLSPassword == "" {
		return nil, fmt.Errorf("%w: username, sub_token, ss_upsk_16, ss_upsk_32, and stls_password are required", ErrInvalidArgument)
	}
	if user.TrafficQuotaBytes < 0 {
		return nil, fmt.Errorf("%w: traffic_quota_bytes cannot be negative", ErrInvalidArgument)
	}
	if user.BillingResetDay < 0 || user.BillingResetDay > 31 {
		return nil, fmt.Errorf("%w: billing_reset_day must be between 0 and 31", ErrInvalidArgument)
	}

	now := time.Now().UTC()
	nowStr := FormatSQLiteTime(now)
	lastResetAt := user.LastResetAt
	if lastResetAt == nil {
		t := now
		lastResetAt = &t
	}

	var (
		newID    int64
		assigned []int64
	)
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
INSERT INTO users (
    username, enabled, sub_token, ss_upsk_16, ss_upsk_32, stls_password,
    traffic_quota_bytes, billing_reset_day, used_up_bytes, used_down_bytes,
    last_reset_at, expire_at, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			user.Username, boolToInt(user.Enabled), user.SubToken, user.SSUPSK16, user.SSUPSK32, user.STLSPassword,
			user.TrafficQuotaBytes, user.BillingResetDay, user.UsedUpBytes, user.UsedDownBytes,
			formatNullableTime(lastResetAt), formatNullableTime(user.ExpireAt),
			nowStr, nowStr,
		)
		if err != nil {
			return mapSQLiteErr(err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("store: user LastInsertId: %w", err)
		}
		newID = id

		if err := insertUserNodesTx(ctx, tx, newID, nodeIDs, nowStr); err != nil {
			return err
		}
		if len(nodeIDs) == 0 {
			assigned = []int64{}
			return nil
		}
		assigned, err = getUserNodeIDsTx(ctx, tx, newID)
		return err
	})
	if err != nil {
		return nil, err
	}

	user.ID = newID
	user.LastResetAt = lastResetAt
	user.CreatedAt = now
	user.UpdatedAt = now
	return assigned, nil
}

// GetUserByID fetches a user by primary key.
func (s *Store) GetUserByID(ctx context.Context, id int64) (*User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, id)
	return scanUser(row)
}

// GetUserByUsername fetches a user by unique username.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	if username == "" {
		return nil, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE username = ?`, username)
	return scanUser(row)
}

// GetUserBySubToken fetches a user by unique subscription token.
func (s *Store) GetUserBySubToken(ctx context.Context, subToken string) (*User, error) {
	if subToken == "" {
		return nil, ErrNotFound
	}
	row := s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE sub_token = ?`, subToken)
	return scanUser(row)
}

// ListUsers returns all users ordered by id ASC.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userColumns+` FROM users ORDER BY id ASC`)
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

// UpdateUser updates mutable user settings (username, enabled, quota, reset day, expire_at).
func (s *Store) UpdateUser(ctx context.Context, user *User) error {
	_, _, err := s.UpdateUserWithNodes(ctx, user, nil)
	return err
}

// UpdateUserWithNodes atomically updates mutable user settings and, when nodeIDs is non-nil,
// replaces user_node_access within the same SQLite transaction. Any error rolls back all changes
// with zero DB side effects. When nodeIDs is non-nil, it returns the previous and new node IDs.
func (s *Store) UpdateUserWithNodes(ctx context.Context, user *User, nodeIDs *[]int64) ([]int64, []int64, error) {
	if user == nil || user.ID <= 0 {
		return nil, nil, fmt.Errorf("%w: invalid user", ErrInvalidArgument)
	}
	if user.Username == "" {
		return nil, nil, fmt.Errorf("%w: username cannot be empty", ErrInvalidArgument)
	}
	if user.TrafficQuotaBytes < 0 {
		return nil, nil, fmt.Errorf("%w: traffic_quota_bytes cannot be negative", ErrInvalidArgument)
	}
	if user.BillingResetDay < 0 || user.BillingResetDay > 31 {
		return nil, nil, fmt.Errorf("%w: billing_reset_day must be between 0 and 31", ErrInvalidArgument)
	}

	now := time.Now().UTC()
	nowStr := FormatSQLiteTime(now)

	var oldIDs, newIDs []int64
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
UPDATE users SET
    username = ?,
    enabled = ?,
    traffic_quota_bytes = ?,
    billing_reset_day = ?,
    expire_at = ?,
    updated_at = ?
WHERE id = ?`,
			user.Username, boolToInt(user.Enabled), user.TrafficQuotaBytes, user.BillingResetDay,
			formatNullableTime(user.ExpireAt), nowStr, user.ID,
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

		if nodeIDs != nil {
			oldIDs, newIDs, err = replaceUserNodesTx(ctx, tx, user.ID, *nodeIDs, nowStr)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	user.UpdatedAt = now
	return oldIDs, newIDs, nil
}

// DeleteUser deletes a user, their daily and minute traffic logs, and per-user system_settings atomically.
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM traffic_logs_daily WHERE target_type = 'user' AND target_id = ?`, id); err != nil {
			return mapSQLiteErr(err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM traffic_usage_logs WHERE user_id = ?`, id); err != nil {
			return mapSQLiteErr(err)
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM system_settings WHERE key = ?`,
			fmt.Sprintf("last_user_reset_month:%d", id),
		); err != nil {
			return mapSQLiteErr(err)
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
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

// ResetUserKeys rotates non-empty user credentials (SS2022 uPSK 16/32, ShadowTLS password, sub_token).
func (s *Store) ResetUserKeys(ctx context.Context, id int64, upsk16, upsk32, stlsPassword, subToken string) error {
	now := FormatSQLiteTime(time.Now().UTC())
	res, err := s.db.ExecContext(ctx, `
UPDATE users SET
    ss_upsk_16 = COALESCE(NULLIF(?, ''), ss_upsk_16),
    ss_upsk_32 = COALESCE(NULLIF(?, ''), ss_upsk_32),
    stls_password = COALESCE(NULLIF(?, ''), stls_password),
    sub_token = COALESCE(NULLIF(?, ''), sub_token),
    updated_at = ?
WHERE id = ?`,
		upsk16, upsk32, stlsPassword, subToken, now, id,
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

// AddUserTrafficDelta atomically adds upDelta and downDelta to a user's counters
// and returns the updated User.
func (s *Store) AddUserTrafficDelta(ctx context.Context, userID int64, upDelta, downDelta int64) (*User, error) {
	if upDelta < 0 || downDelta < 0 {
		return nil, fmt.Errorf("%w: user traffic deltas must be non-negative", ErrInvalidArgument)
	}
	var updated *User
	now := FormatSQLiteTime(time.Now().UTC())
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var curUp, curDown int64
		err := tx.QueryRowContext(ctx, `SELECT used_up_bytes, used_down_bytes FROM users WHERE id = ?`, userID).Scan(&curUp, &curDown)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return mapSQLiteErr(err)
		}
		if curUp > math.MaxInt64-upDelta || curDown > math.MaxInt64-downDelta {
			return fmt.Errorf("%w: user traffic counter overflow", ErrInvalidArgument)
		}

		if _, err := tx.ExecContext(ctx, `
UPDATE users SET
    used_up_bytes = used_up_bytes + ?,
    used_down_bytes = used_down_bytes + ?,
    updated_at = ?
WHERE id = ?`,
			upDelta, downDelta, now, userID,
		); err != nil {
			return mapSQLiteErr(err)
		}
		updated, err = scanUser(tx.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, userID))
		return err
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// ResetUserTraffic zeroes used_up_bytes and used_down_bytes and records last_reset_at.
func (s *Store) ResetUserTraffic(ctx context.Context, id int64, resetAt time.Time) error {
	if resetAt.IsZero() {
		resetAt = time.Now().UTC()
	}
	now := FormatSQLiteTime(time.Now().UTC())
	return s.withTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
UPDATE users SET
    used_up_bytes = 0,
    used_down_bytes = 0,
    last_reset_at = ?,
    updated_at = ?
WHERE id = ?`,
			FormatSQLiteTime(resetAt), now, id,
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
		if _, err := tx.ExecContext(ctx, `DELETE FROM user_node_traffic WHERE user_id = ?`, id); err != nil {
			return mapSQLiteErr(err)
		}
		return nil
	})
}
