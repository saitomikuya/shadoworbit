package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// GetSetting retrieves the value for key from system_settings.
// Returns ErrNotFound if key does not exist.
func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("%w: setting key cannot be empty", ErrInvalidArgument)
	}
	var val string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM system_settings WHERE key = ?`, key).Scan(&val)
	if err != nil {
		return "", mapSQLiteErr(err)
	}
	return val, nil
}

// GetSettingOrDefault retrieves the value for key, returning def if absent.
func (s *Store) GetSettingOrDefault(ctx context.Context, key, def string) (string, error) {
	val, err := s.GetSetting(ctx, key)
	if errors.Is(err, ErrNotFound) {
		return def, nil
	}
	if err != nil {
		return "", err
	}
	return val, nil
}

// SetSetting inserts or updates key in system_settings.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	if key == "" {
		return fmt.Errorf("%w: setting key cannot be empty", ErrInvalidArgument)
	}
	now := FormatSQLiteTime(time.Now().UTC())
	_, err := s.db.ExecContext(ctx, `
INSERT INTO system_settings(key, value, updated_at) VALUES (?, ?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, now,
	)
	return mapSQLiteErr(err)
}

// SetSettingIfAbsent atomically inserts (key, value) only if key is not present (or empty).
// Returns the persisted value and whether this call created/initialized it.
// Satisfies auth.SettingsStore directly.
func (s *Store) SetSettingIfAbsent(ctx context.Context, key, value string) (actual string, created bool, err error) {
	if key == "" {
		return "", false, fmt.Errorf("%w: setting key cannot be empty", ErrInvalidArgument)
	}
	now := FormatSQLiteTime(time.Now().UTC())
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		var existing string
		scanErr := tx.QueryRowContext(ctx, `SELECT value FROM system_settings WHERE key = ?`, key).Scan(&existing)
		switch {
		case errors.Is(scanErr, sql.ErrNoRows):
			if _, execErr := tx.ExecContext(ctx,
				`INSERT INTO system_settings(key, value, updated_at) VALUES (?, ?, ?)`,
				key, value, now,
			); execErr != nil {
				return mapSQLiteErr(execErr)
			}
			actual = value
			created = true
			return nil
		case scanErr != nil:
			return mapSQLiteErr(scanErr)
		case existing == "":
			if _, execErr := tx.ExecContext(ctx,
				`UPDATE system_settings SET value = ?, updated_at = ? WHERE key = ?`,
				value, now, key,
			); execErr != nil {
				return mapSQLiteErr(execErr)
			}
			actual = value
			created = true
			return nil
		default:
			actual = existing
			created = false
			return nil
		}
	})
	if err != nil {
		return "", false, err
	}
	return actual, created, nil
}

// GetAllSettings returns all key/value pairs in system_settings.
func (s *Store) GetAllSettings(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM system_settings ORDER BY key ASC`)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	defer rows.Close()

	out := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, mapSQLiteErr(err)
		}
		out[k] = v
	}
	if err := rows.Err(); err != nil {
		return nil, mapSQLiteErr(err)
	}
	return out, nil
}

// SetSettingsBatch atomically upserts multiple settings inside a single transaction.
func (s *Store) SetSettingsBatch(ctx context.Context, values map[string]string) error {
	if len(values) == 0 {
		return nil
	}
	now := FormatSQLiteTime(time.Now().UTC())
	return s.withTx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `
INSERT INTO system_settings(key, value, updated_at) VALUES (?, ?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`)
		if err != nil {
			return mapSQLiteErr(err)
		}
		defer stmt.Close()

		for k, v := range values {
			if k == "" {
				return fmt.Errorf("%w: setting key cannot be empty", ErrInvalidArgument)
			}
			if _, err := stmt.ExecContext(ctx, k, v, now); err != nil {
				return mapSQLiteErr(err)
			}
		}
		return nil
	})
}
