package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func scanSubTemplate(row rowScanner) (*SubTemplate, error) {
	var (
		t            SubTemplate
		isDefaultInt int
		createdAtStr string
		updatedAtStr string
	)
	err := row.Scan(&t.ID, &t.Name, &t.ClientType, &t.Content, &isDefaultInt, &createdAtStr, &updatedAtStr)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	t.IsDefault = isDefaultInt == 1

	var errTime error
	if t.CreatedAt, errTime = ParseSQLiteTime(createdAtStr); errTime != nil {
		return nil, errTime
	}
	if t.UpdatedAt, errTime = ParseSQLiteTime(updatedAtStr); errTime != nil {
		return nil, errTime
	}
	return &t, nil
}

// CreateSubTemplate inserts a subscription template.
// If tpl.IsDefault is true, any previous default for that client_type is cleared atomically.
func (s *Store) CreateSubTemplate(ctx context.Context, tpl *SubTemplate) error {
	if tpl == nil || tpl.Name == "" || tpl.ClientType == "" {
		return fmt.Errorf("%w: template name and client_type are required", ErrInvalidArgument)
	}
	now := time.Now().UTC()
	tpl.CreatedAt = now
	tpl.UpdatedAt = now
	nowStr := FormatSQLiteTime(now)

	return s.withTx(ctx, func(tx *sql.Tx) error {
		if tpl.IsDefault {
			if _, err := tx.ExecContext(ctx, `
UPDATE sub_templates SET is_default = 0, updated_at = ?
WHERE client_type = ? AND is_default = 1`,
				nowStr, tpl.ClientType,
			); err != nil {
				return mapSQLiteErr(err)
			}
		}
		res, err := tx.ExecContext(ctx, `
INSERT INTO sub_templates(name, client_type, content, is_default, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?)`,
			tpl.Name, tpl.ClientType, tpl.Content, boolToInt(tpl.IsDefault), nowStr, nowStr,
		)
		if err != nil {
			return mapSQLiteErr(err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return err
		}
		tpl.ID = id
		return nil
	})
}

// GetSubTemplateByID fetches a subscription template by ID.
func (s *Store) GetSubTemplateByID(ctx context.Context, id int64) (*SubTemplate, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, client_type, content, is_default, created_at, updated_at FROM sub_templates WHERE id = ?`,
		id,
	)
	return scanSubTemplate(row)
}

// GetDefaultSubTemplate fetches the default subscription template for clientType.
func (s *Store) GetDefaultSubTemplate(ctx context.Context, clientType string) (*SubTemplate, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, client_type, content, is_default, created_at, updated_at FROM sub_templates WHERE client_type = ? AND is_default = 1`,
		clientType,
	)
	return scanSubTemplate(row)
}

// ListSubTemplates lists templates, optionally filtered by clientType (all if empty).
func (s *Store) ListSubTemplates(ctx context.Context, clientType string) ([]SubTemplate, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if clientType == "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, name, client_type, content, is_default, created_at, updated_at FROM sub_templates ORDER BY client_type ASC, is_default DESC, id ASC`,
		)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, name, client_type, content, is_default, created_at, updated_at FROM sub_templates WHERE client_type = ? ORDER BY is_default DESC, id ASC`,
			clientType,
		)
	}
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	defer rows.Close()

	var out []SubTemplate
	for rows.Next() {
		t, err := scanSubTemplate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	if err := rows.Err(); err != nil {
		return nil, mapSQLiteErr(err)
	}
	return out, nil
}

// UpdateSubTemplate updates a template and enforces the single-default-per-client_type invariant.
func (s *Store) UpdateSubTemplate(ctx context.Context, tpl *SubTemplate) error {
	if tpl == nil || tpl.ID <= 0 || tpl.Name == "" || tpl.ClientType == "" {
		return fmt.Errorf("%w: invalid subscription template", ErrInvalidArgument)
	}
	now := time.Now().UTC()
	tpl.UpdatedAt = now
	nowStr := FormatSQLiteTime(now)

	return s.withTx(ctx, func(tx *sql.Tx) error {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM sub_templates WHERE id = ?`, tpl.ID).Scan(&exists); err != nil {
			return mapSQLiteErr(err)
		}

		if tpl.IsDefault {
			if _, err := tx.ExecContext(ctx, `
UPDATE sub_templates SET is_default = 0, updated_at = ?
WHERE client_type = ? AND is_default = 1 AND id != ?`,
				nowStr, tpl.ClientType, tpl.ID,
			); err != nil {
				return mapSQLiteErr(err)
			}
		}

		res, err := tx.ExecContext(ctx, `
UPDATE sub_templates SET name = ?, client_type = ?, content = ?, is_default = ?, updated_at = ? WHERE id = ?`,
			tpl.Name, tpl.ClientType, tpl.Content, boolToInt(tpl.IsDefault), nowStr, tpl.ID,
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
	})
}

// DeleteSubTemplate removes a subscription template by ID.
func (s *Store) DeleteSubTemplate(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sub_templates WHERE id = ?`, id)
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
