package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

func scanDNSRuleGroup(row rowScanner) (*DNSRuleGroup, error) {
	var (
		g            DNSRuleGroup
		rulesJSON    string
		createdAtStr string
		updatedAtStr string
	)
	err := row.Scan(&g.ID, &g.Name, &g.Description, &rulesJSON, &createdAtStr, &updatedAtStr)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	if rulesJSON != "" {
		if err := json.Unmarshal([]byte(rulesJSON), &g.Rules); err != nil {
			return nil, fmt.Errorf("store: decode dns_rule_groups.rules for id %d: %w", g.ID, err)
		}
	}
	if g.Rules == nil {
		g.Rules = []string{}
	}
	var errTime error
	if g.CreatedAt, errTime = ParseSQLiteTime(createdAtStr); errTime != nil {
		return nil, errTime
	}
	if g.UpdatedAt, errTime = ParseSQLiteTime(updatedAtStr); errTime != nil {
		return nil, errTime
	}
	return &g, nil
}

// CreateDNSRuleGroup inserts a new DNS unlock rule group.
func (s *Store) CreateDNSRuleGroup(ctx context.Context, group *DNSRuleGroup) error {
	if group == nil || group.Name == "" {
		return fmt.Errorf("%w: dns rule group name is required", ErrInvalidArgument)
	}
	if group.Rules == nil {
		group.Rules = []string{}
	}
	rulesBytes, err := json.Marshal(group.Rules)
	if err != nil {
		return fmt.Errorf("store: marshal dns rules: %w", err)
	}
	now := time.Now().UTC()
	group.CreatedAt = now
	group.UpdatedAt = now

	res, err := s.db.ExecContext(ctx, `
INSERT INTO dns_rule_groups(name, description, rules, created_at, updated_at)
VALUES (?, ?, ?, ?, ?)`,
		group.Name, group.Description, string(rulesBytes), FormatSQLiteTime(now), FormatSQLiteTime(now),
	)
	if err != nil {
		return mapSQLiteErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	group.ID = id
	return nil
}

// GetDNSRuleGroupByID fetches a DNS rule group by ID.
func (s *Store) GetDNSRuleGroupByID(ctx context.Context, id int64) (*DNSRuleGroup, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, description, rules, created_at, updated_at FROM dns_rule_groups WHERE id = ?`,
		id,
	)
	return scanDNSRuleGroup(row)
}

// ListDNSRuleGroups lists all DNS rule groups ordered by id ASC.
func (s *Store) ListDNSRuleGroups(ctx context.Context) ([]DNSRuleGroup, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, description, rules, created_at, updated_at FROM dns_rule_groups ORDER BY id ASC`,
	)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	defer rows.Close()

	var out []DNSRuleGroup
	for rows.Next() {
		g, err := scanDNSRuleGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	if err := rows.Err(); err != nil {
		return nil, mapSQLiteErr(err)
	}
	return out, nil
}

// UpdateDNSRuleGroup updates a DNS rule group's name, description, and rules.
func (s *Store) UpdateDNSRuleGroup(ctx context.Context, group *DNSRuleGroup) error {
	if group == nil || group.ID <= 0 || group.Name == "" {
		return fmt.Errorf("%w: invalid dns rule group", ErrInvalidArgument)
	}
	if group.Rules == nil {
		group.Rules = []string{}
	}
	rulesBytes, err := json.Marshal(group.Rules)
	if err != nil {
		return fmt.Errorf("store: marshal dns rules: %w", err)
	}
	now := time.Now().UTC()
	group.UpdatedAt = now

	res, err := s.db.ExecContext(ctx, `
UPDATE dns_rule_groups SET name = ?, description = ?, rules = ?, updated_at = ? WHERE id = ?`,
		group.Name, group.Description, string(rulesBytes), FormatSQLiteTime(now), group.ID,
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

// DeleteDNSRuleGroup deletes a DNS rule group. Linked nodes have dns_rule_group_id set to NULL.
func (s *Store) DeleteDNSRuleGroup(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM dns_rule_groups WHERE id = ?`, id)
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
