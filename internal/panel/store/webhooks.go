package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

func scanWebhookChannel(row rowScanner) (*WebhookChannel, error) {
	var (
		w            WebhookChannel
		eventsJSON   string
		enabledInt   int
		createdAtStr string
		updatedAtStr string
	)
	err := row.Scan(&w.ID, &w.Name, &w.Provider, &w.URL, &w.Secret, &eventsJSON, &enabledInt, &createdAtStr, &updatedAtStr)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	w.Enabled = enabledInt == 1
	if eventsJSON != "" {
		if err := json.Unmarshal([]byte(eventsJSON), &w.SubscribedEvents); err != nil {
			return nil, fmt.Errorf("store: decode subscribed_events for webhook %d: %w", w.ID, err)
		}
	}
	if w.SubscribedEvents == nil {
		w.SubscribedEvents = []string{}
	}

	var errTime error
	if w.CreatedAt, errTime = ParseSQLiteTime(createdAtStr); errTime != nil {
		return nil, errTime
	}
	if w.UpdatedAt, errTime = ParseSQLiteTime(updatedAtStr); errTime != nil {
		return nil, errTime
	}
	return &w, nil
}

// CreateWebhookChannel inserts a new webhook alert channel.
func (s *Store) CreateWebhookChannel(ctx context.Context, ch *WebhookChannel) error {
	if ch == nil || ch.Name == "" || ch.Provider == "" || ch.URL == "" {
		return fmt.Errorf("%w: webhook name, provider, and url are required", ErrInvalidArgument)
	}
	if ch.SubscribedEvents == nil {
		ch.SubscribedEvents = []string{}
	}
	eventsBytes, err := json.Marshal(ch.SubscribedEvents)
	if err != nil {
		return fmt.Errorf("store: marshal subscribed_events: %w", err)
	}
	now := time.Now().UTC()
	ch.CreatedAt = now
	ch.UpdatedAt = now
	nowStr := FormatSQLiteTime(now)

	res, err := s.db.ExecContext(ctx, `
INSERT INTO webhook_channels(name, provider, url, secret, subscribed_events, enabled, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		ch.Name, ch.Provider, ch.URL, ch.Secret, string(eventsBytes), boolToInt(ch.Enabled), nowStr, nowStr,
	)
	if err != nil {
		return mapSQLiteErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	ch.ID = id
	return nil
}

// GetWebhookChannelByID fetches a webhook channel by ID.
func (s *Store) GetWebhookChannelByID(ctx context.Context, id int64) (*WebhookChannel, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, provider, url, secret, subscribed_events, enabled, created_at, updated_at FROM webhook_channels WHERE id = ?`,
		id,
	)
	return scanWebhookChannel(row)
}

// ListWebhookChannels lists all webhook channels ordered by id ASC.
func (s *Store) ListWebhookChannels(ctx context.Context) ([]WebhookChannel, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, provider, url, secret, subscribed_events, enabled, created_at, updated_at FROM webhook_channels ORDER BY id ASC`,
	)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	defer rows.Close()

	var out []WebhookChannel
	for rows.Next() {
		w, err := scanWebhookChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *w)
	}
	if err := rows.Err(); err != nil {
		return nil, mapSQLiteErr(err)
	}
	return out, nil
}

// ListEnabledWebhooksByEvent returns enabled webhook channels subscribed to eventType or "*".
func (s *Store) ListEnabledWebhooksByEvent(ctx context.Context, eventType string) ([]WebhookChannel, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, provider, url, secret, subscribed_events, enabled, created_at, updated_at FROM webhook_channels WHERE enabled = 1 ORDER BY id ASC`,
	)
	if err != nil {
		return nil, mapSQLiteErr(err)
	}
	defer rows.Close()

	var out []WebhookChannel
	for rows.Next() {
		w, err := scanWebhookChannel(rows)
		if err != nil {
			return nil, err
		}
		for _, ev := range w.SubscribedEvents {
			if ev == "*" || ev == eventType {
				out = append(out, *w)
				break
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, mapSQLiteErr(err)
	}
	return out, nil
}

// UpdateWebhookChannel updates a webhook channel.
func (s *Store) UpdateWebhookChannel(ctx context.Context, ch *WebhookChannel) error {
	if ch == nil || ch.ID <= 0 || ch.Name == "" || ch.Provider == "" || ch.URL == "" {
		return fmt.Errorf("%w: invalid webhook channel", ErrInvalidArgument)
	}
	if ch.SubscribedEvents == nil {
		ch.SubscribedEvents = []string{}
	}
	eventsBytes, err := json.Marshal(ch.SubscribedEvents)
	if err != nil {
		return fmt.Errorf("store: marshal subscribed_events: %w", err)
	}
	now := time.Now().UTC()
	ch.UpdatedAt = now

	res, err := s.db.ExecContext(ctx, `
UPDATE webhook_channels SET
    name = ?,
    provider = ?,
    url = ?,
    secret = ?,
    subscribed_events = ?,
    enabled = ?,
    updated_at = ?
WHERE id = ?`,
		ch.Name, ch.Provider, ch.URL, ch.Secret, string(eventsBytes), boolToInt(ch.Enabled), FormatSQLiteTime(now), ch.ID,
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

// DeleteWebhookChannel deletes a webhook channel by ID.
func (s *Store) DeleteWebhookChannel(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM webhook_channels WHERE id = ?`, id)
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
