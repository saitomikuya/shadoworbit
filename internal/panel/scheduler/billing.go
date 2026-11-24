package scheduler

import (
	"context"
	"errors"
	"fmt"
	"time"

	"snell-panel/internal/panel/hub"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/panel/webhook"
)

func daysInMonth(year int, month time.Month) int {
	return time.Date(year, month+1, 0, 12, 0, 0, 0, time.UTC).Day()
}

func isOnOrAfterLocalResetDay(t time.Time, year int, month time.Month, effectiveDay int) bool {
	ly, lm, ld := t.Date()
	return ly > year || (ly == year && (lm > month || (lm == month && ld >= effectiveDay)))
}

// RunBillingResets evaluates and executes due monthly billing resets for nodes and users
// at 00:00 in now's time.Location, clamping days 29/30/31 to the month's actual length
// and persisting last_node_reset_month:<id> / last_user_reset_month:<id> for restart idempotency.
func (s *Scheduler) RunBillingResets(ctx context.Context, now time.Time) error {
	if s.store == nil {
		return errors.New("scheduler: nil store")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if now.IsZero() {
		now = s.now()
	}
	loc := now.Location()
	if loc == nil {
		loc = time.UTC
	}
	nowLocal := now.In(loc)
	nowUTC := now.UTC()
	nowYear, nowMonth, nowDay := nowLocal.Date()
	dim := daysInMonth(nowYear, nowMonth)
	currentMonth := nowLocal.Format("2006-01")

	if err := s.runNodeBillingResets(ctx, nowUTC, nowYear, nowMonth, nowDay, dim, currentMonth, loc); err != nil {
		return err
	}
	return s.runUserBillingResets(ctx, nowUTC, nowYear, nowMonth, nowDay, dim, currentMonth, loc)
}

func (s *Scheduler) runNodeBillingResets(
	ctx context.Context,
	nowUTC time.Time,
	nowYear int,
	nowMonth time.Month,
	nowDay int,
	dim int,
	currentMonth string,
	loc *time.Location,
) error {
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return err
	}

	for _, n := range nodes {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		mu := s.nodeLock(n.ID)
		mu.Lock()

		node, err := s.store.GetNodeByID(ctx, n.ID)
		if err != nil {
			mu.Unlock()
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			return err
		}

		day := node.BillingResetDay
		if day < 1 {
			day = 1
		} else if day > 31 {
			day = 31
		}
		effectiveDay := min(day, dim)
		if nowDay < effectiveDay {
			mu.Unlock()
			continue
		}

		key := fmt.Sprintf("%s%d", nodeResetMonthPrefix, node.ID)
		lastMonth, err := s.store.GetSettingOrDefault(ctx, key, "")
		if err != nil {
			mu.Unlock()
			return err
		}
		if lastMonth == currentMonth {
			mu.Unlock()
			continue
		}

		// Creation/calibration guard: if never reset via scheduler yet and LastResetAt is
		// already at or after this month's reset boundary, mark currentMonth without wiping.
		if lastMonth == "" && node.LastResetAt != nil && isOnOrAfterLocalResetDay(node.LastResetAt.In(loc), nowYear, nowMonth, effectiveDay) {
			err := s.store.SetSetting(ctx, key, currentMonth)
			mu.Unlock()
			if err != nil {
				return err
			}
			continue
		}

		wasPaused := node.IsTrafficPaused
		if err := s.store.ResetNodeCycleTraffic(ctx, node.ID, nowUTC); err != nil {
			mu.Unlock()
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			return err
		}
		if err := s.store.SetSetting(ctx, key, currentMonth); err != nil {
			mu.Unlock()
			return err
		}

		online, lastSeen := s.hubConnectionState(node.ID)
		if err := s.store.SetNodeConnectionStatus(ctx, node.ID, online, lastSeen); err != nil && !errors.Is(err, store.ErrNotFound) {
			mu.Unlock()
			return err
		}
		s.setNodeWarned(node.ID, false)

		if wasPaused {
			if _, err := s.store.IncrementNodeConfigRevision(ctx, node.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				mu.Unlock()
				return err
			}
			s.syncNodeIgnoringOffline(ctx, node.ID)
			s.notify(ctx, webhook.AlertEvent{
				Type:       webhook.EventTrafficRecovered,
				Severity:   webhook.SeverityInfo,
				TargetType: webhook.TargetTypeNode,
				TargetID:   node.ID,
				TargetName: node.Name,
				Title:      "Node Monthly Billing Reset",
				Message:    fmt.Sprintf("Node %s monthly cycle traffic reset (%s) and service resumed", node.Name, currentMonth),
				Resolved:   true,
				Timestamp:  nowUTC,
			})
		}

		mu.Unlock()
	}
	return nil
}

func (s *Scheduler) runUserBillingResets(
	ctx context.Context,
	nowUTC time.Time,
	nowYear int,
	nowMonth time.Month,
	nowDay int,
	dim int,
	currentMonth string,
	loc *time.Location,
) error {
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return err
	}

	for _, u := range users {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		mu := s.userLock(u.ID)
		mu.Lock()

		user, err := s.store.GetUserByID(ctx, u.ID)
		if err != nil {
			mu.Unlock()
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			return err
		}

		if user.BillingResetDay <= 0 {
			mu.Unlock()
			continue
		}
		day := user.BillingResetDay
		if day > 31 {
			day = 31
		}
		effectiveDay := min(day, dim)
		if nowDay < effectiveDay {
			mu.Unlock()
			continue
		}

		key := fmt.Sprintf("%s%d", userResetMonthPrefix, user.ID)
		lastMonth, err := s.store.GetSettingOrDefault(ctx, key, "")
		if err != nil {
			mu.Unlock()
			return err
		}
		if lastMonth == currentMonth {
			mu.Unlock()
			continue
		}

		if lastMonth == "" && user.LastResetAt != nil && isOnOrAfterLocalResetDay(user.LastResetAt.In(loc), nowYear, nowMonth, effectiveDay) {
			err := s.store.SetSetting(ctx, key, currentMonth)
			mu.Unlock()
			if err != nil {
				return err
			}
			continue
		}

		wasExhausted := isUserQuotaExhausted(user)
		if err := s.store.ResetUserTraffic(ctx, user.ID, nowUTC); err != nil {
			mu.Unlock()
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			return err
		}
		if err := s.store.SetSetting(ctx, key, currentMonth); err != nil {
			mu.Unlock()
			return err
		}
		s.clearUserExhausted(user.ID)
		mu.Unlock()

		if wasExhausted && user.Enabled && !isUserExpired(user, nowUTC) {
			if _, err := s.store.IncrementConfigRevisionByUser(ctx, user.ID); err != nil {
				return err
			}
			if s.hub != nil {
				if err := s.hub.SyncNodesForUser(ctx, user.ID); err != nil &&
					!errors.Is(err, hub.ErrNodeOffline) &&
					!errors.Is(err, hub.ErrHubClosed) {
					s.logger.Warn("scheduler: sync nodes for reset user failed", "user_id", user.ID, "err", err)
				}
			}
		}
	}
	return nil
}
