package scheduler

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"snell-panel/internal/panel/store"
	"snell-panel/internal/panel/webhook"
	"time"
)

func isUserExpired(u *store.User, nowUTC time.Time) bool {
	return u != nil && u.ExpireAt != nil && !u.ExpireAt.After(nowUTC)
}

func isUserQuotaExhausted(u *store.User) bool {
	return u != nil && u.IsQuotaExhausted()
}

// SweepUsers evaluates all users for expiry and quota exhaustion transitions,
// hot-syncs affected nodes once per unique node, and prunes deleted user IDs.
func (s *Scheduler) SweepUsers(ctx context.Context, now time.Time) error {
	if s.store == nil {
		return errors.New("scheduler: nil store")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if now.IsZero() {
		now = s.now()
	}
	nowUTC := now.UTC()

	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return err
	}

	present := make(map[int64]struct{}, len(users))
	ids := make([]int64, 0, len(users))
	for _, u := range users {
		present[u.ID] = struct{}{}
		ids = append(ids, u.ID)
	}
	s.pruneUserStates(present)

	return s.evaluateUserIDs(ctx, ids, nowUTC)
}

// EvaluateUsers evaluates the specified user IDs for expiry and quota exhaustion transitions,
// deduplicating affected nodes across the batch and syncing each affected node once.
func (s *Scheduler) EvaluateUsers(ctx context.Context, userIDs []int64) error {
	if s.store == nil {
		return errors.New("scheduler: nil store")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if len(userIDs) == 0 {
		return nil
	}

	seen := make(map[int64]struct{}, len(userIDs))
	uniqueIDs := make([]int64, 0, len(userIDs))
	for _, id := range userIDs {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		uniqueIDs = append(uniqueIDs, id)
	}
	if len(uniqueIDs) == 0 {
		return nil
	}

	return s.evaluateUserIDs(ctx, uniqueIDs, s.now().UTC())
}

func (s *Scheduler) evaluateUserIDs(ctx context.Context, userIDs []int64, nowUTC time.Time) error {
	affectedSet := make(map[int64]struct{})
	affectedNodes := make([]int64, 0)

	var expiredAlerts []webhook.AlertEvent
	var quotaAlerts []webhook.AlertEvent

	for _, uid := range userIDs {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		mu := s.userLock(uid)
		mu.Lock()

		user, err := s.store.GetUserByID(ctx, uid)
		if err != nil {
			mu.Unlock()
			if errors.Is(err, store.ErrNotFound) {
				s.deleteUserState(uid)
				continue
			}
			return err
		}

		nowExpired := isUserExpired(user, nowUTC)
		nowExhausted := isUserQuotaExhausted(user)

		s.mu.Lock()
		prev := s.userStates[user.ID]
		s.userStates[user.ID] = userLifecycleState{
			expired:   nowExpired,
			exhausted: nowExhausted,
		}
		s.mu.Unlock()

		newlyExpired := !prev.expired && nowExpired
		newlyExhausted := !prev.exhausted && nowExhausted
		recoveredToActive := (prev.expired || prev.exhausted) && !nowExpired && !nowExhausted

		if user.Enabled && (newlyExpired || newlyExhausted || recoveredToActive) {
			nodeIDs, err := s.store.GetUserNodeIDs(ctx, user.ID)
			if err != nil {
				mu.Unlock()
				return err
			}
			for _, nid := range nodeIDs {
				if _, ok := affectedSet[nid]; !ok {
					affectedSet[nid] = struct{}{}
					affectedNodes = append(affectedNodes, nid)
				}
			}

			if newlyExpired {
				expiredAlerts = append(expiredAlerts, webhook.AlertEvent{
					Type:       webhook.EventUserExpired,
					Severity:   webhook.SeverityWarning,
					TargetType: webhook.TargetTypeUser,
					TargetID:   user.ID,
					TargetName: user.Username,
					Title:      "User Expired",
					Message:    fmt.Sprintf("User %s subscription expired at %s", user.Username, user.ExpireAt.UTC().Format(time.RFC3339)),
					Resolved:   false,
					Timestamp:  nowUTC,
				})
			}
			if newlyExhausted {
				used := uint64(max(int64(0), user.UsedUpBytes)) + uint64(max(int64(0), user.UsedDownBytes))
				quotaAlerts = append(quotaAlerts, webhook.AlertEvent{
					Type:       webhook.EventUserQuotaExhausted,
					Severity:   webhook.SeverityWarning,
					TargetType: webhook.TargetTypeUser,
					TargetID:   user.ID,
					TargetName: user.Username,
					Title:      "User Quota Exhausted",
					Message:    fmt.Sprintf("User %s exhausted traffic quota (%d / %d bytes)", user.Username, used, user.TrafficQuotaBytes),
					Resolved:   false,
					Timestamp:  nowUTC,
				})
			}
		}

		mu.Unlock()
	}

	if len(affectedNodes) > 0 {
		if err := s.store.BumpNodesConfigRevision(ctx, affectedNodes); err != nil {
			return err
		}
		for _, nid := range affectedNodes {
			s.syncNodeIgnoringOffline(ctx, nid)
		}
	}

	if len(expiredAlerts) > 0 && s.isAlertEnabled(ctx, settingAlertUserExpired) {
		for _, evt := range expiredAlerts {
			s.notify(ctx, evt)
		}
	}
	if len(quotaAlerts) > 0 && s.isAlertEnabled(ctx, settingAlertUserQuotaExhausted) {
		for _, evt := range quotaAlerts {
			s.notify(ctx, evt)
		}
	}

	return nil
}

func (s *Scheduler) isAlertEnabled(ctx context.Context, settingKey string) bool {
	val, err := s.store.GetSettingOrDefault(ctx, settingKey, "true")
	if err != nil {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "false", "0", "off":
		return false
	default:
		return true
	}
}

func (s *Scheduler) clearUserExhausted(userID int64) {
	s.mu.Lock()
	if st, ok := s.userStates[userID]; ok {
		st.exhausted = false
		s.userStates[userID] = st
	}
	s.mu.Unlock()
}

func (s *Scheduler) deleteUserState(userID int64) {
	s.mu.Lock()
	delete(s.userStates, userID)
	s.mu.Unlock()
}

func (s *Scheduler) pruneUserStates(present map[int64]struct{}) {
	s.mu.Lock()
	for id := range s.userStates {
		if _, ok := present[id]; !ok {
			delete(s.userStates, id)
		}
	}
	s.mu.Unlock()
}
