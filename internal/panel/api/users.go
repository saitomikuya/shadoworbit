package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"snell-panel/internal/panel/auth"
	"snell-panel/internal/panel/hub"
	"snell-panel/internal/panel/store"
)

type userDTO struct {
	ID                int64   `json:"id"`
	Username          string  `json:"username"`
	Enabled           bool    `json:"enabled"`
	SubToken          string  `json:"sub_token"`
	SSUPSK16          string  `json:"ss_upsk_16"`
	SSUPSK32          string  `json:"ss_upsk_32"`
	STLSPassword      string  `json:"stls_password"`
	TrafficQuotaBytes int64   `json:"traffic_quota_bytes"`
	BillingResetDay   int     `json:"billing_reset_day"`
	UsedUpBytes       int64   `json:"used_up_bytes"`
	UsedDownBytes     int64   `json:"used_down_bytes"`
	ExpireAt          *string `json:"expire_at"`
	NodeIDs           []int64 `json:"node_ids"`
}

type createUserRequest struct {
	Username          string  `json:"username"`
	Enabled           *bool   `json:"enabled"`
	TrafficQuotaBytes int64   `json:"traffic_quota_bytes"`
	BillingResetDay   *int    `json:"billing_reset_day"`
	ExpireAt          *string `json:"expire_at"`
	NodeIDs           []int64 `json:"node_ids"`
}

type optionalTime struct {
	set   bool
	value *time.Time
}

func (o *optionalTime) UnmarshalJSON(data []byte) error {
	o.set = true
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		o.value = nil
		return nil
	}
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	t, err := parseRFC3339UTC(raw)
	if err != nil {
		return err
	}
	o.value = &t
	return nil
}

type updateUserRequest struct {
	Username          *string      `json:"username"`
	Enabled           *bool        `json:"enabled"`
	TrafficQuotaBytes *int64       `json:"traffic_quota_bytes"`
	BillingResetDay   *int         `json:"billing_reset_day"`
	ExpireAt          optionalTime `json:"expire_at"`
	NodeIDs           *[]int64     `json:"node_ids"`
}

type resetKeysRequest struct {
	ResetSubToken     bool `json:"reset_sub_token"`
	ResetUPSK         bool `json:"reset_upsk"`
	ResetSTLSPassword bool `json:"reset_stls_password"`
}

type setUserNodesRequest struct {
	NodeIDs []int64 `json:"node_ids"`
}

func parseRFC3339UTC(raw string) (time.Time, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return time.Time{}, errors.New("empty timestamp")
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

func toUserDTO(u store.User, nodeIDs []int64) userDTO {
	if nodeIDs == nil {
		nodeIDs = []int64{}
	}
	var expireStr *string
	if u.ExpireAt != nil {
		formatted := u.ExpireAt.UTC().Format(time.RFC3339)
		expireStr = &formatted
	}
	return userDTO{
		ID:                u.ID,
		Username:          u.Username,
		Enabled:           u.Enabled,
		SubToken:          u.SubToken,
		SSUPSK16:          u.SSUPSK16,
		SSUPSK32:          u.SSUPSK32,
		STLSPassword:      u.STLSPassword,
		TrafficQuotaBytes: u.TrafficQuotaBytes,
		BillingResetDay:   u.BillingResetDay,
		UsedUpBytes:       u.UsedUpBytes,
		UsedDownBytes:     u.UsedDownBytes,
		ExpireAt:          expireStr,
		NodeIDs:           nodeIDs,
	}
}

func (s *server) handleListUsers(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	accessMap, err := s.store.ListAllUserNodeAccess(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list user node access")
		return
	}

	out := make([]userDTO, 0, len(users))
	for _, u := range users {
		out = append(out, toUserDTO(u, accessMap[u.ID]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) handleCreateUser(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	var req createUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	username := strings.TrimSpace(req.Username)
	if username == "" {
		writeError(w, http.StatusBadRequest, "username cannot be empty")
		return
	}
	if req.TrafficQuotaBytes < 0 {
		writeError(w, http.StatusBadRequest, "traffic_quota_bytes cannot be negative")
		return
	}
	billingResetDay := 1
	if req.BillingResetDay != nil {
		billingResetDay = *req.BillingResetDay
	}
	if billingResetDay < 0 || billingResetDay > 31 {
		writeError(w, http.StatusBadRequest, "billing_reset_day must be between 0 and 31")
		return
	}

	var expireAt *time.Time
	if req.ExpireAt != nil {
		t, err := parseRFC3339UTC(*req.ExpireAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid expire_at timestamp (must be RFC3339)")
			return
		}
		expireAt = &t
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	subToken, err := auth.GenerateSubToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate sub_token")
		return
	}
	upsk16, err := auth.GenerateUPSK16()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate ss_upsk_16")
		return
	}
	upsk32, err := auth.GenerateUPSK32()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate ss_upsk_32")
		return
	}
	stlsPwd, err := auth.GenerateShadowTLSPassword()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate stls_password")
		return
	}

	user := &store.User{
		Username:          username,
		Enabled:           enabled,
		SubToken:          subToken,
		SSUPSK16:          upsk16,
		SSUPSK32:          upsk32,
		STLSPassword:      stlsPwd,
		TrafficQuotaBytes: req.TrafficQuotaBytes,
		BillingResetDay:   billingResetDay,
		ExpireAt:          expireAt,
	}

	nodeIDs, err := s.store.CreateUserWithNodes(r.Context(), user, req.NodeIDs)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			writeError(w, http.StatusConflict, "username already exists")
		case errors.Is(err, store.ErrForeignKey):
			writeError(w, http.StatusBadRequest, "invalid node_ids")
		case errors.Is(err, store.ErrInvalidArgument):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "failed to create user")
		}
		return
	}

	if len(nodeIDs) > 0 {
		if err := s.store.BumpNodesConfigRevision(r.Context(), nodeIDs); err != nil {
			s.logger.Warn("bump revision on user create failed", "user_id", user.ID, "err", err)
		}
		s.syncNodeIDs(r.Context(), nodeIDs)
	}

	writeJSON(w, http.StatusCreated, toUserDTO(*user, nodeIDs))
}

func (s *server) handleGetUser(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	user, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	nodeIDs, err := s.store.GetUserNodeIDs(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get user nodes")
		return
	}

	writeJSON(w, http.StatusOK, toUserDTO(*user, nodeIDs))
}

func (s *server) handleUpdateUser(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	var req updateUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	existing, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to load user")
		return
	}

	updated := *existing
	if req.Username != nil {
		updated.Username = strings.TrimSpace(*req.Username)
	}
	if updated.Username == "" {
		writeError(w, http.StatusBadRequest, "username cannot be empty")
		return
	}
	if req.Enabled != nil {
		updated.Enabled = *req.Enabled
	}
	if req.TrafficQuotaBytes != nil {
		updated.TrafficQuotaBytes = *req.TrafficQuotaBytes
	}
	if updated.TrafficQuotaBytes < 0 {
		writeError(w, http.StatusBadRequest, "traffic_quota_bytes cannot be negative")
		return
	}
	if req.BillingResetDay != nil {
		updated.BillingResetDay = *req.BillingResetDay
	}
	if updated.BillingResetDay < 0 || updated.BillingResetDay > 31 {
		writeError(w, http.StatusBadRequest, "billing_reset_day must be between 0 and 31")
		return
	}
	if req.ExpireAt.set {
		updated.ExpireAt = req.ExpireAt.value
	}

	oldIDs, newIDs, err := s.store.UpdateUserWithNodes(r.Context(), &updated, req.NodeIDs)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "user not found")
		case errors.Is(err, store.ErrConflict):
			writeError(w, http.StatusConflict, "username already exists")
		case errors.Is(err, store.ErrForeignKey):
			writeError(w, http.StatusBadRequest, "invalid node_ids")
		case errors.Is(err, store.ErrInvalidArgument):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "failed to update user")
		}
		return
	}

	if err := s.sched.EvaluateUsers(r.Context(), []int64{id}); err != nil {
		s.logger.Warn("evaluate user after update failed", "user_id", id, "err", err)
	}

	var nodeIDs []int64
	if req.NodeIDs != nil {
		nodeIDs = newIDs
		affectedNodes := unionInt64(oldIDs, newIDs)
		if len(affectedNodes) > 0 {
			if err := s.store.BumpNodesConfigRevision(r.Context(), affectedNodes); err != nil {
				s.logger.Warn("bump nodes revision after user update failed", "user_id", id, "err", err)
			}
			s.syncNodeIDs(r.Context(), affectedNodes)
		}
	} else {
		if _, err := s.store.IncrementConfigRevisionByUser(r.Context(), id); err != nil {
			s.logger.Warn("increment user nodes revision failed", "user_id", id, "err", err)
		}
		if err := s.hub.SyncNodesForUser(r.Context(), id); err != nil && !errors.Is(err, hub.ErrHubClosed) {
			s.logger.Warn("sync nodes for user after update failed", "user_id", id, "err", err)
		}
		nodeIDs, _ = s.store.GetUserNodeIDs(r.Context(), id)
	}

	latest, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		latest = &updated
	}
	writeJSON(w, http.StatusOK, toUserDTO(*latest, nodeIDs))
}

func (s *server) handleDeleteUser(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	nodeIDs, err := s.store.GetUserNodeIDs(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read user nodes")
		return
	}

	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete user")
		return
	}

	if len(nodeIDs) > 0 {
		if err := s.store.BumpNodesConfigRevision(r.Context(), nodeIDs); err != nil {
			s.logger.Warn("bump revision after user delete failed", "user_id", id, "err", err)
		}
		s.syncNodeIDs(r.Context(), nodeIDs)
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *server) handleResetUserKeys(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	if _, err := s.store.GetUserByID(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	var req resetKeysRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	upsk16, err := auth.GenerateUPSK16()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate ss_upsk_16")
		return
	}
	upsk32, err := auth.GenerateUPSK32()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate ss_upsk_32")
		return
	}
	stlsPwd, err := auth.GenerateShadowTLSPassword()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate stls_password")
		return
	}

	var subToken string
	if req.ResetSubToken {
		subToken, err = auth.GenerateSubToken()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to generate sub_token")
			return
		}
	}

	if err := s.store.ResetUserKeys(r.Context(), id, upsk16, upsk32, stlsPwd, subToken); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to reset user keys")
		return
	}

	if _, err := s.store.IncrementConfigRevisionByUser(r.Context(), id); err != nil {
		s.logger.Warn("increment config_revision after reset-keys failed", "user_id", id, "err", err)
	}
	if err := s.hub.SyncNodesForUser(r.Context(), id); err != nil && !errors.Is(err, hub.ErrHubClosed) {
		s.logger.Warn("sync nodes after reset-keys failed", "user_id", id, "err", err)
	}

	updated, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to reload user")
		return
	}
	nodeIDs, _ := s.store.GetUserNodeIDs(r.Context(), id)
	writeJSON(w, http.StatusOK, toUserDTO(*updated, nodeIDs))
}

func (s *server) handleResetUserTraffic(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	user, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	wasExhausted := user.IsQuotaExhausted()

	if err := s.store.ResetUserTraffic(r.Context(), id, time.Now().UTC()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to reset user traffic")
		return
	}

	if err := s.sched.EvaluateUsers(r.Context(), []int64{id}); err != nil {
		s.logger.Warn("evaluate user after reset-traffic failed", "user_id", id, "err", err)
	}

	if wasExhausted {
		if _, err := s.store.IncrementConfigRevisionByUser(r.Context(), id); err != nil {
			s.logger.Warn("increment config_revision after user reset-traffic failed", "user_id", id, "err", err)
		}
		if err := s.hub.SyncNodesForUser(r.Context(), id); err != nil && !errors.Is(err, hub.ErrHubClosed) {
			s.logger.Warn("sync nodes after user reset-traffic failed", "user_id", id, "err", err)
		}
	}

	updated, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to reload user")
		return
	}
	nodeIDs, _ := s.store.GetUserNodeIDs(r.Context(), id)
	writeJSON(w, http.StatusOK, toUserDTO(*updated, nodeIDs))
}

func (s *server) handleGetUserNodes(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	if _, err := s.store.GetUserByID(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to check user")
		return
	}

	nodeIDs, err := s.store.GetUserNodeIDs(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get user nodes")
		return
	}
	if nodeIDs == nil {
		nodeIDs = []int64{}
	}
	writeJSON(w, http.StatusOK, map[string][]int64{"node_ids": nodeIDs})
}

func (s *server) handleGetUserTrafficBreakdown(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	user, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	items, err := s.store.ListUserNodeTraffic(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get user traffic breakdown")
		return
	}
	if items == nil {
		items = []store.UserNodeTrafficEntry{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":          user.ID,
		"username":         user.Username,
		"total_up_bytes":   user.UsedUpBytes,
		"total_down_bytes": user.UsedDownBytes,
		"total_bytes":      user.UsedUpBytes + user.UsedDownBytes,
		"items":            items,
	})
}

func (s *server) handleGetAdminTraffic(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	totalBytes, items, err := s.store.ListAdminNodeTraffic(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get admin traffic breakdown")
		return
	}
	if items == nil {
		items = []store.AdminNodeTrafficEntry{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"username":    "admin",
		"total_bytes": totalBytes,
		"items":       items,
	})
}

func (s *server) handleResetAdminTraffic(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	if err := s.store.ResetAdminTraffic(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to reset admin traffic")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) handleSetUserNodes(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user id")
		return
	}

	var req setUserNodesRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	oldIDs, newIDs, err := s.store.ReplaceUserNodes(r.Context(), id, req.NodeIDs)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "user not found")
		case errors.Is(err, store.ErrForeignKey), errors.Is(err, store.ErrInvalidArgument):
			writeError(w, http.StatusBadRequest, "invalid node_ids")
		default:
			writeError(w, http.StatusInternalServerError, "failed to set user nodes")
		}
		return
	}
	if newIDs == nil {
		newIDs = []int64{}
	}

	affected := unionInt64(oldIDs, newIDs)
	if len(affected) > 0 {
		if err := s.store.BumpNodesConfigRevision(r.Context(), affected); err != nil {
			s.logger.Warn("bump nodes revision after set user nodes failed", "user_id", id, "err", err)
		}
		s.syncNodeIDs(r.Context(), affected)
	}

	writeJSON(w, http.StatusOK, map[string][]int64{"node_ids": newIDs})
}
