package api

import (
	"errors"
	"net/http"

	"snell-panel/internal/panel/auth"
)

type loginRequest struct {
	Password string `json:"password"`
}

type loginResponse struct {
	Token string `json:"token"`
}

type changePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	token, err := s.auth.Login(r.Context(), req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}

	writeJSON(w, http.StatusOK, loginResponse{
		Token: token,
	})
}

func (s *server) handleAuthMe(w http.ResponseWriter, _ *http.Request, _ *auth.AdminClaims) {
	writeJSON(w, http.StatusOK, map[string]bool{
		"authenticated": true,
	})
}

func (s *server) handleChangePassword(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	var req changePasswordRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	err := s.auth.ChangePassword(r.Context(), req.OldPassword, req.NewPassword)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			writeError(w, http.StatusUnauthorized, "invalid old password")
		case errors.Is(err, auth.ErrEmptyPassword), errors.Is(err, auth.ErrPasswordTooLong):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "failed to change password")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
