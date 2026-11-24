package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"snell-panel/internal/panel/sub"
)

func (s *server) handleAdminSub(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	mode := strings.TrimSpace(r.URL.Query().Get("mode"))

	var tplID int64
	if rawTpl := strings.TrimSpace(r.URL.Query().Get("tpl")); rawTpl != "" {
		parsed, err := strconv.ParseInt(rawTpl, 10, 64)
		if err != nil || parsed <= 0 {
			writeError(w, http.StatusBadRequest, "invalid tpl parameter")
			return
		}
		tplID = parsed
	}

	res, err := s.sub.RenderAdmin(r.Context(), token, sub.AdminRenderOptions{
		Mode:       mode,
		TemplateID: tplID,
		BaseURL:    deriveBaseURL(r),
	})
	if res != nil {
		copyHeaders(w.Header(), res.Headers)
	}
	if err != nil {
		writeSubError(w, err)
		return
	}

	ctype := res.ContentType
	if ctype == "" {
		ctype = "text/plain; charset=utf-8"
	}
	w.Header().Set("Content-Type", ctype)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(res.Body))
}

func (s *server) handleUserSub(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	mode := strings.TrimSpace(r.URL.Query().Get("mode"))

	var tplID int64
	if rawTpl := strings.TrimSpace(r.URL.Query().Get("tpl")); rawTpl != "" {
		parsed, err := strconv.ParseInt(rawTpl, 10, 64)
		if err != nil || parsed <= 0 {
			writeError(w, http.StatusBadRequest, "invalid tpl parameter")
			return
		}
		tplID = parsed
	}

	res, err := s.sub.RenderUser(r.Context(), token, r.UserAgent(), sub.UserRenderOptions{
		Target:     target,
		Mode:       mode,
		TemplateID: tplID,
		BaseURL:    deriveBaseURL(r),
	})
	if res != nil {
		copyHeaders(w.Header(), res.Headers)
	}
	if err != nil {
		writeSubError(w, err)
		return
	}

	ctype := res.ContentType
	if ctype == "" {
		ctype = "text/plain; charset=utf-8"
	}
	w.Header().Set("Content-Type", ctype)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(res.Body))
}

func copyHeaders(dst, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Set(k, v)
		}
	}
}

func writeSubError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sub.ErrUnauthorized):
		writeError(w, http.StatusUnauthorized, "unauthorized")
	case errors.Is(err, sub.ErrForbidden):
		writeError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, sub.ErrTemplateNotFound):
		writeError(w, http.StatusNotFound, "template not found")
	case errors.Is(err, sub.ErrInvalidArgument):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "failed to render subscription")
	}
}
