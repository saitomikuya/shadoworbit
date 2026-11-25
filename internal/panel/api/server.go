package api

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"path"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"snell-panel/internal/panel/auth"
	"snell-panel/internal/panel/hub"
	"snell-panel/internal/panel/scheduler"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/panel/sub"
	"snell-panel/internal/panel/webhook"
)

const maxJSONBodyBytes = 1 << 20 // 1 MiB

// Dependencies holds the collaborators required to construct the Panel HTTP handler.
type Dependencies struct {
	Store     *store.Store
	Auth      *auth.Service
	Hub       *hub.Hub
	Sub       *sub.Renderer
	Scheduler *scheduler.Scheduler
	Webhook   *webhook.Engine
	StaticFS  fs.FS
	Logger    *slog.Logger
}

type server struct {
	store    *store.Store
	auth     *auth.Service
	hub      *hub.Hub
	sub      *sub.Renderer
	sched    *scheduler.Scheduler
	webhook  *webhook.Engine
	staticFS fs.FS
	logger   *slog.Logger
}

// NewServer constructs the Panel HTTP handler with recovery, structured logging,
// JWT auth middleware, REST/WS/Subscription routes, and optional SPA static serving.
func NewServer(deps Dependencies) http.Handler {
	if deps.Store == nil {
		panic("api: Store dependency must not be nil")
	}
	if deps.Auth == nil {
		panic("api: Auth dependency must not be nil")
	}
	if deps.Hub == nil {
		panic("api: Hub dependency must not be nil")
	}
	if deps.Sub == nil {
		panic("api: Sub dependency must not be nil")
	}
	if deps.Scheduler == nil {
		panic("api: Scheduler dependency must not be nil")
	}
	if deps.Webhook == nil {
		panic("api: Webhook dependency must not be nil")
	}

	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}

	s := &server{
		store:    deps.Store,
		auth:     deps.Auth,
		hub:      deps.Hub,
		sub:      deps.Sub,
		sched:    deps.Scheduler,
		webhook:  deps.Webhook,
		staticFS: deps.StaticFS,
		logger:   logger,
	}

	mux := http.NewServeMux()
	s.registerRoutes(mux)

	return s.recoverMiddleware(s.loggingMiddleware(mux))
}

func (s *server) registerRoutes(mux *http.ServeMux) {
	// Health check
	mux.HandleFunc("/healthz", s.handleHealthz)

	// Auth
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("GET /api/v1/auth/me", s.requireAdminJWT(s.handleAuthMe))
	mux.HandleFunc("PUT /api/v1/auth/password", s.requireAdminJWT(s.handleChangePassword))

	// Public & Agent WS (explicit method checks so non-GET returns 405, not /api/ 404)
	mux.HandleFunc("/api/v1/public/status", s.handlePublicStatus)
	mux.HandleFunc("/api/v1/public/ws", s.handlePublicWS)
	mux.HandleFunc("/api/v1/agent/ws", s.handleAgentWS)

	// Subscriptions
	mux.HandleFunc("GET /s/admin/{token}", s.handleAdminSub)
	mux.HandleFunc("GET /s/admin/{token}/{filename}", s.handleAdminSub)
	mux.HandleFunc("GET /s/u/{token}", s.handleUserSub)
	mux.HandleFunc("GET /s/u/{token}/{filename}", s.handleUserSub)

	// Admin Nodes
	mux.HandleFunc("GET /api/v1/admin/nodes", s.requireAdminJWT(s.handleListNodes))
	mux.HandleFunc("POST /api/v1/admin/nodes", s.requireAdminJWT(s.handleCreateNode))
	mux.HandleFunc("PUT /api/v1/admin/nodes/reorder", s.requireAdminJWT(s.handleReorderNodes))
	mux.HandleFunc("POST /api/v1/admin/nodes/reorder", s.requireAdminJWT(s.handleReorderNodes))
	mux.HandleFunc("GET /api/v1/admin/nodes/{id}", s.requireAdminJWT(s.handleGetNode))
	mux.HandleFunc("PUT /api/v1/admin/nodes/{id}", s.requireAdminJWT(s.handleUpdateNode))
	mux.HandleFunc("DELETE /api/v1/admin/nodes/{id}", s.requireAdminJWT(s.handleDeleteNode))
	mux.HandleFunc("POST /api/v1/admin/nodes/{id}/reset-traffic", s.requireAdminJWT(s.handleResetNodeTraffic))
	mux.HandleFunc("POST /api/v1/admin/nodes/{id}/calibrate-traffic", s.requireAdminJWT(s.handleCalibrateNodeTraffic))
	mux.HandleFunc("POST /api/v1/admin/nodes/{id}/service-ctl", s.requireAdminJWT(s.handleNodeServiceCtl))
	mux.HandleFunc("POST /api/v1/admin/nodes/{id}/sync", s.requireAdminJWT(s.handleSyncNode))
	mux.HandleFunc("GET /api/v1/admin/nodes/{id}/install-cmd", s.requireAdminJWT(s.handleNodeInstallCmd))

	// Admin Users
	mux.HandleFunc("GET /api/v1/admin/users", s.requireAdminJWT(s.handleListUsers))
	mux.HandleFunc("POST /api/v1/admin/users", s.requireAdminJWT(s.handleCreateUser))
	mux.HandleFunc("GET /api/v1/admin/users/{id}", s.requireAdminJWT(s.handleGetUser))
	mux.HandleFunc("PUT /api/v1/admin/users/{id}", s.requireAdminJWT(s.handleUpdateUser))
	mux.HandleFunc("DELETE /api/v1/admin/users/{id}", s.requireAdminJWT(s.handleDeleteUser))
	mux.HandleFunc("POST /api/v1/admin/users/{id}/reset-keys", s.requireAdminJWT(s.handleResetUserKeys))
	mux.HandleFunc("POST /api/v1/admin/users/{id}/reset-traffic", s.requireAdminJWT(s.handleResetUserTraffic))
	mux.HandleFunc("GET /api/v1/admin/users/{id}/traffic-breakdown", s.requireAdminJWT(s.handleGetUserTrafficBreakdown))
	mux.HandleFunc("GET /api/v1/admin/admin-traffic", s.requireAdminJWT(s.handleGetAdminTraffic))
	mux.HandleFunc("POST /api/v1/admin/admin-traffic/reset", s.requireAdminJWT(s.handleResetAdminTraffic))
	mux.HandleFunc("GET /api/v1/admin/users/{id}/nodes", s.requireAdminJWT(s.handleGetUserNodes))
	mux.HandleFunc("PUT /api/v1/admin/users/{id}/nodes", s.requireAdminJWT(s.handleSetUserNodes))

	// Admin DNS Rule Groups
	mux.HandleFunc("GET /api/v1/admin/dns-rules", s.requireAdminJWT(s.handleListDNSRuleGroups))
	mux.HandleFunc("POST /api/v1/admin/dns-rules", s.requireAdminJWT(s.handleCreateDNSRuleGroup))
	mux.HandleFunc("GET /api/v1/admin/dns-rules/{id}", s.requireAdminJWT(s.handleGetDNSRuleGroup))
	mux.HandleFunc("PUT /api/v1/admin/dns-rules/{id}", s.requireAdminJWT(s.handleUpdateDNSRuleGroup))
	mux.HandleFunc("DELETE /api/v1/admin/dns-rules/{id}", s.requireAdminJWT(s.handleDeleteDNSRuleGroup))

	// Admin Templates
	mux.HandleFunc("GET /api/v1/admin/templates", s.requireAdminJWT(s.handleListTemplates))
	mux.HandleFunc("POST /api/v1/admin/templates", s.requireAdminJWT(s.handleCreateTemplate))
	mux.HandleFunc("GET /api/v1/admin/templates/{id}", s.requireAdminJWT(s.handleGetTemplate))
	mux.HandleFunc("PUT /api/v1/admin/templates/{id}", s.requireAdminJWT(s.handleUpdateTemplate))
	mux.HandleFunc("DELETE /api/v1/admin/templates/{id}", s.requireAdminJWT(s.handleDeleteTemplate))

	// Admin Kernels
	mux.HandleFunc("GET /api/v1/admin/kernels", s.requireAdminJWT(s.handleListKernels))
	mux.HandleFunc("POST /api/v1/admin/kernels/sync", s.requireAdminJWT(s.handleSyncKernels))
	mux.HandleFunc("GET /api/v1/admin/kernels/snell-versions", s.requireAdminJWT(s.handleListSnellVersions))
	mux.HandleFunc("POST /api/v1/admin/kernels/snell-versions", s.requireAdminJWT(s.handleAddSnellVersion))
	mux.HandleFunc("DELETE /api/v1/admin/kernels/snell-versions", s.requireAdminJWT(s.handleDeleteSnellVersion))
	mux.HandleFunc("DELETE /api/v1/admin/kernels/snell-versions/{version}", s.requireAdminJWT(s.handleDeleteSnellVersion))
	mux.HandleFunc("POST /api/v1/admin/kernels/update", s.requireAdminJWT(s.handleKernelUpdate))

	// Admin Webhooks
	mux.HandleFunc("GET /api/v1/admin/webhooks", s.requireAdminJWT(s.handleListWebhooks))
	mux.HandleFunc("POST /api/v1/admin/webhooks", s.requireAdminJWT(s.handleCreateWebhook))
	mux.HandleFunc("GET /api/v1/admin/webhooks/{id}", s.requireAdminJWT(s.handleGetWebhook))
	mux.HandleFunc("PUT /api/v1/admin/webhooks/{id}", s.requireAdminJWT(s.handleUpdateWebhook))
	mux.HandleFunc("DELETE /api/v1/admin/webhooks/{id}", s.requireAdminJWT(s.handleDeleteWebhook))
	mux.HandleFunc("POST /api/v1/admin/webhooks/{id}/test", s.requireAdminJWT(s.handleTestWebhook))

	// Admin Daily Traffic & Settings
	mux.HandleFunc("GET /api/v1/admin/traffic/daily", s.requireAdminJWT(s.handleListDailyTraffic))
	mux.HandleFunc("GET /api/v1/admin/traffic/logs", s.requireAdminJWT(s.handleListTrafficLogs))
	mux.HandleFunc("GET /api/v1/admin/settings", s.requireAdminJWT(s.handleGetSettings))
	mux.HandleFunc("PUT /api/v1/admin/settings", s.requireAdminJWT(s.handleUpdateSettings))

	// Catch-alls so /api/* and /s/* never fall back to SPA HTML
	mux.HandleFunc("/api/", s.handleAPINotFound)
	mux.HandleFunc("/s/", s.handleSubNotFound)

	// SPA & Static Assets
	mux.HandleFunc("/", s.handleSPA)
}

type responseRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *responseRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.status = code
	r.wroteHeader = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(b)
}

func (r *responseRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijacker not supported")
	}
	return h.Hijack()
}

func (r *responseRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func (s *server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("http handler panic",
					"panic", rec,
					"method", r.Method,
					"path", r.URL.Path,
					"stack", string(debug.Stack()),
				)
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.logger.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

func (s *server) requireAdminJWT(next func(http.ResponseWriter, *http.Request, *auth.AdminClaims)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr, err := auth.ExtractBearerToken(r.Header.Get("Authorization"))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		claims, err := s.auth.VerifyJWT(tokenStr)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r, claims)
	}
}

func (s *server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) handleAPINotFound(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotFound, "not found")
}

func (s *server) handleSubNotFound(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotFound, "not found")
}

func (s *server) handleSPA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.staticFS == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	rawPath := r.URL.Path
	// Reject explicit traversal segments before cleaning.
	for _, seg := range strings.Split(strings.ReplaceAll(rawPath, "\\", "/"), "/") {
		if seg == ".." {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
	}

	cleaned := path.Clean("/" + rawPath)
	rel := strings.TrimPrefix(cleaned, "/")

	// /assets/* must resolve to an existing file in StaticFS and never fall back to SPA HTML.
	if cleaned == "/assets" || strings.HasPrefix(cleaned, "/assets/") {
		if rel == "" || !fs.ValidPath(rel) {
			http.NotFound(w, r)
			return
		}
		s.serveStaticFile(w, r, rel, "public, max-age=31536000, immutable")
		return
	}

	// SPA routes: /, /admin, /admin/*
	if cleaned == "/" || cleaned == "/admin" || strings.HasPrefix(cleaned, "/admin/") {
		s.serveStaticFile(w, r, "index.html", "no-cache")
		return
	}

	// Other root static files (e.g. /favicon.ico, /robots.txt) if present in StaticFS.
	if rel != "" && fs.ValidPath(rel) {
		if info, err := fs.Stat(s.staticFS, rel); err == nil && !info.IsDir() {
			s.serveStaticFile(w, r, rel, "public, max-age=3600")
			return
		}
	}

	http.NotFound(w, r)
}

func (s *server) serveStaticFile(w http.ResponseWriter, r *http.Request, relPath, cacheControl string) {
	f, err := s.staticFS.Open(relPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}

	ctype := mime.TypeByExtension(path.Ext(relPath))
	if relPath == "index.html" || path.Ext(relPath) == ".html" {
		ctype = "text/html; charset=utf-8"
	} else if ctype == "" {
		switch strings.ToLower(path.Ext(relPath)) {
		case ".js", ".mjs":
			ctype = "application/javascript; charset=utf-8"
		case ".css":
			ctype = "text/css; charset=utf-8"
		case ".svg":
			ctype = "image/svg+xml"
		case ".json":
			ctype = "application/json; charset=utf-8"
		}
	}
	if ctype != "" {
		w.Header().Set("Content-Type", ctype)
	}
	if cacheControl != "" {
		w.Header().Set("Cache-Control", cacheControl)
	}

	if rs, ok := f.(io.ReadSeeker); ok {
		http.ServeContent(w, r, path.Base(relPath), info.ModTime(), rs)
		return
	}

	data, err := io.ReadAll(f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read static asset")
		return
	}
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return errors.New("empty request body")
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxJSONBodyBytes))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return errors.New("unexpected trailing JSON data")
	}
	return nil
}

func decodeOptionalJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBodyBytes))
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return errors.New("unexpected trailing JSON data")
	}
	return nil
}

func parseID(raw string) (int64, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("invalid id %q", raw)
	}
	return id, nil
}

func deriveBaseURL(r *http.Request) string {
	host := strings.TrimSpace(r.Host)
	if host == "" {
		return ""
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if xfProto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); xfProto != "" {
		first := strings.TrimSpace(strings.Split(xfProto, ",")[0])
		if strings.EqualFold(first, "https") {
			scheme = "https"
		} else if strings.EqualFold(first, "http") {
			scheme = "http"
		}
	}
	return scheme + "://" + host
}

func deriveWSBaseURL(r *http.Request) string {
	base := deriveBaseURL(r)
	if strings.HasPrefix(base, "https://") {
		return "wss://" + strings.TrimPrefix(base, "https://")
	}
	if strings.HasPrefix(base, "http://") {
		return "ws://" + strings.TrimPrefix(base, "http://")
	}
	return ""
}
