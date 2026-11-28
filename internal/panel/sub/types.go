package sub

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"snell-panel/internal/panel/store"
)

const (
	// ModeFull renders a complete client configuration using a template.
	ModeFull = "full"
	// ModeProxy renders only the proxy node list (Proxy List / Proxy Provider).
	ModeProxy = "proxy"

	// DefaultProfileUpdateInterval is the subscription refresh interval in hours.
	DefaultProfileUpdateInterval = "12"
	// DefaultManagedConfigInterval is the Surge managed-config interval in seconds (12h).
	DefaultManagedConfigInterval = 43200
)

// Sentinel errors returned by Renderer.
var (
	ErrUnauthorized       = errors.New("sub: unauthorized subscription token")
	ErrForbidden          = errors.New("sub: subscription access forbidden")
	ErrUserDisabled       = fmt.Errorf("%w: user disabled", ErrForbidden)
	ErrUserExpired        = fmt.Errorf("%w: user expired", ErrForbidden)
	ErrUserQuotaExhausted = fmt.Errorf("%w: user traffic quota exhausted", ErrForbidden)
	ErrTemplateNotFound   = errors.New("sub: subscription template not found")
	ErrInvalidArgument    = errors.New("sub: invalid argument")
	ErrInvalidMode        = fmt.Errorf("%w: invalid render mode", ErrInvalidArgument)
	ErrInvalidTarget      = fmt.Errorf("%w: invalid render target", ErrInvalidArgument)
	ErrInvalidBaseURL     = fmt.Errorf("%w: invalid base URL", ErrInvalidArgument)
	ErrTemplateMismatch   = fmt.Errorf("%w: template client_type mismatch", ErrInvalidArgument)
)

type subStore interface {
	GetSetting(ctx context.Context, key string) (string, error)
	ListNodes(ctx context.Context) ([]store.Node, error)
	ListLBGroups(ctx context.Context) ([]store.LBGroup, error)
	GetUserBySubToken(ctx context.Context, subToken string) (*store.User, error)
	ListAuthorizedNodesForUser(ctx context.Context, userID int64) ([]store.Node, error)
	GetSubTemplateByID(ctx context.Context, id int64) (*store.SubTemplate, error)
	GetDefaultSubTemplate(ctx context.Context, clientType string) (*store.SubTemplate, error)
	ListSubTemplates(ctx context.Context, clientType string) ([]store.SubTemplate, error)
}

// Option configures Renderer behavior.
type Option func(*Renderer)

// WithNow overrides the clock function used for user expiration checks.
func WithNow(fn func() time.Time) Option {
	return func(r *Renderer) {
		if fn != nil {
			r.now = fn
		}
	}
}

// AdminRenderOptions controls admin Surge subscription rendering.
type AdminRenderOptions struct {
	Mode       string
	TemplateID int64
	BaseURL    string
}

// UserRenderOptions controls normal user subscription rendering.
type UserRenderOptions struct {
	Target     string
	Mode       string
	TemplateID int64
	BaseURL    string
}

// RenderResult holds a rendered subscription payload and HTTP metadata.
type RenderResult struct {
	Body        string
	ContentType string
	Headers     http.Header
	Target      string
	NodeCount   int
}

// Renderer renders dual-track admin and user subscriptions from panel store state.
type Renderer struct {
	store subStore
	now   func() time.Time
}

// NewRenderer constructs a subscription Renderer backed by st.
func NewRenderer(st *store.Store, opts ...Option) *Renderer {
	r := &Renderer{
		now: time.Now,
	}
	if st != nil {
		r.store = st
	}
	for _, opt := range opts {
		if opt != nil {
			opt(r)
		}
	}
	return r
}
