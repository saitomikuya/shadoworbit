package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	NodeTokenPrefix   = "nd_live_"
	DefaultJWTIssuer  = "snell-panel"
	DefaultJWTTTL     = 24 * time.Hour
	MaxBcryptPassword = 72 // bcrypt hard input limit
	DefaultAdminSubject = "admin"

	SettingAdminPasswordHash = "admin_password_hash"
	SettingJWTSecret         = "jwt_secret"
)

var (
	ErrEmptyPassword      = errors.New("auth: password cannot be empty")
	ErrPasswordTooLong    = errors.New("auth: password exceeds 72 bytes")
	ErrInvalidCost        = errors.New("auth: invalid bcrypt cost")
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
	ErrInvalidToken       = errors.New("auth: invalid token")
	ErrExpiredToken       = errors.New("auth: token expired")
	ErrInvalidBearer      = errors.New("auth: invalid authorization bearer header")
)

// SettingsStore defines the narrow persistence contract required by auth.Service.
// *store.Store satisfies this interface directly.
type SettingsStore interface {
	GetSetting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
	SetSettingIfAbsent(ctx context.Context, key, value string) (actual string, created bool, err error)
}

// Config configures auth.Service behavior.
type Config struct {
	BcryptCost int              // 0 -> bcrypt.DefaultCost (10)
	TokenTTL   time.Duration    // 0 -> DefaultJWTTTL (24h)
	Issuer     string           // "" -> DefaultJWTIssuer ("snell-panel")
	Now        func() time.Time // nil -> time.Now
}

// Service provides admin authentication, JWT issuance/verification, and password updates.
type Service struct {
	store      SettingsStore
	bcryptCost int
	tokenTTL   time.Duration
	issuer     string
	now        func() time.Time

	secretMu  sync.RWMutex
	jwtSecret []byte
}

// NewService constructs a Service and ensures a persistent HS256 JWT secret exists.
func NewService(ctx context.Context, store SettingsStore, cfg Config) (*Service, error) {
	if store == nil {
		return nil, errors.New("auth: nil SettingsStore")
	}

	cost := cfg.BcryptCost
	if cost == 0 {
		cost = bcrypt.DefaultCost
	} else if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return nil, fmt.Errorf("%w: %d", ErrInvalidCost, cfg.BcryptCost)
	}

	ttl := cfg.TokenTTL
	if ttl <= 0 {
		ttl = DefaultJWTTTL
	}

	issuer := cfg.Issuer
	if issuer == "" {
		issuer = DefaultJWTIssuer
	}

	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	svc := &Service{
		store:      store,
		bcryptCost: cost,
		tokenTTL:   ttl,
		issuer:     issuer,
		now:        nowFn,
	}

	if _, err := svc.EnsureJWTSecret(ctx); err != nil {
		return nil, err
	}

	return svc, nil
}
