package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// dummyBcryptHash is a valid pre-computed bcrypt hash (cost 10) used to equalize
// response timing when a login username does not exist or fails pre-checks.
var dummyBcryptHash = func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte("dummy-timing-equalizer"), bcrypt.DefaultCost)
	return h
}()

// HashPassword hashes password using bcrypt.DefaultCost.
func HashPassword(password string) (string, error) {
	return HashPasswordWithCost(password, bcrypt.DefaultCost)
}

// HashPasswordWithCost validates password constraints and hashes it with the given bcrypt cost.
func HashPasswordWithCost(password string, cost int) (string, error) {
	if password == "" {
		return "", ErrEmptyPassword
	}
	if len(password) > MaxBcryptPassword {
		return "", fmt.Errorf("%w: %w", ErrPasswordTooLong, bcrypt.ErrPasswordTooLong)
	}
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return "", fmt.Errorf("%w: %d", ErrInvalidCost, cost)
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("auth: bcrypt hash: %w", err)
	}
	return string(hashed), nil
}

// VerifyPassword compares a bcrypt hash against a plaintext password.
func VerifyPassword(hash, password string) error {
	if hash == "" || password == "" || len(password) > MaxBcryptPassword {
		return ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return ErrInvalidCredentials
	}
	return nil
}

// HashPassword hashes password using the service's configured bcrypt cost.
func (s *Service) HashPassword(password string) (string, error) {
	return HashPasswordWithCost(password, s.bcryptCost)
}

func (s *Service) verifyAdminCredentials(ctx context.Context, username, password string) (string, error) {
	storedUser, err := s.store.GetSetting(ctx, SettingAdminUsername)
	if err != nil {
		return "", fmt.Errorf("auth: load admin username: %w", err)
	}
	storedHash, err := s.store.GetSetting(ctx, SettingAdminPasswordHash)
	if err != nil {
		return "", fmt.Errorf("auth: load admin password hash: %w", err)
	}

	userMatch := subtle.ConstantTimeCompare([]byte(username), []byte(storedUser)) == 1
	if !userMatch || username == "" || password == "" || len(password) > MaxBcryptPassword {
		_ = bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte("dummy"))
		return "", ErrInvalidCredentials
	}
	if err := VerifyPassword(storedHash, password); err != nil {
		return "", ErrInvalidCredentials
	}
	return storedUser, nil
}

// Login validates admin credentials in constant/equalized time and issues an HS256 JWT.
func (s *Service) Login(ctx context.Context, username, password string) (string, error) {
	storedUser, err := s.verifyAdminCredentials(ctx, username, password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return "", ErrInvalidCredentials
		}
		return "", err
	}
	return s.IssueJWT(storedUser)
}

// ChangePassword verifies oldPassword and atomically replaces the stored admin bcrypt hash.
func (s *Service) ChangePassword(ctx context.Context, username, oldPassword, newPassword string) error {
	if _, err := s.verifyAdminCredentials(ctx, username, oldPassword); err != nil {
		return err
	}
	newHash, err := s.HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.store.SetSetting(ctx, SettingAdminPasswordHash, newHash); err != nil {
		return fmt.Errorf("auth: save new admin password hash: %w", err)
	}
	return nil
}
