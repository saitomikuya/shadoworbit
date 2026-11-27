package auth

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// dummyBcryptHash is a valid pre-computed bcrypt hash (cost 10) used to equalize
// response timing when password pre-checks fail.
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

func (s *Service) verifyAdminPassword(ctx context.Context, password string) error {
	storedHash, err := s.store.GetSetting(ctx, SettingAdminPasswordHash)
	if err != nil {
		return fmt.Errorf("auth: load admin password hash: %w", err)
	}

	if password == "" || len(password) > MaxBcryptPassword {
		_ = bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte("dummy"))
		return ErrInvalidCredentials
	}
	if err := VerifyPassword(storedHash, password); err != nil {
		return ErrInvalidCredentials
	}
	return nil
}

// Login validates admin password in constant/equalized time and issues an HS256 JWT.
func (s *Service) Login(ctx context.Context, password string) (string, error) {
	if err := s.verifyAdminPassword(ctx, password); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return "", ErrInvalidCredentials
		}
		return "", err
	}
	return s.IssueJWT(DefaultAdminSubject)
}

// ChangePassword verifies oldPassword and atomically replaces the stored admin bcrypt hash.
func (s *Service) ChangePassword(ctx context.Context, oldPassword, newPassword string) error {
	if err := s.verifyAdminPassword(ctx, oldPassword); err != nil {
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
