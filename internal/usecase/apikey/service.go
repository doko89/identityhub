// Package apikey manages personal API keys: the owner creates them under
// /account and the identityhub CLI presents them as Bearer tokens. A key
// inherits its owner's permissions; only the SHA-256 hash of the secret
// is stored, the secret itself is shown once at creation.
package apikey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
	"github.com/identityhub/identityhub/internal/usecase/audit"
)

const (
	// SecretPrefix marks IdentityHub secrets (ih_ + 43 base64url chars
	// encoding 32 random bytes, 46 chars total).
	SecretPrefix = "ih_"
	secretBytes  = 32
	secretLength = 46
	// prefixChars is how much of the secret is kept in cleartext for
	// identification (shown in the account UI and the CLI).
	prefixChars = 12
	// MaxNameLength caps the owner-given key label.
	MaxNameLength = 100
	// MaxKeysPerUser caps active keys per owner (revoked and expired
	// keys do not count).
	MaxKeysPerUser = 20
	// MaxExpiryDays caps an optional key TTL; a nil expiry never expires.
	MaxExpiryDays = 365
)

// Service mints, lists, revokes and verifies personal API keys.
type Service struct {
	keys  domain.APIKeyStore
	audit *audit.Service
	clock domain.Clock
}

// Deps wires a Service. Keys and Audit are required; Clock defaults to
// the system clock.
type Deps struct {
	Keys  domain.APIKeyStore
	Audit *audit.Service
	Clock domain.Clock
}

// New validates Deps and builds a Service.
func New(d Deps) (*Service, error) {
	if d.Keys == nil || d.Audit == nil {
		return nil, errors.New("apikey: Keys and Audit are required")
	}
	if d.Clock == nil {
		d.Clock = domain.SystemClock{}
	}
	return &Service{keys: d.Keys, audit: d.Audit, clock: d.Clock}, nil
}

// Create mints one key for userID and returns it with the plaintext
// secret (shown once; only the hash is stored). expiresAt is nil for no
// expiry. createdWithMFA records that the issuing session passed a
// second factor, which is what satisfies the admin MFA gate for Bearer
// requests; the HTTP layer enforces that admins only create keys from
// MFA-verified sessions.
func (s *Service) Create(ctx context.Context, userID uuid.UUID, name string, expiresAt *time.Time, createdWithMFA bool) (domain.APIKey, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return domain.APIKey{}, "", fmt.Errorf("%w: name is required", domain.ErrValidation)
	}
	if len(name) > MaxNameLength {
		return domain.APIKey{}, "", fmt.Errorf("%w: name must be at most %d characters", domain.ErrValidation, MaxNameLength)
	}
	now := s.clock.Now()
	if expiresAt != nil {
		if !now.Before(*expiresAt) {
			return domain.APIKey{}, "", fmt.Errorf("%w: expiry must be in the future", domain.ErrValidation)
		}
		if expiresAt.After(now.AddDate(0, 0, MaxExpiryDays)) {
			return domain.APIKey{}, "", fmt.Errorf("%w: expiry must be within %d days", domain.ErrValidation, MaxExpiryDays)
		}
	}
	existing, err := s.keys.ListByUser(ctx, userID)
	if err != nil {
		return domain.APIKey{}, "", fmt.Errorf("apikey: list keys: %w", err)
	}
	active := 0
	for _, k := range existing {
		if k.Active(now) {
			active++
		}
	}
	if active >= MaxKeysPerUser {
		return domain.APIKey{}, "", fmt.Errorf("%w: too many active keys (max %d)", domain.ErrValidation, MaxKeysPerUser)
	}
	raw := make([]byte, secretBytes)
	if _, err := rand.Read(raw); err != nil {
		return domain.APIKey{}, "", fmt.Errorf("apikey: random secret: %w", err)
	}
	secret := SecretPrefix + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(secret))
	created, err := s.keys.Create(ctx, domain.APIKey{
		UserID: userID, Name: name, Prefix: secret[:prefixChars], KeyHash: sum[:],
		CreatedWithMFA: createdWithMFA, ExpiresAt: expiresAt,
	})
	if err != nil {
		return domain.APIKey{}, "", fmt.Errorf("apikey: store key: %w", err)
	}
	// Best-effort like the other non-login audits: failing here must not
	// orphan a key whose secret was already issued.
	_ = s.audit.Record(ctx, domain.AuditEntry{
		ActorUserID: &userID, Method: domain.MethodAPIKey, Result: domain.ResultSuccess,
		Detail: map[string]any{"action": audit.ActionAPIKeyCreate, "key_id": created.ID.String(), "name": name},
	})
	return created, secret, nil
}

// List returns the owner's keys, newest first (revoked ones included).
func (s *Service) List(ctx context.Context, userID uuid.UUID) ([]domain.APIKey, error) {
	keys, err := s.keys.ListByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("apikey: list keys: %w", err)
	}
	return keys, nil
}

// Revoke soft-revokes one of the owner's keys. Unknown ids and other
// owners' ids both answer ErrNotFound.
func (s *Service) Revoke(ctx context.Context, userID, id uuid.UUID) error {
	if err := s.keys.Revoke(ctx, userID, id, s.clock.Now()); err != nil {
		return fmt.Errorf("apikey: revoke: %w", err)
	}
	_ = s.audit.Record(ctx, domain.AuditEntry{
		ActorUserID: &userID, Method: domain.MethodAPIKey, Result: domain.ResultSuccess,
		Detail: map[string]any{"action": audit.ActionAPIKeyRevoke, "key_id": id.String()},
	})
	return nil
}

// Authenticate resolves a presented secret to its key. Unknown,
// malformed, revoked and expired secrets all answer ErrUnauthorized so
// key state is never leaked. Last use is recorded best-effort: a stats
// write must never fail authentication.
func (s *Service) Authenticate(ctx context.Context, secret string) (domain.APIKey, error) {
	if !validSecretFormat(secret) {
		return domain.APIKey{}, domain.ErrUnauthorized
	}
	sum := sha256.Sum256([]byte(secret))
	k, err := s.keys.ByHash(ctx, sum[:])
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.APIKey{}, domain.ErrUnauthorized
		}
		return domain.APIKey{}, fmt.Errorf("apikey: lookup: %w", err)
	}
	now := s.clock.Now()
	if !k.Active(now) {
		return domain.APIKey{}, domain.ErrUnauthorized
	}
	_ = s.keys.TouchLastUsed(ctx, k.ID, now)
	return k, nil
}

// validSecretFormat accepts only the issued shape (ih_ + 43 base64url
// chars) so junk Bearer tokens skip the database lookup.
func validSecretFormat(secret string) bool {
	if len(secret) != secretLength || !strings.HasPrefix(secret, SecretPrefix) {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(secret[len(SecretPrefix):])
	return err == nil
}
