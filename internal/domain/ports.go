package domain

import "time"

// Clock abstracts time so usecases stay deterministic in tests.
type Clock interface {
	Now() time.Time
}

// SystemClock is the production Clock.
type SystemClock struct{}

// Now returns the current UTC time.
func (SystemClock) Now() time.Time { return time.Now().UTC() }

// PasswordHasher hashes and verifies local-user passwords. The production
// implementation is argon2id with bcrypt and Django PBKDF2 accepted only
// as verification fallbacks (TECH_SPEC §1).
type PasswordHasher interface {
	Hash(password string) ([]byte, error)
	Verify(password string, hash []byte) bool
	// NeedsRehash reports whether hash uses a legacy format that should
	// be upgraded to the current one after a successful verification.
	NeedsRehash(hash []byte) bool
}

// Mailer sends transactional email (reset links, MFA notifications).
// Implemented in internal/adapter/mailer (M1).
type Mailer interface {
	Send(to, subject, textBody, htmlBody string) error
}
