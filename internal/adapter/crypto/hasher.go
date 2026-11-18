// Package crypto implements domain.PasswordHasher with argon2id.
//
// Hash format (PHC string): $argon2id$v=19$m=<mem>,t=<iter>,p=<lanes>$<salt>$<hash>
// bcrypt hashes ($2a$/2b$/2y$ prefixes) and Django PBKDF2 hashes
// (pbkdf2_sha256$iter$salt$hash) are accepted by Verify only as
// migration fallbacks and are never produced here (TECH_SPEC §1).
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

// Parameters balance OWASP's argon2id guidance against bind-storm
// memory: 32 MiB per computation (above the OWASP minimum) keeps a
// burst of legacy binds affordable. Parameters ride in the PHC string,
// so hashes minted with older values keep verifying.
const (
	memoryKB   = 32 * 1024
	iterations = 3
	lanes      = 4
	keyLen     = 32
	saltLen    = 16
)

// maxConcurrentArgon2 bounds simultaneous argon2id computations
// process-wide. Each holds memoryKB while running, so an unbounded
// burst of binds would multiply it into gigabytes (measured: 32
// parallel verifies touched 2 GB at 64 MiB). Four slots cap the worst
// case at 4 × 32 MiB = 128 MiB; excess verifications queue for tens
// of milliseconds each.
const maxConcurrentArgon2 = 4

// argon2Sem is the process-wide computation budget. It must stay
// package-level (not per-Hasher): several services hold their own
// Hasher, and only a shared semaphore bounds their sum.
var argon2Sem = make(chan struct{}, maxConcurrentArgon2)

// acquireArgon2 takes one computation slot; callers defer the release.
// Hash and Verify never nest, so this cannot deadlock.
func acquireArgon2() func() {
	argon2Sem <- struct{}{}
	return func() { <-argon2Sem }
}

// Hasher is the production domain.PasswordHasher. Zero value is ready.
type Hasher struct{}

// Hash derives an argon2id hash for password.
func (Hasher) Hash(password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("password must not be empty")
	}
	defer acquireArgon2()()
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("argon2 salt: %w", err)
	}
	sum := argon2.IDKey([]byte(password), salt, iterations, memoryKB, lanes, keyLen)
	out := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memoryKB, iterations, lanes,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum))
	return []byte(out), nil
}

// Verify checks password against hash. argon2id hashes produced by Hash are
// compared in constant time; bcrypt and Django PBKDF2 hashes fall back to
// their own comparison (kilobytes of memory, so the fallbacks bypass the
// argon2 budget).
func (Hasher) Verify(password string, hash []byte) bool {
	s := string(hash)
	switch {
	case strings.HasPrefix(s, "$argon2id$"):
		defer acquireArgon2()()
		return verifyArgon2(password, s)
	case strings.HasPrefix(s, "$2a$") || strings.HasPrefix(s, "$2b$") || strings.HasPrefix(s, "$2y$"):
		return bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
	case strings.HasPrefix(s, "pbkdf2_sha256$"):
		return verifyPbkdf2SHA256(password, s)
	default:
		return false
	}
}

// NeedsRehash reports whether hash predates argon2id and should be
// upgraded after a successful verification.
func (Hasher) NeedsRehash(hash []byte) bool {
	return !strings.HasPrefix(string(hash), "$argon2id$")
}

// maxPBKDF2Iterations bounds Django-format verification work. Django's
// own defaults stay far below this; larger counts are rejected as
// abusive rather than computed.
const maxPBKDF2Iterations = 2000000

// verifyPbkdf2SHA256 checks Django's pbkdf2_sha256$iter$salt$hash
// encoding: raw salt string, base64 derived key, compared in
// constant time.
func verifyPbkdf2SHA256(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter <= 0 || iter > maxPBKDF2Iterations {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(want) == 0 {
		return false
	}
	got := pbkdf2.Key([]byte(password), []byte(parts[2]), iter, len(want), sha256.New)
	return subtle.ConstantTimeCompare(got, want) == 1
}

func verifyArgon2(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var mem uint32
	var iter uint32
	var thread uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iter, &thread); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, iter, mem, thread, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
