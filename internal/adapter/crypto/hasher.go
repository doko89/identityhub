// Package crypto implements domain.PasswordHasher with argon2id.
//
// Hash format (PHC string): $argon2id$v=19$m=<mem>,t=<iter>,p=<lanes>$<salt>$<hash>
// bcrypt hashes ($2a$/2b$/2y$ prefixes) are accepted by Verify only as a
// migration fallback and are never produced here (TECH_SPEC §1).
package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Parameters follow OWASP's argon2id guidance for interactive logins.
const (
	memoryKB   = 64 * 1024
	iterations = 3
	lanes      = 4
	keyLen     = 32
	saltLen    = 16
)

// Hasher is the production domain.PasswordHasher. Zero value is ready.
type Hasher struct{}

// Hash derives an argon2id hash for password.
func (Hasher) Hash(password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("password must not be empty")
	}
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
// compared in constant time; bcrypt hashes fall back to bcrypt comparison.
func (Hasher) Verify(password string, hash []byte) bool {
	s := string(hash)
	switch {
	case strings.HasPrefix(s, "$argon2id$"):
		return verifyArgon2(password, s)
	case strings.HasPrefix(s, "$2a$") || strings.HasPrefix(s, "$2b$") || strings.HasPrefix(s, "$2y$"):
		return bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
	default:
		return false
	}
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
