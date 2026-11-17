package crypto

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashVerifyRoundTrip(t *testing.T) {
	h := Hasher{}
	sum, err := h.Hash("correct horse battery staple 12+")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if !strings.HasPrefix(string(sum), "$argon2id$") {
		t.Fatalf("Hash() = %q, want $argon2id$ prefix", sum)
	}
	if !h.Verify("correct horse battery staple 12+", sum) {
		t.Error("Verify(correct) = false, want true")
	}
	if h.Verify("wrong password here!!", sum) {
		t.Error("Verify(wrong) = true, want false")
	}
}

func TestHashIsSalted(t *testing.T) {
	h := Hasher{}
	a, _ := h.Hash("same-password-12")
	b, _ := h.Hash("same-password-12")
	if string(a) == string(b) {
		t.Error("two hashes of the same password are identical, want distinct salts")
	}
}

func TestHashEmptyRejected(t *testing.T) {
	if _, err := (Hasher{}).Hash(""); err == nil {
		t.Error("Hash(\"\") = nil error, want failure")
	}
}

func TestVerifyBcryptFallback(t *testing.T) {
	h := Hasher{}
	sum, err := bcrypt.GenerateFromPassword([]byte("legacy-password-1"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt setup: %v", err)
	}
	if !h.Verify("legacy-password-1", sum) {
		t.Error("Verify(bcrypt correct) = false, want true")
	}
	if h.Verify("nope-wrong-password", sum) {
		t.Error("Verify(bcrypt wrong) = true, want false")
	}
}

func TestVerifyMalformed(t *testing.T) {
	h := Hasher{}
	for _, bad := range []string{"", "not-a-hash", "$argon2id$v=19$broken", "$argon2id$v=1$m=1,t=1,p=1$AA$BB"} {
		if h.Verify("whatever-password", []byte(bad)) {
			t.Errorf("Verify(%q) = true, want false", bad)
		}
	}
}
