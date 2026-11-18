package crypto

import (
	"strings"
	"sync"
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

// legacyHash was minted with the previous 64 MiB parameters for
// "legacy-password-1". Parameters ride in the PHC string, so it must
// keep verifying after the default dropped to 32 MiB.
const legacyHash = "$argon2id$v=19$m=65536,t=3,p=4$rwGKMlGy6V4Sho3DA/pGqg$uzbVTOygZLby/uRouOQy0c80+Hzr83VD5XYHyavU4rw"

func TestVerifyLegacyParams(t *testing.T) {
	h := Hasher{}
	if !h.Verify("legacy-password-1", []byte(legacyHash)) {
		t.Error("Verify(legacy 64MiB hash) = false, want true")
	}
	if h.Verify("wrong password here!!", []byte(legacyHash)) {
		t.Error("Verify(wrong, legacy hash) = true, want false")
	}
}

func TestHashUsesCurrentParams(t *testing.T) {
	h := Hasher{}
	sum, err := h.Hash("current-params-12")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if !strings.Contains(string(sum), "$m=32768,t=3,p=4$") {
		t.Errorf("Hash() = %q, want m=32768 params", sum)
	}
}

// TestVerifyConcurrent hammers Verify from many goroutines: results must
// stay correct and the semaphore must not deadlock (the test timeout
// fails a stuck run).
func TestVerifyConcurrent(t *testing.T) {
	h := Hasher{}
	sum, err := h.Hash("concurrent-password-1")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !h.Verify("concurrent-password-1", sum) {
				t.Error("Verify(correct) = false, want true")
			}
			if h.Verify("wrong password here!!", sum) {
				t.Error("Verify(wrong) = true, want false")
			}
		}()
	}
	wg.Wait()
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

// Django vectors generated with hashlib.pbkdf2_hmac (independent oracle).
func TestVerifyDjangoPbkdf2(t *testing.T) {
	h := Hasher{}
	const good = "pbkdf2_sha256$600000$abC123xYz$U8UcgwNMurBc0Om+4TdWpZM0mkaz4SdI6duV9Xhj0Ag="
	if !h.Verify("legacy-password-1", []byte(good)) {
		t.Error("Verify(django correct) = false, want true")
	}
	if h.Verify("nope-wrong-password", []byte(good)) {
		t.Error("Verify(django wrong) = true, want false")
	}
	badIters := []string{
		"pbkdf2_sha256$0$abC123xYz$U8UcgwNMurBc0Om+4TdWpZM0mkaz4SdI6duV9Xhj0Ag=",
		"pbkdf2_sha256$-1$abC123xYz$U8UcgwNMurBc0Om+4TdWpZM0mkaz4SdI6duV9Xhj0Ag=",
		"pbkdf2_sha256$600000x$abC123xYz$U8UcgwNMurBc0Om+4TdWpZM0mkaz4SdI6duV9Xhj0Ag=",
		"pbkdf2_sha256$99999999$abC123xYz$U8UcgwNMurBc0Om+4TdWpZM0mkaz4SdI6duV9Xhj0Ag=",
		"pbkdf2_sha256$600000$abC123xYz$!!!not-base64!!!",
		"pbkdf2_sha256$600000$abC123xYz",
		"pbkdf2_sha512$600000$abC123xYz$U8UcgwNMurBc0Om+4TdWpZM0mkaz4SdI6duV9Xhj0Ag=",
	}
	for _, bad := range badIters {
		if h.Verify("legacy-password-1", []byte(bad)) {
			t.Errorf("Verify(%q) = true, want false", bad)
		}
	}
}

func TestNeedsRehash(t *testing.T) {
	h := Hasher{}
	sum, err := h.Hash("fresh-password-1")
	if err != nil {
		t.Fatal(err)
	}
	if h.NeedsRehash(sum) {
		t.Error("NeedsRehash(argon2id) = true, want false")
	}
	for _, legacy := range []string{
		"$2a$04$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"pbkdf2_sha256$600000$abC123xYz$U8UcgwNMurBc0Om+4TdWpZM0mkaz4SdI6duV9Xhj0Ag=",
	} {
		if !h.NeedsRehash([]byte(legacy)) {
			t.Errorf("NeedsRehash(%q) = false, want true", legacy)
		}
	}
}
