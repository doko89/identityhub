package crypto

import (
	"bytes"
	"testing"
	"time"
)

func TestTOTPVerifyCurrentAndPrevious(t *testing.T) {
	var totp TOTP
	seed, url, err := totp.NewSeed("IdentityHub", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if url == "" || len(seed) == 0 {
		t.Fatal("seed and otpauth URL must be non-empty")
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	step := now.Unix() / 30
	cur, err := totp.Code(seed, step)
	if err != nil {
		t.Fatal(err)
	}
	prev, err := totp.Code(seed, step-1)
	if err != nil {
		t.Fatal(err)
	}
	next, err := totp.Code(seed, step+1)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := totp.Verify(seed, cur, now); !ok || got != step {
		t.Fatalf("current step must verify, got step=%d ok=%v", got, ok)
	}
	if got, ok := totp.Verify(seed, prev, now); !ok || got != step-1 {
		t.Fatalf("previous step must verify, got step=%d ok=%v", got, ok)
	}
	if _, ok := totp.Verify(seed, next, now); ok {
		t.Fatal("future step must NOT verify (narrow window)")
	}
	if _, ok := totp.Verify(seed, "000000", now); ok {
		t.Fatal("wrong code must not verify")
	}
	if _, ok := totp.Verify(seed, "12", now); ok {
		t.Fatal("short code must not verify")
	}
	if _, ok := totp.Verify(seed, "abcdef", now); ok {
		t.Fatal("non-digit code must not verify")
	}
	if _, err := totp.Code(seed, -1); err == nil {
		t.Fatal("negative step must fail")
	}
}

func TestTOTPQRCodePNG(t *testing.T) {
	var totp TOTP
	png, err := totp.QRCodePNG("otpauth://totp/x?secret=ABC", 128)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(png, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatal("output must be a PNG image")
	}
	if _, err := totp.QRCodePNG("", 128); err == nil {
		t.Fatal("empty content must fail")
	}
}

func TestSealerRoundTrip(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	s := Sealer{Key: key}
	sealed, err := s.Seal([]byte("seed-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := s.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "seed-bytes" {
		t.Fatalf("round trip mismatch: %q", plain)
	}
	if _, err := s.Open([]byte("short")); err == nil {
		t.Fatal("tampered payload must fail")
	}
}
