package storage

import (
	"context"
	"strings"
	"testing"
)

func testS3Config() S3Config {
	return S3Config{
		Endpoint: "localhost:9000", Bucket: "identityhub-test",
		Access: "ak", Secret: "sk", UseSSL: false,
	}
}

func TestNewS3RequiresFields(t *testing.T) {
	full := testS3Config()
	cases := []struct {
		name   string
		mutate func(*S3Config)
	}{
		{"empty endpoint", func(c *S3Config) { c.Endpoint = " " }},
		{"empty bucket", func(c *S3Config) { c.Bucket = "" }},
		{"empty access", func(c *S3Config) { c.Access = "" }},
		{"empty secret", func(c *S3Config) { c.Secret = "" }},
		{"endpoint with scheme", func(c *S3Config) { c.Endpoint = "https://s3.example.com" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := full
			tc.mutate(&cfg)
			if _, err := NewS3(cfg); err == nil {
				t.Fatalf("NewS3(%s) must fail", tc.name)
			}
		})
	}
}

func TestNewS3BuildsWithoutNetwork(t *testing.T) {
	// Construction performs no I/O: an unreachable endpoint still
	// builds (boot fail-fast happens in Ping, covered live in the
	// integration suite).
	if _, err := NewS3(testS3Config()); err != nil {
		t.Fatalf("NewS3: %v", err)
	}
}

// TestS3RejectsBadKeysWithoutNetwork verifies the key shape gate runs
// before any S3 call: these must fail without touching the client.
func TestS3RejectsBadKeysWithoutNetwork(t *testing.T) {
	s3, err := NewS3(testS3Config())
	if err != nil {
		t.Fatalf("NewS3: %v", err)
	}
	ctx := context.Background()
	bad := []string{"", "avatar", "../x.webp", "avatar/not-a-uuid.webp", "avatar/x.png", "evil/<uuid>.webp"}
	for _, key := range bad {
		if err := s3.Put(ctx, key, strings.NewReader("x"), 1, "image/webp"); err == nil {
			t.Fatalf("Put(%q) must fail key validation", key)
		}
		if _, err := s3.Get(ctx, key); err == nil {
			t.Fatalf("Get(%q) must fail key validation", key)
		}
		if err := s3.Delete(ctx, key); err == nil {
			t.Fatalf("Delete(%q) must fail key validation", key)
		}
	}
}
