//go:build integration

// S3 backend round-trip against a real S3-compatible server (TECH_SPEC
// §9: protocols against real implementations, not mocks).
//
//	docker run -d --name ih-minio -p 9000:9000 \
//	  -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin123 \
//	  minio/minio server /data
//	TEST_S3_ENDPOINT=localhost:9000 go test -tags=integration ./internal/adapter/storage/ -run TestS3Live
package storage

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func TestS3LiveRoundTrip(t *testing.T) {
	endpoint := os.Getenv("TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("TEST_S3_ENDPOINT not set, skipping live S3 test")
	}
	access := os.Getenv("TEST_S3_ACCESS")
	if access == "" {
		access = "minioadmin"
	}
	secret := os.Getenv("TEST_S3_SECRET")
	if secret == "" {
		secret = "minioadmin123"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const bucket = "identityhub-test"
	admin, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(access, secret, ""),
		Secure: false,
	})
	if err != nil {
		t.Fatalf("admin client: %v", err)
	}
	if err := admin.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
		if resp, ok := err.(minio.ErrorResponse); !ok || resp.Code != "BucketAlreadyOwnedByYou" {
			t.Fatalf("MakeBucket: %v", err)
		}
	}

	s3, err := NewS3(S3Config{
		Endpoint: endpoint, Bucket: bucket,
		Access: access, Secret: secret, UseSSL: false,
	})
	if err != nil {
		t.Fatalf("NewS3: %v", err)
	}
	if err := s3.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	key := "avatar/" + uuid.NewString() + ".webp"
	body := []byte("fake-webp-bytes")
	if err := s3.Put(ctx, key, bytes.NewReader(body), int64(len(body)), "image/webp"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s3.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	raw, err := io.ReadAll(got)
	_ = got.Close()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(raw, body) {
		t.Fatalf("round trip mismatch: got %q", raw)
	}
	if err := s3.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s3.Get(ctx, key); !IsNotFound(err) {
		t.Fatalf("Get after delete err = %v, want IsNotFound", err)
	}
	// Missing-key delete is a no-op.
	if err := s3.Delete(ctx, key); err != nil {
		t.Fatalf("Delete missing: %v", err)
	}

	missing, err := NewS3(S3Config{
		Endpoint: endpoint, Bucket: "no-such-bucket-here",
		Access: access, Secret: secret, UseSSL: false,
	})
	if err != nil {
		t.Fatalf("NewS3: %v", err)
	}
	if err := missing.Ping(ctx); err == nil {
		t.Fatal("Ping on a missing bucket must fail (boot fail-fast)")
	}
}
