package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// S3Config wires one S3-compatible bucket (TECH_SPEC §6.7). Endpoint is
// host[:port] without a scheme (e.g. "s3.example.com" or,
// path-style dev setups, "localhost:9000"); UseSSL selects https.
type S3Config struct {
	Endpoint string
	Bucket   string
	Access   string
	Secret   string
	UseSSL   bool
}

// S3 stores objects in one bucket of an S3-compatible service via
// minio-go. Keys use the same <type>/<uuid>.webp shape as the local
// backend, validated before any network call.
type S3 struct {
	client *minio.Client
	bucket string
}

// NewS3 validates cfg and builds the client. It performs no network I/O;
// callers fail fast at boot with Ping.
func NewS3(cfg S3Config) (*S3, error) {
	cfg.Endpoint = strings.TrimSpace(cfg.Endpoint)
	cfg.Bucket = strings.TrimSpace(cfg.Bucket)
	cfg.Access = strings.TrimSpace(cfg.Access)
	if cfg.Endpoint == "" || cfg.Bucket == "" || cfg.Access == "" || cfg.Secret == "" {
		return nil, errors.New("storage: s3 endpoint, bucket, access key and secret key are all required")
	}
	if strings.Contains(cfg.Endpoint, "://") {
		return nil, fmt.Errorf("storage: s3 endpoint %q must be host[:port] without a scheme", cfg.Endpoint)
	}
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.Access, cfg.Secret, ""),
		Secure: cfg.UseSSL,
	})
	if err != nil {
		return nil, fmt.Errorf("storage: s3 client: %w", err)
	}
	return &S3{client: client, bucket: cfg.Bucket}, nil
}

// Ping verifies the bucket exists and the credentials work. main.go calls
// it at boot so a misconfigured STORAGE_S3_* fails fast with a clear
// error instead of failing the first upload.
func (s *S3) Ping(ctx context.Context) error {
	ok, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("storage: s3 bucket check: %w", err)
	}
	if !ok {
		return fmt.Errorf("storage: s3 bucket %q does not exist", s.bucket)
	}
	return nil
}

// Put uploads the object, replacing any previous version at key.
func (s *S3) Put(ctx context.Context, key string, body io.Reader, size int64, contentType string) error {
	if _, err := splitKey(key); err != nil {
		return err
	}
	if contentType == "" {
		contentType = "image/webp"
	}
	_, err := s.client.PutObject(ctx, s.bucket, key, body, size, minio.PutObjectOptions{
		ContentType: contentType,
	})
	if err != nil {
		return fmt.Errorf("storage: s3 put: %w", err)
	}
	return nil
}

// Get opens the object for reading. A missing key reports IsNotFound.
func (s *S3) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	if _, err := splitKey(key); err != nil {
		return nil, err
	}
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("storage: s3 get: %w", err)
	}
	if _, err := obj.Stat(); err != nil {
		_ = obj.Close()
		var resp minio.ErrorResponse
		if errors.As(err, &resp) && resp.Code == "NoSuchKey" {
			return nil, fmt.Errorf("%w: object not found", errObjectNotFound)
		}
		return nil, fmt.Errorf("storage: s3 stat: %w", err)
	}
	return obj, nil
}

// Delete removes the object. Like the local backend, a missing key is a
// no-op (S3 deletes are idempotent).
func (s *S3) Delete(ctx context.Context, key string) error {
	if _, err := splitKey(key); err != nil {
		return err
	}
	if err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("storage: s3 delete: %w", err)
	}
	return nil
}
