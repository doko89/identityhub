// Package storage implements domain.FileStorage backends (TECH_SPEC
// §6.7). v1 ships the local filesystem backend; the S3 backend arrives
// in M7 behind the same interface.
package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

// Local stores objects as files under dir. Keys are always built by the
// asset usecase as <type>/<uuid>.webp, but every method re-validates the
// key shape so a caller bug can never escape dir (no .., no absolute
// paths, no separators beyond the single type slash).
type Local struct {
	dir string
}

// NewLocal builds a filesystem backend rooted at dir, creating it when
// missing.
func NewLocal(dir string) (*Local, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("storage: dir is required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("storage: create dir: %w", err)
	}
	return &Local{dir: dir}, nil
}

// Put writes the object atomically (temp file + rename) so readers never
// see a half-written image.
func (l *Local) Put(_ context.Context, key string, body io.Reader, _ int64, _ string) error {
	rel, err := splitKey(key)
	if err != nil {
		return err
	}
	dir := filepath.Join(l.dir, rel.dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("storage: create dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		return fmt.Errorf("storage: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := io.Copy(tmp, body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("storage: write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("storage: close: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("storage: chmod: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(dir, rel.file)); err != nil {
		return fmt.Errorf("storage: commit: %w", err)
	}
	return nil
}

// Get opens the object for reading.
func (l *Local) Get(_ context.Context, key string) (io.ReadCloser, error) {
	rel, err := splitKey(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(l.dir, rel.dir, rel.file))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: object not found", errObjectNotFound)
		}
		return nil, fmt.Errorf("storage: open: %w", err)
	}
	return f, nil
}

// Delete removes the object. Missing objects are a no-op (cleanup paths
// must not fail on an already-gone file).
func (l *Local) Delete(_ context.Context, key string) error {
	rel, err := splitKey(key)
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(l.dir, rel.dir, rel.file)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("storage: delete: %w", err)
	}
	return nil
}

// errObjectNotFound marks a missing object without importing domain
// (adapters may import domain — this stays stdlib-only by choice so the
// backend is trivially reusable; callers map it with errors.Is).
var errObjectNotFound = errors.New("storage: object not found")

// IsNotFound reports whether err means the object does not exist.
func IsNotFound(err error) bool { return errors.Is(err, errObjectNotFound) }

type keyParts struct {
	dir  string
	file string
}

// splitKey validates the <type>/<uuid>.webp shape.
func splitKey(key string) (keyParts, error) {
	parts := strings.Split(key, "/")
	if len(parts) != 2 {
		return keyParts{}, fmt.Errorf("storage: invalid key %q", key)
	}
	typ, file := parts[0], parts[1]
	switch typ {
	case "avatar", "app_logo", "saas_logo":
	default:
		return keyParts{}, fmt.Errorf("storage: invalid key type %q", typ)
	}
	name, ok := strings.CutSuffix(file, ".webp")
	if !ok {
		return keyParts{}, fmt.Errorf("storage: invalid key %q (want <uuid>.webp)", key)
	}
	if _, err := uuid.Parse(name); err != nil {
		return keyParts{}, fmt.Errorf("storage: invalid key %q (bad uuid)", key)
	}
	return keyParts{dir: typ, file: file}, nil
}
