package storage

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalRoundTrip(t *testing.T) {
	l, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key := "avatar/123e4567-e89b-12d3-a456-426614174000.webp"
	body := bytes.Repeat([]byte("webp-bytes"), 100)
	if err := l.Put(ctx, key, bytes.NewReader(body), int64(len(body)), "image/webp"); err != nil {
		t.Fatal(err)
	}
	rc, err := l.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("stored bytes must round-trip")
	}
	if err := l.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Get(ctx, key); !IsNotFound(err) {
		t.Fatalf("deleted object must be not-found, got %v", err)
	}
	// Delete is idempotent.
	if err := l.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
}

func TestLocalAcceptsAllAssetTypes(t *testing.T) {
	l, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, typ := range []string{"avatar", "app_logo", "saas_logo", "login_background"} {
		key := typ + "/123e4567-e89b-12d3-a456-426614174000.webp"
		if err := l.Put(ctx, key, strings.NewReader("x"), 1, "image/webp"); err != nil {
			t.Fatalf("Put(%q) must succeed: %v", key, err)
		}
		if err := l.Delete(ctx, key); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLocalRejectsBadKeys(t *testing.T) {
	root := t.TempDir()
	l, err := NewLocal(root)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, key := range []string{
		"", "../evil.webp", "/abs/path.webp", "avatar/../../etc/passwd",
		"avatar/x.png", "avatar/not-a-uuid.webp", "evil/type/x.webp",
		"a/b/c.webp", `avatar\evil.webp`,
	} {
		if err := l.Put(ctx, key, strings.NewReader("x"), 1, "image/webp"); err == nil {
			t.Fatalf("Put(%q) must fail", key)
		}
		if _, err := l.Get(ctx, key); err == nil {
			t.Fatalf("Get(%q) must fail", key)
		}
		if err := l.Delete(ctx, key); err == nil {
			t.Fatalf("Delete(%q) must fail", key)
		}
	}
	// Nothing escaped the root: no files anywhere under it.
	var files []string
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	if len(files) != 0 {
		t.Fatalf("rejected keys must write nothing, got %v", files)
	}
}

func TestNewLocalRequiresDir(t *testing.T) {
	if _, err := NewLocal(""); err == nil {
		t.Fatal("empty dir must fail")
	}
	if _, err := NewLocal("  "); err == nil {
		t.Fatal("blank dir must fail")
	}
}
