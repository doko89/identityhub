package asset

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

// ---------- fakes ----------

type fakeAssets struct {
	byID      map[uuid.UUID]domain.Asset
	createErr error
}

func (f *fakeAssets) Create(_ context.Context, a domain.Asset) (domain.Asset, error) {
	if f.createErr != nil {
		return domain.Asset{}, f.createErr
	}
	f.byID[a.ID] = a
	return a, nil
}
func (f *fakeAssets) ByID(_ context.Context, id uuid.UUID) (domain.Asset, error) {
	a, ok := f.byID[id]
	if !ok {
		return domain.Asset{}, domain.ErrNotFound
	}
	return a, nil
}
func (f *fakeAssets) Delete(_ context.Context, id uuid.UUID) error {
	delete(f.byID, id)
	return nil
}

type fakeStorage struct {
	objects map[string][]byte
	putErr  error
	deleted []string
}

func (f *fakeStorage) Put(_ context.Context, key string, body io.Reader, _ int64, _ string) error {
	if f.putErr != nil {
		return f.putErr
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	f.objects[key] = raw
	return nil
}
func (f *fakeStorage) Get(_ context.Context, key string) (io.ReadCloser, error) {
	raw, ok := f.objects[key]
	if !ok {
		return nil, errors.New("missing")
	}
	return io.NopCloser(bytes.NewReader(raw)), nil
}
func (f *fakeStorage) Delete(_ context.Context, key string) error {
	f.deleted = append(f.deleted, key)
	delete(f.objects, key)
	return nil
}

func testPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.Set(x, y, color.RGBA{uint8(x), uint8(y), 128, 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func testJPEG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 32, 32))
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// ---------- tests ----------

func TestNewRequiresDeps(t *testing.T) {
	if _, err := New(Deps{}); err == nil {
		t.Fatal("empty deps must fail")
	}
}

func TestUploadPNG(t *testing.T) {
	assets := &fakeAssets{byID: map[uuid.UUID]domain.Asset{}}
	storage := &fakeStorage{objects: map[string][]byte{}}
	svc, err := New(Deps{Assets: assets, Storage: storage})
	if err != nil {
		t.Fatal(err)
	}
	actor := uuid.New()
	a, err := svc.Upload(context.Background(), &actor, domain.AssetAvatar, bytes.NewReader(testPNG(t, 64, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if a.Width != 64 || a.Height != 32 {
		t.Fatalf("dims must pass through, got %dx%d", a.Width, a.Height)
	}
	if a.ObjectKey != domain.AssetAvatar+"/"+a.ID.String()+".webp" {
		t.Fatalf("bad object key %q", a.ObjectKey)
	}
	if a.UploadedBy == nil || *a.UploadedBy != actor {
		t.Fatal("uploader must be recorded")
	}
	stored := storage.objects[a.ObjectKey]
	if len(stored) == 0 || string(stored[:4]) != "RIFF" || string(stored[8:12]) != "WEBP" {
		t.Fatal("stored bytes must be a webp container")
	}
	if a.ByteSize != len(stored) {
		t.Fatal("byte size must match the stored object")
	}
	if got := a.PublicPath(); got != "/uploads/avatar/"+a.ID.String()+".webp" {
		t.Fatalf("bad public path %q", got)
	}
}

func TestUploadJPEGAndDownscale(t *testing.T) {
	assets := &fakeAssets{byID: map[uuid.UUID]domain.Asset{}}
	storage := &fakeStorage{objects: map[string][]byte{}}
	svc, _ := New(Deps{Assets: assets, Storage: storage})
	if _, err := svc.Upload(context.Background(), nil, domain.AssetAppLogo, bytes.NewReader(testJPEG(t))); err != nil {
		t.Fatalf("jpeg must be accepted: %v", err)
	}
	a, err := svc.Upload(context.Background(), nil, domain.AssetSaaSLogo, bytes.NewReader(testPNG(t, 1024, 512)))
	if err != nil {
		t.Fatal(err)
	}
	if a.Width != 512 || a.Height != 256 {
		t.Fatalf("long edge must shrink to 512, got %dx%d", a.Width, a.Height)
	}
}

func TestUploadRejects(t *testing.T) {
	assets := &fakeAssets{byID: map[uuid.UUID]domain.Asset{}}
	storage := &fakeStorage{objects: map[string][]byte{}}
	svc, _ := New(Deps{Assets: assets, Storage: storage})
	ctx := context.Background()
	if _, err := svc.Upload(ctx, nil, "banner", bytes.NewReader(testPNG(t, 8, 8))); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("bad type must fail validation, got %v", err)
	}
	if _, err := svc.Upload(ctx, nil, domain.AssetAvatar, strings.NewReader("not an image")); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("non-image must fail validation, got %v", err)
	}
	if _, err := svc.Upload(ctx, nil, domain.AssetAvatar, bytes.NewReader(nil)); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("empty upload must fail validation, got %v", err)
	}
	if MaxUploadBytes != 10<<20 {
		t.Fatalf("MaxUploadBytes = %d, want 10 MB", MaxUploadBytes)
	}
	big := bytes.NewReader(make([]byte, MaxUploadBytes+1))
	if _, err := svc.Upload(ctx, nil, domain.AssetAvatar, big); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("oversize upload must fail validation, got %v", err)
	}
}

func TestUploadFailuresCleanUp(t *testing.T) {
	ctx := context.Background()
	storage := &fakeStorage{objects: map[string][]byte{}, putErr: errors.New("disk full")}
	svc, _ := New(Deps{Assets: &fakeAssets{byID: map[uuid.UUID]domain.Asset{}}, Storage: storage})
	if _, err := svc.Upload(ctx, nil, domain.AssetAvatar, bytes.NewReader(testPNG(t, 8, 8))); err == nil {
		t.Fatal("storage failure must fail the upload")
	}
	storage2 := &fakeStorage{objects: map[string][]byte{}}
	assets2 := &fakeAssets{byID: map[uuid.UUID]domain.Asset{}, createErr: errors.New("db down")}
	svc2, _ := New(Deps{Assets: assets2, Storage: storage2})
	if _, err := svc2.Upload(ctx, nil, domain.AssetAvatar, bytes.NewReader(testPNG(t, 8, 8))); err == nil {
		t.Fatal("metadata failure must fail the upload")
	}
	if len(storage2.deleted) != 1 || len(storage2.objects) != 0 {
		t.Fatal("orphaned object must be deleted on metadata failure")
	}
}
