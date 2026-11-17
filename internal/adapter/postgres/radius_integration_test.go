//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	adaptercrypto "github.com/identityhub/identityhub/internal/adapter/crypto"
	"github.com/identityhub/identityhub/internal/domain"
)

func testEncKey() [32]byte {
	var k [32]byte
	copy(k[:], "0123456789abcdef0123456789abcdef")
	return k
}

func TestRADIUSClientLifecycle(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	clients := NewRADIUSClientRepository(db)

	appID := uuid.New()
	if _, err := db.Pool.Exec(ctx, `INSERT INTO applications (id, slug, name, provider_type)
		VALUES ($1, $2, 'radius test app', 'radius')`, appID, "radius-test-"+uuid.NewString()[:8]); err != nil {
		t.Fatalf("seed application: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM applications WHERE id=$1`, appID)
	})
	sealed, err := adaptercrypto.Seal(testEncKey(), []byte("nas-secret-1"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	c, err := clients.Create(ctx, domain.RADIUSClient{
		ApplicationID: appID, NASIdentifier: "10.20.30.40", SharedSecretEnc: sealed,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM radius_clients WHERE id=$1`, c.ID)
	})

	got, err := clients.ByNASIdentifier(ctx, "10.20.30.40")
	if err != nil {
		t.Fatalf("ByNASIdentifier: %v", err)
	}
	if got.ID != c.ID || got.ApplicationID != c.ApplicationID {
		t.Errorf("got = %+v, want %+v", got, c)
	}
	plain, err := adaptercrypto.Open(testEncKey(), got.SharedSecretEnc)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(plain) != "nas-secret-1" {
		t.Errorf("secret round trip = %q", plain)
	}

	if _, err := clients.ByNASIdentifier(ctx, "10.99.99.99"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("ByNASIdentifier(missing) = %v, want ErrNotFound", err)
	}
	dupAppID := uuid.New()
	if _, err := db.Pool.Exec(ctx, `INSERT INTO applications (id, slug, name, provider_type)
		VALUES ($1, $2, 'radius dup app', 'radius')`, dupAppID, "radius-dup-"+uuid.NewString()[:8]); err != nil {
		t.Fatalf("seed dup application: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM applications WHERE id=$1`, dupAppID)
	})
	dup, err := clients.Create(ctx, domain.RADIUSClient{
		ApplicationID: dupAppID, NASIdentifier: "10.20.30.40", SharedSecretEnc: sealed,
	})
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate Create = %v (%+v), want ErrConflict", err, dup)
	}
	if _, err := clients.Create(ctx, domain.RADIUSClient{}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("empty Create = %v, want ErrValidation", err)
	}
}
