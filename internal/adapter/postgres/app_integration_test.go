//go:build integration

package postgres

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

// The admin apps list filters by dashboard group (?group=); the scan
// must also keep the tail columns (mfa_required, open_in_new_tab)
// aligned with appColumns.
func TestApplicationListFiltersByGroup(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	repo := NewApplicationRepository(db)
	tag := uuid.NewString()[:8]
	mk := func(slug, group string, mfa bool) domain.Application {
		a, err := repo.Create(ctx, domain.Application{
			Slug: slug + "-" + tag, Name: slug, ProviderType: domain.ProviderOIDC,
			LaunchURL: "https://" + slug + ".example.com", IsVisible: true,
			GroupLabel: group, MFARequired: mfa,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		return a
	}
	a := mk("it-wiki", "Tools-"+tag, true)
	b := mk("it-crm", "", false)
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(),
			`DELETE FROM applications WHERE id IN ($1,$2)`, a.ID, b.ID)
	})
	if a.GroupLabel != "Tools-"+tag || !a.MFARequired || a.OpenInNewTab {
		t.Fatalf("create scan misaligned: %+v", a)
	}

	got, total, err := repo.List(ctx, domain.AppFilter{Group: "tools-" + tag, Limit: 10})
	if err != nil || total != 1 || len(got) != 1 || got[0].ID != a.ID {
		t.Fatalf("filtered list = %+v total=%d err=%v, want wiki only", got, total, err)
	}
	all, total, err := repo.List(ctx, domain.AppFilter{Limit: 200})
	if err != nil || total < 2 || len(all) < 2 {
		t.Fatalf("unfiltered list total=%d len=%d err=%v, want both rows", total, len(all), err)
	}
}
