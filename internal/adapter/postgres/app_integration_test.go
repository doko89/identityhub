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

// The admin apps search (?q=) matches slug, name and description, and
// combines with the group filter.
func TestApplicationListFiltersByQuery(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	repo := NewApplicationRepository(db)
	tag := uuid.NewString()[:8]
	mk := func(slug, name, desc, group string) domain.Application {
		a, err := repo.Create(ctx, domain.Application{
			Slug: slug + "-" + tag, Name: name, Description: desc,
			ProviderType: domain.ProviderOIDC, IsVisible: true, GroupLabel: group,
		})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		return a
	}
	a := mk("it-grimoire", "Grimoire-"+tag, "team spellbook "+tag, "Docs-"+tag)
	b := mk("it-ledger", "Ledger-"+tag, "team accounting "+tag, "Docs-"+tag)
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(),
			`DELETE FROM applications WHERE id IN ($1,$2)`, a.ID, b.ID)
	})

	for _, tc := range []struct {
		name string
		f    domain.AppFilter
		want uuid.UUID
	}{
		{"slug", domain.AppFilter{Query: "grimoire-" + tag, Limit: 10}, a.ID},
		{"name case-insensitive", domain.AppFilter{Query: "LEDGER-" + tag, Limit: 10}, b.ID},
		{"description", domain.AppFilter{Query: "SPELLBOOK " + tag, Limit: 10}, a.ID},
		{"query and group", domain.AppFilter{Query: "team", Group: "docs-" + tag, Limit: 10}, a.ID},
	} {
		got, total, err := repo.List(ctx, tc.f)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if tc.name == "query and group" {
			if total != 2 || len(got) != 2 {
				t.Fatalf("%s: total=%d len=%d, want both rows", tc.name, total, len(got))
			}
			continue
		}
		if total != 1 || len(got) != 1 || got[0].ID != tc.want {
			t.Fatalf("%s: total=%d ids=%v, want %s", tc.name, total, got, tc.want)
		}
	}

	// Group mismatch narrows the query hit to nothing.
	got, total, err := repo.List(ctx, domain.AppFilter{Query: "grimoire-" + tag, Group: "nope-" + tag, Limit: 10})
	if err != nil || total != 0 || len(got) != 0 {
		t.Fatalf("query+group mismatch: total=%d len=%d err=%v, want empty", total, len(got), err)
	}
}
