//go:build integration

package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
)

func TestUserAttrDefCRUD(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	repo := NewUserAttrRepository(db)
	tag := uuid.NewString()[:8]
	key := "idept-" + tag

	d, err := repo.CreateDef(ctx, domain.UserAttrDef{Key: key, Type: domain.UserAttrString})
	if err != nil {
		t.Fatalf("CreateDef: %v", err)
	}
	t.Cleanup(func() {
		_ = repo.DeleteDef(context.Background(), key)
	})
	if d.ID == uuid.Nil || d.Key != key || d.Type != domain.UserAttrString || d.Multi {
		t.Fatalf("created def = %+v", d)
	}
	if _, err := repo.CreateDef(ctx, domain.UserAttrDef{Key: key, Type: domain.UserAttrString}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate CreateDef err = %v, want ErrConflict", err)
	}
	if _, err := repo.CreateDef(ctx, domain.UserAttrDef{Key: "Bad Key", Type: domain.UserAttrString}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("bad key CreateDef err = %v, want ErrValidation", err)
	}
	defs, err := repo.ListDefs(ctx)
	if err != nil {
		t.Fatalf("ListDefs: %v", err)
	}
	found := false
	for _, got := range defs {
		if got.Key == key {
			found = true
		}
	}
	if !found {
		t.Fatalf("ListDefs missing %q", key)
	}
	if err := repo.DeleteDef(ctx, key); err != nil {
		t.Fatalf("DeleteDef: %v", err)
	}
	if err := repo.DeleteDef(ctx, key); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("second DeleteDef err = %v, want ErrNotFound", err)
	}
}

func TestUserAttrValues(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	repo := NewUserAttrRepository(db)
	users := NewUserRepository(db)
	tag := uuid.NewString()[:8]

	u, err := users.Create(ctx, domain.User{
		Username: "iattr-" + tag, Email: "iattr@example.com",
		PasswordHash: []byte("dummyhash"), Source: domain.SourceLocal, IsActive: true,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, u.ID)
	})
	dept, err := repo.CreateDef(ctx, domain.UserAttrDef{Key: "idept2-" + tag, Type: domain.UserAttrString})
	if err != nil {
		t.Fatalf("create def: %v", err)
	}
	tags, err := repo.CreateDef(ctx, domain.UserAttrDef{Key: "itags-" + tag, Type: domain.UserAttrString, Multi: true})
	if err != nil {
		t.Fatalf("create def: %v", err)
	}
	t.Cleanup(func() {
		_ = repo.DeleteDef(context.Background(), tags.Key)
	})

	if err := repo.SetValues(ctx, u.ID, map[uuid.UUID][]string{
		dept.ID: {"eng"},
		tags.ID: {"a", "b"},
	}, domain.UserAttrAdmin); err != nil {
		t.Fatalf("SetValues: %v", err)
	}
	got, err := repo.ValuesOfUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("ValuesOfUser: %v", err)
	}
	want := map[string][]string{dept.Key: {"eng"}, tags.Key: {"a", "b"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ValuesOfUser = %v, want %v", got, want)
	}
	// Replace one def, clear the other; batch read agrees.
	if err := repo.SetValues(ctx, u.ID, map[uuid.UUID][]string{
		dept.ID: {"ops"},
		tags.ID: {},
	}, domain.UserAttrAdmin); err != nil {
		t.Fatalf("SetValues replace: %v", err)
	}
	batch, err := repo.ValuesForUsers(ctx, []uuid.UUID{u.ID, uuid.New()})
	if err != nil {
		t.Fatalf("ValuesForUsers: %v", err)
	}
	if !reflect.DeepEqual(batch[u.ID], map[string][]string{dept.Key: {"ops"}}) {
		t.Fatalf("ValuesForUsers = %v", batch)
	}
	if _, ok := batch[uuid.Nil]; ok {
		t.Fatalf("ValuesForUsers has empty entry for missing user")
	}
	// Upstream replace marks ldap and clears missing ldap keys.
	if err := repo.ApplyUpstreamValues(ctx, u.ID, map[uuid.UUID][]string{tags.ID: {"x"}}); err != nil {
		t.Fatalf("ApplyUpstreamValues: %v", err)
	}
	got, err = repo.ValuesOfUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("ValuesOfUser: %v", err)
	}
	// dept was admin-sourced and untouched by the upstream apply (it was
	// not ldap-sourced and not in the snapshot); tags replaced.
	if !reflect.DeepEqual(got, map[string][]string{dept.Key: {"ops"}, tags.Key: {"x"}}) {
		t.Fatalf("after upstream apply = %v", got)
	}
	var source string
	if err := db.Pool.QueryRow(ctx, `SELECT source FROM user_attr_values WHERE user_id=$1 AND def_id=$2`,
		u.ID, tags.ID).Scan(&source); err != nil || source != "ldap" {
		t.Fatalf("tags source = %q, %v, want ldap", source, err)
	}
	// Empty snapshot clears ldap-sourced keys, keeps admin ones.
	if err := repo.ApplyUpstreamValues(ctx, u.ID, map[uuid.UUID][]string{}); err != nil {
		t.Fatalf("ApplyUpstreamValues empty: %v", err)
	}
	got, err = repo.ValuesOfUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("ValuesOfUser: %v", err)
	}
	if !reflect.DeepEqual(got, map[string][]string{dept.Key: {"ops"}}) {
		t.Fatalf("after empty upstream apply = %v", got)
	}
	// Def delete cascades values.
	if err := repo.DeleteDef(ctx, dept.Key); err != nil {
		t.Fatalf("DeleteDef: %v", err)
	}
	got, err = repo.ValuesOfUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("ValuesOfUser: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("after def delete = %v, want empty", got)
	}
}
