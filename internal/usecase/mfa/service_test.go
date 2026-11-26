package mfa

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
	"github.com/identityhub/identityhub/internal/usecase/audit"
)

// ---------- fakes ----------

type fakeStore struct {
	cred     map[uuid.UUID]domain.TOTPCredential
	recovery map[uuid.UUID][]fakeCode
	err      error
	useErr   error
}

type fakeCode struct {
	hash []byte
	used bool
}

func newFakeStore() *fakeStore {
	return &fakeStore{cred: map[uuid.UUID]domain.TOTPCredential{}, recovery: map[uuid.UUID][]fakeCode{}}
}

func (f *fakeStore) EnrollTOTP(_ context.Context, c domain.TOTPCredential) error {
	if _, ok := f.cred[c.UserID]; ok {
		return domain.ErrConflict
	}
	f.cred[c.UserID] = c
	return nil
}

func (f *fakeStore) TOTPOfUser(_ context.Context, id uuid.UUID) (domain.TOTPCredential, error) {
	if f.err != nil {
		return domain.TOTPCredential{}, f.err
	}
	c, ok := f.cred[id]
	if !ok {
		return domain.TOTPCredential{}, domain.ErrNotFound
	}
	return c, nil
}

func (f *fakeStore) AcceptStep(_ context.Context, id uuid.UUID, step int64) error {
	c, ok := f.cred[id]
	if !ok {
		return domain.ErrNotFound
	}
	if step <= c.LastStep {
		return domain.ErrConflict
	}
	c.LastStep = step
	f.cred[id] = c
	return nil
}

func (f *fakeStore) DisableTOTP(_ context.Context, id uuid.UUID) error {
	delete(f.cred, id)
	delete(f.recovery, id)
	return nil
}

func (f *fakeStore) AddRecoveryCodes(_ context.Context, id uuid.UUID, hashes [][]byte) error {
	for _, h := range hashes {
		f.recovery[id] = append(f.recovery[id], fakeCode{hash: h})
	}
	return nil
}

func (f *fakeStore) ReplaceRecoveryCodes(_ context.Context, id uuid.UUID, hashes [][]byte) error {
	f.recovery[id] = nil
	return f.AddRecoveryCodes(context.Background(), id, hashes)
}

func (f *fakeStore) UseRecoveryCode(_ context.Context, id uuid.UUID, hash []byte, _ time.Time) error {
	if f.useErr != nil {
		return f.useErr
	}
	for i, c := range f.recovery[id] {
		if !c.used && string(c.hash) == string(hash) {
			f.recovery[id][i].used = true
			return nil
		}
	}
	return domain.ErrNotFound
}

func (f *fakeStore) RemainingRecoveryCodes(_ context.Context, id uuid.UUID) (int, error) {
	n := 0
	for _, c := range f.recovery[id] {
		if !c.used {
			n++
		}
	}
	return n, nil
}

type fakeUsers struct {
	byID map[uuid.UUID]domain.User
}

func (f *fakeUsers) Create(_ context.Context, u domain.User) (domain.User, error) {
	f.byID[u.ID] = u
	return u, nil
}
func (f *fakeUsers) ByID(_ context.Context, id uuid.UUID) (domain.User, error) {
	u, ok := f.byID[id]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return u, nil
}
func (f *fakeUsers) ByUsername(_ context.Context, _ string) (domain.User, error) {
	return domain.User{}, domain.ErrNotFound
}
func (f *fakeUsers) ByUsernameFold(_ context.Context, _ string) (domain.User, error) {
	return domain.User{}, domain.ErrNotFound
}
func (f *fakeUsers) ByEmail(_ context.Context, _ string) (domain.User, error) {
	return domain.User{}, domain.ErrNotFound
}
func (f *fakeUsers) List(_ context.Context, _ domain.UserFilter) ([]domain.User, int, error) {
	return nil, 0, nil
}
func (f *fakeUsers) AllActive(_ context.Context) ([]domain.User, error) {
	return nil, nil
}
func (f *fakeUsers) Update(_ context.Context, u domain.User) (domain.User, error) {
	f.byID[u.ID] = u
	return u, nil
}
func (f *fakeUsers) SetActive(_ context.Context, id uuid.UUID, active bool) error {
	u := f.byID[id]
	u.IsActive = active
	f.byID[id] = u
	return nil
}
func (f *fakeUsers) SetPasswordHash(_ context.Context, _ uuid.UUID, _ []byte) error {
	return nil
}

func (f *fakeUsers) Delete(_ context.Context, id uuid.UUID) error {
	if _, ok := f.byID[id]; !ok {
		return domain.ErrNotFound
	}
	delete(f.byID, id)
	return nil
}

type fakeGroups struct {
	admins map[uuid.UUID]bool
}

func (f *fakeGroups) Create(_ context.Context, g domain.Group) (domain.Group, error) {
	return g, nil
}
func (f *fakeGroups) ByID(_ context.Context, id uuid.UUID) (domain.Group, error) {
	return domain.Group{ID: id}, nil
}
func (f *fakeGroups) ByName(_ context.Context, name string) (domain.Group, error) {
	return domain.Group{Name: name}, nil
}
func (f *fakeGroups) List(_ context.Context, _, _ int) ([]domain.Group, int, error) {
	return nil, 0, nil
}
func (f *fakeGroups) All(_ context.Context) ([]domain.Group, error) {
	return nil, nil
}
func (f *fakeGroups) Delete(_ context.Context, _ uuid.UUID) error { return nil }
func (f *fakeGroups) AddMember(_ context.Context, _, _ uuid.UUID) error {
	return nil
}
func (f *fakeGroups) RemoveMember(_ context.Context, _, _ uuid.UUID) error {
	return nil
}
func (f *fakeGroups) MemberIDs(_ context.Context, _ uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
}
func (f *fakeGroups) MemberUsernamesByGroup(_ context.Context) (map[uuid.UUID][]string, error) {
	return map[uuid.UUID][]string{}, nil
}
func (f *fakeGroups) GroupsOfUser(_ context.Context, _ uuid.UUID) ([]domain.Group, error) {
	return nil, nil
}
func (f *fakeGroups) IsMember(_ context.Context, id uuid.UUID, name string) (bool, error) {
	return name == domain.AdminGroup && f.admins[id], nil
}

type fakeApps struct {
	byID map[uuid.UUID]domain.Application
}

func (f *fakeApps) Create(_ context.Context, a domain.Application) (domain.Application, error) {
	f.byID[a.ID] = a
	return a, nil
}
func (f *fakeApps) ByID(_ context.Context, id uuid.UUID) (domain.Application, error) {
	a, ok := f.byID[id]
	if !ok {
		return domain.Application{}, domain.ErrNotFound
	}
	return a, nil
}
func (f *fakeApps) BySlug(_ context.Context, _ string) (domain.Application, error) {
	return domain.Application{}, domain.ErrNotFound
}
func (f *fakeApps) List(_ context.Context, _ domain.AppFilter) ([]domain.Application, int, error) {
	return nil, 0, nil
}
func (f *fakeApps) Update(_ context.Context, a domain.Application) (domain.Application, error) {
	f.byID[a.ID] = a
	return a, nil
}
func (f *fakeApps) Delete(_ context.Context, _ uuid.UUID) error { return nil }

// fakeTOTP is a deterministic TOTP: code "111111" matches the current
// step, "222222" the previous one, everything else fails.
type fakeTOTP struct{}

func (fakeTOTP) NewSeed(_, _ string) ([]byte, string, error) {
	return []byte("test-seed-12345678"), "otpauth://totp/test", nil
}
func (fakeTOTP) Verify(_ []byte, code string, at time.Time) (int64, bool) {
	step := at.Unix() / 30
	switch code {
	case "111111":
		return step, true
	case "222222":
		return step - 1, true
	}
	return 0, false
}
func (fakeTOTP) Code(_ []byte, step int64) (string, error) {
	return "111111", nil
}
func (fakeTOTP) QRCodePNG(_ string, _ int) ([]byte, error) { return []byte("png"), nil }

type fakeSealer struct{}

func (fakeSealer) Seal(p []byte) ([]byte, error) { return append([]byte("sealed:"), p...), nil }
func (fakeSealer) Open(s []byte) ([]byte, error) {
	if len(s) < 7 {
		return nil, errors.New("bad seal")
	}
	return s[7:], nil
}

type fakeAudit struct {
	entries []domain.AuditEntry
	err     error
}

func (f *fakeAudit) Append(_ context.Context, e domain.AuditEntry) error {
	if f.err != nil {
		return f.err
	}
	f.entries = append(f.entries, e)
	return nil
}
func (f *fakeAudit) List(_ context.Context, _ domain.AuditFilter) ([]domain.AuditEntry, int, error) {
	return f.entries, len(f.entries), nil
}

type fakeMailer struct{ sent int }

func (f *fakeMailer) Send(_, _, _, _ string) error {
	f.sent++
	return nil
}

type fakeClock struct{ now time.Time }

func (f *fakeClock) Now() time.Time { return f.now }

func newTestService(t *testing.T) (*Service, *fakeStore, *fakeAudit, *fakeMailer, domain.User) {
	t.Helper()
	u := domain.User{ID: uuid.New(), Username: "alice", Email: "alice@example.com", IsActive: true}
	store := newFakeStore()
	aud := &fakeAudit{}
	mailer := &fakeMailer{}
	svc, err := New(Deps{
		Store:  store,
		Users:  &fakeUsers{byID: map[uuid.UUID]domain.User{u.ID: u}},
		Groups: &fakeGroups{admins: map[uuid.UUID]bool{}},
		Apps:   &fakeApps{byID: map[uuid.UUID]domain.Application{}},
		TOTP:   fakeTOTP{}, Sealer: fakeSealer{},
		Audit: audit.New(aud, nil), Clock: &fakeClock{now: time.Unix(1_700_000_000, 0).UTC()},
		Mailer: mailer,
		Rand: func() func(n int) ([]byte, error) {
			var ctr byte
			return func(n int) ([]byte, error) {
				ctr++
				b := make([]byte, n)
				for i := range b {
					b[i] = ctr*31 + byte(i+1)
				}
				return b, nil
			}
		}(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, store, aud, mailer, u
}

// ---------- tests ----------

func TestNewRequiresDeps(t *testing.T) {
	if _, err := New(Deps{}); err == nil {
		t.Fatal("empty deps must fail")
	}
}

func TestEnrollConfirmVerifyCycle(t *testing.T) {
	svc, _, aud, _, u := newTestService(t)
	ctx := context.Background()

	ch, err := svc.EnrollStart(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ch.OTPAuthURL == "" || len(ch.QRCodePNG) == 0 || ch.Secret == "" {
		t.Fatal("challenge must carry URL, QR and secret")
	}
	if _, err := svc.EnrollConfirm(ctx, u.ID, ch.Seed, "000000"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("bad confirm code must fail validation, got %v", err)
	}
	plain, err := svc.EnrollConfirm(ctx, u.ID, ch.Seed, "111111")
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != RecoveryCodeCount {
		t.Fatalf("want %d recovery codes, got %d", RecoveryCodeCount, len(plain))
	}
	// The confirm code itself must not double as a login code (step burned),
	// and the older previous-step code dies with it (anti-replay only
	// moves forward).
	if err := svc.Verify(ctx, u.ID, "111111", "10.0.0.1"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("confirm-code replay must fail, got %v", err)
	}
	if err := svc.Verify(ctx, u.ID, "222222", "10.0.0.1"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("older-step code must fail after the newer step burned, got %v", err)
	}
	// A fresh step verifies once, then replays fail atomically.
	svc.clock.(*fakeClock).now = svc.clock.Now().Add(60 * time.Second)
	if err := svc.Verify(ctx, u.ID, "111111", "10.0.0.1"); err != nil {
		t.Fatalf("fresh-step code must verify: %v", err)
	}
	if err := svc.Verify(ctx, u.ID, "111111", "10.0.0.1"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("reused code must fail, got %v", err)
	}
	// Every login attempt is audited (bad confirm + enroll + 4 verifies).
	if len(aud.entries) != 6 {
		t.Fatalf("want 6 audit entries, got %d", len(aud.entries))
	}
	for _, e := range aud.entries[2:] {
		if e.Method != domain.MethodTOTP || e.IP != "10.0.0.1" {
			t.Fatalf("login audits must carry method=totp and ip: %+v", e)
		}
	}
}

func TestEnrollStartConflict(t *testing.T) {
	svc, store, _, _, u := newTestService(t)
	ctx := context.Background()
	store.cred[u.ID] = domain.TOTPCredential{UserID: u.ID}
	if _, err := svc.EnrollStart(ctx, u.ID); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second enroll must conflict, got %v", err)
	}
}

func TestVerifyNotEnrolled(t *testing.T) {
	svc, _, _, _, u := newTestService(t)
	if err := svc.Verify(context.Background(), u.ID, "111111", ""); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("verify without enroll must fail validation, got %v", err)
	}
}

func TestVerifyFailureNotifies(t *testing.T) {
	svc, store, _, mailer, u := newTestService(t)
	ctx := context.Background()
	store.cred[u.ID] = domain.TOTPCredential{UserID: u.ID, SeedEnc: []byte("sealed:seed")}
	if err := svc.Verify(ctx, u.ID, "000000", "10.0.0.2"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("bad code must be unauthorized, got %v", err)
	}
	if mailer.sent != 1 {
		t.Fatalf("failed second factor must notify once, got %d", mailer.sent)
	}
}

func TestRecoveryCycle(t *testing.T) {
	svc, store, _, _, u := newTestService(t)
	ctx := context.Background()
	ch, err := svc.EnrollStart(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := svc.EnrollConfirm(ctx, u.ID, ch.Seed, "111111")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.VerifyRecovery(ctx, u.ID, plain[0], "10.0.0.3"); err != nil {
		t.Fatalf("recovery code must verify: %v", err)
	}
	// Codes are single-use.
	if err := svc.VerifyRecovery(ctx, u.ID, plain[0], "10.0.0.3"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("reused recovery code must fail, got %v", err)
	}
	if err := svc.VerifyRecovery(ctx, u.ID, "AAAA-BBBB-CCCC-DDDD", "10.0.0.3"); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("unknown recovery code must fail, got %v", err)
	}
	st, err := svc.Status(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !st.HasTOTP || st.RemainingRecoveryCodes != RecoveryCodeCount-1 {
		t.Fatalf("unexpected status: %+v", st)
	}
	// Assert the real hashing path: the stored hash must match the
	// normalized plaintext code.
	sum := sha256.Sum256([]byte(normalizeRecovery(plain[1])))
	found := false
	for _, c := range store.recovery[u.ID] {
		if string(c.hash) == string(sum[:]) {
			found = true
		}
	}
	if !found {
		t.Fatal("stored hash must match the normalized plaintext code")
	}
}

func TestDisableSelfRequiresOldFactor(t *testing.T) {
	svc, _, _, _, u := newTestService(t)
	ctx := context.Background()
	ch, err := svc.EnrollStart(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EnrollConfirm(ctx, u.ID, ch.Seed, "111111"); err != nil {
		t.Fatal(err)
	}
	if err := svc.DisableSelf(ctx, u.ID, "000000"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("disable with bad factor must fail, got %v", err)
	}
	// The confirm code burned its step, so re-auth needs a fresh one.
	svc.clock.(*fakeClock).now = svc.clock.Now().Add(60 * time.Second)
	if err := svc.DisableSelf(ctx, u.ID, "111111"); err != nil {
		t.Fatalf("disable with old factor must succeed: %v", err)
	}
	if has, _ := svc.HasTOTP(ctx, u.ID); has {
		t.Fatal("TOTP must be gone after disable")
	}
}

func TestRegenerateRecovery(t *testing.T) {
	svc, _, _, _, u := newTestService(t)
	ctx := context.Background()
	ch, err := svc.EnrollStart(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	old, err := svc.EnrollConfirm(ctx, u.ID, ch.Seed, "111111")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegenerateRecovery(ctx, u.ID, "000000"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("regenerate with bad factor must fail, got %v", err)
	}
	// The confirm code burned its step, so re-auth needs a fresh one.
	svc.clock.(*fakeClock).now = svc.clock.Now().Add(60 * time.Second)
	fresh, err := svc.RegenerateRecovery(ctx, u.ID, "111111")
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh) != RecoveryCodeCount {
		t.Fatalf("want %d fresh codes, got %d", RecoveryCodeCount, len(fresh))
	}
	_ = old
}

func TestAdminReset(t *testing.T) {
	svc, _, _, _, u := newTestService(t)
	admin := domain.User{ID: uuid.New(), Username: "root", IsActive: true}
	ctx := context.Background()
	ch, err := svc.EnrollStart(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EnrollConfirm(ctx, u.ID, ch.Seed, "111111"); err != nil {
		t.Fatal(err)
	}
	if err := svc.AdminReset(ctx, u.ID, u.ID); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("non-admin reset must be forbidden, got %v", err)
	}
	svc.groups.(*fakeGroups).admins[admin.ID] = true
	svc.users.(*fakeUsers).byID[admin.ID] = admin
	if err := svc.AdminReset(ctx, admin.ID, u.ID); err != nil {
		t.Fatalf("admin reset must succeed: %v", err)
	}
	if has, _ := svc.HasTOTP(ctx, u.ID); has {
		t.Fatal("factors must be gone after admin reset")
	}
	if err := svc.AdminReset(ctx, admin.ID, uuid.New()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("reset of unknown user must be not-found, got %v", err)
	}
}

func TestPolicy(t *testing.T) {
	svc, _, _, _, u := newTestService(t)
	ctx := context.Background()
	appID := uuid.New()
	svc.apps.(*fakeApps).byID[appID] = domain.Application{ID: appID, MFARequired: true}
	plainID := uuid.New()
	svc.apps.(*fakeApps).byID[plainID] = domain.Application{ID: plainID}

	// Unenrolled regular user: no login MFA, app policy per flag.
	required, enrolled, err := svc.RequiredForLogin(ctx, u.ID)
	if err != nil || required || enrolled {
		t.Fatalf("unenrolled user must not require login MFA: %v %v %v", required, enrolled, err)
	}
	if ok, _ := svc.RequiredForApp(ctx, u.ID, appID); !ok {
		t.Fatal("flagged app must require MFA")
	}
	if ok, _ := svc.RequiredForApp(ctx, u.ID, plainID); ok {
		t.Fatal("plain app must not require MFA")
	}
	// Enrolled regular user: login MFA via opt-in.
	ch, err := svc.EnrollStart(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EnrollConfirm(ctx, u.ID, ch.Seed, "111111"); err != nil {
		t.Fatal(err)
	}
	if required, enrolled, _ := svc.RequiredForLogin(ctx, u.ID); !required || !enrolled {
		t.Fatal("enrolled user must require login MFA")
	}
	// Admins always require MFA, even unenrolled and on plain apps.
	admin := domain.User{ID: uuid.New(), Username: "root", IsActive: true}
	svc.users.(*fakeUsers).byID[admin.ID] = admin
	svc.groups.(*fakeGroups).admins[admin.ID] = true
	if required, enrolled, _ := svc.RequiredForLogin(ctx, admin.ID); !required || enrolled {
		t.Fatal("admin must require login MFA even when unenrolled")
	}
	if ok, _ := svc.RequiredForApp(ctx, admin.ID, plainID); !ok {
		t.Fatal("admin must require MFA on every app")
	}
}

func TestNewDefaults(t *testing.T) {
	u := domain.User{ID: uuid.New(), Username: "bob", IsActive: true}
	svc, err := New(Deps{
		Store: newFakeStore(), Users: &fakeUsers{byID: map[uuid.UUID]domain.User{u.ID: u}},
		Groups: &fakeGroups{admins: map[uuid.UUID]bool{}},
		Apps:   &fakeApps{byID: map[uuid.UUID]domain.Application{}},
		TOTP:   fakeTOTP{}, Sealer: fakeSealer{}, Audit: audit.New(&fakeAudit{}, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	if svc.issuer != DefaultIssuer {
		t.Fatalf("default issuer must apply, got %q", svc.issuer)
	}
	ch, err := svc.EnrollStart(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Seed) == 0 {
		t.Fatal("default rand must produce a seed")
	}
}

func TestEnrollConfirmEdgeCases(t *testing.T) {
	svc, _, _, _, u := newTestService(t)
	ctx := context.Background()
	if _, err := svc.EnrollConfirm(ctx, uuid.New(), []byte("seed"), "111111"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown user must be not-found, got %v", err)
	}
	if _, err := svc.EnrollConfirm(ctx, u.ID, nil, "111111"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("empty seed must fail validation, got %v", err)
	}
	ch, err := svc.EnrollStart(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EnrollConfirm(ctx, u.ID, ch.Seed, "111111"); err != nil {
		t.Fatal(err)
	}
	// A concurrent second confirm with a fresh code collides on enroll.
	svc.clock.(*fakeClock).now = svc.clock.Now().Add(60 * time.Second)
	if _, err := svc.EnrollConfirm(ctx, u.ID, ch.Seed, "111111"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second confirm must conflict, got %v", err)
	}
}

func TestCheckFactorRecoveryAndReuse(t *testing.T) {
	svc, _, _, _, u := newTestService(t)
	ctx := context.Background()
	ch, err := svc.EnrollStart(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := svc.EnrollConfirm(ctx, u.ID, ch.Seed, "111111")
	if err != nil {
		t.Fatal(err)
	}
	// A recovery code also re-authenticates (and burns).
	if err := svc.DisableSelf(ctx, u.ID, plain[0]); err != nil {
		t.Fatalf("disable with recovery code must succeed: %v", err)
	}
	// Re-enroll, then reuse one TOTP code for two factor checks: the
	// second check fails closed on the anti-replay step.
	ch, err = svc.EnrollStart(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	svc.clock.(*fakeClock).now = svc.clock.Now().Add(60 * time.Second)
	if _, err := svc.EnrollConfirm(ctx, u.ID, ch.Seed, "111111"); err != nil {
		t.Fatal(err)
	}
	svc.clock.(*fakeClock).now = svc.clock.Now().Add(60 * time.Second)
	if _, err := svc.RegenerateRecovery(ctx, u.ID, "111111"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegenerateRecovery(ctx, u.ID, "111111"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("reused factor code must fail validation, got %v", err)
	}
}

func TestStatusEdges(t *testing.T) {
	svc, _, _, _, u := newTestService(t)
	ctx := context.Background()
	if _, err := svc.Status(ctx, uuid.New()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown user must be not-found, got %v", err)
	}
	st, err := svc.Status(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if st.HasTOTP || st.RemainingRecoveryCodes != 0 {
		t.Fatalf("unenrolled status must be empty: %+v", st)
	}
}

func TestRequiredForAppUnknownApp(t *testing.T) {
	svc, _, _, _, u := newTestService(t)
	if _, err := svc.RequiredForApp(context.Background(), u.ID, uuid.New()); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown app must be not-found, got %v", err)
	}
}

func TestVerifyAuditFailureFailsClosed(t *testing.T) {
	svc, store, aud, _, u := newTestService(t)
	ctx := context.Background()
	store.cred[u.ID] = domain.TOTPCredential{UserID: u.ID, SeedEnc: []byte("sealed:seed")}
	aud.err = errors.New("db down")
	if err := svc.Verify(ctx, u.ID, "111111", "10.0.0.9"); err == nil {
		t.Fatal("audit failure must fail the verify")
	}
	aud.err = nil
	store.cred[u.ID] = domain.TOTPCredential{UserID: u.ID, SeedEnc: []byte("x")}
	if err := svc.Verify(ctx, u.ID, "111111", "10.0.0.9"); err == nil {
		t.Fatal("corrupt seed must fail")
	}
}

func TestVerifyRecoveryUnknownUser(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	if err := svc.VerifyRecovery(context.Background(), uuid.New(), "AAAA", ""); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown user must be not-found, got %v", err)
	}
}

func TestRecoveryEntropyFailure(t *testing.T) {
	svc, _, _, _, u := newTestService(t)
	svc.rand = func(_ int) ([]byte, error) { return nil, errors.New("no entropy") }
	ch, err := svc.EnrollStart(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EnrollConfirm(context.Background(), u.ID, ch.Seed, "111111"); err == nil {
		t.Fatal("rand failure must fail enrollment")
	}
}

func TestNotifySkippedWithoutMailerOrEmail(t *testing.T) {
	svc, store, _, _, u := newTestService(t)
	ctx := context.Background()
	store.cred[u.ID] = domain.TOTPCredential{UserID: u.ID, SeedEnc: []byte("sealed:seed")}
	svc.mailer = nil
	if err := svc.Verify(ctx, u.ID, "000000", ""); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("bad code must be unauthorized, got %v", err)
	}
	u.Email = ""
	svc.users.(*fakeUsers).byID[u.ID] = u
	svc.mailer = &fakeMailer{}
	svc.clock.(*fakeClock).now = svc.clock.Now().Add(60 * time.Second)
	if err := svc.Verify(ctx, u.ID, "000000", ""); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("bad code must be unauthorized, got %v", err)
	}
}

func TestReAuth(t *testing.T) {
	svc, _, aud, _, u := newTestService(t)
	ctx := context.Background()
	if err := svc.ReAuth(ctx, uuid.New(), "111111"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown user must be not-found, got %v", err)
	}
	ch, err := svc.EnrollStart(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EnrollConfirm(ctx, u.ID, ch.Seed, "111111"); err != nil {
		t.Fatal(err)
	}
	if err := svc.ReAuth(ctx, u.ID, "000000"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("bad factor must fail validation, got %v", err)
	}
	svc.clock.(*fakeClock).now = svc.clock.Now().Add(60 * time.Second)
	if err := svc.ReAuth(ctx, u.ID, "111111"); err != nil {
		t.Fatalf("fresh factor must pass: %v", err)
	}
	for _, e := range aud.entries {
		if e.IP != "" {
			t.Fatalf("reauth must not write login audits: %+v", e)
		}
	}
}

func TestHasTOTPStoreError(t *testing.T) {
	svc, store, _, _, _ := newTestService(t)
	store.err = errors.New("db down")
	if _, err := svc.HasTOTP(context.Background(), uuid.New()); err == nil {
		t.Fatal("store error must propagate")
	}
}

func TestStoreErrorsPropagate(t *testing.T) {
	svc, store, _, _, u := newTestService(t)
	ctx := context.Background()
	store.err = errors.New("db down")
	if _, err := svc.EnrollStart(ctx, u.ID); err == nil {
		t.Fatal("store error must fail EnrollStart")
	}
	if _, _, err := svc.RequiredForLogin(ctx, u.ID); err == nil {
		t.Fatal("store error must fail RequiredForLogin")
	}
	if err := svc.DisableSelf(ctx, u.ID, "111111"); err == nil {
		t.Fatal("store error must fail DisableSelf")
	}
	store.err = nil
	ch, err := svc.EnrollStart(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EnrollConfirm(ctx, u.ID, ch.Seed, "111111"); err != nil {
		t.Fatal(err)
	}
	store.useErr = errors.New("db down")
	if err := svc.VerifyRecovery(ctx, u.ID, "AAAA-BBBB-CCCC-DDDD", ""); err == nil {
		t.Fatal("store error must fail VerifyRecovery")
	}
	if err := svc.DisableSelf(ctx, u.ID, "000000"); err == nil {
		t.Fatal("store error must fail checkFactor")
	}
}

func TestDisabledAccountRejected(t *testing.T) {
	svc, _, _, _, u := newTestService(t)
	u.IsActive = false
	svc.users.(*fakeUsers).byID[u.ID] = u
	ctx := context.Background()
	if _, err := svc.EnrollStart(ctx, u.ID); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("disabled account must be forbidden, got %v", err)
	}
	if err := svc.Verify(ctx, u.ID, "111111", ""); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("disabled account must be forbidden, got %v", err)
	}
}
