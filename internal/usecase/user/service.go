// Package user implements user/group management (PRD §6.1) and applies
// upstream directory sync snapshots (PRD §6.2, TECH_SPEC §6.6).
//
// Guard summary: ih_admin cannot be deleted or renamed (no rename exists
// on the store; delete is refused here and by a DB trigger); admins
// cannot remove themselves or the last member; LDAP-synced rows never
// overwrite local rows on username conflict (rejected explicitly).
package user

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/identityhub/identityhub/internal/domain"
	"github.com/identityhub/identityhub/internal/usecase/audit"
)

// Service holds the user/group business rules.
type Service struct {
	users    domain.UserStore
	groups   domain.GroupStore
	sessions domain.SessionRegistry
	audit    *audit.Service
	hasher   domain.PasswordHasher
	clock    domain.Clock
	attrs    domain.UserAttrStore
}

// Deps wires a Service. Users, Groups, Sessions, Audit and Hasher are
// required; Attrs is optional (nil skips upstream attribute application
// and fails the schema methods closed).
type Deps struct {
	Users    domain.UserStore
	Groups   domain.GroupStore
	Sessions domain.SessionRegistry
	Audit    *audit.Service
	Hasher   domain.PasswordHasher
	Clock    domain.Clock
	Attrs    domain.UserAttrStore
}

// New validates Deps and builds a Service.
func New(d Deps) (*Service, error) {
	if d.Users == nil || d.Groups == nil || d.Sessions == nil || d.Audit == nil || d.Hasher == nil {
		return nil, errors.New("user: Users, Groups, Sessions, Audit and Hasher are required")
	}
	if d.Clock == nil {
		d.Clock = domain.SystemClock{}
	}
	return &Service{users: d.Users, groups: d.Groups, sessions: d.Sessions, audit: d.Audit, hasher: d.Hasher, clock: d.Clock, attrs: d.Attrs}, nil
}

// NewUser carries admin-created user fields. Password is required for
// local users and forbidden for LDAP users (their password lives in the
// directory).
type NewUser struct {
	Username    string
	Email       string
	DisplayName string
	Password    string
	Source      domain.UserSource
	ExternalDN  string
}

// CreateUser creates a local or pre-provisioned LDAP user.
func (s *Service) CreateUser(ctx context.Context, actorID uuid.UUID, in NewUser) (domain.User, error) {
	username := strings.TrimSpace(in.Username)
	if username == "" {
		return domain.User{}, fmt.Errorf("%w: username is required", domain.ErrValidation)
	}
	source := in.Source
	if source == "" {
		source = domain.SourceLocal
	}
	var hash []byte
	if source == domain.SourceLocal {
		if len(in.Password) < 12 {
			return domain.User{}, fmt.Errorf("%w: password must be at least 12 characters", domain.ErrValidation)
		}
		var err error
		hash, err = s.hasher.Hash(in.Password)
		if err != nil {
			return domain.User{}, fmt.Errorf("user: hash password: %w", err)
		}
	} else if in.Password != "" {
		return domain.User{}, fmt.Errorf("%w: LDAP users have no local password", domain.ErrValidation)
	}
	u, err := s.users.Create(ctx, domain.User{
		Username: username, Email: strings.TrimSpace(in.Email),
		DisplayName: in.DisplayName, PasswordHash: hash,
		Source: source, ExternalDN: in.ExternalDN, IsActive: true,
	})
	if err != nil {
		return domain.User{}, err
	}
	_ = s.audit.Record(ctx, domain.AuditEntry{
		ActorUserID: &actorID, Method: domain.MethodPassword, Result: domain.ResultSuccess,
		Detail: map[string]any{"action": audit.ActionUserCreate, "target_user_id": u.ID.String()},
	})
	return u, nil
}

// UpdateProfile rewrites display name, email and avatar URL. Username,
// source and DN are immutable after creation.
func (s *Service) UpdateProfile(ctx context.Context, id uuid.UUID, displayName, email, avatarURL string) (domain.User, error) {
	u, err := s.users.ByID(ctx, id)
	if err != nil {
		return domain.User{}, err
	}
	u.DisplayName = displayName
	u.Email = email
	u.AvatarURL = avatarURL
	return s.users.Update(ctx, u)
}

// SetActive activates or deactivates a user. Deactivation revokes every
// session immediately. The last active ih_admin member cannot be
// deactivated (it would lock out administration).
func (s *Service) SetActive(ctx context.Context, actorID, id uuid.UUID, active bool) error {
	u, err := s.users.ByID(ctx, id)
	if err != nil {
		return err
	}
	if !active {
		if err := s.guardLastAdmin(ctx, id); err != nil {
			return err
		}
	}
	if err := s.users.SetActive(ctx, id, active); err != nil {
		return err
	}
	if !active {
		if _, err := s.sessions.RevokeAll(ctx, id); err != nil {
			return fmt.Errorf("user: revoke sessions: %w", err)
		}
	}
	action := audit.ActionUserReactivate
	if !active {
		action = audit.ActionUserDeactivate
	}
	_ = s.audit.Record(ctx, domain.AuditEntry{
		ActorUserID: &actorID, Method: domain.MethodPassword, Result: domain.ResultSuccess,
		Detail: map[string]any{"action": action, "target_user_id": u.ID.String()},
	})
	return nil
}

// guardLastAdmin refuses to disable the last active ih_admin member.
func (s *Service) guardLastAdmin(ctx context.Context, id uuid.UUID) error {
	member, err := s.groups.IsMember(ctx, id, domain.AdminGroup)
	if err != nil {
		return err
	}
	if !member {
		return nil
	}
	admin, err := s.groups.ByName(ctx, domain.AdminGroup)
	if err != nil {
		return err
	}
	ids, err := s.groups.MemberIDs(ctx, admin.ID)
	if err != nil {
		return err
	}
	active := 0
	for _, mid := range ids {
		if mid == id {
			continue
		}
		m, err := s.users.ByID(ctx, mid)
		if err != nil {
			continue // a concurrently deleted member is not active
		}
		if m.IsActive {
			active++
		}
	}
	if active == 0 {
		return fmt.Errorf("%w: cannot deactivate the last active administrator", domain.ErrForbidden)
	}
	return nil
}

// ListUsers searches and pages users (PRD §6.1 user search).
func (s *Service) ListUsers(ctx context.Context, f domain.UserFilter) ([]domain.User, int, error) {
	return s.users.List(ctx, f)
}

// GetUser loads one user by id.
func (s *Service) GetUser(ctx context.Context, id uuid.UUID) (domain.User, error) {
	return s.users.ByID(ctx, id)
}

// CreateGroup creates a group. The reserved name is refused explicitly
// (it is seeded by the initial migration).
func (s *Service) CreateGroup(ctx context.Context, name, description string) (domain.Group, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return domain.Group{}, fmt.Errorf("%w: group name is required", domain.ErrValidation)
	}
	if name == domain.AdminGroup {
		return domain.Group{}, fmt.Errorf("%w: %s is reserved", domain.ErrValidation, domain.AdminGroup)
	}
	return s.groups.Create(ctx, domain.Group{Name: name, Description: description})
}

// DeleteGroup deletes a group; ih_admin is refused (defense in depth —
// the repository and the DB trigger refuse it too).
func (s *Service) DeleteGroup(ctx context.Context, id uuid.UUID) error {
	g, err := s.groups.ByID(ctx, id)
	if err != nil {
		return err
	}
	if g.Name == domain.AdminGroup {
		return domain.ErrForbidden
	}
	return s.groups.Delete(ctx, id)
}

// ListGroups pages groups.
func (s *Service) ListGroups(ctx context.Context, limit, offset int) ([]domain.Group, int, error) {
	return s.groups.List(ctx, limit, offset)
}

// AddMember adds a user to a group (idempotent) and audits the change.
func (s *Service) AddMember(ctx context.Context, actorID, userID, groupID uuid.UUID) error {
	if _, err := s.users.ByID(ctx, userID); err != nil {
		return err
	}
	g, err := s.groups.ByID(ctx, groupID)
	if err != nil {
		return err
	}
	if err := s.groups.AddMember(ctx, userID, groupID); err != nil {
		return err
	}
	_ = s.audit.Record(ctx, domain.AuditEntry{
		ActorUserID: &actorID, Method: domain.MethodPassword, Result: domain.ResultSuccess,
		Detail: map[string]any{
			"action":         audit.ActionMemberAdd,
			"target_user_id": userID.String(), "group": g.Name,
		},
	})
	return nil
}

// RemoveMember removes a user from a group. From ih_admin, admins cannot
// remove themselves or the last member (PRD §6.1).
func (s *Service) RemoveMember(ctx context.Context, actorID, userID, groupID uuid.UUID) error {
	g, err := s.groups.ByID(ctx, groupID)
	if err != nil {
		return err
	}
	if g.Name == domain.AdminGroup {
		if actorID == userID {
			return fmt.Errorf("%w: administrators cannot remove themselves", domain.ErrForbidden)
		}
		ids, err := s.groups.MemberIDs(ctx, groupID)
		if err != nil {
			return err
		}
		member := false
		for _, id := range ids {
			if id == userID {
				member = true
				break
			}
		}
		// Removing a non-member is a no-op; removing the final member
		// would lock out administration.
		if member && len(ids) <= 1 {
			return fmt.Errorf("%w: cannot remove the last administrator", domain.ErrForbidden)
		}
	}
	if err := s.groups.RemoveMember(ctx, userID, groupID); err != nil {
		return err
	}
	_ = s.audit.Record(ctx, domain.AuditEntry{
		ActorUserID: &actorID, Method: domain.MethodPassword, Result: domain.ResultSuccess,
		Detail: map[string]any{
			"action":         audit.ActionMemberRemove,
			"target_user_id": userID.String(), "group": g.Name,
		},
	})
	return nil
}

// SyncReport summarizes one directory sync application (TECH_SPEC §6.6).
type SyncReport struct {
	Created    int
	Updated    int
	Disabled   int
	Reenabled  int
	AdminAdded []string
	// Conflicts holds usernames where a local row already exists: never
	// overwritten, reported for the admin (PRD §6.2).
	Conflicts []string
}

// SyncFromDirectory applies a directory snapshot to the local cache:
// create missing LDAP users, refresh profiles, soft-disable LDAP users
// missing from the directory (disable, never delete), reconcile
// directory-matched groups, and map AdminGroupDN members to ih_admin.
// adminGroupDN may be empty (mapping disabled).
func (s *Service) SyncFromDirectory(ctx context.Context, snap domain.DirectorySnapshot, adminGroupDN string) (SyncReport, error) {
	var rep SyncReport
	seen := make(map[string]bool, len(snap.Users))
	var defs []domain.UserAttrDef
	defsLoaded := false
	for _, lu := range snap.Users {
		if lu.Username == "" {
			continue
		}
		seen[lu.Username] = true
		existing, err := s.users.ByUsername(ctx, lu.Username)
		if errors.Is(err, domain.ErrNotFound) {
			if _, err := s.users.Create(ctx, domain.User{
				Username: lu.Username, Email: lu.Email, DisplayName: lu.DisplayName,
				Source: domain.SourceLDAP, ExternalDN: lu.DN, IsActive: true,
			}); err != nil {
				if errors.Is(err, domain.ErrConflict) {
					rep.Conflicts = append(rep.Conflicts, lu.Username)
					continue
				}
				return rep, fmt.Errorf("user: sync create %q: %w", lu.Username, err)
			}
			rep.Created++
			existing, err = s.users.ByUsername(ctx, lu.Username)
			if err != nil {
				return rep, fmt.Errorf("user: sync re-read %q: %w", lu.Username, err)
			}
		} else if err != nil {
			return rep, fmt.Errorf("user: sync lookup %q: %w", lu.Username, err)
		} else if existing.Source == domain.SourceLocal {
			rep.Conflicts = append(rep.Conflicts, lu.Username)
			continue // never overwrite a local row
		} else {
			existing.Email = lu.Email
			existing.DisplayName = lu.DisplayName
			existing.ExternalDN = lu.DN
			if !existing.IsActive {
				existing.IsActive = true
				rep.Reenabled++
			}
			if _, err := s.users.Update(ctx, existing); err != nil {
				return rep, fmt.Errorf("user: sync update %q: %w", lu.Username, err)
			}
			rep.Updated++
		}
		if lu.Attrs != nil && s.attrs != nil {
			if !defsLoaded {
				var err error
				defs, err = s.attrs.ListDefs(ctx)
				if err != nil {
					return rep, fmt.Errorf("user: sync list attr defs: %w", err)
				}
				defsLoaded = true
			}
			if err := s.attrs.ApplyUpstreamValues(ctx, existing.ID, domain.UpstreamAttrValues(defs, lu.Attrs)); err != nil {
				return rep, fmt.Errorf("user: sync attrs %q: %w", lu.Username, err)
			}
		}
		if err := s.applyAdminMapping(ctx, existing, lu, adminGroupDN, &rep); err != nil {
			return rep, err
		}
	}
	if err := s.softDisableMissing(ctx, seen, &rep); err != nil {
		return rep, err
	}
	if err := s.reconcileGroups(ctx, snap.Groups); err != nil {
		return rep, err
	}
	return rep, nil
}

// CreateAttrDef registers a custom attribute. Keys double as the wire
// names on LDAP, OIDC and SAML; validation rejects reserved names.
func (s *Service) CreateAttrDef(ctx context.Context, actorID uuid.UUID, key string, typ domain.UserAttrType, multi bool) (domain.UserAttrDef, error) {
	if s.attrs == nil {
		return domain.UserAttrDef{}, errors.New("user: attribute store is not configured")
	}
	d, err := s.attrs.CreateDef(ctx, domain.UserAttrDef{Key: key, Type: typ, Multi: multi})
	if err != nil {
		return domain.UserAttrDef{}, err
	}
	_ = s.audit.Record(ctx, domain.AuditEntry{
		ActorUserID: &actorID, Method: domain.MethodPassword, Result: domain.ResultSuccess,
		Detail: map[string]any{"action": audit.ActionAttrDefCreate, "key": key},
	})
	return d, nil
}

// ListAttrDefs returns every attribute def ordered by key.
func (s *Service) ListAttrDefs(ctx context.Context) ([]domain.UserAttrDef, error) {
	if s.attrs == nil {
		return nil, errors.New("user: attribute store is not configured")
	}
	return s.attrs.ListDefs(ctx)
}

// DeleteAttrDef drops a def; its values cascade across all users.
func (s *Service) DeleteAttrDef(ctx context.Context, actorID uuid.UUID, key string) error {
	if s.attrs == nil {
		return errors.New("user: attribute store is not configured")
	}
	if err := s.attrs.DeleteDef(ctx, key); err != nil {
		return err
	}
	_ = s.audit.Record(ctx, domain.AuditEntry{
		ActorUserID: &actorID, Method: domain.MethodPassword, Result: domain.ResultSuccess,
		Detail: map[string]any{"action": audit.ActionAttrDefDelete, "key": key},
	})
	return nil
}

// GetUserAttrs returns one user's custom attributes as typed values:
// single-valued defs are scalars, multi-valued defs are arrays.
func (s *Service) GetUserAttrs(ctx context.Context, userID uuid.UUID) (map[string]any, error) {
	if s.attrs == nil {
		return nil, errors.New("user: attribute store is not configured")
	}
	if _, err := s.users.ByID(ctx, userID); err != nil {
		return nil, err
	}
	defs, err := s.attrs.ListDefs(ctx)
	if err != nil {
		return nil, err
	}
	values, err := s.attrs.ValuesOfUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return domain.TypedAttrValues(defs, values), nil
}

// SetUserAttrs replaces the given keys (scalar or array per key, null
// clears) and returns the user's full typed map. Unknown keys and type
// violations fail the whole write; unmentioned keys are untouched.
func (s *Service) SetUserAttrs(ctx context.Context, actorID, userID uuid.UUID, input map[string]any) (map[string]any, error) {
	if s.attrs == nil {
		return nil, errors.New("user: attribute store is not configured")
	}
	if _, err := s.users.ByID(ctx, userID); err != nil {
		return nil, err
	}
	defs, err := s.attrs.ListDefs(ctx)
	if err != nil {
		return nil, err
	}
	raw, err := domain.NormalizeAttrInput(input)
	if err != nil {
		return nil, err
	}
	canonical, err := domain.ValidateAttrValues(defs, raw)
	if err != nil {
		return nil, err
	}
	byKey := make(map[string]domain.UserAttrDef, len(defs))
	for _, d := range defs {
		byKey[d.Key] = d
	}
	byID := make(map[uuid.UUID][]string, len(canonical))
	keys := make([]string, 0, len(canonical))
	for key, vals := range canonical {
		byID[byKey[key].ID] = vals
		keys = append(keys, key)
	}
	if err := s.attrs.SetValues(ctx, userID, byID, domain.UserAttrAdmin); err != nil {
		return nil, err
	}
	_ = s.audit.Record(ctx, domain.AuditEntry{
		ActorUserID: &actorID, Method: domain.MethodPassword, Result: domain.ResultSuccess,
		Detail: map[string]any{
			"action": audit.ActionUserAttrsUpdate, "target_user_id": userID.String(), "keys": keys,
		},
	})
	values, err := s.attrs.ValuesOfUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return domain.TypedAttrValues(defs, values), nil
}

// applyAdminMapping adds synced directory members of adminGroupDN to
// ih_admin (PRD §6.2). Removal is never automatic: de-admining stays an
// explicit admin action so a directory outage cannot strip all admins.
func (s *Service) applyAdminMapping(ctx context.Context, u domain.User, lu domain.LDAPUser, adminGroupDN string, rep *SyncReport) error {
	if adminGroupDN == "" {
		return nil
	}
	isAdmin := false
	for _, dn := range lu.MemberOf {
		if domain.SameDN(dn, adminGroupDN) {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return nil
	}
	member, err := s.groups.IsMember(ctx, u.ID, domain.AdminGroup)
	if err != nil {
		return fmt.Errorf("user: admin check %q: %w", lu.Username, err)
	}
	if member {
		return nil
	}
	admin, err := s.groups.ByName(ctx, domain.AdminGroup)
	if err != nil {
		return fmt.Errorf("user: load %s: %w", domain.AdminGroup, err)
	}
	if err := s.groups.AddMember(ctx, u.ID, admin.ID); err != nil {
		return fmt.Errorf("user: map admin %q: %w", lu.Username, err)
	}
	rep.AdminAdded = append(rep.AdminAdded, lu.Username)
	return nil
}

// softDisableMissing disables LDAP-source users absent from the snapshot.
// Local users are never touched by sync.
func (s *Service) softDisableMissing(ctx context.Context, seen map[string]bool, rep *SyncReport) error {
	const pageSize = 200
	offset := 0
	for {
		users, total, err := s.users.List(ctx, domain.UserFilter{Source: domain.SourceLDAP, Limit: pageSize, Offset: offset})
		if err != nil {
			return fmt.Errorf("user: sync list: %w", err)
		}
		for _, u := range users {
			if !seen[u.Username] && u.IsActive {
				if err := s.users.SetActive(ctx, u.ID, false); err != nil {
					return fmt.Errorf("user: sync disable %q: %w", u.Username, err)
				}
				rep.Disabled++
			}
		}
		offset += len(users)
		if offset >= total || len(users) == 0 {
			return nil
		}
	}
}

// reconcileGroups creates directory-matched groups and reconciles their
// membership to the directory listing. Local-only groups (no directory
// counterpart) and ih_admin membership are never touched.
func (s *Service) reconcileGroups(ctx context.Context, dirGroups []domain.LDAPGroup) error {
	for _, dg := range dirGroups {
		if dg.Name == "" || dg.Name == domain.AdminGroup {
			continue
		}
		g, err := s.groups.ByName(ctx, dg.Name)
		if errors.Is(err, domain.ErrNotFound) {
			g, err = s.groups.Create(ctx, domain.Group{Name: dg.Name, Description: "Synced from LDAP"})
			if err != nil {
				if errors.Is(err, domain.ErrConflict) {
					continue // raced with an admin create; next sync converges
				}
				return fmt.Errorf("user: sync create group %q: %w", dg.Name, err)
			}
		} else if err != nil {
			return fmt.Errorf("user: sync group lookup %q: %w", dg.Name, err)
		}
		want := make(map[uuid.UUID]bool, len(dg.Members))
		for _, memberDN := range dg.Members {
			u, err := s.userByDN(ctx, memberDN)
			if err != nil {
				if errors.Is(err, domain.ErrNotFound) {
					continue // member outside our synced user base
				}
				// Never reconcile from a partial listing: a failed
				// lookup must abort, not silently empty the group.
				return fmt.Errorf("user: sync resolve %q: %w", memberDN, err)
			}
			if u.ID == uuid.Nil {
				continue
			}
			want[u.ID] = true
			if err := s.groups.AddMember(ctx, u.ID, g.ID); err != nil {
				return fmt.Errorf("user: sync add %q to %q: %w", u.Username, dg.Name, err)
			}
		}
		current, err := s.groups.MemberIDs(ctx, g.ID)
		if err != nil {
			return fmt.Errorf("user: sync members %q: %w", dg.Name, err)
		}
		for _, id := range current {
			if !want[id] {
				if err := s.groups.RemoveMember(ctx, id, g.ID); err != nil {
					return fmt.Errorf("user: sync remove from %q: %w", dg.Name, err)
				}
			}
		}
	}
	return nil
}

// userByDN resolves a member DN to a synced LDAP user by scanning LDAP
// rows. Directories with huge user bases page through List; the scan
// stops at the first DN match.
func (s *Service) userByDN(ctx context.Context, dn string) (domain.User, error) {
	const pageSize = 200
	offset := 0
	for {
		users, total, err := s.users.List(ctx, domain.UserFilter{Source: domain.SourceLDAP, Limit: pageSize, Offset: offset})
		if err != nil {
			return domain.User{}, err
		}
		for _, u := range users {
			if domain.SameDN(u.ExternalDN, dn) {
				return u, nil
			}
		}
		offset += len(users)
		if offset >= total || len(users) == 0 {
			return domain.User{}, domain.ErrNotFound
		}
	}
}
