package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	goldapmessage "github.com/lor00x/goldap/message"
	ldapserver "github.com/vjeantet/ldapserver"

	"github.com/identityhub/identityhub/internal/domain"
	usecaseauth "github.com/identityhub/identityhub/internal/usecase/auth"
)

// LDAP search scopes (RFC 4511 §4.5.1.2).
const (
	scopeBaseObject   = 0
	scopeSingleLevel  = 1
	scopeWholeSubtree = 2
)

// handleBind verifies uid=<username>,ou=users,dc=identityhub + password
// through usecase/auth. Anonymous binds and malformed DNs are protocol
// rejections (not audited, like undecodable HTTP bodies); every real
// credential check is audited inside LoginLegacy.
func (s *Server) handleBind(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	r := m.GetBindRequest()
	ip := peerIP(m)
	fail := func(code int, diag string) {
		res := ldapserver.NewBindResponse(code)
		res.SetDiagnosticMessage(diag)
		w.Write(res)
	}
	if r.AuthenticationChoice() != "simple" {
		fail(ldapserver.LDAPResultAuthMethodNotSupported, "only simple bind is supported")
		return
	}
	dn := string(r.Name())
	password := string(r.AuthenticationSimple())
	if dn == "" || password == "" {
		fail(ldapserver.LDAPResultInvalidCredentials, "invalid credentials")
		return
	}
	username, err := ParseBindDN(dn)
	if err != nil {
		fail(ldapserver.LDAPResultInvalidCredentials, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Recently verified local binds skip argon2 through the bind cache.
	// The cached path still re-checks live account state and audits, so
	// its result mapping is identical to the full login below.
	if uid, ok := s.cachedBindUser(ctx, username, password); ok {
		u, err := s.auth.ConfirmCachedBind(ctx, uid, domain.MethodLDAP, ip)
		s.writeBindResult(w, m, u, err, username, ip)
		return
	}
	u, err := s.auth.LoginLegacy(ctx, usecaseauth.LegacyLoginInput{
		Username: username, Password: password, IP: ip, Method: domain.MethodLDAP,
	})
	if err == nil && u.Source == domain.SourceLocal {
		s.rememberBind(ctx, username, password, u.ID)
	}
	s.writeBindResult(w, m, u, err, username, ip)
}

// writeBindResult maps a legacy login outcome to the bind response.
func (s *Server) writeBindResult(w ldapserver.ResponseWriter, m *ldapserver.Message, u domain.User, err error, username, ip string) {
	fail := func(code int, diag string) {
		res := ldapserver.NewBindResponse(code)
		res.SetDiagnosticMessage(diag)
		w.Write(res)
	}
	switch {
	case err == nil:
		s.markBound(m.Client, u.Username)
		s.log.Info("ldap bind", "username", u.Username, "ip", ip)
		w.Write(ldapserver.NewBindResponse(ldapserver.LDAPResultSuccess))
	case errors.Is(err, usecaseauth.ErrMFARequired):
		fail(ldapserver.LDAPResultInvalidCredentials, err.Error())
	case errors.Is(err, domain.ErrForbidden):
		fail(ldapserver.LDAPResultInvalidCredentials, "account disabled")
	case errors.Is(err, usecaseauth.ErrDirectoryUnavailable):
		s.log.Error("ldap bind: directory unavailable", "username", username, "ip", ip)
		fail(ldapserver.LDAPResultUnavailable, "directory unavailable, try again later")
	default:
		fail(ldapserver.LDAPResultInvalidCredentials, "invalid credentials")
	}
}

// cachedBindUser resolves recently verified credentials to their user.
// A version-query failure is a miss (the full login runs instead); the
// cache never serves when it cannot prove freshness.
func (s *Server) cachedBindUser(ctx context.Context, username, password string) (uuid.UUID, bool) {
	if s.version == nil {
		return uuid.Nil, false
	}
	v, err := s.version.Current(ctx)
	if err != nil {
		return uuid.Nil, false
	}
	return s.bindCache.lookup(bindCacheKey(username, password), v)
}

// rememberBind records a verified local bind under the current
// generation (best-effort: a version-query failure simply skips the
// cache entry).
func (s *Server) rememberBind(ctx context.Context, username, password string, userID uuid.UUID) {
	if s.version == nil {
		return
	}
	if v, err := s.version.Current(ctx); err == nil {
		s.bindCache.store(bindCacheKey(username, password), userID, v)
	}
}

// handleSearch serves the users/groups tree to bound connections only:
// anonymous clients learn nothing about directory contents.
func (s *Server) handleSearch(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	r := m.GetSearchRequest()
	// SearchResultDone carries no diagnostic message in this library
	// version, so failures are result codes plus server-side logs.
	done := func(code int) {
		w.Write(ldapserver.NewSearchResultDoneResponse(code))
	}
	if !s.isBound(m.Client) {
		done(ldapserver.LDAPResultInsufficientAccessRights)
		return
	}
	base := strings.TrimSpace(string(r.BaseObject()))
	scope := int(r.Scope())
	f, err := parseFilter(r.FilterString())
	if err != nil {
		s.log.Warn("ldap search: bad filter", "filter", r.FilterString(), "ip", peerIP(m))
		done(ldapserver.LDAPResultProtocolError)
		return
	}
	if f.unsupported() {
		s.log.Warn("ldap search uses ordering or extensible matching, which never matches here",
			"filter", r.FilterString(), "ip", peerIP(m))
	}
	// Attribute selection: empty or "*" means all user attributes.
	want := map[string]bool{}
	for _, a := range r.Attributes() {
		want[strings.ToLower(string(a))] = true
	}
	allAttrs := len(want) == 0 || want["*"]
	typesOnly := bool(r.TypesOnly())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	candidates, noSuch, err := s.collectEntries(ctx, base, scope, f)
	if err != nil {
		s.log.Error("ldap search failed", "base", base, "error", err)
		done(ldapserver.LDAPResultOperationsError)
		return
	}
	if noSuch {
		done(ldapserver.LDAPResultNoSuchObject)
		return
	}
	var matched []*entry
	for _, e := range candidates {
		if f.match(*e) {
			matched = append(matched, e)
		}
	}
	sizeLimit := int(r.SizeLimit())
	code := ldapserver.LDAPResultSuccess
	if sizeLimit > 0 && len(matched) > sizeLimit {
		matched = matched[:sizeLimit]
		code = ldapserver.LDAPResultSizeLimitExceeded
	}
	for _, e := range matched {
		writeEntry(w, e, want, allAttrs, typesOnly)
	}
	done(code)
}

// handleStartTLS upgrades the connection to TLS in starttls mode (the
// library runs this handler synchronously so no request interleaves
// with the handshake). The bind state resets across the upgrade: the
// client re-binds over the encrypted channel.
func (s *Server) handleStartTLS(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	if s.mode != ModeStartTLS {
		res := ldapserver.NewExtendedResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetResponseName(ldapserver.NoticeOfStartTLS)
		if s.mode == ModeLDAPS {
			res.SetDiagnosticMessage("connection is already encrypted")
		} else {
			res.SetDiagnosticMessage("TLS is not configured on this server")
		}
		w.Write(res)
		return
	}
	tlsConn := tls.Server(m.Client.GetConn(), s.tlsConfig)
	res := ldapserver.NewExtendedResponse(ldapserver.LDAPResultSuccess)
	res.SetResponseName(ldapserver.NoticeOfStartTLS)
	w.Write(res)
	if err := tlsConn.Handshake(); err != nil {
		s.log.Warn("ldap starttls handshake failed", "ip", peerIP(m), "error", err)
		return
	}
	m.Client.SetConn(tlsConn)
	s.clearBound(m.Client)
	s.log.Info("ldap starttls established", "ip", peerIP(m))
}

// handleNotFound rejects directory mutations and every other operation
// the read-only provider does not implement.
func handleNotFound(w ldapserver.ResponseWriter, r *ldapserver.Message) {
	res := ldapserver.NewResponse(ldapserver.LDAPResultUnwillingToPerform)
	res.SetDiagnosticMessage("operation not supported by this server")
	w.Write(res)
}

// collectEntries resolves base+scope to candidate entries. noSuch is
// true when the base DN names nothing in the tree.
func (s *Server) collectEntries(ctx context.Context, base string, scope int, f *filter) (out []*entry, noSuch bool, err error) {
	if base == "" {
		if scope == scopeBaseObject {
			return []*entry{rootDSE()}, false, nil
		}
		return nil, true, nil
	}
	// Point lookups — a bare (uid=x) or an AND containing one — resolve
	// to one indexed row instead of a full tree scan. Container entries
	// carry no uid, so they could never match such a filter anyway.
	if uid, ok := shortCircuitUID(f); ok && userEntriesInScope(base, scope) {
		e, found, err := s.userEntryByName(ctx, uid)
		if err != nil {
			return nil, false, err
		}
		if !found {
			return nil, false, nil
		}
		return []*entry{e}, false, nil
	}
	switch {
	case sameDN(base, BaseDN):
		switch scope {
		case scopeBaseObject:
			return []*entry{domainEntry()}, false, nil
		case scopeSingleLevel:
			return []*entry{ouEntry("users"), ouEntry("groups")}, false, nil
		default:
			return s.wholeTree(ctx)
		}
	case sameDN(base, UsersDN):
		users, memberOf, custom, err := s.activeUsers(ctx)
		if err != nil {
			return nil, false, err
		}
		if scope == scopeBaseObject {
			return []*entry{ouEntry("users")}, false, nil
		}
		entries := userEntries(users, memberOf, custom)
		if scope == scopeWholeSubtree {
			entries = append([]*entry{ouEntry("users")}, entries...)
		}
		return entries, false, nil
	case sameDN(base, GroupsDN):
		groups, members, err := s.groupMembers(ctx)
		if err != nil {
			return nil, false, err
		}
		if scope == scopeBaseObject {
			return []*entry{ouEntry("groups")}, false, nil
		}
		entries := groupEntries(groups, members)
		if scope == scopeWholeSubtree {
			entries = append([]*entry{ouEntry("groups")}, entries...)
		}
		return entries, false, nil
	default:
		// Base scope on a leaf DN (a bind DN read-back or a group DN).
		if scope == scopeBaseObject {
			if e, found, err := s.leafEntry(ctx, base); err != nil || found {
				return []*entry{e}, false, err
			}
		}
		return nil, true, nil
	}
}

// userEntriesInScope reports whether user entries can appear among the
// candidates for base+scope (the (uid=...) short-circuit applies only
// then; container-only scopes keep the generic path).
func userEntriesInScope(base string, scope int) bool {
	if sameDN(base, UsersDN) {
		return scope != scopeBaseObject
	}
	return sameDN(base, BaseDN) && scope == scopeWholeSubtree
}

// userEntryByName resolves one username to its entry for the (uid=...)
// short-circuit. Like the tree scan, inactive users do not exist.
func (s *Server) userEntryByName(ctx context.Context, username string) (*entry, bool, error) {
	u, err := s.users.ByUsernameFold(ctx, username)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && !u.IsActive) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	groups, err := s.groups.GroupsOfUser(ctx, u.ID)
	if err != nil {
		return nil, false, err
	}
	var memberOf []string
	for _, g := range groups {
		memberOf = append(memberOf, GroupDN(g.Name))
	}
	var custom map[string][]string
	if s.attrs != nil {
		custom, err = s.attrs.ValuesOfUser(ctx, u.ID)
		if err != nil {
			return nil, false, err
		}
	}
	return userEntry(u, memberOf, custom), true, nil
}

// leafEntry resolves a user or group DN to its entry for base-scope
// reads. Inactive users do not exist in the tree.
func (s *Server) leafEntry(ctx context.Context, base string) (*entry, bool, error) {
	if username, err := ParseBindDN(base); err == nil {
		u, err := s.users.ByUsername(ctx, username)
		if errors.Is(err, domain.ErrNotFound) || (err == nil && !u.IsActive) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		groups, err := s.groups.GroupsOfUser(ctx, u.ID)
		if err != nil {
			return nil, false, err
		}
		var memberOf []string
		for _, g := range groups {
			memberOf = append(memberOf, GroupDN(g.Name))
		}
		var custom map[string][]string
		if s.attrs != nil {
			custom, err = s.attrs.ValuesOfUser(ctx, u.ID)
			if err != nil {
				return nil, false, err
			}
		}
		return userEntry(u, memberOf, custom), true, nil
	}
	dn, err := parseGroupDN(base)
	if err != nil {
		return nil, false, nil
	}
	g, err := s.groups.ByName(ctx, dn)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	members, err := s.memberDNs(ctx, g.ID)
	if err != nil {
		return nil, false, err
	}
	return groupEntry(g, members), true, nil
}

// wholeTree returns every entry under the base DN.
func (s *Server) wholeTree(ctx context.Context) ([]*entry, bool, error) {
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, false, err
	}
	out := []*entry{domainEntry(), ouEntry("users"), ouEntry("groups")}
	out = append(out, userEntries(snap.users, invertMembers(snap.users, snap.groups, snap.members), snap.custom)...)
	out = append(out, groupEntries(snap.groups, snap.members)...)
	return out, false, nil
}

// snapshot returns the cached whole-directory snapshot, refreshing it
// through loadTree when the version moved or the TTL lapsed.
func (s *Server) snapshot(ctx context.Context) (*treeSnapshot, error) {
	return s.tree.get(ctx, s.loadTree)
}

// loadTree assembles one snapshot: users, groups, one membership join
// and one attribute batch.
func (s *Server) loadTree(ctx context.Context) (*treeSnapshot, error) {
	users, err := s.users.AllActive(ctx)
	if err != nil {
		return nil, err
	}
	groups, members, err := s.loadGroups(ctx)
	if err != nil {
		return nil, err
	}
	custom, err := s.customForUsers(ctx, users)
	if err != nil {
		return nil, err
	}
	return &treeSnapshot{users: users, groups: groups, members: members, custom: custom}, nil
}

// activeUsers lists every active user plus a user-id → group-DN index
// and a user-id → custom-attributes index, served from the snapshot.
func (s *Server) activeUsers(ctx context.Context) ([]domain.User, map[string][]string, map[string]map[string][]string, error) {
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	return snap.users, invertMembers(snap.users, snap.groups, snap.members), snap.custom, nil
}

// customForUsers batch-loads custom attributes keyed by user-ID string.
// A nil store serves no custom attributes.
func (s *Server) customForUsers(ctx context.Context, users []domain.User) (map[string]map[string][]string, error) {
	if s.attrs == nil || len(users) == 0 {
		return nil, nil
	}
	ids := make([]uuid.UUID, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.ID)
	}
	byID, err := s.attrs.ValuesForUsers(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make(map[string]map[string][]string, len(byID))
	for id, vals := range byID {
		out[id.String()] = vals
	}
	return out, nil
}

// invertMembers maps group-id → member user-DNs into user-id → group-DNs.
func invertMembers(users []domain.User, groups []domain.Group, members map[string][]string) map[string][]string {
	idByDN := map[string]string{}
	for _, u := range users {
		idByDN[UserDN(u.Username)] = u.ID.String()
	}
	dnByID := map[string]string{}
	for _, g := range groups {
		dnByID[g.ID.String()] = GroupDN(g.Name)
	}
	out := map[string][]string{}
	for gid, dns := range members {
		gdn, ok := dnByID[gid]
		if !ok {
			continue
		}
		for _, dn := range dns {
			if uid, ok := idByDN[dn]; ok {
				out[uid] = append(out[uid], gdn)
			}
		}
	}
	return out
}

// groupMembers lists every group plus group-id → active-member
// user-DNs, served from the snapshot.
func (s *Server) groupMembers(ctx context.Context) ([]domain.Group, map[string][]string, error) {
	snap, err := s.snapshot(ctx)
	if err != nil {
		return nil, nil, err
	}
	return snap.groups, snap.members, nil
}

// loadGroups lists every group plus group-id → active-member user-DNs
// in two queries: the group list and one membership join.
func (s *Server) loadGroups(ctx context.Context) ([]domain.Group, map[string][]string, error) {
	groups, err := s.groups.All(ctx)
	if err != nil {
		return nil, nil, err
	}
	byGroup, err := s.groups.MemberUsernamesByGroup(ctx)
	if err != nil {
		return nil, nil, err
	}
	members := make(map[string][]string, len(groups))
	for _, g := range groups {
		names := byGroup[g.ID]
		dns := make([]string, 0, len(names))
		for _, n := range names {
			dns = append(dns, UserDN(n))
		}
		members[g.ID.String()] = dns
	}
	return groups, members, nil
}

// memberDNs resolves a group's member ids to user DNs, skipping rows
// that are missing or inactive (they have no entry in the tree). Only
// base-scope group reads use it; subtree listings share the single
// membership join in groupMembers.
func (s *Server) memberDNs(ctx context.Context, groupID uuid.UUID) ([]string, error) {
	ids, err := s.groups.MemberIDs(ctx, groupID)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, id := range ids {
		u, err := s.users.ByID(ctx, id)
		if errors.Is(err, domain.ErrNotFound) || (err == nil && !u.IsActive) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, UserDN(u.Username))
	}
	return out, nil
}

// displayNames maps internal lowercase attribute keys to the canonical
// LDAP names clients expect (go-ldap matches names case-sensitively).
var displayNames = map[string]string{
	"objectclass":          "objectClass",
	"memberof":             "memberOf",
	"displayname":          "displayName",
	"namingcontexts":       "namingContexts",
	"supportedldapversion": "supportedLDAPVersion",
	"vendorname":           "vendorName",
}

// writeEntry writes one search result entry honoring the attribute
// selection.
func writeEntry(w ldapserver.ResponseWriter, e *entry, want map[string]bool, all, typesOnly bool) {
	res := ldapserver.NewSearchResultEntry(e.dn)
	for name, values := range e.attrs {
		if !all && !want[name] {
			continue
		}
		vals := make([]goldapmessage.AttributeValue, 0, len(values))
		if !typesOnly {
			for _, v := range values {
				vals = append(vals, goldapmessage.AttributeValue(v))
			}
		}
		if display, ok := displayNames[name]; ok {
			name = display
		}
		res.AddAttribute(goldapmessage.AttributeDescription(name), vals...)
	}
	w.Write(res)
}

// ---------- entry builders ----------

func rootDSE() *entry {
	return &entry{dn: "", attrs: map[string][]string{
		"objectclass":          {"top"},
		"namingcontexts":       {BaseDN},
		"supportedldapversion": {"3"},
		"vendorname":           {"IdentityHub"},
	}}
}

func domainEntry() *entry {
	return &entry{dn: BaseDN, attrs: map[string][]string{
		"objectclass": {"top", "domain"},
		"dc":          {"identityhub"},
	}}
}

func ouEntry(name string) *entry {
	return &entry{dn: "ou=" + name + "," + BaseDN, attrs: map[string][]string{
		"objectclass": {"top", "organizationalUnit"},
		"ou":          {name},
	}}
}

func userEntries(users []domain.User, memberOf map[string][]string, custom map[string]map[string][]string) []*entry {
	out := make([]*entry, 0, len(users))
	for _, u := range users {
		out = append(out, userEntry(u, memberOf[u.ID.String()], custom[u.ID.String()]))
	}
	return out
}

func userEntry(u domain.User, memberOf []string, custom map[string][]string) *entry {
	cn := u.DisplayName
	if cn == "" {
		cn = u.Username
	}
	attrs := map[string][]string{
		"objectclass": {"top", "person", "organizationalPerson", "inetOrgPerson"},
		"uid":         {u.Username},
		"cn":          {cn},
		"sn":          {cn},
		"displayname": {cn},
	}
	if u.Email != "" {
		attrs["mail"] = []string{u.Email}
	}
	if len(memberOf) > 0 {
		attrs["memberof"] = memberOf
	}
	// Custom keys are lowercase LDAP-safe and never collide with the
	// built-ins (reserved at def creation), so they merge directly.
	for key, vals := range custom {
		if len(vals) > 0 {
			attrs[key] = vals
		}
	}
	return &entry{dn: UserDN(u.Username), attrs: attrs}
}

func groupEntries(groups []domain.Group, members map[string][]string) []*entry {
	out := make([]*entry, 0, len(groups))
	for _, g := range groups {
		out = append(out, groupEntry(g, members[g.ID.String()]))
	}
	return out
}

func groupEntry(g domain.Group, members []string) *entry {
	attrs := map[string][]string{
		"objectclass": {"top", "groupOfNames"},
		"cn":          {g.Name},
	}
	if len(members) > 0 {
		attrs["member"] = members
	}
	if g.Description != "" {
		attrs["description"] = []string{g.Description}
	}
	return &entry{dn: GroupDN(g.Name), attrs: attrs}
}

// ---------- bound-state tracking ----------

// markBound records a successful bind for the connection, sliding the
// lifetime and sweeping expired entries.
func (s *Server) markBound(client any, username string) {
	s.bindsMutex.Lock()
	defer s.bindsMutex.Unlock()
	now := time.Now()
	for c, b := range s.binds {
		if now.After(b.expires) {
			delete(s.binds, c)
		}
	}
	s.binds[client] = boundConn{username: username, expires: now.Add(bindLifetime)}
}

// isBound reports whether the connection holds a live bind, sliding
// its lifetime on success.
func (s *Server) isBound(client any) bool {
	s.bindsMutex.Lock()
	defer s.bindsMutex.Unlock()
	b, ok := s.binds[client]
	if !ok || time.Now().After(b.expires) {
		delete(s.binds, client)
		return false
	}
	b.expires = time.Now().Add(bindLifetime)
	s.binds[client] = b
	return true
}

// clearBound drops any bind for the connection (StartTLS upgrade).
func (s *Server) clearBound(client any) {
	s.bindsMutex.Lock()
	defer s.bindsMutex.Unlock()
	delete(s.binds, client)
}

// peerIP returns the peer IP without the port for audit and logs.
func peerIP(m *ldapserver.Message) string {
	if m == nil || m.Client == nil || m.Client.Addr() == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(m.Client.Addr().String())
	if err != nil {
		return m.Client.Addr().String()
	}
	return host
}

// parseGroupDN extracts the group name from cn=<name>,ou=groups,<base>.
func parseGroupDN(dn string) (string, error) {
	rest, ok := cutPrefixFold(strings.TrimSpace(dn), "cn=")
	if !ok {
		return "", errors.New("not a group dn")
	}
	comma := strings.Index(rest, ",")
	if comma < 0 {
		return "", errors.New("not a group dn")
	}
	name := unescapeDNValue(strings.TrimSpace(rest[:comma]))
	tail := strings.TrimSpace(rest[comma+1:])
	if name == "" || !sameDN(tail, GroupsDN) {
		return "", errors.New("not a group dn")
	}
	return name, nil
}

// cutPrefixFold cuts prefix case-insensitively.
func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return "", false
	}
	return s[len(prefix):], true
}

// unescapeDNValue decodes backslash escapes in a DN attribute value.
func unescapeDNValue(v string) string {
	if !strings.Contains(v, "\\") {
		return v
	}
	var b strings.Builder
	esc := false
	for _, r := range v {
		if esc {
			b.WriteRune(r)
			esc = false
			continue
		}
		if r == '\\' {
			esc = true
			continue
		}
		b.WriteRune(r)
	}
	if esc {
		b.WriteByte('\\')
	}
	return b.String()
}
