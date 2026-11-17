// Package ldapclient implements domain.Directory against an upstream LDAP
// directory with go-ldap (TECH_SPEC §2). It backs both login binds and the
// worker's periodic sync (PRD §6.2).
//
// Every network operation is bounded by Config.Timeout: directory failures
// surface explicit errors, never a hanging page (PRD §5.1).
package ldapclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/identityhub/identityhub/internal/domain"
)

// Default attribute mapping (PRD §6.2). v1 uses conventional attribute
// names; per-deployment overrides ride on Config fields.
const (
	DefaultUserAttr        = "uid"
	DefaultMailAttr        = "mail"
	DefaultDisplayNameAttr = "displayName"
	DefaultDisplayFallback = "cn"
	DefaultMemberOfAttr    = "memberOf"
	DefaultGroupNameAttr   = "cn"
	DefaultGroupMemberAttr = "member"
)

// Config mirrors internal/config LDAPConfig plus attribute mapping.
type Config struct {
	URL          string // ldap://host:port or ldaps://host:port
	BindDN       string
	BindPassword string
	BaseDN       string
	UserFilter   string
	GroupFilter  string
	AdminGroupDN string
	Timeout      time.Duration
	// Attribute mapping; empty fields take the Default* values.
	UserAttr        string
	MailAttr        string
	DisplayNameAttr string
	MemberOfAttr    string
	GroupNameAttr   string
	GroupMemberAttr string
	// TLSConfig overrides the default TLS client config for ldaps://
	// (tests inject an insecure config; production uses system roots).
	TLSConfig *tls.Config
}

func (c *Config) withDefaults() Config {
	out := *c
	if out.UserAttr == "" {
		out.UserAttr = DefaultUserAttr
	}
	if out.MailAttr == "" {
		out.MailAttr = DefaultMailAttr
	}
	if out.DisplayNameAttr == "" {
		out.DisplayNameAttr = DefaultDisplayNameAttr
	}
	if out.MemberOfAttr == "" {
		out.MemberOfAttr = DefaultMemberOfAttr
	}
	if out.GroupNameAttr == "" {
		out.GroupNameAttr = DefaultGroupNameAttr
	}
	if out.GroupMemberAttr == "" {
		out.GroupMemberAttr = DefaultGroupMemberAttr
	}
	return out
}

// Validate rejects unusable connector settings at boot, before the first
// dial.
func (c Config) Validate() error {
	if c.URL == "" {
		return errors.New("ldapclient: URL is required")
	}
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Host == "" {
		return fmt.Errorf("ldapclient: invalid URL %q: want ldap(s)://host[:port]", c.URL)
	}
	if c.BaseDN == "" {
		return errors.New("ldapclient: BaseDN is required")
	}
	if c.Timeout <= 0 {
		return errors.New("ldapclient: Timeout must be positive")
	}
	return nil
}

// Client is the production domain.Directory.
type Client struct {
	cfg Config
}

// New builds a Client; it validates but does not dial.
func New(cfg Config) (*Client, error) {
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Client{cfg: cfg}, nil
}

// AdminGroupDN exposes the configured directory admin-group DN for the
// sync applier (usecase/user matches membership against it).
func (c *Client) AdminGroupDN() string { return c.cfg.AdminGroupDN }

func (c *Client) dial(ctx context.Context) (*ldap.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("ldap dial %s: %w", redactURL(c.cfg.URL), err)
	}
	u, err := url.Parse(c.cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("ldap dial %s: %w", redactURL(c.cfg.URL), err)
	}
	dialer := &net.Dialer{Timeout: c.cfg.Timeout}
	opts := []ldap.DialOpt{ldap.DialWithDialer(dialer)}
	if u.Scheme == "ldaps" {
		tlsCfg := c.cfg.TLSConfig
		if tlsCfg == nil {
			tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
		}
		opts = append(opts, ldap.DialWithTLSConfig(tlsCfg))
	}
	conn, err := ldap.DialURL(c.cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("ldap dial %s: %w", redactURL(c.cfg.URL), err)
	}
	conn.SetTimeout(c.cfg.Timeout)
	return conn, nil
}

// searchTimeout bounds one search request in whole seconds (go-ldap's
// NewSearchRequest takes an int); sub-second timeouts round up to 1s.
func (c *Client) searchTimeout() int {
	if s := int(c.cfg.Timeout / time.Second); s > 0 {
		return s
	}
	return 1
}

// serviceBind authenticates the service account (or anonymously when no
// BindDN is configured, for directories that allow anonymous search).
func (c *Client) serviceBind(conn *ldap.Conn) error {
	if c.cfg.BindDN == "" {
		if err := conn.UnauthenticatedBind(""); err != nil {
			return fmt.Errorf("ldap anonymous bind: %w", err)
		}
		return nil
	}
	if err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
		return fmt.Errorf("ldap service bind: %w", err)
	}
	return nil
}

// andFilter ANDs the base match with the optional admin filter.
func andFilter(base, extra string) string {
	if extra == "" {
		return base
	}
	return "(&" + base + extra + ")"
}

// userFilter matches one login name; the name is escaped so usernames
// cannot inject filter syntax.
func (c *Client) userFilter(username string) string {
	return andFilter(fmt.Sprintf("(%s=%s)", c.cfg.UserAttr, ldap.EscapeFilter(username)),
		c.cfg.UserFilter)
}

// allUsersFilter matches every syncable user entry.
func (c *Client) allUsersFilter() string {
	return andFilter(fmt.Sprintf("(%s=*)", c.cfg.UserAttr), c.cfg.UserFilter)
}

// allGroupsFilter matches every syncable group entry.
func (c *Client) allGroupsFilter() string {
	return andFilter("(objectClass=groupOfNames)", c.cfg.GroupFilter)
}

// Ping verifies the connector can reach and bind to the directory (admin
// connection test, TECH_SPEC §6.6 worker health).
func (c *Client) Ping(ctx context.Context) error {
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	return c.serviceBind(conn)
}

// Authenticate binds to the directory as username (PRD §5.1: login can
// bind directly to LDAP). Unknown users map to ErrNotFound so the caller
// can distinguish "not in the directory" from "bad password".
func (c *Client) Authenticate(ctx context.Context, username, password string) (domain.LDAPUser, error) {
	if username == "" || password == "" {
		return domain.LDAPUser{}, domain.ErrUnauthorized
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return domain.LDAPUser{}, err
	}
	defer conn.Close()

	if err := c.serviceBind(conn); err != nil {
		return domain.LDAPUser{}, err
	}
	entry, err := c.findUser(conn, username)
	if err != nil {
		return domain.LDAPUser{}, err
	}
	// The user bind is the actual credential check.
	if err := conn.Bind(entry.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return domain.LDAPUser{}, domain.ErrUnauthorized
		}
		return domain.LDAPUser{}, fmt.Errorf("ldap user bind: %w", err)
	}
	return c.mapUser(entry), nil
}

func (c *Client) findUser(conn *ldap.Conn, username string) (*ldap.Entry, error) {
	req := ldap.NewSearchRequest(c.cfg.BaseDN, ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 2, c.searchTimeout(), false,
		c.userFilter(username),
		[]string{c.cfg.UserAttr, c.cfg.MailAttr, c.cfg.DisplayNameAttr, DefaultDisplayFallback, c.cfg.MemberOfAttr},
		nil)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ldap user search: %w", err)
	}
	if len(res.Entries) == 0 {
		return nil, domain.ErrNotFound
	}
	if len(res.Entries) > 1 {
		return nil, fmt.Errorf("ldap user search for %q returned %d entries, want 1", username, len(res.Entries))
	}
	return res.Entries[0], nil
}

// Snapshot pulls all users and groups for periodic sync (TECH_SPEC §6.6).
func (c *Client) Snapshot(ctx context.Context) (domain.DirectorySnapshot, error) {
	var snap domain.DirectorySnapshot
	conn, err := c.dial(ctx)
	if err != nil {
		return snap, err
	}
	defer conn.Close()

	if err := c.serviceBind(conn); err != nil {
		return snap, err
	}
	users, err := c.searchUsers(conn)
	if err != nil {
		return snap, err
	}
	groups, err := c.searchGroups(conn)
	if err != nil {
		return snap, err
	}
	snap.Users, snap.Groups = users, groups
	return snap, nil
}

func (c *Client) searchUsers(conn *ldap.Conn) ([]domain.LDAPUser, error) {
	req := ldap.NewSearchRequest(c.cfg.BaseDN, ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, c.searchTimeout(), false,
		c.allUsersFilter(),
		[]string{c.cfg.UserAttr, c.cfg.MailAttr, c.cfg.DisplayNameAttr, DefaultDisplayFallback, c.cfg.MemberOfAttr},
		nil)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ldap users search: %w", err)
	}
	out := make([]domain.LDAPUser, 0, len(res.Entries))
	for _, e := range res.Entries {
		u := c.mapUser(e)
		if u.Username == "" {
			continue // skip entries without a login name
		}
		out = append(out, u)
	}
	return out, nil
}

func (c *Client) searchGroups(conn *ldap.Conn) ([]domain.LDAPGroup, error) {
	req := ldap.NewSearchRequest(c.cfg.BaseDN, ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, c.searchTimeout(), false,
		c.allGroupsFilter(),
		[]string{c.cfg.GroupNameAttr, c.cfg.GroupMemberAttr},
		nil)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ldap groups search: %w", err)
	}
	out := make([]domain.LDAPGroup, 0, len(res.Entries))
	for _, e := range res.Entries {
		name := e.GetAttributeValue(c.cfg.GroupNameAttr)
		if name == "" {
			continue
		}
		out = append(out, domain.LDAPGroup{
			Name:    name,
			DN:      e.DN,
			Members: e.GetAttributeValues(c.cfg.GroupMemberAttr),
		})
	}
	return out, nil
}

func (c *Client) mapUser(e *ldap.Entry) domain.LDAPUser {
	name := e.GetAttributeValue(c.cfg.DisplayNameAttr)
	if name == "" {
		name = e.GetAttributeValue(DefaultDisplayFallback)
	}
	return domain.LDAPUser{
		Username:    e.GetAttributeValue(c.cfg.UserAttr),
		Email:       e.GetAttributeValue(c.cfg.MailAttr),
		DisplayName: name,
		DN:          e.DN,
		MemberOf:    e.GetAttributeValues(c.cfg.MemberOfAttr),
	}
}

// SameDN reports DN equality under a normalized comparison (case and
// surrounding whitespace insensitive). LDAP DNs are case-insensitive, so
// the LDAP_ADMIN_GROUP_DN match must not depend on directory casing.
func SameDN(a, b string) bool {
	return normalizeDN(a) == normalizeDN(b)
}

func normalizeDN(dn string) string {
	parts := strings.Split(dn, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return strings.ToLower(strings.Join(parts, ","))
}

// redactURL strips any userinfo before the URL reaches an error (and
// therefore a log line).
func redactURL(raw string) string {
	if i := strings.LastIndex(raw, "@"); i >= 0 {
		if j := strings.Index(raw, "://"); j >= 0 && j < i {
			return raw[:j+3] + raw[i+1:]
		}
	}
	return raw
}

var _ domain.Directory = (*Client)(nil)
