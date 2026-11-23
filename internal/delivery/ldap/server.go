package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	ldapserver "github.com/vjeantet/ldapserver"

	"github.com/identityhub/identityhub/internal/domain"
	usecaseauth "github.com/identityhub/identityhub/internal/usecase/auth"
)

// Config wires one LDAP listener (TECH_SPEC §6.4).
type Config struct {
	// Mode is ldap (plaintext), ldaps (TLS-wrapped listener) or
	// starttls (plaintext port with the StartTLS extended operation).
	Mode string
	// Addr is the TCP listen address, e.g. ":1389".
	Addr string
	// AllowedCIDRs is the IP whitelist, enforced in OnNewConnection
	// before any LDAP bytes are parsed. Plaintext mode requires it;
	// empty means no restriction in TLS modes.
	AllowedCIDRs []*net.IPNet
	// TLSCertFile/TLSKeyFile hold the managed certificate pair for
	// ldaps/starttls modes.
	TLSCertFile string
	TLSKeyFile  string
	// TLSConfig overrides the file pair (tests inject an in-memory
	// certificate). The minimum version is still raised to TLS 1.2.
	TLSConfig *tls.Config
	// CacheTTL bounds whole-tree snapshots (LDAP_CACHE_TTL). Snapshots
	// also refresh when the directory version moves; <=0 disables the
	// tree cache (every search reads fresh).
	CacheTTL time.Duration
	// BindCacheTTL bounds remembered local binds (LDAP_BIND_CACHE_TTL).
	// <=0, or a nil Version store, disables the bind cache.
	BindCacheTTL time.Duration
	// BaseDN overrides the served naming context
	// (LDAP_SERVE_BASE_DN). Empty serves the default dc=identityhub
	// tree; ou=users/ou=groups stay fixed either way.
	BaseDN string
}

// Deps wires the server to the shared usecases.
type Deps struct {
	Auth   *usecaseauth.Service
	Users  domain.UserStore
	Groups domain.GroupStore
	// Attrs serves custom attributes; nil omits them (tests that
	// predate the schema).
	Attrs domain.UserAttrStore
	// Version reads the directory generation for cache invalidation;
	// nil runs the tree cache TTL-only and disables the bind cache
	// (tests that predate the schema).
	Version domain.DirectoryVersioner
	Log     *slog.Logger
}

// Server is one in-process LDAP listener. It is single-use: call Serve
// once, then Stop.
type Server struct {
	mode      string
	addr      string
	dn        DNTree
	srv       *ldapserver.Server
	auth      *usecaseauth.Service
	users     domain.UserStore
	groups    domain.GroupStore
	attrs     domain.UserAttrStore
	log       *slog.Logger
	tlsConfig *tls.Config
	ready     chan struct{}
	stopOnce  sync.Once
	// rawListener is the TCP listener under the (optional) TLS
	// wrapper; Stop sets a past deadline on it to unblock Accept.
	rawListener net.Listener
	rawMutex    sync.Mutex
	// tree and binds cache whole-directory snapshots and verified
	// local binds; version gates the bind cache (never TTL-only).
	version   domain.DirectoryVersioner
	tree      *treeCache
	bindCache *bindCache
}

// trackedConn wraps one accepted connection so the bind state lives
// exactly as long as the connection itself (RFC 4511: a bind
// authorizes the connection until unbind, re-bind or close — never a
// timer). Pooling clients such as Stalwart only bind when they open a
// connection; expiring that bind mid-connection makes the pool fail
// every operation without ever reconnecting, until the client
// restarts. Short-lived binders (Harbor, Sonar) never notice because
// they bind per operation. When the connection closes the wrapper is
// garbage-collected with it, so no sweeper or expiry map is needed.
type trackedConn struct {
	net.Conn
	mu    sync.Mutex
	bound bool
}

func (c *trackedConn) markBound() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bound = true
}

func (c *trackedConn) isBound() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bound
}

// trackingListener wraps every accepted connection in a trackedConn.
type trackingListener struct {
	net.Listener
}

func (l *trackingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &trackedConn{Conn: c}, nil
}

// New validates cfg, loads TLS material for the TLS modes, and builds
// the routed server. It quiets the library's stdout logger process-wide
// (handlers log through slog instead).
func New(cfg Config, d Deps) (*Server, error) {
	switch cfg.Mode {
	case ModePlain, ModeLDAPS, ModeStartTLS:
	default:
		return nil, fmt.Errorf("ldap: mode must be ldap, ldaps or starttls, got %q", cfg.Mode)
	}
	if cfg.Addr == "" {
		return nil, errors.New("ldap: addr is required")
	}
	if cfg.Mode == ModePlain && len(cfg.AllowedCIDRs) == 0 {
		return nil, errors.New("ldap: plaintext mode requires a non-empty IP whitelist")
	}
	if d.Auth == nil || d.Users == nil || d.Groups == nil {
		return nil, errors.New("ldap: Auth, Users and Groups are required")
	}
	base := strings.TrimSpace(cfg.BaseDN)
	if base == "" {
		base = BaseDN
	}
	tree, err := NewDNTree(base)
	if err != nil {
		return nil, err
	}
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	s := &Server{
		mode: cfg.Mode, addr: cfg.Addr, dn: tree,
		auth: d.Auth, users: d.Users, groups: d.Groups, attrs: d.Attrs, log: log,
		ready:   make(chan struct{}),
		version: d.Version,
	}
	s.tree = newTreeCache(d.Version, cfg.CacheTTL, log)
	bindTTL := cfg.BindCacheTTL
	if d.Version == nil {
		// A bind cache without version invalidation would honor
		// changed passwords until the TTL lapses; TTL-only is fine
		// for the visible tree, never for credentials.
		bindTTL = 0
	}
	s.bindCache = newBindCache(bindTTL)
	if cfg.Mode == ModeLDAPS || cfg.Mode == ModeStartTLS {
		tlsCfg, err := loadTLSConfig(cfg)
		if err != nil {
			return nil, err
		}
		s.tlsConfig = tlsCfg
	}
	ldapserver.Logger = ldapserver.DiscardingLogger
	// Per-connection panics (malformed packets) close only the
	// offending connection; report them with the peer IP instead
	// of failing silently.
	ldapserver.OnPanic = func(addr string, recovered any, _ []byte) {
		log.Warn("ldap recovered client panic", "ip", addr, "panic", recovered)
	}
	srv := ldapserver.NewServer()
	srv.OnNewConnection = allowConn(cfg.AllowedCIDRs, log)
	routes := ldapserver.NewRouteMux()
	routes.Bind(s.handleBind)
	routes.Search(s.handleSearch)
	routes.Extended(s.handleStartTLS).RequestName(ldapserver.NoticeOfStartTLS).Label("StartTLS")
	routes.NotFound(handleNotFound)
	srv.Handle(routes)
	s.srv = srv
	return s, nil
}

// loadTLSConfig builds the server TLS config (TECH_SPEC §8: TLS 1.2
// minimum, managed certificates).
func loadTLSConfig(cfg Config) (*tls.Config, error) {
	if cfg.TLSConfig != nil {
		out := cfg.TLSConfig.Clone()
		if out.MinVersion < tls.VersionTLS12 {
			out.MinVersion = tls.VersionTLS12
		}
		return out, nil
	}
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		return nil, fmt.Errorf("ldap: TLS certificate and key files are required for mode %s", cfg.Mode)
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("ldap: load TLS certificate: %w", err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}, nil
}

// Serve blocks serving LDAP until Stop is called. It returns a bind
// failure immediately, or nil after a clean Stop.
func (s *Server) Serve() error {
	tlsCfg := s.tlsConfig
	// One option: capture the raw listener, wrap it for ldaps, then
	// signal ready — so Addr is final once Ready fires.
	opts := []func(*ldapserver.Server){func(srv *ldapserver.Server) {
		s.rawMutex.Lock()
		s.rawListener = srv.Listener
		s.rawMutex.Unlock()
		if s.mode == ModeLDAPS {
			srv.Listener = tls.NewListener(srv.Listener, tlsCfg)
		}
		// Track after the TLS wrap so GetConn returns the wrapper in
		// every mode (starttls re-wraps on upgrade in handleStartTLS).
		srv.Listener = &trackingListener{srv.Listener}
		close(s.ready)
	}}
	return s.srv.ListenAndServe(s.addr, opts...)
}

// Ready closes once the listener accepts connections; Addr is valid
// after that.
func (s *Server) Ready() <-chan struct{} { return s.ready }

// Addr returns the bound listener address (valid after Ready).
func (s *Server) Addr() net.Addr {
	if s.srv == nil || s.srv.Listener == nil {
		return nil
	}
	return s.srv.Listener.Addr()
}

// Stop shuts the server down. The library's Stop only closes its done
// channel while the accept loop blocks; closing the listener instead
// would crash the loop on a nil connection, and a wakeup dial would
// race a whitelist rejection against the shutdown notice — so Stop
// sets a past deadline on the raw TCP listener. The loop treats the
// resulting Accept timeout as "recheck the done channel and exit",
// which is deterministic and opens no connection. A client
// disconnect landing exactly inside Stop can still trip a
// send-on-closed race inside the library; that panic can only fire
// during shutdown (the process is exiting anyway), never while
// serving.
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		done := make(chan struct{})
		go func() {
			s.srv.Stop()
			close(done)
		}()
		s.rawMutex.Lock()
		raw := s.rawListener
		s.rawMutex.Unlock()
		if tl, ok := raw.(*net.TCPListener); ok {
			_ = tl.SetDeadline(time.Now())
		}
		<-done
	})
}

// allowConn builds the OnNewConnection hook: connections outside the
// whitelist are rejected before any LDAP bytes are parsed (TECH_SPEC
// §6.4). An empty whitelist restricts nothing (TLS modes without one).
//
// Rejection closes the connection inside the hook instead of returning
// an error: the library panics closing a nil response channel on the
// hook-error path, while a pre-closed connection simply EOFs its first
// read and tears down cleanly. Either way the server parses nothing.
func allowConn(nets []*net.IPNet, log *slog.Logger) func(net.Conn) error {
	reject := func(c net.Conn, host string) error {
		log.Warn("ldap connection rejected by whitelist", "ip", host)
		_ = c.Close()
		return nil
	}
	return func(c net.Conn) error {
		if c == nil || c.RemoteAddr() == nil {
			return errors.New("ldap: nil connection")
		}
		if len(nets) == 0 {
			return nil
		}
		addr := ""
		if c.RemoteAddr() != nil {
			addr = c.RemoteAddr().String()
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return reject(c, host)
		}
		for _, n := range nets {
			if n.Contains(ip) {
				return nil
			}
		}
		return reject(c, host)
	}
}
