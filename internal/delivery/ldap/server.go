package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
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
}

// Deps wires the server to the shared usecases.
type Deps struct {
	Auth   *usecaseauth.Service
	Users  domain.UserStore
	Groups domain.GroupStore
	Log    *slog.Logger
}

// Server is one in-process LDAP listener. It is single-use: call Serve
// once, then Stop.
type Server struct {
	mode       string
	addr       string
	srv        *ldapserver.Server
	auth       *usecaseauth.Service
	users      domain.UserStore
	groups     domain.GroupStore
	log        *slog.Logger
	tlsConfig  *tls.Config
	ready      chan struct{}
	stopOnce   sync.Once
	binds      map[any]boundConn
	bindsMutex sync.Mutex
}

// boundConn remembers one connection's successful bind. The map key is
// the library's per-connection client pointer (held, so its address can
// never be reused while the entry lives); entries expire so abandoned
// connections do not accumulate.
type boundConn struct {
	username string
	expires  time.Time
}

// bindLifetime bounds how long one bind authorizes searches on its
// connection (sliding on every authenticated operation).
const bindLifetime = 30 * time.Minute

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
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	s := &Server{
		mode: cfg.Mode, addr: cfg.Addr,
		auth: d.Auth, users: d.Users, groups: d.Groups, log: log,
		ready: make(chan struct{}),
		binds: map[any]boundConn{},
	}
	if cfg.Mode == ModeLDAPS || cfg.Mode == ModeStartTLS {
		tlsCfg, err := loadTLSConfig(cfg)
		if err != nil {
			return nil, err
		}
		s.tlsConfig = tlsCfg
	}
	ldapserver.Logger = ldapserver.DiscardingLogger
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
	var opts []func(*ldapserver.Server)
	if s.mode == ModeLDAPS {
		tlsCfg := s.tlsConfig
		opts = append(opts, func(srv *ldapserver.Server) {
			srv.Listener = tls.NewListener(srv.Listener, tlsCfg)
		})
	}
	opts = append(opts, func(*ldapserver.Server) { close(s.ready) })
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
// channel while the accept loop blocks, and closing the listener
// instead would crash the loop on a nil connection — so Stop runs
// async and a wakeup dial lets the loop notice and exit cleanly.
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		done := make(chan struct{})
		go func() {
			s.srv.Stop()
			close(done)
		}()
		if addr := s.Addr(); addr != nil {
			if c, err := net.DialTimeout("tcp", addr.String(), 2*time.Second); err == nil {
				_ = c.Close()
			}
		}
		<-done
	})
}

// allowConn builds the OnNewConnection hook: connections outside the
// whitelist are rejected before any LDAP bytes are parsed (TECH_SPEC
// §6.4). An empty whitelist restricts nothing (TLS modes without one).
func allowConn(nets []*net.IPNet, log *slog.Logger) func(net.Conn) error {
	return func(c net.Conn) error {
		if c == nil || c.RemoteAddr() == nil {
			return errors.New("ldap: nil connection")
		}
		if len(nets) == 0 {
			return nil
		}
		host, _, err := net.SplitHostPort(c.RemoteAddr().String())
		if err != nil {
			host = c.RemoteAddr().String()
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("ldap: unparsable remote address %q", host)
		}
		for _, n := range nets {
			if n.Contains(ip) {
				return nil
			}
		}
		log.Warn("ldap connection rejected by whitelist", "ip", host)
		return fmt.Errorf("ldap: connection from %s is not whitelisted", host)
	}
}
