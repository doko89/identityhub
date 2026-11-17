// Package radius serves PAP authentication over RADIUS (TECH_SPEC §6.5)
// via layeh.com/radius. NAS devices authenticate with per-device
// shared secrets from radius_clients; user credentials always verify
// through usecase/auth (LoginLegacy), so RADIUS shares password
// policy, directory JIT, audit and the deny-when-MFA-required gate
// with every other login path.
//
// Only Access-Request with PAP (User-Name + User-Password) is answered.
// Packets from unknown NAS addresses are dropped before parsing (no
// shared secret exists to verify them); system failures are dropped so
// the NAS retries, while credential failures get Access-Reject.
package radius

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"

	adaptercrypto "github.com/identityhub/identityhub/internal/adapter/crypto"
	"github.com/identityhub/identityhub/internal/domain"
	usecaseauth "github.com/identityhub/identityhub/internal/usecase/auth"
)

// Config wires one RADIUS listener.
type Config struct {
	// Addr is the UDP listen address, e.g. ":1812".
	Addr string
	// EncKey (ENC_KEY) opens the sealed NAS shared secrets.
	EncKey [32]byte
	// PerNASLimit/PerNASWindow bound packets per NAS source IP.
	// Zero values take DefaultPerNASLimit/DefaultPerNASWindow;
	// tests shrink them to observe drops quickly.
	PerNASLimit  int
	PerNASWindow time.Duration
}

// Deps wires the server to the shared usecases.
type Deps struct {
	Auth    *usecaseauth.Service
	Clients domain.RADIUSClientStore
	Log     *slog.Logger
}

// ErrServerShutdown is returned by Serve after a clean Shutdown.
var ErrServerShutdown = radius.ErrServerShutdown

// Server is one in-process RADIUS listener.
type Server struct {
	addr      string
	encKey    [32]byte
	auth      *usecaseauth.Service
	clients   domain.RADIUSClientStore
	limiter   *nasLimiter
	log       *slog.Logger
	srv       *radius.PacketServer
	ready     chan struct{}
	localAddr net.Addr
}

// New validates cfg and builds the server. The UDP socket binds in
// Serve so bind failures surface there.
func New(cfg Config, d Deps) (*Server, error) {
	if cfg.Addr == "" {
		return nil, errors.New("radius: addr is required")
	}
	// EncKey strength is config's domain (length-checked there); the
	// server uses whatever 32 bytes it is given.
	if d.Auth == nil || d.Clients == nil {
		return nil, errors.New("radius: Auth and Clients are required")
	}
	slogLog := d.Log
	if slogLog == nil {
		slogLog = slog.Default()
	}
	s := &Server{
		addr: cfg.Addr, encKey: cfg.EncKey, auth: d.Auth, clients: d.Clients,
		limiter: newNASLimiter(cfg.PerNASLimit, cfg.PerNASWindow),
		log:     slogLog, ready: make(chan struct{}),
	}
	s.srv = &radius.PacketServer{
		Addr:         cfg.Addr,
		SecretSource: s,
		Handler:      s,
		ErrorLog:     log.New(slogWriter{slogLog}, "", 0),
	}
	return s, nil
}

// Serve binds the UDP socket (fail-fast on bind errors) and blocks
// serving until Shutdown.
func (s *Server) Serve() error {
	conn, err := net.ListenPacket("udp", s.addr)
	if err != nil {
		return fmt.Errorf("radius: listen %s: %w", s.addr, err)
	}
	s.localAddr = conn.LocalAddr()
	close(s.ready)
	return s.srv.Serve(conn)
}

// Ready closes once the socket is bound; Addr is valid after that.
func (s *Server) Ready() <-chan struct{} { return s.ready }

// Addr returns the bound socket address (valid after Ready).
func (s *Server) Addr() net.Addr { return s.localAddr }

// Shutdown drains handlers and closes the socket.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// RADIUSSecret implements radius.SecretSource: the NAS is identified by
// its source IP and its sealed secret is opened for packet
// verification. Unknown NAS addresses (and undecryptable secrets) fail
// the lookup, which drops the packet unverified.
func (s *Server) RADIUSSecret(ctx context.Context, remoteAddr net.Addr) ([]byte, error) {
	host := nasHost(remoteAddr)
	if !s.limiter.Allow(host) {
		s.log.Warn("radius packet dropped: NAS over rate limit", "ip", host)
		return nil, fmt.Errorf("radius: NAS %s over rate limit", host)
	}
	c, err := s.clients.ByNASIdentifier(ctx, host)
	if errors.Is(err, domain.ErrNotFound) {
		s.log.Warn("radius packet from unknown NAS dropped", "ip", host)
		return nil, fmt.Errorf("radius: unknown NAS %s", host)
	}
	if err != nil {
		return nil, fmt.Errorf("radius: NAS lookup: %w", err)
	}
	secret, err := adaptercrypto.Open(s.encKey, c.SharedSecretEnc)
	if err != nil {
		s.log.Error("radius NAS secret unavailable", "nas", host)
		return nil, fmt.Errorf("radius: NAS secret unavailable for %s", host)
	}
	return secret, nil
}

// ServeRADIUS implements radius.Handler: PAP Access-Request against
// LoginLegacy. Non-Access-Request codes are ignored.
func (s *Server) ServeRADIUS(w radius.ResponseWriter, r *radius.Request) {
	if r.Code != radius.CodeAccessRequest {
		return
	}
	reject := func(message string) {
		resp := r.Response(radius.CodeAccessReject)
		_ = rfc2865.ReplyMessage_SetString(resp, message)
		_ = w.Write(resp)
	}
	password, err := rfc2865.UserPassword_Lookup(r.Packet)
	if errors.Is(err, radius.ErrNoAttribute) {
		reject("PAP authentication required")
		return
	}
	if err != nil {
		reject("invalid credentials")
		return
	}
	username := rfc2865.UserName_GetString(r.Packet)
	if username == "" || len(password) == 0 {
		reject("invalid credentials")
		return
	}
	host := nasHost(r.RemoteAddr)
	c, err := s.clients.ByNASIdentifier(r.Context(), host)
	if err != nil {
		// The secret lookup already passed, so this is a transient
		// store failure: drop and let the NAS retry.
		s.log.Error("radius NAS re-lookup failed", "nas", host, "error", err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	u, err := s.auth.LoginLegacy(ctx, usecaseauth.LegacyLoginInput{
		Username: username, Password: string(password), IP: host,
		Method: domain.MethodRADIUS, ApplicationID: &c.ApplicationID,
	})
	switch {
	case err == nil:
		s.log.Info("radius accept", "username", u.Username, "nas", host)
		_ = w.Write(r.Response(radius.CodeAccessAccept))
	case errors.Is(err, usecaseauth.ErrMFARequired):
		reject(err.Error())
	case errors.Is(err, domain.ErrForbidden):
		reject("account disabled")
	case errors.Is(err, usecaseauth.ErrDirectoryUnavailable):
		s.log.Error("radius: directory unavailable", "username", username, "nas", host)
		reject("directory unavailable, try again later")
	case errors.Is(err, domain.ErrUnauthorized):
		reject("invalid credentials")
	default:
		// System failure (DB/audit down): drop so the NAS retries
		// instead of caching a reject.
		s.log.Error("radius auth failed", "username", username, "nas", host, "error", err)
	}
}

// nasHost returns the source IP of a packet for NAS identification and
// audit. unparsable addresses yield "" and match no NAS.
func nasHost(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return ""
	}
	if ip := net.ParseIP(host); ip == nil {
		return ""
	}
	return host
}

// slogWriter routes the library's error log into slog.
type slogWriter struct{ log *slog.Logger }

func (w slogWriter) Write(p []byte) (int, error) {
	w.log.Warn("radius server", "error", string(p))
	return len(p), nil
}
