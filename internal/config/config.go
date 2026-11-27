// Package config loads and validates IdentityHub runtime configuration.
//
// v1 uses environment variables only (TECH_SPEC §1). There are no config
// files. Every external input (port, timeouts, keys) is parsed here so the
// rest of the program works with typed, validated values.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Defaults for the M0 foundation server.
const (
	DefaultHTTPPort        = 8080
	DefaultSessionIdle     = 30 * time.Minute
	DefaultSessionLifetime = 12 * time.Hour
	DefaultWorkerInterval  = 5 * time.Minute
	DefaultLogFormat       = "text"
	DefaultAppEnv          = "development"
	DefaultLDAPTimeout     = 10 * time.Second
	DefaultBaseURL         = "http://localhost:8080"
	DefaultStorageBackend  = "local"
	DefaultStorageDir      = "./var/uploads"
	// DefaultLDAPServerPort is the unprivileged equivalent of 389 for the
	// in-process LDAP provider (TECH_SPEC §6.4). Operators serving the
	// standard ports set LDAP_PORT=389/636 explicitly.
	DefaultLDAPServerPort = 1389
	// DefaultLDAPCacheTTL bounds whole-tree LDAP snapshots. Snapshots
	// also refresh when the directory version moves; the TTL is the
	// backstop for out-of-band writes.
	DefaultLDAPCacheTTL = 5 * time.Minute
	// DefaultLDAPBindCacheTTL bounds remembered local LDAP binds.
	DefaultLDAPBindCacheTTL = time.Minute
	// DefaultRADIUSPort is the standard RADIUS authentication port
	// (TECH_SPEC §6.5).
	DefaultRADIUSPort     = 1812
	productionEnv         = "production"
	encKeyBytes           = 32
	envDatabaseURL        = "DATABASE_URL"
	envHTTPPort           = "HTTP_PORT"
	envAppEnv             = "APP_ENV"
	envEncKey             = "ENC_KEY"
	envLogFormat          = "LOG_FORMAT"
	envSessionIdle        = "SESSION_IDLE_TIMEOUT"
	envSessionLifetime    = "SESSION_LIFETIME"
	envWorkerSyncInterval = "WORKER_SYNC_INTERVAL"
	envBaseURL            = "APP_BASE_URL"
	envLDAPURL            = "LDAP_URL"
	envLDAPBindDN         = "LDAP_BIND_DN"
	envLDAPBindPassword   = "LDAP_BIND_PASSWORD"
	envLDAPBaseDN         = "LDAP_BASE_DN"
	envLDAPUserFilter     = "LDAP_USER_FILTER"
	envLDAPGroupFilter    = "LDAP_GROUP_FILTER"
	envLDAPAdminGroupDN   = "LDAP_ADMIN_GROUP_DN"
	envLDAPTimeout        = "LDAP_TIMEOUT"
	envLDAPAttrMap        = "LDAP_ATTR_MAP"
	envSMTPHost           = "SMTP_HOST"
	envSMTPPort           = "SMTP_PORT"
	envSMTPHeloName       = "SMTP_HELO_NAME"
	envSMTPUsername       = "SMTP_USERNAME"
	envSMTPPassword       = "SMTP_PASSWORD"
	envSMTPFrom           = "SMTP_FROM"
	// LDAP provider (server) settings (TECH_SPEC §6.4). These are
	// distinct from the LDAP_* upstream connector settings above.
	envLDAPMode         = "LDAP_MODE"
	envLDAPPort         = "LDAP_PORT"
	envLDAPAllowedCIDRs = "LDAP_ALLOWED_CIDRS"
	envLDAPTLSCertFile  = "LDAP_TLS_CERT_FILE"
	envLDAPTLSKeyFile   = "LDAP_TLS_KEY_FILE"
	envLDAPCacheTTL     = "LDAP_CACHE_TTL"
	envLDAPBindCacheTTL = "LDAP_BIND_CACHE_TTL"
	envLDAPServeBaseDN  = "LDAP_SERVE_BASE_DN"
	envAuditRetention   = "AUDIT_RETENTION"
	envAuditIgnoreCIDRs = "AUDIT_IGNORE_CIDRS"
	envAuditIgnoreApps  = "AUDIT_IGNORE_APPS"
	// RADIUS provider (server) settings (TECH_SPEC §6.5).
	envRADIUSEnabled = "RADIUS_ENABLED"
	envRADIUSPort    = "RADIUS_PORT"
	// Asset storage settings (TECH_SPEC §6.7).
	envStorageBackend    = "STORAGE_BACKEND"
	envStorageDir        = "STORAGE_DIR"
	envStorageS3Endpoint = "STORAGE_S3_ENDPOINT"
	envStorageS3Bucket   = "STORAGE_S3_BUCKET"
	envStorageS3Access   = "STORAGE_S3_ACCESS_KEY"
	envStorageS3Secret   = "STORAGE_S3_SECRET_KEY"
	envStorageS3UseSSL   = "STORAGE_S3_USE_SSL"
)

// LDAP provider connection modes (TECH_SPEC §6.4). Empty disables the
// in-process LDAP listener.
const (
	LDAPModePlain    = "ldap"
	LDAPModeLDAPS    = "ldaps"
	LDAPModeStartTLS = "starttls"
)

// Config is the validated process-wide configuration.
type Config struct {
	// AppEnv is "development" or "production". Production enables Secure
	// cookies and JSON logging defaults.
	AppEnv string
	// HTTPPort is the TCP port for the HTTP listener.
	HTTPPort int
	// DatabaseURL is the Postgres connection string (pgx compatible).
	DatabaseURL string
	// EncKey encrypts TOTP seeds and RADIUS shared secrets at rest
	// (TECH_SPEC §5). Exactly 32 bytes.
	EncKey [32]byte
	// LogFormat is "text" or "json".
	LogFormat string
	// SessionIdle is the scs idle timeout (TECH_SPEC §8: 30m).
	SessionIdle time.Duration
	// SessionLifetime is the scs absolute lifetime (TECH_SPEC §8: 12h).
	SessionLifetime time.Duration
	// WorkerSyncInterval is the period between worker sync/cleanup runs.
	WorkerSyncInterval time.Duration
	// AuditRetention bounds audit_log rows (AUDIT_RETENTION); the worker
	// deletes older rows. 0 (default) keeps rows forever.
	AuditRetention time.Duration
	// AuditIgnoreCIDRs drops success audit rows from these networks
	// (AUDIT_IGNORE_CIDRS); failures are always kept. Empty records all.
	AuditIgnoreCIDRs []*net.IPNet
	// AuditIgnoreApps drops success audit rows for these application IDs
	// (AUDIT_IGNORE_APPS); failures are always kept. Empty records all.
	AuditIgnoreApps []uuid.UUID
	// BaseURL is the public origin used to build links emailed to users
	// (password reset). No trailing slash.
	BaseURL string
	// LDAP holds the upstream directory connector settings (PRD §6.2).
	// LDAP is disabled when URL is empty.
	LDAP LDAPConfig
	// SMTP holds the transactional mailer settings. Mail is disabled
	// (messages go to the log) when Host is empty.
	SMTP SMTPConfig
	// LDAPProvider holds the in-process LDAP server settings
	// (TECH_SPEC §6.4). The listener is disabled when Mode is empty.
	LDAPProvider LDAPProviderConfig
	// RADIUS holds the in-process RADIUS server settings (TECH_SPEC
	// §6.5). It listens on UDP port 1812 by default.
	RADIUS RADIUSConfig
	// Storage selects the asset object backend (TECH_SPEC §6.7).
	Storage StorageConfig
}

// LDAPConfig mirrors the upstream connector fields (PRD §6.2).
type LDAPConfig struct {
	// URL is the directory endpoint: ldap://host:port or ldaps://host:port.
	URL string
	// BindDN + BindPassword are the service credentials for searches.
	BindDN       string
	BindPassword string
	// BaseDN is the search root for users and groups.
	BaseDN string
	// UserFilter and GroupFilter are extra LDAP filters AND-ed with the
	// objectClass match. Empty means no extra filter.
	UserFilter  string
	GroupFilter string
	// AdminGroupDN optionally maps a directory group to ih_admin: synced
	// members of this DN auto-join ih_admin (PRD §6.2).
	AdminGroupDN string
	// Timeout bounds every dial/search/bind (PRD §5.1: never a hang).
	Timeout time.Duration
	// AttrMap maps upstream directory attributes to custom attribute
	// keys (upstream -> key). Synced values populate the mapped keys;
	// keys without a def are skipped. Nil disables the import.
	AttrMap map[string]string
}

// Enabled reports whether the upstream connector is configured.
func (l LDAPConfig) Enabled() bool { return l.URL != "" }

// LDAPProviderConfig mirrors the in-process LDAP server settings
// (TECH_SPEC §6.4). It is unrelated to LDAPConfig (the upstream
// connector): both may be active at once.
type LDAPProviderConfig struct {
	// Mode is "", "ldap", "ldaps" or "starttls". Empty disables the
	// listener.
	Mode string
	// Port is the TCP port for the LDAP listener.
	Port int
	// AllowedCIDRs is the parsed LDAP_ALLOWED_CIDRS whitelist,
	// enforced in the server's OnNewConnection hook before any LDAP
	// bytes are parsed. Plaintext mode requires it to be non-empty.
	AllowedCIDRs []*net.IPNet
	// TLSCertFile and TLSKeyFile hold the managed certificate pair for
	// ldaps/starttls modes (TECH_SPEC §8: TLS 1.2 minimum).
	TLSCertFile string
	TLSKeyFile  string
	// CacheTTL bounds whole-tree snapshots (default 5m). Snapshots
	// also refresh when the directory version moves; 0 disables the
	// tree cache (every search reads fresh).
	CacheTTL time.Duration
	// BindCacheTTL bounds remembered local binds (default 1m); 0
	// disables the bind cache (every bind verifies the hash).
	BindCacheTTL time.Duration
	// ServeBaseDN overrides the served naming context. Empty serves
	// the default dc=identityhub tree; a set value must parse as a DN
	// (validated when the LDAP server is constructed, so a bad value
	// fails startup with a clear error instead of serving half a tree).
	ServeBaseDN string
}

// Enabled reports whether the LDAP listener is configured.
func (l LDAPProviderConfig) Enabled() bool { return l.Mode != "" }

// RADIUSConfig mirrors the in-process RADIUS server settings
// (TECH_SPEC §6.5).
type RADIUSConfig struct {
	// Enabled toggles the UDP listener. True by default; set
	// RADIUS_ENABLED=false to disable.
	Enabled bool
	// Port is the UDP port for authentication requests.
	Port int
}

// Storage backends (TECH_SPEC §6.7). v1 ships local; s3 is parsed and
// validated here but wired in M7.
const (
	StorageLocal = "local"
	StorageS3    = "s3"
)

// StorageConfig mirrors the asset object-backend settings.
type StorageConfig struct {
	// Backend is "local" (filesystem at Dir) or "s3".
	Backend string
	// Dir roots the local backend.
	Dir string
	// S3* configure the M7 S3 backend (minio-go, S3-compatible).
	S3Endpoint string
	S3Bucket   string
	S3Access   string
	S3Secret   string
	S3UseSSL   bool
}

// SMTPConfig mirrors the transactional mailer settings.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// HeloName overrides the EHLO domain. Empty derives it from the
	// From domain; strict servers (Stalwart) reject Go's "localhost".
	HeloName string
}

// Enabled reports whether real mail delivery is configured.
func (s SMTPConfig) Enabled() bool { return s.Host != "" }

// IsProduction reports whether production hardening applies.
func (c Config) IsProduction() bool { return c.AppEnv == productionEnv }

// CookieSecure mirrors TECH_SPEC §8: Secure cookies in production, where
// TLS terminates at the reverse proxy. In development Secure is off so
// plain-HTTP local testing works.
func (c Config) CookieSecure() bool { return c.IsProduction() }

// Load reads the environment and returns a validated Config.
func Load() (Config, error) {
	cfg := Config{
		AppEnv:             getEnv(envAppEnv, DefaultAppEnv),
		HTTPPort:           DefaultHTTPPort,
		LogFormat:          getEnv(envLogFormat, DefaultLogFormat),
		SessionIdle:        DefaultSessionIdle,
		SessionLifetime:    DefaultSessionLifetime,
		WorkerSyncInterval: DefaultWorkerInterval,
		BaseURL:            strings.TrimRight(getEnv(envBaseURL, DefaultBaseURL), "/"),
	}
	cfg.LDAP = LDAPConfig{
		URL:          strings.TrimSpace(os.Getenv(envLDAPURL)),
		BindDN:       strings.TrimSpace(os.Getenv(envLDAPBindDN)),
		BindPassword: os.Getenv(envLDAPBindPassword),
		BaseDN:       strings.TrimSpace(os.Getenv(envLDAPBaseDN)),
		UserFilter:   strings.TrimSpace(os.Getenv(envLDAPUserFilter)),
		GroupFilter:  strings.TrimSpace(os.Getenv(envLDAPGroupFilter)),
		AdminGroupDN: strings.TrimSpace(os.Getenv(envLDAPAdminGroupDN)),
		Timeout:      DefaultLDAPTimeout,
	}
	cfg.SMTP = SMTPConfig{
		Host:     strings.TrimSpace(os.Getenv(envSMTPHost)),
		Port:     587,
		Username: strings.TrimSpace(os.Getenv(envSMTPUsername)),
		Password: os.Getenv(envSMTPPassword),
		From:     strings.TrimSpace(os.Getenv(envSMTPFrom)),
		HeloName: strings.TrimSpace(os.Getenv(envSMTPHeloName)),
	}
	cfg.LDAPProvider = LDAPProviderConfig{
		Mode:         strings.ToLower(strings.TrimSpace(os.Getenv(envLDAPMode))),
		Port:         DefaultLDAPServerPort,
		TLSCertFile:  strings.TrimSpace(os.Getenv(envLDAPTLSCertFile)),
		TLSKeyFile:   strings.TrimSpace(os.Getenv(envLDAPTLSKeyFile)),
		CacheTTL:     DefaultLDAPCacheTTL,
		BindCacheTTL: DefaultLDAPBindCacheTTL,
		ServeBaseDN:  strings.TrimSpace(os.Getenv(envLDAPServeBaseDN)),
	}
	cfg.RADIUS = RADIUSConfig{Enabled: true, Port: DefaultRADIUSPort}
	cfg.Storage = StorageConfig{
		Backend:    strings.ToLower(strings.TrimSpace(getEnv(envStorageBackend, DefaultStorageBackend))),
		Dir:        strings.TrimSpace(getEnv(envStorageDir, DefaultStorageDir)),
		S3Endpoint: strings.TrimSpace(os.Getenv(envStorageS3Endpoint)),
		S3Bucket:   strings.TrimSpace(os.Getenv(envStorageS3Bucket)),
		S3Access:   strings.TrimSpace(os.Getenv(envStorageS3Access)),
		S3Secret:   os.Getenv(envStorageS3Secret),
		S3UseSSL:   true,
	}
	if raw := strings.TrimSpace(os.Getenv(envStorageS3UseSSL)); raw != "" {
		useSSL, err := strconv.ParseBool(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid %s %q: must be a boolean", envStorageS3UseSSL, raw)
		}
		cfg.Storage.S3UseSSL = useSSL
	}

	if raw := strings.TrimSpace(os.Getenv(envHTTPPort)); raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid %s %q: must be an integer", envHTTPPort, raw)
		}
		cfg.HTTPPort = port
	}

	if raw := strings.TrimSpace(os.Getenv(envSMTPPort)); raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid %s %q: must be an integer", envSMTPPort, raw)
		}
		cfg.SMTP.Port = port
	}
	if raw := strings.TrimSpace(os.Getenv(envLDAPTimeout)); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid %s %q: %v", envLDAPTimeout, raw, err)
		}
		cfg.LDAP.Timeout = d
	}
	if raw := strings.TrimSpace(os.Getenv(envLDAPAttrMap)); raw != "" {
		m, err := parseAttrMap(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid %s: %w", envLDAPAttrMap, err)
		}
		cfg.LDAP.AttrMap = m
	}
	if raw := strings.TrimSpace(os.Getenv(envLDAPPort)); raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid %s %q: must be an integer", envLDAPPort, raw)
		}
		cfg.LDAPProvider.Port = port
	}
	if raw := strings.TrimSpace(os.Getenv(envRADIUSPort)); raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid %s %q: must be an integer", envRADIUSPort, raw)
		}
		cfg.RADIUS.Port = port
	}
	if raw := strings.TrimSpace(os.Getenv(envRADIUSEnabled)); raw != "" {
		enabled, err := strconv.ParseBool(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid %s %q: must be a boolean", envRADIUSEnabled, raw)
		}
		cfg.RADIUS.Enabled = enabled
	}
	if raw := strings.TrimSpace(os.Getenv(envLDAPAllowedCIDRs)); raw != "" {
		nets, err := parseCIDRList(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid %s: %w", envLDAPAllowedCIDRs, err)
		}
		cfg.LDAPProvider.AllowedCIDRs = nets
	}

	cfg.DatabaseURL = strings.TrimSpace(os.Getenv(envDatabaseURL))

	key, err := parseEncKey(strings.TrimSpace(os.Getenv(envEncKey)))
	if err != nil {
		return Config{}, err
	}
	cfg.EncKey = key

	for _, item := range []struct {
		name string
		dst  *time.Duration
	}{
		{envSessionIdle, &cfg.SessionIdle},
		{envSessionLifetime, &cfg.SessionLifetime},
		{envWorkerSyncInterval, &cfg.WorkerSyncInterval},
		{envLDAPCacheTTL, &cfg.LDAPProvider.CacheTTL},
		{envLDAPBindCacheTTL, &cfg.LDAPProvider.BindCacheTTL},
		{envAuditRetention, &cfg.AuditRetention},
	} {
		if raw := strings.TrimSpace(os.Getenv(item.name)); raw != "" {
			d, err := time.ParseDuration(raw)
			if err != nil {
				return Config{}, fmt.Errorf("invalid %s %q: %v", item.name, raw, err)
			}
			*item.dst = d
		}
	}
	if raw := strings.TrimSpace(os.Getenv(envAuditIgnoreCIDRs)); raw != "" {
		nets, err := parseCIDRList(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid %s: %w", envAuditIgnoreCIDRs, err)
		}
		cfg.AuditIgnoreCIDRs = nets
	}
	if raw := strings.TrimSpace(os.Getenv(envAuditIgnoreApps)); raw != "" {
		ids, err := parseUUIDList(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid %s: %w", envAuditIgnoreApps, err)
		}
		cfg.AuditIgnoreApps = ids
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks typed invariants. It is exported so callers that build a
// Config programmatically (tests, future CLIs) get the same rules.
func (c Config) Validate() error {
	switch c.AppEnv {
	case "development", productionEnv:
	default:
		return fmt.Errorf("invalid APP_ENV %q: must be development or production", c.AppEnv)
	}
	if c.HTTPPort < 1 || c.HTTPPort > 65535 {
		return fmt.Errorf("invalid HTTP_PORT %d: must be 1-65535", c.HTTPPort)
	}
	if c.DatabaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	u, err := url.Parse(c.DatabaseURL)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return fmt.Errorf("invalid DATABASE_URL: must be a postgres:// URL")
	}
	switch c.LogFormat {
	case "text", "json":
	default:
		return fmt.Errorf("invalid LOG_FORMAT %q: must be text or json", c.LogFormat)
	}
	if c.SessionIdle <= 0 {
		return fmt.Errorf("invalid SESSION_IDLE_TIMEOUT %v: must be positive", c.SessionIdle)
	}
	if c.SessionLifetime <= 0 {
		return fmt.Errorf("invalid SESSION_LIFETIME %v: must be positive", c.SessionLifetime)
	}
	if c.WorkerSyncInterval <= 0 {
		return fmt.Errorf("invalid WORKER_SYNC_INTERVAL %v: must be positive", c.WorkerSyncInterval)
	}
	if c.AuditRetention < 0 {
		return fmt.Errorf("invalid AUDIT_RETENTION %v: must not be negative (0 keeps rows forever)", c.AuditRetention)
	}
	if u, err := url.Parse(c.BaseURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("invalid APP_BASE_URL %q: must be an http(s) URL with a host", c.BaseURL)
	}
	if err := c.LDAP.Validate(); err != nil {
		return err
	}
	if err := c.SMTP.Validate(); err != nil {
		return err
	}
	if err := c.LDAPProvider.Validate(); err != nil {
		return err
	}
	if err := c.RADIUS.Validate(); err != nil {
		return err
	}
	if err := c.Storage.Validate(); err != nil {
		return err
	}
	return nil
}

// Validate checks the LDAP settings. An empty URL disables the connector
// and skips every other check.
func (l LDAPConfig) Validate() error {
	if !l.Enabled() {
		return nil
	}
	u, err := url.Parse(l.URL)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") || u.Host == "" {
		return fmt.Errorf("invalid LDAP_URL %q: must be ldap(s)://host[:port]", l.URL)
	}
	if l.BaseDN == "" {
		return fmt.Errorf("invalid LDAP_BASE_DN: required when LDAP_URL is set")
	}
	for name, f := range map[string]string{"LDAP_USER_FILTER": l.UserFilter, "LDAP_GROUP_FILTER": l.GroupFilter} {
		if f != "" && !balancedFilter(f) {
			return fmt.Errorf("invalid %s %q: unbalanced parentheses", name, f)
		}
	}
	if l.Timeout <= 0 {
		return fmt.Errorf("invalid LDAP_TIMEOUT %v: must be positive", l.Timeout)
	}
	return nil
}

// Validate checks the SMTP settings. An empty host disables mail delivery
// and skips every other check.
func (s SMTPConfig) Validate() error {
	if !s.Enabled() {
		return nil
	}
	if s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("invalid SMTP_PORT %d: must be 1-65535", s.Port)
	}
	if s.From == "" {
		return fmt.Errorf("invalid SMTP_FROM: required when SMTP_HOST is set")
	}
	return nil
}

// Validate checks the in-process LDAP server settings. An empty mode
// disables the listener and skips every other check. Plaintext mode
// refuses to boot without a non-empty whitelist (TECH_SPEC §8); TLS
// modes require the managed certificate pair.
func (l LDAPProviderConfig) Validate() error {
	if !l.Enabled() {
		return nil
	}
	switch l.Mode {
	case LDAPModePlain, LDAPModeLDAPS, LDAPModeStartTLS:
	default:
		return fmt.Errorf("invalid LDAP_MODE %q: must be ldap, ldaps or starttls", l.Mode)
	}
	if l.Port < 1 || l.Port > 65535 {
		return fmt.Errorf("invalid LDAP_PORT %d: must be 1-65535", l.Port)
	}
	if l.Mode == LDAPModePlain && len(l.AllowedCIDRs) == 0 {
		return fmt.Errorf("invalid LDAP_ALLOWED_CIDRS: required when LDAP_MODE is ldap (plaintext stays locked down)")
	}
	if l.Mode == LDAPModeLDAPS || l.Mode == LDAPModeStartTLS {
		if l.TLSCertFile == "" || l.TLSKeyFile == "" {
			return fmt.Errorf("invalid LDAP_TLS_CERT_FILE/LDAP_TLS_KEY_FILE: both are required for LDAP_MODE=%s", l.Mode)
		}
	}
	if l.CacheTTL < 0 {
		return fmt.Errorf("invalid LDAP_CACHE_TTL %v: must not be negative (0 disables the tree cache)", l.CacheTTL)
	}
	if l.BindCacheTTL < 0 {
		return fmt.Errorf("invalid LDAP_BIND_CACHE_TTL %v: must not be negative (0 disables the bind cache)", l.BindCacheTTL)
	}
	return nil
}

// Validate checks the RADIUS server settings. A disabled server skips
// the port check.
func (r RADIUSConfig) Validate() error {
	if !r.Enabled {
		return nil
	}
	if r.Port < 1 || r.Port > 65535 {
		return fmt.Errorf("invalid RADIUS_PORT %d: must be 1-65535", r.Port)
	}
	return nil
}

// Validate checks the storage settings: local needs a dir, s3 needs an
// endpoint, bucket and credentials. An empty backend (programmatic zero
// value) means local with wiring-time defaults, matching how the other
// optional sections treat their zero value.
func (s StorageConfig) Validate() error {
	switch s.Backend {
	case "", StorageLocal:
		if s.Backend == StorageLocal && s.Dir == "" {
			return fmt.Errorf("invalid STORAGE_DIR: required when STORAGE_BACKEND is local")
		}
		return nil
	case StorageS3:
		if s.S3Endpoint == "" || s.S3Bucket == "" || s.S3Access == "" || s.S3Secret == "" {
			return fmt.Errorf("invalid STORAGE_S3_*: endpoint, bucket, access key and secret key are all required when STORAGE_BACKEND is s3")
		}
		return nil
	default:
		return fmt.Errorf("invalid STORAGE_BACKEND %q: must be local or s3", s.Backend)
	}
}

// parseCIDRList parses a comma-separated whitelist. Each item is a CIDR
// ("10.0.0.0/8") or a bare IP ("10.0.0.5", treated as a /32 or /128).
func parseCIDRList(raw string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(item); err == nil {
			out = append(out, n)
			continue
		}
		if ip := net.ParseIP(item); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		return nil, fmt.Errorf("%q is not a CIDR or IP address", item)
	}
	return out, nil
}

// parseUUIDList parses a comma-separated list of UUIDs (application IDs
// for AUDIT_IGNORE_APPS). Blank items are skipped so a trailing comma is
// harmless.
func parseUUIDList(raw string) ([]uuid.UUID, error) {
	var out []uuid.UUID
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		id, err := uuid.Parse(item)
		if err != nil {
			return nil, fmt.Errorf("%q is not a UUID", item)
		}
		out = append(out, id)
	}
	return out, nil
}

var (
	attrNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]*$`)
	attrKeyPattern  = regexp.MustCompile(`^[a-z][a-z0-9-_]*$`)
)

// parseAttrMap parses "upstream:key,upstream2:key2" into an
// upstream-attribute -> custom-key map. Upstream names follow LDAP
// attribute spelling; keys must already look like def keys (lowercase).
// Either side repeated (two upstreams feeding one key) is rejected:
// sync could not pick a winner.
func parseAttrMap(raw string) (map[string]string, error) {
	out := map[string]string{}
	seenKeys := map[string]string{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		upstream, key, ok := strings.Cut(item, ":")
		upstream, key = strings.TrimSpace(upstream), strings.TrimSpace(key)
		if !ok || upstream == "" || key == "" {
			return nil, fmt.Errorf("%q must look like upstreamAttr:key", item)
		}
		if !attrNamePattern.MatchString(upstream) {
			return nil, fmt.Errorf("%q is not an LDAP attribute name", upstream)
		}
		if len(key) > 64 || !attrKeyPattern.MatchString(key) {
			return nil, fmt.Errorf("%q is not a custom attribute key (lowercase a-z, 0-9, '-')", key)
		}
		if prev, dup := out[upstream]; dup {
			return nil, fmt.Errorf("upstream attribute %q maps twice (%q and %q)", upstream, prev, key)
		}
		if prev, dup := seenKeys[key]; dup {
			return nil, fmt.Errorf("custom attribute %q is fed by two upstreams (%q and %q)", key, prev, upstream)
		}
		out[upstream] = key
		seenKeys[key] = upstream
	}
	return out, nil
}

// balancedFilter is a cheap sanity check for admin-supplied LDAP filters:
// it only verifies parenthesis balance, the common typo class.
func balancedFilter(f string) bool {
	depth := 0
	for _, r := range f {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}

// parseEncKey decodes ENC_KEY. Accepted forms: base64 of exactly 32 bytes
// (preferred) or a raw 32-character string. An empty value is an error:
// every mode that touches the database needs the key, and failing fast at
// boot beats failing on first encrypt.
func parseEncKey(raw string) ([32]byte, error) {
	var out [32]byte
	if raw == "" {
		return out, errors.New("ENC_KEY is required (base64 of 32 random bytes)")
	}
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) == encKeyBytes {
		copy(out[:], decoded)
		return out, nil
	}
	if len(raw) == encKeyBytes {
		copy(out[:], raw)
		return out, nil
	}
	return out, fmt.Errorf("invalid ENC_KEY: must decode to exactly %d bytes", encKeyBytes)
}

func getEnv(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}
