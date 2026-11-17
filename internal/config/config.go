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
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
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
	productionEnv          = "production"
	encKeyBytes            = 32
	envDatabaseURL         = "DATABASE_URL"
	envHTTPPort            = "HTTP_PORT"
	envAppEnv              = "APP_ENV"
	envEncKey              = "ENC_KEY"
	envLogFormat           = "LOG_FORMAT"
	envSessionIdle         = "SESSION_IDLE_TIMEOUT"
	envSessionLifetime     = "SESSION_LIFETIME"
	envWorkerSyncInterval  = "WORKER_SYNC_INTERVAL"
	envBaseURL             = "APP_BASE_URL"
	envLDAPURL             = "LDAP_URL"
	envLDAPBindDN          = "LDAP_BIND_DN"
	envLDAPBindPassword    = "LDAP_BIND_PASSWORD"
	envLDAPBaseDN          = "LDAP_BASE_DN"
	envLDAPUserFilter      = "LDAP_USER_FILTER"
	envLDAPGroupFilter     = "LDAP_GROUP_FILTER"
	envLDAPAdminGroupDN    = "LDAP_ADMIN_GROUP_DN"
	envLDAPTimeout         = "LDAP_TIMEOUT"
	envSMTPHost            = "SMTP_HOST"
	envSMTPPort            = "SMTP_PORT"
	envSMTPUsername        = "SMTP_USERNAME"
	envSMTPPassword        = "SMTP_PASSWORD"
	envSMTPFrom            = "SMTP_FROM"
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
	// BaseURL is the public origin used to build links emailed to users
	// (password reset). No trailing slash.
	BaseURL string
	// LDAP holds the upstream directory connector settings (PRD §6.2).
	// LDAP is disabled when URL is empty.
	LDAP LDAPConfig
	// SMTP holds the transactional mailer settings. Mail is disabled
	// (messages go to the log) when Host is empty.
	SMTP SMTPConfig
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
}

// Enabled reports whether the upstream connector is configured.
func (l LDAPConfig) Enabled() bool { return l.URL != "" }

// SMTPConfig mirrors the transactional mailer settings.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
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
	} {
		if raw := strings.TrimSpace(os.Getenv(item.name)); raw != "" {
			d, err := time.ParseDuration(raw)
			if err != nil {
				return Config{}, fmt.Errorf("invalid %s %q: %v", item.name, raw, err)
			}
			*item.dst = d
		}
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
	if u, err := url.Parse(c.BaseURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("invalid APP_BASE_URL %q: must be an http(s) URL with a host", c.BaseURL)
	}
	if err := c.LDAP.Validate(); err != nil {
		return err
	}
	if err := c.SMTP.Validate(); err != nil {
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
