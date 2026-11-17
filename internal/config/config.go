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
}

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
	}

	if raw := strings.TrimSpace(os.Getenv(envHTTPPort)); raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid %s %q: must be an integer", envHTTPPort, raw)
		}
		cfg.HTTPPort = port
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
	return nil
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
