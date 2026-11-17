package config

import (
	"encoding/base64"
	"testing"
	"time"
)

func testEncKey(t *testing.T) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
}

func setEnv(t *testing.T, k, v string) {
	t.Helper()
	t.Setenv(k, v)
}

func TestLoadDefaults(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://localhost:5432/identityhub")
	setEnv(t, "ENC_KEY", testEncKey(t))
	for _, k := range []string{"APP_ENV", "HTTP_PORT", "LOG_FORMAT", "SESSION_IDLE_TIMEOUT", "SESSION_LIFETIME", "WORKER_SYNC_INTERVAL"} {
		t.Setenv(k, "")
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HTTPPort != DefaultHTTPPort {
		t.Errorf("HTTPPort = %d, want %d", cfg.HTTPPort, DefaultHTTPPort)
	}
	if cfg.AppEnv != "development" || cfg.LogFormat != "text" {
		t.Errorf("AppEnv/LogFormat = %q/%q", cfg.AppEnv, cfg.LogFormat)
	}
	if cfg.SessionIdle != 30*time.Minute || cfg.SessionLifetime != 12*time.Hour {
		t.Errorf("session timeouts = %v/%v", cfg.SessionIdle, cfg.SessionLifetime)
	}
	if cfg.WorkerSyncInterval != 5*time.Minute {
		t.Errorf("WorkerSyncInterval = %v", cfg.WorkerSyncInterval)
	}
	if cfg.CookieSecure() {
		t.Error("CookieSecure() = true in development, want false")
	}
}

func TestLoadProductionHardening(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://db:5432/identityhub?sslmode=require")
	setEnv(t, "ENC_KEY", testEncKey(t))
	setEnv(t, "APP_ENV", "production")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.IsProduction() || !cfg.CookieSecure() {
		t.Error("production must report IsProduction and CookieSecure")
	}
}

func TestLoadFailures(t *testing.T) {
	validURL := "postgres://localhost:5432/identityhub"
	validKey := testEncKey(t)

	cases := []struct {
		name string
		env  map[string]string
	}{
		{"missing DATABASE_URL", map[string]string{"ENC_KEY": validKey}},
		{"bad DATABASE_URL scheme", map[string]string{"DATABASE_URL": "mysql://x/db", "ENC_KEY": validKey}},
		{"missing ENC_KEY", map[string]string{"DATABASE_URL": validURL}},
		{"short ENC_KEY", map[string]string{"DATABASE_URL": validURL, "ENC_KEY": "too-short"}},
		{"bad APP_ENV", map[string]string{"DATABASE_URL": validURL, "ENC_KEY": validKey, "APP_ENV": "staging"}},
		{"bad HTTP_PORT text", map[string]string{"DATABASE_URL": validURL, "ENC_KEY": validKey, "HTTP_PORT": "abc"}},
		{"bad HTTP_PORT range", map[string]string{"DATABASE_URL": validURL, "ENC_KEY": validKey, "HTTP_PORT": "99999"}},
		{"bad LOG_FORMAT", map[string]string{"DATABASE_URL": validURL, "ENC_KEY": validKey, "LOG_FORMAT": "yaml"}},
		{"bad SESSION_IDLE_TIMEOUT", map[string]string{"DATABASE_URL": validURL, "ENC_KEY": validKey, "SESSION_IDLE_TIMEOUT": "nope"}},
		{"zero SESSION_LIFETIME", map[string]string{"DATABASE_URL": validURL, "ENC_KEY": validKey, "SESSION_LIFETIME": "0s"}},
		{"negative WORKER_SYNC_INTERVAL", map[string]string{"DATABASE_URL": validURL, "ENC_KEY": validKey, "WORKER_SYNC_INTERVAL": "-1m"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"DATABASE_URL", "ENC_KEY", "APP_ENV", "HTTP_PORT", "LOG_FORMAT", "SESSION_IDLE_TIMEOUT", "SESSION_LIFETIME", "WORKER_SYNC_INTERVAL"} {
				t.Setenv(k, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if _, err := Load(); err == nil {
				t.Fatal("Load() = nil error, want failure")
			}
		})
	}
}

func TestValidateDirect(t *testing.T) {
	cfg := Config{AppEnv: "development", HTTPPort: 8080, DatabaseURL: "postgres://x/db", LogFormat: "text", SessionIdle: time.Minute, SessionLifetime: time.Hour, WorkerSyncInterval: time.Minute, BaseURL: "http://localhost:8080"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	cfg.HTTPPort = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() with port 0 = nil, want error")
	}
}

func TestLoadLDAPAndSMTP(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://localhost:5432/identityhub")
	setEnv(t, "ENC_KEY", testEncKey(t))
	setEnv(t, "LDAP_URL", "ldaps://dir.example.com:636")
	setEnv(t, "LDAP_BASE_DN", "dc=example,dc=com")
	setEnv(t, "LDAP_BIND_DN", "cn=svc,dc=example,dc=com")
	setEnv(t, "LDAP_BIND_PASSWORD", "s3cret")
	setEnv(t, "LDAP_USER_FILTER", "(department=IT)")
	setEnv(t, "LDAP_ADMIN_GROUP_DN", "cn=admins,ou=groups,dc=example,dc=com")
	setEnv(t, "SMTP_HOST", "mail.example.com")
	setEnv(t, "SMTP_FROM", "idp@example.com")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.LDAP.Enabled() || cfg.LDAP.Timeout != DefaultLDAPTimeout {
		t.Errorf("LDAP = %+v, want enabled with default timeout", cfg.LDAP)
	}
	if !cfg.SMTP.Enabled() || cfg.SMTP.Port != 587 {
		t.Errorf("SMTP = %+v, want enabled with port 587", cfg.SMTP)
	}
	if cfg.BaseURL != DefaultBaseURL {
		t.Errorf("BaseURL = %q, want default", cfg.BaseURL)
	}
}

func TestLoadLDAPSMTPFailures(t *testing.T) {
	validURL := "postgres://localhost:5432/identityhub"
	validKey := testEncKey(t)

	cases := []struct {
		name string
		env  map[string]string
	}{
		{"LDAP_URL without base DN", map[string]string{"LDAP_URL": "ldap://dir:389"}},
		{"LDAP_URL bad scheme", map[string]string{"LDAP_URL": "http://dir:389", "LDAP_BASE_DN": "dc=x"}},
		{"LDAP user filter unbalanced", map[string]string{"LDAP_URL": "ldap://dir:389", "LDAP_BASE_DN": "dc=x", "LDAP_USER_FILTER": "((uid=*)))"}},
		{"LDAP timeout bad", map[string]string{"LDAP_URL": "ldap://dir:389", "LDAP_BASE_DN": "dc=x", "LDAP_TIMEOUT": "nope"}},
		{"SMTP without from", map[string]string{"SMTP_HOST": "mail.example.com"}},
		{"SMTP bad port", map[string]string{"SMTP_HOST": "mail.example.com", "SMTP_FROM": "a@b.c", "SMTP_PORT": "abc"}},
		{"base URL bad", map[string]string{"APP_BASE_URL": "notaurl"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"DATABASE_URL", "ENC_KEY", "LDAP_URL", "LDAP_BASE_DN", "LDAP_USER_FILTER", "LDAP_TIMEOUT", "SMTP_HOST", "SMTP_FROM", "SMTP_PORT", "APP_BASE_URL"} {
				t.Setenv(k, "")
			}
			t.Setenv("DATABASE_URL", validURL)
			t.Setenv("ENC_KEY", validKey)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if _, err := Load(); err == nil {
				t.Fatal("Load() = nil error, want failure")
			}
		})
	}
}
