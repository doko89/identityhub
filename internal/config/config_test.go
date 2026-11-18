package config

import (
	"encoding/base64"
	"net"
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
	setEnv(t, "SMTP_HELO_NAME", "mail.example.com")

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
	if cfg.SMTP.HeloName != "mail.example.com" {
		t.Errorf("SMTP.HeloName = %q", cfg.SMTP.HeloName)
	}
	if cfg.BaseURL != DefaultBaseURL {
		t.Errorf("BaseURL = %q, want default", cfg.BaseURL)
	}
}

func TestLoadLDAPAttrMap(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://localhost:5432/identityhub")
	setEnv(t, "ENC_KEY", testEncKey(t))
	setEnv(t, "LDAP_URL", "ldap://dir.example.com:389")
	setEnv(t, "LDAP_BASE_DN", "dc=example,dc=com")
	setEnv(t, "LDAP_ATTR_MAP", "department:dept, employeeID:employee-id")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.LDAP.AttrMap) != 2 || cfg.LDAP.AttrMap["department"] != "dept" ||
		cfg.LDAP.AttrMap["employeeID"] != "employee-id" {
		t.Errorf("AttrMap = %v", cfg.LDAP.AttrMap)
	}
}

func TestLoadLDAPAttrMapFailures(t *testing.T) {
	validURL := "postgres://localhost:5432/identityhub"
	validKey := testEncKey(t)
	cases := []struct {
		name string
		raw  string
	}{
		{"missing colon", "department"},
		{"empty key", "department:"},
		{"empty upstream", ":dept"},
		{"bad upstream", "dep artment:dept"},
		{"uppercase key", "department:Dept"},
		{"repeated upstream", "department:dept,department:other"},
		{"two upstreams one key", "department:dept,ou:dept"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setEnv(t, "DATABASE_URL", validURL)
			setEnv(t, "ENC_KEY", validKey)
			setEnv(t, "LDAP_URL", "ldap://dir.example.com:389")
			setEnv(t, "LDAP_BASE_DN", "dc=example,dc=com")
			setEnv(t, "LDAP_ATTR_MAP", tc.raw)
			if _, err := Load(); err == nil {
				t.Fatal("Load() = nil error, want failure")
			}
		})
	}
}

func TestLoadLegacyProviderDefaults(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://localhost:5432/identityhub")
	setEnv(t, "ENC_KEY", testEncKey(t))

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.LDAPProvider.Enabled() {
		t.Error("LDAP provider must be disabled by default (empty LDAP_MODE)")
	}
	if cfg.LDAPProvider.Port != DefaultLDAPServerPort {
		t.Errorf("LDAPProvider.Port = %d, want %d", cfg.LDAPProvider.Port, DefaultLDAPServerPort)
	}
	if !cfg.RADIUS.Enabled || cfg.RADIUS.Port != DefaultRADIUSPort {
		t.Errorf("RADIUS = %+v, want enabled on %d", cfg.RADIUS, DefaultRADIUSPort)
	}
	if cfg.LDAPProvider.CacheTTL != DefaultLDAPCacheTTL {
		t.Errorf("LDAP CacheTTL = %v, want %v", cfg.LDAPProvider.CacheTTL, DefaultLDAPCacheTTL)
	}
	if cfg.LDAPProvider.BindCacheTTL != DefaultLDAPBindCacheTTL {
		t.Errorf("LDAP BindCacheTTL = %v, want %v", cfg.LDAPProvider.BindCacheTTL, DefaultLDAPBindCacheTTL)
	}
	if cfg.AuditRetention != 0 {
		t.Errorf("AuditRetention = %v, want 0 (keep forever by default)", cfg.AuditRetention)
	}
}

func TestLoadCacheAndRetention(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://localhost:5432/identityhub")
	setEnv(t, "ENC_KEY", testEncKey(t))
	setEnv(t, "LDAP_MODE", "ldap")
	setEnv(t, "LDAP_ALLOWED_CIDRS", "127.0.0.1/32")
	setEnv(t, "LDAP_CACHE_TTL", "30s")
	setEnv(t, "LDAP_BIND_CACHE_TTL", "0")
	setEnv(t, "AUDIT_RETENTION", "2160h")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.LDAPProvider.CacheTTL != 30*time.Second {
		t.Errorf("CacheTTL = %v, want 30s", cfg.LDAPProvider.CacheTTL)
	}
	if cfg.LDAPProvider.BindCacheTTL != 0 {
		t.Errorf("BindCacheTTL = %v, want 0 (disabled)", cfg.LDAPProvider.BindCacheTTL)
	}
	if cfg.AuditRetention != 2160*time.Hour {
		t.Errorf("AuditRetention = %v, want 2160h", cfg.AuditRetention)
	}
}

func TestLoadCacheAndRetentionFailures(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://localhost:5432/identityhub")
	setEnv(t, "ENC_KEY", testEncKey(t))
	setEnv(t, "LDAP_MODE", "ldap")
	setEnv(t, "LDAP_ALLOWED_CIDRS", "127.0.0.1/32")
	for env := range map[string]bool{"LDAP_CACHE_TTL": true, "LDAP_BIND_CACHE_TTL": true, "AUDIT_RETENTION": true} {
		t.Run(env, func(t *testing.T) {
			t.Setenv(env, "-1s")
			if _, err := Load(); err == nil {
				t.Errorf("Load() with %s=-1s succeeded, want error", env)
			}
		})
	}
}

func TestLoadLegacyProviders(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://localhost:5432/identityhub")
	setEnv(t, "ENC_KEY", testEncKey(t))
	setEnv(t, "LDAP_MODE", "ldap")
	setEnv(t, "LDAP_PORT", "1389")
	setEnv(t, "LDAP_ALLOWED_CIDRS", "10.0.0.0/8, 192.168.1.50")
	setEnv(t, "LDAP_SERVE_BASE_DN", "dc=example,dc=com")
	setEnv(t, "RADIUS_ENABLED", "false")
	setEnv(t, "RADIUS_PORT", "11812")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.LDAPProvider.Enabled() || cfg.LDAPProvider.Mode != "ldap" {
		t.Errorf("LDAPProvider = %+v, want enabled ldap mode", cfg.LDAPProvider)
	}
	if cfg.LDAPProvider.ServeBaseDN != "dc=example,dc=com" {
		t.Errorf("ServeBaseDN = %q", cfg.LDAPProvider.ServeBaseDN)
	}
	if len(cfg.LDAPProvider.AllowedCIDRs) != 2 {
		t.Fatalf("AllowedCIDRs = %d nets, want 2", len(cfg.LDAPProvider.AllowedCIDRs))
	}
	if !cfg.LDAPProvider.AllowedCIDRs[0].Contains(net.ParseIP("10.1.2.3")) {
		t.Error("10.1.2.3 must be inside 10.0.0.0/8")
	}
	if !cfg.LDAPProvider.AllowedCIDRs[1].Contains(net.ParseIP("192.168.1.50")) {
		t.Error("bare IP whitelist entry must match itself as /32")
	}
	if cfg.RADIUS.Enabled || cfg.RADIUS.Port != 11812 {
		t.Errorf("RADIUS = %+v, want disabled on 11812", cfg.RADIUS)
	}
}

func TestLoadLegacyProviderFailures(t *testing.T) {
	validURL := "postgres://localhost:5432/identityhub"
	validKey := testEncKey(t)

	cases := []struct {
		name string
		env  map[string]string
	}{
		{"LDAP_MODE bogus", map[string]string{"LDAP_MODE": "ldapi"}},
		{"LDAP plaintext without whitelist", map[string]string{"LDAP_MODE": "ldap"}},
		{"LDAP port bad", map[string]string{"LDAP_MODE": "ldap", "LDAP_ALLOWED_CIDRS": "10.0.0.0/8", "LDAP_PORT": "abc"}},
		{"LDAP port range", map[string]string{"LDAP_MODE": "ldap", "LDAP_ALLOWED_CIDRS": "10.0.0.0/8", "LDAP_PORT": "0"}},
		{"LDAP whitelist bad entry", map[string]string{"LDAP_MODE": "ldap", "LDAP_ALLOWED_CIDRS": "not-a-cidr"}},
		{"LDAPS without cert pair", map[string]string{"LDAP_MODE": "ldaps"}},
		{"StartTLS with cert but no key", map[string]string{"LDAP_MODE": "starttls", "LDAP_TLS_CERT_FILE": "/tmp/c.pem"}},
		{"RADIUS port bad", map[string]string{"RADIUS_PORT": "abc"}},
		{"RADIUS port range", map[string]string{"RADIUS_PORT": "70000"}},
		{"RADIUS enabled bad bool", map[string]string{"RADIUS_ENABLED": "sometimes"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"DATABASE_URL", "ENC_KEY", "LDAP_MODE", "LDAP_PORT", "LDAP_ALLOWED_CIDRS", "LDAP_TLS_CERT_FILE", "LDAP_TLS_KEY_FILE", "RADIUS_ENABLED", "RADIUS_PORT"} {
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

func TestLDAPProviderTLSModesNeedOnlyCertPair(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://localhost:5432/identityhub")
	setEnv(t, "ENC_KEY", testEncKey(t))
	setEnv(t, "LDAP_MODE", "STARTTLS")
	setEnv(t, "LDAP_TLS_CERT_FILE", "/tmp/c.pem")
	setEnv(t, "LDAP_TLS_KEY_FILE", "/tmp/k.pem")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.LDAPProvider.Mode != "starttls" {
		t.Errorf("Mode = %q, want lowercased starttls", cfg.LDAPProvider.Mode)
	}
	// TLS modes boot without a whitelist (encryption replaces the
	// plaintext lockdown), but the whitelist still applies when set.
	if len(cfg.LDAPProvider.AllowedCIDRs) != 0 {
		t.Errorf("AllowedCIDRs = %v, want empty", cfg.LDAPProvider.AllowedCIDRs)
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

func TestLoadStorageDefaults(t *testing.T) {
	setEnv(t, "DATABASE_URL", "postgres://localhost:5432/identityhub")
	setEnv(t, "ENC_KEY", testEncKey(t))
	t.Setenv("STORAGE_BACKEND", "")
	t.Setenv("STORAGE_DIR", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Storage.Backend != StorageLocal || cfg.Storage.Dir != DefaultStorageDir {
		t.Errorf("storage = %+v, want local backend", cfg.Storage)
	}
	if !cfg.Storage.S3UseSSL {
		t.Error("S3 TLS must default to on")
	}
}

func TestLoadStorageFailures(t *testing.T) {
	validURL := "postgres://localhost:5432/identityhub"
	validKey := testEncKey(t)

	cases := []struct {
		name string
		env  map[string]string
	}{
		{"bad backend", map[string]string{"STORAGE_BACKEND": "gcs"}},
		{"s3 without credentials", map[string]string{"STORAGE_BACKEND": "s3"}},
		{"s3 without bucket", map[string]string{
			"STORAGE_BACKEND": "s3", "STORAGE_S3_ENDPOINT": "https://s3.example.com",
			"STORAGE_S3_ACCESS_KEY": "ak", "STORAGE_S3_SECRET_KEY": "sk",
		}},
		{"s3 bad ssl flag", map[string]string{
			"STORAGE_BACKEND": "s3", "STORAGE_S3_ENDPOINT": "https://s3.example.com",
			"STORAGE_S3_BUCKET": "b", "STORAGE_S3_ACCESS_KEY": "ak",
			"STORAGE_S3_SECRET_KEY": "sk", "STORAGE_S3_USE_SSL": "nope",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range []string{"DATABASE_URL", "ENC_KEY", "STORAGE_BACKEND", "STORAGE_DIR", "STORAGE_S3_ENDPOINT", "STORAGE_S3_BUCKET", "STORAGE_S3_ACCESS_KEY", "STORAGE_S3_SECRET_KEY", "STORAGE_S3_USE_SSL"} {
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
