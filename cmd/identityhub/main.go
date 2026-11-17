// Command identityhub is the single IdentityHub binary (TECH_SPEC §3).
//
//	identityhub serve        # HTTP API + embedded web/ (+ LDAP/RADIUS from M4)
//	identityhub worker       # LDAP sync, email outbox, cleanup jobs
//	identityhub migrate      # goose up (also: down, status)
//	identityhub create-admin # bootstrap the first ih_admin member
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/identityhub/identityhub/internal/adapter/crypto"
	"github.com/identityhub/identityhub/internal/adapter/ldapclient"
	"github.com/identityhub/identityhub/internal/adapter/mailer"
	"github.com/identityhub/identityhub/internal/adapter/oidc"
	"github.com/identityhub/identityhub/internal/adapter/postgres"
	adaptersaml "github.com/identityhub/identityhub/internal/adapter/saml"
	"github.com/identityhub/identityhub/internal/config"
	deliveryhttp "github.com/identityhub/identityhub/internal/delivery/http"
	"github.com/identityhub/identityhub/internal/domain"
	usecaseaudit "github.com/identityhub/identityhub/internal/usecase/audit"
	usecaseauth "github.com/identityhub/identityhub/internal/usecase/auth"
	usecaseoidcflow "github.com/identityhub/identityhub/internal/usecase/oidcflow"
	usecasesamlflow "github.com/identityhub/identityhub/internal/usecase/samlflow"
	usecaseuser "github.com/identityhub/identityhub/internal/usecase/user"
	"github.com/identityhub/identityhub/internal/worker"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "identityhub: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: identityhub <serve|worker|migrate|create-admin> [flags]")
	}
	switch args[0] {
	case "serve":
		return runServe(args[1:])
	case "worker":
		return runWorker(args[1:])
	case "migrate":
		return runMigrate(args[1:])
	case "create-admin":
		return runCreateAdmin(args[1:])
	case "-h", "-help", "--help", "help":
		fmt.Println("usage: identityhub <serve|worker|migrate|create-admin> [flags]")
		return nil
	default:
		return fmt.Errorf("unknown command %q: want serve|worker|migrate|create-admin", args[0])
	}
}

// setup loads config, opens logging + database. Every command needs all
// three, so they share one helper.
func setup(ctx context.Context) (config.Config, *slog.Logger, *postgres.DB, error) {
	cfg, err := config.Load()
	if err != nil {
		return config.Config{}, nil, nil, err
	}
	log := newLogger(cfg)
	db, err := postgres.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return config.Config{}, nil, nil, err
	}
	return cfg, log, db, nil
}

// services is the wired M1 dependency graph. main.go is the only
// concrete wiring site (TECH_SPEC §4).
type services struct {
	auth         *usecaseauth.Service
	users        *usecaseuser.Service
	audits       *usecaseaudit.Service
	groups       *postgres.GroupRepository
	registry     *postgres.SessionRegistryRepository
	dir          domain.Directory // nil when LDAP_URL is unset
	oidc         domain.OIDCProvider
	oidcFlow     *usecaseoidcflow.Service
	challenges   *postgres.OIDCChallengeRepository
	oidcClients  *postgres.OIDCClientRepository
	saml         domain.SAMLProvider
	samlFlow     *usecasesamlflow.Service
	samlRequests *postgres.SAMLRequestRepository
	samlSPs      *postgres.SAMLSPRepository
}

// wireServices builds repositories, adapters and usecases. LDAP and SMTP
// degrade gracefully: an unset LDAP_URL disables directory login/sync,
// an unset SMTP_HOST logs mail instead of delivering it.
func wireServices(ctx context.Context, db *postgres.DB, cfg config.Config, log *slog.Logger) (*services, error) {
	users := postgres.NewUserRepository(db)
	groups := postgres.NewGroupRepository(db)
	auditRepo := postgres.NewAuditRepository(db)
	passwords := postgres.NewPasswordRepository(db)
	registry := postgres.NewSessionRegistryRepository(db)
	oidcClients := postgres.NewOIDCClientRepository(db)
	consents := postgres.NewOIDCConsentRepository(db)
	challenges := postgres.NewOIDCChallengeRepository(db)
	audits := usecaseaudit.New(auditRepo, nil)

	var m domain.Mailer
	if cfg.SMTP.Enabled() {
		smtpMailer, err := mailer.NewSMTP(mailer.Config{
			Host: cfg.SMTP.Host, Port: cfg.SMTP.Port, Username: cfg.SMTP.Username,
			Password: cfg.SMTP.Password, From: cfg.SMTP.From,
		})
		if err != nil {
			return nil, fmt.Errorf("wire mailer: %w", err)
		}
		m = smtpMailer
	} else {
		log.Info("SMTP not configured; mail goes to the log (set SMTP_HOST to deliver)")
		m = mailer.NewLog(log)
	}

	var dir domain.Directory
	if cfg.LDAP.Enabled() {
		client, err := ldapclient.New(ldapclient.Config{
			URL: cfg.LDAP.URL, BindDN: cfg.LDAP.BindDN, BindPassword: cfg.LDAP.BindPassword,
			BaseDN: cfg.LDAP.BaseDN, UserFilter: cfg.LDAP.UserFilter, GroupFilter: cfg.LDAP.GroupFilter,
			AdminGroupDN: cfg.LDAP.AdminGroupDN, Timeout: cfg.LDAP.Timeout,
		})
		if err != nil {
			return nil, fmt.Errorf("wire ldapclient: %w", err)
		}
		dir = client
	} else {
		log.Info("LDAP upstream not configured; directory login/sync disabled (set LDAP_URL to enable)")
	}

	authSvc, err := usecaseauth.New(usecaseauth.Deps{
		Users: users, Groups: groups, Resets: passwords, History: passwords,
		Sessions: registry, Audit: audits, Hasher: crypto.Hasher{},
		Mailer: m, Directory: dir, BaseURL: cfg.BaseURL,
	})
	if err != nil {
		return nil, fmt.Errorf("wire auth: %w", err)
	}
	userSvc, err := usecaseuser.New(usecaseuser.Deps{
		Users: users, Groups: groups, Sessions: registry, Audit: audits, Hasher: crypto.Hasher{},
	})
	if err != nil {
		return nil, fmt.Errorf("wire user: %w", err)
	}
	oidcFlow, err := usecaseoidcflow.New(usecaseoidcflow.Deps{
		Clients: oidcClients, Groups: groups, Consents: consents,
	})
	if err != nil {
		return nil, fmt.Errorf("wire oidcflow: %w", err)
	}
	oidcProvider, err := oidc.New(ctx, db.Pool, oidcClients, oidc.Config{
		Issuer: cfg.BaseURL, GlobalSecret: cfg.EncKey[:], SendDebug: !cfg.IsProduction(),
	})
	if err != nil {
		return nil, fmt.Errorf("wire oidc: %w", err)
	}
	samlSPs := postgres.NewSAMLSPRepository(db)
	samlRequests := postgres.NewSAMLRequestRepository(db)
	samlFlow, err := usecasesamlflow.New(usecasesamlflow.Deps{
		SPs: samlSPs, Groups: groups,
	})
	if err != nil {
		return nil, fmt.Errorf("wire samlflow: %w", err)
	}
	samlProvider, err := adaptersaml.New(ctx, db.Pool, samlSPs, adaptersaml.Config{
		Issuer: cfg.BaseURL,
	})
	if err != nil {
		return nil, fmt.Errorf("wire saml: %w", err)
	}
	return &services{
		auth: authSvc, users: userSvc, audits: audits, groups: groups,
		registry: registry, dir: dir, oidc: oidcProvider, oidcFlow: oidcFlow,
		challenges: challenges, oidcClients: oidcClients,
		saml: samlProvider, samlFlow: samlFlow,
		samlRequests: samlRequests, samlSPs: samlSPs,
	}, nil
}

func newLogger(cfg config.Config) *slog.Logger {
	level := slog.LevelInfo
	if !cfg.IsProduction() {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	if cfg.LogFormat == "json" || cfg.IsProduction() {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, log, db, err := setup(ctx)
	if err != nil {
		return err
	}
	defer db.Close()

	svc, err := wireServices(ctx, db, cfg, log)
	if err != nil {
		return err
	}
	sessions := deliveryhttp.NewSessionManager(db.Pool, deliveryhttp.SessionConfig{
		IdleTimeout: cfg.SessionIdle,
		Lifetime:    cfg.SessionLifetime,
		Secure:      cfg.CookieSecure(),
	})
	handlers := deliveryhttp.NewHandlers(deliveryhttp.HandlerDeps{
		Sessions: sessions, Registry: svc.registry, Auth: svc.auth, Users: svc.users,
		Audits: svc.audits, Groups: svc.groups, Directory: svc.dir, Log: log,
		OIDC: svc.oidc, OIDCFlow: svc.oidcFlow, Challenges: svc.challenges, OIDCClients: svc.oidcClients,
		SAML: svc.saml, SAMLFlow: svc.samlFlow, SAMLRequests: svc.samlRequests, SAMLSPs: svc.samlSPs,
	})
	handler := deliveryhttp.NewRouter(deliveryhttp.Deps{Sessions: sessions, DB: db, Handlers: handlers})

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	log.Info("serving HTTP", "port", cfg.HTTPPort, "env", cfg.AppEnv)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

func runWorker(args []string) error {
	fs := flag.NewFlagSet("worker", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, log, db, err := setup(ctx)
	if err != nil {
		return err
	}
	defer db.Close()

	svc, err := wireServices(ctx, db, cfg, log)
	if err != nil {
		return err
	}
	runner := worker.NewRunner(db.Pool, cfg.WorkerSyncInterval, log)
	if svc.dir != nil {
		adminDN := cfg.LDAP.AdminGroupDN
		runner.WithLDAPSync(func(syncCtx context.Context) error {
			snap, err := svc.dir.Snapshot(syncCtx)
			if err != nil {
				return err
			}
			rep, err := svc.users.SyncFromDirectory(syncCtx, snap, adminDN)
			if err != nil {
				return err
			}
			log.Info("ldap sync applied",
				"created", rep.Created, "updated", rep.Updated,
				"disabled", rep.Disabled, "reenabled", rep.Reenabled,
				"admin_added", len(rep.AdminAdded), "conflicts", len(rep.Conflicts))
			for _, c := range rep.Conflicts {
				log.Warn("ldap sync conflict: local user kept, directory entry ignored", "username", c)
			}
			return nil
		})
	}
	return runner.Run(ctx)
}

func runMigrate(args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	// migrate needs config but manages its own short-lived connection.
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	action := "up"
	if fs.NArg() > 0 {
		action = fs.Arg(0)
	}
	switch action {
	case "up":
		if err := postgres.MigrateUp(ctx, cfg.DatabaseURL); err != nil {
			return fmt.Errorf("migrate up: %w", err)
		}
		fmt.Println("migrations applied")
		return nil
	case "down":
		if err := postgres.MigrateDown(ctx, cfg.DatabaseURL); err != nil {
			return fmt.Errorf("migrate down: %w", err)
		}
		fmt.Println("rolled back one migration")
		return nil
	case "status":
		return postgres.MigrationStatus(ctx, cfg.DatabaseURL)
	default:
		return fmt.Errorf("unknown migrate action %q: want up|down|status", action)
	}
}

func runCreateAdmin(args []string) error {
	fs := flag.NewFlagSet("create-admin", flag.ContinueOnError)
	username := fs.String("username", "", "admin username (required)")
	email := fs.String("email", "", "admin email (required)")
	password := fs.String("password", "", "admin password, min 12 chars (or $IDENTITYHUB_ADMIN_PASSWORD)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	*username = strings.TrimSpace(*username)
	*email = strings.TrimSpace(*email)
	if *password == "" {
		*password = os.Getenv("IDENTITYHUB_ADMIN_PASSWORD")
	}
	if *username == "" || *email == "" {
		return fmt.Errorf("create-admin: --username and --email are required")
	}
	if len(*password) < 12 {
		return fmt.Errorf("create-admin: password must be at least 12 characters (PRD §6.10)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, log, db, err := setup(ctx)
	if err != nil {
		return err
	}
	defer db.Close()

	users := postgres.NewUserRepository(db)
	groups := postgres.NewGroupRepository(db)

	if _, err := users.ByUsername(ctx, *username); err == nil {
		return fmt.Errorf("create-admin: username %q already exists", *username)
	} else if !isNotFound(err) {
		return fmt.Errorf("create-admin: lookup: %w", err)
	}
	hash, err := crypto.Hasher{}.Hash(*password)
	if err != nil {
		return fmt.Errorf("create-admin: hash password: %w", err)
	}
	u, err := users.Create(ctx, domain.User{
		Username: *username, Email: *email, DisplayName: *username,
		PasswordHash: hash, Source: domain.SourceLocal, IsActive: true,
	})
	if err != nil {
		return fmt.Errorf("create-admin: create user: %w", err)
	}
	admin, err := groups.ByName(ctx, domain.AdminGroup)
	if err != nil {
		return fmt.Errorf("create-admin: %s group missing (run `migrate up` first): %w", domain.AdminGroup, err)
	}
	if err := groups.AddMember(ctx, u.ID, admin.ID); err != nil {
		return fmt.Errorf("create-admin: add to %s: %w", domain.AdminGroup, err)
	}
	log.Info("admin created", "username", *username, "id", u.ID.String())
	fmt.Printf("admin %q created and added to %s\n", *username, domain.AdminGroup)
	return nil
}

func isNotFound(err error) bool {
	return errors.Is(err, domain.ErrNotFound)
}
