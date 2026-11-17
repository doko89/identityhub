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
	"github.com/identityhub/identityhub/internal/adapter/postgres"
	"github.com/identityhub/identityhub/internal/config"
	deliveryhttp "github.com/identityhub/identityhub/internal/delivery/http"
	"github.com/identityhub/identityhub/internal/domain"
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

	sessions := deliveryhttp.NewSessionManager(db.Pool, deliveryhttp.SessionConfig{
		IdleTimeout: cfg.SessionIdle,
		Lifetime:    cfg.SessionLifetime,
		Secure:      cfg.CookieSecure(),
	})
	handler := deliveryhttp.NewRouter(deliveryhttp.Deps{Sessions: sessions, DB: db})

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

	return worker.NewRunner(db.Pool, cfg.WorkerSyncInterval, log).Run(ctx)
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
