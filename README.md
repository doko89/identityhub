# IdentityHub

Single-tenant Identity Provider: one place for users, groups, and apps —
login via LDAP/local, SSO via OIDC/SAML, legacy via LDAP/RADIUS, plus MFA,
an app dashboard, and branding. See [PRD.md](PRD.md),
[TECH_SPEC.md](docs/TECH_SPEC.md), [DESIGN.md](docs/DESIGN.md).

Status: M0 foundation (this task). Login, protocols, and MFA land in M1–M7.

## Quickstart

Requirements: Go ≥ 1.24, Node ≥ 20, Docker (for Postgres).

```sh
# 1. Config
cp .env.example .env   # then set DATABASE_URL + ENC_KEY (openssl rand -base64 32)

# 2. Database (example: local docker)
docker run -d --name identityhub-pg \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=identityhub -p 5432:5432 postgres:16-alpine

# 3. Frontend build (embeds into the Go binary via go:embed)
cd web && npm install && npm run build && cd ..

# 4. Migrate + bootstrap the first admin
go run ./cmd/identityhub migrate up
go run ./cmd/identityhub create-admin --username root --email root@example.com

# 5. Run
go run ./cmd/identityhub serve     # HTTP API + web/ (LDAP/RADIUS from M4)
go run ./cmd/identityhub worker    # sync/email/cleanup jobs
```

Open `http://localhost:8080/login`. Probes: `GET /healthz` (liveness, no DB),
`GET /readyz` (readiness, pings Postgres).

## Layout

- `cmd/identityhub` — single binary: `serve|worker|migrate|create-admin`
- `internal/domain` — entities + ports (imports no other internal package)
- `internal/config` — env-only config + boot validation
- `internal/adapter/{postgres,crypto}` — pgx stores, goose runner, argon2id
- `internal/delivery/http` — chi router, scs sessions, embedded SPA
- `internal/worker` — periodic jobs (session/token cleanup in M0)
- `migrations` — goose SQL (`00001_init.sql` seeds `ih_admin` + branding)
- `web` — React+Vite+TS SPA; `web/dist` is the embedded production build

Dependency rule: `delivery → usecase → domain`; `adapter` implements
domain-owned interfaces; `main.go` is the only wiring site.

## Checks

```sh
go vet ./... && gofmt -l cmd internal web migrations  # must print nothing
go test ./...                                          # unit
TEST_DATABASE_URL=postgres://... go test -tags=integration ./internal/adapter/postgres/
cd web && npm run build   # tsc + vite
```

## Deploy

Single binary: `npm run build` in `web/`, then `go build ./cmd/identityhub`.
Configure only via env (see `.env.example`); TLS terminates at the reverse
proxy. `migrate up` runs separately before first `serve`.
