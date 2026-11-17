# IdentityHub

Single-tenant Identity Provider: one place for users, groups, and apps —
login via LDAP/local, SSO via OIDC/SAML, legacy via LDAP/RADIUS, plus MFA,
an app dashboard, and branding. See [PRD.md](PRD.md),
[TECH_SPEC.md](docs/TECH_SPEC.md), [DESIGN.md](docs/DESIGN.md).

Status: M2 OIDC provider (code+PKCE, refresh rotation, discovery/JWKS) + consent page.
Protocols and MFA land in M2–M7.

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

## API (M1)

Sessions via `identityhub_session` cookie (HttpOnly + Secure in
production + SameSite=Lax). Rate limits per TECH_SPEC §8
(login 10/min/IP + 5/min/user with progressive lockout).

```sh
# Login (local argon2id or LDAP bind incl. just-in-time provisioning)
curl -c jar -X POST localhost:8080/api/auth/login \
  -d '{"username":"root","password":"..."}'
curl -b jar localhost:8080/api/auth/me
curl -b jar -X POST localhost:8080/api/auth/logout

# Password management (local users only; LDAP users get an explicit
# "contact your directory admin" message)
curl -b jar -X POST localhost:8080/api/account/password/change \
  -d '{"current_password":"...","new_password":"...","new_password_confirm":"..."}'
curl -X POST localhost:8080/api/auth/password/forgot -d '{"login":"ara"}'
curl -X POST localhost:8080/api/auth/password/reset \
  -d '{"token":"...","new_password":"...","new_password_confirm":"..."}'

# Admin (ih_admin members; every membership change is audited)
curl -b jar localhost:8080/api/admin/users?q=ara
curl -b jar -X POST localhost:8080/api/admin/users \
  -d '{"username":"ara","email":"ara@example.com","password":"..."}'
curl -b jar -X POST localhost:8080/api/admin/users/<id>/password \
  -d '{"new_password":"..."}'
curl -b jar localhost:8080/api/admin/groups
curl -b jar localhost:8080/api/admin/audit?result=failure
curl -b jar -X POST localhost:8080/api/admin/ldap/test
```

Every login — success, failure, or rate-limited — lands in `audit_log`
(fail-closed: a failed audit write fails the login).

## OIDC (M2)

Provider endpoints (authorization code + PKCE for public clients,
`client_secret_basic`/`_post` for confidential ones, refresh rotation,
`sub` = user UUID, claims `preferred_username`/`email`/`name`/`groups`):

```sh
curl localhost:8080/.well-known/openid-configuration
curl localhost:8080/oauth2/jwks
# Browser flow: GET /oauth2/auth?client_id=...&redirect_uri=...&response_type=code&scope=openid...
#   → /login?next=... (when logged out) → /consent?challenge=... → client redirect with ?code=
curl -X POST localhost:8080/oauth2/token -d 'grant_type=authorization_code&code=...&redirect_uri=...&client_id=...&code_verifier=...'
curl -H "Authorization: Bearer ..." localhost:8080/oauth2/userinfo
```

Test clients are seeded in the integration suite
(`internal/delivery/http/oidc_integration_test.go -tags=integration`):
one public PKCE client and one confidential client, both exercised
end-to-end (consent grant/deny, exchange, userinfo, refresh rotation,
code-replay revocation). Admin UI/API for client registration arrives
with the app-catalog milestone; the `domain.OIDCClientStore` port and
Postgres repository are already in place.

## Layout

- `cmd/identityhub` — single binary: `serve|worker|migrate|create-admin`
- `internal/domain` — entities + ports (imports no other internal package)
- `internal/config` — env-only config + boot validation (LDAP/SMTP included)
- `internal/usecase/{auth,user,audit,oidcflow}` — login, password mgmt, user/group CRUD, LDAP sync apply, audit, OIDC authorize/consent decisions
- `internal/adapter/{postgres,crypto,ldapclient,mailer,oidc}` — pgx stores + goose runner, argon2id, go-ldap connector, SMTP/log mail, fosite OIDC behind `domain.OIDCProvider`
- `internal/delivery/http` — chi router, JSON API, rate limits, scs sessions, embedded SPA
- `internal/worker` — periodic jobs (LDAP sync when configured + session/token/OIDC cleanup)
- `migrations` — goose SQL (`00001` core schema + `ih_admin` seed, `00002` session registry, `00003` OIDC storage)
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
