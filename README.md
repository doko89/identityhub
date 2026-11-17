# IdentityHub

Single-tenant Identity Provider: one place for users, groups, and apps —
login via LDAP/local, SSO via OIDC/SAML, legacy via LDAP/RADIUS, plus MFA,
an app dashboard, and branding. See [PRD.md](PRD.md),
[TECH_SPEC.md](docs/TECH_SPEC.md), [DESIGN.md](docs/DESIGN.md).

Status: M4 legacy providers (in-process LDAP + RADIUS PAP) over M3 SAML + M2 OIDC + M1 login.
MFA, dashboard, and hardening land in M5–M7.

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
go run ./cmd/identityhub serve     # HTTP API + web/ + LDAP/RADIUS providers
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
curl -b jar -X POST localhost:8080/api/admin/users/<id>/invite
curl -b jar localhost:8080/api/admin/groups
curl -b jar localhost:8080/api/admin/audit?result=failure
curl -b jar -X POST localhost:8080/api/admin/ldap/test

# Custom attributes (schema + values; ride LDAP/OIDC/SAML under their key)
curl -b jar -X POST localhost:8080/api/admin/user-attrs \
  -d '{"key":"dept","type":"string"}'
curl -b jar -X PUT localhost:8080/api/admin/users/<id>/attrs \
  -d '{"dept":"eng"}'
```

Every login — success, failure, or rate-limited — lands in `audit_log`
(fail-closed: a failed audit write fails the login).

## OIDC (M2)

Provider endpoints (authorization code + PKCE for public clients,
`client_secret_basic`/`_post` for confidential ones, refresh rotation,
`sub` = user UUID, claims `preferred_username`/`email`/`name`/`groups` + custom attributes):

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

## SAML (M3)

IdP endpoints (crewjam/saml behind `domain.SAMLProvider`; NameID =
username; attributes `email`/`displayName`/`groups` + custom attributes; assertion and
response both signed; AuthnRequests verified when signed, replay-checked
by request ID):

```sh
curl localhost:8080/saml/metadata
# SP-initiated (Redirect or POST binding):
#   GET /saml/sso?SAMLRequest=...&RelayState=...[&SigAlg=...&Signature=...]
#   → /login?next=... (when logged out) → auto-submit form to the SP ACS
# IdP-initiated (dashboard launch):
#   GET /saml/sso?sp=<entityID>&RelayState=...
# Single logout: GET|POST /saml/slo (LogoutRequest → signed LogoutResponse;
#   bare request → local logout + redirect home)
```

SPs register by metadata import: `saml.ParseSPMetadata` extracts
entityID, the default POST ACS, the preferred SLO endpoint and the
signing certificate into `saml_sps` (raw XML kept for audit). The IdP
signing key persists in `saml_keys`, so the metadata certificate is
stable across restarts. One real SP (crewjam/saml client) passes
end-to-end in `internal/delivery/http/saml_integration_test.go
-tags=integration`: Redirect + signed POST SSO, login-round-trip stash
replay, signed-redirect tamper rejection, IdP-initiated SSO, SLO with
session kill, ForceAuthn/IsPassive, and rejection paths. Admin UI/API
for SP registration arrives with the app-catalog milestone; the
`domain.SAMLSPStore` port and Postgres repository are already in place.

## LDAP + RADIUS (M4)

In-process legacy providers calling the same `usecase/auth` as HTTP
login (local argon2id, directory bind with JIT, fail-closed audit).
Both deny users who must use MFA — admins always (TECH_SPEC §8, no
exceptions) — since a legacy bind cannot prompt for a second factor;
per-app MFA policy for regular users arrives with the app catalog.

```sh
# LDAP (vjeantet/ldapserver): modes ldap/ldaps/starttls via LDAP_MODE
# (listener disabled when unset). Bind DN:
#   uid=<username>,ou=users,dc=identityhub
# Plaintext refuses to boot without LDAP_ALLOWED_CIDRS, enforced in
# OnNewConnection before any LDAP bytes are parsed. Search serves
# ou=users (inetOrgPerson: uid/cn/sn/mail/memberOf + custom attrs) and ou=groups
# (groupOfNames: cn/member) to bound connections only.
ldapsearch -H ldap://localhost:1389 -x \
  -D uid=ara,ou=users,dc=identityhub -w '...' \
  -b ou=users,dc=identityhub '(uid=ara)' mail memberOf
# FortiGate group mapping, DN matching, and cache tuning
# (LDAP_CACHE_TTL/LDAP_BIND_CACHE_TTL): docs/INTEGRATION.md §4.2–4.3

# RADIUS (layeh/radius): PAP on UDP RADIUS_PORT (default 1812).
# NAS devices register in radius_clients with nas_identifier = source
# IP; unknown NAS and wrong-secret packets are dropped unverified.
# Credential failures get Access-Reject (+ Reply-Message reason);
# system failures are dropped so the NAS retries.
```

End-to-end coverage with real clients against ephemeral listeners:
`internal/delivery/{ldap,radius}/*_integration_test.go
-tags=integration` (bind/search/whitelist/StartTLS/LDAPS, PAP
accept/reject/MFA-deny/NAS-drop, audit rows). NAS registration is an
admin API since M7 (`POST /api/admin/radius/clients`, secrets sealed
with ENC_KEY via AES-256-GCM); RADIUS also carries per-NAS flood
protection (300 packets/min, excess dropped before the NAS lookup).

## MFA (M5)

TOTP (pquerna/otp behind `domain.TOTP`) + single-use recovery codes
(`usecase/mfa`): QR enroll shown once, narrow window (current step + at
most one previous, never the future step), atomic anti-replay (one
UPDATE accepts a step only when newer than the recorded one — reused
codes fail even under concurrency), seeds sealed with ENC_KEY, failed
second-factor attempts emailed best-effort. Policy: admins always
require MFA (login parks at setup until enrolled; `/api/admin/*`
additionally requires a session factor verification); regular users by
opt-in enroll and per-app `mfa_required` flags.

```sh
# Login flow: POST /api/auth/login → {mfa_required, setup_required?}
#   → /mfa (verify) or /mfa?setup=1 (enroll doubles as the second step)
#   → POST /api/auth/mfa/totp {code} or {recovery_code} (5/min/user + lockout)
# Self-service: GET /api/account/mfa/status, POST /api/account/mfa/enroll(+/confirm),
#   POST /api/account/mfa/disable, POST /api/account/mfa/recovery/regenerate
#   (factor changes re-auth with the old factor)
# MFA loss: POST /api/admin/users/:id/mfa/reset (audited), user re-enrolls
# Password change with MFA: code fresh within 10 min or pass totp_code
curl localhost:8080/api/my-apps  # dashboard (below), after login
```

## Dashboard + uploads (M6)

App catalog (`usecase/app`): `GET /api/my-apps` lists visible apps
whose bindings admit the user; `GET /api/apps/:slug/launch` resolves
the admin-provided SSO entry (MFA-gated per policy — the client steps
up and retries). No bindings = all active users allowed; with
bindings, all-or-any evaluation (strictest-wins across the app's rows:
one `all` binding makes the whole app require-all). Binding targets:
`user` (user_id), `group` (group_id), `policy` (`group:<name>` or
`email_domain:<domain>` clauses joined by `|`). OIDC authorize and
SAML SSO enforce the same bindings, and legacy LDAP/RADIUS binds deny
per-app-MFA users (the global LDAP tree keeps the admin-only gate —
no app identity on the wire). Admin API: `/api/admin/apps` CRUD +
`/bindings` sub-collection.

Uploads (`usecase/asset` + `adapter/storage` local backend): `POST
/api/uploads` (multipart `file` + `asset_type=avatar|app_logo|saas_logo`;
avatars any user, logos admin-only) validates magic bytes (jpeg/png/
webp, max 10 MB), re-encodes to webp server-side (pure-Go lossless,
512px long edge — the `.webp` contract never trusts the client), and
answers the public path; `GET /uploads/<type>/<uuid>.webp` serves
`image/webp` with immutable caching. Storage via `domain.FileStorage`:
`STORAGE_BACKEND=local` (dir `STORAGE_DIR`) or `s3` (minio-go,
endpoint/bucket/credentials via `STORAGE_S3_*`, bucket checked at
boot) since M7.

## Hardening (M7)

Branding (`usecase/branding` + `GET /api/branding` public /
`PATCH /api/admin/branding`): the singleton row is cached in memory and
refreshed on admin update; `custom_css` is sanitized server-side
(`@import`/`url(`/`</style>` refused, 10 KB cap) and the SPA theme
provider (`features/branding`) applies variables + `light|dark|system`
class without a redeploy. Provider registration closes the T3/T4 gap:
`/api/admin/oidc/clients` (confidential secrets bcrypt-hashed, shown
once; public PKCE-only; redirect URIs https except loopback),
`/api/admin/saml/sps` (metadata-XML import), `/api/admin/radius/clients`
(NAS secrets sealed, shown once) — one credential of each kind per app.
Audit CSV: `GET /api/admin/audit/export` shares the list filters,
capped at 10.000 newest rows. Per-protocol operator guide (a non-dev
admin adds an OIDC app following it alone): `docs/INTEGRATION.md`; v1
scope decisions: `docs/DECISIONS.md`.

## API keys + CLI

Personal API keys (`/account/api-keys` in the console, or
`POST /api/account/api-keys` with `{"name","expires_in_days?"}`) authenticate
the `identityhub-cli` management tool and any Bearer client. Only the SHA-256
hash is stored; the `ih_...` secret is shown once. A key inherits its
owner's permissions, so admin keys are only issued from MFA-verified
sessions (admins always have MFA) — that issuance is what satisfies the
admin MFA gate for Bearer requests. Users with MFA step up with a TOTP code
when the session verification is older than 10 minutes. `GET` lists,
`DELETE /api/account/api-keys/{id}` revokes with immediate effect.

```sh
make build-cli
export IDENTITYHUB_API_KEY=ih_...   # from /account/api-keys
identityhub-cli whoami
identityhub-cli users list --q ara
identityhub-cli groups members add <group-id> --user <user-id>
identityhub-cli apps create --slug wiki --name Wiki --provider-type oidc
identityhub-cli audit list --result failure --limit 20
identityhub-cli --json branding get  # every command speaks --json too
```

`users`, `groups`, `apps`, `bindings`, `oidc`, `saml`, `radius`, `audit`,
`ldap test`, `branding` and `apikeys` cover the same surface as the admin
console; `--server` (or `$IDENTITYHUB_SERVER`) points the CLI at another
origin. Keys minted through the CLI itself are never MFA-verified, so a
fresh admin key always comes from the browser.

## Layout

- `cmd/identityhub` — single binary: `serve|worker|migrate|create-admin`
- `cmd/identityhub-cli` — management CLI over the JSON API (Bearer API key)
- `internal/domain` — entities + ports (imports no other internal package)
- `internal/config` — env-only config + boot validation (LDAP/SMTP included)
- `internal/usecase/{auth,user,audit,oidcflow,samlflow,mfa,app,asset,branding}` — login, password mgmt, user/group CRUD, LDAP sync apply, audit (+CSV), OIDC authorize/consent + SAML assertion decisions, TOTP/recovery/policy, app catalog + bindings + launch + provider registration, webp uploads, brand singleton
- `internal/adapter/{postgres,crypto,ldapclient,mailer,oidc,saml,storage}` — pgx stores + goose runner, argon2id + TOTP + seed seal, go-ldap connector, SMTP/log mail, fosite OIDC behind `domain.OIDCProvider`, crewjam SAML behind `domain.SAMLProvider`, local/S3 file storage
- `internal/delivery/http` — chi router, JSON API, rate limits, scs sessions, MFA second step + dashboard + uploads + branding + provider registration, embedded SPA
- `internal/delivery/{ldap,radius}` — in-process LDAP (bind/search/StartTLS/LDAPS + CIDR gate) and RADIUS PAP via `usecase/auth.LoginLegacy` (deny-when-MFA-required incl. per-app policy, per-NAS flood protection)
- `internal/worker` — periodic jobs (LDAP sync when configured + session/token/OIDC/SAML cleanup)
- `migrations` — goose SQL (`00001` core schema + `ih_admin` seed, `00002` session registry, `00003` OIDC storage, `00004` SAML keys + request stash, `00005` per-app MFA flag, `00006` app new-tab, `00007` branding tagline, `00008` API keys, `00009` LDAP indexes, `00010` user attrs, `00011` directory version)
- `web` — React+Vite+TS SPA (vitest + eslint + playwright); `web/dist` is the embedded production build
- `docs/INTEGRATION.md` — per-protocol operator guide; `docs/DECISIONS.md` — v1 scope decisions

Dependency rule: `delivery → usecase → domain`; `adapter` implements
domain-owned interfaces; `main.go` is the only wiring site.

## Checks

```sh
go vet ./... && gofmt -l cmd internal  # must print nothing
go test ./...                          # unit
go test ./internal/usecase/... -cover  # each package >= 85%
TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5434/identityhub \
  go test -tags=integration ./...      # real Postgres (+ S3 with TEST_S3_ENDPOINT)
cd web && npm run typecheck && npm run lint && npm run test && npm run build
PLAYWRIGHT_BASE_URL=http://localhost:8080 \
  TEST_E2E_USER=u TEST_E2E_PASSWORD=p npm run test:e2e  # against live serve
```

## Deploy

Single binary: `npm run build` in `web/`, then `go build ./cmd/identityhub`.
Configure only via env (see `.env.example`); TLS terminates at the reverse
proxy. `migrate up` runs separately before first `serve`.
