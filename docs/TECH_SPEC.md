# TECH_SPEC — IdentityHub (Go)

Product reference: [PRD.md](../PRD.md). This is the v1 technical specification: Go stack, library choices, architecture, data model, and endpoints. Core principle: **never reimplement protocols from scratch** — every protocol is handled by a proven library; our code holds only business rules (users, policies, attribute mapping).

All Go modules below were verified resolvable via the Go proxy on 17 Nov 2026.

## 1. Core Stack

| Layer | Choice | Notes |
|---|---|---|
| Language | Go (>= 1.24) | One language for core, worker, and protocol servers |
| HTTP router | `github.com/go-chi/chi/v5` | Standard routing + middleware |
| Database | PostgreSQL 16 + `github.com/jackc/pgx/v5` | Direct access via pgx, no ORM in v1 |
| Migrations | `github.com/pressly/goose/v3` | Ordered SQL files in `migrations/` |
| Sessions | `github.com/alexedwards/scs/v2` + `pgxstore` | Server-side sessions in Postgres |
| UI | React + Vite + TS + Tailwind + shadcn/ui | Feature-based SPA in `web/`; production build embedded in the Go binary via `go:embed` |
| FE routing | `react-router-dom` | Login, dashboard, admin, account routes |
| FE data | `@tanstack/react-query` | API fetch + cache |
| FE state | `zustand` | Light state (user session, theme) |
| Logging | `log/slog` (stdlib) | JSON in production |
| Config | env vars, stdlib parsing | No config files in v1 |
| Password hashing | `golang.org/x/crypto` (argon2id) | bcrypt only as a verification fallback |

No ORM in v1: explicit pgx queries are easier to audit for auth code and avoid surprising lazy-loading behavior.

## 2. Per-Feature Library Map

| Feature | Library | Library role | Our code role |
|---|---|---|---|
| OIDC/OAuth2 provider | `github.com/ory/fosite` | Grant flows, token validation, PKCE, JWKS, discovery | Storage interface implementations (client, authorize code, token, key) on Postgres; login + consent pages |
| OIDC alternative | `github.com/zitadel/oidc/v3` | Ready-made OP package, higher-level API | Used only if fosite proves too heavy in M2; exactly one is used |
| SAML IdP | `github.com/crewjam/saml` (+ `samlidp` subpackage as reference) | SP metadata parsing, assertion building, signing (via `goxmldsig`) | Per-app SP registry, attribute mapping, SSO/SLO endpoints |
| LDAP upstream (client) | `github.com/go-ldap/ldap/v3` | Bind, search, TLS | Sync connector + login bind |
| LDAP provider (server) | `github.com/vjeantet/ldapserver` | LDAP protocol listener, bind/search handlers | Handlers delegate to the user usecase |
| RADIUS provider (server) | `layeh.com/radius` | RADIUS packet server | Access-request handler (PAP first) to the user usecase |
| MFA TOTP | `github.com/pquerna/otp` | Seed generation, QR URI, code validation | Enroll, when-required policy, anti-replay, recovery codes |
| MFA WebAuthn (v1.1) | `github.com/go-webauthn/webauthn` | Registration + authentication ceremonies | Credential storage, policy, device management pages |
| webp encoding | `github.com/kolesa-team/go-webp` | Pure-Go webp encode/decode | Re-encode uploads to webp in `adapter/storage` |
| S3 storage | `github.com/minio/minio-go/v7` | S3-compatible client | `s3` backend in `adapter/storage` |

Hard rule: our code **must not** hand-parse or hand-sign JWT/SAML/XML tokens. Everything goes through the libraries above. Exceptions must be discussed and recorded here.

Library risk notes:

- `layeh.com/radius` (canonical import path — the module declares itself as `layeh.com/radius`, not the github path) has no tagged releases; pin the pseudo-version (`v0.0.0-20231213012653-1006025d24f8`) and record it in `go.mod`. The package API is small and stable.
- `samlidp` is a minimal example IdP; budget M3 time to harden it (audience validation, assertion lifetime limits, audit).
- `fosite` is full-powered but has a steep learning curve; wrap it in `internal/adapter/oidc` behind `domain`-owned interfaces, so it can be swapped for `zitadel/oidc` without touching usecases or delivery.

## 3. Process Architecture (v1)

One Go binary, four run modes:

```text
identityhub serve    # HTTP (JSON API + OIDC + SAML + embedded web/) + LDAP + RADIUS listeners
identityhub worker   # LDAP sync, email sending, token rotation, session cleanup
identityhub migrate      # goose up/down
identityhub create-admin # bootstrap the first admin (must change password + enroll MFA at first login)
```

Build: `npm run build` in `web/` produces `web/dist`, which `go build` embeds via `go:embed` — the release artifact is a single binary with no separate static files to deploy.

The LDAP/RADIUS servers run as goroutines in the same process and call the same usecases as the HTTP handlers. A separate outpost pattern (standalone edge processes) is **not** v1; it is only reconsidered for remote sites or network-isolation needs.

## 4. Repo Structure (Clean Architecture)

```text
identityhub/
  cmd/identityhub/main.go        # serve/worker/migrate/create-admin subcommands + DI wiring
  internal/
    domain/          # entities + interfaces (ports): repository, clock, hasher, mailer, tokenstore
      user.go group.go application.go binding.go audit.go branding.go mfa.go errors.go
    usecase/         # business rules; knows no HTTP/SQL/protocols
      auth/          # password login, policy evaluation, session decisions
      user/          # user/group CRUD, LDAP sync results
      mfa/           # TOTP enroll/verify, recovery codes, MFA policy
      app/           # app catalog + access bindings + launch
      branding/      # brand/theme settings
      audit/         # audit log writes and reads
      asset/         # asset uploads: type validation, authorization, webp conversion
      oidcflow/      # login+consent decisions for authorize requests
      samlflow/      # assertion decisions for AuthnRequests
    adapter/         # implementations of domain interfaces (outer details)
      postgres/      # pgx: all repositories + fosite storage
      oidc/          # fosite wrapper (swappable for zitadel/oidc)
      saml/          # crewjam/saml wrapper
      ldapclient/    # upstream LDAP connector + sync (go-ldap)
      crypto/        # argon2id, seed/secret encryption (x/crypto)
      mailer/        # email sender (SMTP)
      storage/       # interface + local/S3 backends, webp re-encode
    delivery/        # entry points: translate protocols -> usecases
      http/          # chi router, JSON API handlers, middleware, serve embedded web/ build
      ldap/          # LDAP server handlers (vjeantet/ldapserver)
      radius/        # RADIUS server handlers (layeh/radius)
    worker/          # scheduled jobs: ldap_sync, cleanup, email_outbox (call usecases)
    config/          # env parsing + boot-time validation
  migrations/      # goose SQL
  web/             # React app (Vite + TS + Tailwind + shadcn/ui), feature-based
    src/
      app/         # router, providers (query/theme/auth), global layout
      shared/      # ui/ (shadcn), lib/, hooks/, api-client/
      features/
        auth/      # login, MFA, password, session (api/ components/ pages/ hooks/)
        dashboard/ # user app menu
        account/   # user MFA management
        admin-users/ admin-apps/ admin-audit/  # per-feature admin console
        branding/  # theme provider + brand tokens from API
  docs/TECH_SPEC.md
  PRD.md
```

Dependency rule: `delivery` -> `usecase` -> `domain`; `adapter` implements `domain`-owned interfaces. `domain` imports no other internal package. `usecase` imports no `adapter`, `delivery`, chi, pgx, or protocol libraries — all outer details are injected as domain interfaces. `main.go` is the only concrete wiring site.

Frontend conventions (shadcn): `web/components.json` sets the alias and install path for components to `src/shared/ui/`; all components are installed via the CLI (`npx shadcn@latest add ...`), never hand-written when a registry item exists; styling must use semantic tokens (`bg-primary`, `text-muted-foreground`) so CSS-variable branding works — raw colors and manual `dark:` overrides are forbidden. Initial v1 components: button, input, card, dialog, table, dropdown-menu, badge, avatar, skeleton, alert, toast, tabs.

## 5. Data Model (core)

```sql
users(id, username UNIQUE, email, display_name, password_hash NULLABLE,
      source TEXT, -- 'local' | 'ldap'
      external_dn NULLABLE, is_active, avatar_url NULLABLE, created_at, updated_at)
groups(id, name UNIQUE, description)
user_groups(user_id, group_id)
applications(id, slug UNIQUE, name, description, icon_url, launch_url,
             group_label, provider_type, -- 'oidc'|'saml'|'ldap'|'radius'
             is_visible, sort_order)
oidc_clients(id, application_id UNIQUE, client_id UNIQUE, client_secret_hash,
             redirect_uris TEXT[], scopes TEXT[])
saml_sps(id, application_id UNIQUE, entity_id UNIQUE, acs_url,
         slo_url NULLABLE, metadata_xml, cert_pem NULLABLE)
ldap_provider_config(id, application_id UNIQUE, bind_dn_template, base_dn, user_filter)
radius_clients(id, application_id UNIQUE, nas_identifier, shared_secret_enc, UNIQUE(nas_identifier))
app_bindings(id, application_id, binding_type, -- 'user'|'group'|'policy'
             user_id NULLABLE, group_id NULLABLE, policy_expr NULLABLE)
mfa_totp(user_id UNIQUE, seed_enc, created_at, last_step BIGINT DEFAULT 0)
mfa_recovery_codes(id, user_id, code_hash UNIQUE, used_at NULLABLE)
password_reset_tokens(id, user_id, token_hash UNIQUE, expires_at, used_at NULLABLE, created_ip INET)
password_history(id, user_id, password_hash, created_at)
webauthn_credentials(id, user_id, credential_id UNIQUE, public_key, sign_count, aaguid, name)
assets(id UUID, asset_type TEXT, -- 'avatar'|'app_logo'|'saas_logo'|'login_background'
       object_key UNIQUE, byte_size INT, width INT, height INT,
       uploaded_by NULLABLE, created_at)
branding(id CHECK (id = 1), org_name, logo_url, favicon_url, primary_color,
         theme TEXT DEFAULT 'system', login_background_url, custom_css NULLABLE)
audit_log(id BIGSERIAL, at TIMESTAMPTZ, actor_user_id NULLABLE, application_id NULLABLE,
          method TEXT, result TEXT, ip INET, detail JSONB)
user_attr_defs(id, attr_key UNIQUE, attr_type, -- 'string'|'number'|'boolean'
               multi BOOLEAN DEFAULT FALSE, created_at)
user_attr_values(user_id, def_id, ordinal, value TEXT, -- PK(user_id, def_id, ordinal)
                 source TEXT DEFAULT 'admin') -- 'admin'|'ldap'
```

Encryption keys for `seed_enc` and `shared_secret_enc` come from env (`ENC_KEY`, 32 bytes); decrypted only in memory during verification.

`avatar_url`, `icon_url`, and `logo_url` hold public paths of the form `/uploads/<assetType>/<uuid>.webp` referencing an `assets` row.

Admin model: admin rights come solely from membership in the reserved `ih_admin` group (seeded in the initial migration; cannot be deleted or renamed). Guards: admins cannot remove themselves or the last member; every membership change is audited. Each `/api/admin/*` request checks membership directly so revoked admins lose access immediately. The first admin is bootstrapped via `create-admin` (must change password and enroll MFA at first login).

Custom attributes: the admin defines the schema in `user_attr_defs` (lowercase LDAP-safe key, type, multi flag; reserved wire names rejected) and per-user values live in `user_attr_values`. Keys double as the wire names on LDAP, OIDC and SAML. `source` tracks the last writer: mapped keys are upstream-managed — each directory sync replaces them wholesale (`ldap`), so admin edits to a mapped key are overwritten, while `admin` values are never touched by sync. Def deletion cascades its values.

## 6. Endpoints and Flows

### 6.1 Frontend (SPA) and session API

SPA routes (React): `/login`, `/mfa`, `/forgot-password`, `/reset-password`, `/` (dashboard), `/account/mfa`, `/admin/*`. The backend serves a JSON API; sessions via scs cookie:

- `POST /api/auth/login` — username/password; rate limited per IP + per user.
- `POST /api/auth/mfa/totp` — second step when policy requires it.
- `POST /api/auth/logout`, `GET /api/auth/me` — end and read the active session.
- `POST /api/account/password/change` — current + new password twice; MFA re-auth required when active; terminates other sessions.
- `POST /api/auth/password/forgot` — request a reset link; always a generic success response (anti account-enumeration).
- `POST /api/auth/password/reset` — token + new password; single-use token, 15-minute TTL.
- `POST /api/admin/users/:id/password` — admin sets a local user's password; LDAP users rejected explicitly; recorded in audit.
- `GET /api/my-apps` — the user's app dashboard (only passing bindings); each app carries `is_favorite` + `last_launched_at` for the favorites/recents rows.
- `PUT|DELETE /api/my-apps/:slug/favorite` — pin/unpin a dashboard app (same visibility rules as launch).
- `GET /api/apps/:slug/launch` — start SSO into an app (IdP-initiated); successful opens stamp the recents row.
- `/api/account/mfa/*` — TOTP enroll/disable, regenerate recovery codes (re-auth with the old factor required to change factors).
- `/api/admin/*` — user/group/app/provider CRUD, branding, audit; requires `ih_admin` membership + MFA.
- `GET|POST /api/admin/user-attrs`, `DELETE /api/admin/user-attrs/:key` — attribute schema CRUD (def deletion cascades values).
- `GET /api/admin/users/:id/attrs`, `PUT /api/admin/users/:id/attrs` — per-user values (scalar or array per key, null clears; unknown keys and type violations fail the write).
- `GET /api/branding` — active brand/theme settings (public, no secrets).

### 6.2 OIDC (via fosite)

- `GET /oauth2/auth`, `POST /oauth2/token`, `GET /oauth2/userinfo`, `GET /.well-known/openid-configuration`, `GET /oauth2/jwks`.
- Flow: authorization code + PKCE required for public clients; client secrets for confidential ones.
- Claims: `sub` = stable user UUID, `preferred_username`, `email`, `name`, `groups` (group-name array), plus custom attributes as typed claims (scalars, arrays when multi-valued). Discovery `claims_supported` appends the def keys dynamically (degrades to the static list when the store is unwired or fails).
- Refresh token rotation: the old token dies when used.

### 6.3 SAML (via crewjam/saml)

- `GET /saml/metadata` — IdP metadata.
- `POST /saml/sso` — accept AuthnRequest, authenticate the user, send a signed Response to the ACS.
- `GET|POST /saml/slo` — basic logout.
- NameID = username (unspecified), or email (emailAddress) for SPs registered with `name_id=email`; attributes: email, displayName, groups, plus custom attributes as `xs:string` values (sorted by key).

### 6.4 LDAP provider (via vjeantet/ldapserver)

- Connection modes (deployment-wide env `LDAP_MODE`): `ldap` (plaintext, default port 1389/389), `ldaps` (TLS-wrapped listener, default 636), `starttls` (plaintext port that upgrades via the StartTLS extended operation).
- TLS config (`LDAP_TLS_CERT_FILE`, `LDAP_TLS_KEY_FILE`): TLS 1.2 minimum, certificates from the secret store. Plaintext mode refuses to boot unless the whitelist below is non-empty.
- IP whitelist: global `LDAP_ALLOWED_CIDRS` (comma-separated CIDRs) enforced in the library's `OnNewConnection` hook — rejected connections are closed before any LDAP bytes are parsed, so even plaintext 389 only talks to known clients.
- Bind: DN `uid=<username>,ou=users,dc=identityhub` + password; the delivery handler calls `usecase/auth`. Binds stay password-only for every user including admins (no MFA gate: the protocols have no second channel) — one account serves both web and legacy logins.
- Search: users (`inetOrgPerson`: uid/cn/sn/displayName/mail/memberOf plus custom attributes) and groups per the app's `ldap_provider_config`. Point lookups (`(uid=x)`, bare or inside AND) resolve one indexed row; custom keys are filterable like built-ins. Listings cost a fixed handful of queries (users, groups, one membership join, one attribute batch) — no per-user/per-member queries.

### 6.5 RADIUS provider (via layeh/radius, port 1812)

- PAP Access-Request: username/password against local users; minimal reply attributes (Framed-IP when configured).
- Same credential rule as the LDAP provider: password-only for every user including admins, no MFA gate.

### 6.6 Worker

- `ldap_sync` every N minutes: pull users/groups, soft-disable users missing from the directory (disable, don't delete); users in the directory group set as `LDAP_ADMIN_GROUP_DN` are added to `ih_admin`. `LDAP_ATTR_MAP=upstream:key,...` imports directory attributes into mapped custom keys (keys without a def are skipped; uncoercible values are dropped, never failing the sync).
- Daily `session_cleanup`, `token_cleanup`.
- `email_outbox`: failed second-factor notifications, MFA factor changes, password reset links.

### 6.7 Asset uploads

- `POST /api/uploads` (multipart: `file` + `asset_type` = `avatar`|`app_logo`|`saas_logo`|`login_background`): users may upload an avatar for their own account; `app_logo`/`saas_logo`/`login_background` are admin-only. Response: public path.
- `GET /uploads/<assetType>/<uuid>.webp` — public read with `Cache-Control: public, max-age=31536000, immutable`.
- Flow: the frontend converts to webp via the Canvas API first (saves bandwidth + instant preview), then the backend still validates and re-encodes to webp via the library (max 512px long edge for icons, 1920px for `login_background`, quality 80) — the `.webp` contract is guaranteed by the server, not the client.
- Validation: jpeg/png/webp input, max 10 MB (check magic bytes, not the extension); random UUID filenames.
- Storage goes through the `domain.FileStorage` interface (`Put/Get/Delete`) with 2 backends in `adapter/storage`: `local` (filesystem, served by Go/reverse proxy) and `s3` (minio-go, S3-compatible). Selected via env `STORAGE_BACKEND=local|s3` (+ endpoint/bucket/credentials for s3). The S3 backend is nice-to-have, built after local is stable.

## 7. Branding/Theme

- The single `branding(id=1)` row is read once per request (in-memory cache + invalidation on admin update).
- The frontend fetches the brand via `GET /api/branding`; `features/branding` applies it as shadcn CSS variables (`--primary`, `--background`, ...) + the `light|dark|system` theme class, plus the org logo and name. The row also carries the admin dashboard theme (`dashboard_columns` 2-4, `dashboard_icon_shape`, `dashboard_density`, `dashboard_background` + photo URL); the user may override columns/density per device (localStorage).
- `custom_css` is sanitized server-side (blocks `@import`, `url(`, `</style>`); max 10 KB.

## 8. Security (concise, binding)

- TLS terminates at the reverse proxy; the binary only listens for HTTP/LDAP/RADIUS on private networks (except ports that must be public).
- All secrets come from env/secret store; no secrets in the repo or logs.
- Rate limits: login 10/min/IP + 5/min/user; TOTP verify 5/min/user; forgot-password 3/hour/email + 10/hour/IP; progressive lockout.
- Reset tokens: 256-bit random, stored hashed, 15-minute TTL, single-use, one active token per user; forgot responses always generic so account existence is not leaked.
- Uploads: reject non-jpeg/png/webp (magic bytes), 10 MB and dimension caps, UUID filenames with no user input in the path, serve as `image/webp` + `nosniff`; app/SaaS logos are admin-only.
- LDAP provider: modes `ldap`/`ldaps`/`starttls`; TLS 1.2+ with managed certificates; plaintext boots only with a non-empty `LDAP_ALLOWED_CIDRS`; whitelist enforced at connection accept, before any bind or search is parsed.
- TOTP: reject reuse of an accepted code (atomic `last_step`), encrypted seeds, enroll shows the QR exactly once.
- Sessions: `HttpOnly + Secure + SameSite=Lax` cookies, 30-minute idle timeout, 12-hour absolute.
- Admins (`ih_admin` members): MFA required on web login and app launch, no exceptions. Legacy LDAP/RADIUS binds stay password-only (those protocols have no second channel).

## 9. Testing

- Unit: table-driven policy bindings, attribute mapping, config validation, TOTP anti-replay (`usecase/...` packages, no DB; adapters mocked via domain interfaces).
- Integration (real Postgres via docker required): fosite storage, end-to-end TOTP enroll/verify, app bindings, audit.
- Protocols: OIDC against fosite as the client; SAML with a `crewjam/saml` test SP; LDAP/RADIUS with real clients (`go-ldap`, `layeh/radius` client) against an in-process listener — not mocked handlers.
- Frontend: component and hook units (vitest + testing-library), login→dashboard e2e (playwright).
- Merge gate: `go vet ./...`, `gofmt -l`, unit + integration green. Coverage target for `usecase/...` >= 85%.

## 10. Decisions vs Alternatives

| Decision | Rejected alternative | Reason |
|---|---|---|
| One binary, in-process LDAP/RADIUS | Separate authentik-style outposts | Simpler v1 operations; outposts only for remote sites |
| pgx with no ORM | GORM/ent | Auth queries must be explicit and auditable |
| React SPA + shadcn/ui | Server-rendered Go templates | Ready-made components + CSS-variable theming for branding; team choice |
| fosite (in adapter, behind domain interfaces) | Hand-rolled OIDC | No hand-made crypto/protocols |
| scs + Postgres sessions | Stateless JWT sessions | Instant revoke (logout, user disable) with no denylist |

## 11. Build Order (maps to PRD milestones)

1. M0: `config`, `domain`, `adapter/postgres` + initial migration (seeds `ih_admin`), `serve` + `/healthz`, sessions, `create-admin`, React scaffold + empty login page embedded via `go:embed`.
2. M1: `adapter/ldapclient` (bind + sync) + `usecase/user`, password login + password management (change/forgot/admin reset), `usecase/audit`.
3. M2: `adapter/oidc` + `usecase/oidcflow` + consent page; validate with 2 test clients.
4. M3: `adapter/saml` + `usecase/samlflow` + 1 real SP.
5. M4: in-process `delivery/ldap` (modes ldap/ldaps/starttls + IP whitelist) + `delivery/radius` calling the same usecases.
6. M5: `usecase/mfa` (TOTP + recovery + policy) + `/account/mfa` page.
7. M6: dashboard + `usecase/app` (bindings + launch flow) + asset uploads (local backend).
8. M7: `usecase/branding`, S3 storage backend (nice-to-have), final rate limits, hardening, per-protocol `docs/INTEGRATION.md`.
