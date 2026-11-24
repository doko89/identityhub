# IdentityHub Integration Guide (per protocol)

Connect a real application to IdentityHub without writing code. Every step
below is a copy-paste `curl` against the admin API plus the app's own
SSO settings page. Read §0–§1 once, then jump to your protocol (§2 OIDC,
§3 SAML, §4 LDAP, §5 RADIUS).

Conventions: `IDP=https://idp.example.com` is your public base URL
(`APP_BASE_URL`). All admin calls need the session cookie (§0).

## 0. Before you start: an admin API session

Admin API calls authenticate with a cookie session, and admins must pass
a second factor — there is no API token in v1. Keep one cookie jar:

```bash
IDP=https://idp.example.com
JAR=/tmp/ih-admin.jar   # chmod 600; delete when done

# 1. Password login. Unenrolled admins park at setup; enrolled admins
#    park at the second step.
curl -c "$JAR" -X POST "$IDP/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"root","password":"..."}'
# -> {"mfa_required":true,"setup_required":true}   (first time)
# -> {"mfa_required":true}                         (already enrolled)

# 2a. First time only: enroll TOTP. The response shows the secret ONCE —
#     add it to your authenticator app, then confirm with its code.
curl -b "$JAR" -c "$JAR" -X POST "$IDP/api/account/mfa/enroll" \
  -H 'Content-Type: application/json' -d '{}'
# -> {"secret":"JBSW...","otpauth_url":"otpauth://...","qr_png":"..."}
curl -b "$JAR" -c "$JAR" -X POST "$IDP/api/account/mfa/enroll/confirm" \
  -H 'Content-Type: application/json' -d '{"code":"123456"}'
# -> 200 plus recovery codes — store them offline. The session is now a
#    full admin session.

# 2b. Already enrolled: verify the second step instead.
curl -b "$JAR" -c "$JAR" -X POST "$IDP/api/auth/mfa/totp" \
  -H 'Content-Type: application/json' -d '{"code":"123456"}'
# -> 200, full admin session.

# 3. Sanity check (200 with your user, is_admin true).
curl -b "$JAR" "$IDP/api/auth/me"
```

Sessions idle out after 30 minutes. If a call below returns 401, repeat
step 1 (+ 2b). Every login — success or failure — lands in the audit log
(§7).

## 1. Register the app in the catalog (once per app)

Each integration starts as one catalog row (dashboard tile, bindings,
per-app MFA). `provider_type` labels the primary protocol; it never
blocks registering other protocols for the same app.

```bash
curl -b "$JAR" -X POST "$IDP/api/admin/apps" \
  -H 'Content-Type: application/json' -d '{
    "slug": "wiki",
    "name": "Company Wiki",
    "description": "Internal docs",
    "launch_url": "https://wiki.example.com",
    "group_label": "Productivity",
    "provider_type": "oidc",
    "is_visible": true,
    "mfa_required": false
  }'
# -> 201 {"app":{"id":"<APP_ID>", ...}} — save APP_ID for §2/§3/§5.
```

Rules: `slug` + `name` required, slug unique; `provider_type` is one of
`oidc|saml|ldap|radius`. `mfa_required: true` forces a second factor
before this app launches (§6). Deleting the app cascades to its protocol
credentials: `curl -b "$JAR" -X DELETE "$IDP/api/admin/apps/<APP_ID>"`.

Exactly one protocol credential of each kind may exist per app (second
registration → `409 already exists`).

## 2. OIDC: web apps, SPAs, mobile (authorization code + PKCE)

IdentityHub is an OpenID Provider: discovery + JWKS + code flow with
PKCE for public clients, secrets for confidential ones, refresh-token
rotation, and a consent page with remembered grants.

Protocol endpoints (issuer = your `APP_BASE_URL`):

| Purpose       | Endpoint                             |
|---------------|--------------------------------------|
| Discovery     | `GET /.well-known/openid-configuration` |
| Authorize     | `GET /oauth2/auth`                   |
| Token         | `POST /oauth2/token`                 |
| User info     | `GET /oauth2/userinfo`               |
| Signing keys  | `GET /oauth2/jwks`                   |

### 2.1 Register the client

```bash
# Confidential web app (server side keeps a secret):
curl -b "$JAR" -X POST "$IDP/api/admin/oidc/clients" \
  -H 'Content-Type: application/json' -d '{
    "application_id": "<APP_ID>",
    "redirect_uris": ["https://wiki.example.com/oauth2/callback"],
    "scopes": ["openid", "profile", "email", "groups"]
  }'
# -> 201 {"client":{"client_id":"oidc-...","redirect_uris":[...],
#          "scopes":[...],"public":false},
#         "client_secret":"<shown ONCE — copy it now>"}

# Public SPA/mobile (PKCE-only, no secret is issued or accepted):
curl -b "$JAR" -X POST "$IDP/api/admin/oidc/clients" \
  -H 'Content-Type: application/json' -d '{
    "application_id": "<APP_ID>",
    "redirect_uris": ["https://spa.example.com/callback"],
    "public": true
  }'
```

Rules: at least one `redirect_uri`; `https` everywhere except loopback
(`http://localhost|127.0.0.1|[::1]` for local dev); no `#fragment`;
scopes come from `openid profile email groups offline_access` (default
`openid profile email`) and must include `openid`. `client_id` is
generated (`oidc-<hex>`) unless you pass your own
(3–128 chars, letters/digits/`._-`). The secret is bcrypt-hashed at
rest; lists never re-show it (`GET /api/admin/oidc/clients`). Rotate by
deleting and re-registering:
`curl -b "$JAR" -X DELETE "$IDP/api/admin/oidc/clients/<CLIENT_ID>"`.

### 2.2 Configure the app (any OIDC client)

Point the app's generic-OIDC / OAuth2 form at discovery and fill:

- Issuer / discovery: `$IDP/.well-known/openid-configuration`
- Client ID / secret: from §2.1 (public clients: PKCE ON, secret empty)
- Scopes: `openid profile email groups` (add `offline_access` only if
  the app needs refresh tokens)
- Redirect URI: exactly one of the registered URIs (byte-identical)

Example (Grafana `grafana.ini`): `enabled=true`,
`client_id=<id>`, `client_secret=<secret>`,
`auth_url=$IDP/oauth2/auth`, `token_url=$IDP/oauth2/token`,
`api_url=$IDP/oauth2/userinfo`, `scopes=openid profile email groups`,
plus `role_attribute_path` on the `groups` claim if you map roles.

### 2.3 Claims you can rely on

| Claim              | Value                                    |
|--------------------|------------------------------------------|
| `sub`              | Stable user UUID (join key, never reuse) |
| `preferred_username` | IdentityHub username                   |
| `email`, `name`    | Email, display name                      |
| `groups`           | Array of group names (needs `groups` scope) |

### 2.4 Behaviour notes

- First login per user+client shows the consent page (granted scopes
  are remembered; repeat logins skip it while the grant covers the
  request). Denying returns the app `access_denied`.
- Refresh tokens rotate: each use issues a new one and kills the old;
  replaying a code or an old refresh token kills the grant (fail
  closed). Request `offline_access`/`offline` scope to get one.
- Users outside the app's bindings (§6) are refused at authorize time.

### 2.5 Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| App says `redirect_uri mismatch` / authorize 400s | The app sent a URI not registered byte-for-byte in §2.1 (scheme, host, port, path, trailing slash). |
| Token call 401s (confidential) | Wrong/rotated secret, or a public client sending one. Re-register to rotate. |
| Public client authorize fails | PKCE `code_challenge` missing — enable PKCE in the app. |
| `access_denied` right after login | User denied consent, or bindings (§6) exclude them. |
| Loop login → app → login | App session not persisting, or clock skew > minutes between app and IdP. |

## 3. SAML 2.0: enterprise apps (SSO + SLO)

IdentityHub is a SAML Identity Provider: SP-initiated Redirect/POST,
IdP-initiated SSO, signed responses/assertions, and logout.

Protocol endpoints:

| Purpose       | Endpoint              |
|---------------|-----------------------|
| IdP metadata  | `GET /saml/metadata`  |
| SSO           | `GET|POST /saml/sso`  |
| Logout        | `GET|POST /saml/slo`  |
| IdP-initiated | `GET /saml/sso?sp=<entityID>` |

### 3.1 Register the SP (paste its metadata)

Get the app's SP metadata XML (its SSO settings page usually offers
"download metadata" or shows the XML). Save it to `sp.xml`, then:

```bash
python3 - <<'EOF' > /tmp/sp.json
import json
print(json.dumps({"application_id": "<APP_ID>",
                  "metadata_xml": open("sp.xml").read()}))
EOF
curl -b "$JAR" -X POST "$IDP/api/admin/saml/sps" \
  -H 'Content-Type: application/json' -d @/tmp/sp.json
# -> 201 {"sp":{"entity_id":"...","acs_url":"...","slo_url":"..."}}
```

IdentityHub picks the default POST assertion consumer service, the
preferred logout endpoint, and the signing certificate; the raw XML is
kept for audit (max 1 MB). Lists:
`GET /api/admin/saml/sps`. Re-import by deleting first (entity ids are
URLs, so delete takes a query parameter):

```bash
curl -b "$JAR" -X DELETE \
  "$IDP/api/admin/saml/sps?entity_id=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=""))' '<ENTITY_ID>')"
```

### 3.2 Configure the app

- IdP metadata / entity ID / SSO URL / certificate: all inside
  `$IDP/saml/metadata` — paste that URL into the app when it accepts
  "IdP metadata URL", else import the downloaded file.
- NameID: `username` (transient/persistent formats are not offered),
  or `email` for SPs registered with `name_id=email` (e.g. SendGrid).
- Attributes: `email`, `displayName`, `groups` (multi-valued group
  names), plus compat defaults `display_name`/`is_admin` (phpIPAM) and
  `FirstName`/`LastName` (SendGrid JIT). Map the app's email/name/role
  fields to these.
- Signatures: responses AND assertions are signed. Unsigned AuthnRequests
  are accepted; signed ones are verified against the imported SP
  certificate. `ForceAuthn` forces a fresh password login.

### 3.3 Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Import 400s | Not XML, no `entityID`/`SPSSODescriptor`, or no HTTP-POST ACS in the file. |
| App rejects the response | Clock skew between app and IdP, audience/`InResponseTo` mismatch, or the app fetched stale IdP metadata — re-import `$IDP/saml/metadata`. |
| Unknown issuer / ACS mismatch errors | The app sends a different entityID/ACS than imported — re-export SP metadata from the app and re-import. |
| User loops to login | Bindings (§6) exclude them, or the session expired mid-POST (stale challenge) — retry once. |

## 4. LDAP: legacy apps (Nextcloud, Jenkins, …)

IdentityHub serves a read-only LDAP tree for apps that cannot speak
modern SSO. One global tree, no per-app registration (the v1
`ldap_provider_config` rows are reserved, not served).

Enable on the server (env, then restart `serve`):

```bash
LDAP_MODE=ldap            # ldap | ldaps | starttls
LDAP_PORT=1389            # 389/636 are standard but need root
LDAP_ALLOWED_CIDRS=10.0.0.0/8,192.168.0.0/16   # REQUIRED for ldap mode
# ldaps/starttls additionally need:
# LDAP_TLS_CERT_FILE=/run/secrets/ldap.crt
# LDAP_TLS_KEY_FILE=/run/secrets/ldap.key      # TLS 1.2 minimum
```

App settings:

- Host/port: IdP host + `LDAP_PORT`; encryption per `LDAP_MODE`.
- Bind DN: `uid=<username>,ou=users,dc=identityhub` with the user's
  password. Search base: `ou=users,dc=identityhub`
  (users) / `ou=groups,dc=identityhub` (groups).
- Directory layout is fixed: `uid` = username, groups carry member
  `uid`s. Anonymous binds can only read the root DSE; search needs a
  bound user.

Rules that bite: every bind is a real login (password policy,
audit — §4.1). Plaintext mode refuses to boot without a whitelist,
enforced before any LDAP bytes are parsed.

### 4.1 MFA and service accounts

LDAP has no second-factor channel, so binds are password-only for
every user including `ih_admin` members — one account serves both web
and LDAP logins. The per-app `mfa_required` flag is enforced at
web/app launch, never on binds. Integrate accordingly:

- Human LDAP logins: the app's own session carries the risk
  (documented tradeoff); prefer `ldaps`/`starttls` so passwords never
  cross the network in clear, or
- Service accounts: create a dedicated non-admin user per app, give it
  a 20+ char random password, bind only with that DN.

### 4.2 FortiGate (SSL-VPN / IPsec with group mapping)

FortiGate authenticates with a bind, then maps the user to firewall
groups with a separate group search — a passing "test connectivity"
with empty groups means the group half mismatches, not the password.
Groups are `groupOfNames` under `ou=groups,dc=identityhub` with full
user DNs in `member`; user entries also carry `memberOf`.

Server settings (`User & Authentication > LDAP Servers`):

- Server Name/IP + port: IdP host + `LDAP_PORT` (use `ldaps` in
  production; plaintext only inside trusted nets with
  `LDAP_ALLOWED_CIDRS` set).
- Common Name Identifier: `uid`.
- Distinguished Name: `ou=users,dc=identityhub`, so the constructed
  bind DN is `uid=<username>,ou=users,dc=identityhub`.
- Bind Type: Regular (a service account DN), or per-user bind — either
  way the connection must be bound; anonymous search is rejected.
- Group Search Base: `ou=groups,dc=identityhub`, scope Subtree.
- Group Object Filter: leave the default
  `(&(objectClass=groupOfNames)(member=*))`, or narrow with the user
  DN the same way (`member=uid=<username>,ou=users,dc=identityhub`).
  DN comparison is spacing/casing-insensitive.

Then map firewall user groups to the LDAP `cn` values (the names must
match exactly), and verify from the FortiGate CLI before touching VPN
policies:

```bash
diagnose test authserver ldap <server-name> <username> <password>
# expect: authentication success + the matched group list
```

If groups stay empty, replicate the exact emitted filter with
`ldapsearch` against the IdP: groups there mean the Forti template or
the firewall-group name mapping is wrong, not the directory. Two
sharp edges: empty groups carry no `member` attribute at all, and
filters using LDAP matching rules (`member:1.2.840...:=...`,
nested-group lookups) are not decodable by the underlying LDAP
library — the server cannot respond to them, so clients must stick to
equality/substring/presence filters (FortiGate's defaults do).

### 4.3 Performance and scale

Whole-tree searches serve from an in-memory snapshot that refreshes
when the directory version moves (every user/group/membership/MFA
write bumps it, from any process) or when the TTL lapses; verified
local binds are remembered separately so boxes that re-bind every
operation skip argon2. Both caches are version-gated, audit writes
still run per bind, and directory (upstream) users are never cached:

```bash
LDAP_CACHE_TTL=5m        # tree snapshots (0 disables: every search reads fresh)
LDAP_BIND_CACHE_TTL=60s  # remembered binds (0 disables: every bind verifies)
```

Password hashing is argon2id at 32 MiB × 3 iterations with at most 4
concurrent computations process-wide (older 64 MiB hashes keep
verifying), so a burst of cold binds is memory-bounded at ~128 MiB
plus heap instead of scaling with concurrency.

Two more knobs for busy directories: `pool_max_conns` in
`DATABASE_URL` (the pool is shared by HTTP + LDAP; raise it under
concurrent LDAP load), and `AUDIT_RETENTION` (e.g. `2160h` = 90 days)
so the worker prunes `audit_log`, which otherwise grows one row per
bind forever.

### 4.4 Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Server refuses to start in `ldap` mode | `LDAP_ALLOWED_CIDRS` empty — set it (plaintext stays locked down). |
| `invalid credentials` for a correct password | Wrong bind DN shape (must be `uid=<u>,ou=users,dc=identityhub`), disabled user, or MFA-required user (§4.1). |
| Search returns nothing | Searching anonymously (bind first), or a filter outside the served subset — equality/presence/substring filters with AND/OR/NOT on `uid`/`cn`/`mail`/objectClass. |
| Connection reset on StartTLS | Cert/key missing or TLS < 1.2. |
| VPN login passes but groups are empty | Group search mismatch — see the FortiGate recipe (§4.2). |

## 5. RADIUS: VPN / Wi-Fi (PAP)

IdentityHub answers RADIUS Access-Request with PAP on UDP 1812
(`RADIUS_PORT`; disable with `RADIUS_ENABLED=false`). The NAS is
identified by its source IP; unknown NAS packets are dropped before
parsing, and per-NAS floods past 300 packets/minute are dropped too.

### 5.1 Register the NAS

```bash
curl -b "$JAR" -X POST "$IDP/api/admin/radius/clients" \
  -H 'Content-Type: application/json' -d '{
    "application_id": "<APP_ID>",
    "nas_identifier": "10.0.0.5"
  }'
# -> 201 {"client":{"nas_identifier":"10.0.0.5"},
#         "shared_secret":"<32 hex chars, shown ONCE>"}
```

`nas_identifier` must be the device's source IP (what the IdP sees —
check NAT). Pass your own `"shared_secret"` (≥ 8 chars) or omit it to
generate. Secrets are sealed with `ENC_KEY` at rest and never re-shown
(`GET /api/admin/radius/clients` lists devices only). Rotate by
deleting + re-registering:
`curl -b "$JAR" -X DELETE "$IDP/api/admin/radius/clients/10.0.0.5"`.

### 5.2 Configure the device (example: generic VPN gateway)

- Server: IdP host, port 1812, PAP, shared secret from §5.1.
- Usernames are IdentityHub usernames; passwords are user passwords.
- Accept = Access-Accept; wrong password/disabled user = Access-Reject
  with a `Reply-Message`. RADIUS is password-only (§4.1 rule): admins
  authenticate with the same account they use on the web, no second
  account needed.
- Expect retries, not errors, during IdP maintenance: system failures
  are dropped so the NAS retries; only credential failures reject.

### 5.3 Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| No response at all (timeout) | Unknown NAS IP (register §5.1 — mind NAT), wrong shared secret, `RADIUS_ENABLED=false`, or the per-NAS rate limit during a flood. All drop silently by design. |
| Rejects with "multi-factor ..." | MFA-required user over a protocol without MFA — see §5.2. |
| Rejects with "account disabled" | User deactivated in IdentityHub. |
| "directory unavailable" | Upstream LDAP (PRD §6.2) down — local users still work. |

## 6. Who sees the app: bindings, launch, per-app MFA

No bindings = every active user sees the app. Add bindings to restrict:
if any binding says `all`, every binding must match (strictest wins);
otherwise one matching binding suffices.

```bash
# Whole group (resolve the group id via GET /api/admin/groups):
curl -b "$JAR" -X POST "$IDP/api/admin/apps/<APP_ID>/bindings" \
  -H 'Content-Type: application/json' \
  -d '{"binding_type":"group","group_id":"<GROUP_ID>","eval_mode":"any"}'

# One user:
curl -b "$JAR" -X POST "$IDP/api/admin/apps/<APP_ID>/bindings" \
  -H 'Content-Type: application/json' \
  -d '{"binding_type":"user","user_id":"<USER_ID>","eval_mode":"any"}'

# Policy (OR with |): group:<name> or email_domain:<domain>:
curl -b "$JAR" -X POST "$IDP/api/admin/apps/<APP_ID>/bindings" \
  -H 'Content-Type: application/json' \
  -d '{"binding_type":"policy","policy_expr":"group:engineering|email_domain:example.com","eval_mode":"any"}'
```

Users open `GET /api/apps/<slug>/launch` (or click the dashboard tile)
to SSO in; excluded users are refused at authorize/assertion time, not
just hidden. Flip per-app MFA without touching the app:

```bash
curl -b "$JAR" -X PATCH "$IDP/api/admin/apps/<APP_ID>" \
  -H 'Content-Type: application/json' -d '{"mfa_required":true}'
```

## 7. Verify end-to-end (the 3-app checklist)

PRD §10 calls for ≥3 real integrations (≥1 OIDC, ≥1 SAML/RADIUS). For
each app, walk: register (§2/§3/§5) → bind (§6) → real login in the app
→ audit row. Every login produces exactly one audit entry:

```bash
# Watch the log (filters: actor, app, method, result, since, until):
curl -b "$JAR" "$IDP/api/admin/audit?method=oidc&result=success&limit=5"

# Export the evidence as CSV (same filters, max 10.000 newest rows):
curl -b "$JAR" -o audit.csv \
  "$IDP/api/admin/audit/export?method=radius&result=success"
head -3 audit.csv
# id,at,actor_user_id,application_id,method,result,ip,detail
```

Worked minimum: (1) one OIDC web app login (shows in audit with
`method=oidc`), (2) one SAML **or** RADIUS login (`method=saml` /
`method=radius`), (3) a second app of any protocol, (4) an MFA-loss
recovery (`POST /api/admin/users/<id>/mfa/reset`, then the user logs
straight in and re-enrolls), (5) the CSV export above containing all of
it. When all five check out, the integration milestone is done.

## 8. Branding without a deploy

```bash
curl "$IDP/api/branding"   # public: what login pages render
curl -b "$JAR" -X PATCH "$IDP/api/admin/branding" \
  -H 'Content-Type: application/json' -d '{
    "org_name": "Acme", "primary_color": "#0f766e", "theme": "system",
    "logo_url": "https://cdn.example.com/logo.svg",
    "custom_css": ".login-card { border-radius: 2px; }"
  }'
```

Only sent keys change. `primary_color` is `#rrggbb`, `theme` is
`light|dark|system`, `custom_css` is capped at 10 KB and rejects
`@import`, `url(` and `</style>` — the SPA applies it as variables +
theme class on the next load, no rebuild. Upload logos as multipart
(`asset_type=app_logo` + `file` field) via `POST /api/uploads`
(admin-only; served back as `.webp` under `/uploads/`).

## 9. HRIS provisioning: users, passwords, invites (REST)

HRIS systems provision outbound over the admin API (the LDAP provider
is read-only, so directory-write provisioning cannot target it). The
flow mirrors the Authentik pattern: provision first, then email the
user a setup link.

```bash
# 1. Provision without a password (invite-pending: cannot log in yet).
#    Omit "password", or send "" — both leave the account hashless.
curl -b "$JAR" -X POST "$IDP/api/admin/users" \
  -H 'Content-Type: application/json' -d '{
    "username": "ara", "email": "ara@example.com", "display_name": "Ara"
  }'
# -> 201 {"user": {"id": "<USER_ID>", ...}}

# 2. Invite: emails a single-use 15-minute setup link. No rate limit
#    (the admin gate + audit entry are the abuse control), so bulk
#    onboarding will not throttle like the public forgot-password
#    endpoint (3/hour/account + 10/hour/IP) would.
curl -b "$JAR" -X POST "$IDP/api/admin/users/<USER_ID>/invite"
# -> 200 {"message": "Invitation sent."}
# The user opens /reset-password?token=... and chooses a password:
# min 8 characters with one uppercase letter and one symbol.
```

Rules: invite targets must be active local users with an email
address (LDAP users and deactivated accounts get explicit 400s);
minting a new link revokes the previous one, so re-invites are safe.
Every invite lands in `audit_log` with
`detail.action=user_invite` and the acting admin. Group membership
rides the same API (`POST /api/admin/groups/{id}/members`).

## Appendix A: endpoint reference (this guide)

| Method+path | Purpose |
|-------------|---------|
| `POST /api/auth/login`, `POST /api/auth/mfa/totp` | Admin session (§0) |
| `POST /api/admin/users/{id}/invite` | HRIS invite, no rate limit (§9) |
| `POST /api/account/mfa/enroll`, `.../enroll/confirm` | First-time admin TOTP (§0) |
| `GET /api/auth/me` | Session check |
| `POST /api/admin/apps`, `PATCH/DELETE /api/admin/apps/{id}` | Catalog (§1) |
| `POST /api/admin/apps/{id}/bindings` (+ `GET`, `DELETE .../{bindingID}`) | Access (§6) |
| `GET|POST /api/admin/oidc/clients`, `DELETE .../{clientID}` | OIDC (§2) |
| `GET|POST /api/admin/saml/sps`, `DELETE ...?entity_id=` | SAML (§3) |
| `GET|POST /api/admin/radius/clients`, `DELETE .../{nas}` | RADIUS (§5) |
| `GET /api/admin/audit`, `GET /api/admin/audit/export` | Audit + CSV (§7) |
| `GET /api/branding`, `PATCH /api/admin/branding` | Branding (§8) |

## Appendix B: error vocabulary

| Status | Meaning |
|--------|---------|
| 400 | Validation failed — the `error` string names the rule (fix input). |
| 401 | No/expired session — re-login (§0); on login itself, bad credentials. |
| 403 | Authenticated but not `ih_admin`, or admin without fresh MFA (`mfa_required: true` — do §0 step 2b). |
| 404 | Unknown id (or double delete). |
| 409 | Duplicate: slug/client/entity/NAS taken, or a second credential for one app. |
| 429 (+ `Retry-After`) | Rate limited: login 10/min/IP + 5/min/user with progressive lockout, TOTP 5/min/user, forgot-password 3/hour/account + 10/hour/IP. |
| 503 | Upstream directory unreachable (local logins still work). |
