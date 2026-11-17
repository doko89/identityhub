# PRD — IdentityHub

## 1. Summary

IdentityHub is an Identity Provider (IdP) and user management platform for organizations. One place to manage users, groups, and applications, with users sourced from LDAP, authentication served to apps via LDAP, OIDC, SAML, and RADIUS, plus MFA, an authentik-style application dashboard, and branding/theme customization.

Target market: international. Product language: English.

Status: initial draft for agreement before implementation.

## 2. Goals

- Unify logins for all internal apps behind one IdP.
- Use the existing LDAP directory as the identity source with no forced migration.
- Serve modern SSO (OIDC/SAML) alongside legacy protocols (LDAP/RADIUS for VPN, Wi-Fi, network gear).
- Raise security with MFA and audit logging.
- Deliver a consistent experience: one app dashboard, one brandable login page.

## 3. Non-Goals (v1)

- Multi-tenant / public SaaS. v1 is single-tenant for one organization.
- Upstream login via third-party OIDC/SAML (e.g. "sign in with Google"). v1 supports LDAP upstream only. Can be added later.
- Automatic migration from other IdPs (Keycloak/Authentik). Integrations are done per app, manually.

## 4. Users and Roles

| Role | Needs |
|---|---|
| End user (employee) | Sign in once, see their app list, click to open. Manage their own MFA. |
| IT admin | Manage users/groups/apps, configure the provider per app, manage branding, view audit logs. |
| App developer | Clear per-protocol integration guides (client ID/secret, SAML metadata, bind DN, RADIUS shared secret). |

## 5. Core Flows

### 5.1 User source

```text
Existing LDAP directory --> LDAP connector --> local users/groups (cache) --> login & SSO
```

- Login can bind directly to LDAP.
- Periodic sync pulls users and groups so the dashboard and policies keep working when LDAP is slow.
- LDAP failures must surface explicit errors with timeouts, never a hanging page.

### 5.2 Auth served to apps

Each application has exactly one primary provider:

| Provider | Used for |
|---|---|
| OIDC (authorization code + PKCE) | Modern web and mobile apps |
| SAML | Enterprise apps (ERP, HRIS, etc.) |
| LDAP | Legacy apps that can only do LDAP bind |
| RADIUS | VPN, Wi-Fi, switches/network devices |

### 5.3 Standard login flow

1. User opens an app -> redirected to the IdentityHub login page.
2. User enters username + password (validated against LDAP or the local database).
3. If policy requires it, the user is asked for a second factor (TOTP, then WebAuthn).
4. On success -> redirected back to the app with a token/assertion per protocol.
5. Users can also open the dashboard directly and click an app (IdP-initiated).

## 6. Functional Requirements

### 6.1 User and group management (required)

- User CRUD: name, unique username, email, active/inactive status, groups, avatar (upload, auto-webp).
- Group CRUD with user members.
- Admin rights come from membership in the reserved `ih_admin` group (no separate flag); promote/demote = add/remove group members.
- The `ih_admin` group cannot be deleted or renamed; admins cannot remove themselves or the last member.
- First admin is bootstrapped via CLI/env, must change password and enroll MFA at first login.
- Admin user impersonation for troubleshooting (recorded in audit).
- Admin password reset for local users (see 6.10).
- User/group search.

### 6.2 Upstream LDAP connector (required)

- Config: host, port, TLS, bind DN, base DN, user/group filters, attribute mapping.
- Connection test from the admin UI.
- Manual and scheduled sync.
- Username conflicts are rejected explicitly, never silently overwritten.
- Optional admin mapping: members of a configured directory group auto-join `ih_admin` on sync.

### 6.3 OIDC provider (required, top priority)

- Authorization code flow + PKCE, refresh tokens with rotation.
- Endpoints: authorize, token, userinfo, JWKS, discovery.
- Per-app client registration: client ID, secret, redirect URI (exact match), scopes.
- Consent page before sharing attributes.
- Standard claims: sub, name, email, groups.

### 6.4 SAML provider (required)

- IdP metadata and SP metadata import (XML).
- Signed assertions, ACS URL, NameID mapping.
- Basic single logout.
- One real SP must pass end-to-end.

### 6.5 LDAP and RADIUS providers (required)

- Edge companion processes for binary protocols; identity decisions stay in the core over HTTPS.
- LDAP: per-user bind DN, per-app search base where needed; connection modes ldap/ldaps/starttls; IP whitelist so plaintext stays locked down.
- RADIUS: client/shared secret per device, PAP first; record the method in audit.

### 6.6 MFA (required)

- v1: TOTP (QR enroll), single-use 6-digit codes, narrow validation window (current step + at most one previous), reject reuse of the same code.
- Single-use recovery codes at enroll time.
- Policy: required for admins; optional/required per app for regular users.
- Protection: rate limits and lockout on MFA attempts, notification on failed second-factor login.
- TOTP seeds stored encrypted, never returned to the client after enroll.
- v1.1: WebAuthn/FIDO2 or passkeys as the phishing-resistant factor.

### 6.7 authentik-style app dashboard (required)

- Users only see apps they may access (user/group/policy bindings).
- Clicking an app SSOs straight in without re-login (while the session lasts).
- Admins control visibility: no bindings = all users allowed; with bindings = all-or-any evaluation mode.
- Each app has a name, icon (`app_logo` upload, auto-webp), description, URL, and display group.
- Third-party SaaS app logos are uploaded separately as the `saas_logo` type.

### 6.8 Branding and theme (required)

- Global settings with no code changes: org name, logo, favicon, primary color, light/dark mode, login page background.
- Applied consistently across the login page, user dashboard, and admin console.
- Logo and favicon are uploaded via the upload endpoint (auto-webp).
- Saved changes take effect immediately with no redeploy.

### 6.9 Audit and admin (required)

- Log every login: who, when, app, method (password/TOTP/WebAuthn/LDAP/RADIUS), success/failure, IP.
- Admin dashboard: recent logins, most-used apps, system status.
- CSV report export.

### 6.10 Password management (required)

- Self-service change: signed-in user enters current + new password twice; MFA re-auth required when MFA is active; all other sessions are terminated after the change.
- Forgot password: user enters email/username on the login page; the system emails a single-use token link (15-minute expiry, one active token per user); responses are always generic so account existence is not leaked; after reset, all other sessions are terminated.
- Admin reset: admin sets a new password for local users; LDAP users are rejected explicitly (LDAP passwords live in the directory); every action is audited (acting admin, target user, time).
- All three features are for `local`-source users only; LDAP users who try them get a clear message to contact their directory admin.
- Password policy: minimum 8 characters with one uppercase letter and one symbol; rejected if equal to the current or any of the last 10 passwords.

## 7. Non-Functional Requirements

- Security: hashed passwords (argon2/bcrypt), encrypted client secrets, mandatory TLS on all endpoints, no secrets in logs, CSRF protection on forms.
- Availability: one relational database; core + worker architecture so email/sync never block login.
- Early performance: password login < 1s (excluding slow upstreams); dashboard < 500ms for 100 apps.
- Operations: single-binary artifacts (frontend embedded), container deploy (core, worker, database), env-based config, daily database backups.

## 8. Architecture (v1)

```text
                 +------------------+
                 |  Apps (RP/SP)     |
                 +--------+---------+
                          | OIDC / SAML (HTTPS)
                          | LDAP / RADIUS (via edge companion)
                 +--------v---------+
                 |  Core IdentityHub |
                 |  API + login flow |
                 +---+----------+----+
                     |          |
              +------v---+  +---v------+
              | Worker   |  | Database |
              |          |  | + files  |
              +------+---+  +----------+
                     |
              +------v--------+
              | LDAP upstream |
              +---------------+
```

## 9. Milestones

1. M0 — Foundation: repo, data schema (seeds `ih_admin`), sessions, minimal admin API, bootstrap CLI.
2. M1 — Local login + LDAP upstream + password management + audit.
3. M2 — End-to-end OIDC provider (highest risk, prioritized).
4. M3 — SAML provider + one real SP.
5. M4 — LDAP and RADIUS providers.
6. M5 — TOTP MFA + recovery + policies.
7. M6 — App dashboard + authorization.
8. M7 — Branding/theme + hardening + integration docs.

## 10. v1 Success Criteria

- 3 real apps integrated (at least 1 OIDC, 1 SAML or RADIUS).
- 100% of logins recorded in audit with the correct method.
- A non-developer admin can add a new OIDC app using only the docs.
- Brand/theme changes with no deploy.
- MFA loss flow (recovery reset) passes end-to-end.

## 11. Open Questions

1. Is LDAP only a user source, or will third-party upstream OIDC/SAML login be needed later?
2. Which app integrates first? (decides M2 vs M3 vs M4 order)
3. Is single-tenant enough for the first year?
4. MFA mandatory for all users on day one, or phased?
5. First deployment target (single VPS, Kubernetes, managed platform)?
