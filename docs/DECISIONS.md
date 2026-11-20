# v1 Decisions (PRD §11 + DESIGN §9 open questions)

Recorded at the M7 close-out. Every question below shipped with the
decision stated — no v1 blocker is left open.

## PRD §11

1. **LDAP only user source, or third-party upstream OIDC/SAML login
   later?** → LDAP-only in v1 (`adapter/ldapclient` bind + worker sync
   + `LDAP_ADMIN_GROUP_DN` mapping). Upstream OIDC/SAML login is
   deferred post-v1; no tables or config keys are reserved for it.
2. **Which app integrates first (M2 vs M3 vs M4 order)?** → Built in
   spec order: OIDC (M2), then SAML (M3), then LDAP/RADIUS providers
   (M4). The order stuck because each milestone's e2e suite green-lit
   the next.
3. **Is single-tenant enough for the first year?** → Yes. One
   `branding(id=1)` row, no tenant column anywhere, one OIDC issuer and
   one SAML entity per deployment. Multi-tenancy needs a migration, not
   a rewrite — out of v1 scope.
4. **MFA mandatory for all users on day one, or phased?** → Phased:
   `ih_admin` members always (login parks at setup until enrolled, and
   `/api/admin/*` needs a session factor verification with no
   exceptions); regular users opt in via self-service, and admins can
   force it per app (`mfa_required`). Legacy LDAP/RADIUS binds stay
   password-only since those protocols have no second channel, so one
   account serves both web and legacy logins.
5. **First deployment target?** → Single binary on one host behind a
   reverse proxy (TLS terminates at the proxy; env-only config; `migrate
   up` before first `serve`). No Kubernetes manifests ship in v1.

## DESIGN §9

1. **Final primary color and official logo file?** → Indigo default
   stays (`#4f46e5` light / `#6366f1` dark); no official logo file
   ships — each deployment sets its own via `PATCH /api/admin/branding`
   (`logo_url`, CDN or `/uploads/...`) without a redeploy.
2. **Localization roadmap: which locale after English?** → None
   committed for v1. UI strings are English-only; no i18n framework is
   wired, so the second locale is a post-v1 project decision.
3. **Illustrations/empty states: built-in or custom?** → Neither ships
   in v1: empty states are text-only (dashboard, admin lists). A custom
   set can land with the admin console UI without backend changes.

## TECH_SPEC deviations (as built)

- **WebP encoder**: `kolesa-team/go-webp` needs cgo + system libwebp,
  which breaks the single-binary artifact — v1 uses pure-Go
  `HugoSmits86/nativewebp` (lossless VP8L) instead. Only functional
  delta: lossless instead of quality-80 lossy.
- **OIDC library**: fosite stayed (no switch to `zitadel/oidc`); it
  proved workable behind `domain.OIDCProvider`.
- **S3 backend**: shipped in M7 after all (`STORAGE_BACKEND=s3`,
  minio-go, boot-time bucket check) — the "nice-to-have" made v1.
