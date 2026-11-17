# DESIGN.md — IdentityHub Design System

Product reference: [PRD.md](../PRD.md). Technical reference: [TECH_SPEC.md](TECH_SPEC.md).
UI stack: React + Vite + Tailwind v4 + shadcn/ui (see frontend conventions in TECH_SPEC §4).

This document is the single source of visual decisions. Token values below are defaults that can change without touching components — change tokens, not classes in components.

## 1. Brand

- **Name:** IdentityHub. **Positioning:** the single front door to company apps — trusted, secure, unobtrusive.
- **Voice:** concise, professional, reassuring. Error messages explain what happened + what the user should do ("Wrong password. Try again or click Forgot password.").
- **UI language:** English (international target). A localization framework is deferred to post-v1.
- **Logo:** simple wordmark + mark; files uploaded via the asset endpoint (`/uploads/...`). Usage: clearspace equal to the cap height of "I", minimum 24px (digital), no rotation or effects.

## 2. Design Tokens

### 2.1 Colors (shadcn CSS variables)

Default primary: indigo — good contrast in light and dark, enterprise without stiffness.

**Light:**

| Token | Value | Used for |
|---|---|---|
| `--background` | `#ffffff` | Page background |
| `--foreground` | `#18181b` | Primary text |
| `--primary` | `#4f46e5` | Primary buttons, links, focus |
| `--primary-foreground` | `#ffffff` | Text on primary |
| `--muted` | `#f4f4f5` | Secondary surfaces |
| `--muted-foreground` | `#71717a` | Secondary text |
| `--accent` | `#eef2ff` | Soft hover/highlight |
| `--destructive` | `#dc2626` | Dangerous actions, errors |
| `--border` / `--input` | `#e4e4e7` | Lines, input frames |
| `--ring` | `#4f46e5` | Focus ring |

**Dark (`.dark` class on root):**

| Token | Value |
|---|---|
| `--background` | `#09090b` |
| `--foreground` | `#fafafa` |
| `--primary` | `#6366f1` |
| `--primary-foreground` | `#ffffff` |
| `--muted` | `#27272a` |
| `--muted-foreground` | `#a1a1aa` |
| `--accent` | `#27272a` |
| `--destructive` | `#ef4444` |
| `--border` / `--input` | `#27272a` |
| `--ring` | `#6366f1` |

**Status (extra `@theme` tokens):** `--success` `#16a34a`/`#4ade80`, `--warning` `#d97706`/`#fbbf24`, `--info` `#2563eb`/`#60a5fa` (light/dark). Used via `Badge` and `Alert`, never raw colors.

### 2.2 Typography

- Font: Inter, `system-ui` fallback. One family for all UI.
- Scale: login-only display (600/32), page title (600/20), card title (600/16), body (400/14), small/secondary (400/12). Relaxed line-height (1.5 body).
- No more than 2 weights per page (400 + 600).

### 2.3 Shape and shadow

- `--radius`: `0.625rem` (shadcn default). Cards `rounded-xl`, inputs/buttons `rounded-md`.
- Shadows: Tailwind defaults; dashboard cards `shadow-sm`, dialogs `shadow-lg`. No colored shadows.

## 3. Branding Feature Linkage (PRD 6.8)

`GET /api/branding` returns `primary_color`, `logo_url`, `theme` (light/dark/system). `features/branding` applies them at boot:

1. Set `--primary` and `--ring` from `primary_color` (hex validated on the server).
2. Set the `.dark` class from `theme` + OS preference + user choice (localStorage wins over system).
3. Render the org logo/name on the login page, dashboard header, and admin sidebar.

`custom_css` (optional, max 10 KB, server-sanitized) is injected last. Light/dark mode must be tested on every §5 page.

## 4. Components (shadcn)

Install via CLI into `src/shared/ui/`. Rules: semantic tokens, `Field`+`FieldGroup` for forms, `gap-*` not `space-*`, `size-*` for square icons, always a `DialogTitle`.

| Need | Components |
|---|---|
| Login/password forms | `Card`, `Field`, `Input`, `Button`, `Alert` |
| MFA TOTP | `InputOTP`, `Button`, `Alert` |
| App dashboard | `Card`, `Avatar`+`AvatarFallback`, `Badge`, `Empty`, `Skeleton` |
| Admin console | `Sidebar`, `Table`, `Dialog`, `Sheet`, `DropdownMenu`, `Pagination`, `Breadcrumb` |
| Global feedback | `toast` (sonner), `Alert`, `Skeleton`, `Spinner`+`disabled` on loading buttons |

## 5. Page Specs

### 5.1 Login (`/login`)

Centered `max-w-sm` card: logo + org name, "Sign in" title, username + password form + full-width primary button, right-aligned "Forgot password?" link, small "© IdentityHub" footer. Background: `--background` + subtle primary radial accent (pure CSS, no image). Errors: destructive `Alert` above the form, focus returned to the failing field.

### 5.2 MFA (`/mfa`) and password (`/forgot-password`, `/reset-password`, `/account/mfa`)

Same centered-card pattern as §5.1. MFA: 6-box `InputOTP` + verify button + "try another way" link when >1 factor exists. Forgot password: one email/username field + the exact same generic success message whether the account exists or not. MFA management: list of enrolled factors (name + "last used") with add/remove actions via confirming `Dialog` + re-auth.

### 5.3 Dashboard (`/`)

Header: small logo + org name left; right: theme toggle, user `Avatar` + `DropdownMenu` (Manage MFA, Change password, Sign out). Body: "Hello, {name}" greeting, app card grid (40px icon, name, 1-line description, OIDC/SAML/LDAP/RADIUS protocol `Badge`). Empty: `Empty` ("No applications assigned to you yet"). Loading: `Skeleton` grid.

### 5.4 Admin console (`/admin/*`)

`Sidebar` layout (nav: Dashboard, Users, Groups, Applications, Branding, Audit Log) + content. Lists: `Table` + search + `Pagination`; add/edit via right `Sheet`; delete/reset-password via destructive confirming `Dialog`. Audit log: read-only table + date/method filter + CSV export. Branding: form + live mini login-card preview.

## 6. Motion

Principles: fast, smooth, meaningful — animation explains state changes, never decorates. CSS-first via `tw-animate-css` (bundled with shadcn v4); no JS animation library in v1.

| Token | Value | Used for |
|---|---|---|
| `--duration-instant` | `100ms` | Hover, press, focus |
| `--duration-standard` | `200ms` | Dialog, dropdown, tooltip, accordion |
| `--duration-expressive` | `300ms` | Sheet, toast, route transition |
| `--ease-enter` | `cubic-bezier(0.16, 1, 0.3, 1)` | All element entrances |
| `--ease-exit` | `cubic-bezier(0.4, 0, 1, 1)` | All element exits |

Standard patterns: dialog/popover `fade+zoom-in 95%→100%`; sheet slides from the right over 300ms; toast slides from the bottom; accordion animates height over 200ms; buttons `scale 0.98` when pressed; route change fades over 150ms; loading uses `Skeleton` (built-in shimmer, no hand-rolled `animate-pulse`).

Hard rules: animate only `transform` and `opacity` (no `width`/`height`/`top` animation except accordion); 300ms max except skeletons; honor `prefers-reduced-motion` — disable all non-essential animation via one global media query. On slow devices, route transitions may be disabled via a flag in `features/branding`.

## 7. Responsive

Mobile-first with default Tailwind breakpoints (`sm` 640, `md` 768, `lg` 1024, `xl` 1280).

| Area | <640px | ≥1024px |
|---|---|---|
| Login/MFA/password | Full-width card, 16px padding | Centered `max-w-sm` card |
| Dashboard | 1-column grid, compact header | 3–4 column grid |
| Admin | Sidebar becomes hamburger `Sheet`; dialogs become `Drawer` | Fixed sidebar + content |
| Tables | Horizontal scroll, sticky action column | Full table |
| User header | Avatar + menu only | Avatar + name + menu |

General rules: 44px minimum touch targets; no hover-only critical content; test every page at 360px, 768px, 1024px, and 1440px before merge.

## 8. Accessibility (required)

- Every input has an associated label; errors use `data-invalid` + `aria-invalid`.
- Text contrast ≥ 4.5:1 in both themes (re-verify on every `primary_color` change).
- Keyboard focus always visible (`ring`); logical tab order; dialogs trap focus.
- Never convey information by color alone — always a companion text/icon.

## 9. Open Questions

1. Final primary color (indigo default in §2.1) and official logo file.
2. Localization roadmap: which locale ships after English?
3. Illustrations/empty states: generic built-in set or custom design?
