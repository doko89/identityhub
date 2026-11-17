import type { Branding } from "./api";

// ThemeChoice is the user's theme preference: an explicit mode or the OS.
export type ThemeChoice = "light" | "dark" | "system";

// THEME_STORAGE_KEY holds the ThemeToggle choice. A stored choice wins
// over the server brand default (DESIGN.md §3).
export const THEME_STORAGE_KEY = "ih-theme";

// normalizeTheme maps brand/stored strings onto a choice; "" (legacy
// brand default) and anything unknown fall back to null = follow the OS.
export function normalizeTheme(value: string | null | undefined): ThemeChoice | null {
  if (value === "light" || value === "dark" || value === "system") {
    return value;
  }
  return null;
}

// getStoredTheme reads the user's saved choice, or null when unset,
// invalid, or unreadable (private mode).
export function getStoredTheme(): ThemeChoice | null {
  try {
    return normalizeTheme(localStorage.getItem(THEME_STORAGE_KEY));
  } catch {
    return null;
  }
}

// setStoredTheme persists the user's choice ("system" is stored
// explicitly so it keeps winning over an explicit brand default).
export function setStoredTheme(choice: ThemeChoice): void {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, choice);
  } catch {
    // Private mode: the choice still applies for this session.
  }
}

// resolveTheme picks the winning choice: stored > brand default > OS.
export function resolveTheme(brandTheme: string): ThemeChoice {
  return getStoredTheme() ?? normalizeTheme(brandTheme) ?? "system";
}

// applyTheme toggles the .dark class (index.css tokens). Empty and
// "system" follow the OS; explicit light/dark win.
export function applyTheme(theme: string): void {
  const dark =
    theme === "dark" ||
    (theme !== "light" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.classList.toggle("dark", dark);
}

// applyBrand pushes one brand row into the document: shadcn CSS
// variables, the theme class, the tab title, and the admin's custom_css
// (already sanitized server-side: no @import/url(</style>, max 10 KB).
export function applyBrand(b: Branding): void {
  const root = document.documentElement;
  if (/^#[0-9a-fA-F]{6}$/.test(b.primary_color)) {
    root.style.setProperty("--primary", b.primary_color);
    root.style.setProperty("--ring", b.primary_color);
  }
  applyTheme(resolveTheme(b.theme));
  document.title = b.org_name !== "" ? b.org_name : "IdentityHub";
  const existing = document.getElementById("ih-custom-css");
  if (b.custom_css !== "") {
    const el = existing ?? document.createElement("style");
    el.id = "ih-custom-css";
    el.textContent = b.custom_css;
    if (existing === null) {
      document.head.appendChild(el);
    }
  } else {
    existing?.remove();
  }
}
