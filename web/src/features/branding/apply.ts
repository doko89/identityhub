import type { Branding } from "./api";

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
  applyTheme(b.theme);
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
