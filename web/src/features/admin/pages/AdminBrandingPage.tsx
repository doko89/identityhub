import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { fetchBranding, type Branding } from "@/features/branding/api";
import { buttonStyle, inputStyle, labelStyle } from "@/shared/ui/formStyles";
import { updateBranding, type BrandingPatch } from "../api";
import { Notice, toNotice, type AdminNotice } from "../components/adminUi";

// Admin branding editor (PRD §6.8, DESIGN §5.4): every field of the brand
// singleton with a live mini login-card preview. Saving invalidates the
// BrandProvider query so the whole SPA re-themes at once.
export function AdminBrandingPage() {
  const queryClient = useQueryClient();
  const [brand, setBrand] = useState<Branding | null>(null);
  const [notice, setNotice] = useState<AdminNotice | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const b = await fetchBranding();
        if (!cancelled) setBrand(b);
      } catch {
        if (!cancelled) setNotice({ text: "Cannot load the current branding. Try again.", stepUp: false });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (brand === null) return;
    setBusy(true);
    setNotice(null);
    setSaved(false);
    try {
      const patch: BrandingPatch = {
        org_name: brand.org_name,
        logo_url: brand.logo_url,
        favicon_url: brand.favicon_url,
        primary_color: brand.primary_color,
        theme: brand.theme,
        login_background_url: brand.login_background_url,
        custom_css: brand.custom_css,
      };
      const { branding } = await updateBranding(patch);
      setBrand(branding);
      setSaved(true);
      await queryClient.invalidateQueries({ queryKey: ["branding"] });
    } catch (err) {
      setNotice(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  function set<K extends keyof Branding>(key: K, value: Branding[K]) {
    setBrand((prev) => (prev === null ? prev : { ...prev, [key]: value }));
  }

  return (
    <div>
      <h1 style={{ fontSize: 20, fontWeight: 600, margin: "0 0 4px" }}>Branding</h1>
      <p style={{ fontSize: 13, color: "var(--muted-foreground)", margin: "0 0 16px" }}>
        Organization theme for the login page and the whole app. Changes apply immediately.
      </p>
      <Notice value={notice} />
      {saved && (
        <p role="status" style={{ fontSize: 13, color: "var(--muted-foreground)" }}>
          Saved. The new theme is live.
        </p>
      )}
      {brand === null && notice === null && (
        <p style={{ fontSize: 14, color: "var(--muted-foreground)" }}>Loading branding…</p>
      )}
      {brand !== null && (
        <div style={{ display: "flex", gap: 24, flexWrap: "wrap", alignItems: "flex-start" }}>
          <form onSubmit={(e) => void submit(e)} className="ih-panel" style={{ flex: "1 1 320px", margin: 0 }}>
            <label style={labelStyle}>
              Organization name
              <input
                name="org_name"
                style={inputStyle}
                value={brand.org_name}
                onChange={(e) => set("org_name", e.target.value)}
              />
            </label>
            <label style={labelStyle}>
              Logo URL
              <input
                name="logo_url"
                style={inputStyle}
                value={brand.logo_url}
                onChange={(e) => set("logo_url", e.target.value)}
                placeholder="/uploads/logo.png"
              />
            </label>
            <label style={labelStyle}>
              Favicon URL
              <input
                name="favicon_url"
                style={inputStyle}
                value={brand.favicon_url}
                onChange={(e) => set("favicon_url", e.target.value)}
                placeholder="/uploads/favicon.ico"
              />
            </label>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 12px" }}>
              <label style={labelStyle}>
                Primary color
                <input
                  name="primary_color"
                  style={inputStyle}
                  value={brand.primary_color}
                  onChange={(e) => set("primary_color", e.target.value)}
                  placeholder="#4f46e5"
                />
              </label>
              <label style={labelStyle}>
                Theme
                <select
                  name="theme"
                  style={inputStyle}
                  value={brand.theme}
                  onChange={(e) => set("theme", e.target.value)}
                >
                  <option value="">system</option>
                  <option value="system">system</option>
                  <option value="light">light</option>
                  <option value="dark">dark</option>
                </select>
              </label>
            </div>
            <label style={labelStyle}>
              Login background URL
              <input
                name="login_background_url"
                style={inputStyle}
                value={brand.login_background_url}
                onChange={(e) => set("login_background_url", e.target.value)}
                placeholder="/uploads/login-bg.jpg"
              />
            </label>
            <label style={{ ...labelStyle, marginBottom: 16 }}>
              Custom CSS (max 10 KB, sanitized on the server)
              <textarea
                name="custom_css"
                style={{ ...inputStyle, minHeight: 90, fontFamily: "monospace", fontSize: 12 }}
                value={brand.custom_css}
                onChange={(e) => set("custom_css", e.target.value)}
                placeholder=".login-card { … }"
              />
            </label>
            <button type="submit" style={buttonStyle} disabled={busy}>
              {busy ? "Saving…" : "Save branding"}
            </button>
          </form>
          <Preview brand={brand} />
        </div>
      )}
    </div>
  );
}

// Preview is a miniature of the login card (DESIGN §5.1) driven by the
// draft values, so admins see the theme before saving.
function Preview({ brand }: { brand: Branding }) {
  const orgName = brand.org_name !== "" ? brand.org_name : "IdentityHub";
  const primary = /^#[0-9a-fA-F]{6}$/.test(brand.primary_color) ? brand.primary_color : "#4f46e5";
  const dark = brand.theme === "dark";
  return (
    <div style={{ flex: "0 1 300px" }} aria-label="Login preview">
      <p style={{ fontSize: 12, color: "var(--muted-foreground)", margin: "0 0 8px" }}>Preview</p>
      <div
        style={{
          border: "1px solid var(--border)",
          borderRadius: "var(--radius)",
          background: dark ? "#09090b" : "#ffffff",
          color: dark ? "#fafafa" : "#18181b",
          padding: 20,
        }}
      >
        {brand.logo_url !== "" && (
          <img src={brand.logo_url} alt="" style={{ height: 24, marginBottom: 8 }} />
        )}
        <p style={{ fontSize: 16, fontWeight: 600, margin: "0 0 2px" }}>{orgName}</p>
        <p style={{ fontSize: 12, color: dark ? "#a1a1aa" : "#71717a", margin: "0 0 12px" }}>
          Sign in
        </p>
        <div
          style={{
            border: "1px solid var(--input)",
            borderRadius: "calc(var(--radius) - 2px)",
            padding: "6px 10px",
            fontSize: 12,
            color: dark ? "#a1a1aa" : "#71717a",
            marginBottom: 8,
          }}
        >
          Username
        </div>
        <div
          style={{
            background: primary,
            color: "#ffffff",
            borderRadius: "calc(var(--radius) - 2px)",
            padding: "8px 10px",
            fontSize: 13,
            fontWeight: 600,
            textAlign: "center",
          }}
        >
          Sign in
        </div>
      </div>
    </div>
  );
}
