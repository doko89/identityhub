import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { fetchBranding, type Branding } from "@/features/branding/api";
import { UploadField } from "@/features/uploads/components/UploadField";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Card, CardContent } from "@/shared/ui/card";
import { Field, FieldGroup, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/shared/ui/select";
import { Skeleton } from "@/shared/ui/skeleton";
import { Spinner } from "@/shared/ui/spinner";
import { Textarea } from "@/shared/ui/textarea";
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
      <h1 className="text-xl font-semibold">Branding</h1>
      <p className="mt-1 mb-4 text-sm text-muted-foreground">
        Organization theme for the login page and the whole app. Changes apply immediately.
      </p>
      <Notice value={notice} />
      {saved && (
        <Alert role="status" className="mb-4">
          <AlertDescription>Saved. The new theme is live.</AlertDescription>
        </Alert>
      )}
      {brand === null && notice === null && (
        <div className="flex max-w-md flex-col gap-3" aria-label="Loading branding">
          <Skeleton className="h-9 w-full" />
          <Skeleton className="h-9 w-full" />
          <Skeleton className="h-9 w-full" />
        </div>
      )}
      {brand !== null && (
        <div className="flex flex-wrap items-start gap-6">
          <Card className="min-w-80 flex-1">
            <CardContent>
              <form onSubmit={(e) => void submit(e)}>
                <FieldGroup>
                  <Field>
                    <FieldLabel htmlFor="brand-org">Organization name</FieldLabel>
                    <Input
                      id="brand-org"
                      name="org_name"
                      value={brand.org_name}
                      onChange={(e) => set("org_name", e.target.value)}
                    />
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="brand-logo">Logo URL</FieldLabel>
                    <Input
                      id="brand-logo"
                      name="logo_url"
                      value={brand.logo_url}
                      onChange={(e) => set("logo_url", e.target.value)}
                      placeholder="/uploads/logo.png"
                    />
                  </Field>
                  <UploadField
                    id="logo-upload"
                    assetType="app_logo"
                    label="Upload a logo file"
                    description="JPEG, PNG or WebP, max 2 MB. Fills the logo URL above."
                    onUploaded={(url) => set("logo_url", url)}
                  />
                  <Field>
                    <FieldLabel htmlFor="brand-favicon">Favicon URL</FieldLabel>
                    <Input
                      id="brand-favicon"
                      name="favicon_url"
                      value={brand.favicon_url}
                      onChange={(e) => set("favicon_url", e.target.value)}
                      placeholder="/uploads/favicon.ico"
                    />
                  </Field>
                  <UploadField
                    id="favicon-upload"
                    assetType="app_logo"
                    label="Upload a favicon file"
                    description="JPEG, PNG or WebP, max 2 MB. Fills the favicon URL above."
                    onUploaded={(url) => set("favicon_url", url)}
                  />
                  <div className="grid grid-cols-2 gap-x-3">
                    <Field>
                      <FieldLabel htmlFor="brand-color">Primary color</FieldLabel>
                      <Input
                        id="brand-color"
                        name="primary_color"
                        value={brand.primary_color}
                        onChange={(e) => set("primary_color", e.target.value)}
                        placeholder="#4f46e5"
                      />
                    </Field>
                    <Field>
                      <FieldLabel htmlFor="brand-theme">Theme</FieldLabel>
                      <Select
                        value={brand.theme === "" ? "system" : brand.theme}
                        onValueChange={(v) => set("theme", v)}
                      >
                        <SelectTrigger id="brand-theme">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="system">system</SelectItem>
                          <SelectItem value="light">light</SelectItem>
                          <SelectItem value="dark">dark</SelectItem>
                        </SelectContent>
                      </Select>
                    </Field>
                  </div>
                  <Field>
                    <FieldLabel htmlFor="brand-bg">Login background URL</FieldLabel>
                    <Input
                      id="brand-bg"
                      name="login_background_url"
                      value={brand.login_background_url}
                      onChange={(e) => set("login_background_url", e.target.value)}
                      placeholder="/uploads/login-bg.jpg"
                    />
                  </Field>
                  <UploadField
                    id="login-bg-upload"
                    assetType="app_logo"
                    label="Upload a background file"
                    description="JPEG, PNG or WebP, max 2 MB. Fills the background URL above."
                    onUploaded={(url) => set("login_background_url", url)}
                  />
                  <Field>
                    <FieldLabel htmlFor="brand-css">Custom CSS (max 10 KB, sanitized on the server)</FieldLabel>
                    <Textarea
                      id="brand-css"
                      name="custom_css"
                      className="min-h-24 font-mono text-xs"
                      value={brand.custom_css}
                      onChange={(e) => set("custom_css", e.target.value)}
                      placeholder=".login-card { … }"
                    />
                  </Field>
                  <Button type="submit" className="w-full" disabled={busy}>
                    {busy ? <Spinner data-icon="inline-start" /> : null}
                    {busy ? "Saving…" : "Save branding"}
                  </Button>
                </FieldGroup>
              </form>
            </CardContent>
          </Card>
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
    <div className="w-75 shrink-0" aria-label="Login preview">
      <p className="mt-0 mb-2 text-xs text-muted-foreground">Preview</p>
      <div
        className="rounded-xl border p-5"
        style={{
          background: dark ? "#09090b" : "#ffffff",
          color: dark ? "#fafafa" : "#18181b",
        }}
      >
        {brand.logo_url !== "" && (
          <img src={brand.logo_url} alt="" className="mb-2 h-6" />
        )}
        <p className="mt-0 mb-0.5 text-base font-semibold">{orgName}</p>
        <p className="mt-0 mb-3 text-xs" style={{ color: dark ? "#a1a1aa" : "#71717a" }}>
          Sign in
        </p>
        <div
          className="mb-2 rounded-md border px-2.5 py-1.5 text-xs"
          style={{ color: dark ? "#a1a1aa" : "#71717a" }}
        >
          Username
        </div>
        <div
          className="rounded-md px-2.5 py-2 text-center text-sm font-semibold text-white"
          style={{ background: primary }}
        >
          Sign in
        </div>
      </div>
    </div>
  );
}
