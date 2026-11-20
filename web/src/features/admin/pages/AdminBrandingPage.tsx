import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Check } from "lucide-react";
import { fetchBranding, type Branding } from "@/features/branding/api";
import { ImageDropzone } from "@/features/uploads/components/ImageDropzone";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/shared/ui/card";
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
        tagline: brand.tagline,
        logo_url: brand.logo_url,
        favicon_url: brand.favicon_url,
        primary_color: brand.primary_color,
        theme: brand.theme,
        login_background_url: brand.login_background_url,
        custom_css: brand.custom_css,
        dashboard_columns: brand.dashboard_columns,
        dashboard_icon_shape: brand.dashboard_icon_shape,
        dashboard_density: brand.dashboard_density,
        dashboard_background: brand.dashboard_background,
        dashboard_background_url: brand.dashboard_background_url,
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

  // Mirrors the server rule (domain/branding.go): empty keeps the
  // default, otherwise the color must be #rrggbb.
  const colorInvalid =
    brand !== null && brand.primary_color !== "" && !isHexColor(brand.primary_color);

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
          <form onSubmit={(e) => void submit(e)} className="grid min-w-80 flex-1 gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Organization</CardTitle>
                <CardDescription>The name shown on login and across the app.</CardDescription>
              </CardHeader>
              <CardContent>
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
                    <FieldLabel htmlFor="brand-tagline">Tagline</FieldLabel>
                    <Input
                      id="brand-tagline"
                      name="tagline"
                      value={brand.tagline}
                      onChange={(e) => set("tagline", e.target.value)}
                      placeholder="The single front door to every company app."
                      maxLength={200}
                    />
                    <p className="text-xs text-muted-foreground">
                      Shown under the name on the sign-in page. Empty keeps the default.
                    </p>
                  </Field>
                </FieldGroup>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Logo and favicon</CardTitle>
                <CardDescription>Shown on login, the dashboard, and the browser tab.</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field>
                    <FieldLabel htmlFor="logo-upload">Logo</FieldLabel>
                    <ImageDropzone
                      id="logo-upload"
                      assetType="app_logo"
                      label="Upload logo"
                      hint="JPEG, PNG or WebP, max 10 MB. Drop an image here or click to browse."
                      onUploaded={(url) => set("logo_url", url)}
                    >
                      {brand.logo_url !== "" ? (
                        <img src={brand.logo_url} alt="" className="h-12 w-full rounded-md border object-contain" />
                      ) : (
                        <div className="flex h-12 w-full items-center justify-center rounded-md border border-dashed text-xs text-muted-foreground">
                          No logo yet
                        </div>
                      )}
                    </ImageDropzone>
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="favicon-upload">Favicon</FieldLabel>
                    <ImageDropzone
                      id="favicon-upload"
                      assetType="app_logo"
                      label="Upload favicon"
                      hint="JPEG, PNG or WebP, max 10 MB. Drop an image here or click to browse."
                      onUploaded={(url) => set("favicon_url", url)}
                    >
                      {brand.favicon_url !== "" ? (
                        <img src={brand.favicon_url} alt="" className="size-12 rounded-md border object-contain" />
                      ) : (
                        <div className="flex size-12 items-center justify-center rounded-md border border-dashed text-xs text-muted-foreground">
                          None
                        </div>
                      )}
                    </ImageDropzone>
                  </Field>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Color and theme</CardTitle>
                <CardDescription>Pick a preset or type any #rrggbb color code.</CardDescription>
              </CardHeader>
              <CardContent>
                <FieldGroup>
                  <Field>
                    <FieldLabel id="brand-color-label" htmlFor="brand-color">
                      Primary color
                    </FieldLabel>
                    <div
                      role="radiogroup"
                      aria-labelledby="brand-color-label"
                      className="flex flex-wrap gap-2"
                    >
                      {PRESET_COLORS.map((preset) => {
                        const selected =
                          brand.primary_color.toLowerCase() === preset.hex.toLowerCase();
                        return (
                          <button
                            key={preset.hex}
                            type="button"
                            role="radio"
                            aria-checked={selected}
                            title={preset.name}
                            aria-label={preset.name}
                            onClick={() => set("primary_color", preset.hex)}
                            style={{ background: preset.hex }}
                            className={
                              selected
                                ? "grid size-8 place-items-center rounded-full text-white ring-2 ring-ring ring-offset-2 ring-offset-background"
                                : "grid size-8 place-items-center rounded-full border text-transparent hover:ring-2 hover:ring-ring hover:ring-offset-2 hover:ring-offset-background"
                            }
                          >
                            <Check className="size-4" aria-hidden="true" />
                          </button>
                        );
                      })}
                    </div>
                    <div className="flex items-center gap-2">
                      <span
                        aria-hidden="true"
                        style={{ background: isHexColor(brand.primary_color) ? brand.primary_color : "transparent" }}
                        className="size-9 shrink-0 rounded-md border"
                      />
                      <Input
                        id="brand-color"
                        name="primary_color"
                        value={brand.primary_color}
                        onChange={(e) => set("primary_color", e.target.value)}
                        placeholder="#4f46e5"
                        maxLength={7}
                        aria-invalid={colorInvalid}
                        className="font-mono"
                      />
                      <input
                        type="color"
                        aria-label="Pick a custom color"
                        value={isHexColor(brand.primary_color) ? brand.primary_color : "#4f46e5"}
                        onChange={(e) => set("primary_color", e.target.value)}
                        className="size-9 shrink-0 cursor-pointer rounded-md border bg-background p-1"
                      />
                    </div>
                    {colorInvalid ? (
                      <p role="alert" className="text-sm text-destructive">
                        Use the #rrggbb format, e.g. #4f46e5.
                      </p>
                    ) : (
                      <p className="text-xs text-muted-foreground">
                        Empty keeps the default indigo.
                      </p>
                    )}
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
                </FieldGroup>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Dashboard</CardTitle>
                <CardDescription>App grid layout for every user.</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field>
                    <FieldLabel htmlFor="brand-columns">Grid columns</FieldLabel>
                    <Select
                      value={String(brand.dashboard_columns || 3)}
                      onValueChange={(v) => set("dashboard_columns", Number(v))}
                    >
                      <SelectTrigger id="brand-columns">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="2">2 columns</SelectItem>
                        <SelectItem value="3">3 columns</SelectItem>
                        <SelectItem value="4">4 columns</SelectItem>
                      </SelectContent>
                    </Select>
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="brand-shape">App icon shape</FieldLabel>
                    <Select
                      value={brand.dashboard_icon_shape || "rounded"}
                      onValueChange={(v) => set("dashboard_icon_shape", v)}
                    >
                      <SelectTrigger id="brand-shape">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="rounded">Rounded</SelectItem>
                        <SelectItem value="circle">Circle</SelectItem>
                        <SelectItem value="square">Square</SelectItem>
                      </SelectContent>
                    </Select>
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="brand-density">Card density</FieldLabel>
                    <Select
                      value={brand.dashboard_density || "comfortable"}
                      onValueChange={(v) => set("dashboard_density", v)}
                    >
                      <SelectTrigger id="brand-density">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="comfortable">Comfortable</SelectItem>
                        <SelectItem value="compact">Compact</SelectItem>
                      </SelectContent>
                    </Select>
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="brand-bg">Background</FieldLabel>
                    <Select
                      value={brand.dashboard_background || "pattern"}
                      onValueChange={(v) => set("dashboard_background", v)}
                    >
                      <SelectTrigger id="brand-bg">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="pattern">Brand pattern</SelectItem>
                        <SelectItem value="plain">Plain</SelectItem>
                        <SelectItem value="photo">Photo</SelectItem>
                      </SelectContent>
                    </Select>
                  </Field>
                </div>
                <Field className="mt-4">
                  <FieldLabel htmlFor="dashboard-bg-upload">Background photo</FieldLabel>
                  <ImageDropzone
                    id="dashboard-bg-upload"
                    assetType="login_background"
                    label="Upload dashboard background"
                    hint="Shown when the background is Photo. JPEG, PNG or WebP, max 10 MB."
                    onUploaded={(url) => set("dashboard_background_url", url)}
                  >
                    {brand.dashboard_background_url !== "" ? (
                      <img
                        src={brand.dashboard_background_url}
                        alt=""
                        className="h-20 w-48 border object-cover"
                      />
                    ) : (
                      <div className="flex h-20 w-48 items-center justify-center border border-dashed text-xs text-muted-foreground">
                        No background yet
                      </div>
                    )}
                  </ImageDropzone>
                </Field>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Login background</CardTitle>
                <CardDescription>Backdrop photo behind the sign-in card.</CardDescription>
              </CardHeader>
              <CardContent>
                <Field>
                  <FieldLabel htmlFor="login-bg-upload">Background image</FieldLabel>
                  <ImageDropzone
                    id="login-bg-upload"
                    assetType="login_background"
                    label="Upload login background"
                    hint="JPEG, PNG or WebP, max 10 MB. Drop an image here or click to browse."
                    onUploaded={(url) => set("login_background_url", url)}
                  >
                    {brand.login_background_url !== "" ? (
                      <img
                        src={brand.login_background_url}
                        alt=""
                        className="h-20 w-48 border object-cover"
                      />
                    ) : (
                      <div className="flex h-20 w-48 items-center justify-center border border-dashed text-xs text-muted-foreground">
                        No background yet
                      </div>
                    )}
                  </ImageDropzone>
                </Field>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Advanced</CardTitle>
                <CardDescription>Optional CSS applied after the theme.</CardDescription>
              </CardHeader>
              <CardContent>
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
              </CardContent>
            </Card>
            <Button type="submit" className="w-full" disabled={busy || colorInvalid}>
              {busy ? <Spinner data-icon="inline-start" /> : null}
              {busy ? "Saving…" : "Save branding"}
            </Button>
          </form>
          <Preview brand={brand} />
        </div>
      )}
    </div>
  );
}

// PRESET_COLORS offers one-click brand colors; the hex input beside
// them accepts any custom #rrggbb code.
const PRESET_COLORS: Array<{ name: string; hex: string }> = [
  { name: "Indigo (default)", hex: "#4f46e5" },
  { name: "Blue", hex: "#2563eb" },
  { name: "Teal", hex: "#0f766e" },
  { name: "Green", hex: "#16a34a" },
  { name: "Amber", hex: "#d97706" },
  { name: "Red", hex: "#dc2626" },
  { name: "Pink", hex: "#db2777" },
  { name: "Slate", hex: "#334155" },
];

function isHexColor(value: string): boolean {
  return /^#[0-9a-fA-F]{6}$/.test(value);
}

// Preview is a miniature of the login card (DESIGN §5.1) driven by the
// draft values, so admins see the theme before saving.
function Preview({ brand }: { brand: Branding }) {
  const orgName = brand.org_name !== "" ? brand.org_name : "IdentityHub";
  const primary = /^#[0-9a-fA-F]{6}$/.test(brand.primary_color) ? brand.primary_color : "#4f46e5";
  const dark = brand.theme === "dark";
  return (
    <div className="w-75 shrink-0 lg:sticky lg:top-6" aria-label="Login preview">
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
