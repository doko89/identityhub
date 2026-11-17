// Branding API client (TECH_SPEC §7). The public theme endpoint carries
// no secrets; the login page and BrandProvider fetch it on every load.
export interface Branding {
  org_name: string;
  logo_url: string;
  favicon_url: string;
  primary_color: string;
  theme: string;
  login_background_url: string;
  custom_css: string;
}

export async function fetchBranding(): Promise<Branding> {
  const res = await fetch("/api/branding");
  if (!res.ok) {
    throw new Error(`branding ${res.status}`);
  }
  const data = (await res.json()) as { branding: Branding };
  return data.branding;
}
