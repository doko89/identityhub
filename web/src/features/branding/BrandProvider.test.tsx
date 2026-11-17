import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import type { Branding } from "./api";
import {
  THEME_STORAGE_KEY,
  applyBrand,
  applyTheme,
  getStoredTheme,
  normalizeTheme,
  resolveTheme,
  setStoredTheme,
} from "./apply";
import { BrandProvider, useBrand } from "./BrandProvider";

const brand: Branding = {
  org_name: "Acme",
  tagline: "",
  logo_url: "",
  favicon_url: "",
  primary_color: "#123abc",
  theme: "light",
  login_background_url: "",
  custom_css: "",
};

// jsdom ships no matchMedia; the provider only needs matches + listeners.
function mockMatchMedia(dark: boolean): void {
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: (query: string) => ({
      matches: dark && query.includes("dark"),
      media: query,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
    }),
  });
}

afterEach(() => {
  document.documentElement.classList.remove("dark");
  document.documentElement.style.removeProperty("--primary");
  document.documentElement.style.removeProperty("--ring");
  document.getElementById("ih-custom-css")?.remove();
  document.getElementById("ih-favicon")?.remove();
  document.title = "";
  localStorage.clear();
  vi.unstubAllGlobals();
});

describe("applyTheme", () => {
  it("forces dark and light explicitly", () => {
    mockMatchMedia(false);
    applyTheme("dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    applyTheme("light");
    expect(document.documentElement.classList.contains("dark")).toBe(false);
  });

  it("follows the OS on system and empty", () => {
    mockMatchMedia(true);
    applyTheme("system");
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    mockMatchMedia(false);
    applyTheme("");
    expect(document.documentElement.classList.contains("dark")).toBe(false);
  });
});

describe("theme storage", () => {
  it("normalizes known choices and rejects the rest", () => {
    expect(normalizeTheme("light")).toBe("light");
    expect(normalizeTheme("dark")).toBe("dark");
    expect(normalizeTheme("system")).toBe("system");
    expect(normalizeTheme("")).toBeNull();
    expect(normalizeTheme("midnight")).toBeNull();
    expect(normalizeTheme(null)).toBeNull();
    expect(normalizeTheme(undefined)).toBeNull();
  });

  it("round-trips the stored choice", () => {
    expect(getStoredTheme()).toBeNull();
    setStoredTheme("dark");
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
    expect(getStoredTheme()).toBe("dark");
  });

  it("resolves stored > brand default > system", () => {
    expect(resolveTheme("dark")).toBe("dark");
    expect(resolveTheme("")).toBe("system");
    expect(resolveTheme("midnight")).toBe("system");
    setStoredTheme("light");
    expect(resolveTheme("dark")).toBe("light");
    // An explicit stored "system" beats an explicit brand default.
    setStoredTheme("system");
    expect(resolveTheme("dark")).toBe("system");
    // A corrupt stored value falls back to the brand default.
    localStorage.setItem(THEME_STORAGE_KEY, "midnight");
    expect(resolveTheme("dark")).toBe("dark");
  });
});

describe("applyBrand", () => {
  it("sets CSS variables, title and custom css", () => {
    mockMatchMedia(false);
    applyBrand({ ...brand, theme: "dark", custom_css: ".x{color:red}" });
    const root = document.documentElement;
    expect(root.style.getPropertyValue("--primary")).toBe("#123abc");
    expect(root.style.getPropertyValue("--ring")).toBe("#123abc");
    expect(root.classList.contains("dark")).toBe(true);
    expect(document.title).toBe("Acme");
    expect(document.getElementById("ih-custom-css")?.textContent).toBe(".x{color:red}");
  });

  it("ignores malformed colors and clears stale css", () => {
    mockMatchMedia(false);
    applyBrand({ ...brand, custom_css: ".x{color:red}" });
    expect(document.getElementById("ih-custom-css")).not.toBeNull();
    applyBrand({ ...brand, primary_color: "red", custom_css: "" });
    // A malformed color leaves the previous variable untouched.
    expect(document.documentElement.style.getPropertyValue("--primary")).toBe("#123abc");
    expect(document.getElementById("ih-custom-css")).toBeNull();
  });

  it("lets the stored user choice win over the brand default", () => {
    mockMatchMedia(false);
    setStoredTheme("dark");
    applyBrand({ ...brand, theme: "light" });
    expect(document.documentElement.classList.contains("dark")).toBe(true);
  });

  it("points the tab icon at the brand favicon", () => {
    mockMatchMedia(false);
    applyBrand({ ...brand, favicon_url: "/uploads/app_logo/9.webp" });
    const link = document.getElementById("ih-favicon");
    expect(link?.getAttribute("rel")).toBe("icon");
    expect(link?.getAttribute("href")).toBe("/uploads/app_logo/9.webp");
    // Re-applying reuses the same element instead of adding another.
    applyBrand({ ...brand, favicon_url: "/uploads/app_logo/10.webp" });
    expect(document.querySelectorAll("#ih-favicon")).toHaveLength(1);
    expect(document.getElementById("ih-favicon")?.getAttribute("href")).toBe(
      "/uploads/app_logo/10.webp",
    );
  });

  it("removes the tab icon when the brand has no favicon", () => {
    mockMatchMedia(false);
    applyBrand({ ...brand, favicon_url: "/uploads/app_logo/9.webp" });
    expect(document.getElementById("ih-favicon")).not.toBeNull();
    applyBrand({ ...brand, favicon_url: "" });
    expect(document.getElementById("ih-favicon")).toBeNull();
  });
});

describe("BrandProvider", () => {
  function shell(children: ReactNode): ReactNode {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  }

  function ShowName(): ReactNode {
    const b = useBrand();
    return <span>{b !== null ? b.org_name : "loading"}</span>;
  }

  it("fetches once and exposes the brand", async () => {
    mockMatchMedia(false);
    const fetchMock = vi.fn(async () =>
      Response.json({ branding: { ...brand, org_name: "Fetched Co" } }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const { getByText } = render(shell(
      <BrandProvider>
        <ShowName />
      </BrandProvider>,
    ));
    await waitFor(() => expect(getByText("Fetched Co")).toBeDefined());
    expect(document.title).toBe("Fetched Co");
    expect(fetchMock).toHaveBeenCalledWith("/api/branding");
  });

  it("keeps defaults when the endpoint fails", async () => {
    mockMatchMedia(false);
    vi.stubGlobal("fetch", vi.fn(async () => new Response("oops", { status: 500 })));
    const { getByText } = render(shell(
      <BrandProvider>
        <ShowName />
      </BrandProvider>,
    ));
    // The provider never throws: children render with a null brand.
    expect(getByText("loading")).toBeDefined();
  });

  it("applies the stored choice even when the endpoint fails", async () => {
    mockMatchMedia(false);
    setStoredTheme("dark");
    vi.stubGlobal("fetch", vi.fn(async () => new Response("oops", { status: 500 })));
    render(shell(
      <BrandProvider>
        <ShowName />
      </BrandProvider>,
    ));
    await waitFor(() =>
      expect(document.documentElement.classList.contains("dark")).toBe(true),
    );
  });
});
