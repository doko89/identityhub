import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Branding } from "@/features/branding/api";
import { BrandProvider } from "@/features/branding/BrandProvider";
import { AuthBrandHeader } from "./AuthBrandHeader";

afterEach(() => {
  document.title = "";
  localStorage.clear();
  cleanup();
  vi.unstubAllGlobals();
});

const brand: Branding = {
  org_name: "Acme",
  tagline: "",
  logo_url: "/uploads/app_logo/9.webp",
  favicon_url: "",
  primary_color: "#123abc",
  theme: "light",
  login_background_url: "",
  custom_css: "",
};

describe("AuthBrandHeader", () => {
  it("falls back to IdentityHub without a brand", () => {
    const { getByRole, container } = render(<AuthBrandHeader />);
    expect(getByRole("heading", { name: "IdentityHub" })).toBeDefined();
    expect(container.querySelector("img")).toBeNull();
    expect(getByRole("img", { name: "IdentityHub logo" })).toBeDefined();
  });

  it("shows the org name and logo from the brand", async () => {
    Object.defineProperty(window, "matchMedia", {
      writable: true,
      value: () => ({
        matches: false,
        media: "",
        addEventListener: () => undefined,
        removeEventListener: () => undefined,
      }),
    });
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({ branding: brand })));
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { findByRole, container } = render(
      <QueryClientProvider client={client}>
        <BrandProvider>
          <AuthBrandHeader />
        </BrandProvider>
      </QueryClientProvider>,
    );
    expect((await findByRole("heading", { name: "Acme" })).textContent).toBe("Acme");
    expect(container.querySelector('img[src="/uploads/app_logo/9.webp"]')).not.toBeNull();
  });
});
