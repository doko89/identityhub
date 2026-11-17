import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import { THEME_STORAGE_KEY } from "./apply";
import { BrandProvider } from "./BrandProvider";
import { ThemeToggle } from "./ThemeToggle";

// jsdom ships no matchMedia; the toggle only needs matches.
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
  cleanup();
  document.documentElement.classList.remove("dark");
  localStorage.clear();
  vi.unstubAllGlobals();
});

// Radix opens the dropdown on pointerdown, not click.
function openMenu(trigger: HTMLElement): void {
  fireEvent.pointerDown(trigger, { button: 0, ctrlKey: false });
}

describe("ThemeToggle", () => {
  it("defaults to System and leaves the OS in charge", async () => {
    mockMatchMedia(true);
    const { findByRole, getByRole } = render(<ThemeToggle />);
    openMenu(getByRole("button", { name: "Theme" }));
    const system = await findByRole("menuitemradio", { name: "System" });
    expect(system.getAttribute("aria-checked")).toBe("true");
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBeNull();
  });

  it("switches mode, applies it, and persists the choice", async () => {
    mockMatchMedia(false);
    const { findByRole, getByRole } = render(<ThemeToggle />);

    openMenu(getByRole("button", { name: "Theme" }));
    fireEvent.click(await findByRole("menuitemradio", { name: "Dark" }));
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);

    openMenu(getByRole("button", { name: "Theme" }));
    const light = await findByRole("menuitemradio", { name: "Light" });
    fireEvent.click(light);
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe("light");
    expect(document.documentElement.classList.contains("dark")).toBe(false);
  });

  it("restores the persisted choice on mount", async () => {
    mockMatchMedia(false);
    localStorage.setItem(THEME_STORAGE_KEY, "dark");
    const { findByRole, getByRole } = render(<ThemeToggle />);
    openMenu(getByRole("button", { name: "Theme" }));
    const dark = await findByRole("menuitemradio", { name: "Dark" });
    expect(dark.getAttribute("aria-checked")).toBe("true");
  });

  it("shows the stored choice winning over the brand default", async () => {
    mockMatchMedia(false);
    localStorage.setItem(THEME_STORAGE_KEY, "dark");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({
          branding: {
            org_name: "Acme",
            logo_url: "",
            favicon_url: "",
            primary_color: "#123abc",
            theme: "light",
            login_background_url: "",
            custom_css: "",
          },
        }),
      ),
    );
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const shell = (children: ReactNode): ReactNode => (
      <QueryClientProvider client={client}>
        <BrandProvider>{children}</BrandProvider>
      </QueryClientProvider>
    );
    const { findByRole, getByRole } = render(shell(<ThemeToggle />));
    openMenu(getByRole("button", { name: "Theme" }));
    const dark = await findByRole("menuitemradio", { name: "Dark" });
    expect(dark.getAttribute("aria-checked")).toBe("true");
  });
});
