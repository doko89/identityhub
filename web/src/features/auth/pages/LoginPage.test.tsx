import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import type { Branding } from "@/features/branding/api";
import { BrandProvider } from "@/features/branding/BrandProvider";
import { LoginPage } from "./LoginPage";

afterEach(() => {
  cleanup();
  document.title = "";
  vi.unstubAllGlobals();
});

const brand: Branding = {
  org_name: "Acme",
  tagline: "Acme apps, one sign-in.",
  logo_url: "/uploads/app_logo/7.webp",
  favicon_url: "",
  primary_color: "#123abc",
  theme: "light",
  login_background_url: "/uploads/app_logo/8.webp",
  custom_css: "",
  dashboard_columns: 3,
  dashboard_icon_shape: "rounded",
  dashboard_density: "comfortable",
  dashboard_background: "pattern",
  dashboard_background_url: "",
};

function mockMatchMedia(): void {
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: () => ({
      matches: false,
      media: "",
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
    }),
  });
}

function shell(children: ReactNode): ReactNode {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={client}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

describe("LoginPage", () => {
  it("shows the default brand panel and posts credentials", async () => {
    let posted: unknown = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
        posted = JSON.parse(String(init?.body)) as unknown;
        return Response.json({ error: "Wrong password. Try again." }, { status: 401 });
      }),
    );
    const { container, getAllByRole, getByLabelText, getByRole, getByText } = render(
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>,
    );
    expect(getByRole("heading", { name: "Sign in" })).toBeDefined();
    // The panel and the mobile header each render the mark (CSS shows one).
    expect(getAllByRole("img", { name: "IdentityHub logo" })).toHaveLength(2);
    expect(getByText(/single front door/)).toBeDefined();
    fireEvent.change(getByLabelText("Username"), { target: { value: "alice" } });
    fireEvent.change(getByLabelText("Password"), { target: { value: "secret" } });
    fireEvent.click(getByRole("button", { name: "Sign in" }));
    await waitFor(() => expect(getByText("Wrong password. Try again.")).toBeDefined());
    expect(posted).toEqual({ username: "alice", password: "secret" });
    expect(container.querySelector('img[src="/uploads/app_logo/8.webp"]')).toBeNull();
  });

  it("shows the brand backdrop photo and logo when uploaded", async () => {
    mockMatchMedia();
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({ branding: brand })));
    const { container, getByText } = render(
      shell(
        <BrandProvider>
          <LoginPage />
        </BrandProvider>,
      ),
    );
    await waitFor(() =>
      expect(container.querySelector('img[src="/uploads/app_logo/8.webp"]')).not.toBeNull(),
    );
    expect(container.querySelector('img[src="/uploads/app_logo/7.webp"]')).not.toBeNull();
    expect(getByText("Welcome back to Acme.")).toBeDefined();
    expect(getByText("Acme apps, one sign-in.")).toBeDefined();
  });
});
