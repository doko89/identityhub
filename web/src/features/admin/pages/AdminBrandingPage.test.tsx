import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";
import type { Branding } from "@/features/branding/api";
import { AdminBrandingPage } from "./AdminBrandingPage";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const brand: Branding = {
  org_name: "Acme",
  logo_url: "",
  favicon_url: "",
  primary_color: "#123abc",
  theme: "light",
  login_background_url: "",
  custom_css: "",
};

function shell(children: ReactNode): ReactNode {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={client}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

describe("AdminBrandingPage", () => {
  it("loads the brand and previews the org name live", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({ branding: brand })));
    const { container, getByLabelText } = render(shell(<AdminBrandingPage />));
    await waitFor(() => expect(getByLabelText("Organization name")).toBeDefined());
    const input = getByLabelText("Organization name") as HTMLInputElement;
    expect(input.value).toBe("Acme");
    fireEvent.change(input, { target: { value: "Globex" } });
    const preview = container.querySelector('[aria-label="Login preview"]') as HTMLElement;
    expect(preview.textContent).toContain("Globex");
  });

  it("patches the brand and confirms the save", async () => {
    let patched: unknown = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
        if (init?.method === "PATCH") {
          patched = JSON.parse(String(init.body)) as unknown;
          return Response.json({ branding: { ...brand, org_name: "Globex" } });
        }
        return Response.json({ branding: brand });
      }),
    );
    const { getByLabelText, getByRole, getByText } = render(shell(<AdminBrandingPage />));
    await waitFor(() => expect(getByLabelText("Organization name")).toBeDefined());
    const input = getByLabelText("Organization name") as HTMLInputElement;
    fireEvent.change(input, { target: { value: "Globex" } });
    fireEvent.click(getByRole("button", { name: "Save branding" }));
    await waitFor(() => expect(getByText("Saved. The new theme is live.")).toBeDefined());
    expect(patched).toMatchObject({ org_name: "Globex", theme: "light" });
  });
});
