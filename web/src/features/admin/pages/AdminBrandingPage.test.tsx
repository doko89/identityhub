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
  tagline: "",
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
    fireEvent.change(getByLabelText("Tagline"), { target: { value: "Globex apps, one sign-in." } });
    fireEvent.click(getByRole("button", { name: "Save branding" }));
    await waitFor(() => expect(getByText("Saved. The new theme is live.")).toBeDefined());
    expect(patched).toMatchObject({
      org_name: "Globex",
      tagline: "Globex apps, one sign-in.",
      theme: "light",
    });
  });

  it("uploads a logo file and saves its URL", async () => {
    let patched: unknown = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
        if (String(url) === "/api/uploads" && init?.method === "POST") {
          return Response.json(
            { id: "9", url: "/uploads/app_logo/9.webp", width: 200, height: 60, byte_size: 42 },
            { status: 201 },
          );
        }
        if (init?.method === "PATCH") {
          patched = JSON.parse(String(init.body)) as unknown;
          return Response.json({ branding: { ...brand, logo_url: "/uploads/app_logo/9.webp" } });
        }
        return Response.json({ branding: brand });
      }),
    );
    const { container, getByLabelText, getByRole } = render(shell(<AdminBrandingPage />));
    await waitFor(() => expect(getByLabelText("Organization name")).toBeDefined());
    const picker = container.querySelector("#logo-upload") as HTMLInputElement;
    fireEvent.change(picker, {
      target: { files: [new File([new Uint8Array(10)], "logo.png", { type: "image/png" })] },
    });
    await waitFor(() =>
      expect(container.querySelector('img[src="/uploads/app_logo/9.webp"]')).not.toBeNull(),
    );
    fireEvent.click(getByRole("button", { name: "Save branding" }));
    await waitFor(() => expect(patched).toMatchObject({ logo_url: "/uploads/app_logo/9.webp" }));
  });

  it("applies a preset color to the hex input", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({ branding: brand })));
    const { getByLabelText, getByRole } = render(shell(<AdminBrandingPage />));
    await waitFor(() => expect(getByLabelText("Organization name")).toBeDefined());
    fireEvent.click(getByRole("radio", { name: "Teal" }));
    const input = getByRole("textbox", { name: "Primary color" }) as HTMLInputElement;
    expect(input.value).toBe("#0f766e");
    expect(getByRole("radio", { name: "Teal" }).getAttribute("aria-checked")).toBe("true");
  });

  it("rejects a malformed color code and blocks saving", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({ branding: brand })));
    const { getByLabelText, getByRole, getByText, queryByText } = render(shell(<AdminBrandingPage />));
    await waitFor(() => expect(getByLabelText("Organization name")).toBeDefined());
    const input = getByRole("textbox", { name: "Primary color" }) as HTMLInputElement;
    fireEvent.change(input, { target: { value: "red" } });
    expect(getByText("Use the #rrggbb format, e.g. #4f46e5.")).toBeDefined();
    expect(getByRole("button", { name: "Save branding" }).hasAttribute("disabled")).toBe(true);
    fireEvent.change(input, { target: { value: "" } });
    expect(queryByText("Use the #rrggbb format, e.g. #4f46e5.")).toBeNull();
    expect(getByRole("button", { name: "Save branding" }).hasAttribute("disabled")).toBe(false);
  });
});
