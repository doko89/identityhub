import { cleanup, fireEvent, render, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AdminProvidersPage } from "./AdminProvidersPage";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

// Radix opens the dropdown on pointerdown, not click.
function openMenu(trigger: HTMLElement): void {
  fireEvent.pointerDown(trigger, { button: 0, ctrlKey: false });
}

const appId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const app = {
  id: appId, slug: "wiki", name: "Wiki", description: "", icon_url: "", launch_url: "",
  group_label: "", provider_type: "oidc", is_visible: true, sort_order: 0, mfa_required: false,
};

function stubAll(overrides: { clients?: unknown[]; sps?: unknown[]; radius?: unknown[] } = {}) {
  const calls: Array<{ url: string; method: string | undefined; body: unknown }> = [];
  const fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const u = String(url);
    calls.push({ url: u, method: init?.method, body: init?.body });
    if (u.startsWith("/api/admin/apps?")) {
      return Response.json({ apps: [app], total: 1 });
    }
    if (u.startsWith("/api/admin/oidc/clients")) {
      if (init?.method === "POST") {
        return Response.json(
          {
            client: {
              application_id: appId, client_id: "wiki-web",
              redirect_uris: ["https://wiki.example.com/cb"], scopes: ["openid"], public: false,
            },
            client_secret: "sekret-sekali",
          },
          { status: 201 },
        );
      }
      return Response.json({ clients: overrides.clients ?? [], total: 0 });
    }
    if (u.startsWith("/api/admin/saml/sps")) {
      return Response.json({ sps: overrides.sps ?? [], total: 0 });
    }
    if (u.startsWith("/api/admin/radius/clients")) {
      return Response.json({ clients: overrides.radius ?? [], total: 0 });
    }
    throw new Error(`unexpected ${u}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return { fetchMock, calls };
}

describe("AdminProvidersPage", () => {
  it("renders all three provider sections", async () => {
    stubAll({
      clients: [
        {
          application_id: appId, client_id: "wiki-web",
          redirect_uris: ["https://wiki.example.com/cb"], scopes: ["openid"], public: false,
        },
      ],
      sps: [{ application_id: appId, entity_id: "https://sp.example.com", acs_url: "https://sp.example.com/acs", slo_url: "" }],
      radius: [{ application_id: appId, nas_identifier: "vpn-1" }],
    });
    const { getByText } = render(
      <MemoryRouter>
        <AdminProvidersPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("wiki-web")).toBeDefined());
    expect(getByText("https://sp.example.com")).toBeDefined();
    expect(getByText("vpn-1")).toBeDefined();
  });

  it("registers an OIDC client and shows the secret once", async () => {
    const { calls } = stubAll();
    const { findByRole, getByRole, getByText } = render(
      <MemoryRouter>
        <AdminProvidersPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByRole("button", { name: "Add provider" })).toBeDefined());
    openMenu(getByRole("button", { name: "Add provider" }));
    fireEvent.click(await findByRole("menuitem", { name: "OIDC client" }));
    const sheet = await findByRole("dialog", { name: "Register OIDC client" });
    fireEvent.change(within(sheet).getByLabelText("Client ID"), { target: { value: "wiki-web" } });
    fireEvent.change(within(sheet).getByLabelText("Redirect URIs (space or comma separated)"), {
      target: { value: "https://wiki.example.com/cb" },
    });
    fireEvent.change(within(sheet).getByLabelText("Scopes (space or comma separated)"), {
      target: { value: "openid" },
    });
    fireEvent.click(within(sheet).getByRole("button", { name: "Register client" }));
    await waitFor(() => expect(getByText("sekret-sekali")).toBeDefined());
    const post = calls.find((c) => c.method === "POST" && c.url === "/api/admin/oidc/clients");
    expect(post?.body).toBe(
      JSON.stringify({
        application_id: appId,
        client_id: "wiki-web",
        redirect_uris: ["https://wiki.example.com/cb"],
        scopes: ["openid"],
        public: false,
      }),
    );
  });

  it("opens each protocol sheet from the Add provider menu", async () => {
    stubAll();
    const { findByRole, getByRole, getByText } = render(
      <MemoryRouter>
        <AdminProvidersPage />
      </MemoryRouter>,
    );
    await waitFor(() => {
      expect(getByText("No OIDC clients yet.")).toBeDefined();
      expect(getByText("No SAML service providers yet.")).toBeDefined();
      expect(getByText("No RADIUS clients yet.")).toBeDefined();
    });
    const pairs: Array<[string, string]> = [
      ["OIDC client", "Register OIDC client"],
      ["SAML service provider", "Import SAML SP"],
      ["RADIUS client", "Register RADIUS client"],
    ];
    for (const [item, title] of pairs) {
      openMenu(getByRole("button", { name: "Add provider" }));
      fireEvent.click(await findByRole("menuitem", { name: item }));
      const sheet = await findByRole("dialog", { name: title });
      expect(sheet).toBeDefined();
      // The open sheet is modal, so close it before opening the next one.
      fireEvent.click(within(sheet).getByRole("button", { name: "Close" }));
      await waitFor(() => expect(getByRole("button", { name: "Add provider" })).toBeDefined());
    }
  });
});
