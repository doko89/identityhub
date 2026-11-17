import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AdminProvidersPage } from "./AdminProvidersPage";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

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
    const { container, getByRole, getByText } = render(
      <MemoryRouter>
        <AdminProvidersPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByRole("button", { name: "Register OIDC client" })).toBeDefined());
    fireEvent.click(getByRole("button", { name: "Register OIDC client" }));
    const section = container.querySelector('section[aria-label="OIDC clients"]') as HTMLElement;
    const set = (name: string, value: string) => {
      const input = section.querySelector(`[name="${name}"]`) as HTMLInputElement;
      fireEvent.change(input, { target: { value } });
    };
    set("client_id", "wiki-web");
    set("redirect_uris", "https://wiki.example.com/cb");
    set("scopes", "openid");
    const form = section.querySelector("form") as HTMLFormElement;
    fireEvent.submit(form);
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
});
