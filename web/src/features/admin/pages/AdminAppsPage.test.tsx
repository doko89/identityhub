import { cleanup, fireEvent, render, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AdminAppsPage } from "./AdminAppsPage";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const wiki = {
  id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
  slug: "wiki",
  name: "Wiki",
  description: "",
  icon_url: "",
  launch_url: "https://wiki.example.com",
  group_label: "",
  provider_type: "oidc",
  is_visible: true,
  sort_order: 0,
  mfa_required: false,
};

describe("AdminAppsPage", () => {
  it("lists apps and opens the bindings panel", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL | Request) => {
        const u = String(url);
        if (u.startsWith("/api/admin/apps?")) {
          return Response.json({ apps: [wiki], total: 1 });
        }
        if (u === `/api/admin/apps/${wiki.id}/bindings`) {
          return Response.json({
            bindings: [
              {
                id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                application_id: wiki.id,
                binding_type: "group",
                group_id: "cccccccc-cccc-cccc-cccc-cccccccccccc",
                eval_mode: "any",
              },
            ],
          });
        }
        throw new Error(`unexpected ${u}`);
      }),
    );
    const { getByRole, getByText } = render(
      <MemoryRouter>
        <AdminAppsPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("Wiki")).toBeDefined());
    fireEvent.click(getByRole("button", { name: "Bindings" }));
    await waitFor(() => expect(getByText(/cccccccc-cccc/)).toBeDefined());
  });

  it("creates an app with the form values", async () => {
    const created = { ...wiki, id: "dddddddd-dddd-dddd-dddd-dddddddddddd", slug: "crm", name: "CRM" };
    let posted: unknown = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
        if (init?.method === "POST") {
          posted = JSON.parse(String(init.body)) as unknown;
          return Response.json({ app: created }, { status: 201 });
        }
        return Response.json({ apps: [wiki], total: 1 });
      }),
    );
    const { getByRole, getByText } = render(
      <MemoryRouter>
        <AdminAppsPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("Wiki")).toBeDefined());
    fireEvent.click(getByRole("button", { name: "Add application" }));
    const sheet = getByRole("dialog", { name: "Add application" });
    fireEvent.change(within(sheet).getByLabelText("Slug"), { target: { value: "crm" } });
    fireEvent.change(within(sheet).getByLabelText("Name"), { target: { value: "CRM" } });
    fireEvent.click(within(sheet).getByRole("button", { name: "Create application" }));
    await waitFor(() => expect(getByText("CRM")).toBeDefined());
    expect(posted).toMatchObject({ slug: "crm", name: "CRM", provider_type: "oidc" });
  });
});
