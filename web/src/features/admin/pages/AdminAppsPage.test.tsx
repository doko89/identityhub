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
  group_label: "Tools",
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
    expect(getByRole("cell", { name: "Tools" })).toBeDefined();
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
    fireEvent.click(within(sheet).getByLabelText("Open in new tab"));
    fireEvent.click(within(sheet).getByRole("button", { name: "Create application" }));
    await waitFor(() => expect(getByText("CRM")).toBeDefined());
    expect(posted).toMatchObject({ slug: "crm", name: "CRM", provider_type: "oidc", open_in_new_tab: true });
  });

  it("uploads a dropped icon and sends its URL on create", async () => {
    const created = {
      ...wiki,
      id: "dddddddd-dddd-dddd-dddd-dddddddddddd",
      slug: "crm",
      name: "CRM",
      icon_url: "/uploads/app_logo/9.webp",
    };
    let posted: unknown = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
        if (String(url) === "/api/uploads" && init?.method === "POST") {
          return Response.json(
            { id: "9", url: "/uploads/app_logo/9.webp", width: 100, height: 100, byte_size: 42 },
            { status: 201 },
          );
        }
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
    const zone = sheet.querySelector('div[aria-label="Upload app icon"]') as HTMLElement;
    fireEvent.drop(zone, {
      dataTransfer: { files: [new File([new Uint8Array(10)], "icon.png", { type: "image/png" })] },
    });
    await waitFor(() =>
      expect(sheet.querySelector('img[src="/uploads/app_logo/9.webp"]')).not.toBeNull(),
    );
    fireEvent.click(within(sheet).getByRole("button", { name: "Create application" }));
    await waitFor(() => expect(getByText("CRM")).toBeDefined());
    expect(posted).toMatchObject({ slug: "crm", icon_url: "/uploads/app_logo/9.webp" });
  });

  it("clears a stale bindings error once loading succeeds", async () => {
    const binding = {
      id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      application_id: wiki.id,
      binding_type: "group",
      group_id: "cccccccc-cccc-cccc-cccc-cccccccccccc",
      eval_mode: "any",
    };
    let bindingsCalls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
        const u = String(url);
        if (u.startsWith("/api/admin/apps?")) {
          return Response.json({ apps: [wiki], total: 1 });
        }
        if (u === `/api/admin/apps/${wiki.id}/bindings` && init?.method === "POST") {
          return Response.json({ binding }, { status: 201 });
        }
        if (u === `/api/admin/apps/${wiki.id}/bindings`) {
          bindingsCalls += 1;
          if (bindingsCalls === 1) {
            throw new TypeError("Failed to fetch");
          }
          return Response.json({ bindings: [binding] });
        }
        if (u.startsWith("/api/admin/users?")) {
          return Response.json({
            users: [{ id: "dddddddd-dddd-dddd-dddd-dddddddddddd", username: "ara", email: "ara@example.com" }],
            total: 1,
          });
        }
        throw new Error(`unexpected ${u}`);
      }),
    );
    const { getByLabelText, getByRole, getByText, queryByText } = render(
      <MemoryRouter>
        <AdminAppsPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("Wiki")).toBeDefined());
    fireEvent.click(getByRole("button", { name: "Bindings" }));
    await waitFor(() => expect(getByText("Cannot reach the server. Try again.")).toBeDefined());
    fireEvent.change(getByLabelText("Binding target"), { target: { value: "ara" } });
    fireEvent.click(getByRole("button", { name: "Add" }));
    await waitFor(() => expect(getByText(/cccccccc-cccc/)).toBeDefined());
    expect(queryByText("Cannot reach the server. Try again.")).toBeNull();
  });

  it("clears a failed submit error once creating succeeds", async () => {
    const created = { ...wiki, id: "dddddddd-dddd-dddd-dddd-dddddddddddd", slug: "crm", name: "CRM" };
    let posts = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
        if (init?.method === "POST") {
          posts += 1;
          if (posts === 1) {
            return Response.json({ error: "Slug taken" }, { status: 400 });
          }
          return Response.json({ app: created }, { status: 201 });
        }
        return Response.json({ apps: [wiki], total: 1 });
      }),
    );
    const { getByRole, getByText, queryByText } = render(
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
    await waitFor(() => expect(getByText("Slug taken")).toBeDefined());
    fireEvent.click(within(sheet).getByRole("button", { name: "Create application" }));
    await waitFor(() => expect(getByText("CRM")).toBeDefined());
    expect(queryByText("Slug taken")).toBeNull();
  });

  it("filters the list by dashboard group", async () => {
    const urls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL | Request) => {
        urls.push(String(url));
        return Response.json({ apps: [wiki], total: 1 });
      }),
    );
    const { getByLabelText, getByRole, getByText } = render(
      <MemoryRouter>
        <AdminAppsPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("Wiki")).toBeDefined());
    fireEvent.change(getByLabelText("Filter by dashboard group"), { target: { value: "Tools" } });
    fireEvent.click(getByRole("button", { name: "Search" }));
    await waitFor(() => expect(urls.some((u) => u.includes("group=Tools"))).toBe(true));
    fireEvent.click(getByRole("button", { name: "Reset" }));
    await waitFor(() => {
      const calls = urls.filter((u) => u.includes("/api/admin/apps?"));
      expect(calls[calls.length - 1]).not.toContain("group=");
    });
  });
});
