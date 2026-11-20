import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { resetSessionForTests } from "@/shared/stores/session";
import { DashboardPage } from "./DashboardPage";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  resetSessionForTests();
});

const user = {
  id: "11111111-1111-1111-1111-111111111111",
  username: "alice",
  email: "alice@example.com",
  display_name: "Alice",
  source: "local",
  is_active: true,
  avatar_url: "",
  groups: [],
  is_admin: false,
};

type MockApp = {
  id: string;
  slug: string;
  name: string;
  description: string;
  icon_url: string;
  launch_url: string;
  group_label: string;
  provider_type: string;
  mfa_required: boolean;
  open_in_new_tab: boolean;
  is_favorite: boolean;
  last_launched_at: string | null;
};

const apps: MockApp[] = [
  {
    id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", slug: "wiki", name: "Wiki",
    description: "", icon_url: "", launch_url: "https://wiki.example.com",
    group_label: "", provider_type: "oidc", mfa_required: false, open_in_new_tab: false,
    is_favorite: false, last_launched_at: null,
  },
  {
    id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", slug: "crm", name: "CRM",
    description: "", icon_url: "", launch_url: "https://crm.example.com",
    group_label: "", provider_type: "oidc", mfa_required: true, open_in_new_tab: true,
    is_favorite: false, last_launched_at: null,
  },
];

function stubFetch(list: MockApp[] = apps) {
  const fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    void init;
    const u = String(url);
    if (u === "/api/auth/me") {
      return Response.json({ user });
    }
    if (u === "/api/my-apps") {
      return Response.json({ apps: list });
    }
    if (u.endsWith("/favorite")) {
      return new Response(null, { status: 204 });
    }
    if (u === "/api/apps/wiki/launch") {
      return Response.json({ launch_url: "https://wiki.example.com/sso" });
    }
    if (u === "/api/apps/crm/launch") {
      return Response.json({ launch_url: "https://crm.example.com/sso" });
    }
    throw new Error(`unexpected ${u}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("DashboardPage", () => {
  it("opens new-tab apps with window.open and others in place", async () => {
    const fetchMock = stubFetch();
    const openMock = vi.fn();
    vi.stubGlobal("open", openMock);
    const { getByRole, getByText } = render(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("CRM")).toBeDefined());
    fireEvent.click(getByRole("button", { name: "Open CRM" }));
    await waitFor(() =>
      expect(openMock).toHaveBeenCalledWith("https://crm.example.com/sso", "_blank", "noopener"),
    );
    fireEvent.click(getByRole("button", { name: "Open Wiki" }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/apps/wiki/launch"));
    expect(openMock).toHaveBeenCalledTimes(1);
  });

  it("shows the default logo, greeting, and MFA marks without a brand", async () => {
    stubFetch();
    const { getByRole, getByText, getByTitle } = render(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("CRM")).toBeDefined());
    expect(getByRole("img", { name: "IdentityHub logo" })).toBeDefined();
    expect(getByText("Hello, Alice")).toBeDefined();
    expect(getByText("2 applications ready to launch.")).toBeDefined();
    expect(getByTitle("Requires two-step verification")).toBeDefined();
  });

  it("filters applications by name", async () => {
    stubFetch();
    const { getByPlaceholderText, getByText, queryByText } = render(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("CRM")).toBeDefined());
    fireEvent.change(getByPlaceholderText("Filter applications…"), { target: { value: "crm" } });
    expect(queryByText("Wiki")).toBeNull();
    expect(getByText("CRM")).toBeDefined();
    fireEvent.change(getByPlaceholderText("Filter applications…"), { target: { value: "zzz" } });
    expect(getByText("No applications match “zzz”.")).toBeDefined();
  });

  it("pins and unpins an app from favorites", async () => {
    const fetchMock = stubFetch();
    const { getByRole, getByText, getAllByRole, queryByRole } = render(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("CRM")).toBeDefined());
    expect(queryByRole("heading", { name: "Favorites (1)" })).toBeNull();
    fireEvent.click(getByRole("button", { name: "Pin Wiki" }));
    await waitFor(() => expect(getByRole("heading", { name: "Favorites (1)" })).toBeDefined());
    expect(fetchMock).toHaveBeenCalledWith("/api/my-apps/wiki/favorite", { method: "PUT" });
    // The pinned app moves out of the grouped list: one Wiki tile total.
    expect(getAllByRole("button", { name: "Open Wiki" })).toHaveLength(1);
    expect(queryByRole("heading", { name: "Apps (1)" })).toBeNull();
    fireEvent.click(getByRole("button", { name: "Unpin Wiki" }));
    await waitFor(() => expect(queryByRole("heading", { name: "Favorites (1)" })).toBeNull());
    expect(fetchMock).toHaveBeenCalledWith("/api/my-apps/wiki/favorite", { method: "DELETE" });
  });

  it("shows favorites and recents above the grouped list without duplicates", async () => {
    const list: MockApp[] = [
      ...apps.map((a) =>
        a.slug === "wiki"
          ? { ...a, is_favorite: true, last_launched_at: "2026-11-20T12:00:00Z" }
          : { ...a, is_favorite: false, last_launched_at: "2026-11-20T11:00:00Z" },
      ),
      {
        id: "cccccccc-cccc-cccc-cccc-cccccccccccc",
        slug: "vault",
        name: "Vault",
        description: "",
        icon_url: "",
        launch_url: "https://vault.example.com",
        group_label: "",
        provider_type: "oidc",
        mfa_required: false,
        open_in_new_tab: false,
        is_favorite: false,
        last_launched_at: null,
      },
    ];
    stubFetch(list);
    const { getByRole, getAllByRole, getByText } = render(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("Vault")).toBeDefined());
    expect(getByRole("heading", { name: "Favorites (1)" })).toBeDefined();
    expect(getByRole("heading", { name: "Recently used (1)" })).toBeDefined();
    expect(getAllByRole("button", { name: "Open Wiki" })).toHaveLength(1);
    expect(getAllByRole("button", { name: "Open CRM" })).toHaveLength(1);
  });

  it("rolls back the pin when the server rejects it", async () => {
    const fetchMock = vi.fn(async (url: string | URL | Request) => {
      const u = String(url);
      if (u === "/api/auth/me") {
        return Response.json({ user });
      }
      if (u === "/api/my-apps") {
        return Response.json({ apps });
      }
      return Response.json({ error: "no access to this application" }, { status: 403 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const { getByRole, getByText, queryByRole } = render(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("CRM")).toBeDefined());
    fireEvent.click(getByRole("button", { name: "Pin Wiki" }));
    await waitFor(() => expect(getByText("Could not update favorites. Try again.")).toBeDefined());
    expect(queryByRole("heading", { name: "Favorites (1)" })).toBeNull();
    expect(getByRole("button", { name: "Pin Wiki" })).toBeDefined();
  });

  it("keeps dashboard content above the fixed wallpaper", async () => {
    stubFetch();
    const { container, getByText } = render(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("CRM")).toBeDefined());
    // Regression: an opaque photo wallpaper sits fixed behind everything;
    // static rows (group headings) need their own stacking level or the
    // photo covers them while animated cards float above it.
    const main = container.querySelector("main");
    expect(main?.className).toContain("relative");
    expect(main?.className).toContain("z-10");
  });

  it("hides the default heading unless grouping is meaningful", async () => {
    stubFetch();
    const ungrouped = render(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(ungrouped.getByText("CRM")).toBeDefined());
    expect(ungrouped.queryByRole("heading", { name: "Apps (2)" })).toBeNull();
    ungrouped.unmount();
    const grouped = apps.map((a) => (a.slug === "wiki" ? { ...a, group_label: "Tools" } : a));
    stubFetch(grouped);
    const { getByRole, getByText } = render(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("CRM")).toBeDefined());
    expect(getByRole("heading", { name: "Tools (1)" })).toBeDefined();
    expect(getByRole("heading", { name: "Apps (1)" })).toBeDefined();
  });
});
