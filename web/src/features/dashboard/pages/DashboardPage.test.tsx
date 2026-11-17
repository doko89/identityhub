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

const apps = [
  {
    id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", slug: "wiki", name: "Wiki",
    description: "", icon_url: "", launch_url: "https://wiki.example.com",
    group_label: "", provider_type: "oidc", mfa_required: false, open_in_new_tab: false,
  },
  {
    id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", slug: "crm", name: "CRM",
    description: "", icon_url: "", launch_url: "https://crm.example.com",
    group_label: "", provider_type: "oidc", mfa_required: false, open_in_new_tab: true,
  },
];

function stubFetch() {
  const fetchMock = vi.fn(async (url: string | URL | Request) => {
    const u = String(url);
    if (u === "/api/auth/me") {
      return Response.json({ user });
    }
    if (u === "/api/my-apps") {
      return Response.json({ apps });
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
});
