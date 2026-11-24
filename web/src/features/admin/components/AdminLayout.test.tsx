import { cleanup, render, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { resetSessionForTests } from "@/shared/stores/session";
import { AdminLayout } from "./AdminLayout";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  resetSessionForTests();
});

const admin = {
  id: "11111111-1111-1111-1111-111111111111",
  username: "root",
  email: "root@example.com",
  display_name: "Root",
  source: "local",
  is_active: true,
  avatar_url: "",
  groups: ["ih_admin"],
  is_admin: true,
};

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route element={<AdminLayout />}>
          <Route path="/admin/users" element={<div>users page</div>} />
          <Route path="/admin/groups" element={<div>groups page</div>} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}

describe("AdminLayout", () => {
  it("renders the sidebar nav with the active section", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({ user: admin })));
    const { getByRole, getByText } = renderAt("/admin/users");
    await waitFor(() => expect(getByText("users page")).toBeDefined());
    expect(getByRole("navigation", { name: "Admin" })).toBeDefined();
    expect(getByRole("link", { name: "Users" }).getAttribute("aria-current")).toBe("page");
    expect(getByText("Admin console · Users")).toBeDefined();
    expect(getByRole("link", { name: "Back to dashboard" })).toBeDefined();
  });

  it("links the topbar to the API docs in a new tab", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({ user: admin })));
    const { getByRole } = renderAt("/admin/users");
    await waitFor(() => expect(getByRole("link", { name: "API documentation" })).toBeDefined());
    const link = getByRole("link", { name: "API documentation" });
    expect(link.getAttribute("href")).toBe("/api/admin/docs");
    expect(link.getAttribute("target")).toBe("_blank");
  });

  it("shows the forbidden page for non-admins", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ user: { ...admin, is_admin: false } })),
    );
    const { getByText, queryByRole } = renderAt("/admin/groups");
    await waitFor(() => expect(getByText("Administrator access required")).toBeDefined());
    expect(queryByRole("navigation", { name: "Admin" })).toBeNull();
  });
});
