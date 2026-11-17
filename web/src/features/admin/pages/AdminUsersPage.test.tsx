import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AdminUsersPage } from "./AdminUsersPage";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const alice = {
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

function stubList(users: unknown[] = [alice], total = 1): ReturnType<typeof vi.fn> {
  const fetchMock = vi.fn(async () => Response.json({ users, total }));
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("AdminUsersPage", () => {
  it("lists users with status and admin flags", async () => {
    const fetchMock = stubList();
    const { getByText, getByRole } = render(
      <MemoryRouter>
        <AdminUsersPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("alice@example.com")).toBeDefined());
    expect(getByRole("cell", { name: "Active" })).toBeDefined();
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(String(fetchMock.mock.calls[0]?.[0])).toContain("/api/admin/users?");
  });

  it("creates a user and prepends the row", async () => {
    const bob = { ...alice, id: "22222222-2222-2222-2222-222222222222", username: "bob", email: "bob@example.com" };
    const fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      if (typeof url === "string" && url.startsWith("/api/admin/users?")) {
        return Response.json({ users: [alice], total: 1 });
      }
      expect(init?.method).toBe("POST");
      return Response.json({ user: bob }, { status: 201 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const { container, getByRole, getByText } = render(
      <MemoryRouter>
        <AdminUsersPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("alice@example.com")).toBeDefined());
    fireEvent.click(getByRole("button", { name: "Add user" }));
    const form = container.querySelector("form.ih-panel") as HTMLFormElement;
    const set = (name: string, value: string) => {
      const input = form.querySelector(`[name="${name}"]`) as HTMLInputElement;
      fireEvent.change(input, { target: { value } });
    };
    set("username", "bob");
    set("email", "bob@example.com");
    set("password", "secret-1");
    fireEvent.click(getByRole("button", { name: "Create user" }));
    await waitFor(() => expect(getByText("bob@example.com")).toBeDefined());
  });

  it("shows the backend message on failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ error: "administrator access required" }, { status: 403 })),
    );
    const { getByRole } = render(
      <MemoryRouter>
        <AdminUsersPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByRole("alert")).toBeDefined());
    expect(getByRole("alert").textContent).toContain("administrator access required");
  });
});
