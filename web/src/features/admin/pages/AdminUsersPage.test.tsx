import { cleanup, fireEvent, render, waitFor, within } from "@testing-library/react";
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
    const { getByRole, getByText } = render(
      <MemoryRouter>
        <AdminUsersPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("alice@example.com")).toBeDefined());
    fireEvent.click(getByRole("button", { name: "Add user" }));
    const sheet = getByRole("dialog", { name: "Add user" });
    const set = (label: string, value: string) => {
      fireEvent.change(within(sheet).getByLabelText(label), { target: { value } });
    };
    set("Username", "bob");
    set("Email", "bob@example.com");
    set("Password", "secret-1");
    fireEvent.click(within(sheet).getByRole("button", { name: "Create user" }));
    await waitFor(() => expect(getByText("bob@example.com")).toBeDefined());
  });

  it("uploads an avatar in the edit sheet and saves its URL", async () => {
    const uploadedUrl = "/uploads/avatar/aaa.webp";
    let patchBody: Record<string, unknown> | null = null;
    const fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const u = String(url);
      if (u.startsWith("/api/admin/users?")) {
        return Response.json({ users: [alice], total: 1 });
      }
      if (u === "/api/uploads" && init?.method === "POST") {
        expect((init.body as FormData).get("asset_type")).toBe("avatar");
        return Response.json({ id: "aaa", url: uploadedUrl, width: 1, height: 1, byte_size: 3 });
      }
      expect(init?.method).toBe("PATCH");
      patchBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return Response.json({ user: { ...alice, avatar_url: uploadedUrl } });
    });
    vi.stubGlobal("fetch", fetchMock);
    const { getByRole, getByText } = render(
      <MemoryRouter>
        <AdminUsersPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("alice@example.com")).toBeDefined());
    fireEvent.click(getByRole("button", { name: "Edit alice" }));
    const sheet = getByRole("dialog", { name: "Edit alice" });
    expect(within(sheet).getByText("No avatar")).toBeDefined();
    const input = sheet.querySelector("#edit-avatar-upload") as HTMLInputElement;
    fireEvent.change(input, { target: { files: [new File(["img"], "a.png", { type: "image/png" })] } });
    await waitFor(() => expect(within(sheet).queryByText("No avatar")).toBeNull());
    fireEvent.click(within(sheet).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(patchBody).not.toBeNull());
    expect(patchBody?.["avatar_url"]).toBe(uploadedUrl);
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
