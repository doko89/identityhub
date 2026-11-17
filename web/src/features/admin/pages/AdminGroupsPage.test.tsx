import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AdminGroupsPage } from "./AdminGroupsPage";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const eng = { id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", name: "eng", description: "", member_count: 1 };
const memberId = "11111111-1111-1111-1111-111111111111";

describe("AdminGroupsPage", () => {
  it("lists groups and opens the member panel", async () => {
    const fetchMock = vi.fn(async (url: string | URL | Request) => {
      const u = String(url);
      if (u.startsWith("/api/admin/groups?")) {
        return Response.json({ groups: [eng], total: 1 });
      }
      if (u === `/api/admin/groups/${eng.id}`) {
        return Response.json({
          group: { id: eng.id, name: "eng", description: "", members: [memberId] },
        });
      }
      if (u === `/api/admin/users/${memberId}`) {
        return Response.json({
          user: {
            id: memberId, username: "alice", email: "alice@example.com", display_name: "",
            source: "local", is_active: true, avatar_url: "", groups: [], is_admin: false,
          },
        });
      }
      throw new Error(`unexpected ${u}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const { getByRole, getByText } = render(
      <MemoryRouter>
        <AdminGroupsPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("eng")).toBeDefined());
    fireEvent.click(getByRole("button", { name: "Members" }));
    await waitFor(() => expect(getByText("alice (alice@example.com)")).toBeDefined());
  });

  it("surfaces the backend refusal when deleting ih_admin", async () => {
    const admin = { id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", name: "ih_admin", description: "", member_count: 1 };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
        if (init?.method === "DELETE") {
          return Response.json({ error: "the ih_admin group cannot be deleted" }, { status: 400 });
        }
        return Response.json({ groups: [admin], total: 1 });
      }),
    );
    const { getByRole, getByText } = render(
      <MemoryRouter>
        <AdminGroupsPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("ih_admin")).toBeDefined());
    fireEvent.click(getByRole("button", { name: "Delete" }));
    fireEvent.click(getByRole("button", { name: "Delete group" }));
    await waitFor(() =>
      expect(getByText("the ih_admin group cannot be deleted")).toBeDefined(),
    );
  });
});
