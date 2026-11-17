import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AdminAttrsPage } from "./AdminAttrsPage";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const dept = { key: "dept", type: "string", multi: false };
const userId = "11111111-1111-1111-1111-111111111111";

describe("AdminAttrsPage", () => {
  it("lists defs and edits one user's values", async () => {
    let saved: unknown = null;
    const fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const u = String(url);
      if (u === "/api/admin/user-attrs" && (init?.method === undefined || init.method === "GET")) {
        return Response.json({ defs: [dept] });
      }
      if (u.startsWith("/api/admin/users?")) {
        return Response.json({
          users: [{ id: userId, username: "alice", email: "alice@example.com" }],
          total: 1,
        });
      }
      if (u === `/api/admin/users/${userId}/attrs` && init?.method === "PUT") {
        saved = JSON.parse(String(init.body));
        return Response.json({ attrs: { dept: "eng" } });
      }
      if (u === `/api/admin/users/${userId}/attrs`) {
        return Response.json({ attrs: {} });
      }
      throw new Error(`unexpected ${u} ${init?.method ?? "GET"}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const { getByText, getByLabelText, getByRole } = render(
      <MemoryRouter>
        <AdminAttrsPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("dept")).toBeDefined());

    fireEvent.change(getByLabelText("User to edit"), { target: { value: "alice" } });
    fireEvent.click(getByRole("button", { name: "Load" }));
    await waitFor(() => expect(getByText("Editing")).toBeDefined());

    fireEvent.change(getByLabelText(/dept/), { target: { value: "eng" } });
    fireEvent.click(getByRole("button", { name: "Save values" }));
    await waitFor(() => expect(getByText("Saved.", { exact: false })).toBeDefined());
    expect(saved).toEqual({ dept: "eng" });
  });

  it("surfaces the backend refusal for reserved keys", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
        if (init?.method === "POST") {
          return Response.json({ error: 'attribute key "sub" is reserved' }, { status: 400 });
        }
        return Response.json({ defs: [] });
      }),
    );
    const { getByText, getByRole, getByLabelText } = render(
      <MemoryRouter>
        <AdminAttrsPage />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(getByText("No custom attributes yet.", { exact: false })).toBeDefined(),
    );
    fireEvent.click(getByRole("button", { name: "Add attribute" }));
    fireEvent.change(getByLabelText("Key"), { target: { value: "sub" } });
    fireEvent.click(getByRole("button", { name: "Create attribute" }));
    await waitFor(() => expect(getByText('attribute key "sub" is reserved')).toBeDefined());
  });
});
