import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AdminLDAPTestPage } from "./AdminLDAPTestPage";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderPage() {
  return render(
    <MemoryRouter>
      <AdminLDAPTestPage />
    </MemoryRouter>,
  );
}

describe("AdminLDAPTestPage", () => {
  it("reports a reachable directory", async () => {
    const fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      expect(String(url)).toBe("/api/admin/ldap/test");
      expect(init?.method).toBe("POST");
      return Response.json({ configured: true, ok: true });
    });
    vi.stubGlobal("fetch", fetchMock);
    const { getByRole, getByText } = renderPage();
    expect(fetchMock).not.toHaveBeenCalled();
    fireEvent.click(getByRole("button", { name: "Run test" }));
    await waitFor(() => expect(getByText("Directory is reachable")).toBeDefined());
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("reports an unconfigured upstream", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({ configured: false, ok: false, error: "LDAP upstream is not configured" }),
      ),
    );
    const { getByRole, getByText } = renderPage();
    fireEvent.click(getByRole("button", { name: "Run test" }));
    await waitFor(() => expect(getByText("LDAP is not configured")).toBeDefined());
    expect(getByText("LDAP upstream is not configured")).toBeDefined();
  });

  it("reports an unreachable directory as a failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({ configured: true, ok: false, error: "directory unreachable" }),
      ),
    );
    const { getByRole, getByText } = renderPage();
    fireEvent.click(getByRole("button", { name: "Run test" }));
    await waitFor(() => expect(getByText("Directory unreachable")).toBeDefined());
    expect(getByText("directory unreachable")).toBeDefined();
  });

  it("shows a notice when the request itself fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("down");
      }),
    );
    const { getByRole, getByText } = renderPage();
    fireEvent.click(getByRole("button", { name: "Run test" }));
    await waitFor(() => expect(getByText("Cannot reach the server. Try again.")).toBeDefined());
  });
});
