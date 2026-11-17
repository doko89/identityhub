import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AdminAuditPage, exportFileName } from "./AdminAuditPage";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const entry = {
  id: 7,
  at: "2026-11-17T10:00:00Z",
  actor_user_id: "11111111-1111-1111-1111-111111111111",
  application_id: null,
  method: "password",
  result: "failure",
  ip: "10.0.0.1",
  detail: { reason: "bad password" },
};

describe("AdminAuditPage", () => {
  it("lists entries and filters by method", async () => {
    const seen: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL | Request) => {
        seen.push(String(url));
        return Response.json({ entries: [entry], total: 1 });
      }),
    );
    const { container, getByRole, getByText } = render(
      <MemoryRouter>
        <AdminAuditPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("10.0.0.1")).toBeDefined());
    const form = container.querySelector("form") as HTMLFormElement;
    const method = form.querySelector('[name="method"]') as HTMLSelectElement;
    fireEvent.change(method, { target: { value: "password" } });
    fireEvent.click(getByRole("button", { name: "Filter" }));
    await waitFor(() => expect(seen.length).toBeGreaterThan(1));
    expect(seen[seen.length - 1]).toContain("method=password");
  });

  it("downloads the CSV with the active filters", async () => {
    const seen: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL | Request) => {
        const u = String(url);
        seen.push(u);
        if (u.startsWith("/api/admin/audit/export")) {
          return new Response("id,at\n7,now\n", {
            headers: { "Content-Disposition": 'attachment; filename="audit-export-x.csv"' },
          });
        }
        return Response.json({ entries: [entry], total: 1 });
      }),
    );
    const createURL = vi.fn(() => "blob:fake");
    const revokeURL = vi.fn();
    Object.defineProperty(window.URL, "createObjectURL", { value: createURL, writable: true });
    Object.defineProperty(window.URL, "revokeObjectURL", { value: revokeURL, writable: true });
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
    try {
      const { container, getByRole, getByText } = render(
        <MemoryRouter>
          <AdminAuditPage />
        </MemoryRouter>,
      );
      await waitFor(() => expect(getByText("10.0.0.1")).toBeDefined());
      const form = container.querySelector("form") as HTMLFormElement;
      const result = form.querySelector('[name="result"]') as HTMLSelectElement;
      fireEvent.change(result, { target: { value: "failure" } });
      fireEvent.click(getByRole("button", { name: "Filter" }));
      await waitFor(() => expect(seen.some((u) => u.includes("result=failure"))).toBe(true));
      fireEvent.click(getByRole("button", { name: "Export CSV" }));
      await waitFor(() => expect(createURL).toHaveBeenCalled());
      expect(clickSpy).toHaveBeenCalled();
      expect(revokeURL).toHaveBeenCalledWith("blob:fake");
      expect(seen.some((u) => u.startsWith("/api/admin/audit/export") && u.includes("result=failure"))).toBe(
        true,
      );
    } finally {
      clickSpy.mockRestore();
    }
  });
});

describe("exportFileName", () => {
  it("honors Content-Disposition and falls back", () => {
    expect(exportFileName('attachment; filename="audit-export-1.csv"')).toBe("audit-export-1.csv");
    expect(exportFileName(null)).toBe("audit-export.csv");
    expect(exportFileName("attachment")).toBe("audit-export.csv");
  });
});
