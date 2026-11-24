import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ConsentPage } from "./ConsentPage";

const realLocation = window.location;

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  Object.defineProperty(window, "location", {
    value: realLocation,
    writable: true,
    configurable: true,
  });
});

const info = {
  challenge: "abc",
  client_id: "web",
  client_name: "Wiki",
  redirect_uri: "https://wiki.example.com/callback",
  scopes: ["openid", "profile"],
};

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/consent?challenge=abc"]}>
      <ConsentPage />
    </MemoryRouter>,
  );
}

describe("ConsentPage", () => {
  it("shows a redirecting state and then navigates to the client", async () => {
    let href = "http://localhost/consent?challenge=abc";
    Object.defineProperty(window, "location", {
      value: {
        get href() {
          return href;
        },
        set href(v: string) {
          href = v;
        },
      },
      writable: true,
      configurable: true,
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
        if (init?.method === "POST") {
          return Response.json({ redirect_to: "https://wiki.example.com/callback?code=xyz" });
        }
        return Response.json(info);
      }),
    );
    const { getByRole, getByText } = renderPage();
    await waitFor(() => expect(getByText("Wiki")).toBeDefined());
    fireEvent.click(getByRole("button", { name: "Allow" }));
    await waitFor(() =>
      expect(getByText("Redirecting you back to wiki.example.com…")).toBeDefined(),
    );
    await waitFor(() => expect(href).toBe("https://wiki.example.com/callback?code=xyz"), {
      timeout: 3000,
    });
  });

  it("renders a form_post page into the document", async () => {
    const formHtml = '<html><body><form method="post" action="https://wiki.example.com/cb"></form></body></html>';
    const openSpy = vi.spyOn(document, "open").mockImplementation(() => window);
    const writeSpy = vi.spyOn(document, "write").mockImplementation(() => undefined);
    const closeSpy = vi.spyOn(document, "close").mockImplementation(() => undefined);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
        if (init?.method === "POST") {
          return Response.json({ form_post: formHtml });
        }
        return Response.json(info);
      }),
    );
    const { getByRole, getByText } = renderPage();
    await waitFor(() => expect(getByText("Wiki")).toBeDefined());
    fireEvent.click(getByRole("button", { name: "Allow" }));
    await waitFor(() =>
      expect(getByText("Redirecting you back to wiki.example.com…")).toBeDefined(),
    );
    await waitFor(() => expect(writeSpy).toHaveBeenCalledWith(formHtml), { timeout: 3000 });
    expect(openSpy).toHaveBeenCalled();
    expect(closeSpy).toHaveBeenCalled();
  });

  it("surfaces decision failures without navigating", async () => {
    const seen: string[] = [];
    Object.defineProperty(window, "location", {
      value: {
        get href() {
          return seen.join(",");
        },
        set href(v: string) {
          seen.push(v);
        },
      },
      writable: true,
      configurable: true,
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
        if (init?.method === "POST") {
          return Response.json({ error: "consent request expired" }, { status: 410 });
        }
        return Response.json(info);
      }),
    );
    const { getByRole, getByText, queryByText } = renderPage();
    await waitFor(() => expect(getByText("Wiki")).toBeDefined());
    fireEvent.click(getByRole("button", { name: "Allow" }));
    await waitFor(() => expect(getByText("consent request expired")).toBeDefined());
    expect(queryByText(/Redirecting you back/)).toBeNull();
    expect(seen).toEqual([]);
  });
});
