import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { resetSessionForTests } from "@/shared/stores/session";
import { AccountAPIKeysPage } from "./AccountAPIKeysPage";

afterEach(() => {
  cleanup();
  resetSessionForTests();
  vi.unstubAllGlobals();
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

const key = {
  id: "22222222-2222-2222-2222-222222222222",
  name: "laptop",
  prefix: "ih_abc123",
  created_with_mfa: false,
  expires_at: null,
  revoked_at: null,
  last_used_at: null,
  created_at: "2026-11-17T10:00:00Z",
};

function stubFetch(impl: (url: string, init?: RequestInit) => Response) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string | URL | Request, init?: RequestInit) =>
      impl(url.toString(), init),
    ),
  );
}

describe("AccountAPIKeysPage", () => {
  it("lists keys and creates one, showing the secret once", async () => {
    const issued = { ...key, id: "33333333-3333-3333-3333-333333333333", name: "cli" };
    stubFetch((url, init) => {
      if (url.endsWith("/api/auth/me")) return Response.json({ user });
      if (url.endsWith("/api/account/mfa/status"))
        return Response.json({ has_totp: false, remaining_recovery_codes: 0 });
      if (url.endsWith("/api/account/api-keys") && init?.method === "POST")
        return Response.json({ api_key: issued, secret: "ih_secret-shown-once" }, { status: 201 });
      if (url.endsWith("/api/account/api-keys")) return Response.json({ api_keys: [key] });
      throw new Error(`unexpected fetch ${init?.method ?? "GET"} ${url}`);
    });

    const { getByText, getByLabelText, getByRole } = render(
      <MemoryRouter>
        <AccountAPIKeysPage />
      </MemoryRouter>,
    );

    await waitFor(() => expect(getByText("laptop")).toBeDefined());
    expect(getByText("ih_abc123… · created 11/17/2026")).toBeDefined();

    fireEvent.change(getByLabelText("New key name"), { target: { value: "cli" } });
    fireEvent.click(getByRole("button", { name: "Create API key" }));

    await waitFor(() => expect(getByText("Copy your secret now")).toBeDefined());
    expect(getByText("ih_secret-shown-once")).toBeDefined();
    expect(getByText("cli")).toBeDefined();
  });

  it("revokes after a confirm click", async () => {
    stubFetch((url) => {
      if (url.endsWith("/api/auth/me")) return Response.json({ user });
      if (url.endsWith("/api/account/mfa/status"))
        return Response.json({ has_totp: false, remaining_recovery_codes: 0 });
      if (url.endsWith("/api/account/api-keys")) return Response.json({ api_keys: [key] });
      if (url.endsWith(`/api/account/api-keys/${key.id}`)) return new Response(null, { status: 204 });
      throw new Error(`unexpected fetch ${url}`);
    });

    const { getByText, getByRole } = render(
      <MemoryRouter>
        <AccountAPIKeysPage />
      </MemoryRouter>,
    );

    await waitFor(() => expect(getByText("laptop")).toBeDefined());
    fireEvent.click(getByRole("button", { name: "Revoke" }));
    expect(getByRole("button", { name: "Confirm" })).toBeDefined();
    fireEvent.click(getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(getByText("revoked")).toBeDefined());
  });

  it("asks for a TOTP code when the user has MFA", async () => {
    stubFetch((url) => {
      if (url.endsWith("/api/auth/me")) return Response.json({ user });
      if (url.endsWith("/api/account/mfa/status"))
        return Response.json({ has_totp: true, remaining_recovery_codes: 8 });
      if (url.endsWith("/api/account/api-keys")) return Response.json({ api_keys: [] });
      throw new Error(`unexpected fetch ${url}`);
    });

    const { getByText, getByLabelText } = render(
      <MemoryRouter>
        <AccountAPIKeysPage />
      </MemoryRouter>,
    );

    await waitFor(() => expect(getByText("No API keys yet. Create one above to use the CLI.")).toBeDefined());
    expect(getByLabelText("Authenticator code")).toBeDefined();
  });
});
