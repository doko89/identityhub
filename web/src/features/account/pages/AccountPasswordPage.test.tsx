import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { resetSessionForTests } from "@/shared/stores/session";
import { AccountPasswordPage } from "./AccountPasswordPage";

afterEach(() => {
  cleanup();
  resetSessionForTests();
  vi.unstubAllGlobals();
});

const localUser = {
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

// stubApi answers the session + MFA-status loads and records the change
// request body for assertions.
function stubApi(opts: {
  user?: unknown;
  hasTOTP?: boolean;
  change?: { status: number; body: unknown };
}): { bodies: unknown[] } {
  const bodies: unknown[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const path = String(url);
      if (path === "/api/auth/me") {
        return Response.json({ user: opts.user ?? localUser });
      }
      if (path === "/api/account/mfa/status") {
        return Response.json({ has_totp: opts.hasTOTP ?? false, remaining_recovery_codes: 0 });
      }
      if (path === "/api/account/password/change") {
        expect(init?.method).toBe("POST");
        bodies.push(JSON.parse(String(init?.body)) as unknown);
        const change = opts.change ?? { status: 200, body: { sessions_revoked: 2 } };
        return Response.json(change.body, { status: change.status });
      }
      throw new Error(`unexpected fetch ${path}`);
    }),
  );
  return { bodies };
}

function renderPage() {
  return render(
    <MemoryRouter>
      <AccountPasswordPage />
    </MemoryRouter>,
  );
}

function fillPasswordForm(container: HTMLElement, current: string, next: string, confirm: string) {
  const currentInput = container.querySelector('input[name="current_password"]') as HTMLInputElement;
  const nextInput = container.querySelector('input[name="new_password"]') as HTMLInputElement;
  const confirmInput = container.querySelector(
    'input[name="new_password_confirm"]',
  ) as HTMLInputElement;
  fireEvent.change(currentInput, { target: { value: current } });
  fireEvent.change(nextInput, { target: { value: next } });
  fireEvent.change(confirmInput, { target: { value: confirm } });
}

describe("AccountPasswordPage", () => {
  it("changes the password and reports revoked sessions", async () => {
    const { bodies } = stubApi({});
    const { container, getByRole, getByText } = renderPage();
    await waitFor(() =>
      expect(container.querySelector('input[name="current_password"]')).not.toBeNull(),
    );
    expect(container.querySelector('input[name="totp_code"]')).toBeNull();
    fillPasswordForm(container, "old-password-000", "new-password-111", "new-password-111");
    fireEvent.click(getByRole("button", { name: "Change password" }));
    await waitFor(() => expect(getByText("Password changed")).toBeDefined());
    expect(getByText("Signed out 2 other sessions.")).toBeDefined();
    expect(bodies).toEqual([
      {
        current_password: "old-password-000",
        new_password: "new-password-111",
        new_password_confirm: "new-password-111",
      },
    ]);
  });

  it("sends the TOTP re-auth code when the user has MFA", async () => {
    const { bodies } = stubApi({ hasTOTP: true });
    const { container, getByRole, getByText } = renderPage();
    await waitFor(() => expect(container.querySelector('input[name="totp_code"]')).not.toBeNull());
    fillPasswordForm(container, "old-password-000", "new-password-111", "new-password-111");
    const totp = container.querySelector('input[name="totp_code"]') as HTMLInputElement;
    fireEvent.change(totp, { target: { value: "123456" } });
    fireEvent.click(getByRole("button", { name: "Change password" }));
    await waitFor(() => expect(getByText("Password changed")).toBeDefined());
    expect(bodies).toHaveLength(1);
    expect(bodies[0]).toMatchObject({ totp_code: "123456" });
  });

  it("shows the backend message when the current password is wrong", async () => {
    stubApi({ change: { status: 401, body: { error: "current password is incorrect" } } });
    const { container, getByRole, getByText } = renderPage();
    await waitFor(() =>
      expect(container.querySelector('input[name="current_password"]')).not.toBeNull(),
    );
    fillPasswordForm(container, "wrong-password-0", "new-password-111", "new-password-111");
    fireEvent.click(getByRole("button", { name: "Change password" }));
    await waitFor(() => expect(getByText("current password is incorrect")).toBeDefined());
  });

  it("shows the re-auth prompt when the backend demands a fresh factor", async () => {
    stubApi({
      hasTOTP: true,
      change: {
        status: 403,
        body: {
          error: "recent second-factor verification is required to change the password",
          mfa_required: true,
        },
      },
    });
    const { container, getByRole, getByText } = renderPage();
    await waitFor(() => expect(container.querySelector('input[name="totp_code"]')).not.toBeNull());
    fillPasswordForm(container, "old-password-000", "new-password-111", "new-password-111");
    fireEvent.click(getByRole("button", { name: "Change password" }));
    await waitFor(() =>
      expect(
        getByText("recent second-factor verification is required to change the password"),
      ).toBeDefined(),
    );
  });

  it("tells LDAP users the directory owns their password", async () => {
    stubApi({ user: { ...localUser, source: "ldap" } });
    const { container, getByText } = renderPage();
    await waitFor(() => expect(getByText("Managed by your directory")).toBeDefined());
    expect(container.querySelector('input[name="current_password"]')).toBeNull();
  });
});
