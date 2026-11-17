import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ForgotPasswordPage } from "./ForgotPasswordPage";
import { ResetPasswordPage } from "./ResetPasswordPage";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("ForgotPasswordPage", () => {
  it("posts the login and shows the generic message", async () => {
    const fetchMock = vi.fn(async () =>
      Response.json({ message: "If an account exists for that username or email, a reset link is on its way." }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const { container, getByRole, getByText } = render(
      <MemoryRouter>
        <ForgotPasswordPage />
      </MemoryRouter>,
    );
    const input = container.querySelector('input[name="login"]') as HTMLInputElement;
    fireEvent.change(input, { target: { value: "alice" } });
    fireEvent.click(getByRole("button", { name: "Send reset link" }));
    await waitFor(() => expect(getByText(/a reset link is on its way/)).toBeDefined());
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/auth/password/forgot",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ login: "alice" }),
      }),
    );
  });

  it("explains rate limiting without leaking existence", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 429 })));
    const { container, getByRole, getByText } = render(
      <MemoryRouter>
        <ForgotPasswordPage />
      </MemoryRouter>,
    );
    const input = container.querySelector('input[name="login"]') as HTMLInputElement;
    fireEvent.change(input, { target: { value: "alice" } });
    fireEvent.click(getByRole("button", { name: "Send reset link" }));
    await waitFor(() =>
      expect(getByText("Too many attempts. Wait a minute and try again.")).toBeDefined(),
    );
  });

  it("shows a notice when the server is unreachable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("down");
      }),
    );
    const { container, getByRole, getByText } = render(
      <MemoryRouter>
        <ForgotPasswordPage />
      </MemoryRouter>,
    );
    const input = container.querySelector('input[name="login"]') as HTMLInputElement;
    fireEvent.change(input, { target: { value: "alice" } });
    fireEvent.click(getByRole("button", { name: "Send reset link" }));
    await waitFor(() => expect(getByText("Cannot reach the server. Try again.")).toBeDefined());
  });
});

describe("ResetPasswordPage", () => {
  it("asks for a new link when the token is missing", () => {
    const { getByText } = render(
      <MemoryRouter initialEntries={["/reset-password"]}>
        <ResetPasswordPage />
      </MemoryRouter>,
    );
    expect(getByText(/missing token/)).toBeDefined();
  });

  it("redeems the token and links back to sign in", async () => {
    const fetchMock = vi.fn(async () =>
      Response.json({ message: "Password has been reset. You can now sign in." }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const { container, getByRole } = render(
      <MemoryRouter initialEntries={["/reset-password?token=tok123"]}>
        <ResetPasswordPage />
      </MemoryRouter>,
    );
    const pw = container.querySelector('input[name="new_password"]') as HTMLInputElement;
    const pw2 = container.querySelector('input[name="new_password_confirm"]') as HTMLInputElement;
    fireEvent.change(pw, { target: { value: "new-secret-1" } });
    fireEvent.change(pw2, { target: { value: "new-secret-1" } });
    fireEvent.click(getByRole("button", { name: "Reset password" }));
    await waitFor(() => expect(getByRole("status")).toBeDefined());
    expect(getByRole("status").textContent).toContain("Password has been reset.");
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/auth/password/reset",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({
          token: "tok123",
          new_password: "new-secret-1",
          new_password_confirm: "new-secret-1",
        }),
      }),
    );
  });

  it("surfaces an expired-token error from the API", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ error: "invalid or expired token" }, { status: 400 })),
    );
    const { container, getByRole, getByText } = render(
      <MemoryRouter initialEntries={["/reset-password?token=stale"]}>
        <ResetPasswordPage />
      </MemoryRouter>,
    );
    const pw = container.querySelector('input[name="new_password"]') as HTMLInputElement;
    const pw2 = container.querySelector('input[name="new_password_confirm"]') as HTMLInputElement;
    fireEvent.change(pw, { target: { value: "new-secret-1" } });
    fireEvent.change(pw2, { target: { value: "new-secret-1" } });
    fireEvent.click(getByRole("button", { name: "Reset password" }));
    await waitFor(() => expect(getByText("invalid or expired token")).toBeDefined());
  });
});
