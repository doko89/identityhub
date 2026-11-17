import { cleanup, render, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { resetSessionForTests } from "@/shared/stores/session";
import { AccountPage } from "./AccountPage";

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

describe("AccountPage", () => {
  it("shows the profile, self-service links and the avatar uploader", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({ user })));
    const { container, getByRole, getByText } = render(
      <MemoryRouter>
        <AccountPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("alice · alice@example.com")).toBeDefined());
    expect(getByRole("link", { name: "Change password" }).getAttribute("href")).toBe(
      "/account/password",
    );
    expect(getByRole("link", { name: "Two-step verification" }).getAttribute("href")).toBe(
      "/account/mfa",
    );
    expect(container.querySelector("#avatar-upload")).not.toBeNull();
    expect(container.querySelector("img")).toBeNull();
  });

  it("shows the current avatar when one is set", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ user: { ...user, avatar_url: "/uploads/avatar/1.webp" } })),
    );
    const { container, getByText } = render(
      <MemoryRouter>
        <AccountPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("alice · alice@example.com")).toBeDefined());
    const img = container.querySelector('img[src="/uploads/avatar/1.webp"]');
    expect(img).not.toBeNull();
  });
});
