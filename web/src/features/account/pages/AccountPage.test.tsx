import { cleanup, fireEvent, render, waitFor } from "@testing-library/react";
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

// Radix AvatarImage only renders <img> once its programmatic Image
// reports loaded; jsdom images never load, so complete them by hand.
function completeAvatarImages(): void {
  vi.stubGlobal(
    "Image",
    class {
      complete = true;
      naturalWidth = 100;
      crossOrigin: string | null = null;
      referrerPolicy = "";
      src = "";
      addEventListener(): void {}
      removeEventListener(): void {}
    },
  );
}

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
    completeAvatarImages();
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

  it("attaches a dropped image as the new avatar", async () => {
    completeAvatarImages();
    const bodies: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
        if (String(url) === "/api/uploads" && init?.method === "POST") {
          return Response.json(
            { id: "9", url: "/uploads/avatar/9.webp", width: 100, height: 100, byte_size: 42 },
            { status: 201 },
          );
        }
        if (String(url) === "/api/account/avatar") {
          bodies.push(String(init?.body));
          return Response.json({ user: { ...user, avatar_url: "/uploads/avatar/9.webp" } });
        }
        return Response.json({ user });
      }),
    );
    const { container, getByText } = render(
      <MemoryRouter>
        <AccountPage />
      </MemoryRouter>,
    );
    await waitFor(() => expect(getByText("alice · alice@example.com")).toBeDefined());
    const zone = container.querySelector('[role="button"]') as HTMLElement;
    fireEvent.drop(zone, {
      dataTransfer: { files: [new File([new Uint8Array(10)], "me.png", { type: "image/png" })] },
    });
    await waitFor(() =>
      expect(container.querySelector('img[src="/uploads/avatar/9.webp"]')).not.toBeNull(),
    );
    expect(bodies).toEqual([JSON.stringify({ avatar_url: "/uploads/avatar/9.webp" })]);
  });
});
