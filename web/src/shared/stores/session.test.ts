import { afterEach, describe, expect, it, vi } from "vitest";
import { resetSessionForTests, useSessionStore } from "./session";

afterEach(() => {
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

describe("useSessionStore", () => {
  it("loads the user once and caches it", async () => {
    const fetchMock = vi.fn(async () => Response.json({ user }));
    vi.stubGlobal("fetch", fetchMock);
    const { load } = useSessionStore.getState();
    await expect(load()).resolves.toMatchObject({ username: "alice" });
    await expect(load()).resolves.toMatchObject({ username: "alice" });
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(useSessionStore.getState().status).toBe("signed-in");
  });

  it("shares one request between concurrent callers", async () => {
    const fetchMock = vi.fn(async () => Response.json({ user }));
    vi.stubGlobal("fetch", fetchMock);
    const { load } = useSessionStore.getState();
    const [a, b] = await Promise.all([load(), load()]);
    expect(a?.username).toBe("alice");
    expect(b?.username).toBe("alice");
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("marks 401 as signed-out", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({ error: "no" }, { status: 401 })));
    const { load } = useSessionStore.getState();
    await expect(load()).resolves.toBeNull();
    expect(useSessionStore.getState().status).toBe("signed-out");
  });

  it("marks network failure as error and retries on next load", async () => {
    const fetchMock = vi.fn<() => Promise<Response>>(async () => {
      throw new Error("down");
    });
    vi.stubGlobal("fetch", fetchMock);
    const { load } = useSessionStore.getState();
    await expect(load()).resolves.toBeNull();
    expect(useSessionStore.getState().status).toBe("error");
    fetchMock.mockImplementation(async () => Response.json({ user }));
    await expect(load()).resolves.toMatchObject({ username: "alice" });
  });

  it("clear drops the cached user", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({ user })));
    const { load, clear } = useSessionStore.getState();
    await load();
    clear();
    expect(useSessionStore.getState().user).toBeNull();
    expect(useSessionStore.getState().status).toBe("signed-out");
  });

  it("setUser replaces the cached user without fetching", async () => {
    const fetchMock = vi.fn(async () => Response.json({ user }));
    vi.stubGlobal("fetch", fetchMock);
    const { load, setUser } = useSessionStore.getState();
    setUser({ ...user, avatar_url: "/uploads/avatar/9.webp" });
    expect(useSessionStore.getState().user).toMatchObject({ avatar_url: "/uploads/avatar/9.webp" });
    expect(useSessionStore.getState().status).toBe("signed-in");
    await expect(load()).resolves.toMatchObject({ avatar_url: "/uploads/avatar/9.webp" });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
