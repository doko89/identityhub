import { create } from "zustand";
import { ApiError } from "@/shared/api/client";
import { fetchSessionUser, type SessionUser } from "@/shared/api/session";

export type SessionStatus = "idle" | "loading" | "signed-in" | "signed-out" | "error";

interface SessionState {
  status: SessionStatus;
  user: SessionUser | null;
  // load fetches /api/auth/me once and shares the in-flight request, so
  // pages mounting together (layout + page) cause a single call.
  load: () => Promise<SessionUser | null>;
  // clear drops the cached session (used after sign-out).
  clear: () => void;
}

let inflight: Promise<SessionUser | null> | null = null;

export const useSessionStore = create<SessionState>()((set, get) => ({
  status: "idle",
  user: null,
  load: () => {
    const { status, user } = get();
    if (status === "signed-in" && user !== null) {
      return Promise.resolve(user);
    }
    if (inflight !== null) {
      return inflight;
    }
    set({ status: "loading" });
    inflight = fetchSessionUser()
      .then((u) => {
        set({ status: "signed-in", user: u });
        return u as SessionUser | null;
      })
      .catch((err: unknown) => {
        if (err instanceof ApiError && err.status === 401) {
          set({ status: "signed-out", user: null });
        } else {
          set({ status: "error", user: null });
        }
        return null;
      })
      .finally(() => {
        inflight = null;
      });
    return inflight;
  },
  clear: () => {
    set({ status: "signed-out", user: null });
  },
}));

// resetSessionForTests drops cached state between unit tests.
export function resetSessionForTests(): void {
  inflight = null;
  useSessionStore.setState({ status: "idle", user: null });
}
