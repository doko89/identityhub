import { ApiError } from "@/shared/api/client";

// SessionUser mirrors the backend's userJSON (handlers.go): the signed-in
// user's profile plus group names and the derived admin flag.
export interface SessionUser {
  id: string;
  username: string;
  email: string;
  display_name: string;
  source: string;
  is_active: boolean;
  avatar_url: string;
  groups: string[];
  is_admin: boolean;
}

// fetchSessionUser calls GET /api/auth/me. Failures throw ApiError with
// the backend's user-facing message, like the admin client.
export async function fetchSessionUser(): Promise<SessionUser> {
  const res = await fetch("/api/auth/me");
  if (!res.ok) {
    const data = (await res.json().catch(() => null)) as {
      error?: string;
      mfa_required?: boolean;
    } | null;
    throw new ApiError(
      res.status,
      data?.error ?? `Request failed (${res.status})`,
      data?.mfa_required === true,
    );
  }
  const data = (await res.json()) as { user: SessionUser };
  return data.user;
}

// signOut ends the server session; the caller navigates afterwards.
export async function signOut(): Promise<void> {
  await fetch("/api/auth/logout", { method: "POST" }).catch(() => null);
}
