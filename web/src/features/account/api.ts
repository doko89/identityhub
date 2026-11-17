import { ApiError } from "@/shared/api/client";

// Typed client for the self-service account API (TECH_SPEC §6.1).
// Failures throw ApiError carrying the HTTP status and the user-facing
// {error} message, like the admin client.

async function toApiError(res: Response): Promise<ApiError> {
  const data = (await res.json().catch(() => null)) as {
    error?: string;
    mfa_required?: boolean;
  } | null;
  return new ApiError(
    res.status,
    data?.error ?? `Request failed (${res.status})`,
    data?.mfa_required === true,
  );
}

// ---------- password ----------

export interface ChangePasswordInput {
  current_password: string;
  new_password: string;
  new_password_confirm: string;
  // totp_code is the re-auth factor, required when the user has MFA and
  // the session's last verification is older than 10 minutes.
  totp_code?: string;
}

// changePassword changes the session user's own password (PRD §6.10).
// The backend answers how many other sessions it revoked.
export async function changePassword(input: ChangePasswordInput): Promise<{ sessions_revoked: number }> {
  const res = await fetch("/api/account/password/change", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    throw await toApiError(res);
  }
  return (await res.json()) as { sessions_revoked: number };
}

// ---------- MFA status ----------

export interface MFAStatus {
  has_totp: boolean;
  remaining_recovery_codes: number;
}

export async function getMFAStatus(): Promise<MFAStatus> {
  const res = await fetch("/api/account/mfa/status");
  if (!res.ok) {
    throw await toApiError(res);
  }
  return (await res.json()) as MFAStatus;
}
