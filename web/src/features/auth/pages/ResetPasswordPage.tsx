import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useBrand } from "@/features/branding/BrandProvider";
import { errorMessage } from "@/shared/api/client";
import {
  buttonStyle,
  cardStyle,
  inputStyle,
  labelStyle,
  linkStyle,
  noticeStyle,
  pageStyle,
} from "@/shared/ui/formStyles";

// Reset-password page (DESIGN §5.2): redeems the ?token= from the mailed
// link with a new password pair. A missing token is a dead link, shown
// without calling the API.
export function ResetPasswordPage() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token") ?? "";
  const [notice, setNotice] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);
  const brand = useBrand();
  const orgName = brand?.org_name !== undefined && brand.org_name !== "" ? brand.org_name : "IdentityHub";

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setNotice(null);
    try {
      const form = new FormData(e.currentTarget as HTMLFormElement);
      const res = await fetch("/api/auth/password/reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          token,
          new_password: form.get("new_password"),
          new_password_confirm: form.get("new_password_confirm"),
        }),
      });
      if (res.status === 429) {
        setNotice("Too many attempts. Wait a minute and try again.");
        return;
      }
      if (!res.ok) {
        setNotice(await errorMessage(res, "This link is invalid or expired. Request a new one."));
        return;
      }
      setDone(true);
    } catch {
      setNotice("Cannot reach the server. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main style={pageStyle}>
      <div style={cardStyle}>
        <h1 style={{ fontSize: 20, fontWeight: 600, margin: "0 0 4px" }}>{orgName}</h1>
        <p style={{ fontSize: 14, color: "var(--muted-foreground)", margin: "0 0 16px" }}>
          Choose a new password
        </p>
        {token === "" ? (
          <p role="alert" style={{ fontSize: 14 }}>
            This reset link is incomplete (missing token).{" "}
            <Link to="/forgot-password" style={linkStyle}>
              Request a new one
            </Link>
            .
          </p>
        ) : done ? (
          <p role="status" style={{ fontSize: 14 }}>
            Password has been reset.{" "}
            <Link to="/login" style={linkStyle}>
              Sign in
            </Link>
            .
          </p>
        ) : (
          <form onSubmit={(e) => void submit(e)}>
            <label style={labelStyle}>
              New password
              <input
                name="new_password"
                type="password"
                autoComplete="new-password"
                style={inputStyle}
                required
              />
            </label>
            <label style={{ ...labelStyle, marginBottom: 16 }}>
              Confirm new password
              <input
                name="new_password_confirm"
                type="password"
                autoComplete="new-password"
                style={inputStyle}
                required
              />
            </label>
            <button type="submit" style={buttonStyle} disabled={busy}>
              {busy ? "Resetting…" : "Reset password"}
            </button>
          </form>
        )}
        {notice !== null && (
          <p role="alert" style={noticeStyle}>
            {notice}
          </p>
        )}
        <p style={{ fontSize: 13, marginBottom: 0 }}>
          <Link to="/login" style={linkStyle}>
            Back to sign in
          </Link>
        </p>
      </div>
    </main>
  );
}
