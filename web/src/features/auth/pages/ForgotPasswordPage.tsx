import { useState } from "react";
import { Link } from "react-router-dom";
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

// Forgot-password page (DESIGN §5.2): one username/email field. The API
// always answers the same generic message whether the account exists or
// not, and the page repeats it verbatim so existence never leaks.
export function ForgotPasswordPage() {
  const [notice, setNotice] = useState<string | null>(null);
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);
  const brand = useBrand();
  const orgName = brand?.org_name !== undefined && brand.org_name !== "" ? brand.org_name : "IdentityHub";

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setNotice(null);
    try {
      const form = new FormData(e.currentTarget as HTMLFormElement);
      const res = await fetch("/api/auth/password/forgot", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ login: form.get("login") }),
      });
      if (res.status === 429) {
        setNotice("Too many attempts. Wait a minute and try again.");
        return;
      }
      if (!res.ok) {
        setNotice(await errorMessage(res, "Something went wrong. Try again."));
        return;
      }
      setSent(true);
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
          Reset your password
        </p>
        {sent ? (
          <p role="status" style={{ fontSize: 14 }}>
            If an account exists for that username or email, a reset link is on its way. Check your
            inbox, then{" "}
            <Link to="/login" style={linkStyle}>
              back to sign in
            </Link>
            .
          </p>
        ) : (
          <form onSubmit={(e) => void submit(e)}>
            <label style={labelStyle}>
              Username or email
              <input name="login" autoComplete="username" style={inputStyle} required />
            </label>
            <button type="submit" style={buttonStyle} disabled={busy}>
              {busy ? "Sending…" : "Send reset link"}
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
