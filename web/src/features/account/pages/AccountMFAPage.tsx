import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

type Status = {
  has_totp: boolean;
  remaining_recovery_codes: number;
};

// Self-service factor management (TECH_SPEC §6.1): enroll with QR,
// regenerate recovery codes, or disable — factor changes always
// re-authenticate with the old factor first.
export function AccountMFAPage() {
  const [status, setStatus] = useState<Status | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [enroll, setEnroll] = useState<{ otpauth_url: string; secret: string; qr_png: string } | null>(null);
  const [confirm, setConfirm] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [factor, setFactor] = useState("");
  const [mode, setMode] = useState<"idle" | "disable" | "regenerate">("idle");
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      const res = await fetch("/api/account/mfa/status");
      if (res.status === 401) {
        window.location.href = "/login?next=/account/mfa";
        return;
      }
      if (!res.ok) {
        setNotice("Cannot load your MFA status. Try again.");
        return;
      }
      setStatus((await res.json()) as Status);
    } catch {
      setNotice("Cannot reach the server. Try again.");
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function startEnroll() {
    setBusy(true);
    setNotice(null);
    try {
      const res = await fetch("/api/account/mfa/enroll", { method: "POST" });
      const payload = (await res.json().catch(() => null)) as {
        otpauth_url?: string;
        secret?: string;
        qr_png?: string;
        error?: string;
      } | null;
      if (!res.ok || !payload?.qr_png || !payload.secret) {
        setNotice(payload?.error ?? "Could not start enrollment. Try again.");
        return;
      }
      setEnroll({ otpauth_url: payload.otpauth_url ?? "", secret: payload.secret, qr_png: payload.qr_png });
    } catch {
      setNotice("Cannot reach the server. Try again.");
    } finally {
      setBusy(false);
    }
  }

  async function finishEnroll(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setNotice(null);
    try {
      const res = await fetch("/api/account/mfa/enroll/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: confirm }),
      });
      const payload = (await res.json().catch(() => null)) as {
        recovery_codes?: string[];
        error?: string;
      } | null;
      if (!res.ok || !payload?.recovery_codes) {
        setNotice(payload?.error ?? "That code did not match. Try again.");
        return;
      }
      setCodes(payload.recovery_codes);
      setEnroll(null);
      setConfirm("");
      await load();
    } catch {
      setNotice("Cannot reach the server. Try again.");
    } finally {
      setBusy(false);
    }
  }

  async function submitFactor(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setNotice(null);
    try {
      const path =
        mode === "disable" ? "/api/account/mfa/disable" : "/api/account/mfa/recovery/regenerate";
      const res = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: factor }),
      });
      const payload = (await res.json().catch(() => null)) as {
        recovery_codes?: string[];
        error?: string;
      } | null;
      if (!res.ok) {
        setNotice(payload?.error ?? "That code did not match. Try again.");
        return;
      }
      if (payload?.recovery_codes) {
        setCodes(payload.recovery_codes);
      }
      setFactor("");
      setMode("idle");
      await load();
    } catch {
      setNotice("Cannot reach the server. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main style={{ minHeight: "100vh", padding: "24px 16px", maxWidth: 640, margin: "0 auto" }}>
      <p style={{ fontSize: 13 }}>
        <Link to="/" style={{ color: "var(--primary)" }}>
          ← Back to dashboard
        </Link>
      </p>
      <h1 style={{ fontSize: 22, fontWeight: 700, margin: "0 0 4px" }}>Two-step verification</h1>
      {status === null && notice === null && (
        <p style={{ fontSize: 14, color: "var(--muted-foreground)" }}>Loading…</p>
      )}
      {status !== null && !status.has_totp && codes === null && (
        <>
          <p style={{ fontSize: 14, color: "var(--muted-foreground)" }}>
            Two-step verification is off. Turn it on to protect your account with an authenticator
            app.
          </p>
          {enroll === null ? (
            <button type="button" style={buttonStyle} disabled={busy} onClick={() => void startEnroll()}>
              {busy ? "Starting…" : "Set up authenticator"}
            </button>
          ) : (
            <>
              <p style={{ fontSize: 14 }}>Scan this code, then enter the 6-digit code it shows.</p>
              <img
                src={enroll.qr_png}
                alt="TOTP enrollment QR code"
                width={200}
                height={200}
                style={{ display: "block", margin: "0 0 12px", border: "1px solid var(--border)" }}
              />
              <p style={{ fontSize: 12, color: "var(--muted-foreground)", wordBreak: "break-all" }}>
                Can&apos;t scan? Enter this secret manually: <code>{enroll.secret}</code>
              </p>
              <form onSubmit={(e) => void finishEnroll(e)}>
                <label style={{ display: "block", fontSize: 14, marginBottom: 16, maxWidth: 280 }}>
                  6-digit code
                  <input
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                    autoComplete="one-time-code"
                    inputMode="numeric"
                    style={inputStyle}
                    required
                  />
                </label>
                <div style={{ maxWidth: 280 }}>
                  <button type="submit" style={buttonStyle} disabled={busy}>
                    {busy ? "Confirming…" : "Confirm"}
                  </button>
                </div>
              </form>
            </>
          )}
        </>
      )}
      {status !== null && status.has_totp && (
        <>
          <p style={{ fontSize: 14, color: "var(--muted-foreground)" }}>
            Two-step verification is on. Unused recovery codes: {status.remaining_recovery_codes}.
          </p>
          {mode === "idle" ? (
            <div style={{ display: "flex", gap: 8, maxWidth: 460 }}>
              <button type="button" style={secondaryStyle} onClick={() => setMode("regenerate")}>
                New recovery codes
              </button>
              <button type="button" style={secondaryStyle} onClick={() => setMode("disable")}>
                Turn off
              </button>
            </div>
          ) : (
            <form onSubmit={(e) => void submitFactor(e)} style={{ maxWidth: 280 }}>
              <p style={{ fontSize: 14 }}>
                {mode === "disable"
                  ? "Enter a current code to turn two-step verification off."
                  : "Enter a current code to rotate your recovery codes."}
              </p>
              <label style={{ display: "block", fontSize: 14, marginBottom: 16 }}>
                Current code
                <input
                  value={factor}
                  onChange={(e) => setFactor(e.target.value)}
                  autoComplete="one-time-code"
                  style={inputStyle}
                  required
                />
              </label>
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  type="button"
                  style={secondaryStyle}
                  onClick={() => {
                    setMode("idle");
                    setFactor("");
                  }}
                >
                  Cancel
                </button>
                <button type="submit" style={buttonStyle} disabled={busy}>
                  {busy ? "Working…" : "Confirm"}
                </button>
              </div>
            </form>
          )}
        </>
      )}
      {codes !== null && (
        <section style={{ marginTop: 24 }}>
          <h2 style={{ fontSize: 16, fontWeight: 600 }}>Recovery codes</h2>
          <p style={{ fontSize: 14, color: "var(--muted-foreground)" }}>
            Save these somewhere safe. Each works once, and they are never shown again.
          </p>
          <ul style={{ fontSize: 13, fontFamily: "monospace" }}>
            {codes.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
          <button type="button" style={secondaryStyle} onClick={() => setCodes(null)}>
            I saved my codes
          </button>
        </section>
      )}
      {notice !== null && (
        <p role="alert" style={{ fontSize: 13, color: "var(--muted-foreground)" }}>
          {notice}
        </p>
      )}
    </main>
  );
}

const inputStyle: React.CSSProperties = {
  display: "block",
  width: "100%",
  boxSizing: "border-box",
  marginTop: 4,
  padding: "8px 12px",
  border: "1px solid var(--input)",
  borderRadius: "calc(var(--radius) - 2px)",
  background: "var(--background)",
  color: "var(--foreground)",
  fontSize: 14,
};

const buttonStyle: React.CSSProperties = {
  width: "100%",
  padding: "10px 12px",
  border: "none",
  borderRadius: "calc(var(--radius) - 2px)",
  background: "var(--primary)",
  color: "var(--primary-foreground)",
  fontSize: 14,
  fontWeight: 600,
  cursor: "pointer",
};

const secondaryStyle: React.CSSProperties = {
  flex: 1,
  padding: "10px 12px",
  border: "1px solid var(--border)",
  borderRadius: "calc(var(--radius) - 2px)",
  background: "transparent",
  color: "var(--foreground)",
  fontSize: 14,
  fontWeight: 600,
  cursor: "pointer",
};
