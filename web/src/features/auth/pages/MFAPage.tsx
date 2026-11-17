import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

// Second login step (PRD §6.6): TOTP code or recovery code. Renders in
// three modes from the query string:
//   /mfa?next=...            verify a code to finish login
//   /mfa?setup=1&next=...    enroll first (admin first login), then continue
//   /mfa?stepup=1&next=...   step up a full session for an MFA-gated app
export function MFAPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const next = safeNext(searchParams.get("next"));
  const setup = searchParams.get("setup") === "1";
  const stepup = searchParams.get("stepup") === "1";

  if (setup) {
    return <EnrollFlow next={next} />;
  }
  return <VerifyForm next={next} stepup={stepup} onSetup={() => navigate(`/mfa?setup=1&next=${encodeURIComponent(next)}`)} />;
}

function VerifyForm({ next, stepup, onSetup }: { next: string; stepup: boolean; onSetup: () => void }) {
  const [code, setCode] = useState("");
  const [recovery, setRecovery] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setNotice(null);
    try {
      const res = await fetch("/api/auth/mfa/totp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(recovery ? { recovery_code: code } : { code }),
      });
      if (res.status === 401) {
        setNotice("That code did not match. Try again.");
        return;
      }
      if (res.status === 429) {
        setNotice("Too many attempts. Wait a minute and try again.");
        return;
      }
      if (!res.ok) {
        const data = (await res.json().catch(() => null)) as { error?: string } | null;
        setNotice(data?.error ?? "Verification failed. Try again.");
        return;
      }
      window.location.href = next;
    } catch {
      setNotice("Cannot reach the server. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main style={pageStyle}>
      <div style={cardStyle}>
        <h1 style={titleStyle}>Two-step verification</h1>
        <p style={subStyle}>
          {stepup ? "This app needs a second factor." : "Enter the code from your authenticator app."}
        </p>
        <form onSubmit={(e) => void submit(e)}>
          <label style={{ display: "block", fontSize: 14, marginBottom: 16 }}>
            {recovery ? "Recovery code" : "6-digit code"}
            <input
              name="code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              autoComplete="one-time-code"
              inputMode={recovery ? "text" : "numeric"}
              placeholder={recovery ? "XXXX-XXXX-XXXX-XXXX" : "123456"}
              style={inputStyle}
              required
            />
          </label>
          <button type="submit" style={buttonStyle} disabled={busy}>
            {busy ? "Verifying…" : "Verify"}
          </button>
        </form>
        <p style={{ fontSize: 13 }}>
          <button
            type="button"
            onClick={() => {
              setRecovery(!recovery);
              setCode("");
              setNotice(null);
            }}
            style={linkStyle}
          >
            {recovery ? "Use an authenticator code instead" : "Use a recovery code instead"}
          </button>
        </p>
        <p style={{ fontSize: 13 }}>
          <button type="button" onClick={onSetup} style={linkStyle}>
            Set up a new authenticator instead
          </button>
        </p>
        {notice !== null && (
          <p role="alert" style={{ fontSize: 13, color: "var(--muted-foreground)" }}>
            {notice}
          </p>
        )}
      </div>
    </main>
  );
}

type EnrollData = {
  otpauth_url: string;
  secret: string;
  qr_png: string;
};

function EnrollFlow({ next }: { next: string }) {
  const [data, setData] = useState<EnrollData | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [confirm, setConfirm] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [started, setStarted] = useState(false);

  async function start() {
    setBusy(true);
    setNotice(null);
    try {
      const res = await fetch("/api/account/mfa/enroll", { method: "POST" });
      const payload = (await res.json().catch(() => null)) as (EnrollData & { error?: string }) | null;
      if (!res.ok || payload === null) {
        setNotice(payload?.error ?? "Could not start enrollment. Try again.");
        return;
      }
      setData(payload);
      setStarted(true);
    } catch {
      setNotice("Cannot reach the server. Try again.");
    } finally {
      setBusy(false);
    }
  }

  async function finish(e: React.FormEvent) {
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
    } catch {
      setNotice("Cannot reach the server. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main style={pageStyle}>
      <div style={{ ...cardStyle, maxWidth: 460 }}>
        <h1 style={titleStyle}>Set up two-step verification</h1>
        {!started && (
          <>
            <p style={subStyle}>You will scan a QR code with your authenticator app.</p>
            <button type="button" style={buttonStyle} disabled={busy} onClick={() => void start()}>
              {busy ? "Starting…" : "Start setup"}
            </button>
          </>
        )}
        {started && codes === null && data !== null && (
          <>
            <p style={subStyle}>Scan this code, then enter the 6-digit code it shows.</p>
            <img
              src={data.qr_png}
              alt="TOTP enrollment QR code"
              width={200}
              height={200}
              style={{ display: "block", margin: "0 auto 12px", border: "1px solid var(--border)" }}
            />
            <p style={{ fontSize: 12, color: "var(--muted-foreground)", wordBreak: "break-all" }}>
              Can&apos;t scan? Enter this secret manually: <code>{data.secret}</code>
            </p>
            <form onSubmit={(e) => void finish(e)}>
              <label style={{ display: "block", fontSize: 14, marginBottom: 16 }}>
                6-digit code
                <input
                  name="code"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  autoComplete="one-time-code"
                  inputMode="numeric"
                  style={inputStyle}
                  required
                />
              </label>
              <button type="submit" style={buttonStyle} disabled={busy}>
                {busy ? "Confirming…" : "Confirm"}
              </button>
            </form>
          </>
        )}
        {codes !== null && (
          <>
            <p style={subStyle}>
              Save these recovery codes somewhere safe. Each works once, and they are never shown
              again.
            </p>
            <ul style={{ fontSize: 13, fontFamily: "monospace", paddingLeft: 20 }}>
              {codes.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
            <button
              type="button"
              style={buttonStyle}
              onClick={() => {
                window.location.href = next;
              }}
            >
              I saved my codes — continue
            </button>
          </>
        )}
        {notice !== null && (
          <p role="alert" style={{ fontSize: 13, color: "var(--muted-foreground)" }}>
            {notice}
          </p>
        )}
      </div>
    </main>
  );
}

function safeNext(next: string | null): string {
  if (next !== null && next.startsWith("/") && !next.startsWith("//")) {
    return next;
  }
  return "/";
}

const pageStyle: React.CSSProperties = {
  minHeight: "100vh",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  padding: 16,
  background: "radial-gradient(60rem 30rem at 50% -10%, var(--accent), transparent)",
};

const cardStyle: React.CSSProperties = {
  width: "100%",
  maxWidth: 380,
  border: "1px solid var(--border)",
  borderRadius: "var(--radius)",
  background: "var(--background)",
  padding: 24,
};

const titleStyle: React.CSSProperties = { fontSize: 20, fontWeight: 600, margin: "0 0 4px" };

const subStyle: React.CSSProperties = {
  fontSize: 14,
  color: "var(--muted-foreground)",
  margin: "0 0 16px",
};

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

const linkStyle: React.CSSProperties = {
  background: "none",
  border: "none",
  padding: 0,
  color: "var(--primary)",
  fontSize: 13,
  cursor: "pointer",
};
