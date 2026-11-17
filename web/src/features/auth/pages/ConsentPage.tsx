import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";

type ConsentInfo = {
  challenge: string;
  client_id: string;
  client_name: string;
  redirect_uri: string;
  scopes: string[];
};

const scopeLabels: Record<string, string> = {
  openid: "Verify your identity",
  profile: "Your username and display name",
  email: "Your email address",
  groups: "Your group memberships",
  offline_access: "Stay signed in (refresh access while you are away)",
  offline: "Stay signed in (refresh access while you are away)",
};

// Consent page (PRD §6.3): shown before IdentityHub shares attributes
// with an app. Allow/Deny posts the decision; the API answers the client
// redirect target, which may be cross-origin, so the page navigates the
// whole browser there.
export function ConsentPage() {
  const [searchParams] = useSearchParams();
  const challenge = searchParams.get("challenge") ?? "";
  const [info, setInfo] = useState<ConsentInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (challenge === "") {
      setError("Missing consent challenge. Restart sign-in from the app.");
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(`/api/oidc/consent?challenge=${encodeURIComponent(challenge)}`);
        if (!res.ok) {
          const data = (await res.json().catch(() => null)) as { error?: string } | null;
          if (!cancelled) setError(data?.error ?? "This consent request expired. Restart sign-in from the app.");
          return;
        }
        const data = (await res.json()) as ConsentInfo;
        if (!cancelled) setInfo(data);
      } catch {
        if (!cancelled) setError("Cannot reach the server. Try again.");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [challenge]);

  async function decide(grant: boolean) {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/oidc/consent", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challenge, grant }),
      });
      const data = (await res.json().catch(() => null)) as {
        redirect_to?: string;
        error?: string;
      } | null;
      if (!res.ok || !data?.redirect_to) {
        setError(data?.error ?? "Authorization failed. Restart sign-in from the app.");
        return;
      }
      window.location.href = data.redirect_to;
    } catch {
      setError("Cannot reach the server. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 16,
        background: "radial-gradient(60rem 30rem at 50% -10%, var(--accent), transparent)",
      }}
    >
      <div
        style={{
          width: "100%",
          maxWidth: 440,
          border: "1px solid var(--border)",
          borderRadius: "var(--radius)",
          background: "var(--background)",
          padding: 24,
        }}
      >
        <h1 style={{ fontSize: 20, fontWeight: 600, margin: "0 0 4px" }}>Authorize app</h1>
        {info === null && error === null && (
          <p style={{ fontSize: 14, color: "var(--muted-foreground)" }}>Loading request…</p>
        )}
        {error !== null && (
          <p role="alert" style={{ fontSize: 14, color: "var(--muted-foreground)" }}>
            {error}
          </p>
        )}
        {info !== null && (
          <>
            <p style={{ fontSize: 14, color: "var(--muted-foreground)", margin: "0 0 12px" }}>
              <strong style={{ color: "var(--foreground)" }}>{info.client_name}</strong> wants to
              sign you in and access:
            </p>
            <ul style={{ fontSize: 14, paddingLeft: 20, margin: "0 0 16px" }}>
              {info.scopes.map((scope) => (
                <li key={scope} style={{ marginBottom: 4 }}>
                  {scopeLabels[scope] ?? scope}{" "}
                  <span style={{ color: "var(--muted-foreground)", fontSize: 12 }}>
                    ({scope})
                  </span>
                </li>
              ))}
            </ul>
            <p style={{ fontSize: 12, color: "var(--muted-foreground)", margin: "0 0 16px" }}>
              You will return to {redirectHost(info.redirect_uri)} after deciding.
            </p>
            <div style={{ display: "flex", gap: 8 }}>
              <button type="button" style={denyStyle} disabled={busy} onClick={() => void decide(false)}>
                Deny
              </button>
              <button type="button" style={allowStyle} disabled={busy} onClick={() => void decide(true)}>
                {busy ? "Working…" : "Allow"}
              </button>
            </div>
          </>
        )}
      </div>
    </main>
  );
}

function redirectHost(redirectUri: string): string {
  try {
    return new URL(redirectUri).host;
  } catch {
    return redirectUri;
  }
}

const allowStyle: React.CSSProperties = {
  flex: 1,
  padding: "10px 12px",
  border: "none",
  borderRadius: "calc(var(--radius) - 2px)",
  background: "var(--primary)",
  color: "var(--primary-foreground)",
  fontSize: 14,
  fontWeight: 600,
  cursor: "pointer",
};

const denyStyle: React.CSSProperties = {
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
