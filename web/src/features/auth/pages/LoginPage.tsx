import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useBrand } from "@/features/branding/BrandProvider";

// Login page (DESIGN §5.1 layout). Posts to POST /api/auth/login; on
// success the browser continues to ?next= (the OIDC authorize request)
// when it is a safe relative target, else to the dashboard.
export function LoginPage() {
  const [searchParams] = useSearchParams();
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const brand = useBrand();
  const orgName = brand?.org_name !== undefined && brand.org_name !== "" ? brand.org_name : "IdentityHub";
  const background =
    brand?.login_background_url !== undefined && brand.login_background_url !== ""
      ? { backgroundImage: `url("${brand.login_background_url}")`, backgroundSize: "cover" }
      : { background: "radial-gradient(60rem 30rem at 50% -10%, var(--accent), transparent)" };

  return (
    <main
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 16,
        ...background,
      }}
    >
      <div
        style={{
          width: "100%",
          maxWidth: 380,
          border: "1px solid var(--border)",
          borderRadius: "var(--radius)",
          background: "var(--background)",
          padding: 24,
        }}
      >
        {brand?.logo_url !== undefined && brand.logo_url !== "" && (
          <img src={brand.logo_url} alt="" style={{ height: 28, marginBottom: 8 }} />
        )}
        <h1 style={{ fontSize: 20, fontWeight: 600, margin: "0 0 4px" }}>{orgName}</h1>
        <p style={{ fontSize: 14, color: "var(--muted-foreground)", margin: "0 0 16px" }}>
          Sign in
        </p>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setNotice(null);
            try {
              const form = new FormData(e.currentTarget);
              const res = await fetch("/api/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                  username: form.get("username"),
                  password: form.get("password"),
                }),
              });
              if (!res.ok) {
                const data = (await res.json().catch(() => null)) as { error?: string } | null;
                setNotice(data?.error ?? "Sign-in failed. Try again.");
                return;
              }
              const data = (await res.json().catch(() => null)) as {
                mfa_required?: boolean;
                setup_required?: boolean;
              } | null;
              const next = safeNext(searchParams.get("next"));
              if (data?.mfa_required) {
                const setup = data.setup_required ? "setup=1&" : "";
                window.location.href = `/mfa?${setup}next=${encodeURIComponent(next)}`;
                return;
              }
              window.location.href = next;
            } catch {
              setNotice("Cannot reach the server. Try again.");
            } finally {
              setBusy(false);
            }
          }}
        >
          <label style={{ display: "block", fontSize: 14, marginBottom: 12 }}>
            Username
            <input
              name="username"
              autoComplete="username"
              style={inputStyle}
              required
            />
          </label>
          <label style={{ display: "block", fontSize: 14, marginBottom: 16 }}>
            Password
            <input
              name="password"
              type="password"
              autoComplete="current-password"
              style={inputStyle}
              required
            />
          </label>
          <button type="submit" style={buttonStyle} disabled={busy}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
        {notice !== null && (
          <p role="alert" style={{ fontSize: 13, color: "var(--muted-foreground)" }}>
            {notice}
          </p>
        )}
        <p style={{ fontSize: 12, color: "var(--muted-foreground)", marginBottom: 0 }}>
          © {orgName}
        </p>
      </div>
    </main>
  );
}

// safeNext accepts only relative return targets (open-redirect guard).
function safeNext(next: string | null): string {
  if (next !== null && next.startsWith("/") && !next.startsWith("//")) {
    return next;
  }
  return "/";
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
