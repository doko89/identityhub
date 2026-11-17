import { useState } from "react";

// M0 placeholder login page (DESIGN §5.1 layout). The form posts to
// POST /api/auth/login, which lands in M1 — until then it shows a notice.
export function LoginPage() {
  const [notice, setNotice] = useState<string | null>(null);

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
          maxWidth: 380,
          border: "1px solid var(--border)",
          borderRadius: "var(--radius)",
          background: "var(--background)",
          padding: 24,
        }}
      >
        <h1 style={{ fontSize: 20, fontWeight: 600, margin: "0 0 4px" }}>IdentityHub</h1>
        <p style={{ fontSize: 14, color: "var(--muted-foreground)", margin: "0 0 16px" }}>
          Sign in
        </p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setNotice("Login is not available yet — the M0 scaffold serves this page only.");
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
          <button type="submit" style={buttonStyle}>
            Sign in
          </button>
        </form>
        {notice !== null && (
          <p role="alert" style={{ fontSize: 13, color: "var(--muted-foreground)" }}>
            {notice}
          </p>
        )}
        <p style={{ fontSize: 12, color: "var(--muted-foreground)", marginBottom: 0 }}>
          © IdentityHub
        </p>
      </div>
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
