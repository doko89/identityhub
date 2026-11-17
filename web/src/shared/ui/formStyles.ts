import type { CSSProperties } from "react";

// Shared form styles for auth + admin pages: the same centered-card look
// as LoginPage (DESIGN §5.1/§5.2), driven by the shadcn CSS variables in
// index.css so branding overrides apply everywhere.
export const pageStyle: CSSProperties = {
  minHeight: "100vh",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  padding: 16,
  background: "radial-gradient(60rem 30rem at 50% -10%, var(--accent), transparent)",
};

export const cardStyle: CSSProperties = {
  width: "100%",
  maxWidth: 380,
  border: "1px solid var(--border)",
  borderRadius: "var(--radius)",
  background: "var(--background)",
  padding: 24,
};

export const inputStyle: CSSProperties = {
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

export const buttonStyle: CSSProperties = {
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

export const secondaryStyle: CSSProperties = {
  width: "100%",
  padding: "10px 12px",
  border: "1px solid var(--border)",
  borderRadius: "calc(var(--radius) - 2px)",
  background: "transparent",
  color: "var(--foreground)",
  fontSize: 14,
  fontWeight: 600,
  cursor: "pointer",
};

export const linkStyle: CSSProperties = {
  color: "var(--primary)",
  fontSize: 13,
};

export const noticeStyle: CSSProperties = {
  fontSize: 13,
  color: "var(--muted-foreground)",
};

export const labelStyle: CSSProperties = {
  display: "block",
  fontSize: 14,
  marginBottom: 12,
};
