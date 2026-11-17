import { useEffect, useState } from "react";
import { Link, NavLink, Outlet } from "react-router-dom";
import { ApiError } from "@/shared/api/client";
import { getMe } from "../api";
import "./AdminLayout.css";

// AdminLayout guards /admin/* (DESIGN §5.4): signed-out admins bounce to
// login, non-admins see a forbidden page, and the backend's 403 stays the
// real guard on every call the pages make.
export function AdminLayout() {
  const [state, setState] = useState<"loading" | "ok" | "forbidden">("loading");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const { user } = await getMe();
        if (!cancelled) setState(user.is_admin ? "ok" : "forbidden");
      } catch (err) {
        if (!cancelled) {
          if (err instanceof ApiError && err.status === 401) {
            window.location.href = `/login?next=${encodeURIComponent(window.location.pathname)}`;
            return;
          }
          setState("forbidden");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (state === "loading") {
    return (
      <main style={{ minHeight: "100vh", padding: "24px 16px", maxWidth: 1100, margin: "0 auto" }}>
        <p style={{ fontSize: 14, color: "var(--muted-foreground)" }}>Loading…</p>
      </main>
    );
  }

  if (state === "forbidden") {
    return (
      <main style={{ minHeight: "100vh", padding: "24px 16px", maxWidth: 640, margin: "0 auto" }}>
        <h1 style={{ fontSize: 20, fontWeight: 600 }}>Administrator access required</h1>
        <p style={{ fontSize: 14, color: "var(--muted-foreground)" }}>
          This console is only for administrators.{" "}
          <Link to="/" style={{ color: "var(--primary)" }}>
            Back to dashboard
          </Link>
          .
        </p>
      </main>
    );
  }

  return (
    <div className="ih-admin">
      <nav className="ih-admin-nav" aria-label="Admin">
        <div style={{ fontSize: 15, fontWeight: 700, padding: "8px 12px" }}>Admin console</div>
        {links.map(([to, label]) => (
          <NavLink key={to} to={to} className={({ isActive }) => (isActive ? "ih-active" : "")}>
            {label}
          </NavLink>
        ))}
        <Link to="/">← Back to dashboard</Link>
      </nav>
      <main className="ih-admin-main">
        <Outlet />
      </main>
    </div>
  );
}

const links: Array<[string, string]> = [
  ["/admin/users", "Users"],
  ["/admin/groups", "Groups"],
  ["/admin/apps", "Applications"],
  ["/admin/providers", "Providers"],
  ["/admin/branding", "Branding"],
  ["/admin/audit", "Audit log"],
];
