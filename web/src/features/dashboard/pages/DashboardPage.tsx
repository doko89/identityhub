import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

type AppEntry = {
  id: string;
  slug: string;
  name: string;
  description: string;
  icon_url: string;
  launch_url: string;
  group_label: string;
  provider_type: string;
  mfa_required: boolean;
};

type Me = {
  user: {
    username: string;
    display_name: string;
    is_admin: boolean;
  };
};

// User dashboard (PRD §6.7): the signed-in user's apps, grouped by the
// admin's display group. Clicking an app SSOs straight in while the
// session lasts; MFA-gated apps detour through step-up first.
export function DashboardPage() {
  const navigate = useNavigate();
  const [me, setMe] = useState<Me["user"] | null>(null);
  const [apps, setApps] = useState<AppEntry[] | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const meRes = await fetch("/api/auth/me");
        if (meRes.status === 401) {
          navigate("/login?next=/", { replace: true });
          return;
        }
        if (!meRes.ok) {
          if (!cancelled) setNotice("Cannot load your session. Try again.");
          return;
        }
        const meData = (await meRes.json()) as Me;
        const appsRes = await fetch("/api/my-apps");
        if (!appsRes.ok) {
          if (!cancelled) setNotice("Cannot load your apps. Try again.");
          return;
        }
        const appsData = (await appsRes.json()) as { apps: AppEntry[] };
        if (!cancelled) {
          setMe(meData.user);
          setApps(appsData.apps);
        }
      } catch {
        if (!cancelled) setNotice("Cannot reach the server. Try again.");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [navigate]);

  async function launch(app: AppEntry) {
    setNotice(null);
    try {
      const res = await fetch(`/api/apps/${encodeURIComponent(app.slug)}/launch`);
      const data = (await res.json().catch(() => null)) as {
        launch_url?: string;
        mfa_required?: boolean;
        error?: string;
      } | null;
      if (res.status === 403 && data?.mfa_required) {
        navigate("/mfa?stepup=1&next=/");
        return;
      }
      if (!res.ok || !data) {
        setNotice(data?.error ?? "Could not open this app.");
        return;
      }
      if (!data.launch_url) {
        setNotice(`${app.name} has no launch URL configured yet. Ask your administrator.`);
        return;
      }
      window.location.href = data.launch_url;
    } catch {
      setNotice("Cannot reach the server. Try again.");
    }
  }

  async function signOut() {
    await fetch("/api/auth/logout", { method: "POST" }).catch(() => null);
    window.location.href = "/login";
  }

  const groups = new Map<string, AppEntry[]>();
  for (const app of apps ?? []) {
    const label = app.group_label || "Apps";
    const list = groups.get(label) ?? [];
    list.push(app);
    groups.set(label, list);
  }

  return (
    <main style={{ minHeight: "100vh", padding: "24px 16px", maxWidth: 960, margin: "0 auto" }}>
      <header
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: 24,
        }}
      >
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, margin: 0 }}>IdentityHub</h1>
          {me !== null && (
            <p style={{ fontSize: 13, color: "var(--muted-foreground)", margin: "4px 0 0" }}>
              Signed in as {me.display_name || me.username}
              {me.is_admin ? " (admin)" : ""}
            </p>
          )}
        </div>
        <nav style={{ display: "flex", gap: 12, alignItems: "center", fontSize: 13 }}>
          {me?.is_admin === true && (
            <Link to="/admin" style={{ color: "var(--primary)" }}>
              Admin
            </Link>
          )}
          <Link to="/account" style={{ color: "var(--primary)" }}>
            Account
          </Link>
          <Link to="/account/mfa" style={{ color: "var(--primary)" }}>
            Two-step verification
          </Link>
          <Link to="/account/password" style={{ color: "var(--primary)" }}>
            Change password
          </Link>
          <button type="button" onClick={() => void signOut()} style={linkButtonStyle}>
            Sign out
          </button>
        </nav>
      </header>

      {notice !== null && (
        <p role="alert" style={{ fontSize: 14, color: "var(--muted-foreground)" }}>
          {notice}
        </p>
      )}
      {apps === null && notice === null && (
        <p style={{ fontSize: 14, color: "var(--muted-foreground)" }}>Loading your apps…</p>
      )}
      {apps !== null && apps.length === 0 && (
        <p style={{ fontSize: 14, color: "var(--muted-foreground)" }}>
          No apps yet. Ask your administrator to add you to one.
        </p>
      )}
      {[...groups.entries()].map(([label, list]) => (
        <section key={label} style={{ marginBottom: 24 }}>
          <h2 style={{ fontSize: 15, fontWeight: 600, margin: "0 0 12px" }}>{label}</h2>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))",
              gap: 12,
            }}
          >
            {list.map((app) => (
              <button
                key={app.id}
                type="button"
                onClick={() => void launch(app)}
                style={appCardStyle}
              >
                {app.icon_url ? (
                  <img
                    src={app.icon_url}
                    alt=""
                    width={40}
                    height={40}
                    style={{ borderRadius: 8, objectFit: "cover" }}
                  />
                ) : (
                  <span style={appInitialStyle}>{app.name.slice(0, 1).toUpperCase()}</span>
                )}
                <span style={{ fontSize: 14, fontWeight: 600, marginTop: 8 }}>{app.name}</span>
                {app.description && (
                  <span
                    style={{
                      fontSize: 12,
                      color: "var(--muted-foreground)",
                      marginTop: 4,
                      display: "block",
                    }}
                  >
                    {app.description}
                  </span>
                )}
              </button>
            ))}
          </div>
        </section>
      ))}
    </main>
  );
}

const linkButtonStyle: React.CSSProperties = {
  background: "none",
  border: "none",
  padding: 0,
  color: "var(--primary)",
  fontSize: 13,
  cursor: "pointer",
};

const appCardStyle: React.CSSProperties = {
  display: "flex",
  flexDirection: "column",
  alignItems: "flex-start",
  textAlign: "left",
  padding: 16,
  border: "1px solid var(--border)",
  borderRadius: "var(--radius)",
  background: "var(--background)",
  color: "var(--foreground)",
  cursor: "pointer",
};

const appInitialStyle: React.CSSProperties = {
  width: 40,
  height: 40,
  borderRadius: 8,
  background: "var(--accent)",
  color: "var(--foreground)",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: 18,
  fontWeight: 700,
};
