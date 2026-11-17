import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Search, ShieldCheck } from "lucide-react";
import { BrandMark } from "@/features/branding/BrandMark";
import { useBrand } from "@/features/branding/BrandProvider";
import { ThemeToggle } from "@/features/branding/ThemeToggle";
import { signOut as endSession } from "@/shared/api/session";
import { useSessionStore } from "@/shared/stores/session";
import { Alert, AlertDescription, AlertTitle } from "@/shared/ui/alert";
import { Avatar, AvatarFallback, AvatarImage } from "@/shared/ui/avatar";
import { Badge } from "@/shared/ui/badge";
import { Button } from "@/shared/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/shared/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/shared/ui/dropdown-menu";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/shared/ui/empty";
import { Skeleton } from "@/shared/ui/skeleton";

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
  open_in_new_tab: boolean;
};

// User dashboard (PRD §6.7): the signed-in user's apps, grouped by the
// admin's display group. Clicking an app SSOs straight in while the
// session lasts; MFA-gated apps detour through step-up first.
export function DashboardPage() {
  const navigate = useNavigate();
  const brand = useBrand();
  const orgName = brand?.org_name !== undefined && brand.org_name !== "" ? brand.org_name : "IdentityHub";
  const loadSession = useSessionStore((s) => s.load);
  const me = useSessionStore((s) => s.user);
  const clearSession = useSessionStore((s) => s.clear);
  const [apps, setApps] = useState<AppEntry[] | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [q, setQ] = useState("");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const user = await loadSession();
        if (cancelled) return;
        if (user === null) {
          navigate("/login?next=/", { replace: true });
          return;
        }
        const appsRes = await fetch("/api/my-apps");
        if (!appsRes.ok) {
          if (!cancelled) setNotice("Cannot load your apps. Try again.");
          return;
        }
        const appsData = (await appsRes.json()) as { apps: AppEntry[] };
        if (!cancelled) {
          setApps(appsData.apps);
        }
      } catch {
        if (!cancelled) setNotice("Cannot reach the server. Try again.");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [navigate, loadSession]);

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
      if (app.open_in_new_tab) {
        window.open(data.launch_url, "_blank", "noopener");
      } else {
        window.location.href = data.launch_url;
      }
    } catch {
      setNotice("Cannot reach the server. Try again.");
    }
  }

  async function signOut() {
    await endSession();
    clearSession();
    window.location.href = "/login";
  }

  const needle = q.trim().toLowerCase();
  const visible = (apps ?? []).filter(
    (app) =>
      needle === "" ||
      app.name.toLowerCase().includes(needle) ||
      app.description.toLowerCase().includes(needle),
  );
  const groups = new Map<string, AppEntry[]>();
  for (const app of visible) {
    const label = app.group_label || "Apps";
    const list = groups.get(label) ?? [];
    list.push(app);
    groups.set(label, list);
  }

  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-20 border-b bg-background/95 backdrop-blur">
        <div className="mx-auto flex w-full max-w-5xl items-center justify-between gap-4 px-4 py-3">
          <div className="flex items-center gap-2.5">
            {brand?.logo_url !== undefined && brand.logo_url !== "" ? (
              <img src={brand.logo_url} alt="" className="h-8" />
            ) : (
              <BrandMark className="size-8 text-primary" />
            )}
            <div>
              <h1 className="text-base leading-tight font-bold">{orgName}</h1>
              {me !== null && (
                <p className="text-xs text-muted-foreground">
                  Signed in as {me.display_name || me.username}
                  {me.is_admin ? " (admin)" : ""}
                </p>
              )}
            </div>
          </div>
          <nav className="flex items-center gap-2" aria-label="User">
            <ThemeToggle />
            {me?.is_admin === true && (
              <Button variant="ghost" size="sm" asChild>
                <Link to="/admin">Admin</Link>
              </Button>
            )}
            {me !== null && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon" aria-label="Account menu">
                    <Avatar className="size-8">
                      {me.avatar_url !== "" && <AvatarImage src={me.avatar_url} alt="" />}
                      <AvatarFallback>{initials(me.display_name || me.username)}</AvatarFallback>
                    </Avatar>
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem onSelect={() => navigate("/account")}>
                    Account
                  </DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => navigate("/account/mfa")}>
                    Two-step verification
                  </DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => navigate("/account/password")}>
                    Change password
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onSelect={() => void signOut()}>Sign out</DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            )}
          </nav>
        </div>
      </header>
      <main className="mx-auto w-full max-w-5xl px-4 py-6">
        {me !== null && apps !== null && apps.length > 0 && (
          <div className="mb-5 flex flex-wrap items-end gap-3">
            <div>
              <h2 className="text-lg font-semibold">Hello, {me.display_name || me.username}</h2>
              <p className="text-sm text-muted-foreground">
                {apps.length} application{apps.length === 1 ? "" : "s"} ready to launch.
              </p>
            </div>
            {apps.length > 1 && (
              <label className="ml-auto flex items-center gap-2 rounded-md border bg-card px-2.5 py-1.5 text-sm shadow-xs">
                <Search className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
                <span className="sr-only">Filter applications</span>
                <input
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  placeholder="Filter applications…"
                  className="w-44 bg-transparent outline-none placeholder:text-muted-foreground"
                />
              </label>
            )}
          </div>
        )}

        {notice !== null && (
          <Alert variant="destructive" className="mb-4">
            <AlertTitle>Something went wrong</AlertTitle>
            <AlertDescription>{notice}</AlertDescription>
          </Alert>
        )}
        {apps === null && notice === null && (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3" aria-label="Loading your apps">
            <Skeleton className="h-28 w-full" />
            <Skeleton className="h-28 w-full" />
            <Skeleton className="h-28 w-full" />
          </div>
        )}
        {apps !== null && apps.length === 0 && (
          <Empty>
            <EmptyHeader>
              <EmptyTitle>No applications assigned to you yet</EmptyTitle>
              <EmptyDescription>Ask your administrator to add you to one.</EmptyDescription>
            </EmptyHeader>
          </Empty>
        )}
        {apps !== null && apps.length > 0 && visible.length === 0 && (
          <p className="text-sm text-muted-foreground">No applications match “{q.trim()}”.</p>
        )}
        {[...groups.entries()].map(([label, list]) => (
          <section key={label} className="mb-6">
            <h2 className="mb-3 text-sm font-semibold">
              {label}{" "}
              <span className="font-normal text-muted-foreground">({list.length})</span>
            </h2>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {list.map((app) => (
                <Card
                  key={app.id}
                  className="cursor-pointer transition hover:border-primary/50 hover:shadow-sm"
                  onClick={() => void launch(app)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      void launch(app);
                    }
                  }}
                  tabIndex={0}
                  role="button"
                  aria-label={`Open ${app.name}`}
                >
                  <CardHeader className="flex-row items-start gap-3">
                    {app.icon_url ? (
                      <img
                        src={app.icon_url}
                        alt=""
                        width={40}
                        height={40}
                        className="size-10 rounded-md object-cover"
                      />
                    ) : (
                      <Avatar className="size-10 rounded-md">
                        <AvatarFallback className="rounded-md">
                          {app.name.slice(0, 1).toUpperCase()}
                        </AvatarFallback>
                      </Avatar>
                    )}
                    <div className="min-w-0">
                      <CardTitle className="text-sm">{app.name}</CardTitle>
                      {app.description && (
                        <CardDescription className="line-clamp-1">{app.description}</CardDescription>
                      )}
                    </div>
                    {app.mfa_required && (
                      <span title="Requires two-step verification" className="ml-auto shrink-0">
                        <ShieldCheck className="size-4 text-muted-foreground" aria-hidden="true" />
                      </span>
                    )}
                    <Badge
                      variant="secondary"
                      className={app.mfa_required ? "shrink-0" : "ml-auto shrink-0"}
                    >
                      {app.provider_type}
                    </Badge>
                  </CardHeader>
                </Card>
              ))}
            </div>
          </section>
        ))}
      </main>
    </div>
  );
}

function initials(name: string): string {
  const parts = name.trim().split(/\s+/);
  const first = parts[0]?.slice(0, 1) ?? "";
  const second = parts.length > 1 ? (parts[1]?.slice(0, 1) ?? "") : "";
  return (first + second).toUpperCase() || "?";
}
