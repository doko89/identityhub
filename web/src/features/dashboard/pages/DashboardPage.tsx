import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Search, ShieldCheck, Star } from "lucide-react";
import { BrandMark } from "@/features/branding/BrandMark";
import { useBrand } from "@/features/branding/BrandProvider";
import { ThemeToggle } from "@/features/branding/ThemeToggle";
import { DashboardViewMenu } from "../components/DashboardViewMenu";
import { Wallpaper } from "../components/Wallpaper";
import {
  gridClassFor,
  iconShapeClassFor,
  normalizeBackground,
  normalizeIconShape,
  resolveDashboardView,
  type DashboardColumns,
  type DashboardDensity,
} from "../theme";
import {
  getStoredColumns,
  getStoredDensity,
  setStoredColumns,
  setStoredDensity,
} from "../viewPrefs";
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
  is_favorite: boolean;
  last_launched_at: string | null;
};

// maxRecents caps the Recently used row; older launches stay reachable
// in the grouped list below.
const maxRecents = 6;

// User dashboard (PRD §6.7): the signed-in user's apps, grouped by the
// admin's display group. Clicking an app SSOs straight in while the
// session lasts; MFA-gated apps detour through step-up first.
export function DashboardPage() {
  const navigate = useNavigate();
  const brand = useBrand();
  const orgName = brand?.org_name !== undefined && brand.org_name !== "" ? brand.org_name : "IdentityHub";
  // Dashboard theme: the admin brand sets the defaults, the user's
  // per-device view choices override columns and density.
  const [viewColumns, setViewColumns] = useState<DashboardColumns | null>(getStoredColumns);
  const [viewDensity, setViewDensity] = useState<DashboardDensity | null>(getStoredDensity);
  const view = resolveDashboardView(brand, { columns: viewColumns, density: viewDensity });
  const gridClass = gridClassFor(view.columns);
  const iconShapeClass = iconShapeClassFor(normalizeIconShape(brand?.dashboard_icon_shape));
  const compact = view.density === "compact";
  const background = normalizeBackground(brand?.dashboard_background);
  const backgroundUrl = brand?.dashboard_background_url ?? "";

  function pickColumns(columns: DashboardColumns | null) {
    setStoredColumns(columns);
    setViewColumns(columns);
  }

  function pickDensity(density: DashboardDensity | null) {
    setStoredDensity(density);
    setViewDensity(density);
  }
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

  // toggleFavorite flips the pin optimistically and rolls back when the
  // server rejects the change.
  async function toggleFavorite(app: AppEntry) {
    const on = app.is_favorite !== true;
    setApps((prev) => prev?.map((a) => (a.id === app.id ? { ...a, is_favorite: on } : a)) ?? null);
    try {
      const res = await fetch(`/api/my-apps/${encodeURIComponent(app.slug)}/favorite`, {
        method: on ? "PUT" : "DELETE",
      });
      if (!res.ok) {
        throw new Error(`favorite ${res.status}`);
      }
    } catch {
      setApps(
        (prev) => prev?.map((a) => (a.id === app.id ? { ...a, is_favorite: !on } : a)) ?? null,
      );
      setNotice("Could not update favorites. Try again.");
    }
  }

  const needle = q.trim().toLowerCase();
  const visible = (apps ?? []).filter(
    (app) =>
      needle === "" ||
      app.name.toLowerCase().includes(needle) ||
      app.description.toLowerCase().includes(needle),
  );
  // Shortcuts first: favorites, then the most recent launches (a pinned
  // app shows only in Favorites). The grouped list below shows the rest.
  const favorites = visible.filter((app) => app.is_favorite === true);
  const favoriteIDs = new Set(favorites.map((app) => app.id));
  const recents = visible
    .filter((app) => !favoriteIDs.has(app.id) && (app.last_launched_at ?? null) !== null)
    .sort((a, b) => Date.parse(b.last_launched_at ?? "") - Date.parse(a.last_launched_at ?? ""))
    .slice(0, maxRecents);
  const recentIDs = new Set(recents.map((app) => app.id));
  const groups = new Map<string, AppEntry[]>();
  for (const app of visible) {
    if (favoriteIDs.has(app.id) || recentIDs.has(app.id)) {
      continue;
    }
    const label = app.group_label || "Apps";
    const list = groups.get(label) ?? [];
    list.push(app);
    groups.set(label, list);
  }

  return (
    <div className="min-h-screen">
      <Wallpaper background={background} photoUrl={backgroundUrl} />
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
            <DashboardViewMenu
              columns={viewColumns}
              density={viewDensity}
              onColumns={pickColumns}
              onDensity={pickDensity}
            />
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
      {/* Relative + z-10 keeps every dashboard row above the fixed
      wallpaper: an opaque photo would otherwise cover static content
      (group headings), while animated cards float above it. */}
      <main className="relative z-10 mx-auto w-full max-w-5xl px-4 py-6">
        {me !== null && apps !== null && apps.length > 0 && (
          <div className="anim-fade mb-5 flex flex-wrap items-end gap-3">
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
          <Alert variant="destructive" className="anim-fade mb-4">
            <AlertTitle>Something went wrong</AlertTitle>
            <AlertDescription>{notice}</AlertDescription>
          </Alert>
        )}
        {apps === null && notice === null && (
          <div className={gridClass} aria-label="Loading your apps">
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
        {favorites.length > 0 && (
          <section key="favorites" className="mb-6" aria-label="Favorites">
            <h2 className="mb-3 text-sm font-semibold">
              Favorites{" "}
              <span className="font-normal text-muted-foreground">({favorites.length})</span>
            </h2>
            <div className={gridClass}>
              {favorites.map((app, i) => (
                <AppCard
                  key={app.id}
                  app={app}
                  index={i}
                  iconShapeClass={iconShapeClass}
                  compact={compact}
                  onLaunch={launch}
                  onToggleFavorite={toggleFavorite}
                />
              ))}
            </div>
          </section>
        )}
        {recents.length > 0 && (
          <section key="recents" className="mb-6" aria-label="Recently used">
            <h2 className="mb-3 text-sm font-semibold">
              Recently used{" "}
              <span className="font-normal text-muted-foreground">({recents.length})</span>
            </h2>
            <div className={gridClass}>
              {recents.map((app, i) => (
                <AppCard
                  key={app.id}
                  app={app}
                  index={i}
                  iconShapeClass={iconShapeClass}
                  compact={compact}
                  onLaunch={launch}
                  onToggleFavorite={toggleFavorite}
                />
              ))}
            </div>
          </section>
        )}
        {[...groups.entries()].map(([label, list]) => (
          <section key={label} className="mb-6">
            {(groups.size > 1 || label !== "Apps") && (
              <h2 className="mb-3 text-sm font-semibold">
                {label}{" "}
                <span className="font-normal text-muted-foreground">({list.length})</span>
              </h2>
            )}
            <div className={gridClass}>
              {list.map((app, i) => (
                <AppCard
                  key={app.id}
                  app={app}
                  index={i}
                  iconShapeClass={iconShapeClass}
                  compact={compact}
                  onLaunch={launch}
                  onToggleFavorite={toggleFavorite}
                />
              ))}
            </div>
          </section>
        ))}
      </main>
    </div>
  );
}

// AppCard is one launch tile: icon, name, description, the favorite
// star, and the MFA/provider marks. The star stops propagation so
// pinning never launches the app (click and keyboard alike).
function AppCard({
  app,
  index,
  iconShapeClass,
  compact,
  onLaunch,
  onToggleFavorite,
}: {
  app: AppEntry;
  index: number;
  iconShapeClass: string;
  compact: boolean;
  onLaunch: (app: AppEntry) => void;
  onToggleFavorite: (app: AppEntry) => void;
}) {
  const favorite = app.is_favorite === true;
  return (
    <Card
      className="anim-rise cursor-pointer transition hover:border-primary/50 hover:shadow-sm active:scale-[0.99]"
      style={{ animationDelay: `${Math.min(index, 8) * 35}ms` }}
      onClick={() => void onLaunch(app)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          void onLaunch(app);
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
            className={`${compact ? "size-8" : "size-10"} ${iconShapeClass} object-cover`}
          />
        ) : (
          <Avatar className={`${compact ? "size-8" : "size-10"} ${iconShapeClass}`}>
            <AvatarFallback className={iconShapeClass}>
              {app.name.slice(0, 1).toUpperCase()}
            </AvatarFallback>
          </Avatar>
        )}
        <div className="min-w-0">
          <CardTitle className="text-sm">{app.name}</CardTitle>
          {!compact && app.description && (
            <CardDescription className="line-clamp-1">{app.description}</CardDescription>
          )}
        </div>
        <div className="ml-auto flex shrink-0 items-center gap-1.5">
          <button
            type="button"
            aria-label={favorite ? `Unpin ${app.name}` : `Pin ${app.name}`}
            aria-pressed={favorite}
            title={favorite ? "Pinned to favorites" : "Pin to favorites"}
            onClick={(e) => {
              e.stopPropagation();
              onToggleFavorite(app);
            }}
            onKeyDown={(e) => {
              e.stopPropagation();
            }}
            className="rounded p-0.5 text-muted-foreground hover:text-foreground"
          >
            <Star
              className={favorite ? "size-4 fill-primary text-primary" : "size-4"}
              aria-hidden="true"
            />
          </button>
          {app.mfa_required && (
            <span title="Requires two-step verification">
              <ShieldCheck className="size-4 text-muted-foreground" aria-hidden="true" />
            </span>
          )}
          <Badge variant="secondary">{app.provider_type}</Badge>
        </div>
      </CardHeader>
    </Card>
  );
}

function initials(name: string): string {
  const parts = name.trim().split(/\s+/);
  const first = parts[0]?.slice(0, 1) ?? "";
  const second = parts.length > 1 ? (parts[1]?.slice(0, 1) ?? "") : "";
  return (first + second).toUpperCase() || "?";
}
