import { useEffect, useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";
import {
  ArrowLeft,
  FlaskConical,
  KeyRound,
  LayoutGrid,
  Menu,
  Palette,
  ScrollText,
  Tags,
  Users,
  UsersRound,
  type LucideIcon,
} from "lucide-react";
import { cn } from "cn";
import { BrandMark } from "@/features/branding/BrandMark";
import { useBrand } from "@/features/branding/BrandProvider";
import { ThemeToggle } from "@/features/branding/ThemeToggle";
import { useSessionStore } from "@/shared/stores/session";
import { Avatar, AvatarFallback, AvatarImage } from "@/shared/ui/avatar";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbList,
  BreadcrumbPage,
} from "@/shared/ui/breadcrumb";
import { Button, buttonVariants } from "@/shared/ui/button";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/shared/ui/sheet";
import { Skeleton } from "@/shared/ui/skeleton";

// AdminLayout guards /admin/* (DESIGN §5.4): signed-out admins bounce to
// login, non-admins see a forbidden page, and the backend's 403 stays the
// real guard on every call the pages make.
//
// Shell: a fixed sidebar + sticky topbar on desktop, the same nav in a
// left Sheet behind a hamburger below lg. Accents stay on the --primary
// token so the branding primary_color keeps working.
export function AdminLayout() {
  const loadSession = useSessionStore((s) => s.load);
  const me = useSessionStore((s) => s.user);
  const brand = useBrand();
  const [state, setState] = useState<"loading" | "ok" | "forbidden">("loading");
  const [navOpen, setNavOpen] = useState(false);
  const location = useLocation();
  const section = allLinks.find(([to]) => location.pathname === to)?.[1] ?? "Console";
  const orgName =
    brand?.org_name !== undefined && brand.org_name !== "" ? brand.org_name : "IdentityHub";

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const user = await loadSession();
      if (cancelled) return;
      if (user === null) {
        if (useSessionStore.getState().status === "signed-out") {
          window.location.href = `/login?next=${encodeURIComponent(window.location.pathname)}`;
          return;
        }
        setState("forbidden");
        return;
      }
      setState(user.is_admin ? "ok" : "forbidden");
    })();
    return () => {
      cancelled = true;
    };
  }, [loadSession]);

  if (state === "loading") {
    return (
      <main className="mx-auto w-full max-w-5xl px-4 py-6" aria-label="Loading">
        <div className="flex flex-col gap-3">
          <Skeleton className="h-8 w-48" />
          <Skeleton className="h-24 w-full" />
          <Skeleton className="h-24 w-full" />
        </div>
      </main>
    );
  }

  if (state === "forbidden") {
    return (
      <main className="mx-auto w-full max-w-xl px-4 py-6">
        <h1 className="text-xl font-semibold">Administrator access required</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          This console is only for administrators.{" "}
          <Link to="/" className="text-primary hover:underline">
            Back to dashboard
          </Link>
          .
        </p>
      </main>
    );
  }

  return (
    <div className="flex min-h-screen bg-muted/50">
      <aside className="sticky top-0 hidden h-screen w-62 shrink-0 flex-col border-r bg-background lg:flex">
        <div className="flex items-center gap-2.5 px-4 pt-5 pb-3">
          {brand?.logo_url !== undefined && brand.logo_url !== "" ? (
            <img src={brand.logo_url} alt="" className="size-8 shrink-0 rounded-md object-cover" />
          ) : (
            <BrandMark className="size-8 shrink-0 text-primary" />
          )}
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold">{orgName}</p>
            <p className="text-xs text-muted-foreground">Admin console</p>
          </div>
        </div>
        <div className="flex-1 overflow-y-auto px-2 pb-2">
          <AdminNav />
        </div>
        <div className="grid gap-2 border-t p-3">
          <Button variant="ghost" size="sm" className="justify-start" asChild>
            <Link to="/">
              <ArrowLeft className="size-4" />
              Back to dashboard
            </Link>
          </Button>
          {me !== null && (
            <div className="flex items-center gap-2.5 rounded-md bg-muted px-2.5 py-2">
              <Avatar className="size-8">
                {me.avatar_url !== "" && <AvatarImage src={me.avatar_url} alt="" />}
                <AvatarFallback>{initials(me.display_name || me.username)}</AvatarFallback>
              </Avatar>
              <div className="min-w-0">
                <p className="truncate text-[13px] font-medium">{me.display_name || me.username}</p>
                <p className="text-xs text-muted-foreground">Administrator</p>
              </div>
            </div>
          )}
        </div>
      </aside>

      <div className="min-w-0 flex-1">
        <header className="sticky top-0 z-20 flex items-center gap-2 border-b bg-background px-4 py-2.5 lg:px-6">
          <Sheet open={navOpen} onOpenChange={setNavOpen}>
            <Button
              variant="ghost"
              size="icon"
              className="lg:hidden"
              aria-label="Open navigation"
              onClick={() => setNavOpen(true)}
            >
              <Menu className="size-5" />
            </Button>
            <SheetContent side="left" className="w-72 gap-0 p-0">
              <SheetHeader className="border-b p-4 text-left">
                <SheetTitle className="text-sm">{orgName} · Admin</SheetTitle>
              </SheetHeader>
              <div className="overflow-y-auto p-2">
                <AdminNav onNavigate={() => setNavOpen(false)} />
              </div>
            </SheetContent>
          </Sheet>
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem>
                <BreadcrumbPage>Admin console · {section}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
          <div className="ml-auto flex items-center gap-1">
            <ThemeToggle />
            {me !== null && (
              <Button variant="ghost" size="icon" className="rounded-full" asChild>
                <Link to="/account" aria-label="Account settings">
                  <Avatar className="size-7">
                    {me.avatar_url !== "" && <AvatarImage src={me.avatar_url} alt="" />}
                    <AvatarFallback>{initials(me.display_name || me.username)}</AvatarFallback>
                  </Avatar>
                </Link>
              </Button>
            )}
          </div>
        </header>
        <main className="mx-auto w-full max-w-6xl px-4 py-6 lg:px-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

// AdminNav is shared by the desktop sidebar and the mobile Sheet. The
// active link stays on the --primary token (bg-primary/10) so a branding
// primary_color re-themes it along with everything else.
function AdminNav({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <nav aria-label="Admin" className="flex flex-col gap-4">
      {groups.map((group) => (
        <div key={group.heading}>
          <p className="px-3 pt-1 pb-1.5 text-[11px] font-semibold tracking-wider text-muted-foreground uppercase">
            {group.heading}
          </p>
          <div className="flex flex-col gap-0.5">
            {group.links.map(({ to, label, Icon }) => (
              <NavLink
                key={to}
                to={to}
                onClick={onNavigate}
                className={({ isActive }) =>
                  cn(
                    buttonVariants({ variant: "ghost", size: "sm" }),
                    "justify-start gap-2.5 font-medium",
                    isActive &&
                      "bg-primary/10 font-semibold text-primary hover:bg-primary/10 hover:text-primary",
                  )
                }
              >
                <Icon className="size-4" />
                {label}
              </NavLink>
            ))}
          </div>
        </div>
      ))}
    </nav>
  );
}

const groups: Array<{
  heading: string;
  links: Array<{ to: string; label: string; Icon: LucideIcon }>;
}> = [
  {
    heading: "Manage",
    links: [
      { to: "/admin/users", label: "Users", Icon: Users },
      { to: "/admin/groups", label: "Groups", Icon: UsersRound },
      { to: "/admin/attrs", label: "Attributes", Icon: Tags },
      { to: "/admin/apps", label: "Applications", Icon: LayoutGrid },
      { to: "/admin/providers", label: "Providers", Icon: KeyRound },
    ],
  },
  {
    heading: "System",
    links: [
      { to: "/admin/branding", label: "Branding", Icon: Palette },
      { to: "/admin/audit", label: "Audit log", Icon: ScrollText },
      { to: "/admin/ldap-test", label: "LDAP test", Icon: FlaskConical },
    ],
  },
];

const allLinks: Array<[string, string]> = groups.flatMap((g) =>
  g.links.map((l): [string, string] => [l.to, l.label]),
);

function initials(name: string): string {
  const parts = name.trim().split(/\s+/);
  const first = parts[0]?.slice(0, 1) ?? "";
  const second = parts.length > 1 ? (parts[1]?.slice(0, 1) ?? "") : "";
  return (first + second).toUpperCase() || "?";
}
