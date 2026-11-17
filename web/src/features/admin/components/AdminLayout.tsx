import { useEffect, useState } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";
import { cn } from "cn";
import { useSessionStore } from "@/shared/stores/session";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbList,
  BreadcrumbPage,
} from "@/shared/ui/breadcrumb";
import { Button, buttonVariants } from "@/shared/ui/button";
import { Separator } from "@/shared/ui/separator";
import { Skeleton } from "@/shared/ui/skeleton";
import "./AdminLayout.css";

// AdminLayout guards /admin/* (DESIGN §5.4): signed-out admins bounce to
// login, non-admins see a forbidden page, and the backend's 403 stays the
// real guard on every call the pages make.
export function AdminLayout() {
  const loadSession = useSessionStore((s) => s.load);
  const [state, setState] = useState<"loading" | "ok" | "forbidden">("loading");
  const location = useLocation();
  const section = links.find(([to]) => location.pathname === to)?.[1] ?? "Console";

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
    <div className="mx-auto flex min-h-screen w-full max-w-5xl flex-col gap-6 px-4 py-6 md:flex-row">
      <nav className="flex flex-row flex-wrap gap-1 self-start md:sticky md:top-6 md:w-48 md:flex-col" aria-label="Admin">
        <div className="w-full px-3 py-2 text-sm font-bold">Admin console</div>
        {links.map(([to, label]) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              cn(buttonVariants({ variant: "ghost", size: "sm" }), "justify-start", isActive && "bg-muted font-semibold")
            }
          >
            {label}
          </NavLink>
        ))}
        <Button variant="ghost" size="sm" className="justify-start" asChild>
          <Link to="/">← Back to dashboard</Link>
        </Button>
      </nav>
      <main className="min-w-0 flex-1">
        <Breadcrumb className="mb-4">
          <BreadcrumbList>
            <BreadcrumbItem>
              <BreadcrumbPage>Admin console · {section}</BreadcrumbPage>
            </BreadcrumbItem>
          </BreadcrumbList>
        </Breadcrumb>
        <Separator className="mb-4" />
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
  ["/admin/ldap-test", "LDAP test"],
];
