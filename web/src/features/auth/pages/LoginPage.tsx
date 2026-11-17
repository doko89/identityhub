import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { AuthBrandHeader } from "@/features/auth/components/AuthBrandHeader";
import { BrandMark } from "@/features/branding/BrandMark";
import { useBrand } from "@/features/branding/BrandProvider";
import { Alert, AlertDescription, AlertTitle } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Field, FieldGroup, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
import { Spinner } from "@/shared/ui/spinner";

// Login page (DESIGN §5.1 layout): an asymmetric 3:2 split. The wide
// panel shows the brand backdrop photo when one is uploaded, else the
// built-in brand panel; the narrow panel holds the sign-in form.
// Posts to POST /api/auth/login; on success the browser continues to
// ?next= (the OIDC authorize request) when it is a safe relative
// target, else to the dashboard.
export function LoginPage() {
  const [searchParams] = useSearchParams();
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const brand = useBrand();
  const orgName =
    brand?.org_name !== undefined && brand.org_name !== "" ? brand.org_name : "IdentityHub";
  const backgroundUrl =
    brand?.login_background_url !== undefined && brand.login_background_url !== ""
      ? brand.login_background_url
      : null;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setNotice(null);
    try {
      const form = new FormData(e.currentTarget as HTMLFormElement);
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
  }

  return (
    <main className="grid min-h-screen lg:grid-cols-5">
      <div className="relative hidden overflow-hidden lg:col-span-3 lg:block">
        {backgroundUrl !== null ? (
          <>
            <img
              src={backgroundUrl}
              alt=""
              className="absolute inset-0 h-full w-full object-cover"
            />
            <div
              aria-hidden="true"
              className="absolute inset-0 bg-gradient-to-t from-black/70 via-black/20 to-transparent"
            />
          </>
        ) : (
          <div aria-hidden="true" className="absolute inset-0 bg-primary">
            <BrandMark className="absolute -right-10 -bottom-10 size-64 text-white/10" />
          </div>
        )}
        <div className="absolute inset-x-0 bottom-0 p-10">
          <div className="flex items-center gap-3">
            {brand?.logo_url !== undefined && brand.logo_url !== "" ? (
              <img src={brand.logo_url} alt="" className="h-10" />
            ) : (
              <BrandMark className="size-10 text-white" />
            )}
            <p className="text-2xl font-bold text-white">{orgName}</p>
          </div>
          <p className="mt-3 max-w-md text-white/80">
            The single front door to every company app. Sign in once, open anything.
          </p>
        </div>
      </div>

      <div className="flex flex-col justify-center px-4 py-10 sm:px-8 lg:col-span-2">
        <div className="mx-auto w-full max-w-sm">
          <div className="mb-8 lg:hidden">
            <AuthBrandHeader />
          </div>
          <h1 className="text-2xl font-semibold">Sign in</h1>
          <p className="mt-1 mb-6 text-sm text-muted-foreground">
            Welcome back{orgName === "IdentityHub" ? "" : ` to ${orgName}`}.
          </p>
          <form onSubmit={(e) => void submit(e)}>
            <FieldGroup>
              {notice !== null && (
                <Alert variant="destructive">
                  <AlertTitle>Sign-in failed</AlertTitle>
                  <AlertDescription>{notice}</AlertDescription>
                </Alert>
              )}
              <Field>
                <FieldLabel htmlFor="login-username">Username</FieldLabel>
                <Input id="login-username" name="username" autoComplete="username" required />
              </Field>
              <Field>
                <FieldLabel htmlFor="login-password">Password</FieldLabel>
                <Input
                  id="login-password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                />
              </Field>
              <Button type="submit" className="w-full" disabled={busy}>
                {busy ? <Spinner data-icon="inline-start" /> : null}
                {busy ? "Signing in…" : "Sign in"}
              </Button>
            </FieldGroup>
          </form>
          <p className="mt-3 text-right text-sm">
            <Link to="/forgot-password" className="text-primary hover:underline">
              Forgot password?
            </Link>
          </p>
          <p className="mt-10 text-xs text-muted-foreground">© IdentityHub</p>
        </div>
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
