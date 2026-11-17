import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { AuthBrandHeader } from "@/features/auth/components/AuthBrandHeader";
import { useBrand } from "@/features/branding/BrandProvider";
import { Alert, AlertDescription, AlertTitle } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Card, CardContent, CardHeader } from "@/shared/ui/card";
import { Field, FieldGroup, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
import { Spinner } from "@/shared/ui/spinner";

// Login page (DESIGN §5.1 layout). Posts to POST /api/auth/login; on
// success the browser continues to ?next= (the OIDC authorize request)
// when it is a safe relative target, else to the dashboard.
export function LoginPage() {
  const [searchParams] = useSearchParams();
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const brand = useBrand();
  const background =
    brand?.login_background_url !== undefined && brand.login_background_url !== ""
      ? { backgroundImage: `url("${brand.login_background_url}")`, backgroundSize: "cover" }
      : { background: "radial-gradient(60rem 30rem at 50% -10%, var(--accent), transparent)" };

  return (
    <main
      className="flex min-h-screen flex-col items-center justify-center gap-6 p-4"
      style={background}
    >
      <AuthBrandHeader />
      <Card className="w-full max-w-sm">
        <CardHeader>
          <h2 className="text-xl leading-none font-semibold">Sign in</h2>
        </CardHeader>
        <CardContent>
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
        </CardContent>
      </Card>
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
