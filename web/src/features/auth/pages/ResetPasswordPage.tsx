import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useBrand } from "@/features/branding/BrandProvider";
import { errorMessage } from "@/shared/api/client";
import { Alert, AlertDescription, AlertTitle } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Card, CardContent, CardDescription, CardHeader } from "@/shared/ui/card";
import { Field, FieldGroup, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
import { Spinner } from "@/shared/ui/spinner";

// Reset-password page (DESIGN §5.2): redeems the ?token= from the mailed
// link with a new password pair. A missing token is a dead link, shown
// without calling the API.
export function ResetPasswordPage() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token") ?? "";
  const [notice, setNotice] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);
  const brand = useBrand();
  const orgName = brand?.org_name !== undefined && brand.org_name !== "" ? brand.org_name : "IdentityHub";

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setNotice(null);
    try {
      const form = new FormData(e.currentTarget as HTMLFormElement);
      const res = await fetch("/api/auth/password/reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          token,
          new_password: form.get("new_password"),
          new_password_confirm: form.get("new_password_confirm"),
        }),
      });
      if (res.status === 429) {
        setNotice("Too many attempts. Wait a minute and try again.");
        return;
      }
      if (!res.ok) {
        setNotice(await errorMessage(res, "This link is invalid or expired. Request a new one."));
        return;
      }
      setDone(true);
    } catch {
      setNotice("Cannot reach the server. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-[radial-gradient(60rem_30rem_at_50%_-10%,var(--accent),transparent)] p-4">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <h1 className="text-xl leading-none font-semibold">{orgName}</h1>
          <CardDescription>Choose a new password</CardDescription>
        </CardHeader>
        <CardContent>
          {token === "" ? (
            <Alert variant="destructive">
              <AlertTitle>Link incomplete</AlertTitle>
              <AlertDescription>
                This reset link is incomplete (missing token).{" "}
                <Link to="/forgot-password" className="text-primary hover:underline">
                  Request a new one
                </Link>
                .
              </AlertDescription>
            </Alert>
          ) : done ? (
            <Alert role="status">
              <AlertDescription>
                Password has been reset.{" "}
                <Link to="/login" className="text-primary hover:underline">
                  Sign in
                </Link>
                .
              </AlertDescription>
            </Alert>
          ) : (
            <form onSubmit={(e) => void submit(e)}>
              <FieldGroup>
                {notice !== null && (
                  <Alert variant="destructive">
                    <AlertTitle>Couldn&apos;t reset the password</AlertTitle>
                    <AlertDescription>{notice}</AlertDescription>
                  </Alert>
                )}
                <Field>
                  <FieldLabel htmlFor="reset-new">New password</FieldLabel>
                  <Input
                    id="reset-new"
                    name="new_password"
                    type="password"
                    autoComplete="new-password"
                    required
                  />
                </Field>
                <Field>
                  <FieldLabel htmlFor="reset-confirm">Confirm new password</FieldLabel>
                  <Input
                    id="reset-confirm"
                    name="new_password_confirm"
                    type="password"
                    autoComplete="new-password"
                    required
                  />
                </Field>
                <Button type="submit" className="w-full" disabled={busy}>
                  {busy ? <Spinner data-icon="inline-start" /> : null}
                  {busy ? "Resetting…" : "Reset password"}
                </Button>
              </FieldGroup>
            </form>
          )}
          <p className="mt-3 mb-0 text-sm">
            <Link to="/login" className="text-primary hover:underline">
              Back to sign in
            </Link>
          </p>
        </CardContent>
      </Card>
    </main>
  );
}
