import { useState } from "react";
import { Link } from "react-router-dom";
import { useBrand } from "@/features/branding/BrandProvider";
import { errorMessage } from "@/shared/api/client";
import { Alert, AlertDescription, AlertTitle } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Card, CardContent, CardDescription, CardHeader } from "@/shared/ui/card";
import { Field, FieldGroup, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
import { Spinner } from "@/shared/ui/spinner";

// Forgot-password page (DESIGN §5.2): one username/email field. The API
// always answers the same generic message whether the account exists or
// not, and the page repeats it verbatim so existence never leaks.
export function ForgotPasswordPage() {
  const [notice, setNotice] = useState<string | null>(null);
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);
  const brand = useBrand();
  const orgName = brand?.org_name !== undefined && brand.org_name !== "" ? brand.org_name : "IdentityHub";

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setNotice(null);
    try {
      const form = new FormData(e.currentTarget as HTMLFormElement);
      const res = await fetch("/api/auth/password/forgot", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ login: form.get("login") }),
      });
      if (res.status === 429) {
        setNotice("Too many attempts. Wait a minute and try again.");
        return;
      }
      if (!res.ok) {
        setNotice(await errorMessage(res, "Something went wrong. Try again."));
        return;
      }
      setSent(true);
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
          <CardDescription>Reset your password</CardDescription>
        </CardHeader>
        <CardContent>
          {sent ? (
            <Alert role="status">
              <AlertDescription>
                If an account exists for that username or email, a reset link is on its way. Check
                your inbox, then{" "}
                <Link to="/login" className="text-primary hover:underline">
                  back to sign in
                </Link>
                .
              </AlertDescription>
            </Alert>
          ) : (
            <form onSubmit={(e) => void submit(e)}>
              <FieldGroup>
                {notice !== null && (
                  <Alert variant="destructive">
                    <AlertTitle>Couldn&apos;t send the link</AlertTitle>
                    <AlertDescription>{notice}</AlertDescription>
                  </Alert>
                )}
                <Field>
                  <FieldLabel htmlFor="forgot-login">Username or email</FieldLabel>
                  <Input id="forgot-login" name="login" autoComplete="username" required />
                </Field>
                <Button type="submit" className="w-full" disabled={busy}>
                  {busy ? <Spinner data-icon="inline-start" /> : null}
                  {busy ? "Sending…" : "Send reset link"}
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
