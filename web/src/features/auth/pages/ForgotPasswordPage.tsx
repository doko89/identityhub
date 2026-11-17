import { useState } from "react";
import { Link } from "react-router-dom";
import { AuthBrandHeader } from "@/features/auth/components/AuthBrandHeader";
import { AuthSplitPanel } from "@/features/auth/components/AuthSplitPanel";
import { errorMessage } from "@/shared/api/client";
import { Alert, AlertDescription, AlertTitle } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
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
    <main className="grid min-h-screen lg:grid-cols-5">
      <AuthSplitPanel />

      <div className="flex flex-col justify-center px-4 py-10 sm:px-8 lg:col-span-2">
        <div className="anim-rise mx-auto w-full max-w-sm" style={{ animationDelay: "80ms" }}>
          <div className="mb-8 lg:hidden">
            <AuthBrandHeader />
          </div>
          <h1 className="text-2xl font-semibold">Reset your password</h1>
          <p className="mt-1 mb-6 text-sm text-muted-foreground">
            Enter your username or email and we&apos;ll send a reset link.
          </p>
          {sent ? (
            <Alert role="status" className="anim-fade">
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
                  <Alert variant="destructive" className="anim-fade">
                    <AlertTitle>Couldn&apos;t send the link</AlertTitle>
                    <AlertDescription>{notice}</AlertDescription>
                  </Alert>
                )}
                <Field>
                  <FieldLabel htmlFor="forgot-login">Username or email</FieldLabel>
                  <Input id="forgot-login" name="login" autoComplete="username" required />
                </Field>
                <Button type="submit" className="w-full active:scale-[0.98]" disabled={busy}>
                  {busy ? <Spinner data-icon="inline-start" /> : null}
                  {busy ? "Sending…" : "Send reset link"}
                </Button>
              </FieldGroup>
            </form>
          )}
          <p className="mt-3 text-sm">
            <Link to="/login" className="text-primary hover:underline">
              Back to sign in
            </Link>
          </p>
          <p className="mt-10 text-xs text-muted-foreground">© IdentityHub</p>
        </div>
      </div>
    </main>
  );
}
