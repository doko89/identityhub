import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { ApiError } from "@/shared/api/client";
import { useSessionStore } from "@/shared/stores/session";
import { PasswordChecklist } from "@/features/account/components/PasswordChecklist";
import { Alert, AlertDescription, AlertTitle } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Card, CardContent, CardDescription, CardHeader } from "@/shared/ui/card";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
import { Skeleton } from "@/shared/ui/skeleton";
import { Spinner } from "@/shared/ui/spinner";
import { changePassword, getMFAStatus } from "../api";

// Self-service password change (PRD §6.10): current + new pair, with a
// TOTP re-auth field when the user has MFA. Success revokes every other
// session; LDAP users are told the directory owns their password.
export function AccountPasswordPage() {
  const loadSession = useSessionStore((s) => s.load);
  const sessionUser = useSessionStore((s) => s.user);
  const [hasTOTP, setHasTOTP] = useState<boolean | null>(null);
  const [ready, setReady] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<number | null>(null);
  const [form, setForm] = useState({ current: "", next: "", confirm: "", totp: "" });

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const user = await loadSession();
      if (cancelled) return;
      if (user === null) {
        window.location.href = "/login?next=/account/password";
        return;
      }
      try {
        const st = await getMFAStatus();
        if (!cancelled) setHasTOTP(st.has_totp);
      } catch {
        if (!cancelled) setHasTOTP(false);
      }
      if (!cancelled) setReady(true);
    })();
    return () => {
      cancelled = true;
    };
  }, [loadSession]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setDone(null);
    try {
      const res = await changePassword({
        current_password: form.current,
        new_password: form.next,
        new_password_confirm: form.confirm,
        ...(form.totp !== "" ? { totp_code: form.totp } : {}),
      });
      setDone(res.sessions_revoked);
      setForm({ current: "", next: "", confirm: "", totp: "" });
      toast.success("Password changed.");
    } catch (err) {
      setError(err instanceof ApiError ? stripPrefix(err.message) : "Cannot reach the server. Try again.");
    } finally {
      setBusy(false);
    }
  }

  function set<K extends keyof typeof form>(key: K, value: (typeof form)[K]) {
    setForm((prev) => ({ ...prev, [key]: value }));
  }

  const isLocal = sessionUser === null || sessionUser.source === "local";

  return (
    <main className="mx-auto w-full max-w-xl px-4 py-6">
      <p className="text-sm">
        <Link to="/" className="text-primary hover:underline">
          ← Back to dashboard
        </Link>
      </p>
      <Card className="mt-4">
        <CardHeader>
          <h1 className="text-xl leading-none font-semibold">Change password</h1>
          <CardDescription>
            Your new password signs out every other session. It must be at least 8 characters with
            an uppercase letter and a symbol, and differ from your recent passwords.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {!ready && (
            <div className="flex flex-col gap-3" aria-label="Loading">
              <Skeleton className="h-9 w-full" />
              <Skeleton className="h-9 w-full" />
              <Skeleton className="h-9 w-full" />
            </div>
          )}
          {ready && !isLocal && (
            <Alert>
              <AlertTitle>Managed by your directory</AlertTitle>
              <AlertDescription>
                Your account signs in through LDAP, so your password lives in the directory. Contact
                your directory administrator to change it.
              </AlertDescription>
            </Alert>
          )}
          {ready && isLocal && (
            <form onSubmit={(e) => void submit(e)}>
              <FieldGroup>
                {error !== null && (
                  <Alert variant="destructive" role="alert">
                    <AlertTitle>Couldn&apos;t change the password</AlertTitle>
                    <AlertDescription>{error}</AlertDescription>
                  </Alert>
                )}
                {done !== null && (
                  <Alert role="status">
                    <AlertTitle>Password changed</AlertTitle>
                    <AlertDescription>
                      {done === 0
                        ? "No other sessions were signed in."
                        : `Signed out ${done} other session${done === 1 ? "" : "s"}.`}
                    </AlertDescription>
                  </Alert>
                )}
                <Field>
                  <FieldLabel htmlFor="current-password">Current password</FieldLabel>
                  <Input
                    id="current-password"
                    name="current_password"
                    type="password"
                    autoComplete="current-password"
                    value={form.current}
                    onChange={(e) => set("current", e.target.value)}
                    required
                  />
                </Field>
                <Field>
                  <FieldLabel htmlFor="new-password">New password</FieldLabel>
                  <Input
                    id="new-password"
                    name="new_password"
                    type="password"
                    autoComplete="new-password"
                    value={form.next}
                    onChange={(e) => set("next", e.target.value)}
                    required
                  />
                  <FieldDescription>
                    At least 8 characters, with an uppercase letter and a symbol.
                  </FieldDescription>
                  <PasswordChecklist value={form.next} />
                </Field>
                <Field>
                  <FieldLabel htmlFor="new-password-confirm">Confirm new password</FieldLabel>
                  <Input
                    id="new-password-confirm"
                    name="new_password_confirm"
                    type="password"
                    autoComplete="new-password"
                    value={form.confirm}
                    onChange={(e) => set("confirm", e.target.value)}
                    required
                  />
                </Field>
                {hasTOTP === true && (
                  <Field>
                    <FieldLabel htmlFor="totp-code">Authenticator code</FieldLabel>
                    <Input
                      id="totp-code"
                      name="totp_code"
                      autoComplete="one-time-code"
                      inputMode="numeric"
                      value={form.totp}
                      onChange={(e) => set("totp", e.target.value)}
                    />
                    <FieldDescription>
                      You use two-step verification: enter the current 6-digit code so we know
                      it&apos;s you.
                    </FieldDescription>
                  </Field>
                )}
                <Button type="submit" disabled={busy}>
                  {busy ? <Spinner data-icon="inline-start" /> : null}
                  {busy ? "Changing…" : "Change password"}
                </Button>
              </FieldGroup>
            </form>
          )}
        </CardContent>
      </Card>
    </main>
  );
}

function stripPrefix(message: string): string {
  // ApiError prefixes "API <status>: "; the alert shows the message only.
  const i = message.indexOf(": ");
  return i >= 0 ? message.slice(i + 2) : message;
}
