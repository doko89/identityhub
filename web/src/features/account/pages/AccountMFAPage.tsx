import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Alert, AlertDescription, AlertTitle } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/shared/ui/card";
import { Field, FieldGroup, FieldLabel } from "@/shared/ui/field";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/shared/ui/input-otp";
import { Separator } from "@/shared/ui/separator";
import { Skeleton } from "@/shared/ui/skeleton";
import { Spinner } from "@/shared/ui/spinner";

type Status = {
  has_totp: boolean;
  remaining_recovery_codes: number;
};

// Self-service factor management (TECH_SPEC §6.1): enroll with QR,
// regenerate recovery codes, or disable — factor changes always
// re-authenticate with the old factor first.
export function AccountMFAPage() {
  const [status, setStatus] = useState<Status | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [enroll, setEnroll] = useState<{ otpauth_url: string; secret: string; qr_png: string } | null>(null);
  const [confirm, setConfirm] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [factor, setFactor] = useState("");
  const [mode, setMode] = useState<"idle" | "disable" | "regenerate">("idle");
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      const res = await fetch("/api/account/mfa/status");
      if (res.status === 401) {
        window.location.href = "/login?next=/account/mfa";
        return;
      }
      if (!res.ok) {
        setNotice("Cannot load your MFA status. Try again.");
        return;
      }
      setStatus((await res.json()) as Status);
    } catch {
      setNotice("Cannot reach the server. Try again.");
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function startEnroll() {
    setBusy(true);
    setNotice(null);
    try {
      const res = await fetch("/api/account/mfa/enroll", { method: "POST" });
      const payload = (await res.json().catch(() => null)) as {
        otpauth_url?: string;
        secret?: string;
        qr_png?: string;
        error?: string;
      } | null;
      if (!res.ok || !payload?.qr_png || !payload.secret) {
        setNotice(payload?.error ?? "Could not start enrollment. Try again.");
        return;
      }
      setEnroll({ otpauth_url: payload.otpauth_url ?? "", secret: payload.secret, qr_png: payload.qr_png });
    } catch {
      setNotice("Cannot reach the server. Try again.");
    } finally {
      setBusy(false);
    }
  }

  async function finishEnroll(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setNotice(null);
    try {
      const res = await fetch("/api/account/mfa/enroll/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: confirm }),
      });
      const payload = (await res.json().catch(() => null)) as {
        recovery_codes?: string[];
        error?: string;
      } | null;
      if (!res.ok || !payload?.recovery_codes) {
        setNotice(payload?.error ?? "That code did not match. Try again.");
        return;
      }
      setCodes(payload.recovery_codes);
      setEnroll(null);
      setConfirm("");
      await load();
    } catch {
      setNotice("Cannot reach the server. Try again.");
    } finally {
      setBusy(false);
    }
  }

  async function submitFactor(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setNotice(null);
    try {
      const path =
        mode === "disable" ? "/api/account/mfa/disable" : "/api/account/mfa/recovery/regenerate";
      const res = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: factor }),
      });
      const payload = (await res.json().catch(() => null)) as {
        recovery_codes?: string[];
        error?: string;
      } | null;
      if (!res.ok) {
        setNotice(payload?.error ?? "That code did not match. Try again.");
        return;
      }
      if (payload?.recovery_codes) {
        setCodes(payload.recovery_codes);
      }
      setFactor("");
      setMode("idle");
      await load();
    } catch {
      setNotice("Cannot reach the server. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="mx-auto w-full max-w-xl px-4 py-6">
      <p className="text-sm">
        <Link to="/account" className="text-primary hover:underline">
          ← Back to account
        </Link>
      </p>
      <Card className="mt-4">
        <CardHeader>
          <CardTitle>Two-step verification</CardTitle>
          {status !== null && !status.has_totp && codes === null && (
            <CardDescription>
              Two-step verification is off. Turn it on to protect your account with an
              authenticator app.
            </CardDescription>
          )}
          {status !== null && status.has_totp && (
            <CardDescription>
              Two-step verification is on. Unused recovery codes:{" "}
              {status.remaining_recovery_codes}.
            </CardDescription>
          )}
        </CardHeader>
        <CardContent>
          <FieldGroup>
            {status === null && notice === null && (
              <div className="flex flex-col gap-3" aria-label="Loading">
                <Skeleton className="h-9 w-full" />
                <Skeleton className="h-9 w-48" />
              </div>
            )}
            {status !== null && !status.has_totp && codes === null && enroll === null && (
              <div>
                <Button type="button" disabled={busy} onClick={() => void startEnroll()}>
                  {busy ? <Spinner data-icon="inline-start" /> : null}
                  {busy ? "Starting…" : "Set up authenticator"}
                </Button>
              </div>
            )}
            {status !== null && !status.has_totp && codes === null && enroll !== null && (
              <>
                <p className="text-sm">Scan this code, then enter the 6-digit code it shows.</p>
                <img
                  src={enroll.qr_png}
                  alt="TOTP enrollment QR code"
                  width={200}
                  height={200}
                  className="mb-3 block border"
                />
                <p className="text-xs break-all text-muted-foreground">
                  Can&apos;t scan? Enter this secret manually: <code>{enroll.secret}</code>
                </p>
                <form onSubmit={(e) => void finishEnroll(e)}>
                  <FieldGroup>
                    <Field>
                      <FieldLabel htmlFor="mfa-confirm">6-digit code</FieldLabel>
                      <CodeInput
                        id="mfa-confirm"
                        value={confirm}
                        onChange={setConfirm}
                        disabled={busy}
                      />
                    </Field>
                    <div>
                      <Button type="submit" disabled={busy}>
                        {busy ? <Spinner data-icon="inline-start" /> : null}
                        {busy ? "Confirming…" : "Confirm"}
                      </Button>
                    </div>
                  </FieldGroup>
                </form>
              </>
            )}
            {status !== null && status.has_totp && mode === "idle" && (
              <div className="flex max-w-md gap-2">
                <Button type="button" variant="outline" onClick={() => setMode("regenerate")}>
                  New recovery codes
                </Button>
                <Button type="button" variant="outline" onClick={() => setMode("disable")}>
                  Turn off
                </Button>
              </div>
            )}
            {status !== null && status.has_totp && mode !== "idle" && (
              <form onSubmit={(e) => void submitFactor(e)} className="max-w-xs">
                <FieldGroup>
                  <p className="text-sm">
                    {mode === "disable"
                      ? "Enter a current code to turn two-step verification off."
                      : "Enter a current code to rotate your recovery codes."}
                  </p>
                  <Field>
                    <FieldLabel htmlFor="mfa-factor">Current code</FieldLabel>
                    <CodeInput
                      id="mfa-factor"
                      value={factor}
                      onChange={setFactor}
                      disabled={busy}
                    />
                  </Field>
                  <div className="flex gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => {
                        setMode("idle");
                        setFactor("");
                      }}
                    >
                      Cancel
                    </Button>
                    <Button type="submit" disabled={busy}>
                      {busy ? <Spinner data-icon="inline-start" /> : null}
                      {busy ? "Working…" : "Confirm"}
                    </Button>
                  </div>
                </FieldGroup>
              </form>
            )}
            {codes !== null && (
              <>
                <Separator />
                <div>
                  <h2 className="text-base font-semibold">Recovery codes</h2>
                  <p className="text-sm text-muted-foreground">
                    Save these somewhere safe. Each works once, and they are never shown again.
                  </p>
                  <ul className="mt-2 font-mono text-sm">
                    {codes.map((c) => (
                      <li key={c}>{c}</li>
                    ))}
                  </ul>
                  <Button
                    type="button"
                    variant="outline"
                    className="mt-3"
                    onClick={() => setCodes(null)}
                  >
                    I saved my codes
                  </Button>
                </div>
              </>
            )}
            {notice !== null && (
              <Alert variant="destructive">
                <AlertTitle>Something went wrong</AlertTitle>
                <AlertDescription>{notice}</AlertDescription>
              </Alert>
            )}
          </FieldGroup>
        </CardContent>
      </Card>
    </main>
  );
}

function CodeInput({
  id,
  value,
  onChange,
  disabled,
}: {
  id: string;
  value: string;
  onChange: (value: string) => void;
  disabled: boolean;
}) {
  return (
    <InputOTP id={id} maxLength={6} value={value} onChange={onChange} disabled={disabled} required>
      <InputOTPGroup>
        <InputOTPSlot index={0} />
        <InputOTPSlot index={1} />
        <InputOTPSlot index={2} />
        <InputOTPSlot index={3} />
        <InputOTPSlot index={4} />
        <InputOTPSlot index={5} />
      </InputOTPGroup>
    </InputOTP>
  );
}
