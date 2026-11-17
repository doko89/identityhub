import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Download } from "lucide-react";
import { downloadRecoveryCodes } from "@/shared/download";
import { AuthBrandHeader } from "@/features/auth/components/AuthBrandHeader";
import { AuthSplitPanel } from "@/features/auth/components/AuthSplitPanel";
import { Alert, AlertDescription, AlertTitle } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Field, FieldGroup, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
import { Spinner } from "@/shared/ui/spinner";

// Second login step (PRD §6.6): TOTP code or recovery code. Renders in
// three modes from the query string (same split layout as login):
//   /mfa?next=...            verify a code to finish login
//   /mfa?setup=1&next=...    enroll first (admin first login), then continue
//   /mfa?stepup=1&next=...   step up a full session for an MFA-gated app
export function MFAPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const next = safeNext(searchParams.get("next"));
  const setup = searchParams.get("setup") === "1";
  const stepup = searchParams.get("stepup") === "1";

  if (setup) {
    return <EnrollFlow next={next} />;
  }
  return <VerifyForm next={next} stepup={stepup} onSetup={() => navigate(`/mfa?setup=1&next=${encodeURIComponent(next)}`)} />;
}

// MfaShell mirrors the login page shell (DESIGN §5.1): brand split
// panel on wide screens, narrow form column, mobile brand header.
function MfaShell({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children: React.ReactNode;
}) {
  return (
    <main className="grid min-h-screen lg:grid-cols-5">
      <AuthSplitPanel />
      <div className="flex flex-col justify-center px-4 py-10 sm:px-8 lg:col-span-2">
        <div className="anim-rise mx-auto w-full max-w-sm" style={{ animationDelay: "80ms" }}>
          <div className="mb-8 lg:hidden">
            <AuthBrandHeader />
          </div>
          <h1 className="text-2xl font-semibold">{title}</h1>
          <p className="mt-1 mb-6 text-sm text-muted-foreground">{subtitle}</p>
          {children}
          <p className="mt-10 text-xs text-muted-foreground">© IdentityHub</p>
        </div>
      </div>
    </main>
  );
}

function VerifyForm({ next, stepup, onSetup }: { next: string; stepup: boolean; onSetup: () => void }) {
  const [code, setCode] = useState("");
  const [recovery, setRecovery] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setNotice(null);
    try {
      const res = await fetch("/api/auth/mfa/totp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(recovery ? { recovery_code: code } : { code }),
      });
      if (res.status === 401) {
        setNotice("That code did not match. Try again.");
        return;
      }
      if (res.status === 429) {
        setNotice("Too many attempts. Wait a minute and try again.");
        return;
      }
      if (!res.ok) {
        const data = (await res.json().catch(() => null)) as { error?: string } | null;
        setNotice(data?.error ?? "Verification failed. Try again.");
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
    <MfaShell
      title="Two-step verification"
      subtitle={stepup ? "This app needs a second factor." : "Enter the code from your authenticator app."}
    >
      <form onSubmit={(e) => void submit(e)}>
        <FieldGroup>
          {notice !== null && (
            <Alert variant="destructive">
              <AlertTitle>Verification failed</AlertTitle>
              <AlertDescription>{notice}</AlertDescription>
            </Alert>
          )}
          <Field>
            <FieldLabel htmlFor="mfa-code">{recovery ? "Recovery code" : "6-digit code"}</FieldLabel>
            {recovery ? (
              <Input
                id="mfa-code"
                name="code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                autoComplete="one-time-code"
                inputMode="text"
                placeholder="XXXX-XXXX-XXXX-XXXX"
                required
              />
            ) : (
              <Input
                id="mfa-code"
                name="totp_code"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                autoComplete="one-time-code"
                inputMode="numeric"
                maxLength={6}
                placeholder="123456"
                required
              />
            )}
          </Field>
          <Button type="submit" className="w-full active:scale-[0.98]" disabled={busy}>
            {busy ? <Spinner data-icon="inline-start" /> : null}
            {busy ? "Verifying…" : "Verify"}
          </Button>
        </FieldGroup>
      </form>
      <div className="mt-3 flex flex-col gap-2 text-sm">
        <Button
          type="button"
          variant="link"
          className="h-auto justify-start p-0"
          onClick={() => {
            setRecovery(!recovery);
            setCode("");
            setNotice(null);
          }}
        >
          {recovery ? "Use an authenticator code instead" : "Use a recovery code instead"}
        </Button>
        <Button
          type="button"
          variant="link"
          className="h-auto justify-start p-0"
          onClick={onSetup}
        >
          Set up a new authenticator instead
        </Button>
      </div>
    </MfaShell>
  );
}

type EnrollData = {
  otpauth_url: string;
  secret: string;
  qr_png: string;
};

function EnrollFlow({ next }: { next: string }) {
  const [data, setData] = useState<EnrollData | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [confirm, setConfirm] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [started, setStarted] = useState(false);

  async function start() {
    setBusy(true);
    setNotice(null);
    try {
      const res = await fetch("/api/account/mfa/enroll", { method: "POST" });
      const payload = (await res.json().catch(() => null)) as (EnrollData & { error?: string }) | null;
      if (!res.ok || payload === null) {
        setNotice(payload?.error ?? "Could not start enrollment. Try again.");
        return;
      }
      setData(payload);
      setStarted(true);
    } catch {
      setNotice("Cannot reach the server. Try again.");
    } finally {
      setBusy(false);
    }
  }

  async function finish(e: React.FormEvent) {
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
    } catch {
      setNotice("Cannot reach the server. Try again.");
    } finally {
      setBusy(false);
    }
  }

  const subtitle =
    codes !== null
      ? "Save these recovery codes somewhere safe."
      : started
        ? "Scan this code, then enter the 6-digit code it shows."
        : "You will scan a QR code with your authenticator app.";

  return (
    <MfaShell title="Set up two-step verification" subtitle={subtitle}>
      <FieldGroup>
        {notice !== null && (
          <Alert variant="destructive">
            <AlertTitle>Setup failed</AlertTitle>
            <AlertDescription>{notice}</AlertDescription>
          </Alert>
        )}
        {!started && (
          <Button type="button" className="w-full active:scale-[0.98]" disabled={busy} onClick={() => void start()}>
            {busy ? <Spinner data-icon="inline-start" /> : null}
            {busy ? "Starting…" : "Start setup"}
          </Button>
        )}
        {started && codes === null && data !== null && (
          <>
            <img
              src={data.qr_png}
              alt="TOTP enrollment QR code"
              width={200}
              height={200}
              className="mb-3 block border"
            />
            <p className="text-xs break-all text-muted-foreground">
              Can&apos;t scan? Enter this secret manually: <code>{data.secret}</code>
            </p>
            <form onSubmit={(e) => void finish(e)}>
              <FieldGroup>
                <Field>
                  <FieldLabel htmlFor="enroll-code">6-digit code</FieldLabel>
                  <Input
                    id="enroll-code"
                    name="totp_code"
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                    autoComplete="one-time-code"
                    inputMode="numeric"
                    maxLength={6}
                    placeholder="123456"
                    required
                  />
                </Field>
                <Button type="submit" className="w-full active:scale-[0.98]" disabled={busy}>
                  {busy ? <Spinner data-icon="inline-start" /> : null}
                  {busy ? "Confirming…" : "Confirm"}
                </Button>
              </FieldGroup>
            </form>
          </>
        )}
        {codes !== null && (
          <>
            <p className="text-sm text-muted-foreground">
              Each works once, and they are never shown again.
            </p>
            <ul className="font-mono text-sm">
              {codes.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
            <Button
              type="button"
              variant="outline"
              className="w-full"
              onClick={() => downloadRecoveryCodes(codes)}
            >
              <Download data-icon="inline-start" />
              Download codes (.txt)
            </Button>
            <Button
              type="button"
              className="w-full active:scale-[0.98]"
              onClick={() => {
                window.location.href = next;
              }}
            >
              I saved my codes — continue
            </Button>
          </>
        )}
      </FieldGroup>
    </MfaShell>
  );
}

function safeNext(next: string | null): string {
  if (next !== null && next.startsWith("/") && !next.startsWith("//")) {
    return next;
  }
  return "/";
}
