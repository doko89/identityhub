import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Alert, AlertDescription, AlertTitle } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import { Card, CardContent, CardDescription, CardHeader } from "@/shared/ui/card";
import { Spinner } from "@/shared/ui/spinner";

type ConsentInfo = {
  challenge: string;
  client_id: string;
  client_name: string;
  redirect_uri: string;
  scopes: string[];
};

const scopeLabels: Record<string, string> = {
  openid: "Verify your identity",
  profile: "Your username and display name",
  email: "Your email address",
  groups: "Your group memberships",
  offline_access: "Stay signed in (refresh access while you are away)",
  offline: "Stay signed in (refresh access while you are away)",
};

// Consent page (PRD §6.3): shown before IdentityHub shares attributes
// with an app. Allow/Deny posts the decision; the API answers the client
// redirect target, which may be cross-origin, so the page navigates the
// whole browser there.
export function ConsentPage() {
  const [searchParams] = useSearchParams();
  const challenge = searchParams.get("challenge") ?? "";
  const [info, setInfo] = useState<ConsentInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (challenge === "") {
      setError("Missing consent challenge. Restart sign-in from the app.");
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(`/api/oidc/consent?challenge=${encodeURIComponent(challenge)}`);
        if (!res.ok) {
          const data = (await res.json().catch(() => null)) as { error?: string } | null;
          if (!cancelled) setError(data?.error ?? "This consent request expired. Restart sign-in from the app.");
          return;
        }
        const data = (await res.json()) as ConsentInfo;
        if (!cancelled) setInfo(data);
      } catch {
        if (!cancelled) setError("Cannot reach the server. Try again.");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [challenge]);

  async function decide(grant: boolean) {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/oidc/consent", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ challenge, grant }),
      });
      const data = (await res.json().catch(() => null)) as {
        redirect_to?: string;
        error?: string;
      } | null;
      if (!res.ok || !data?.redirect_to) {
        setError(data?.error ?? "Authorization failed. Restart sign-in from the app.");
        return;
      }
      window.location.href = data.redirect_to;
    } catch {
      setError("Cannot reach the server. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-[radial-gradient(60rem_30rem_at_50%_-10%,var(--accent),transparent)] p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <h1 className="text-xl leading-none font-semibold">Authorize app</h1>
          {info === null && error === null && (
            <CardDescription>Loading request…</CardDescription>
          )}
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {error !== null && (
            <Alert variant="destructive">
              <AlertTitle>Authorization failed</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          {info !== null && (
            <>
              <p className="text-sm text-muted-foreground">
                <strong className="text-foreground">{info.client_name}</strong> wants to sign you
                in and access:
              </p>
              <ul className="flex flex-col gap-1 pl-5 text-sm">
                {info.scopes.map((scope) => (
                  <li key={scope} className="list-disc">
                    {scopeLabels[scope] ?? scope}{" "}
                    <span className="text-xs text-muted-foreground">({scope})</span>
                  </li>
                ))}
              </ul>
              <p className="text-xs text-muted-foreground">
                You will return to {redirectHost(info.redirect_uri)} after deciding.
              </p>
              <div className="flex gap-2">
                <Button
                  type="button"
                  variant="outline"
                  className="flex-1"
                  disabled={busy}
                  onClick={() => void decide(false)}
                >
                  Deny
                </Button>
                <Button
                  type="button"
                  className="flex-1"
                  disabled={busy}
                  onClick={() => void decide(true)}
                >
                  {busy ? <Spinner data-icon="inline-start" /> : null}
                  {busy ? "Working…" : "Allow"}
                </Button>
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </main>
  );
}

function redirectHost(redirectUri: string): string {
  try {
    return new URL(redirectUri).host;
  } catch {
    return redirectUri;
  }
}
