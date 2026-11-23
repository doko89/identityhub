import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { ApiError } from "@/shared/api/client";
import { useSessionStore } from "@/shared/stores/session";
import { Alert, AlertDescription, AlertTitle } from "@/shared/ui/alert";
import { Badge } from "@/shared/ui/badge";
import { Button } from "@/shared/ui/button";
import { Card, CardContent, CardDescription, CardHeader } from "@/shared/ui/card";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
import { Separator } from "@/shared/ui/separator";
import { Skeleton } from "@/shared/ui/skeleton";
import { Spinner } from "@/shared/ui/spinner";
import { createAPIKey, getMFAStatus, listAPIKeys, revokeAPIKey } from "../api";
import type { APIKey } from "../api";

// Self-service API keys: the owner mints personal tokens for the
// identityhub CLI, which presents them as Bearer credentials. A key
// inherits its owner's permissions; the secret is shown once at creation
// and revocation takes effect immediately.
export function AccountAPIKeysPage() {
  const loadSession = useSessionStore((s) => s.load);
  const [ready, setReady] = useState(false);
  const [hasTOTP, setHasTOTP] = useState(false);
  const [keys, setKeys] = useState<APIKey[]>([]);
  const [name, setName] = useState("");
  const [expiry, setExpiry] = useState("never");
  const [totp, setTotp] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [issued, setIssued] = useState<{ key: APIKey; secret: string } | null>(null);
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);
  // Captured once: expiry badges compare against the page-load time instead
  // of calling Date.now() during render.
  const [now] = useState(() => Date.now());

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const user = await loadSession();
      if (cancelled) return;
      if (user === null) {
        window.location.href = "/login?next=/account/api-keys";
        return;
      }
      try {
        const [st, list] = await Promise.all([getMFAStatus(), listAPIKeys()]);
        if (cancelled) return;
        setHasTOTP(st.has_totp);
        setKeys(list);
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof ApiError ? stripPrefix(err.message) : "Cannot reach the server. Try again.");
      }
      setReady(true);
    })();
    return () => {
      cancelled = true;
    };
  }, [loadSession]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setIssued(null);
    try {
      const res = await createAPIKey({
        name: name.trim(),
        ...(expiry === "never" ? {} : { expires_in_days: Number(expiry) }),
        ...(totp !== "" ? { totp_code: totp } : {}),
      });
      setKeys((prev) => [res.api_key, ...prev]);
      setIssued({ key: res.api_key, secret: res.secret });
      setName("");
      setTotp("");
      toast.success("API key created. Copy the secret now — it won't be shown again.");
    } catch (err) {
      setError(err instanceof ApiError ? stripPrefix(err.message) : "Cannot reach the server. Try again.");
    } finally {
      setBusy(false);
    }
  }

  async function revoke(id: string) {
    if (confirmRevoke !== id) {
      setConfirmRevoke(id);
      return;
    }
    setConfirmRevoke(null);
    setError(null);
    try {
      await revokeAPIKey(id);
      setKeys((prev) =>
        prev.map((k) => (k.id === id ? { ...k, revoked_at: new Date().toISOString() } : k)),
      );
      toast.success("API key revoked.");
    } catch (err) {
      setError(err instanceof ApiError ? stripPrefix(err.message) : "Cannot reach the server. Try again.");
    }
  }

  async function copySecret(secret: string) {
    try {
      await navigator.clipboard.writeText(secret);
      toast.success("Secret copied.");
    } catch {
      toast.error("Copy failed — select the secret by hand.");
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
          <h1 className="text-xl leading-none font-semibold">API keys</h1>
          <CardDescription>
            Personal tokens for the identityhub CLI. A key can do everything you can — keep
            secrets out of chat logs and shared files.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {!ready && (
            <div className="flex flex-col gap-3" aria-label="Loading">
              <Skeleton className="h-9 w-full" />
              <Skeleton className="h-9 w-full" />
            </div>
          )}
          {ready && (
            <div className="flex flex-col gap-4">
              {error !== null && (
                <Alert variant="destructive" role="alert">
                  <AlertTitle>Something went wrong</AlertTitle>
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}
              {issued !== null && (
                <Alert role="status">
                  <AlertTitle>Copy your secret now</AlertTitle>
                  <AlertDescription>
                    <code className="block w-full overflow-x-auto rounded bg-muted p-2 font-mono text-xs break-all">
                      {issued.secret}
                    </code>
                    <span className="mt-2 block">
                      Use it as{" "}
                      <code className="font-mono text-xs">IDENTITYHUB_API_KEY</code> for the CLI.
                      This is the only time it is shown.
                    </span>
                    <Button
                      type="button"
                      variant="secondary"
                      size="sm"
                      className="mt-2"
                      onClick={() => void copySecret(issued.secret)}
                    >
                      Copy secret
                    </Button>
                  </AlertDescription>
                </Alert>
              )}
              <form onSubmit={(e) => void submit(e)}>
                <FieldGroup>
                  <Field>
                    <FieldLabel htmlFor="key-name">New key name</FieldLabel>
                    <Input
                      id="key-name"
                      name="name"
                      placeholder="e.g. laptop"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      required
                      maxLength={100}
                    />
                  </Field>
                  <Field>
                    <FieldLabel htmlFor="key-expiry">Expires</FieldLabel>
                    <select
                      id="key-expiry"
                      name="expires_in_days"
                      value={expiry}
                      onChange={(e) => setExpiry(e.target.value)}
                      className="h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-xs outline-none"
                    >
                      <option value="never">Never</option>
                      <option value="30">In 30 days</option>
                      <option value="90">In 90 days</option>
                      <option value="365">In 1 year</option>
                    </select>
                    <FieldDescription>Shorter is safer; expired keys stop working.</FieldDescription>
                  </Field>
                  {hasTOTP && (
                    <Field>
                      <FieldLabel htmlFor="key-totp">Authenticator code</FieldLabel>
                      <Input
                        id="key-totp"
                        name="totp_code"
                        autoComplete="one-time-code"
                        inputMode="numeric"
                        value={totp}
                        onChange={(e) => setTotp(e.target.value)}
                      />
                      <FieldDescription>
                        You use two-step verification: enter the current 6-digit code so we
                        know it&apos;s you.
                      </FieldDescription>
                    </Field>
                  )}
                  <Button type="submit" disabled={busy}>
                    {busy ? <Spinner data-icon="inline-start" /> : null}
                    {busy ? "Creating…" : "Create API key"}
                  </Button>
                </FieldGroup>
              </form>
              <Separator />
              <div className="flex flex-col gap-3">
                <h2 className="text-sm font-semibold">Your keys</h2>
                {keys.length === 0 && (
                  <p className="text-sm text-muted-foreground">
                    No API keys yet. Create one above to use the CLI.
                  </p>
                )}
                {keys.map((k) => (
                  <div key={k.id} className="flex items-center gap-3 rounded-md border p-3">
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-semibold">{k.name}</p>
                      <p className="font-mono text-xs text-muted-foreground">
                        {k.prefix}… · created {formatDate(k.created_at)}
                        {k.expires_at !== null && ` · expires ${formatDate(k.expires_at)}`}
                        {k.last_used_at !== null && ` · used ${formatDate(k.last_used_at)}`}
                      </p>
                    </div>
                    <StatusBadge apiKey={k} now={now} />
                    {k.revoked_at === null && (
                      <Button
                        type="button"
                        variant={confirmRevoke === k.id ? "destructive" : "secondary"}
                        size="sm"
                        onClick={() => void revoke(k.id)}
                      >
                        {confirmRevoke === k.id ? "Confirm" : "Revoke"}
                      </Button>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </main>
  );
}

function StatusBadge({ apiKey, now }: { apiKey: APIKey; now: number }) {
  if (apiKey.revoked_at !== null) {
    return <Badge variant="secondary">revoked</Badge>;
  }
  if (apiKey.expires_at !== null && new Date(apiKey.expires_at).getTime() <= now) {
    return <Badge variant="secondary">expired</Badge>;
  }
  return <Badge>active</Badge>;
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString();
}

function stripPrefix(message: string): string {
  // ApiError prefixes "API <status>: "; the alert shows the message only.
  const i = message.indexOf(": ");
  return i >= 0 ? message.slice(i + 2) : message;
}
