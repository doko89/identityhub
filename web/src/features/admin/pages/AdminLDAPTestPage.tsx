import { useState } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/shared/ui/alert";
import { Badge } from "@/shared/ui/badge";
import { Button } from "@/shared/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/shared/ui/card";
import { Spinner } from "@/shared/ui/spinner";
import { testLDAP, type LDAPTestResult } from "../api";
import { Notice, toNotice, type AdminNotice } from "../components/adminUi";

// Admin LDAP test (PRD §6.2): one button pings the upstream directory
// and shows whether it is configured and reachable.
export function AdminLDAPTestPage() {
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<AdminNotice | null>(null);
  const [result, setResult] = useState<LDAPTestResult | null>(null);

  async function run() {
    setBusy(true);
    setNotice(null);
    setResult(null);
    try {
      setResult(await testLDAP());
    } catch (err) {
      setNotice(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h1 className="text-xl font-semibold">LDAP test</h1>
      <p className="mt-1 mb-4 text-sm text-muted-foreground">
        Check the connection to the upstream directory. The test binds with the configured service
        account and reports whether the directory answers.
      </p>
      <Notice value={notice} />
      <Card className="max-w-xl">
        <CardHeader>
          <CardTitle className="text-base">Upstream directory</CardTitle>
          <CardDescription>
            Runs <code className="font-mono text-xs">POST /api/admin/ldap/test</code> against the
            server&apos;s LDAP settings.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div>
            <Button type="button" onClick={() => void run()} disabled={busy}>
              {busy ? <Spinner data-icon="inline-start" /> : null}
              {busy ? "Testing…" : "Run test"}
            </Button>
          </div>
          {result !== null && <LDAPResult value={result} />}
        </CardContent>
      </Card>
    </div>
  );
}

function LDAPResult({ value }: { value: LDAPTestResult }) {
  if (value.ok) {
    return (
      <Alert role="status">
        <AlertTitle className="flex items-center gap-2">
          Directory is reachable <Badge>ok</Badge>
        </AlertTitle>
        <AlertDescription>
          The upstream directory answered. LDAP logins and sync can proceed.
        </AlertDescription>
      </Alert>
    );
  }
  if (!value.configured) {
    return (
      <Alert role="status">
        <AlertTitle className="flex items-center gap-2">
          LDAP is not configured <Badge variant="secondary">disabled</Badge>
        </AlertTitle>
        <AlertDescription>
          {value.error ?? "Set LDAP_URL on the server to enable the upstream directory."}
        </AlertDescription>
      </Alert>
    );
  }
  return (
    <Alert variant="destructive" role="alert">
      <AlertTitle className="flex items-center gap-2">
        Directory unreachable <Badge variant="destructive">failed</Badge>
      </AlertTitle>
      <AlertDescription>{value.error ?? "The directory did not answer. Check LDAP_URL."}</AlertDescription>
    </Alert>
  );
}
