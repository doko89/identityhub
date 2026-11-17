import { useCallback, useEffect, useState } from "react";
import { errorMessage } from "@/shared/api/client";
import { Badge } from "@/shared/ui/badge";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/shared/ui/select";
import { Skeleton } from "@/shared/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/shared/ui/table";
import { ADMIN_PAGE_SIZE, exportAuditURL, listAudit, type AuditEntry, type AuditListParams } from "../api";
import { Notice, Pager, toNotice, type AdminNotice } from "../components/adminUi";

// Admin audit log (PRD §6.9): read-only table with method/result/date
// filters plus a CSV export carrying the same filters.
export function AdminAuditPage() {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [filters, setFilters] = useState<AuditListParams>({});
  const [method, setMethod] = useState("");
  const [result, setResult] = useState("");
  const [notice, setNotice] = useState<AdminNotice | null>(null);
  const [exporting, setExporting] = useState(false);

  const load = useCallback(async (f: AuditListParams, nextOffset: number) => {
    setNotice(null);
    try {
      const res = await listAudit({ ...f, limit: ADMIN_PAGE_SIZE, offset: nextOffset });
      setEntries(res.entries);
      setTotal(res.total);
      setOffset(nextOffset);
    } catch (err) {
      setNotice(toNotice(err));
    }
  }, []);

  useEffect(() => {
    void load({}, 0);
  }, [load]);

  function apply(e: React.FormEvent) {
    e.preventDefault();
    const form = new FormData(e.currentTarget as HTMLFormElement);
    const text = (k: string) => String(form.get(k) ?? "").trim();
    const instant = (k: string) => {
      const raw = String(form.get(k) ?? "");
      if (raw === "") return "";
      const t = new Date(raw);
      return Number.isNaN(t.getTime()) ? "" : t.toISOString();
    };
    const f: AuditListParams = {
      method,
      result,
      actor: text("actor"),
      app: text("app"),
      since: instant("since"),
      until: instant("until"),
    };
    setFilters(f);
    void load(f, 0);
  }

  async function exportCSV() {
    setExporting(true);
    setNotice(null);
    try {
      const res = await fetch(exportAuditURL(filters));
      if (!res.ok) {
        setNotice({ text: await errorMessage(res, "Export failed. Try again."), stepUp: false });
        return;
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = exportFileName(res.headers.get("Content-Disposition"));
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch {
      setNotice({ text: "Cannot reach the server. Try again.", stepUp: false });
    } finally {
      setExporting(false);
    }
  }

  return (
    <div>
      <h1 className="text-xl font-semibold">Audit log</h1>
      <p className="mt-1 mb-4 text-sm text-muted-foreground">
        Every login, newest first. The CSV export carries the same filters as the table.
      </p>

      <form onSubmit={apply} className="mb-3 flex flex-wrap gap-2">
        <Select value={method === "" ? "any" : method} onValueChange={(v) => setMethod(v === "any" ? "" : v)}>
          <SelectTrigger aria-label="Filter by method" className="w-36">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="any">Any method</SelectItem>
            {["password", "totp", "webauthn", "ldap", "radius", "oidc", "saml"].map((m) => (
              <SelectItem key={m} value={m}>
                {m}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={result === "" ? "any" : result} onValueChange={(v) => setResult(v === "any" ? "" : v)}>
          <SelectTrigger aria-label="Filter by result" className="w-36">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="any">Any result</SelectItem>
            <SelectItem value="success">success</SelectItem>
            <SelectItem value="failure">failure</SelectItem>
          </SelectContent>
        </Select>
        <Input name="actor" placeholder="Actor user ID" aria-label="Filter by actor" className="w-44" />
        <Input name="app" placeholder="Application ID" aria-label="Filter by app" className="w-44" />
        <Input name="since" type="datetime-local" aria-label="Filter from" className="w-48" />
        <Input name="until" type="datetime-local" aria-label="Filter until" className="w-48" />
        <Button type="submit" variant="outline">
          Filter
        </Button>
        <Button type="button" variant="outline" disabled={exporting} onClick={() => void exportCSV()}>
          {exporting ? "Exporting…" : "Export CSV"}
        </Button>
      </form>

      <Notice value={notice} />

      {entries === null && notice === null && (
        <div className="flex flex-col gap-2" aria-label="Loading audit log">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      )}
      {entries !== null && (
        <>
          <div className="overflow-x-auto rounded-lg border bg-card">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>Method</TableHead>
                  <TableHead>Result</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>Detail</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {entries.map((e) => (
                  <TableRow key={e.id}>
                    <TableCell>{formatTime(e.at)}</TableCell>
                    <TableCell className="max-w-36 overflow-hidden text-ellipsis">
                      {e.actor_user_id ?? "—"}
                    </TableCell>
                    <TableCell>{e.method}</TableCell>
                    <TableCell>
                      {e.result === "success" ? (
                        <Badge>success</Badge>
                      ) : (
                        <Badge variant="destructive">failure</Badge>
                      )}
                    </TableCell>
                    <TableCell>{e.ip || "—"}</TableCell>
                    <TableCell className="max-w-56 overflow-hidden text-ellipsis">
                      {formatDetail(e.detail)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <Pager offset={offset} total={total} onPage={(o) => void load(filters, o)} />
        </>
      )}
    </div>
  );
}

function formatTime(at: string): string {
  const t = new Date(at);
  return Number.isNaN(t.getTime()) ? at : t.toLocaleString();
}

function formatDetail(detail: unknown): string {
  if (detail === null || detail === undefined) return "—";
  const s = typeof detail === "string" ? detail : JSON.stringify(detail);
  return s.length > 100 ? `${s.slice(0, 100)}…` : s;
}

// exportFileName honors the backend's Content-Disposition filename,
// falling back to a stable name when it is absent.
export function exportFileName(header: string | null): string {
  if (header !== null) {
    const m = /filename="([^"]+)"/.exec(header);
    if (m?.[1] !== undefined) return m[1];
  }
  return "audit-export.csv";
}
