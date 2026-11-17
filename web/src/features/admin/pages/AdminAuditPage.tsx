import { useCallback, useEffect, useState } from "react";
import { errorMessage } from "@/shared/api/client";
import { inputStyle, secondaryStyle } from "@/shared/ui/formStyles";
import { ADMIN_PAGE_SIZE, exportAuditURL, listAudit, type AuditEntry, type AuditListParams } from "../api";
import { Notice, Pager, toNotice, type AdminNotice } from "../components/adminUi";

// Admin audit log (PRD §6.9): read-only table with method/result/date
// filters plus a CSV export carrying the same filters.
export function AdminAuditPage() {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [filters, setFilters] = useState<AuditListParams>({});
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
      method: text("method"),
      result: text("result"),
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
      <h1 style={{ fontSize: 20, fontWeight: 600, margin: "0 0 4px" }}>Audit log</h1>
      <p style={{ fontSize: 13, color: "var(--muted-foreground)", margin: "0 0 16px" }}>
        Every login, newest first. The CSV export carries the same filters as the table.
      </p>

      <form
        onSubmit={apply}
        style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}
      >
        <select name="method" defaultValue="" style={{ ...inputStyle, marginTop: 0, width: 130 }} aria-label="Filter by method">
          <option value="">Any method</option>
          {["password", "totp", "webauthn", "ldap", "radius", "oidc", "saml"].map((m) => (
            <option key={m} value={m}>{m}</option>
          ))}
        </select>
        <select name="result" defaultValue="" style={{ ...inputStyle, marginTop: 0, width: 130 }} aria-label="Filter by result">
          <option value="">Any result</option>
          <option value="success">success</option>
          <option value="failure">failure</option>
        </select>
        <input name="actor" placeholder="Actor user ID" aria-label="Filter by actor" style={{ ...inputStyle, marginTop: 0, width: 170 }} />
        <input name="app" placeholder="Application ID" aria-label="Filter by app" style={{ ...inputStyle, marginTop: 0, width: 170 }} />
        <input name="since" type="datetime-local" aria-label="Filter from" style={{ ...inputStyle, marginTop: 0, width: 190 }} />
        <input name="until" type="datetime-local" aria-label="Filter until" style={{ ...inputStyle, marginTop: 0, width: 190 }} />
        <button type="submit" style={{ ...secondaryStyle, width: "auto" }}>
          Filter
        </button>
        <button
          type="button"
          style={{ ...secondaryStyle, width: "auto" }}
          disabled={exporting}
          onClick={() => void exportCSV()}
        >
          {exporting ? "Exporting…" : "Export CSV"}
        </button>
      </form>

      <Notice value={notice} />

      {entries === null && notice === null && (
        <p style={{ fontSize: 14, color: "var(--muted-foreground)" }}>Loading audit log…</p>
      )}
      {entries !== null && (
        <>
          <div className="ih-table-wrap">
            <table className="ih-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Actor</th>
                  <th>Method</th>
                  <th>Result</th>
                  <th>IP</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((e) => (
                  <tr key={e.id}>
                    <td>{formatTime(e.at)}</td>
                    <td style={{ maxWidth: 140, overflow: "hidden", textOverflow: "ellipsis" }}>
                      {e.actor_user_id ?? "—"}
                    </td>
                    <td>{e.method}</td>
                    <td>{e.result}</td>
                    <td>{e.ip || "—"}</td>
                    <td style={{ maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis" }}>
                      {formatDetail(e.detail)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
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
