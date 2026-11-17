import { useCallback, useEffect, useState } from "react";
import { buttonStyle, inputStyle, labelStyle, secondaryStyle } from "@/shared/ui/formStyles";
import {
  deleteOIDCClient,
  deleteRADIUSClient,
  deleteSAMLSP,
  importSAMLSP,
  listApps,
  listOIDCClients,
  listRADIUSClients,
  listSAMLSPs,
  registerOIDCClient,
  registerRADIUSClient,
  type AdminApp,
  type OIDCClient,
  type RADIUSClient,
  type SAMLSP,
} from "../api";
import { Notice, toNotice, type AdminNotice } from "../components/adminUi";

// Admin providers console (M7): protocol credentials per catalog app —
// OIDC clients, SAML service providers (metadata import), RADIUS NAS
// clients. Plaintext secrets are shown once at registration.
export function AdminProvidersPage() {
  const [apps, setApps] = useState<AdminApp[] | null>(null);
  const [notice, setNotice] = useState<AdminNotice | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const res = await listApps({ limit: 200 });
        setApps(res.apps);
      } catch (err) {
        setNotice(toNotice(err));
      }
    })();
  }, []);

  return (
    <div>
      <h1 style={{ fontSize: 20, fontWeight: 600, margin: "0 0 4px" }}>Providers</h1>
      <p style={{ fontSize: 13, color: "var(--muted-foreground)", margin: "0 0 16px" }}>
        Protocol credentials bound to catalog applications.
      </p>
      <Notice value={notice} />
      {apps === null && notice === null && (
        <p style={{ fontSize: 14, color: "var(--muted-foreground)" }}>Loading…</p>
      )}
      {apps !== null && (
        <>
          <OIDCSection apps={apps} onError={setNotice} />
          <SAMLSection apps={apps} onError={setNotice} />
          <RADIUSSection apps={apps} onError={setNotice} />
        </>
      )}
    </div>
  );
}

function AppSelect({ apps, name, label }: { apps: AdminApp[]; name: string; label: string }) {
  return (
    <label style={labelStyle}>
      {label}
      <select name={name} style={inputStyle} required defaultValue={apps[0]?.id ?? ""}>
        {apps.map((a) => (
          <option key={a.id} value={a.id}>
            {a.slug} — {a.name}
          </option>
        ))}
      </select>
    </label>
  );
}

function OIDCSection({ apps, onError }: { apps: AdminApp[]; onError: (n: AdminNotice) => void }) {
  const [clients, setClients] = useState<OIDCClient[] | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [secret, setSecret] = useState<{ clientId: string; value: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await listOIDCClients({ limit: 200 });
      setClients(res.clients);
    } catch (err) {
      onError(toNotice(err));
    }
  }, [onError]);

  useEffect(() => {
    void load();
  }, [load]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const form = new FormData(e.currentTarget as HTMLFormElement);
      const split = (v: FormDataEntryValue | null) =>
        String(v ?? "")
          .split(/[\s,]+/)
          .map((s) => s.trim())
          .filter((s) => s !== "");
      const clientId = String(form.get("client_id") ?? "");
      const res = await registerOIDCClient({
        application_id: String(form.get("application_id") ?? ""),
        client_id: clientId,
        redirect_uris: split(form.get("redirect_uris")),
        scopes: split(form.get("scopes")),
        public: (form.get("public") as string | null) === "on",
      });
      setShowForm(false);
      if (res.client_secret !== undefined) {
        setSecret({ clientId, value: res.client_secret });
      }
      await load();
    } catch (err) {
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  async function remove(clientId: string) {
    setBusy(true);
    try {
      await deleteOIDCClient(clientId);
      await load();
    } catch (err) {
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section style={{ marginBottom: 32 }} aria-label="OIDC clients">
      <h2 style={{ fontSize: 16, fontWeight: 600, margin: "0 0 8px" }}>OIDC clients</h2>
      {secret !== null && (
        <div className="ih-panel" role="status" style={{ borderColor: "var(--warning, #d97706)" }}>
          <p style={{ fontSize: 13, margin: "0 0 8px" }}>
            Client secret for <code>{secret.clientId}</code> — shown once, copy it now:
          </p>
          <code style={{ fontSize: 13, wordBreak: "break-all" }}>{secret.value}</code>
          <div style={{ marginTop: 8 }}>
            <button type="button" style={{ ...secondaryStyle, width: "auto" }} onClick={() => setSecret(null)}>
              I saved it
            </button>
          </div>
        </div>
      )}
      {clients !== null && clients.length > 0 && (
        <div className="ih-table-wrap" style={{ marginBottom: 12 }}>
          <table className="ih-table">
            <thead>
              <tr>
                <th>Client ID</th>
                <th>Redirect URIs</th>
                <th>Scopes</th>
                <th>Type</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {clients.map((c) => (
                <tr key={c.client_id}>
                  <td>{c.client_id}</td>
                  <td style={{ whiteSpace: "normal" }}>{c.redirect_uris.join(", ") || "—"}</td>
                  <td style={{ whiteSpace: "normal" }}>{c.scopes.join(", ") || "—"}</td>
                  <td>{c.public ? "public" : "confidential"}</td>
                  <td>
                    <button type="button" style={rowLinkStyle} disabled={busy} onClick={() => void remove(c.client_id)}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <button
        type="button"
        style={{ ...secondaryStyle, width: "auto" }}
        onClick={() => setShowForm((v) => !v)}
      >
        {showForm ? "Close" : "Register OIDC client"}
      </button>
      {showForm && (
        <form onSubmit={(e) => void submit(e)} className="ih-panel" style={{ maxWidth: 520 }}>
          <AppSelect apps={apps} name="application_id" label="Application" />
          <label style={labelStyle}>
            Client ID
            <input name="client_id" style={inputStyle} required />
          </label>
          <label style={labelStyle}>
            Redirect URIs (space or comma separated)
            <input name="redirect_uris" style={inputStyle} placeholder="https://app.example.com/callback" />
          </label>
          <label style={labelStyle}>
            Scopes (space or comma separated)
            <input name="scopes" style={inputStyle} placeholder="openid profile email" />
          </label>
          <label style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 14, marginBottom: 16 }}>
            <input name="public" type="checkbox" />
            Public client (no secret, PKCE)
          </label>
          <button type="submit" style={buttonStyle} disabled={busy}>
            {busy ? "Registering…" : "Register client"}
          </button>
        </form>
      )}
    </section>
  );
}

function SAMLSection({ apps, onError }: { apps: AdminApp[]; onError: (n: AdminNotice) => void }) {
  const [sps, setSps] = useState<SAMLSP[] | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await listSAMLSPs({ limit: 200 });
      setSps(res.sps);
    } catch (err) {
      onError(toNotice(err));
    }
  }, [onError]);

  useEffect(() => {
    void load();
  }, [load]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const form = new FormData(e.currentTarget as HTMLFormElement);
      await importSAMLSP(
        String(form.get("application_id") ?? ""),
        String(form.get("metadata_xml") ?? ""),
      );
      setShowForm(false);
      await load();
    } catch (err) {
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  async function remove(entityId: string) {
    setBusy(true);
    try {
      await deleteSAMLSP(entityId);
      await load();
    } catch (err) {
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section style={{ marginBottom: 32 }} aria-label="SAML service providers">
      <h2 style={{ fontSize: 16, fontWeight: 600, margin: "0 0 8px" }}>SAML service providers</h2>
      {sps !== null && sps.length > 0 && (
        <div className="ih-table-wrap" style={{ marginBottom: 12 }}>
          <table className="ih-table">
            <thead>
              <tr>
                <th>Entity ID</th>
                <th>ACS URL</th>
                <th>SLO URL</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {sps.map((sp) => (
                <tr key={sp.entity_id}>
                  <td style={{ whiteSpace: "normal" }}>{sp.entity_id}</td>
                  <td style={{ whiteSpace: "normal" }}>{sp.acs_url}</td>
                  <td style={{ whiteSpace: "normal" }}>{sp.slo_url || "—"}</td>
                  <td>
                    <button type="button" style={rowLinkStyle} disabled={busy} onClick={() => void remove(sp.entity_id)}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <button
        type="button"
        style={{ ...secondaryStyle, width: "auto" }}
        onClick={() => setShowForm((v) => !v)}
      >
        {showForm ? "Close" : "Import SAML SP"}
      </button>
      {showForm && (
        <form onSubmit={(e) => void submit(e)} className="ih-panel" style={{ maxWidth: 520 }}>
          <AppSelect apps={apps} name="application_id" label="Application" />
          <label style={{ ...labelStyle, marginBottom: 16 }}>
            SP metadata XML
            <textarea
              name="metadata_xml"
              style={{ ...inputStyle, minHeight: 120, fontFamily: "monospace", fontSize: 12 }}
              placeholder="<EntityDescriptor …>…</EntityDescriptor>"
              required
            />
          </label>
          <button type="submit" style={buttonStyle} disabled={busy}>
            {busy ? "Importing…" : "Import SP"}
          </button>
        </form>
      )}
    </section>
  );
}

function RADIUSSection({ apps, onError }: { apps: AdminApp[]; onError: (n: AdminNotice) => void }) {
  const [clients, setClients] = useState<RADIUSClient[] | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [secret, setSecret] = useState<{ nas: string; value: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await listRADIUSClients({ limit: 200 });
      setClients(res.clients);
    } catch (err) {
      onError(toNotice(err));
    }
  }, [onError]);

  useEffect(() => {
    void load();
  }, [load]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const form = new FormData(e.currentTarget as HTMLFormElement);
      const nas = String(form.get("nas_identifier") ?? "");
      const res = await registerRADIUSClient({
        application_id: String(form.get("application_id") ?? ""),
        nas_identifier: nas,
        shared_secret: String(form.get("shared_secret") ?? ""),
      });
      setShowForm(false);
      setSecret({ nas, value: res.shared_secret });
      await load();
    } catch (err) {
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  async function remove(nas: string) {
    setBusy(true);
    try {
      await deleteRADIUSClient(nas);
      await load();
    } catch (err) {
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section style={{ marginBottom: 8 }} aria-label="RADIUS clients">
      <h2 style={{ fontSize: 16, fontWeight: 600, margin: "0 0 8px" }}>RADIUS clients</h2>
      {secret !== null && (
        <div className="ih-panel" role="status" style={{ borderColor: "var(--warning, #d97706)" }}>
          <p style={{ fontSize: 13, margin: "0 0 8px" }}>
            Shared secret for <code>{secret.nas}</code> — shown once, copy it now:
          </p>
          <code style={{ fontSize: 13, wordBreak: "break-all" }}>{secret.value}</code>
          <div style={{ marginTop: 8 }}>
            <button type="button" style={{ ...secondaryStyle, width: "auto" }} onClick={() => setSecret(null)}>
              I saved it
            </button>
          </div>
        </div>
      )}
      {clients !== null && clients.length > 0 && (
        <div className="ih-table-wrap" style={{ marginBottom: 12 }}>
          <table className="ih-table">
            <thead>
              <tr>
                <th>NAS identifier</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {clients.map((c) => (
                <tr key={c.nas_identifier}>
                  <td>{c.nas_identifier}</td>
                  <td>
                    <button type="button" style={rowLinkStyle} disabled={busy} onClick={() => void remove(c.nas_identifier)}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <button
        type="button"
        style={{ ...secondaryStyle, width: "auto" }}
        onClick={() => setShowForm((v) => !v)}
      >
        {showForm ? "Close" : "Register RADIUS client"}
      </button>
      {showForm && (
        <form onSubmit={(e) => void submit(e)} className="ih-panel" style={{ maxWidth: 520 }}>
          <AppSelect apps={apps} name="application_id" label="Application" />
          <label style={labelStyle}>
            NAS identifier
            <input name="nas_identifier" style={inputStyle} required placeholder="vpn-gateway-1" />
          </label>
          <label style={{ ...labelStyle, marginBottom: 16 }}>
            Shared secret
            <input name="shared_secret" type="password" autoComplete="new-password" style={inputStyle} required />
          </label>
          <button type="submit" style={buttonStyle} disabled={busy}>
            {busy ? "Registering…" : "Register client"}
          </button>
        </form>
      )}
    </section>
  );
}

const rowLinkStyle: React.CSSProperties = {
  background: "none",
  border: "none",
  padding: 0,
  color: "var(--primary)",
  fontSize: 13,
  cursor: "pointer",
};
