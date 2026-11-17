import { useCallback, useEffect, useState } from "react";
import { buttonStyle, inputStyle, labelStyle, secondaryStyle } from "@/shared/ui/formStyles";
import {
  ADMIN_PAGE_SIZE,
  createApp,
  createBinding,
  deleteApp,
  deleteBinding,
  listApps,
  listBindings,
  resolveGroupId,
  resolveUserId,
  updateApp,
  type AdminApp,
  type AppBinding,
  type AppPatch,
  type NewBinding,
} from "../api";
import { Notice, Pager, toNotice, type AdminNotice } from "../components/adminUi";

// Admin applications console (PRD §6.7): catalog CRUD plus visibility
// bindings (user/group/policy) per application.
export function AdminAppsPage() {
  const [apps, setApps] = useState<AdminApp[] | null>(null);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [notice, setNotice] = useState<AdminNotice | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState<AdminApp | null>(null);
  const [bindingsFor, setBindingsFor] = useState<AdminApp | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<AdminApp | null>(null);

  const load = useCallback(async (nextOffset: number) => {
    setNotice(null);
    try {
      const res = await listApps({ limit: ADMIN_PAGE_SIZE, offset: nextOffset });
      setApps(res.apps);
      setTotal(res.total);
      setOffset(nextOffset);
    } catch (err) {
      setNotice(toNotice(err));
    }
  }, []);

  useEffect(() => {
    void load(0);
  }, [load]);

  async function runDelete(a: AdminApp) {
    setNotice(null);
    try {
      await deleteApp(a.id);
      setConfirmDelete(null);
      if (bindingsFor?.id === a.id) setBindingsFor(null);
      if (editing?.id === a.id) setEditing(null);
      setApps((prev) => prev?.filter((x) => x.id !== a.id) ?? null);
      setTotal((t) => Math.max(0, t - 1));
    } catch (err) {
      setConfirmDelete(null);
      setNotice(toNotice(err));
    }
  }

  return (
    <div>
      <h1 style={{ fontSize: 20, fontWeight: 600, margin: "0 0 4px" }}>Applications</h1>
      <p style={{ fontSize: 13, color: "var(--muted-foreground)", margin: "0 0 16px" }}>
        The SSO catalog. Bindings decide who sees each app on the dashboard.
      </p>

      <div style={{ marginBottom: 12 }}>
        <button
          type="button"
          style={{ ...buttonStyle, width: "auto" }}
          onClick={() => setShowCreate((v) => !v)}
        >
          {showCreate ? "Close" : "Add application"}
        </button>
      </div>

      <Notice value={notice} />

      {showCreate && (
        <AppForm
          title="Add application"
          submitLabel="Create application"
          onSubmit={(patch) => createApp(patch).then(({ app }) => app)}
          onDone={(app) => {
            setShowCreate(false);
            setApps((prev) => (prev === null ? [app] : [app, ...prev]));
            setTotal((t) => t + 1);
          }}
          onError={setNotice}
        />
      )}

      {editing !== null && (
        <AppForm
          title={`Edit ${editing.slug}`}
          submitLabel="Save"
          initial={editing}
          onSubmit={(patch) => updateApp(editing.id, patch).then(({ app }) => app)}
          onDone={(app) => {
            setEditing(null);
            setApps((prev) => prev?.map((x) => (x.id === app.id ? app : x)) ?? null);
          }}
          onError={setNotice}
          onClose={() => setEditing(null)}
        />
      )}

      {apps === null && notice === null && (
        <p style={{ fontSize: 14, color: "var(--muted-foreground)" }}>Loading applications…</p>
      )}
      {apps !== null && (
        <>
          <div className="ih-table-wrap">
            <table className="ih-table">
              <thead>
                <tr>
                  <th>Slug</th>
                  <th>Name</th>
                  <th>Protocol</th>
                  <th>Visible</th>
                  <th>MFA</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {apps.map((a) => (
                  <tr key={a.id}>
                    <td>{a.slug}</td>
                    <td>{a.name}</td>
                    <td>{a.provider_type}</td>
                    <td>{a.is_visible ? "Yes" : "No"}</td>
                    <td>{a.mfa_required ? "Required" : "—"}</td>
                    <td>
                      <span className="ih-row-actions">
                        <button type="button" style={rowLinkStyle} onClick={() => setEditing(a)}>
                          Edit
                        </button>
                        <button type="button" style={rowLinkStyle} onClick={() => setBindingsFor(a)}>
                          Bindings
                        </button>
                        {confirmDelete?.id === a.id ? (
                          <span style={{ display: "inline-flex", gap: 4, fontSize: 13 }}>
                            Delete {a.slug}?
                            <button type="button" style={dangerLinkStyle} onClick={() => void runDelete(a)}>
                              Yes
                            </button>
                            <button type="button" style={rowLinkStyle} onClick={() => setConfirmDelete(null)}>
                              No
                            </button>
                          </span>
                        ) : (
                          <button type="button" style={rowLinkStyle} onClick={() => setConfirmDelete(a)}>
                            Delete
                          </button>
                        )}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager offset={offset} total={total} onPage={(o) => void load(o)} />
        </>
      )}

      {bindingsFor !== null && (
        <BindingsPanel
          key={bindingsFor.id}
          app={bindingsFor}
          onError={setNotice}
          onClose={() => setBindingsFor(null)}
        />
      )}
    </div>
  );
}

function AppForm({
  title,
  submitLabel,
  initial,
  onSubmit,
  onDone,
  onError,
  onClose,
}: {
  title: string;
  submitLabel: string;
  initial?: AdminApp;
  onSubmit: (patch: AppPatch) => Promise<AdminApp>;
  onDone: (app: AdminApp) => void;
  onError: (n: AdminNotice) => void;
  onClose?: () => void;
}) {
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const form = new FormData(e.currentTarget as HTMLFormElement);
      const sortRaw = String(form.get("sort_order") ?? "").trim();
      const patch: AppPatch = {
        slug: String(form.get("slug") ?? ""),
        name: String(form.get("name") ?? ""),
        description: String(form.get("description") ?? ""),
        icon_url: String(form.get("icon_url") ?? ""),
        launch_url: String(form.get("launch_url") ?? ""),
        group_label: String(form.get("group_label") ?? ""),
        provider_type: String(form.get("provider_type") ?? ""),
        is_visible: (form.get("is_visible") as string | null) === "on",
        mfa_required: (form.get("mfa_required") as string | null) === "on",
      };
      if (sortRaw !== "") {
        patch.sort_order = Number(sortRaw);
      }
      onDone(await onSubmit(patch));
    } catch (err) {
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={(e) => void submit(e)} className="ih-panel" style={{ maxWidth: 520 }}>
      <h2 style={{ fontSize: 15, fontWeight: 600, margin: "0 0 12px" }}>{title}</h2>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 12px" }}>
        <label style={labelStyle}>
          Slug
          <input name="slug" style={inputStyle} defaultValue={initial?.slug ?? ""} required />
        </label>
        <label style={labelStyle}>
          Name
          <input name="name" style={inputStyle} defaultValue={initial?.name ?? ""} required />
        </label>
      </div>
      <label style={labelStyle}>
        Description
        <input name="description" style={inputStyle} defaultValue={initial?.description ?? ""} />
      </label>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 12px" }}>
        <label style={labelStyle}>
          Protocol
          <select name="provider_type" style={inputStyle} defaultValue={initial?.provider_type ?? "oidc"}>
            <option value="oidc">oidc</option>
            <option value="saml">saml</option>
            <option value="ldap">ldap</option>
            <option value="radius">radius</option>
          </select>
        </label>
        <label style={labelStyle}>
          Dashboard group
          <input name="group_label" style={inputStyle} defaultValue={initial?.group_label ?? ""} />
        </label>
      </div>
      <label style={labelStyle}>
        Launch URL
        <input name="launch_url" style={inputStyle} defaultValue={initial?.launch_url ?? ""} placeholder="https://…" />
      </label>
      <label style={labelStyle}>
        Icon URL
        <input name="icon_url" style={inputStyle} defaultValue={initial?.icon_url ?? ""} placeholder="/uploads/….png" />
      </label>
      <label style={labelStyle}>
        Sort order
        <input
          name="sort_order"
          type="number"
          style={inputStyle}
          defaultValue={initial !== undefined ? initial.sort_order : ""}
          placeholder="0"
        />
      </label>
      <div style={{ display: "flex", gap: 16, marginBottom: 16, fontSize: 14 }}>
        <label style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <input name="is_visible" type="checkbox" defaultChecked={initial?.is_visible ?? true} />
          Visible
        </label>
        <label style={{ display: "flex", gap: 6, alignItems: "center" }}>
          <input name="mfa_required" type="checkbox" defaultChecked={initial?.mfa_required ?? false} />
          Require MFA
        </label>
      </div>
      <div style={{ display: "flex", gap: 8 }}>
        {onClose !== undefined && (
          <button type="button" style={secondaryStyle} onClick={onClose}>
            Cancel
          </button>
        )}
        <button type="submit" style={buttonStyle} disabled={busy}>
          {busy ? "Saving…" : submitLabel}
        </button>
      </div>
    </form>
  );
}

function BindingsPanel({ app, onError, onClose }: { app: AdminApp; onError: (n: AdminNotice) => void; onClose: () => void }) {
  const [bindings, setBindings] = useState<AppBinding[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [kind, setKind] = useState("user");

  const load = useCallback(async () => {
    try {
      const res = await listBindings(app.id);
      setBindings(res.bindings);
    } catch (err) {
      onError(toNotice(err));
    }
  }, [app.id, onError]);

  useEffect(() => {
    void load();
  }, [load]);

  async function add(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const form = new FormData(e.currentTarget as HTMLFormElement);
      const bindingType = String(form.get("binding_type") ?? "user");
      const target = String(form.get("target") ?? "").trim();
      const evalMode = String(form.get("eval_mode") ?? "any");
      const b: NewBinding = { binding_type: bindingType, eval_mode: evalMode };
      if (bindingType === "user") {
        b.user_id = await resolveUserId(target);
      } else if (bindingType === "group") {
        b.group_id = await resolveGroupId(target);
      } else {
        b.policy_expr = target;
      }
      await createBinding(app.id, b);
      (e.currentTarget as HTMLFormElement).reset();
      setKind("user");
      await load();
    } catch (err) {
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: string) {
    setBusy(true);
    try {
      await deleteBinding(app.id, id);
      await load();
    } catch (err) {
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="ih-panel" style={{ maxWidth: 640 }} aria-label={`Bindings of ${app.slug}`}>
      <h2 style={{ fontSize: 15, fontWeight: 600, margin: "0 0 4px" }}>
        Bindings of {app.slug}
      </h2>
      <p style={{ fontSize: 13, color: "var(--muted-foreground)", margin: "0 0 12px" }}>
        Who sees this app. Eval mode &quot;any&quot; grants on the first match, &quot;all&quot;
        requires every binding to match.
      </p>
      <form onSubmit={(e) => void add(e)} style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
        <select
          name="binding_type"
          value={kind}
          onChange={(e) => setKind(e.target.value)}
          style={{ ...inputStyle, marginTop: 0, width: 110 }}
          aria-label="Binding type"
        >
          <option value="user">user</option>
          <option value="group">group</option>
          <option value="policy">policy</option>
        </select>
        <input
          name="target"
          placeholder={kind === "policy" ? "policy expression" : kind === "group" ? "Group name or ID" : "Username, email, or ID"}
          aria-label="Binding target"
          style={{ ...inputStyle, marginTop: 0, flex: "1 1 180px" }}
          required
        />
        <select name="eval_mode" defaultValue="any" style={{ ...inputStyle, marginTop: 0, width: 90 }} aria-label="Eval mode">
          <option value="any">any</option>
          <option value="all">all</option>
        </select>
        <button type="submit" style={{ ...secondaryStyle, width: "auto" }} disabled={busy}>
          Add
        </button>
        <button type="button" style={{ ...secondaryStyle, width: "auto" }} onClick={onClose}>
          Close
        </button>
      </form>
      {bindings === null && (
        <p style={{ fontSize: 13, color: "var(--muted-foreground)" }}>Loading bindings…</p>
      )}
      {bindings !== null && bindings.length === 0 && (
        <p style={{ fontSize: 13, color: "var(--muted-foreground)" }}>
          No bindings: nobody sees this app yet.
        </p>
      )}
      {bindings !== null && bindings.length > 0 && (
        <ul style={{ listStyle: "none", padding: 0, margin: 0, fontSize: 13 }}>
          {bindings.map((b) => (
            <li
              key={b.id}
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                padding: "6px 0",
                borderBottom: "1px solid var(--border)",
              }}
            >
              <span>
                <code>{b.binding_type}</code> · {bindingTarget(b)} · {b.eval_mode}
              </span>
              <button type="button" style={rowLinkStyle} disabled={busy} onClick={() => void remove(b.id)}>
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function bindingTarget(b: AppBinding): string {
  if (b.user_id !== undefined) return b.user_id;
  if (b.group_id !== undefined) return b.group_id;
  return b.policy_expr ?? "—";
}

const rowLinkStyle: React.CSSProperties = {
  background: "none",
  border: "none",
  padding: 0,
  color: "var(--primary)",
  fontSize: 13,
  cursor: "pointer",
};

const dangerLinkStyle: React.CSSProperties = {
  ...rowLinkStyle,
  color: "var(--destructive)",
  fontWeight: 600,
};
