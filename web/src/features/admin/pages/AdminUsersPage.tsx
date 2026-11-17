import { useCallback, useEffect, useState } from "react";
import { ApiError } from "@/shared/api/client";
import { buttonStyle, inputStyle, labelStyle, secondaryStyle } from "@/shared/ui/formStyles";
import {
  ADMIN_PAGE_SIZE,
  createUser,
  getUser,
  listUsers,
  resetUserMFA,
  setAdmin,
  setUserPassword,
  updateUser,
  type AdminUser,
} from "../api";
import { Notice, Pager, toNotice, type AdminNotice } from "../components/adminUi";

// Admin users console (PRD §6.1): search + list, create, edit profile,
// activate/deactivate, grant/revoke admin, set password, reset MFA.
export function AdminUsersPage() {
  const [users, setUsers] = useState<AdminUser[] | null>(null);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [q, setQ] = useState("");
  const [source, setSource] = useState("");
  const [active, setActive] = useState("");
  const [notice, setNotice] = useState<AdminNotice | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState<AdminUser | null>(null);

  const load = useCallback(async (nextOffset: number) => {
    setNotice(null);
    try {
      const res = await listUsers({
        q,
        source,
        ...(active === "" ? {} : { active: active === "true" }),
        limit: ADMIN_PAGE_SIZE,
        offset: nextOffset,
      });
      setUsers(res.users);
      setTotal(res.total);
      setOffset(nextOffset);
    } catch (err) {
      setNotice(toNotice(err));
    }
  }, [q, source, active]);

  useEffect(() => {
    void load(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div>
      <h1 style={{ fontSize: 20, fontWeight: 600, margin: "0 0 4px" }}>Users</h1>
      <p style={{ fontSize: 13, color: "var(--muted-foreground)", margin: "0 0 16px" }}>
        Local and LDAP accounts. Deactivation revokes every session immediately.
      </p>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          void load(0);
        }}
        style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}
      >
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search name, username, email…"
          style={{ ...inputStyle, marginTop: 0, width: 220 }}
          aria-label="Search users"
        />
        <select
          value={source}
          onChange={(e) => setSource(e.target.value)}
          style={{ ...inputStyle, marginTop: 0, width: 130 }}
          aria-label="Filter by source"
        >
          <option value="">All sources</option>
          <option value="local">local</option>
          <option value="ldap">ldap</option>
        </select>
        <select
          value={active}
          onChange={(e) => setActive(e.target.value)}
          style={{ ...inputStyle, marginTop: 0, width: 130 }}
          aria-label="Filter by status"
        >
          <option value="">Any status</option>
          <option value="true">Active</option>
          <option value="false">Disabled</option>
        </select>
        <button type="submit" style={{ ...secondaryStyle, width: "auto" }}>
          Search
        </button>
        <button
          type="button"
          style={{ ...buttonStyle, width: "auto" }}
          onClick={() => setShowCreate((v) => !v)}
        >
          {showCreate ? "Close" : "Add user"}
        </button>
      </form>

      <Notice value={notice} />

      {showCreate && (
        <CreateUserForm
          onDone={(created) => {
            setShowCreate(false);
            setUsers((prev) => (prev === null ? [created] : [created, ...prev]));
            setTotal((t) => t + 1);
          }}
          onError={setNotice}
        />
      )}

      {editing !== null && (
        <EditUserForm
          user={editing}
          onDone={(updated) => {
            setEditing(null);
            setUsers((prev) => prev?.map((u) => (u.id === updated.id ? updated : u)) ?? null);
          }}
          onError={setNotice}
          onClose={() => setEditing(null)}
        />
      )}

      {users === null && notice === null && (
        <p style={{ fontSize: 14, color: "var(--muted-foreground)" }}>Loading users…</p>
      )}
      {users !== null && (
        <>
          <div className="ih-table-wrap">
            <table className="ih-table">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Display name</th>
                  <th>Email</th>
                  <th>Source</th>
                  <th>Status</th>
                  <th>Admin</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td>{u.username}</td>
                    <td>{u.display_name || "—"}</td>
                    <td>{u.email || "—"}</td>
                    <td>{u.source}</td>
                    <td>{u.is_active ? "Active" : "Disabled"}</td>
                    <td>{u.is_admin ? "Yes" : "No"}</td>
                    <td>
                      <span className="ih-row-actions">
                        <RowButton label="Edit" onClick={() => setEditing(u)} />
                        <PasswordButton user={u} onError={setNotice} />
                        <MFAResetButton user={u} onError={setNotice} />
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
    </div>
  );
}

function RowButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        background: "none",
        border: "none",
        padding: 0,
        color: "var(--primary)",
        fontSize: 13,
        cursor: "pointer",
      }}
    >
      {label}
    </button>
  );
}

function CreateUserForm({
  onDone,
  onError,
}: {
  onDone: (u: AdminUser) => void;
  onError: (n: AdminNotice) => void;
}) {
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const form = new FormData(e.currentTarget as HTMLFormElement);
      const source = String(form.get("source") ?? "local");
      const { user } = await createUser({
        username: String(form.get("username") ?? ""),
        email: String(form.get("email") ?? ""),
        display_name: String(form.get("display_name") ?? ""),
        password: String(form.get("password") ?? ""),
        source,
        external_dn: String(form.get("external_dn") ?? ""),
      });
      onDone(user);
    } catch (err) {
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={(e) => void submit(e)} className="ih-panel" style={{ maxWidth: 480 }}>
      <h2 style={{ fontSize: 15, fontWeight: 600, margin: "0 0 12px" }}>Add user</h2>
      <label style={labelStyle}>
        Username
        <input name="username" style={inputStyle} required />
      </label>
      <label style={labelStyle}>
        Email
        <input name="email" type="email" style={inputStyle} required />
      </label>
      <label style={labelStyle}>
        Display name
        <input name="display_name" style={inputStyle} />
      </label>
      <label style={labelStyle}>
        Password
        <input name="password" type="password" autoComplete="new-password" style={inputStyle} required />
      </label>
      <label style={labelStyle}>
        Source
        <select name="source" style={inputStyle} defaultValue="local">
          <option value="local">local</option>
          <option value="ldap">ldap (pre-provisioned)</option>
        </select>
      </label>
      <label style={{ ...labelStyle, marginBottom: 16 }}>
        External DN (LDAP only)
        <input name="external_dn" style={inputStyle} placeholder="uid=alice,ou=people,dc=example,dc=com" />
      </label>
      <button type="submit" style={buttonStyle} disabled={busy}>
        {busy ? "Creating…" : "Create user"}
      </button>
    </form>
  );
}

function EditUserForm({
  user,
  onDone,
  onError,
  onClose,
}: {
  user: AdminUser;
  onDone: (u: AdminUser) => void;
  onError: (n: AdminNotice) => void;
  onClose: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [adminBusy, setAdminBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const form = new FormData(e.currentTarget as HTMLFormElement);
      const { user: updated } = await updateUser(user.id, {
        display_name: String(form.get("display_name") ?? ""),
        email: String(form.get("email") ?? ""),
        avatar_url: String(form.get("avatar_url") ?? ""),
        is_active: (form.get("is_active") as string | null) === "on",
      });
      onDone(updated);
    } catch (err) {
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  async function toggleAdmin() {
    setAdminBusy(true);
    try {
      await setAdmin(user.id, !user.is_admin);
      const { user: updated } = await getUser(user.id);
      onDone(updated);
    } catch (err) {
      onError(toNotice(err));
    } finally {
      setAdminBusy(false);
    }
  }

  return (
    <form onSubmit={(e) => void submit(e)} className="ih-panel" style={{ maxWidth: 480 }}>
      <h2 style={{ fontSize: 15, fontWeight: 600, margin: "0 0 12px" }}>
        Edit {user.username}
        {user.is_admin ? " (admin)" : ""}
      </h2>
      <label style={labelStyle}>
        Display name
        <input name="display_name" style={inputStyle} defaultValue={user.display_name} />
      </label>
      <label style={labelStyle}>
        Email
        <input name="email" type="email" style={inputStyle} defaultValue={user.email} />
      </label>
      <label style={labelStyle}>
        Avatar URL
        <input name="avatar_url" style={inputStyle} defaultValue={user.avatar_url} />
      </label>
      <label style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 14, marginBottom: 16 }}>
        <input name="is_active" type="checkbox" defaultChecked={user.is_active} />
        Active (unchecking revokes every session)
      </label>
      <div style={{ display: "flex", gap: 8 }}>
        <button type="button" style={secondaryStyle} onClick={onClose}>
          Cancel
        </button>
        <button type="submit" style={buttonStyle} disabled={busy}>
          {busy ? "Saving…" : "Save"}
        </button>
      </div>
      <div style={{ marginTop: 12 }}>
        <button
          type="button"
          style={secondaryStyle}
          disabled={adminBusy}
          onClick={() => void toggleAdmin()}
        >
          {adminBusy
            ? "Working…"
            : user.is_admin
              ? "Revoke administrator"
              : "Grant administrator"}
        </button>
      </div>
    </form>
  );
}

function PasswordButton({ user, onError }: { user: AdminUser; onError: (n: AdminNotice) => void }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  if (!open) {
    return <RowButton label="Password" onClick={() => setOpen(true)} />;
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const form = new FormData(e.currentTarget as HTMLFormElement);
      await setUserPassword(user.id, String(form.get("new_password") ?? ""));
      setOpen(false);
    } catch (err) {
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={(e) => void submit(e)} style={{ display: "inline-flex", gap: 4 }}>
      <input
        name="new_password"
        type="password"
        autoComplete="new-password"
        placeholder="New password"
        aria-label={`New password for ${user.username}`}
        style={{ ...inputStyle, marginTop: 0, width: 130, padding: "4px 8px" }}
        required
      />
      <button
        type="submit"
        disabled={busy}
        style={{ background: "none", border: "none", color: "var(--primary)", cursor: "pointer", fontSize: 13 }}
      >
        Set
      </button>
      <button
        type="button"
        onClick={() => setOpen(false)}
        style={{ background: "none", border: "none", color: "var(--muted-foreground)", cursor: "pointer", fontSize: 13 }}
      >
        ×
      </button>
    </form>
  );
}

function MFAResetButton({ user, onError }: { user: AdminUser; onError: (n: AdminNotice) => void }) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);

  if (!confirming) {
    return <RowButton label="Reset MFA" onClick={() => setConfirming(true)} />;
  }

  async function run() {
    setBusy(true);
    try {
      await resetUserMFA(user.id);
      setConfirming(false);
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        // Route absent when MFA is unwired; nothing to reset.
        setConfirming(false);
        return;
      }
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <span style={{ display: "inline-flex", gap: 4, fontSize: 13 }}>
      Clear {user.username}&apos;s factors?
      <button
        type="button"
        disabled={busy}
        onClick={() => void run()}
        style={{ background: "none", border: "none", color: "var(--destructive)", cursor: "pointer", fontSize: 13, fontWeight: 600 }}
      >
        Yes
      </button>
      <button
        type="button"
        onClick={() => setConfirming(false)}
        style={{ background: "none", border: "none", color: "var(--muted-foreground)", cursor: "pointer", fontSize: 13 }}
      >
        No
      </button>
    </span>
  );
}
