import { useCallback, useEffect, useState } from "react";
import { buttonStyle, inputStyle, labelStyle, secondaryStyle } from "@/shared/ui/formStyles";
import {
  ADMIN_PAGE_SIZE,
  addMember,
  createGroup,
  deleteGroup,
  getGroup,
  getUser,
  listGroups,
  removeMember,
  resolveUserId,
  type AdminGroup,
} from "../api";
import { Notice, Pager, toNotice, type AdminNotice } from "../components/adminUi";

// Admin groups console (PRD §6.1): list, create, delete, and membership
// editing. ih_admin is reserved: the backend refuses its deletion and
// guards its last member, and the page surfaces those messages.
export function AdminGroupsPage() {
  const [groups, setGroups] = useState<AdminGroup[] | null>(null);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [notice, setNotice] = useState<AdminNotice | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [selected, setSelected] = useState<AdminGroup | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<AdminGroup | null>(null);

  const load = useCallback(async (nextOffset: number) => {
    setNotice(null);
    try {
      const res = await listGroups({ limit: ADMIN_PAGE_SIZE, offset: nextOffset });
      setGroups(res.groups);
      setTotal(res.total);
      setOffset(nextOffset);
    } catch (err) {
      setNotice(toNotice(err));
    }
  }, []);

  useEffect(() => {
    void load(0);
  }, [load]);

  async function runDelete(g: AdminGroup) {
    setNotice(null);
    try {
      await deleteGroup(g.id);
      setConfirmDelete(null);
      if (selected?.id === g.id) setSelected(null);
      setGroups((prev) => prev?.filter((x) => x.id !== g.id) ?? null);
      setTotal((t) => Math.max(0, t - 1));
    } catch (err) {
      setConfirmDelete(null);
      setNotice(toNotice(err));
    }
  }

  return (
    <div>
      <h1 style={{ fontSize: 20, fontWeight: 600, margin: "0 0 4px" }}>Groups</h1>
      <p style={{ fontSize: 13, color: "var(--muted-foreground)", margin: "0 0 16px" }}>
        Membership drives app access and the admin flag (ih_admin members are administrators).
      </p>

      <div style={{ marginBottom: 12 }}>
        <button
          type="button"
          style={{ ...buttonStyle, width: "auto" }}
          onClick={() => setShowCreate((v) => !v)}
        >
          {showCreate ? "Close" : "Add group"}
        </button>
      </div>

      <Notice value={notice} />

      {showCreate && (
        <CreateGroupForm
          onDone={(g) => {
            setShowCreate(false);
            void load(offset);
            setSelected({ id: g.id, name: g.name, description: g.description, member_count: 0 });
          }}
          onError={setNotice}
        />
      )}

      {groups === null && notice === null && (
        <p style={{ fontSize: 14, color: "var(--muted-foreground)" }}>Loading groups…</p>
      )}
      {groups !== null && (
        <>
          <div className="ih-table-wrap">
            <table className="ih-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Description</th>
                  <th>Members</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {groups.map((g) => (
                  <tr key={g.id}>
                    <td>{g.name}</td>
                    <td style={{ whiteSpace: "normal" }}>{g.description || "—"}</td>
                    <td>{g.member_count}</td>
                    <td>
                      <span className="ih-row-actions">
                        <button type="button" style={rowLinkStyle} onClick={() => setSelected(g)}>
                          Members
                        </button>
                        {confirmDelete?.id === g.id ? (
                          <span style={{ display: "inline-flex", gap: 4, fontSize: 13 }}>
                            Delete {g.name}?
                            <button type="button" style={dangerLinkStyle} onClick={() => void runDelete(g)}>
                              Yes
                            </button>
                            <button type="button" style={rowLinkStyle} onClick={() => setConfirmDelete(null)}>
                              No
                            </button>
                          </span>
                        ) : (
                          <button type="button" style={rowLinkStyle} onClick={() => setConfirmDelete(g)}>
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

      {selected !== null && (
        <GroupMembers
          key={selected.id}
          group={selected}
          onError={setNotice}
          onClose={() => setSelected(null)}
          onCountChange={(delta) =>
            setGroups((prev) =>
              prev?.map((g) =>
                g.id === selected.id ? { ...g, member_count: g.member_count + delta } : g,
              ) ?? null,
            )
          }
        />
      )}
    </div>
  );
}

function CreateGroupForm({
  onDone,
  onError,
}: {
  onDone: (g: { id: string; name: string; description: string }) => void;
  onError: (n: AdminNotice) => void;
}) {
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const form = new FormData(e.currentTarget as HTMLFormElement);
      const { group } = await createGroup(
        String(form.get("name") ?? ""),
        String(form.get("description") ?? ""),
      );
      onDone(group);
    } catch (err) {
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={(e) => void submit(e)} className="ih-panel" style={{ maxWidth: 480 }}>
      <h2 style={{ fontSize: 15, fontWeight: 600, margin: "0 0 12px" }}>Add group</h2>
      <label style={labelStyle}>
        Name
        <input name="name" style={inputStyle} required />
      </label>
      <label style={{ ...labelStyle, marginBottom: 16 }}>
        Description
        <input name="description" style={inputStyle} />
      </label>
      <button type="submit" style={buttonStyle} disabled={busy}>
        {busy ? "Creating…" : "Create group"}
      </button>
    </form>
  );
}

function GroupMembers({
  group,
  onError,
  onClose,
  onCountChange,
}: {
  group: AdminGroup;
  onError: (n: AdminNotice) => void;
  onClose: () => void;
  onCountChange: (delta: number) => void;
}) {
  const [members, setMembers] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const { group: detail } = await getGroup(group.id);
      setMembers(detail.members);
    } catch (err) {
      onError(toNotice(err));
    }
  }, [group.id, onError]);

  useEffect(() => {
    void load();
  }, [load]);

  async function add(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const el = e.currentTarget as HTMLFormElement;
      const login = String(new FormData(el).get("login") ?? "");
      const userId = await resolveUserId(login);
      await addMember(group.id, userId);
      el.reset();
      onCountChange(1);
      await load();
    } catch (err) {
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  async function remove(userId: string) {
    setBusy(true);
    try {
      await removeMember(group.id, userId);
      onCountChange(-1);
      await load();
    } catch (err) {
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="ih-panel" style={{ maxWidth: 560 }} aria-label={`Members of ${group.name}`}>
      <h2 style={{ fontSize: 15, fontWeight: 600, margin: "0 0 4px" }}>Members of {group.name}</h2>
      <form
        onSubmit={(e) => void add(e)}
        style={{ display: "flex", gap: 8, margin: "12px 0", flexWrap: "wrap" }}
      >
        <input
          name="login"
          placeholder="Username, email, or user ID"
          aria-label="User to add"
          style={{ ...inputStyle, marginTop: 0, flex: "1 1 200px" }}
          required
        />
        <button type="submit" style={{ ...secondaryStyle, width: "auto" }} disabled={busy}>
          Add
        </button>
        <button type="button" style={{ ...secondaryStyle, width: "auto" }} onClick={onClose}>
          Close
        </button>
      </form>
      {members === null && (
        <p style={{ fontSize: 13, color: "var(--muted-foreground)" }}>Loading members…</p>
      )}
      {members !== null && members.length === 0 && (
        <p style={{ fontSize: 13, color: "var(--muted-foreground)" }}>No members yet.</p>
      )}
      {members !== null && members.length > 0 && (
        <ul style={{ listStyle: "none", padding: 0, margin: 0, fontSize: 13 }}>
          {members.map((id) => (
            <MemberRow key={id} userId={id} busy={busy} onRemove={() => void remove(id)} />
          ))}
        </ul>
      )}
    </section>
  );
}

// MemberRow resolves one member id to a username; unknown ids (deleted
// users) still render so removal stays possible.
function MemberRow({ userId, busy, onRemove }: { userId: string; busy: boolean; onRemove: () => void }) {
  const [label, setLabel] = useState(userId);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const { user } = await getUser(userId);
        if (!cancelled) setLabel(`${user.username} (${user.email || "no email"})`);
      } catch {
        // Keep the raw id: the row stays removable.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [userId]);

  return (
    <li
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        padding: "6px 0",
        borderBottom: "1px solid var(--border)",
      }}
    >
      <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{label}</span>
      <button type="button" style={rowLinkStyle} disabled={busy} onClick={onRemove}>
        Remove
      </button>
    </li>
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

const dangerLinkStyle: React.CSSProperties = {
  ...rowLinkStyle,
  color: "var(--destructive)",
  fontWeight: 600,
};
