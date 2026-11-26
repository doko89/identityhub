import { useCallback, useEffect, useState, type ReactNode } from "react";
import { KeyRound, Pencil, Plus, RotateCcw, ShieldCheck, Trash2 } from "lucide-react";
import { ApiError } from "@/shared/api/client";
import { ImageDropzone } from "@/features/uploads/components/ImageDropzone";
import { Avatar, AvatarFallback, AvatarImage } from "@/shared/ui/avatar";
import { Badge } from "@/shared/ui/badge";
import { Button } from "@/shared/ui/button";
import { Checkbox } from "@/shared/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import { Field, FieldGroup, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
import { Separator } from "@/shared/ui/separator";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/shared/ui/select";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/shared/ui/sheet";
import { Skeleton } from "@/shared/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/shared/ui/table";
import {
  ADMIN_PAGE_SIZE,
  attrsToDrafts,
  createUser,
  deleteUser,
  draftsToBody,
  getUser,
  getUserAttrs,
  hasAttrDraft,
  listAttrDefs,
  listUsers,
  resetUserMFA,
  setAdmin,
  setUserAttrs,
  setUserPassword,
  updateUser,
  type AdminUser,
  type AttrDef,
  type AttrDrafts,
} from "../api";
import { Notice, Pager, toNotice, type AdminNotice } from "../components/adminUi";
import { UserAttrFields } from "../components/UserAttrFields";

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
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold">Users</h1>
        <span className="rounded-full border bg-card px-2.5 py-0.5 text-xs font-semibold text-muted-foreground">
          {total} total
        </span>
        <div className="ml-auto">
          <Button type="button" onClick={() => setShowCreate(true)}>
            <Plus className="size-4" />
            Add user
          </Button>
        </div>
      </div>
      <p className="mt-1 mb-4 text-sm text-muted-foreground">
        Local and LDAP accounts. Deactivation revokes every session immediately.
      </p>

      <Notice value={notice} />

      <div className="overflow-hidden rounded-xl border bg-card">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void load(0);
          }}
          className="flex flex-wrap items-center gap-2 border-b p-3"
        >
        <Input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search name, username, email…"
          aria-label="Search users"
          className="w-56"
        />
        <Select value={source === "" ? "all" : source} onValueChange={(v) => setSource(v === "all" ? "" : v)}>
          <SelectTrigger aria-label="Filter by source" className="w-36">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All sources</SelectItem>
            <SelectItem value="local">local</SelectItem>
            <SelectItem value="ldap">ldap</SelectItem>
          </SelectContent>
        </Select>
        <Select value={active === "" ? "any" : active} onValueChange={(v) => setActive(v === "any" ? "" : v)}>
          <SelectTrigger aria-label="Filter by status" className="w-36">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="any">Any status</SelectItem>
            <SelectItem value="true">Active</SelectItem>
            <SelectItem value="false">Disabled</SelectItem>
          </SelectContent>
        </Select>
        <Button type="submit" variant="outline">
          Search
        </Button>
        {users !== null && (
          <span className="ml-auto text-xs text-muted-foreground">
            {total === 0 ? "No users" : `Showing ${offset + 1}–${offset + users.length} of ${total}`}
          </span>
        )}
        </form>

        {users === null && notice === null && (
          <div className="flex flex-col gap-2 p-3" aria-label="Loading users">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        )}
        {users !== null && (
          <>
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>User</TableHead>
                    <TableHead>Display name</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Admin</TableHead>
                    <TableHead>
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {users.map((u) => (
                    <TableRow key={u.id}>
                      <TableCell>
                        <div className="flex items-center gap-2.5">
                          <Avatar className="size-8">
                            {u.avatar_url !== "" && <AvatarImage src={u.avatar_url} alt="" />}
                            <AvatarFallback>
                              {initials(u.display_name || u.username)}
                            </AvatarFallback>
                          </Avatar>
                          <div className="min-w-0">
                            <p className="font-medium">{u.username}</p>
                            <p className="truncate font-mono text-xs text-muted-foreground">
                              {u.email || "—"}
                            </p>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>{u.display_name || "—"}</TableCell>
                      <TableCell>
                        {u.source === "ldap" ? (
                          <Badge variant="outline">ldap</Badge>
                        ) : (
                          <Badge variant="secondary">{u.source}</Badge>
                        )}
                      </TableCell>
                      <TableCell>
                        {u.is_active ? <Badge>Active</Badge> : <Badge variant="secondary">Disabled</Badge>}
                      </TableCell>
                      <TableCell>
                        {u.is_admin ? (
                          <span className="inline-flex items-center gap-1.5 text-[13px] font-semibold text-primary">
                            <ShieldCheck className="size-3.5" />
                            Admin
                          </span>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <span className="flex gap-0.5">
                          <RowButton
                            label={`Edit ${u.username}`}
                            title="Edit"
                            onClick={() => setEditing(u)}
                          >
                            <Pencil className="size-4" />
                          </RowButton>
                          <PasswordButton user={u} onError={setNotice} />
                          <MFAResetButton user={u} onError={setNotice} />
                          <DeleteUserButton
                            user={u}
                            onError={setNotice}
                            onDeleted={() => {
                              setUsers((prev) => (prev === null ? prev : prev.filter((x) => x.id !== u.id)));
                              setTotal((t) => Math.max(0, t - 1));
                            }}
                          />
                        </span>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <div className="border-t px-3 py-2.5">
              <Pager offset={offset} total={total} onPage={(o) => void load(o)} className="" />
            </div>
          </>
        )}
      </div>

      <Sheet open={showCreate} onOpenChange={setShowCreate}>
        <SheetContent className="gap-0">
          <SheetHeader className="border-b px-6 py-5">
            <SheetTitle>Add user</SheetTitle>
            <SheetDescription>Create a local account or pre-provision an LDAP one.</SheetDescription>
          </SheetHeader>
          <div className="min-h-0 flex-1 overflow-y-auto px-6 py-5">
            <CreateUserForm
              onDone={(created) => {
                setShowCreate(false);
                setUsers((prev) => (prev === null ? [created] : [created, ...prev]));
                setTotal((t) => t + 1);
              }}
              onError={setNotice}
            />
          </div>
        </SheetContent>
      </Sheet>

      <Sheet open={editing !== null} onOpenChange={(open) => { if (!open) setEditing(null); }}>
        <SheetContent className="gap-0">
          <SheetHeader className="border-b px-6 py-5">
            <SheetTitle>Edit {editing?.username}</SheetTitle>
            <SheetDescription>Profile, status, and administrator grant.</SheetDescription>
          </SheetHeader>
          <div className="min-h-0 flex-1 overflow-y-auto px-6 py-5">
            {editing !== null && (
              <EditUserForm
                key={editing.id}
                user={editing}
                onDone={(updated) => {
                  setEditing(null);
                  setUsers((prev) => prev?.map((u) => (u.id === updated.id ? updated : u)) ?? null);
                }}
                onError={setNotice}
                onClose={() => setEditing(null)}
              />
            )}
          </div>
        </SheetContent>
      </Sheet>

    </div>
  );
}

function RowButton({
  label,
  title,
  onClick,
  children,
}: {
  label: string;
  title: string;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <Button
      type="button"
      variant="ghost"
      size="icon-sm"
      title={title}
      aria-label={label}
      onClick={onClick}
    >
      {children}
    </Button>
  );
}

function initials(name: string): string {
  const parts = name.trim().split(/\s+/);
  const first = parts[0]?.slice(0, 1) ?? "";
  const second = parts.length > 1 ? (parts[1]?.slice(0, 1) ?? "") : "";
  return (first + second).toUpperCase() || "?";
}

function CreateUserForm({
  onDone,
  onError,
}: {
  onDone: (u: AdminUser) => void;
  onError: (n: AdminNotice) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [source, setSource] = useState("local");
  const [defs, setDefs] = useState<AttrDef[] | null>(null);
  const [drafts, setDrafts] = useState<AttrDrafts>({});

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await listAttrDefs();
        if (!cancelled) setDefs(res.defs);
      } catch (err) {
        if (!cancelled) onError(toNotice(err));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [onError]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const form = new FormData(e.currentTarget as HTMLFormElement);
      const { user } = await createUser({
        username: String(form.get("username") ?? ""),
        email: String(form.get("email") ?? ""),
        display_name: String(form.get("display_name") ?? ""),
        password: String(form.get("password") ?? ""),
        source,
        external_dn: String(form.get("external_dn") ?? ""),
      });
      if (defs !== null && hasAttrDraft(drafts)) {
        try {
          await setUserAttrs(user.id, draftsToBody(defs, drafts));
        } catch (err) {
          const n = toNotice(err);
          onDone(user);
          onError({ ...n, text: `User created, but attributes were not saved: ${n.text}` });
          return;
        }
      }
      onDone(user);
    } catch (err) {
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={(e) => void submit(e)}>
      <FieldGroup>
        <Field>
          <FieldLabel htmlFor="new-username">Username</FieldLabel>
          <Input id="new-username" name="username" required />
        </Field>
        <Field>
          <FieldLabel htmlFor="new-email">Email</FieldLabel>
          <Input id="new-email" name="email" type="email" required />
        </Field>
        <Field>
          <FieldLabel htmlFor="new-display-name">Display name</FieldLabel>
          <Input id="new-display-name" name="display_name" />
        </Field>
        <Field>
          <FieldLabel htmlFor="new-password">Password</FieldLabel>
          <Input id="new-password" name="password" type="password" autoComplete="new-password" required />
        </Field>
        <Field>
          <FieldLabel htmlFor="new-source">Source</FieldLabel>
          <Select value={source} onValueChange={setSource}>
            <SelectTrigger id="new-source">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="local">local</SelectItem>
              <SelectItem value="ldap">ldap (pre-provisioned)</SelectItem>
            </SelectContent>
          </Select>
        </Field>
        <Field>
          <FieldLabel htmlFor="new-external-dn">External DN (LDAP only)</FieldLabel>
          <Input
            id="new-external-dn"
            name="external_dn"
            placeholder="uid=alice,ou=people,dc=example,dc=com"
          />
        </Field>
      </FieldGroup>
      {defs !== null && defs.length > 0 && (
        <>
          <Separator className="my-5" />
          <h3 className="mb-3 text-sm font-semibold">Custom attributes</h3>
          <UserAttrFields defs={defs} drafts={drafts} onChange={setDrafts} idPrefix="new-attr-" />
        </>
      )}
      <div className="sticky bottom-0 -mx-6 mt-5 -mb-5 border-t bg-background px-6 py-4">
        <Button type="submit" className="w-full" disabled={busy}>
          {busy ? "Creating…" : "Create user"}
        </Button>
      </div>
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
  const [displayName, setDisplayName] = useState(user.display_name);
  const [email, setEmail] = useState(user.email);
  const [avatarUrl, setAvatarUrl] = useState(user.avatar_url);
  const [isActive, setIsActive] = useState(user.is_active);
  const [defs, setDefs] = useState<AttrDef[] | null>(null);
  const [drafts, setDrafts] = useState<AttrDrafts>({});

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [defRes, attrRes] = await Promise.all([listAttrDefs(), getUserAttrs(user.id)]);
        if (cancelled) return;
        setDefs(defRes.defs);
        setDrafts(attrsToDrafts(defRes.defs, attrRes.attrs));
      } catch (err) {
        if (!cancelled) onError(toNotice(err));
      }
    })();
    return () => {
      cancelled = true;
    };
    // Remounted per user (key on the sheet), so user.id is fixed here.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const { user: updated } = await updateUser(user.id, {
        display_name: displayName,
        email,
        avatar_url: avatarUrl,
        is_active: isActive,
      });
      if (defs !== null && defs.length > 0) {
        try {
          await setUserAttrs(user.id, draftsToBody(defs, drafts));
        } catch (err) {
          const n = toNotice(err);
          onDone(updated);
          onError({ ...n, text: `Profile saved, but attributes were not saved: ${n.text}` });
          return;
        }
      }
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
    <form onSubmit={(e) => void submit(e)}>
      <FieldGroup>
        <Field>
          <FieldLabel htmlFor="edit-display-name">Display name</FieldLabel>
          <Input
            id="edit-display-name"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="edit-email">Email</FieldLabel>
          <Input
            id="edit-email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="edit-avatar-upload">Avatar</FieldLabel>
          <ImageDropzone
            id="edit-avatar-upload"
            assetType="avatar"
            label="Upload user avatar"
            hint="JPEG, PNG or WebP, max 10 MB. Drop an image here or click to browse."
            onUploaded={(url) => setAvatarUrl(url)}
            className="rounded-full"
          >
            {avatarUrl !== "" ? (
              <Avatar className="size-16">
                <AvatarImage src={avatarUrl} alt="" />
                <AvatarFallback>{user.username.slice(0, 1).toUpperCase()}</AvatarFallback>
              </Avatar>
            ) : (
              <div className="flex size-16 items-center justify-center rounded-full border border-dashed text-xs text-muted-foreground">
                No avatar
              </div>
            )}
          </ImageDropzone>
        </Field>
        <Field orientation="horizontal">
          <Checkbox
            id="edit-active"
            checked={isActive}
            onCheckedChange={(v) => setIsActive(v === true)}
          />
          <FieldLabel htmlFor="edit-active">Active (unchecking revokes every session)</FieldLabel>
        </Field>
      </FieldGroup>
      {defs !== null && defs.length > 0 && (
        <>
          <Separator className="my-5" />
          <h3 className="mb-3 text-sm font-semibold">Custom attributes</h3>
          <UserAttrFields defs={defs} drafts={drafts} onChange={setDrafts} idPrefix="edit-attr-" />
        </>
      )}
      <div className="sticky bottom-0 -mx-6 mt-5 -mb-5 grid gap-2 border-t bg-background px-6 py-4">
        <div className="flex gap-2">
          <Button type="button" variant="outline" className="flex-1" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" className="flex-1" disabled={busy}>
            {busy ? "Saving…" : "Save"}
          </Button>
        </div>
        <Button
          type="button"
          variant="outline"
          className="w-full"
          disabled={adminBusy}
          onClick={() => void toggleAdmin()}
        >
          {adminBusy ? "Working…" : user.is_admin ? "Revoke administrator" : "Grant administrator"}
        </Button>
      </div>
    </form>
  );
}

function PasswordButton({ user, onError }: { user: AdminUser; onError: (n: AdminNotice) => void }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [password, setPassword] = useState("");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await setUserPassword(user.id, password);
      setOpen(false);
      setPassword("");
    } catch (err) {
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <RowButton label={`Set password for ${user.username}`} title="Set password" onClick={() => setOpen(true)}>
        <KeyRound className="size-4" />
      </RowButton>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Set password for {user.username}</DialogTitle>
          <DialogDescription>
            The user signs in with this password next time. LDAP accounts cannot be changed here.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={(e) => void submit(e)}>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor={`pw-${user.id}`}>New password</FieldLabel>
              <Input
                id={`pw-${user.id}`}
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </Field>
            <DialogFooter>
              <Button type="submit" disabled={busy}>
                {busy ? "Setting…" : "Set password"}
              </Button>
            </DialogFooter>
          </FieldGroup>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function MFAResetButton({ user, onError }: { user: AdminUser; onError: (n: AdminNotice) => void }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    try {
      await resetUserMFA(user.id);
      setOpen(false);
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        // Route absent when MFA is unwired; nothing to reset.
        setOpen(false);
        return;
      }
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <RowButton label={`Reset MFA for ${user.username}`} title="Reset MFA" onClick={() => setOpen(true)}>
        <RotateCcw className="size-4" />
      </RowButton>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Reset MFA for {user.username}</DialogTitle>
          <DialogDescription>
            This clears every enrolled factor and recovery code. The user logs straight in and
            re-enrolls.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button type="button" variant="destructive" disabled={busy} onClick={() => void run()}>
            {busy ? "Resetting…" : "Reset factors"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function DeleteUserButton({
  user,
  onError,
  onDeleted,
}: {
  user: AdminUser;
  onError: (n: AdminNotice) => void;
  onDeleted: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    try {
      await deleteUser(user.id);
      setOpen(false);
      onDeleted();
    } catch (err) {
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <RowButton label={`Delete ${user.username}`} title="Delete" onClick={() => setOpen(true)}>
        <Trash2 className="size-4" />
      </RowButton>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Delete {user.username}</DialogTitle>
          <DialogDescription>
            This permanently removes the account, its sessions, group memberships, and API keys.
            Own account, the last administrator, and LDAP-synced accounts cannot be deleted.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button type="button" variant="destructive" disabled={busy} onClick={() => void run()}>
            {busy ? "Deleting…" : "Delete user"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
