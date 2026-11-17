import { useCallback, useEffect, useState } from "react";
import { Button } from "@/shared/ui/button";
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
  const [deleteBusy, setDeleteBusy] = useState(false);

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
    setDeleteBusy(true);
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
    } finally {
      setDeleteBusy(false);
    }
  }

  return (
    <div>
      <h1 className="text-xl font-semibold">Groups</h1>
      <p className="mt-1 mb-4 text-sm text-muted-foreground">
        Membership drives app access and the admin flag (ih_admin members are administrators).
      </p>

      <div className="mb-3">
        <Button type="button" onClick={() => setShowCreate(true)}>
          Add group
        </Button>
      </div>

      <Notice value={notice} />

      <Sheet open={showCreate} onOpenChange={setShowCreate}>
        <SheetContent>
          <SheetHeader>
            <SheetTitle>Add group</SheetTitle>
            <SheetDescription>Groups collect users for app access and admin grants.</SheetDescription>
          </SheetHeader>
          <div className="mt-4">
            <CreateGroupForm
              onDone={(g) => {
                setShowCreate(false);
                void load(offset);
                setSelected({ id: g.id, name: g.name, description: g.description, member_count: 0 });
              }}
              onError={setNotice}
            />
          </div>
        </SheetContent>
      </Sheet>

      <Dialog open={confirmDelete !== null} onOpenChange={(open) => { if (!open) setConfirmDelete(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete {confirmDelete?.name}?</DialogTitle>
            <DialogDescription>
              The group and its app bindings disappear immediately. This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setConfirmDelete(null)}>
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              disabled={deleteBusy}
              onClick={() => { if (confirmDelete !== null) void runDelete(confirmDelete); }}
            >
              {deleteBusy ? "Deleting…" : "Delete group"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {groups === null && notice === null && (
        <div className="flex flex-col gap-2" aria-label="Loading groups">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      )}
      {groups !== null && (
        <>
          <div className="overflow-x-auto rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Description</TableHead>
                  <TableHead>Members</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {groups.map((g) => (
                  <TableRow key={g.id}>
                    <TableCell>{g.name}</TableCell>
                    <TableCell className="whitespace-normal">{g.description || "—"}</TableCell>
                    <TableCell>{g.member_count}</TableCell>
                    <TableCell>
                      <span className="flex gap-1">
                        <Button
                          type="button"
                          variant="link"
                          size="sm"
                          className="h-auto p-1"
                          onClick={() => setSelected(g)}
                        >
                          Members
                        </Button>
                        <Button
                          type="button"
                          variant="link"
                          size="sm"
                          className="h-auto p-1"
                          onClick={() => setConfirmDelete(g)}
                        >
                          Delete
                        </Button>
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <Pager offset={offset} total={total} onPage={(o) => void load(o)} />
        </>
      )}

      <Sheet open={selected !== null} onOpenChange={(open) => { if (!open) setSelected(null); }}>
        <SheetContent>
          <SheetHeader>
            <SheetTitle>Members of {selected?.name}</SheetTitle>
            <SheetDescription>Add users by username, email, or ID.</SheetDescription>
          </SheetHeader>
          <div className="mt-4">
            {selected !== null && (
              <GroupMembers
                key={selected.id}
                group={selected}
                onError={setNotice}
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
        </SheetContent>
      </Sheet>
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
    <form onSubmit={(e) => void submit(e)}>
      <FieldGroup>
        <Field>
          <FieldLabel htmlFor="new-group-name">Name</FieldLabel>
          <Input id="new-group-name" name="name" required />
        </Field>
        <Field>
          <FieldLabel htmlFor="new-group-description">Description</FieldLabel>
          <Input id="new-group-description" name="description" />
        </Field>
        <Button type="submit" className="w-full" disabled={busy}>
          {busy ? "Creating…" : "Create group"}
        </Button>
      </FieldGroup>
    </form>
  );
}

function GroupMembers({
  group,
  onError,
  onCountChange,
}: {
  group: AdminGroup;
  onError: (n: AdminNotice) => void;
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
    <div aria-label={`Members of ${group.name}`}>
      <form onSubmit={(e) => void add(e)} className="mb-3 flex flex-wrap gap-2">
        <Input
          name="login"
          placeholder="Username, email, or user ID"
          aria-label="User to add"
          className="min-w-48 flex-1"
          required
        />
        <Button type="submit" variant="outline" disabled={busy}>
          Add
        </Button>
      </form>
      <Separator className="mb-2" />
      {members === null && <p className="text-sm text-muted-foreground">Loading members…</p>}
      {members !== null && members.length === 0 && (
        <p className="text-sm text-muted-foreground">No members yet.</p>
      )}
      {members !== null && members.length > 0 && (
        <ul className="m-0 list-none p-0 text-sm">
          {members.map((id) => (
            <MemberRow key={id} userId={id} busy={busy} onRemove={() => void remove(id)} />
          ))}
        </ul>
      )}
    </div>
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
    <li className="flex items-center justify-between gap-2 border-b py-1.5 last:border-b-0">
      <span className="overflow-hidden text-ellipsis">{label}</span>
      <Button
        type="button"
        variant="link"
        size="sm"
        className="h-auto shrink-0 p-1"
        disabled={busy}
        onClick={onRemove}
      >
        Remove
      </Button>
    </li>
  );
}
