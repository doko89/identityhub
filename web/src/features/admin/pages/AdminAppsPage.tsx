import { useCallback, useEffect, useState } from "react";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/shared/ui/select";
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
  const [deleteBusy, setDeleteBusy] = useState(false);

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
    setDeleteBusy(true);
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
    } finally {
      setDeleteBusy(false);
    }
  }

  return (
    <div>
      <h1 className="text-xl font-semibold">Applications</h1>
      <p className="mt-1 mb-4 text-sm text-muted-foreground">
        The SSO catalog. Bindings decide who sees each app on the dashboard.
      </p>

      <div className="mb-3">
        <Button type="button" onClick={() => setShowCreate(true)}>
          Add application
        </Button>
      </div>

      <Notice value={notice} />

      <Sheet open={showCreate} onOpenChange={setShowCreate}>
        <SheetContent>
          <SheetHeader>
            <SheetTitle>Add application</SheetTitle>
            <SheetDescription>Register one catalog row for the app.</SheetDescription>
          </SheetHeader>
          <div className="mt-4">
            <AppForm
              submitLabel="Create application"
              onSubmit={(patch) => createApp(patch).then(({ app }) => app)}
              onDone={(app) => {
                setShowCreate(false);
                setApps((prev) => (prev === null ? [app] : [app, ...prev]));
                setTotal((t) => t + 1);
              }}
              onError={setNotice}
            />
          </div>
        </SheetContent>
      </Sheet>

      <Sheet open={editing !== null} onOpenChange={(open) => { if (!open) setEditing(null); }}>
        <SheetContent>
          <SheetHeader>
            <SheetTitle>Edit {editing?.slug}</SheetTitle>
            <SheetDescription>Catalog row, visibility, and per-app MFA.</SheetDescription>
          </SheetHeader>
          <div className="mt-4">
            {editing !== null && (
              <AppForm
                key={editing.id}
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
          </div>
        </SheetContent>
      </Sheet>

      <Sheet open={bindingsFor !== null} onOpenChange={(open) => { if (!open) setBindingsFor(null); }}>
        <SheetContent>
          <SheetHeader>
            <SheetTitle>Bindings of {bindingsFor?.slug}</SheetTitle>
            <SheetDescription>
              Who sees this app. Eval mode &quot;any&quot; grants on the first match, &quot;all&quot;
              requires every binding to match.
            </SheetDescription>
          </SheetHeader>
          <div className="mt-4">
            {bindingsFor !== null && (
              <BindingsPanel key={bindingsFor.id} app={bindingsFor} onError={setNotice} />
            )}
          </div>
        </SheetContent>
      </Sheet>

      <Dialog open={confirmDelete !== null} onOpenChange={(open) => { if (!open) setConfirmDelete(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete {confirmDelete?.slug}?</DialogTitle>
            <DialogDescription>
              The app and its protocol credentials disappear immediately. This cannot be undone.
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
              {deleteBusy ? "Deleting…" : "Delete application"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {apps === null && notice === null && (
        <div className="flex flex-col gap-2" aria-label="Loading applications">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      )}
      {apps !== null && (
        <>
          <div className="overflow-x-auto rounded-lg border bg-card">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Slug</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Protocol</TableHead>
                  <TableHead>Visible</TableHead>
                  <TableHead>MFA</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {apps.map((a) => (
                  <TableRow key={a.id}>
                    <TableCell>{a.slug}</TableCell>
                    <TableCell>{a.name}</TableCell>
                    <TableCell>
                      <Badge variant="secondary">{a.provider_type}</Badge>
                    </TableCell>
                    <TableCell>{a.is_visible ? "Yes" : "No"}</TableCell>
                    <TableCell>{a.mfa_required ? "Required" : "—"}</TableCell>
                    <TableCell>
                      <span className="flex gap-1">
                        <RowButton label="Edit" onClick={() => setEditing(a)} />
                        <RowButton label="Bindings" onClick={() => setBindingsFor(a)} />
                        <RowButton label="Delete" onClick={() => setConfirmDelete(a)} />
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
    </div>
  );
}

function RowButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <Button type="button" variant="link" size="sm" className="h-auto p-1" onClick={onClick}>
      {label}
    </Button>
  );
}

function AppForm({
  submitLabel,
  initial,
  onSubmit,
  onDone,
  onError,
  onClose,
}: {
  submitLabel: string;
  initial?: AdminApp;
  onSubmit: (patch: AppPatch) => Promise<AdminApp>;
  onDone: (app: AdminApp) => void;
  onError: (n: AdminNotice) => void;
  onClose?: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [providerType, setProviderType] = useState(initial?.provider_type ?? "oidc");
  const [isVisible, setIsVisible] = useState(initial?.is_visible ?? true);
  const [mfaRequired, setMfaRequired] = useState(initial?.mfa_required ?? false);

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
        provider_type: providerType,
        is_visible: isVisible,
        mfa_required: mfaRequired,
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
    <form onSubmit={(e) => void submit(e)}>
      <FieldGroup>
        <div className="grid grid-cols-2 gap-x-3">
          <Field>
            <FieldLabel htmlFor="app-slug">Slug</FieldLabel>
            <Input id="app-slug" name="slug" defaultValue={initial?.slug ?? ""} required />
          </Field>
          <Field>
            <FieldLabel htmlFor="app-name">Name</FieldLabel>
            <Input id="app-name" name="name" defaultValue={initial?.name ?? ""} required />
          </Field>
        </div>
        <Field>
          <FieldLabel htmlFor="app-description">Description</FieldLabel>
          <Input id="app-description" name="description" defaultValue={initial?.description ?? ""} />
        </Field>
        <div className="grid grid-cols-2 gap-x-3">
          <Field>
            <FieldLabel htmlFor="app-protocol">Protocol</FieldLabel>
            <Select value={providerType} onValueChange={setProviderType}>
              <SelectTrigger id="app-protocol">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="oidc">oidc</SelectItem>
                <SelectItem value="saml">saml</SelectItem>
                <SelectItem value="ldap">ldap</SelectItem>
                <SelectItem value="radius">radius</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <Field>
            <FieldLabel htmlFor="app-group">Dashboard group</FieldLabel>
            <Input id="app-group" name="group_label" defaultValue={initial?.group_label ?? ""} />
          </Field>
        </div>
        <Field>
          <FieldLabel htmlFor="app-launch">Launch URL</FieldLabel>
          <Input
            id="app-launch"
            name="launch_url"
            defaultValue={initial?.launch_url ?? ""}
            placeholder="https://…"
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="app-icon">Icon URL</FieldLabel>
          <Input
            id="app-icon"
            name="icon_url"
            defaultValue={initial?.icon_url ?? ""}
            placeholder="/uploads/….png"
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="app-sort">Sort order</FieldLabel>
          <Input
            id="app-sort"
            name="sort_order"
            type="number"
            defaultValue={initial !== undefined ? initial.sort_order : ""}
            placeholder="0"
          />
        </Field>
        <div className="flex gap-4">
          <Field orientation="horizontal">
            <Checkbox
              id="app-visible"
              checked={isVisible}
              onCheckedChange={(v) => setIsVisible(v === true)}
            />
            <FieldLabel htmlFor="app-visible">Visible</FieldLabel>
          </Field>
          <Field orientation="horizontal">
            <Checkbox
              id="app-mfa"
              checked={mfaRequired}
              onCheckedChange={(v) => setMfaRequired(v === true)}
            />
            <FieldLabel htmlFor="app-mfa">Require MFA</FieldLabel>
          </Field>
        </div>
        <div className="flex gap-2">
          {onClose !== undefined && (
            <Button type="button" variant="outline" className="flex-1" onClick={onClose}>
              Cancel
            </Button>
          )}
          <Button type="submit" className="flex-1" disabled={busy}>
            {busy ? "Saving…" : submitLabel}
          </Button>
        </div>
      </FieldGroup>
    </form>
  );
}

function BindingsPanel({ app, onError }: { app: AdminApp; onError: (n: AdminNotice) => void }) {
  const [bindings, setBindings] = useState<AppBinding[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [kind, setKind] = useState("user");
  const [evalMode, setEvalMode] = useState("any");

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
      const target = String(form.get("target") ?? "").trim();
      const b: NewBinding = { binding_type: kind, eval_mode: evalMode };
      if (kind === "user") {
        b.user_id = await resolveUserId(target);
      } else if (kind === "group") {
        b.group_id = await resolveGroupId(target);
      } else {
        b.policy_expr = target;
      }
      await createBinding(app.id, b);
      (e.currentTarget as HTMLFormElement).reset();
      setKind("user");
      setEvalMode("any");
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
    <div aria-label={`Bindings of ${app.slug}`}>
      <form onSubmit={(e) => void add(e)} className="mb-3 flex flex-wrap gap-2">
        <Select value={kind} onValueChange={setKind}>
          <SelectTrigger aria-label="Binding type" className="w-28">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="user">user</SelectItem>
            <SelectItem value="group">group</SelectItem>
            <SelectItem value="policy">policy</SelectItem>
          </SelectContent>
        </Select>
        <Input
          name="target"
          placeholder={
            kind === "policy"
              ? "policy expression"
              : kind === "group"
                ? "Group name or ID"
                : "Username, email, or ID"
          }
          aria-label="Binding target"
          className="min-w-44 flex-1"
          required
        />
        <Select value={evalMode} onValueChange={setEvalMode}>
          <SelectTrigger aria-label="Eval mode" className="w-24">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="any">any</SelectItem>
            <SelectItem value="all">all</SelectItem>
          </SelectContent>
        </Select>
        <Button type="submit" variant="outline" disabled={busy}>
          Add
        </Button>
      </form>
      <Separator className="mb-2" />
      {bindings === null && <p className="text-sm text-muted-foreground">Loading bindings…</p>}
      {bindings !== null && bindings.length === 0 && (
        <p className="text-sm text-muted-foreground">No bindings: nobody sees this app yet.</p>
      )}
      {bindings !== null && bindings.length > 0 && (
        <ul className="m-0 list-none p-0 text-sm">
          {bindings.map((b) => (
            <li
              key={b.id}
              className="flex items-center justify-between gap-2 border-b py-1.5 last:border-b-0"
            >
              <span>
                <code>{b.binding_type}</code> · {bindingTarget(b)} · {b.eval_mode}
              </span>
              <Button
                type="button"
                variant="link"
                size="sm"
                className="h-auto shrink-0 p-1"
                disabled={busy}
                onClick={() => void remove(b.id)}
              >
                Remove
              </Button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function bindingTarget(b: AppBinding): string {
  if (b.user_id !== undefined) return b.user_id;
  if (b.group_id !== undefined) return b.group_id;
  return b.policy_expr ?? "—";
}
