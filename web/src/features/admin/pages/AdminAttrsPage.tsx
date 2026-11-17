import { useCallback, useEffect, useState } from "react";
import { Plus } from "lucide-react";
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
import { Textarea } from "@/shared/ui/textarea";
import {
  createAttrDef,
  deleteAttrDef,
  getUserAttrs,
  listAttrDefs,
  resolveUserId,
  setUserAttrs,
  type AttrDef,
  type AttrValue,
} from "../api";
import { Notice, toNotice, type AdminNotice } from "../components/adminUi";

// Admin custom-attributes console: the schema (key, type, multi-valued)
// plus per-user values. Keys double as the wire names on LDAP, OIDC and
// SAML; the backend rejects reserved names. Values set here are
// admin-sourced — upstream-mapped keys are overwritten by directory sync.
export function AdminAttrsPage() {
  const [defs, setDefs] = useState<AttrDef[] | null>(null);
  const [notice, setNotice] = useState<AdminNotice | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<AttrDef | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);

  const load = useCallback(async () => {
    setNotice(null);
    try {
      const res = await listAttrDefs();
      setDefs(res.defs);
    } catch (err) {
      setNotice(toNotice(err));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function runDelete(d: AttrDef) {
    setDeleteBusy(true);
    setNotice(null);
    try {
      await deleteAttrDef(d.key);
      setConfirmDelete(null);
      setDefs((prev) => prev?.filter((x) => x.key !== d.key) ?? null);
    } catch (err) {
      setConfirmDelete(null);
      setNotice(toNotice(err));
    } finally {
      setDeleteBusy(false);
    }
  }

  return (
    <div>
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold">Custom attributes</h1>
        <div className="ml-auto">
          <Button type="button" onClick={() => setShowCreate(true)}>
            <Plus className="size-4" />
            Add attribute
          </Button>
        </div>
      </div>
      <p className="mt-1 mb-4 text-sm text-muted-foreground">
        Schema first, values per user below. Attributes ride LDAP search, OIDC claims, and SAML
        assertions under their key.
      </p>

      <Notice value={notice} />

      <Sheet open={showCreate} onOpenChange={setShowCreate}>
        <SheetContent className="gap-0">
          <SheetHeader className="border-b px-6 py-5">
            <SheetTitle>Add attribute</SheetTitle>
            <SheetDescription>
              Lowercase key, value type, and whether it takes multiple values.
            </SheetDescription>
          </SheetHeader>
          <div className="min-h-0 flex-1 overflow-y-auto px-6 py-5">
            <CreateDefForm
              onDone={() => {
                setShowCreate(false);
                void load();
              }}
              onError={setNotice}
            />
          </div>
        </SheetContent>
      </Sheet>

      <Dialog open={confirmDelete !== null} onOpenChange={(open) => { if (!open) setConfirmDelete(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete {confirmDelete?.key}?</DialogTitle>
            <DialogDescription>
              The attribute and every user&apos;s value disappear immediately. This cannot be
              undone.
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
              {deleteBusy ? "Deleting…" : "Delete attribute"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {defs === null && notice === null && (
        <div className="flex flex-col gap-2" aria-label="Loading attributes">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      )}
      {defs !== null && (
        <div className="overflow-x-auto rounded-lg border bg-card">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Key</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Multi</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {defs.map((d) => (
                <TableRow key={d.key}>
                  <TableCell className="font-mono text-[13px]">{d.key}</TableCell>
                  <TableCell>
                    <Badge variant="secondary">{d.type}</Badge>
                  </TableCell>
                  <TableCell>{d.multi ? "yes" : "—"}</TableCell>
                  <TableCell>
                    <Button
                      type="button"
                      variant="link"
                      size="sm"
                      className="h-auto p-1"
                      onClick={() => setConfirmDelete(d)}
                    >
                      Delete
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {defs !== null && defs.length === 0 && (
        <p className="mt-3 text-sm text-muted-foreground">
          No custom attributes yet. Add one to start storing per-user values.
        </p>
      )}

      <Separator className="my-6" />
      <UserValues defs={defs ?? []} onError={setNotice} />
    </div>
  );
}

function CreateDefForm({
  onDone,
  onError,
}: {
  onDone: () => void;
  onError: (n: AdminNotice) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [type, setType] = useState("string");
  const [multi, setMulti] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const form = new FormData(e.currentTarget as HTMLFormElement);
      await createAttrDef({ key: String(form.get("key") ?? ""), type, multi });
      onDone();
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
          <FieldLabel htmlFor="new-attr-key">Key</FieldLabel>
          <Input id="new-attr-key" name="key" placeholder="department" required />
        </Field>
        <Field>
          <FieldLabel htmlFor="new-attr-type">Type</FieldLabel>
          <Select value={type} onValueChange={setType}>
            <SelectTrigger id="new-attr-type">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="string">string</SelectItem>
              <SelectItem value="number">number</SelectItem>
              <SelectItem value="boolean">boolean</SelectItem>
            </SelectContent>
          </Select>
        </Field>
        <Field orientation="horizontal">
          <Checkbox id="new-attr-multi" checked={multi} onCheckedChange={(v) => setMulti(v === true)} />
          <FieldLabel htmlFor="new-attr-multi">Multi-valued</FieldLabel>
        </Field>
      </FieldGroup>
      <div className="sticky bottom-0 -mx-6 mt-5 -mb-5 border-t bg-background px-6 py-4">
        <Button type="submit" className="w-full" disabled={busy}>
          {busy ? "Creating…" : "Create attribute"}
        </Button>
      </div>
    </form>
  );
}

// UserValues edits one user's values: pick the user by login, then one
// editor per def (multi-valued defs take one value per line). Clearing
// an editor clears the key on save.
function UserValues({
  defs,
  onError,
}: {
  defs: AttrDef[];
  onError: (n: AdminNotice) => void;
}) {
  const [login, setLogin] = useState("");
  const [subject, setSubject] = useState<{ id: string; label: string } | null>(null);
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [loadBusy, setLoadBusy] = useState(false);
  const [saveBusy, setSaveBusy] = useState(false);
  const [savedTick, setSavedTick] = useState(0);

  async function load(e: React.FormEvent) {
    e.preventDefault();
    setLoadBusy(true);
    try {
      const id = await resolveUserId(login);
      const { attrs } = await getUserAttrs(id);
      setSubject({ id, label: login.trim() });
      const next: Record<string, string> = {};
      for (const d of defs) {
        const v = attrs[d.key];
        next[d.key] = v === undefined ? "" : toDraft(v);
      }
      setDrafts(next);
    } catch (err) {
      setSubject(null);
      onError(toNotice(err));
    } finally {
      setLoadBusy(false);
    }
  }

  async function save() {
    if (subject === null) return;
    setSaveBusy(true);
    try {
      const body: Record<string, AttrValue | null> = {};
      for (const d of defs) {
        const raw = drafts[d.key] ?? "";
        if (d.multi) {
          const lines = raw
            .split("\n")
            .map((l) => l.trim())
            .filter((l) => l !== "");
          body[d.key] = lines.length > 0 ? lines : null;
        } else {
          body[d.key] = raw.trim() === "" ? null : raw.trim();
        }
      }
      const { attrs } = await setUserAttrs(subject.id, body);
      const next: Record<string, string> = {};
      for (const d of defs) {
        const v = attrs[d.key];
        next[d.key] = v === undefined ? "" : toDraft(v);
      }
      setDrafts(next);
      setSavedTick((t) => t + 1);
    } catch (err) {
      onError(toNotice(err));
    } finally {
      setSaveBusy(false);
    }
  }

  return (
    <section aria-label="User values">
      <h2 className="text-lg font-semibold">User values</h2>
      <p className="mt-1 mb-4 text-sm text-muted-foreground">
        Load a user, edit each attribute, then save. Upstream-mapped keys are overwritten by the
        next directory sync.
      </p>
      <form onSubmit={(e) => void load(e)} className="mb-4 flex max-w-xl flex-wrap gap-2">
        <Input
          name="login"
          value={login}
          onChange={(e) => setLogin(e.target.value)}
          placeholder="Username, email, or user ID"
          aria-label="User to edit"
          className="min-w-48 flex-1"
          required
        />
        <Button type="submit" variant="outline" disabled={loadBusy}>
          {loadBusy ? "Loading…" : "Load"}
        </Button>
      </form>
      {subject !== null && defs.length === 0 && (
        <p className="text-sm text-muted-foreground">Define an attribute above first.</p>
      )}
      {subject !== null && defs.length > 0 && (
        <div className="max-w-xl">
          <p className="mb-3 text-sm text-muted-foreground">
            Editing <span className="font-medium text-foreground">{subject.label}</span>
            {savedTick > 0 && <span key={savedTick}> · Saved.</span>}
          </p>
          <FieldGroup>
            {defs.map((d) => (
              <Field key={d.key}>
                <FieldLabel htmlFor={`attr-value-${d.key}`}>
                  <span className="font-mono text-[13px]">{d.key}</span>
                  <span className="ml-2 font-normal text-muted-foreground">
                    {d.type}
                    {d.multi ? " · multi" : ""}
                  </span>
                </FieldLabel>
                {d.multi ? (
                  <Textarea
                    id={`attr-value-${d.key}`}
                    value={drafts[d.key] ?? ""}
                    onChange={(e) => setDrafts((prev) => ({ ...prev, [d.key]: e.target.value }))}
                    placeholder="one value per line"
                    rows={3}
                  />
                ) : d.type === "boolean" ? (
                  <Select
                    value={drafts[d.key] === "" || drafts[d.key] === undefined ? "unset" : drafts[d.key]}
                    onValueChange={(v) =>
                      setDrafts((prev) => ({ ...prev, [d.key]: v === "unset" ? "" : v }))
                    }
                  >
                    <SelectTrigger id={`attr-value-${d.key}`}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="unset">Unset</SelectItem>
                      <SelectItem value="true">true</SelectItem>
                      <SelectItem value="false">false</SelectItem>
                    </SelectContent>
                  </Select>
                ) : (
                  <Input
                    id={`attr-value-${d.key}`}
                    value={drafts[d.key] ?? ""}
                    onChange={(e) => setDrafts((prev) => ({ ...prev, [d.key]: e.target.value }))}
                    placeholder={d.type === "number" ? "3" : "value"}
                  />
                )}
              </Field>
            ))}
          </FieldGroup>
          <div className="mt-4">
            <Button type="button" onClick={() => void save()} disabled={saveBusy}>
              {saveBusy ? "Saving…" : "Save values"}
            </Button>
          </div>
        </div>
      )}
    </section>
  );
}

// toDraft renders a typed value back into its editor text.
function toDraft(v: AttrValue): string {
  if (Array.isArray(v)) {
    return v.map((e) => String(e)).join("\n");
  }
  return String(v);
}
