import { useCallback, useEffect, useState } from "react";
import { ChevronDown, Plus } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/shared/ui/alert";
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/shared/ui/dropdown-menu";
import { Field, FieldGroup, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
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
import { Textarea } from "@/shared/ui/textarea";
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
// clients. Plaintext secrets are shown once at registration. One
// "Add provider" menu opens the per-protocol sheet in its section.
export function AdminProvidersPage() {
  const [apps, setApps] = useState<AdminApp[] | null>(null);
  const [notice, setNotice] = useState<AdminNotice | null>(null);
  const [form, setForm] = useState<ProviderForm | null>(null);

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
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold">Providers</h1>
        <div className="ml-auto">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button type="button" disabled={apps === null}>
                <Plus className="size-4" />
                Add provider
                <ChevronDown className="size-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onSelect={() => setForm("oidc")}>OIDC client</DropdownMenuItem>
              <DropdownMenuItem onSelect={() => setForm("saml")}>
                SAML service provider
              </DropdownMenuItem>
              <DropdownMenuItem onSelect={() => setForm("radius")}>RADIUS client</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>
      <p className="mt-1 mb-4 text-sm text-muted-foreground">
        Protocol credentials bound to catalog applications.
      </p>
      <Notice value={notice} />
      {apps === null && notice === null && (
        <div className="flex flex-col gap-2" aria-label="Loading">
          <Skeleton className="h-10 w-full" />
          <Skeleton className="h-10 w-full" />
        </div>
      )}
      {apps !== null && (
        <>
          <OIDCSection
            apps={apps}
            onError={setNotice}
            showForm={form === "oidc"}
            onOpenChange={(open) => setForm(open ? "oidc" : null)}
          />
          <SAMLSection
            apps={apps}
            onError={setNotice}
            showForm={form === "saml"}
            onOpenChange={(open) => setForm(open ? "saml" : null)}
          />
          <RADIUSSection
            apps={apps}
            onError={setNotice}
            showForm={form === "radius"}
            onOpenChange={(open) => setForm(open ? "radius" : null)}
          />
        </>
      )}
    </div>
  );
}

// ProviderForm names the sheet the Add provider menu opens; null closes all.
type ProviderForm = "oidc" | "saml" | "radius";

function AppSelect({
  apps,
  id,
  value,
  onChange,
}: {
  apps: AdminApp[];
  id: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <Field>
      <FieldLabel htmlFor={id}>Application</FieldLabel>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger id={id}>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {apps.map((a) => (
            <SelectItem key={a.id} value={a.id}>
              {a.slug} — {a.name}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </Field>
  );
}

function RowButton({
  label,
  disabled,
  onClick,
}: {
  label: string;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <Button
      type="button"
      variant="link"
      size="sm"
      className="h-auto p-1"
      disabled={disabled}
      onClick={onClick}
    >
      {label}
    </Button>
  );
}

function OIDCSection({
  apps,
  onError,
  showForm,
  onOpenChange,
}: {
  apps: AdminApp[];
  onError: (n: AdminNotice) => void;
  showForm: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [clients, setClients] = useState<OIDCClient[] | null>(null);
  const [secret, setSecret] = useState<{ clientId: string; value: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<OIDCClient | null>(null);

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

  async function remove(clientId: string) {
    setBusy(true);
    try {
      await deleteOIDCClient(clientId);
      setConfirmDelete(null);
      await load();
    } catch (err) {
      setConfirmDelete(null);
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="mb-8" aria-label="OIDC clients">
      <h2 className="mb-2 text-base font-semibold">OIDC clients</h2>
      {secret !== null && (
        <Alert role="status" className="mb-3">
          <AlertTitle>Client secret — shown once</AlertTitle>
          <AlertDescription>
            Client secret for <code>{secret.clientId}</code> — shown once, copy it now:{" "}
            <code className="font-mono break-all">{secret.value}</code>
            <div className="mt-2">
              <Button type="button" variant="outline" size="sm" onClick={() => setSecret(null)}>
                I saved it
              </Button>
            </div>
          </AlertDescription>
        </Alert>
      )}
      {clients !== null && clients.length > 0 && (
        <div className="mb-3 overflow-x-auto rounded-lg border bg-card">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Client ID</TableHead>
                <TableHead>Redirect URIs</TableHead>
                <TableHead>Scopes</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {clients.map((c) => (
                <TableRow key={c.client_id}>
                  <TableCell>{c.client_id}</TableCell>
                  <TableCell className="whitespace-normal">
                    {c.redirect_uris.join(", ") || "—"}
                  </TableCell>
                  <TableCell className="whitespace-normal">{c.scopes.join(", ") || "—"}</TableCell>
                  <TableCell>
                    <Badge variant="secondary">{c.public ? "public" : "confidential"}</Badge>
                  </TableCell>
                  <TableCell>
                    <RowButton label="Delete" disabled={busy} onClick={() => setConfirmDelete(c)} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {clients !== null && clients.length === 0 && (
        <p className="mb-3 text-sm text-muted-foreground">No OIDC clients yet.</p>
      )}
      <Sheet open={showForm} onOpenChange={onOpenChange}>
        <SheetContent className="gap-0">
          <SheetHeader className="border-b px-6 py-5">
            <SheetTitle>Register OIDC client</SheetTitle>
            <SheetDescription>One client per application; the secret shows once.</SheetDescription>
          </SheetHeader>
          <div className="min-h-0 flex-1 overflow-y-auto px-6 py-5">
            <OIDCForm
              apps={apps}
              onDone={(clientId, clientSecret) => {
                onOpenChange(false);
                if (clientSecret !== undefined) {
                  setSecret({ clientId, value: clientSecret });
                }
                void load();
              }}
              onError={onError}
            />
          </div>
        </SheetContent>
      </Sheet>
      <ConfirmDeleteDialog
        title={`Delete ${confirmDelete?.client_id ?? ""}?`}
        text="The client and its grants disappear immediately. This cannot be undone."
        open={confirmDelete !== null}
        busy={busy}
        onClose={() => setConfirmDelete(null)}
        onConfirm={() => { if (confirmDelete !== null) void remove(confirmDelete.client_id); }}
      />
    </section>
  );
}

function OIDCForm({
  apps,
  onDone,
  onError,
}: {
  apps: AdminApp[];
  onDone: (clientId: string, clientSecret: string | undefined) => void;
  onError: (n: AdminNotice) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [applicationId, setApplicationId] = useState(apps[0]?.id ?? "");
  const [isPublic, setIsPublic] = useState(false);

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
        application_id: applicationId,
        client_id: clientId,
        redirect_uris: split(form.get("redirect_uris")),
        scopes: split(form.get("scopes")),
        public: isPublic,
      });
      onDone(clientId, res.client_secret);
    } catch (err) {
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={(e) => void submit(e)}>
      <FieldGroup>
        <AppSelect apps={apps} id="oidc-app" value={applicationId} onChange={setApplicationId} />
        <Field>
          <FieldLabel htmlFor="oidc-client-id">Client ID</FieldLabel>
          <Input id="oidc-client-id" name="client_id" required />
        </Field>
        <Field>
          <FieldLabel htmlFor="oidc-redirects">Redirect URIs (space or comma separated)</FieldLabel>
          <Input
            id="oidc-redirects"
            name="redirect_uris"
            placeholder="https://app.example.com/callback"
          />
        </Field>
        <Field>
          <FieldLabel htmlFor="oidc-scopes">Scopes (space or comma separated)</FieldLabel>
          <Input id="oidc-scopes" name="scopes" placeholder="openid profile email" />
        </Field>
        <Field orientation="horizontal">
          <Checkbox id="oidc-public" checked={isPublic} onCheckedChange={(v) => setIsPublic(v === true)} />
          <FieldLabel htmlFor="oidc-public">Public client (no secret, PKCE)</FieldLabel>
        </Field>
      </FieldGroup>
      <div className="sticky bottom-0 -mx-6 mt-5 -mb-5 border-t bg-background px-6 py-4">
        <Button type="submit" className="w-full" disabled={busy}>
          {busy ? "Registering…" : "Register client"}
        </Button>
      </div>
    </form>
  );
}

function SAMLSection({
  apps,
  onError,
  showForm,
  onOpenChange,
}: {
  apps: AdminApp[];
  onError: (n: AdminNotice) => void;
  showForm: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [sps, setSps] = useState<SAMLSP[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<SAMLSP | null>(null);

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

  async function remove(entityId: string) {
    setBusy(true);
    try {
      await deleteSAMLSP(entityId);
      setConfirmDelete(null);
      await load();
    } catch (err) {
      setConfirmDelete(null);
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="mb-8" aria-label="SAML service providers">
      <h2 className="mb-2 text-base font-semibold">SAML service providers</h2>
      {sps !== null && sps.length > 0 && (
        <div className="mb-3 overflow-x-auto rounded-lg border bg-card">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Entity ID</TableHead>
                <TableHead>ACS URL</TableHead>
                <TableHead>SLO URL</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sps.map((sp) => (
                <TableRow key={sp.entity_id}>
                  <TableCell className="whitespace-normal">{sp.entity_id}</TableCell>
                  <TableCell className="whitespace-normal">{sp.acs_url}</TableCell>
                  <TableCell className="whitespace-normal">{sp.slo_url || "—"}</TableCell>
                  <TableCell>
                    <RowButton label="Delete" disabled={busy} onClick={() => setConfirmDelete(sp)} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {sps !== null && sps.length === 0 && (
        <p className="mb-3 text-sm text-muted-foreground">No SAML service providers yet.</p>
      )}
      <Sheet open={showForm} onOpenChange={onOpenChange}>
        <SheetContent className="gap-0">
          <SheetHeader className="border-b px-6 py-5">
            <SheetTitle>Import SAML SP</SheetTitle>
            <SheetDescription>Paste the app&apos;s SP metadata XML.</SheetDescription>
          </SheetHeader>
          <div className="min-h-0 flex-1 overflow-y-auto px-6 py-5">
            <SAMLForm
              apps={apps}
              onDone={() => {
                onOpenChange(false);
                void load();
              }}
              onError={onError}
            />
          </div>
        </SheetContent>
      </Sheet>
      <ConfirmDeleteDialog
        title={`Delete ${confirmDelete?.entity_id ?? ""}?`}
        text="The service provider disappears immediately. This cannot be undone."
        open={confirmDelete !== null}
        busy={busy}
        onClose={() => setConfirmDelete(null)}
        onConfirm={() => { if (confirmDelete !== null) void remove(confirmDelete.entity_id); }}
      />
    </section>
  );
}

function SAMLForm({
  apps,
  onDone,
  onError,
}: {
  apps: AdminApp[];
  onDone: () => void;
  onError: (n: AdminNotice) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [applicationId, setApplicationId] = useState(apps[0]?.id ?? "");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const form = new FormData(e.currentTarget as HTMLFormElement);
      await importSAMLSP(applicationId, String(form.get("metadata_xml") ?? ""));
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
        <AppSelect apps={apps} id="saml-app" value={applicationId} onChange={setApplicationId} />
        <Field>
          <FieldLabel htmlFor="saml-metadata">SP metadata XML</FieldLabel>
          <Textarea
            id="saml-metadata"
            name="metadata_xml"
            className="min-h-30 font-mono text-xs"
            placeholder="<EntityDescriptor …>…</EntityDescriptor>"
            required
          />
        </Field>
      </FieldGroup>
      <div className="sticky bottom-0 -mx-6 mt-5 -mb-5 border-t bg-background px-6 py-4">
        <Button type="submit" className="w-full" disabled={busy}>
          {busy ? "Importing…" : "Import SP"}
        </Button>
      </div>
    </form>
  );
}

function RADIUSSection({
  apps,
  onError,
  showForm,
  onOpenChange,
}: {
  apps: AdminApp[];
  onError: (n: AdminNotice) => void;
  showForm: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const [clients, setClients] = useState<RADIUSClient[] | null>(null);
  const [secret, setSecret] = useState<{ nas: string; value: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<RADIUSClient | null>(null);

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

  async function remove(nas: string) {
    setBusy(true);
    try {
      await deleteRADIUSClient(nas);
      setConfirmDelete(null);
      await load();
    } catch (err) {
      setConfirmDelete(null);
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="mb-2" aria-label="RADIUS clients">
      <h2 className="mb-2 text-base font-semibold">RADIUS clients</h2>
      {secret !== null && (
        <Alert role="status" className="mb-3">
          <AlertTitle>Shared secret — shown once</AlertTitle>
          <AlertDescription>
            Shared secret for <code>{secret.nas}</code> — shown once, copy it now:{" "}
            <code className="font-mono break-all">{secret.value}</code>
            <div className="mt-2">
              <Button type="button" variant="outline" size="sm" onClick={() => setSecret(null)}>
                I saved it
              </Button>
            </div>
          </AlertDescription>
        </Alert>
      )}
      {clients !== null && clients.length > 0 && (
        <div className="mb-3 overflow-x-auto rounded-lg border bg-card">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>NAS identifier</TableHead>
                <TableHead>Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {clients.map((c) => (
                <TableRow key={c.nas_identifier}>
                  <TableCell>{c.nas_identifier}</TableCell>
                  <TableCell>
                    <RowButton label="Delete" disabled={busy} onClick={() => setConfirmDelete(c)} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {clients !== null && clients.length === 0 && (
        <p className="text-sm text-muted-foreground">No RADIUS clients yet.</p>
      )}
      <Sheet open={showForm} onOpenChange={onOpenChange}>
        <SheetContent className="gap-0">
          <SheetHeader className="border-b px-6 py-5">
            <SheetTitle>Register RADIUS client</SheetTitle>
            <SheetDescription>One NAS device per application.</SheetDescription>
          </SheetHeader>
          <div className="min-h-0 flex-1 overflow-y-auto px-6 py-5">
            <RADIUSForm
              apps={apps}
              onDone={(nas, value) => {
                onOpenChange(false);
                setSecret({ nas, value });
                void load();
              }}
              onError={onError}
            />
          </div>
        </SheetContent>
      </Sheet>
      <ConfirmDeleteDialog
        title={`Delete ${confirmDelete?.nas_identifier ?? ""}?`}
        text="The NAS client disappears immediately. This cannot be undone."
        open={confirmDelete !== null}
        busy={busy}
        onClose={() => setConfirmDelete(null)}
        onConfirm={() => { if (confirmDelete !== null) void remove(confirmDelete.nas_identifier); }}
      />
    </section>
  );
}

function RADIUSForm({
  apps,
  onDone,
  onError,
}: {
  apps: AdminApp[];
  onDone: (nas: string, secret: string) => void;
  onError: (n: AdminNotice) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [applicationId, setApplicationId] = useState(apps[0]?.id ?? "");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const form = new FormData(e.currentTarget as HTMLFormElement);
      const nas = String(form.get("nas_identifier") ?? "");
      const res = await registerRADIUSClient({
        application_id: applicationId,
        nas_identifier: nas,
        shared_secret: String(form.get("shared_secret") ?? ""),
      });
      onDone(nas, res.shared_secret);
    } catch (err) {
      onError(toNotice(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={(e) => void submit(e)}>
      <FieldGroup>
        <AppSelect apps={apps} id="radius-app" value={applicationId} onChange={setApplicationId} />
        <Field>
          <FieldLabel htmlFor="radius-nas">NAS identifier</FieldLabel>
          <Input id="radius-nas" name="nas_identifier" required placeholder="vpn-gateway-1" />
        </Field>
        <Field>
          <FieldLabel htmlFor="radius-secret">Shared secret</FieldLabel>
          <Input
            id="radius-secret"
            name="shared_secret"
            type="password"
            autoComplete="new-password"
            required
          />
        </Field>
      </FieldGroup>
      <div className="sticky bottom-0 -mx-6 mt-5 -mb-5 border-t bg-background px-6 py-4">
        <Button type="submit" className="w-full" disabled={busy}>
          {busy ? "Registering…" : "Register client"}
        </Button>
      </div>
    </form>
  );
}

function ConfirmDeleteDialog({
  title,
  text,
  open,
  busy,
  onClose,
  onConfirm,
}: {
  title: string;
  text: string;
  open: boolean;
  busy: boolean;
  onClose: () => void;
  onConfirm: () => void;
}) {
  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o) onClose(); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{text}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button type="button" variant="destructive" disabled={busy} onClick={onConfirm}>
            {busy ? "Deleting…" : "Delete"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
