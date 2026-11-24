import type { Branding } from "@/features/branding/api";
import { ApiError } from "@/shared/api/client";

// Typed client for the admin JSON API (TECH_SPEC §6.1). Every function
// mirrors one backend handler; failures throw ApiError carrying the HTTP
// status and the user-facing {error} message, so pages only branch on
// status (401 → sign in, 403 → forbidden/step-up, else notice).

export interface AdminUser {
  id: string;
  username: string;
  email: string;
  display_name: string;
  source: string;
  is_active: boolean;
  avatar_url: string;
  groups: string[];
  is_admin: boolean;
}

export interface AdminGroup {
  id: string;
  name: string;
  description: string;
  member_count: number;
}

export interface AdminGroupDetail {
  id: string;
  name: string;
  description: string;
  members: string[];
}

export interface AdminApp {
  id: string;
  slug: string;
  name: string;
  description: string;
  icon_url: string;
  launch_url: string;
  group_label: string;
  provider_type: string;
  is_visible: boolean;
  sort_order: number;
  mfa_required: boolean;
  open_in_new_tab: boolean;
}

export interface AppBinding {
  id: string;
  application_id: string;
  binding_type: string;
  user_id?: string;
  group_id?: string;
  policy_expr?: string;
  eval_mode: string;
  effect: string;
}

export interface OIDCClient {
  application_id: string;
  client_id: string;
  redirect_uris: string[];
  scopes: string[];
  public: boolean;
}

export interface SAMLSP {
  application_id: string;
  entity_id: string;
  acs_url: string;
  slo_url: string;
}

export interface RADIUSClient {
  application_id: string;
  nas_identifier: string;
}

export interface AuditEntry {
  id: number;
  at: string;
  actor_user_id: string | null;
  application_id: string | null;
  method: string;
  result: string;
  ip: string;
  detail: unknown;
}

export const ADMIN_PAGE_SIZE = 20;

async function toApiError(res: Response): Promise<ApiError> {
  const data = (await res.json().catch(() => null)) as {
    error?: string;
    mfa_required?: boolean;
  } | null;
  return new ApiError(
    res.status,
    data?.error ?? `Request failed (${res.status})`,
    data?.mfa_required === true,
  );
}

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(path);
  if (!res.ok) {
    throw await toApiError(res);
  }
  return (await res.json()) as T;
}

async function sendJSON<T>(path: string, method: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    throw await toApiError(res);
  }
  return (await res.json()) as T;
}

async function sendVoid(path: string, method: string, body?: unknown): Promise<void> {
  const init: RequestInit = { method, headers: { "Content-Type": "application/json" } };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }
  const res = await fetch(path, init);
  if (!res.ok) {
    throw await toApiError(res);
  }
}

// ---------- users ----------

export interface UserListParams {
  q?: string;
  source?: string;
  active?: boolean;
  limit?: number;
  offset?: number;
}

export function listUsers(p: UserListParams = {}): Promise<{ users: AdminUser[]; total: number }> {
  const q = new URLSearchParams();
  if (p.q !== undefined && p.q !== "") q.set("q", p.q);
  if (p.source !== undefined && p.source !== "") q.set("source", p.source);
  if (p.active !== undefined) q.set("active", p.active ? "true" : "false");
  q.set("limit", String(p.limit ?? ADMIN_PAGE_SIZE));
  q.set("offset", String(p.offset ?? 0));
  return getJSON(`/api/admin/users?${q.toString()}`);
}

export interface NewUser {
  username: string;
  email: string;
  display_name: string;
  password: string;
  source?: string;
  external_dn?: string;
}

export function createUser(u: NewUser): Promise<{ user: AdminUser }> {
  return sendJSON("/api/admin/users", "POST", u);
}

export function getUser(id: string): Promise<{ user: AdminUser }> {
  return getJSON(`/api/admin/users/${encodeURIComponent(id)}`);
}

export interface UserPatch {
  display_name?: string;
  email?: string;
  avatar_url?: string;
  is_active?: boolean;
}

export function updateUser(id: string, patch: UserPatch): Promise<{ user: AdminUser }> {
  return sendJSON(`/api/admin/users/${encodeURIComponent(id)}`, "PATCH", patch);
}

export function setUserPassword(id: string, newPassword: string): Promise<void> {
  return sendVoid(`/api/admin/users/${encodeURIComponent(id)}/password`, "POST", {
    new_password: newPassword,
  });
}

export function resetUserMFA(id: string): Promise<void> {
  return sendVoid(`/api/admin/users/${encodeURIComponent(id)}/mfa/reset`, "POST");
}

// setAdmin grants/revokes membership in the reserved ih_admin group
// (there is no admin flag on the user row itself).
export async function setAdmin(userId: string, makeAdmin: boolean): Promise<void> {
  const { groups } = await listGroups({ limit: 200 });
  const admin = groups.find((g) => g.name === "ih_admin");
  if (!admin) {
    throw new ApiError(500, "The ih_admin group is missing.");
  }
  if (makeAdmin) {
    await addMember(admin.id, userId);
  } else {
    await removeMember(admin.id, userId);
  }
}

const uuidRe = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// resolveUserId accepts a pasted UUID or a username/email (exact match).
export async function resolveUserId(login: string): Promise<string> {
  const trimmed = login.trim();
  if (uuidRe.test(trimmed)) {
    return trimmed;
  }
  const { users } = await listUsers({ q: trimmed, limit: 10 });
  const match = users.find((u) => u.username === trimmed || u.email === trimmed) ?? users[0];
  if (!match) {
    throw new ApiError(404, `No user "${trimmed}".`);
  }
  return match.id;
}

// ---------- groups ----------

export function listGroups(
  p: { limit?: number; offset?: number } = {},
): Promise<{ groups: AdminGroup[]; total: number }> {
  const q = new URLSearchParams({
    limit: String(p.limit ?? ADMIN_PAGE_SIZE),
    offset: String(p.offset ?? 0),
  });
  return getJSON(`/api/admin/groups?${q.toString()}`);
}

export function createGroup(name: string, description: string): Promise<{ group: AdminGroupDetail }> {
  return sendJSON("/api/admin/groups", "POST", { name, description });
}

export function getGroup(id: string): Promise<{ group: AdminGroupDetail }> {
  return getJSON(`/api/admin/groups/${encodeURIComponent(id)}`);
}

export function deleteGroup(id: string): Promise<void> {
  return sendVoid(`/api/admin/groups/${encodeURIComponent(id)}`, "DELETE");
}

export function addMember(groupId: string, userId: string): Promise<void> {
  return sendVoid(`/api/admin/groups/${encodeURIComponent(groupId)}/members`, "POST", {
    user_id: userId,
  });
}

export function removeMember(groupId: string, userId: string): Promise<void> {
  return sendVoid(
    `/api/admin/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(userId)}`,
    "DELETE",
  );
}

// resolveGroupId accepts a pasted UUID or an exact group name.
export async function resolveGroupId(name: string): Promise<string> {
  const trimmed = name.trim();
  if (uuidRe.test(trimmed)) {
    return trimmed;
  }
  const { groups } = await listGroups({ limit: 200 });
  const match = groups.find((g) => g.name === trimmed);
  if (!match) {
    throw new ApiError(404, `No group "${trimmed}".`);
  }
  return match.id;
}

// ---------- apps + bindings ----------

export interface AppListParams {
  q?: string;
  group?: string;
  limit?: number;
  offset?: number;
}

export function listApps(p: AppListParams = {}): Promise<{ apps: AdminApp[]; total: number }> {
  const q = new URLSearchParams({
    limit: String(p.limit ?? ADMIN_PAGE_SIZE),
    offset: String(p.offset ?? 0),
  });
  if (p.q !== undefined && p.q !== "") q.set("q", p.q);
  if (p.group !== undefined && p.group !== "") q.set("group", p.group);
  return getJSON(`/api/admin/apps?${q.toString()}`);
}

export interface AppPatch {
  slug?: string;
  name?: string;
  description?: string;
  icon_url?: string;
  launch_url?: string;
  group_label?: string;
  provider_type?: string;
  is_visible?: boolean;
  sort_order?: number;
  mfa_required?: boolean;
  open_in_new_tab?: boolean;
}

export function createApp(a: AppPatch): Promise<{ app: AdminApp }> {
  return sendJSON("/api/admin/apps", "POST", a);
}

export function getApp(id: string): Promise<{ app: AdminApp }> {
  return getJSON(`/api/admin/apps/${encodeURIComponent(id)}`);
}

export function updateApp(id: string, patch: AppPatch): Promise<{ app: AdminApp }> {
  return sendJSON(`/api/admin/apps/${encodeURIComponent(id)}`, "PATCH", patch);
}

export function deleteApp(id: string): Promise<void> {
  return sendVoid(`/api/admin/apps/${encodeURIComponent(id)}`, "DELETE");
}

export function listBindings(appId: string): Promise<{ bindings: AppBinding[] }> {
  return getJSON(`/api/admin/apps/${encodeURIComponent(appId)}/bindings`);
}

export interface NewBinding {
  binding_type: string;
  user_id?: string;
  group_id?: string;
  policy_expr?: string;
  eval_mode?: string;
  effect?: string;
}

export function createBinding(appId: string, b: NewBinding): Promise<{ binding: AppBinding }> {
  return sendJSON(`/api/admin/apps/${encodeURIComponent(appId)}/bindings`, "POST", b);
}

export function deleteBinding(appId: string, bindingId: string): Promise<void> {
  return sendVoid(
    `/api/admin/apps/${encodeURIComponent(appId)}/bindings/${encodeURIComponent(bindingId)}`,
    "DELETE",
  );
}

// ---------- providers ----------

export function listOIDCClients(
  p: { limit?: number; offset?: number } = {},
): Promise<{ clients: OIDCClient[]; total: number }> {
  const q = new URLSearchParams({
    limit: String(p.limit ?? ADMIN_PAGE_SIZE),
    offset: String(p.offset ?? 0),
  });
  return getJSON(`/api/admin/oidc/clients?${q.toString()}`);
}

export interface NewOIDCClient {
  application_id: string;
  client_id: string;
  redirect_uris: string[];
  scopes: string[];
  public: boolean;
}

export function registerOIDCClient(
  c: NewOIDCClient,
): Promise<{ client: OIDCClient; client_secret?: string }> {
  return sendJSON("/api/admin/oidc/clients", "POST", c);
}

export function deleteOIDCClient(clientID: string): Promise<void> {
  return sendVoid(`/api/admin/oidc/clients/${encodeURIComponent(clientID)}`, "DELETE");
}

export function listSAMLSPs(
  p: { limit?: number; offset?: number } = {},
): Promise<{ sps: SAMLSP[]; total: number }> {
  const q = new URLSearchParams({
    limit: String(p.limit ?? ADMIN_PAGE_SIZE),
    offset: String(p.offset ?? 0),
  });
  return getJSON(`/api/admin/saml/sps?${q.toString()}`);
}

export function importSAMLSP(applicationId: string, metadataXML: string): Promise<{ sp: SAMLSP }> {
  return sendJSON("/api/admin/saml/sps", "POST", {
    application_id: applicationId,
    metadata_xml: metadataXML,
  });
}

export function deleteSAMLSP(entityID: string): Promise<void> {
  return sendVoid(`/api/admin/saml/sps?entity_id=${encodeURIComponent(entityID)}`, "DELETE");
}

export function listRADIUSClients(
  p: { limit?: number; offset?: number } = {},
): Promise<{ clients: RADIUSClient[]; total: number }> {
  const q = new URLSearchParams({
    limit: String(p.limit ?? ADMIN_PAGE_SIZE),
    offset: String(p.offset ?? 0),
  });
  return getJSON(`/api/admin/radius/clients?${q.toString()}`);
}

export function registerRADIUSClient(c: {
  application_id: string;
  nas_identifier: string;
  shared_secret: string;
}): Promise<{ client: RADIUSClient; shared_secret: string }> {
  return sendJSON("/api/admin/radius/clients", "POST", c);
}

export function deleteRADIUSClient(nas: string): Promise<void> {
  return sendVoid(`/api/admin/radius/clients/${encodeURIComponent(nas)}`, "DELETE");
}

// ---------- custom attributes ----------

export interface AttrDef {
  key: string;
  type: string;
  multi: boolean;
}

export type AttrValue = string | number | boolean | Array<string | number | boolean>;

export function listAttrDefs(): Promise<{ defs: AttrDef[] }> {
  return getJSON("/api/admin/user-attrs");
}

export function createAttrDef(d: { key: string; type: string; multi: boolean }): Promise<{ def: AttrDef }> {
  return sendJSON("/api/admin/user-attrs", "POST", d);
}

export function deleteAttrDef(key: string): Promise<void> {
  return sendVoid(`/api/admin/user-attrs/${encodeURIComponent(key)}`, "DELETE");
}

export function getUserAttrs(id: string): Promise<{ attrs: Record<string, AttrValue> }> {
  return getJSON(`/api/admin/users/${encodeURIComponent(id)}/attrs`);
}

export function setUserAttrs(
  id: string,
  attrs: Record<string, AttrValue | null>,
): Promise<{ attrs: Record<string, AttrValue> }> {
  return sendJSON(`/api/admin/users/${encodeURIComponent(id)}/attrs`, "PUT", attrs);
}

// AttrDrafts are the editor texts keyed by def key: multi-valued defs
// join values with newlines, booleans use "true"/"false"/"" (unset).
export type AttrDrafts = Record<string, string>;

// attrsToDrafts renders typed values back into editor texts.
export function attrsToDrafts(defs: AttrDef[], attrs: Record<string, AttrValue>): AttrDrafts {
  const drafts: AttrDrafts = {};
  for (const d of defs) {
    const v = attrs[d.key];
    if (v === undefined) {
      drafts[d.key] = "";
    } else if (Array.isArray(v)) {
      drafts[d.key] = v.map((e) => String(e)).join("\n");
    } else {
      drafts[d.key] = String(v);
    }
  }
  return drafts;
}

// draftsToBody converts editor texts into a PUT body: blank editors
// clear the key (null), multi-valued editors split on newlines.
export function draftsToBody(
  defs: AttrDef[],
  drafts: AttrDrafts,
): Record<string, AttrValue | null> {
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
  return body;
}

// hasAttrDraft reports whether any editor holds a value (create sheets
// skip the PUT when nothing was filled in).
export function hasAttrDraft(drafts: AttrDrafts): boolean {
  return Object.values(drafts).some((v) => v.trim() !== "");
}

// ---------- LDAP upstream ----------

export interface LDAPTestResult {
  configured: boolean;
  ok: boolean;
  error?: string;
}

// testLDAP pings the upstream directory (PRD §6.2). The backend always
// answers 200 with the outcome; transport failures throw ApiError.
export function testLDAP(): Promise<LDAPTestResult> {
  return sendJSON("/api/admin/ldap/test", "POST", {});
}

// ---------- branding ----------

export interface BrandingPatch {
  org_name?: string;
  tagline?: string;
  logo_url?: string;
  favicon_url?: string;
  primary_color?: string;
  theme?: string;
  login_background_url?: string;
  custom_css?: string;
  dashboard_columns?: number;
  dashboard_icon_shape?: string;
  dashboard_density?: string;
  dashboard_background?: string;
  dashboard_background_url?: string;
}

export function updateBranding(patch: BrandingPatch): Promise<{ branding: Branding }> {
  return sendJSON("/api/admin/branding", "PATCH", patch);
}

// ---------- audit ----------

export interface AuditListParams {
  actor?: string;
  app?: string;
  method?: string;
  result?: string;
  since?: string;
  until?: string;
  limit?: number;
  offset?: number;
}

function auditQuery(p: AuditListParams): string {
  const q = new URLSearchParams();
  if (p.actor !== undefined && p.actor !== "") q.set("actor", p.actor);
  if (p.app !== undefined && p.app !== "") q.set("app", p.app);
  if (p.method !== undefined && p.method !== "") q.set("method", p.method);
  if (p.result !== undefined && p.result !== "") q.set("result", p.result);
  if (p.since !== undefined && p.since !== "") q.set("since", p.since);
  if (p.until !== undefined && p.until !== "") q.set("until", p.until);
  q.set("limit", String(p.limit ?? ADMIN_PAGE_SIZE));
  q.set("offset", String(p.offset ?? 0));
  return q.toString();
}

export function listAudit(p: AuditListParams = {}): Promise<{ entries: AuditEntry[]; total: number }> {
  return getJSON(`/api/admin/audit?${auditQuery(p)}`);
}

// exportAuditURL carries the same filters as the list view (minus
// paging) so the CSV matches what the admin sees.
export function exportAuditURL(p: AuditListParams = {}): string {
  const q = new URLSearchParams();
  for (const [k, v] of new URLSearchParams(auditQuery(p)).entries()) {
    if (k !== "limit" && k !== "offset") q.set(k, v);
  }
  const s = q.toString();
  return s === "" ? "/api/admin/audit/export" : `/api/admin/audit/export?${s}`;
}
