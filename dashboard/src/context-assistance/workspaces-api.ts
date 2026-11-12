import { fetchWithGuardAuth } from "../guard-api";
import { isGuardDemoMode } from "../guard-demo";
import { ContextAssistanceApiError } from "./api";

export type ContextSource = { source_id: string; path: string; sha256: string; documents: number };
export type ContextNotesAccess = { read: boolean; propose: boolean };
export type ContextBrokerRevision = { epoch: string; version: string };
export type ContextSharing = {
  mode: "private_graph" | "private_broker" | "shared_broker";
  notes: ContextNotesAccess & { documents: number; revision: ContextBrokerRevision | null };
  client_lease_seconds: number | null;
};
export type ContextWorkspaceScope = {
  scope_id: string; workspace: string; app: string; policy_revision: string;
  sources: ContextSource[]; retained_contexts: number; revoked: boolean;
  native_policy_facts?: boolean;
  sharing?: ContextSharing;
  receipt_window?: { enabled: boolean; retained: number; dropped: string; coverage: "bounded_recent_native_receipts" };
};
export type ContextBrief = {
  schema: "guard-cigar-context-brief.v1"; snapshot_id: string; policy_revision: string;
  graph_revision: number; rendered: string; rendered_tokens: number; data_role: true;
  citations: { source: string; node_id: string; start_line: number; end_line: number; document_digest: string }[];
  excerpts: { text: string; citations: unknown[] }[];
};
export type ContextProof = { currentPassword?: string; totpCode?: string };
export type ContextAgentSession = { session_id: string; scope_id: string | null; phase: "pending" | "authorized"; expires_in_seconds: number };

const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const text = (value: unknown): value is string => typeof value === "string";
const digest = (value: unknown): value is string => text(value) && /^[a-f0-9]{64}$/.test(value);
const count = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;
function invalid(): never { throw new ContextAssistanceApiError("workspace_payload_invalid", "CIGAR sent back something this page does not understand. Refresh and try again."); }

export function validContextBrokerRevision(value: unknown): value is ContextBrokerRevision {
  return object(value) && digest(value.epoch) && text(value.version) && /^(0|[1-9][0-9]{0,19})$/.test(value.version)
    && (value.version.length < 20 || value.version <= "18446744073709551615");
}

export function parseContextScope(value: unknown): ContextWorkspaceScope {
  if (!object(value) || !text(value.scope_id) || !text(value.workspace) || !text(value.app)
      || !digest(value.policy_revision) || !count(value.retained_contexts) || typeof value.revoked !== "boolean"
      || !Array.isArray(value.sources) || value.sources.length > 32
      || !value.sources.every((source) => object(source) && text(source.source_id) && text(source.path)
        && digest(source.sha256) && count(source.documents))) invalid();
  if (value.native_policy_facts !== undefined && typeof value.native_policy_facts !== "boolean") invalid();
  if (value.sharing !== undefined) {
    const sharing = value.sharing;
    if (!object(sharing) || !["private_graph", "private_broker", "shared_broker"].includes(String(sharing.mode)) || !object(sharing.notes)
        || typeof sharing.notes.read !== "boolean" || typeof sharing.notes.propose !== "boolean"
        || (sharing.notes.propose && !sharing.notes.read) || !count(sharing.notes.documents) || sharing.notes.documents > 32
        || !(sharing.notes.revision === null || validContextBrokerRevision(sharing.notes.revision))
        || (sharing.mode === "shared_broker" ? sharing.client_lease_seconds !== 300
          : sharing.client_lease_seconds !== null || sharing.notes.read || sharing.notes.propose)) invalid();
  }
  if (value.receipt_window !== undefined && (!object(value.receipt_window)
      || typeof value.receipt_window.enabled !== "boolean" || !count(value.receipt_window.retained)
      || value.receipt_window.retained > 16 || !text(value.receipt_window.dropped)
      || !/^(0|[1-9][0-9]{0,19})$/.test(value.receipt_window.dropped)
      || value.receipt_window.coverage !== "bounded_recent_native_receipts")) invalid();
  return value as ContextWorkspaceScope;
}

export function parseContextBrief(value: unknown): ContextBrief {
  if (!object(value) || value.schema !== "guard-cigar-context-brief.v1" || value.data_role !== true
      || !digest(value.snapshot_id) || !text(value.policy_revision) || !count(value.graph_revision)
      || !text(value.rendered) || value.rendered.length > 262_144 || !count(value.rendered_tokens)
      || !Array.isArray(value.excerpts) || value.excerpts.length > 16
      || !value.excerpts.every((excerpt) => object(excerpt) && text(excerpt.text) && Array.isArray(excerpt.citations))
      || !Array.isArray(value.citations) || value.citations.length > 1024
      || !value.citations.every((citation) => object(citation) && text(citation.source) && text(citation.node_id)
        && count(citation.start_line) && citation.start_line > 0 && count(citation.end_line)
        && citation.end_line >= citation.start_line && digest(citation.document_digest))) invalid();
  return value as ContextBrief;
}

/** Plain words for a refused request. A refused pick names its likely cause:
 *  reading files again cannot help with a secret-looking, blocked or private file. */
function refusal(code: string, action: string, status: number): string {
  if (code.endsWith("context_storage_repair_required")) return "CIGAR's saved notes need repair. Delete them in CIGAR → Privacy, then add the project again.";
  if (code.endsWith("context_storage_outcome_unknown")) return "CIGAR's saved notes may have changed before this finished. Check CIGAR → Privacy, then try again.";
  if (code.endsWith("context_resource_limit") && action === "authorize_agent") {
    return "CIGAR is connected to as many apps as it can. Disconnect an app or remove a project you no longer use, then reconnect this app and use its new code.";
  }
  if (code.endsWith("context_busy") || code.endsWith("_busy")) return "CIGAR is still finishing something. Try again in a moment.";
  if (code.endsWith("context_scope_denied") && action === "grant") {
    return "CIGAR couldn't add these files. It won't read a file that looks like it holds a password or key, a file your settings block, or a folder Guard keeps private. Take that file out, or pick another folder, and try again.";
  }
  if (code.endsWith("context_stale") || code.endsWith("context_scope_denied")) return "The project or its files changed. Choose Read files again, or add the project again.";
  if (status === 403 || status === 401) return "Guard needs your approval password for this.";
  return "CIGAR could not finish that. Refresh and try again.";
}

async function ask(route: "workspace" | "workspace-access" | "workspace-grant", input: Record<string, unknown>, proof?: ContextProof, signal?: AbortSignal) {
  if (isGuardDemoMode()) throw new ContextAssistanceApiError("demo_unavailable", "Context sources require a local Guard installation.");
  const timeout = AbortSignal.timeout(12_000);
  const response = await fetchWithGuardAuth(`/v1/context-assistance/${route}`, {
    method: "POST", headers: { "Content-Type": "application/json" }, cache: "no-store",
    signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
    body: JSON.stringify({ input, ...(proof?.currentPassword ? { approval_password: proof.currentPassword } : {}),
      ...(proof?.totpCode ? { approval_totp_code: proof.totpCode } : {}) }),
  });
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const code = object(body) && text(body.code) && /^[a-z0-9_]{1,160}$/.test(body.code) ? body.code : "context_request_refused";
    const message = refusal(code, String(input.action), response.status);
    throw new ContextAssistanceApiError(code, message);
  }
  if (!object(body) || body.schema !== "guard-cigar-workspace-result.v1" || body.data_role !== true || !object(body.result)) invalid();
  return body.result;
}
export { ask as requestContextWorkspace, refusal as contextRefusalMessage };

export async function listContextWorkspaces(signal?: AbortSignal): Promise<ContextWorkspaceScope[]> {
  const result = await ask("workspace", { action: "list" }, undefined, signal);
  if (!Array.isArray(result.scopes) || result.scopes.length > 8) invalid();
  return result.scopes.map(parseContextScope);
}
export async function grantContextWorkspace(workspace: string, sources: string[], proof?: ContextProof, signal?: AbortSignal, app = "dashboard", notes?: ContextNotesAccess) {
  return parseContextScope(await ask("workspace-grant", { action: "grant", workspace, app, sources, ...(notes ? { shared_notes: notes } : {}) }, proof, signal));
}
export async function listContextAgentSessions(signal?: AbortSignal): Promise<ContextAgentSession[]> {
  const result = await ask("workspace", { action: "list_agents" }, undefined, signal);
  if (!Array.isArray(result.agent_sessions) || result.agent_sessions.length > 8
      || !result.agent_sessions.every((item) => object(item) && text(item.session_id)
        && (item.scope_id === null || text(item.scope_id)) && ["pending", "authorized"].includes(String(item.phase))
        && count(item.expires_in_seconds) && item.expires_in_seconds <= 3600)) invalid();
  return result.agent_sessions as ContextAgentSession[];
}
export async function authorizeContextAgentSession(sessionId: string, scopeId: string, proof?: ContextProof, signal?: AbortSignal) {
  return ask("workspace-grant", { action: "authorize_agent", session_id: sessionId, scope_id: scopeId }, proof, signal);
}
export async function revokeContextAgentSession(sessionId: string, signal?: AbortSignal) {
  return ask("workspace-access", { action: "revoke_agent", session_id: sessionId }, undefined, signal);
}
export async function manageContextWorkspace(action: "refresh" | "withdraw" | "revoke" | "clear", scopeId?: string, sourceId?: string, signal?: AbortSignal) {
  return ask("workspace-access", { action, ...(scopeId ? { scope_id: scopeId } : {}), ...(sourceId ? { source_id: sourceId } : {}) }, undefined, signal);
}
export async function compileWorkspaceContext(scopeId: string, query: string, signal?: AbortSignal) {
  const result = await ask("workspace", { action: "compile", scope_id: scopeId, query }, undefined, signal);
  if (result.current !== true) invalid();
  const scope = result.scope === undefined ? null : parseContextScope(result.scope);
  if (scope && scope.scope_id !== scopeId) invalid();
  return { brief: parseContextBrief(result.brief), scope };
}
