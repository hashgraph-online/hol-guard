import { ContextAssistanceApiError } from "./api";
import { isCigarProducerVersion } from "./release-version";
import { parseSavedEvidence, type SavedEvidence } from "./saved-evidence";
import { parseNativeDecisionAssociation, type NativeDecisionAssociation } from "./action-api";
import { parseContextBrief, parseContextScope, requestContextWorkspace,
  type ContextBrief, type ContextSource, type ContextWorkspaceScope } from "./workspaces-api";

export type ContextHistoryEntry = {
  history_id: string; prepared_at_ms: string; snapshot_id: string; policy_revision: string; graph_revision: number;
  rendered_tokens: number; citations: ContextBrief["citations"]; sources: Omit<ContextSource, "documents">[];
  association: NativeDecisionAssociation | null; sdk_version: string; worker_fingerprint: string;
  historical: true; text_retained: true; observation: "prepared_not_delivery_or_execution";
};
export type ContextHistoryDetail = {
  scope: ContextWorkspaceScope; entry: ContextHistoryEntry; brief: ContextBrief | null; source_access: "available" | "unavailable";
  source_states: { source_id: string; state: "unchanged" | "changed" | "unavailable"; recorded_sha256: string; current_sha256: string | null }[];
};
export type ContextHistorySummary = { entries: number; encoded_bytes: number; dropped: string; max_entries: 8; max_encoded_bytes: 524288; storage: "memory" };
export type ContextDataSummary = {
  schema: "guard-cigar-data-summary.v1" | "guard-cigar-data-summary.v2"; storage: "memory"; data_role: true; active_scopes: number; selected_files: number;
  current_contexts: number; history_entries: number; history_encoded_bytes: number; agent_sessions: number;
  max_history_entries_per_scope: 8; max_history_encoded_bytes_per_scope: 524288;
  saved_context: "unavailable"; cleared_history: boolean;
  history_storage?: "memory"; saved_evidence?: SavedEvidence; cleared_saved?: boolean;
};
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const text = (value: unknown): value is string => typeof value === "string";
const digest = (value: unknown): value is string => text(value) && /^[a-f0-9]{64}$/.test(value);
const count = (value: unknown, max: number): value is number => Number.isSafeInteger(value) && Number(value) >= 0 && Number(value) <= max;
function invalid(): never { throw new ContextAssistanceApiError("history_payload_invalid", "Guard returned incompatible context history. Refresh its status."); }

export function parseContextDataSummary(value: unknown): ContextDataSummary {
  if (!object(value) || !["guard-cigar-data-summary.v1", "guard-cigar-data-summary.v2"].includes(String(value.schema)) || value.storage !== "memory" || value.data_role !== true
      || !count(value.active_scopes, 8) || !count(value.selected_files, 256) || !count(value.current_contexts, 64)
      || !count(value.history_entries, 64) || !count(value.history_encoded_bytes, 4194304) || !count(value.agent_sessions, 8)
      || value.max_history_entries_per_scope !== 8 || value.max_history_encoded_bytes_per_scope !== 524288
      || value.saved_context !== "unavailable" || typeof value.cleared_history !== "boolean") invalid();
  if (value.schema === "guard-cigar-data-summary.v2") {
    if (value.history_storage !== "memory" || typeof value.cleared_saved !== "boolean") invalid();
    parseSavedEvidence(value.saved_evidence);
  } else if (value.saved_evidence !== undefined) parseSavedEvidence(value.saved_evidence);
  return value as ContextDataSummary;
}

export function parseContextHistoryEntry(value: unknown): ContextHistoryEntry {
  if (!object(value) || !text(value.history_id) || !/^history:[1-9][0-9]{0,19}$/.test(value.history_id)
      || !text(value.prepared_at_ms) || !/^(0|[1-9][0-9]{0,19})$/.test(value.prepared_at_ms)
      || !digest(value.snapshot_id) || !digest(value.policy_revision) || !count(value.graph_revision, Number.MAX_SAFE_INTEGER)
      || !count(value.rendered_tokens, 32768) || !isCigarProducerVersion(value.sdk_version) || !digest(value.worker_fingerprint)
      || value.historical !== true || value.text_retained !== true || value.observation !== "prepared_not_delivery_or_execution"
      || !Array.isArray(value.sources) || value.sources.length > 32 || !value.sources.every((source) => object(source)
        && text(source.source_id) && text(source.path) && source.path.length <= 1024 && digest(source.sha256))) invalid();
  parseContextBrief({ ...value, schema: "guard-cigar-context-brief.v1", data_role: true, rendered: "", excerpts: [] });
  const association = value.association === null ? null : parseNativeDecisionAssociation(value.association);
  return { ...value, association } as ContextHistoryEntry;
}

function scopeFor(value: unknown, expected: ContextWorkspaceScope) {
  const scope = parseContextScope(value);
  if (scope.revoked || scope.scope_id !== expected.scope_id || scope.workspace !== expected.workspace || scope.app !== expected.app) invalid();
  return scope;
}
function historical(value: unknown): asserts value is Record<string, unknown> {
  if (!object(value) || value.history_schema !== "guard-cigar-history.v1" || value.historical !== true || value.current !== false) invalid();
}
export function parseContextHistory(value: unknown, expected: ContextWorkspaceScope, decisionId?: string) {
  historical(value);
  const scope = scopeFor(value.scope, expected);
  if (!Array.isArray(value.entries) || value.entries.length > 8) invalid();
  const entries = value.entries.map(parseContextHistoryEntry);
  const summary = value.summary;
  if (!object(summary) || !count(summary.entries, 8) || !count(summary.encoded_bytes, 524288)
      || !text(summary.dropped) || !/^(0|[1-9][0-9]{0,19})$/.test(summary.dropped)
      || summary.max_entries !== 8 || summary.max_encoded_bytes !== 524288 || summary.storage !== "memory") invalid();
  if (new Set(entries.map((entry) => entry.history_id)).size !== entries.length
      || entries.some((entry) => decisionId && entry.association?.decision_id !== decisionId)) invalid();
  return { scope, entries, summary: summary as ContextHistorySummary };
}
export function parseContextHistoryDetail(value: unknown, expected: ContextWorkspaceScope, historyId: string): ContextHistoryDetail {
  historical(value);
  const scope = scopeFor(value.scope, expected);
  const entry = parseContextHistoryEntry(value.entry);
  if (entry.history_id !== historyId || !["available", "unavailable"].includes(String(value.source_access))
      || !Array.isArray(value.source_states) || value.source_states.length !== entry.sources.length) invalid();
  const states = value.source_states;
  if (!states.every((state) => object(state) && text(state.source_id) && digest(state.recorded_sha256)
      && (state.current_sha256 === null || digest(state.current_sha256))
      && ["unchanged", "changed", "unavailable"].includes(String(state.state))
      && entry.sources.some((source) => source.source_id === state.source_id && source.sha256 === state.recorded_sha256))
      || new Set(states.map((state) => state.source_id)).size !== states.length
      || entry.sources.some((source) => !scope.sources.some((grant) => grant.source_id === source.source_id && grant.path === source.path))) invalid();
  const brief = value.brief === null ? null : parseContextBrief(value.brief);
  if ((value.source_access === "available") !== Boolean(brief) || (brief && (brief.snapshot_id !== entry.snapshot_id
      || brief.policy_revision !== entry.policy_revision || !brief.citations.every((citation) => ["guard:policy", "guard:action", "guard:receipts", ...(scope.sharing?.notes.read ? ["guard:notes"] : []), ...entry.sources.map((source) => source.source_id)].includes(citation.source))))) invalid();
  return { scope, entry, brief, source_access: value.source_access as "available" | "unavailable", source_states: states as ContextHistoryDetail["source_states"] };
}

export const fetchContextData = async (signal?: AbortSignal) => parseContextDataSummary(await requestContextWorkspace("workspace", { action: "data" }, undefined, signal));
export const forgetContextHistory = async (signal?: AbortSignal) => parseContextDataSummary(await requestContextWorkspace("workspace-access", { action: "forget_history" }, undefined, signal));
export const forgetSavedEvidence = async (signal?: AbortSignal) => parseContextDataSummary(await requestContextWorkspace("workspace-access", { action: "forget_saved" }, undefined, signal));
export async function listContextHistory(scope: ContextWorkspaceScope, decisionId?: string, signal?: AbortSignal) {
  const value = await requestContextWorkspace("workspace", { action: "history", scope_id: scope.scope_id, ...(decisionId ? { decision_id: decisionId } : {}) }, undefined, signal);
  return parseContextHistory(value, scope, decisionId);
}
export async function readContextHistory(scope: ContextWorkspaceScope, historyId: string, signal?: AbortSignal) {
  return parseContextHistoryDetail(await requestContextWorkspace("workspace", { action: "history_detail", scope_id: scope.scope_id, history_id: historyId }, undefined, signal), scope, historyId);
}
