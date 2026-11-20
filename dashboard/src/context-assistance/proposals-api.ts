import { ContextAssistanceApiError } from "./api";
import { parseContextScope, requestContextWorkspace, validContextBrokerRevision,
  type ContextBrokerRevision, type ContextProof } from "./workspaces-api";

export type ContextNoteDocument = { id: string; text: string; start_line: number };
export type ContextProposal = {
  proposal_id: string; connection_id: string | null; state: "pending" | "admitted" | "rejected";
  basis_snapshot: string; expected: ContextBrokerRevision; documents: number; bytes: number;
  basis: Record<string, ContextBrokerRevision>; data_role: true;
};
export type ContextProposalDetail = Omit<ContextProposal, "documents" | "bytes"> & {
  documents: ContextNoteDocument[] | null; current_documents: ContextNoteDocument[] | null;
  current_revision: ContextBrokerRevision | null;
  approval_grant: false; source_access: "available" | "unavailable";
  source_states: { source_id: string; path: string; state: "unchanged" | "changed" | "unavailable"; current_sha256: string | null }[];
};
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const id = (value: unknown): value is string => typeof value === "string" && /^[A-Za-z0-9_.:-]{1,128}$/.test(value);
const digest = (value: unknown): value is string => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const count = (value: unknown, max: number) => Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= max;
const documents = (value: unknown) => Array.isArray(value) && value.length <= 32
  && value.every((item) => record(item) && id(item.id) && item.id.startsWith("note:") && item.start_line === 1
    && typeof item.text === "string" && item.text.length <= 16384)
  && value.reduce((total, item) => total + item.text.length, 0) <= 16384;
function invalid(): never { throw new ContextAssistanceApiError("proposal_payload_invalid", "Guard returned incompatible shared-note data. Refresh the proposal list."); }
function common(value: unknown): value is Record<string, unknown> {
  return record(value) && id(value.proposal_id) && (value.connection_id === null || (id(value.connection_id) && value.connection_id.startsWith("agent:")))
    && ["pending", "admitted", "rejected"].includes(String(value.state)) && digest(value.basis_snapshot)
    && validContextBrokerRevision(value.expected) && record(value.basis) && Object.keys(value.basis).length <= 32
    && Object.entries(value.basis).every(([source, revision]) => id(source) && validContextBrokerRevision(revision)) && value.data_role === true;
}

export async function listContextProposals(scopeId: string, signal?: AbortSignal): Promise<ContextProposal[]> {
  const result = await requestContextWorkspace("workspace", { action: "proposals", scope_id: scopeId }, undefined, signal);
  const scope = parseContextScope(result.scope);
  const permitted = ["guard:policy", "guard:receipts", ...scope.sources.map((source) => source.source_id)];
  if (scope.scope_id !== scopeId || scope.sharing?.notes.read !== true || !Array.isArray(result.proposals) || result.proposals.length > 32
      || !result.proposals.every((item) => common(item) && count(item.documents, 32) && count(item.bytes, 16384)
        && Object.keys(item.basis as object).every((source) => permitted.includes(source)))) invalid();
  return result.proposals as ContextProposal[];
}
export async function loadContextProposal(scopeId: string, proposalId: string, signal?: AbortSignal): Promise<ContextProposalDetail> {
  const result = await requestContextWorkspace("workspace", { action: "proposal", scope_id: scopeId, proposal_id: proposalId }, undefined, signal);
  const scope = parseContextScope(result.scope);
  const value = result.proposal;
  const permitted = ["guard:policy", "guard:receipts", ...scope.sources.map((source) => source.source_id)];
  if (scope.scope_id !== scopeId || scope.sharing?.notes.read !== true || !common(value) || value.proposal_id !== proposalId
      || !Object.keys(value.basis as object).every((source) => permitted.includes(source))
      || value.approval_grant !== false || !["available", "unavailable"].includes(String(value.source_access))
      || !(value.documents === null || documents(value.documents))
      || !(value.current_documents === null || documents(value.current_documents))
      || !(value.current_revision === null || validContextBrokerRevision(value.current_revision))
      || (value.source_access === "unavailable" && (value.documents !== null || value.current_documents !== null))
      || !Array.isArray(value.source_states) || value.source_states.length > 32
      || !value.source_states.every((state) => record(state) && id(state.source_id) && typeof state.path === "string" && state.path.length <= 4096
        && ["unchanged", "changed", "unavailable"].includes(String(state.state)) && (state.current_sha256 === null || digest(state.current_sha256))
        && scope.sources.some((source) => source.source_id === state.source_id && source.path === state.path))
      || new Set(value.source_states.map((state) => state.source_id)).size !== value.source_states.length
      || value.source_states.length !== scope.sources.filter((source) => Object.hasOwn(value.basis as object, source.source_id)).length) invalid();
  return value as unknown as ContextProposalDetail;
}
export async function decideContextProposal(scopeId: string, proposalId: string, admit: boolean, proof?: ContextProof, signal?: AbortSignal) {
  const result = await requestContextWorkspace(admit ? "workspace-grant" : "workspace-access", {
    action: admit ? "admit_proposal" : "reject_proposal", scope_id: scopeId, proposal_id: proposalId,
  }, proof, signal);
  if (result.proposal_id !== proposalId || result.state !== (admit ? "admitted" : "rejected") || result.data_role !== true
      || (admit && (result.approval_grant !== false || !validContextBrokerRevision(result.revision)))) invalid();
  return result;
}
export async function clearContextNotes(scopeId: string, signal?: AbortSignal) {
  return requestContextWorkspace("workspace-access", { action: "clear_notes", scope_id: scopeId }, undefined, signal);
}
