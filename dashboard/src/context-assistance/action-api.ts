import { ContextAssistanceApiError } from "./api";
export { attachedNativeDecision } from "./native-decision-selector";
import { parseContextBrief, parseContextScope, requestContextWorkspace,
  type ContextBrief, type ContextWorkspaceScope } from "./workspaces-api";

export type NativeDecisionAssociation = {
  schema: "guard-context-native-decision.v1"; data_role: true;
  binding: "authenticated_native_decision"; decision_id: string; harness: string; event: "PreToolUse";
  action_type: string; operation: string; policy_generation: string;
  execution_binding: "unqualified"; approval_grant: false;
};
export type NativeDecisionContext = {
  brief: ContextBrief; scope: ContextWorkspaceScope; association: NativeDecisionAssociation; explanation: unknown;
};
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const digest = (value: unknown): value is string => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
function invalid(): never {
  throw new ContextAssistanceApiError("native_decision_payload_invalid", "Guard returned incompatible native decision context. Refresh its status.");
}

export function parseNativeDecisionAssociation(association: unknown): NativeDecisionAssociation {
  if (!object(association)) invalid();
  if (association.schema !== "guard-context-native-decision.v1" || association.data_role !== true
      || association.binding !== "authenticated_native_decision"
      || !digest(association.decision_id) || typeof association.harness !== "string" || !/^[a-z0-9-]{1,64}$/.test(association.harness) || association.event !== "PreToolUse"
      || typeof association.policy_generation !== "string" || !/^[1-9][0-9]{0,19}$/.test(association.policy_generation)
      || association.execution_binding !== "unqualified" || association.approval_grant !== false
      || !["command", "file_read", "file_write", "package", "mcp_tool", "network", "process_service", "browser", "config", "prompt", "harness", "unknown"].includes(String(association.action_type))
      || !["execute", "read", "write", "install", "call", "request", "start", "stop", "navigate", "set", "submit", "unknown"].includes(String(association.operation))) invalid();
  return association as NativeDecisionAssociation;
}

export function parseNativeDecisionContext(value: unknown, expected: { scope: ContextWorkspaceScope; decisionId: string; harness: string }): NativeDecisionContext {
  if (!object(value) || value.current !== true) invalid();
  const association = parseNativeDecisionAssociation(value.association);
  if (association.decision_id !== expected.decisionId || association.harness !== expected.harness) invalid();
  const scope = parseContextScope(value.scope);
  const brief = parseContextBrief(value.brief);
  if (scope.scope_id !== expected.scope.scope_id || scope.workspace !== expected.scope.workspace
      || scope.app !== expected.scope.app || scope.revoked || !scope.native_policy_facts
      || brief.policy_revision !== scope.policy_revision
      || !brief.citations.some((citation) => citation.source === "guard:action")
      || brief.citations.some((citation) => !["guard:action", "guard:policy", "guard:receipts", ...(scope.sharing?.notes.read ? ["guard:notes"] : []), ...scope.sources.map((source) => source.source_id)].includes(citation.source))) invalid();
  return { scope, brief, association: association as NativeDecisionAssociation, explanation: value.explanation };
}

export async function prepareNativeDecisionContext(scope: ContextWorkspaceScope, decisionId: string, harness: string, signal?: AbortSignal, snapshotId?: string) {
  if (!digest(decisionId) || (snapshotId !== undefined && !digest(snapshotId))) invalid();
  const value = await requestContextWorkspace("workspace", { action: "action", scope_id: scope.scope_id, decision_id: decisionId,
    ...(snapshotId ? { snapshot_id: snapshotId } : {}) }, undefined, signal);
  return parseNativeDecisionContext(value, { scope, decisionId, harness });
}
