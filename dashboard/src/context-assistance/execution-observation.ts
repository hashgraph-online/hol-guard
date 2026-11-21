export type ContextExecutionObservation = {
  schema: "guard-cigar-native-execution-observation.v1";
  data_role: true;
  effect_id: string;
  snapshot_id: string;
  scope_id: string;
  execution_reference: string | null;
  phase: "prepared" | "not_dispatched" | "dispatch_acknowledged" | "completed" | "outcome_unknown";
  source_qualification: "captured_native_facts_only";
  SDK_checked_at_ms: number | null;
  native_barrier_checked_at_ms: number | null;
  context_eligible_at_last_check: boolean;
  association_applied: boolean;
  native_dispatch_acknowledged: boolean;
  reason: "captured_native_binding_changed" | "context_revoked_expired_or_unavailable" | "native_operation_already_recorded" | null;
  approval_grant: false;
  send_boundary_atomicity: false;
};

const record = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const digest = (value: unknown) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const timestamp = (value: unknown) => value === null
  || (typeof value === "number" && Number.isSafeInteger(value) && value >= 0);
const keys = new Set(["schema", "data_role", "effect_id", "snapshot_id", "scope_id", "execution_reference",
  "phase", "source_qualification", "SDK_checked_at_ms", "native_barrier_checked_at_ms",
  "context_eligible_at_last_check", "association_applied", "native_dispatch_acknowledged", "reason",
  "approval_grant", "send_boundary_atomicity"]);

/** Presentation validates observations; it never creates execution authority. */
export function isContextExecutionObservation(value: unknown): value is ContextExecutionObservation {
  if (!record(value) || Object.keys(value).length !== keys.size || Object.keys(value).some((key) => !keys.has(key))) return false;
  return value.schema === "guard-cigar-native-execution-observation.v1" && value.data_role === true
    && typeof value.effect_id === "string" && /^execution:[a-f0-9]{64}$/.test(value.effect_id)
    && digest(value.snapshot_id) && typeof value.scope_id === "string" && /^scope:[a-f0-9]{64}$/.test(value.scope_id)
    && (value.execution_reference === null || digest(value.execution_reference))
    && ["prepared", "not_dispatched", "dispatch_acknowledged", "completed", "outcome_unknown"].includes(String(value.phase))
    && value.source_qualification === "captured_native_facts_only"
    && timestamp(value.SDK_checked_at_ms) && timestamp(value.native_barrier_checked_at_ms)
    && typeof value.context_eligible_at_last_check === "boolean" && typeof value.association_applied === "boolean"
    && typeof value.native_dispatch_acknowledged === "boolean"
    && (value.reason === null || ["captured_native_binding_changed", "context_revoked_expired_or_unavailable", "native_operation_already_recorded"].includes(String(value.reason)))
    && value.approval_grant === false && value.send_boundary_atomicity === false
    && (!value.association_applied || (value.native_dispatch_acknowledged && value.context_eligible_at_last_check && value.native_barrier_checked_at_ms !== null))
    && (value.phase !== "not_dispatched" || !value.native_dispatch_acknowledged)
    && (value.phase !== "dispatch_acknowledged" || value.native_dispatch_acknowledged);
}
