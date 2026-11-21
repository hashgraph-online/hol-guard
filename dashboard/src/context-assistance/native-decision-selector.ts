// Presentation metadata only. Rust authenticates the native origin and scope;
// neither this selector nor the attached receipt grants execution authority.
export type NativeDecisionSelector = {
  schema: "guard-native-hook-decision-receipt.v1"; authority: "rust";
  harness: string; event_name: "PreToolUse"; decision_id: string; origin_authentication: string;
};
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const digest = (value: unknown): value is string => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);

export function parseNativeDecisionSelector(value: unknown, harness: string, event = "PreToolUse"): NativeDecisionSelector | undefined {
  if (!object(value) || event !== "PreToolUse" || value.schema !== "guard-native-hook-decision-receipt.v1"
      || value.authority !== "rust" || value.event_name !== event || value.harness !== harness
      || !digest(value.decision_id) || !digest(value.origin_authentication)) return undefined;
  return { schema: "guard-native-hook-decision-receipt.v1", authority: "rust", event_name: "PreToolUse",
    harness, decision_id: value.decision_id, origin_authentication: value.origin_authentication };
}

export function attachedNativeDecision(envelope: unknown, harness: string): string | null {
  return object(envelope) ? parseNativeDecisionSelector(envelope.native_origin_receipt, harness)?.decision_id ?? null : null;
}
