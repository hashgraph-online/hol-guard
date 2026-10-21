import type { McpPolicyDecisionResult, McpPolicyRequest } from "./guard-api";

export const STATUS_LABELS: Record<McpPolicyRequest["status"], string> = {
  pending: "Pending review", applied: "Applied", declined: "Declined", expired: "Expired", failed: "Failed",
};
export const FAILURE_CODE_LABELS: Record<string, string> = {
  policy_write_failed: "Guard could not write the policy file.",
  approval_already_resolved: "This request was already resolved.",
  approval_gate_required: "Approval gate authentication is required.",
  missing_required_fields: "Required fields were missing from the request.",
  invalid_arguments: "The request contained invalid arguments.",
};
export function resolveOutcomeMessage(result: McpPolicyDecisionResult): string {
  switch (result.status) {
    case "applied": return "Policy applied.";
    case "declined": return "Request declined.";
    default: return `Request is now ${STATUS_LABELS[result.status].toLowerCase()}.`;
  }
}
export function planToneClass(tone: "emerald" | "amber" | "rose"): string {
  switch (tone) {
    case "emerald": return "border-emerald-200 bg-emerald-50 text-emerald-700";
    case "amber": return "border-amber-200 bg-amber-50 text-amber-700";
    case "rose": return "border-rose-200 bg-rose-50 text-rose-700";
  }
}
export function statusTone(status: McpPolicyRequest["status"]): "success" | "default" | "warning" | "destructive" | "info" {
  switch (status) {
    case "applied": return "success";
    case "declined": return "default";
    case "expired": return "warning";
    case "failed": return "destructive";
    default: return "info";
  }
}
export function isActable(request: McpPolicyRequest): boolean {
  return !request.isTerminal && !request.isExpired;
}
export function truncateDigest(digest: string): string {
  return digest.length <= 16 ? digest : `${digest.slice(0, 12)}…${digest.slice(-4)}`;
}
export function formatTimestamp(iso: string): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
