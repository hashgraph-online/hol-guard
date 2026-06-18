import type { GuardCloudExceptionRequestCreateInput } from "./guard-api";
import type { GuardApprovalRequest, GuardReceipt, GuardRuntimeSnapshot } from "./guard-types";
import type { RequestScopeValue } from "./policy-cloud-exception-request-layout";

export const DRAFT_STORAGE_KEY = "hol-guard:cloud-exception-request-draft";

export const WIZARD_STEPS = ["Source", "Scope", "Guardrails", "Review"] as const;
export type WizardStep = (typeof WIZARD_STEPS)[number];

export type SourceMode = "approval" | "receipt" | "paste-id";

export type CloudExceptionRequestDraft = {
  sourceMode: SourceMode;
  sourceReceiptId: string;
  sourceReviewItemId: string;
  pastedRequestId: string;
  scope: RequestScopeValue;
  harness: string;
  artifactId: string;
  publisher: string;
  workingDirectory: string;
  owner: string;
  requestedBy: string;
  reason: string;
  requestedExpiresAt: string;
  linkedTicket: string;
  maxUses: string;
  stepIndex: number;
};

export type SubmittedRequestState = {
  requestId: string;
  submittedAt: string;
  status: "pending";
};

export function defaultExpiryIso(): string {
  const date = new Date();
  date.setDate(date.getDate() + 30);
  return date.toISOString();
}

export function toDatetimeLocalValue(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function fromDatetimeLocalValue(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return new Date().toISOString();
  }
  return date.toISOString();
}

export function resolveDefaultWorkingDirectory(snapshot: GuardRuntimeSnapshot): string {
  const install = snapshot.managed_installs?.find((entry) => entry.workspace?.trim());
  return install?.workspace?.trim() ?? "";
}

export function resolveResolvedApprovals(snapshot: GuardRuntimeSnapshot): GuardApprovalRequest[] {
  return (snapshot.items ?? []).filter(
    (item) => Boolean(item.resolved_at?.trim()) || Boolean(item.resolution_action?.trim()),
  );
}

export function resolveApprovalById(
  snapshot: GuardRuntimeSnapshot,
  requestId: string,
): GuardApprovalRequest | null {
  const trimmed = requestId.trim();
  if (!trimmed) {
    return null;
  }
  return (snapshot.items ?? []).find((item) => item.request_id === trimmed) ?? null;
}

export function createDefaultDraft(snapshot: GuardRuntimeSnapshot): CloudExceptionRequestDraft {
  const receipts = snapshot.latest_receipts ?? [];
  const approvals = resolveResolvedApprovals(snapshot);
  const firstReceipt = receipts[0];
  const firstApproval = approvals[0];
  const hasApproval = Boolean(firstApproval);
  const sourceMode: SourceMode = hasApproval ? "approval" : receipts.length > 0 ? "receipt" : "receipt";

  return {
    sourceMode,
    sourceReceiptId: hasApproval ? "" : (firstReceipt?.receipt_id ?? ""),
    sourceReviewItemId: hasApproval ? (firstApproval?.request_id ?? "") : "",
    pastedRequestId: "",
    scope: "workspace",
    harness: firstReceipt?.harness ?? firstApproval?.harness ?? "codex",
    artifactId: firstReceipt?.artifact_id ?? firstApproval?.artifact_id ?? "",
    publisher: firstApproval?.publisher?.trim() ?? "",
    workingDirectory:
      firstApproval?.workspace?.trim() ||
      resolveDefaultWorkingDirectory(snapshot) ||
      firstReceipt?.source_scope?.trim() ||
      "",
    owner: "",
    requestedBy: "",
    reason: "",
    requestedExpiresAt: defaultExpiryIso(),
    linkedTicket: "",
    maxUses: "",
    stepIndex: 0,
  };
}

export function isDraftRecord(value: unknown): value is Partial<CloudExceptionRequestDraft> {
  return value !== null && typeof value === "object";
}

export function loadDraftFromStorage(): Partial<CloudExceptionRequestDraft> | null {
  try {
    const saved = localStorage.getItem(DRAFT_STORAGE_KEY);
    if (!saved) {
      return null;
    }
    const parsed: unknown = JSON.parse(saved);
    return isDraftRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export function saveDraftToStorage(draft: CloudExceptionRequestDraft): void {
  try {
    localStorage.setItem(DRAFT_STORAGE_KEY, JSON.stringify(draft));
  } catch {
    // ignore storage failures
  }
}

export function mergeDraft(
  base: CloudExceptionRequestDraft,
  saved: Partial<CloudExceptionRequestDraft> | null,
): CloudExceptionRequestDraft {
  if (!saved) {
    return base;
  }
  return {
    ...base,
    ...saved,
    stepIndex: typeof saved.stepIndex === "number" ? saved.stepIndex : base.stepIndex,
  };
}

export function hasValidSourceAnchor(draft: CloudExceptionRequestDraft): boolean {
  if (draft.sourceMode === "receipt") {
    return Boolean(draft.sourceReceiptId.trim());
  }
  if (draft.sourceMode === "approval") {
    return Boolean(draft.sourceReviewItemId.trim());
  }
  if (draft.sourceMode === "paste-id") {
    return Boolean(draft.pastedRequestId.trim());
  }
  return false;
}

export function isReasonValid(reason: string): boolean {
  const trimmed = reason.trim();
  return trimmed.length >= 24 && trimmed.length <= 280;
}

export function isExpiryValid(requestedExpiresAt: string): boolean {
  const date = new Date(requestedExpiresAt);
  if (Number.isNaN(date.getTime())) {
    return false;
  }
  return date.getTime() > Date.now();
}

export function canAdvanceFromScope(draft: CloudExceptionRequestDraft): boolean {
  if (draft.scope === "team-policy") {
    return false;
  }
  if (draft.scope === "artifact" && !draft.artifactId.trim()) {
    return false;
  }
  if (draft.scope === "publisher" && !draft.publisher.trim()) {
    return false;
  }
  if (draft.scope === "workspace" && !draft.workingDirectory.trim()) {
    return false;
  }
  if ((draft.scope === "harness" || draft.scope === "artifact") && !draft.harness.trim()) {
    return false;
  }
  return true;
}

export function canAdvanceFromGuardrails(draft: CloudExceptionRequestDraft): boolean {
  return (
    draft.owner.trim().length > 0 &&
    draft.requestedBy.trim().length > 0 &&
    isReasonValid(draft.reason) &&
    isExpiryValid(draft.requestedExpiresAt)
  );
}

export function canSubmitDraft(draft: CloudExceptionRequestDraft): boolean {
  return hasValidSourceAnchor(draft) && canAdvanceFromScope(draft) && canAdvanceFromGuardrails(draft);
}

export function buildReasonForSubmit(draft: CloudExceptionRequestDraft): string {
  const parts = [draft.reason.trim()];
  if (draft.linkedTicket.trim()) {
    parts.push(`Ticket: ${draft.linkedTicket.trim()}`);
  }
  if (draft.maxUses.trim()) {
    parts.push(`Max uses: ${draft.maxUses.trim()}`);
  }
  return parts.filter(Boolean).join("\n");
}

export function buildSubmitPayload(draft: CloudExceptionRequestDraft): GuardCloudExceptionRequestCreateInput {
  if (draft.scope === "team-policy") {
    throw new Error("Team policy exceptions must be created directly in Guard Cloud.");
  }

  const payload: GuardCloudExceptionRequestCreateInput = {
    scope: draft.scope,
    requestedBy: draft.requestedBy.trim(),
    owner: draft.owner.trim(),
    reason: buildReasonForSubmit(draft),
    requestedExpiresAt: draft.requestedExpiresAt,
    sourceReceiptId: null,
    sourceReviewItemId: null,
  };

  if (draft.sourceMode === "receipt") {
    payload.sourceReceiptId = draft.sourceReceiptId.trim() || null;
  } else if (draft.sourceMode === "approval") {
    payload.sourceReviewItemId = draft.sourceReviewItemId.trim() || null;
  } else if (draft.sourceMode === "paste-id") {
    payload.sourceReviewItemId = draft.pastedRequestId.trim() || null;
  }

  if (draft.scope === "artifact") {
    payload.harness = draft.harness.trim() || null;
    payload.artifactId = draft.artifactId.trim() || null;
  } else if (draft.scope === "publisher") {
    payload.publisher = draft.publisher.trim() || null;
  } else if (draft.scope === "harness") {
    payload.harness = draft.harness.trim() || null;
  } else if (draft.scope === "workspace") {
    payload.workingDirectory = draft.workingDirectory.trim() || null;
  }

  return payload;
}

export function resolveSelectedReceipt(
  receipts: GuardReceipt[],
  draft: CloudExceptionRequestDraft,
): GuardReceipt | null {
  if (draft.sourceMode === "receipt" && draft.sourceReceiptId.trim()) {
    return receipts.find((entry) => entry.receipt_id === draft.sourceReceiptId) ?? null;
  }
  return null;
}

export function resolveSelectedApproval(
  snapshot: GuardRuntimeSnapshot,
  draft: CloudExceptionRequestDraft,
): GuardApprovalRequest | null {
  if (draft.sourceMode === "approval" && draft.sourceReviewItemId.trim()) {
    return resolveApprovalById(snapshot, draft.sourceReviewItemId);
  }
  if (draft.sourceMode === "paste-id" && draft.pastedRequestId.trim()) {
    return resolveApprovalById(snapshot, draft.pastedRequestId);
  }
  return null;
}

export function resolvePublisherFromSource(
  snapshot: GuardRuntimeSnapshot,
  draft: CloudExceptionRequestDraft,
  receipts: GuardReceipt[],
): string | null {
  const approval = resolveSelectedApproval(snapshot, draft);
  if (approval?.publisher?.trim()) {
    return approval.publisher.trim();
  }
  const receipt = resolveSelectedReceipt(receipts, draft);
  if (receipt?.source_scope?.trim()) {
    return receipt.source_scope.trim();
  }
  return null;
}

export function formatRelativeTime(value: string | null | undefined): string | null {
  if (!value?.trim()) {
    return null;
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return null;
  }
  const diffMs = Date.now() - date.getTime();
  const diffDays = Math.round(diffMs / (24 * 60 * 60 * 1000));
  if (diffDays <= 0) {
    return "Today";
  }
  if (diffDays === 1) {
    return "1 day ago";
  }
  return `${diffDays} days ago`;
}
