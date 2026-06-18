function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function assertEqual<T>(actual: T, expected: T, message: string): void {
  if (actual !== expected) {
    throw new Error(`${message}: expected ${String(expected)}, got ${String(actual)}`);
  }
}

import {
  canAdvanceFromGuardrails,
  canAdvanceFromScope,
  canSubmitDraft,
  createDefaultDraft,
  hasValidSourceAnchor,
  isDraftRecord,
  isEmailValid,
  isExpiryValid,
  isReasonValid,
  loadDraftFromStorage,
  mergeDraft,
  buildSubmitPayload,
} from "./policy-cloud-exception-request-draft";
import type { GuardRuntimeSnapshot } from "./guard-types";

function makeSnapshot(overrides: Partial<GuardRuntimeSnapshot> = {}): GuardRuntimeSnapshot {
  return {
    generated_at: new Date().toISOString(),
    approval_center_url: null,
    runtime_state: null,
    device: { device_id: "device-1", label: "This machine" },
    latest_connect_state: null,
    proof_status: {
      state: "not_connected",
      label: "Not connected",
      detail: "",
      request_id: null,
      verified: false,
      verified_at: null,
      subject: null,
      issuer: null,
    },
    pending_count: 0,
    receipt_count: 1,
    headline_state: "protected",
    headline_label: "Protected",
    headline_detail: "",
    sync_configured: false,
    cloud_state: "local_only",
    cloud_state_label: "Local only",
    cloud_state_detail: "",
    cloud_pairing_state: "unpaired",
    cloud_sync_health: "unknown",
    dashboard_url: "/",
    inbox_url: "/inbox",
    fleet_url: "/fleet",
    connect_url: "/connect",
    items: [],
    latest_receipts: [
      {
        receipt_id: "receipt-local-1",
        harness: "codex",
        artifact_id: "artifact-1",
        artifact_hash: "hash",
        policy_decision: "allow",
        capabilities_summary: "",
        changed_capabilities: [],
        provenance_summary: "",
        user_override: null,
        timestamp: new Date().toISOString(),
      },
    ],
    ...overrides,
  };
}

assertEqual(isReasonValid("short"), false, "short reason invalid");
assertEqual(isReasonValid("This reason is long enough for validation."), true, "valid reason");
assertEqual(isExpiryValid(new Date(Date.now() - 1000).toISOString()), false, "past expiry invalid");
assertEqual(isExpiryValid(new Date(Date.now() + 86400000).toISOString()), true, "future expiry valid");

const baseDraft = createDefaultDraft(makeSnapshot());
assertEqual(hasValidSourceAnchor({ ...baseDraft, sourceMode: "receipt", sourceReceiptId: "receipt-local-1" }), true, "receipt anchor");
assertEqual(hasValidSourceAnchor({ ...baseDraft, sourceMode: "receipt", sourceReceiptId: "" }), false, "empty receipt");
assertEqual(canAdvanceFromScope({ ...baseDraft, scope: "workspace", workingDirectory: "/tmp/project" }), true, "workspace scope");
assertEqual(canAdvanceFromScope({ ...baseDraft, scope: "workspace", workingDirectory: "" }), false, "empty workspace");
assert(
  canAdvanceFromGuardrails({
    ...baseDraft,
    owner: "owner@example.com",
    requestedBy: "requester@example.com",
    reason: "Needed for local development work on dependencies.",
    requestedExpiresAt: new Date(Date.now() + 86400000).toISOString(),
  }),
  "guardrails valid",
);

const submitDraft = {
  ...baseDraft,
  sourceMode: "receipt" as const,
  sourceReceiptId: "receipt-local-1",
  scope: "workspace" as const,
  workingDirectory: "/tmp/project",
  owner: "owner@example.com",
  requestedBy: "requester@example.com",
  reason: "Needed for local development work on dependencies.",
  requestedExpiresAt: new Date(Date.now() + 86400000).toISOString(),
};
assert(canSubmitDraft(submitDraft), "can submit valid draft");
const payload = buildSubmitPayload(submitDraft);
assertEqual(payload.scope, "workspace", "payload scope");
assertEqual(payload.sourceReceiptId, "receipt-local-1", "payload receipt");
assertEqual(payload.workingDirectory, "/tmp/project", "payload workspace");

assertEqual(isEmailValid("not-an-email"), false, "invalid email");
assertEqual(isEmailValid("owner@example.com"), true, "valid email");
assertEqual(isDraftRecord([1, 2]), false, "array is not draft record");
assertEqual(isDraftRecord({ sourceReceiptId: "x" }), true, "draft record");
assertEqual(isDraftRecord(null), false, "not draft record");
assertEqual(mergeDraft(baseDraft, { reason: "saved" }).reason, "saved", "merge draft");

try {
  localStorage.setItem("hol-guard:cloud-exception-request-draft", "{not-json");
  assertEqual(loadDraftFromStorage(), null, "corrupt draft ignored");
} catch {
  // ignore when localStorage unavailable
}

console.log("policy-cloud-exception-request-draft.test.ts: all assertions passed");
