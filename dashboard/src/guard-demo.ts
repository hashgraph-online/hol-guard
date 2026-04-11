import type {
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardPolicyDecision,
  GuardReceipt
} from "./guard-types";

const now = "2026-04-11T12:00:00Z";

const demoRequest: GuardApprovalRequest = {
  request_id: "request-workspace-skill",
  harness: "codex",
  artifact_id: "codex:project:workspace_skill",
  artifact_name: "workspace_skill",
  artifact_hash: "sha256-demo-workspace-skill",
  publisher: "hashgraph-online",
  policy_action: "require-reapproval",
  recommended_scope: "artifact",
  changed_fields: ["args", "headers"],
  source_scope: "project",
  config_path: "~/.codex/config.toml",
  review_command: "hol-guard approvals approve request-workspace-skill",
  approval_url: "http://127.0.0.1:4781/requests/request-workspace-skill",
  status: "pending",
  resolution_action: null,
  resolution_scope: null,
  reason: null,
  created_at: now,
  resolved_at: null
};

const demoReceipt: GuardReceipt = {
  receipt_id: "receipt-workspace-skill",
  harness: "codex",
  artifact_id: demoRequest.artifact_id,
  artifact_hash: "sha256-previous-workspace-skill",
  policy_decision: "allow",
  capabilities_summary: "stdio, outbound requests, custom headers",
  changed_capabilities: ["custom headers"],
  provenance_summary: "publisher hashgraph-online · signed locally",
  user_override: "artifact",
  artifact_name: demoRequest.artifact_name,
  source_scope: demoRequest.source_scope,
  timestamp: "2026-04-10T18:42:00Z"
};

const demoPolicy: GuardPolicyDecision = {
  harness: "codex",
  scope: "artifact",
  artifact_id: demoRequest.artifact_id,
  workspace: null,
  publisher: demoRequest.publisher,
  action: "allow",
  reason: "approved locally after diff review",
  updated_at: "2026-04-10T18:42:00Z"
};

const demoDiff: GuardArtifactDiff = {
  artifact_id: demoRequest.artifact_id,
  harness: demoRequest.harness,
  changed_fields: demoRequest.changed_fields,
  previous_hash: "sha256-previous-workspace-skill",
  current_hash: demoRequest.artifact_hash,
  recorded_at: now
};

export function isGuardDemoMode(): boolean {
  if (!import.meta.env.DEV) {
    return false;
  }
  return new URLSearchParams(window.location.search).get("demo") === "1";
}

export function getDemoRequests(): GuardApprovalRequest[] {
  return [demoRequest];
}

export function getDemoRequest(requestId: string): GuardApprovalRequest {
  if (requestId !== demoRequest.request_id) {
    throw new Error("Request failed with 404");
  }
  return demoRequest;
}

export function getDemoReceipts(): GuardReceipt[] {
  return [demoReceipt];
}

export function getDemoPolicy(harness: string): GuardPolicyDecision[] {
  return harness === demoPolicy.harness ? [demoPolicy] : [];
}

export function getDemoDiff(artifactId: string, harness: string): GuardArtifactDiff | null {
  if (artifactId !== demoDiff.artifact_id || harness !== demoDiff.harness) {
    return null;
  }
  return demoDiff;
}
