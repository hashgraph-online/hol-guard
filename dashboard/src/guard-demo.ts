import type {
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardPolicyDecision,
  GuardReceipt
} from "./guard-types";

const now = "2026-04-11T12:00:00Z";

const demoRequests: GuardApprovalRequest[] = [
  {
    request_id: "request-env-reader",
    harness: "claude-code",
    artifact_id: "claude-code:project:data-pipeline",
    artifact_name: "data-pipeline",
    artifact_type: "mcp_server",
    artifact_hash: "sha256-abc123def456",
    publisher: "unknown",
    policy_action: "require-reapproval",
    recommended_scope: "artifact",
    changed_fields: ["first_seen"],
    source_scope: "project",
    config_path: "./claude.json",
    launch_target: "npx -y @data-pipeline/mcp-server",
    transport: "stdio",
    review_command: "hol-guard approvals approve request-env-reader",
    approval_url: "http://127.0.0.1:4781/approvals/request-env-reader",
    status: "pending",
    resolution_action: null,
    resolution_scope: null,
    reason: null,
    created_at: now,
    resolved_at: null,
    risk_headline: "Reads .env files and sends contents to remote API",
    risk_summary: "This MCP server requests filesystem access to read .env and .env.local files, then opens an outbound HTTPS connection to an unverified endpoint.",
    risk_signals: [
      "Reads .env, .env.local, .env.production",
      "Opens outbound connection to api.data-pipeline.io",
      "First time seen in this workspace"
    ],
    why_now: "This MCP server was just added to your Claude Code config. Guard has never certified it.",
    trigger_summary: "New MCP server added to project config — no prior approval exists."
  },
  {
    request_id: "request-workspace-skill",
    harness: "codex",
    artifact_id: "codex:project:workspace_skill",
    artifact_name: "workspace_skill",
    artifact_type: "mcp_server",
    artifact_hash: "sha256-demo-workspace-skill",
    publisher: "hashgraph-online",
    policy_action: "require-reapproval",
    recommended_scope: "artifact",
    changed_fields: ["args", "headers"],
    source_scope: "project",
    config_path: "~/.codex/config.toml",
    launch_target: "node workspace-skill.js",
    transport: "stdio",
    review_command: "hol-guard approvals approve request-workspace-skill",
    approval_url: "http://127.0.0.1:4781/approvals/request-workspace-skill",
    status: "pending",
    resolution_action: null,
    resolution_scope: null,
    reason: null,
    created_at: now,
    resolved_at: null,
    risk_headline: "Startup arguments and network headers changed",
    risk_summary: "The launch arguments and HTTP headers for this MCP server changed since the last approval. The new headers include an Authorization bearer token.",
    risk_signals: [
      "args changed: added --api-key flag",
      "headers changed: Authorization bearer token added",
      "Outbound requests may now include credentials"
    ],
    why_now: "The MCP server config was modified after your last approval.",
    trigger_summary: "Startup arguments and network headers changed since last approval."
  }
];

const demoReceipt: GuardReceipt = {
  receipt_id: "receipt-workspace-skill",
  harness: "codex",
  artifact_id: demoRequests[1].artifact_id,
  artifact_hash: "sha256-previous-workspace-skill",
  policy_decision: "allow",
  capabilities_summary: "stdio transport, outbound HTTP requests",
  changed_capabilities: ["custom headers"],
  provenance_summary: "publisher hashgraph-online · signed locally",
  user_override: "artifact",
  artifact_name: demoRequests[1].artifact_name,
  source_scope: demoRequests[1].source_scope,
  timestamp: "2026-04-10T18:42:00Z"
};

const demoPolicy: GuardPolicyDecision = {
  harness: "codex",
  scope: "artifact",
  artifact_id: demoRequests[1].artifact_id,
  workspace: null,
  publisher: demoRequests[1].publisher,
  action: "allow",
  reason: "approved locally after diff review",
  updated_at: "2026-04-10T18:42:00Z"
};

const demoDiff: GuardArtifactDiff = {
  artifact_id: demoRequests[1].artifact_id,
  harness: demoRequests[1].harness,
  changed_fields: demoRequests[1].changed_fields,
  previous_hash: "sha256-previous-workspace-skill",
  current_hash: demoRequests[1].artifact_hash,
  recorded_at: now
};

export function isGuardDemoMode(): boolean {
  if (!import.meta.env.DEV) {
    return false;
  }
  return new URLSearchParams(window.location.search).get("demo") === "1";
}

export function getDemoRequests(): GuardApprovalRequest[] {
  return demoRequests;
}

export function getDemoRequest(requestId: string): GuardApprovalRequest {
  const match = demoRequests.find((r) => r.request_id === requestId);
  if (!match) {
    throw new Error("Request failed with 404");
  }
  return match;
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
