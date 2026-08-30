import assert from "node:assert/strict";
import type { GuardApprovalRequest } from "./guard-types";
import { resolveSecondaryRiskSummary } from "./secondary-risk-dedupe";

const BASE_REQUEST: GuardApprovalRequest = {
  request_id: "srd-req-1",
  harness: "codex",
  artifact_id: "codex:project:bash",
  artifact_name: "bash",
  artifact_type: "command",
  artifact_hash: "sha256-srd",
  publisher: "codex-local",
  policy_action: "require-reapproval",
  recommended_scope: "artifact",
  changed_fields: ["first_seen"],
  source_scope: "project",
  config_path: "/Users/test/.codex/config.toml",
  workspace: "/workspace/project",
  launch_target: null,
  transport: "stdio",
  review_command: "hol-guard approvals approve srd-req-1",
  approval_url: "http://127.0.0.1:4455/approvals/srd-req-1",
  status: "pending",
  resolution_action: null,
  resolution_scope: null,
  reason: null,
  created_at: "2026-04-01T10:00:00Z",
  resolved_at: null,
  action_envelope_json: null,
  decision_v2_json: null,
};

const COMPOUND_SHELL_PRIMARY_DETAIL =
  "Sensitive native tool action (unresolved shell execution context): Guard could not prove the working directory for every shell segment and requires one conservative decision before the user confirms execution (shell_cwd_workspace_escape). Use a literal, existing in-workspace directory with deterministic cd/pushd/popd control flow, or run the command from the intended directory.";

const COMPOUND_FINDINGS_DUPLICATE_RISK_REQUEST: GuardApprovalRequest = {
  ...BASE_REQUEST,
  request_id: "srd-compound-findings-duplicate-risk",
  risk_summary: `Compound command findings: ${COMPOUND_SHELL_PRIMARY_DETAIL} Guard requires one review because part of this shell command is unresolved.`,
  decision_v2_json: {
    guard_action: "require-reapproval",
    action: "ask",
    reason: "unresolved shell execution context",
    user_title: "Review required",
    user_body: COMPOUND_SHELL_PRIMARY_DETAIL,
    harness_message: "Paused",
    dashboard_primary_detail: COMPOUND_SHELL_PRIMARY_DETAIL,
    approval_scopes: ["artifact"],
    retry_instruction: null,
    confidence: "likely",
    signals: [],
  },
};
assert(
  resolveSecondaryRiskSummary(COMPOUND_FINDINGS_DUPLICATE_RISK_REQUEST) === null,
  "SRD-01: secondary risk summary hides compound findings that restate the primary detail plus review boilerplate"
);

const COMPOUND_FINDINGS_TRIGGER_FALLBACK_REQUEST: GuardApprovalRequest = {
  ...BASE_REQUEST,
  request_id: "srd-compound-findings-trigger-fallback",
  trigger_summary: COMPOUND_SHELL_PRIMARY_DETAIL,
  risk_summary: `Compound command findings: ${COMPOUND_SHELL_PRIMARY_DETAIL} Guard requires one review because part of this shell command is unresolved.`,
};
assert(
  resolveSecondaryRiskSummary(COMPOUND_FINDINGS_TRIGGER_FALLBACK_REQUEST) === null,
  "SRD-02: secondary risk summary hides compound findings that restate the trigger summary detail"
);

const COMPOUND_FINDINGS_DISTINCT_RISK_REQUEST: GuardApprovalRequest = {
  ...COMPOUND_FINDINGS_DUPLICATE_RISK_REQUEST,
  request_id: "srd-compound-findings-distinct-risk",
  risk_summary: `Compound command findings: ${COMPOUND_SHELL_PRIMARY_DETAIL} This command may expose credentials from the ignored directory.`,
};
assert(
  resolveSecondaryRiskSummary(COMPOUND_FINDINGS_DISTINCT_RISK_REQUEST) ===
    COMPOUND_FINDINGS_DISTINCT_RISK_REQUEST.risk_summary,
  "SRD-03: secondary risk summary keeps compound findings when a segment adds distinct safety context"
);

const COMPOUND_FINDINGS_BOILERPLATE_ONLY_REQUEST: GuardApprovalRequest = {
  ...BASE_REQUEST,
  request_id: "srd-compound-findings-boilerplate-only",
  risk_summary: "Compound command findings: Guard requires one review because part of this shell command is unresolved.",
};
assert(
  resolveSecondaryRiskSummary(COMPOUND_FINDINGS_BOILERPLATE_ONLY_REQUEST) ===
    COMPOUND_FINDINGS_BOILERPLATE_ONLY_REQUEST.risk_summary,
  "SRD-04: secondary risk summary keeps boilerplate-only compound findings when no primary detail exists"
);

const LONG_PROMPT_EXCERPT =
  "Summarize the incident timeline from the on-call notes and draft the status update for the internal review thread before standup.";
const PROMPT_TRANSMIT_CONTEXT_REQUEST: GuardApprovalRequest = {
  ...BASE_REQUEST,
  request_id: "srd-prompt-transmit-context",
  artifact_type: "prompt_request",
  risk_summary: `Codex prompt for \`.npmrc\`: ${LONG_PROMPT_EXCERPT} would transmit private data to a third-party service.`,
  action_envelope_json: {
    schema_version: 1,
    action_id: "act-srd-1",
    harness: "codex",
    event_name: "tool_call",
    action_type: "prompt",
    workspace: null,
    workspace_hash: null,
    tool_name: null,
    command: null,
    prompt_excerpt: LONG_PROMPT_EXCERPT,
    prompt_text: null,
    target_paths: [],
    network_hosts: [],
    mcp_server: null,
    mcp_tool: null,
    package_manager: null,
    package_name: null,
  },
};
assert(
  resolveSecondaryRiskSummary(PROMPT_TRANSMIT_CONTEXT_REQUEST) === PROMPT_TRANSMIT_CONTEXT_REQUEST.risk_summary,
  "SRD-05: secondary risk summary keeps appended unclassified safety reasons such as third-party transmission"
);

console.log("secondary-risk-dedupe.test.ts: all tests passed");
