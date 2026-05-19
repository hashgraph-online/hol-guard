import {
  resolveEnvelopeDisplayText,
  resolveStoppedCommandText,
  resolveTerminalLabel,
  displayArtifactName,
  EMPTY_QUEUE_TITLE,
  STALE_REQUEST_COPY,
  QUEUE_CONNECTION_ERROR_HEADLINE,
  QUEUE_CONNECTION_ERROR_INSTRUCTION,
  buildRecommendation,
  scopeLabel,
  buildCodexResumeUx,
} from "./approval-center-utils";
import type { GuardActionEnvelope, GuardApprovalRequest, GuardCodexResumeResult } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const BASE_ENVELOPE: GuardActionEnvelope = {
  schema_version: 1,
  action_id: "act-layout-test",
  harness: "claude-code",
  event_name: "tool_call",
  action_type: "harness_start",
  workspace: null,
  workspace_hash: null,
  tool_name: null,
  command: null,
  prompt_excerpt: null,
  target_paths: [],
  network_hosts: [],
  mcp_server: null,
  mcp_tool: null,
  package_manager: null,
  package_name: null,
  script_name: null,
  raw_payload_redacted: {}
};

const BASE_REQUEST: GuardApprovalRequest = {
  request_id: "request-layout-test",
  harness: "claude-code",
  artifact_id: "claude-code:project:bash",
  artifact_name: "bash",
  artifact_type: "command",
  artifact_hash: "sha256-layout",
  publisher: null,
  policy_action: "require-reapproval",
  recommended_scope: "artifact",
  changed_fields: ["first_seen"],
  source_scope: "project",
  config_path: "./claude.json",
  launch_target: "git status",
  transport: "stdio",
  review_command: "hol-guard approvals approve request-layout-test",
  approval_url: "http://127.0.0.1:4781/approvals/request-layout-test",
  status: "pending",
  resolution_action: null,
  resolution_scope: null,
  reason: null,
  created_at: "2026-04-11T12:00:00Z",
  resolved_at: null,
  action_envelope_json: null
};

const shellEnvelope: GuardActionEnvelope = {
  ...BASE_ENVELOPE,
  action_type: "shell_command",
  command: "git diff HEAD~1 -- src/"
};

const shellRequest: GuardApprovalRequest = {
  ...BASE_REQUEST,
  action_envelope_json: shellEnvelope
};

assert(
  resolveStoppedCommandText(shellRequest).length > 0,
  "T493: CTA section has non-empty command text for shell_command item (CTA content available above fold)"
);

assert(
  resolveStoppedCommandText(shellRequest) === "git diff HEAD~1 -- src/",
  "T494: resolveStoppedCommandText returns the envelope command for shell_command item"
);

const longCommand = "a".repeat(200);
const longCommandEnvelope: GuardActionEnvelope = {
  ...BASE_ENVELOPE,
  action_type: "shell_command",
  command: longCommand
};
const longCommandRequest: GuardApprovalRequest = {
  ...BASE_REQUEST,
  action_envelope_json: longCommandEnvelope
};

assert(
  resolveStoppedCommandText(longCommandRequest) === longCommand,
  "T495: resolveStoppedCommandText does not truncate a 200-character command string"
);

assert(
  resolveStoppedCommandText(longCommandRequest).length === 200,
  "T495: 200-char command preserved at full length"
);

const harnessStartEnvelope: GuardActionEnvelope = { ...BASE_ENVELOPE, action_type: "harness_start" };
assert(
  resolveEnvelopeDisplayText(harnessStartEnvelope) === null,
  "T496: resolveEnvelopeDisplayText returns null for harness_start; no raw content displayed"
);

assert(
  displayArtifactName(BASE_REQUEST) === "bash",
  "T497: displayArtifactName returns artifact_name when present"
);

const requestNoName: GuardApprovalRequest = {
  ...BASE_REQUEST,
  artifact_name: "",
  artifact_id: "claude-code:project:fallback-id"
};
assert(
  displayArtifactName(requestNoName) === "claude-code:project:fallback-id",
  "T497: displayArtifactName falls back to artifact_id when name is empty"
);

const requestNoNameOrId: GuardApprovalRequest = {
  ...BASE_REQUEST,
  artifact_name: "",
  artifact_id: ""
};
assert(
  displayArtifactName(requestNoNameOrId) === "this action",
  "T497: displayArtifactName falls back to 'this action' when both name and id are empty"
);

assert(
  resolveTerminalLabel(shellRequest) === "Command",
  "T479: resolveTerminalLabel returns 'Command' for shell_command action type"
);

const promptRequest: GuardApprovalRequest = {
  ...BASE_REQUEST,
  action_envelope_json: { ...BASE_ENVELOPE, action_type: "prompt", prompt_excerpt: "Ignore instructions" }
};
assert(
  resolveTerminalLabel(promptRequest) === "Prompt excerpt",
  "T480: resolveTerminalLabel returns 'Prompt excerpt' for prompt action type"
);

const fileReadRequest: GuardApprovalRequest = {
  ...BASE_REQUEST,
  action_envelope_json: { ...BASE_ENVELOPE, action_type: "file_read", target_paths: ["/etc/hosts"] }
};
assert(
  resolveTerminalLabel(fileReadRequest) === "File path",
  "T481: resolveTerminalLabel returns 'File path' for file_read action type"
);

const mcpRequest: GuardApprovalRequest = {
  ...BASE_REQUEST,
  action_envelope_json: { ...BASE_ENVELOPE, action_type: "mcp_tool", mcp_server: "my-server", mcp_tool: "fetch" }
};
assert(
  resolveTerminalLabel(mcpRequest) === "MCP server / tool",
  "T482: resolveTerminalLabel returns 'MCP server / tool' for mcp_tool action type"
);

const packageRequest: GuardApprovalRequest = {
  ...BASE_REQUEST,
  action_envelope_json: { ...BASE_ENVELOPE, action_type: "package_script", package_manager: "npm", package_name: "lodash", script_name: null }
};
assert(
  resolveTerminalLabel(packageRequest) === "Package",
  "T483: resolveTerminalLabel returns 'Package' for package_script action type"
);

const networkRequest: GuardApprovalRequest = {
  ...BASE_REQUEST,
  action_envelope_json: { ...BASE_ENVELOPE, action_type: "network_request", network_hosts: ["api.example.com"] }
};
assert(
  resolveTerminalLabel(networkRequest) === "Network destination",
  "T484: resolveTerminalLabel returns 'Network destination' for network_request action type"
);

assert(
  resolveTerminalLabel(BASE_REQUEST) === "Stopped command",
  "T479-T484: resolveTerminalLabel returns 'Stopped command' when no envelope present"
);

assert(
  EMPTY_QUEUE_TITLE === "No blocked actions",
  'C5: Empty queue shows friendly copy "No blocked actions"; EMPTY_QUEUE_TITLE constant is correct'
);

assert(
  EMPTY_QUEUE_TITLE.toLowerCase().includes("no blocked"),
  'C5: Empty queue title does not say "no items"; uses friendly language instead'
);

assert(
  STALE_REQUEST_COPY === "This request was already decided.",
  'C6: Stale request shows "already decided" copy; STALE_REQUEST_COPY constant is correct'
);

assert(
  STALE_REQUEST_COPY.toLowerCase().includes("already decided"),
  'C6: Stale request copy contains "already decided"; not approve/block buttons'
);

assert(
  scopeLabel("artifact") === "This retry only",
  "C7: Artifact scope copy makes one-retry behavior clear"
);

assert(
  scopeLabel("workspace") === "Same action in this project",
  "C8: Workspace scope copy makes same-action project behavior clear"
);

assert(
  buildRecommendation(BASE_REQUEST).includes("Project approval remembers this same action"),
  "C9: Recommendation explains project approval does not trust new sensitive actions"
);

assert(
  QUEUE_CONNECTION_ERROR_HEADLINE.toLowerCase().includes("daemon"),
  "C10: Connection error headline mentions the daemon so users know what to start"
);

assert(
  QUEUE_CONNECTION_ERROR_HEADLINE.toLowerCase().includes("approval link"),
  "C10: Connection error headline explains approval links require the daemon to be running"
);

assert(
  QUEUE_CONNECTION_ERROR_INSTRUCTION.toLowerCase().includes("reload"),
  "C11: Connection error instruction tells users to reload after starting Guard"
);

assert(
  QUEUE_CONNECTION_ERROR_INSTRUCTION.toLowerCase().includes("start"),
  "C11: Connection error instruction tells users to start Guard on this machine"
);

assert(
  scopeLabel("workspace") === "Same action in this project",
  "C12: scopeLabel for workspace is unchanged; only button label changes (GR125)"
);

assert(
  scopeLabel("global") !== "Remember for project",
  "C12: scopeLabel for global is not the project-scoped label"
);

function makeResume(status: GuardCodexResumeResult["status"], extras?: Partial<GuardCodexResumeResult>): GuardCodexResumeResult {
  return {
    status,
    supported: true,
    attempt_count: 0,
    request_id: null,
    operation_id: null,
    harness: null,
    resolution_action: null,
    strategy: null,
    thread_id: null,
    reason: null,
    message: null,
    last_error: null,
    created_at: null,
    updated_at: null,
    last_attempt_at: null,
    sent_at: null,
    ...extras,
  };
}

const uxPending = buildCodexResumeUx(makeResume("pending"));
assert(uxPending.showRetry === false, "C13: pending status has showRetry false");
assert(uxPending.headline.toLowerCase().includes("continu"), "C13: pending headline mentions continuing");

const uxInProgress = buildCodexResumeUx(makeResume("in_progress"));
assert(uxInProgress.showRetry === false, "C13: in_progress status has showRetry false");
assert(uxInProgress.headline.toLowerCase().includes("continu"), "C13: in_progress headline mentions continuing");

const uxSent = buildCodexResumeUx(makeResume("sent"));
assert(uxSent.showRetry === false, "C13: sent status has showRetry false");
assert(uxSent.headline.toLowerCase().includes("codex"), "C13: sent headline mentions Codex");

const uxAlreadySent = buildCodexResumeUx(makeResume("already_sent"));
assert(uxAlreadySent.showRetry === false, "C13: already_sent status has showRetry false");
assert(uxAlreadySent.headline === uxSent.headline, "C13: already_sent and sent have same headline");

const uxFailed = buildCodexResumeUx(makeResume("failed", { last_error: "connection lost" }));
assert(uxFailed.showRetry === true, "C13: failed status has showRetry true");
assert(uxFailed.body === "connection lost", "C13: failed uses last_error for body");

const uxFailedFallback = buildCodexResumeUx(makeResume("failed", { reason: "timeout" }));
assert(uxFailedFallback.body === "timeout", "C13: failed falls back to reason when no last_error");

const uxFailedDefault = buildCodexResumeUx(makeResume("failed"));
assert(uxFailedDefault.body !== null, "C13: failed has non-null body even without error details");

const uxSkipped = buildCodexResumeUx(makeResume("skipped"));
assert(uxSkipped.showRetry === false, "C13: skipped status has showRetry false");
assert(uxSkipped.body !== null && uxSkipped.body.toLowerCase().includes("terminal"), "C13: skipped body mentions terminal");

console.log("approval-center-layout.test.ts: all tests passed");
