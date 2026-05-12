import {
  buildDecisionPayload,
  scopeChoicesForRequest,
} from "./approval-scopes";
import type { GuardApprovalRequest } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const BASE_REQUEST: GuardApprovalRequest = {
  request_id: "request-scope-test",
  harness: "codex",
  artifact_id: "codex:project:bash",
  artifact_name: "bash",
  artifact_type: "command",
  artifact_hash: "sha256-scope",
  publisher: "codex-local",
  policy_action: "require-reapproval",
  recommended_scope: "artifact",
  changed_fields: ["first_seen"],
  source_scope: "project",
  config_path: "./config.toml",
  workspace: "/workspace/project",
  launch_target: "git status",
  transport: "stdio",
  review_command: "hol-guard approvals approve request-scope-test",
  approval_url: "http://127.0.0.1:4781/approvals/request-scope-test",
  status: "pending",
  resolution_action: null,
  resolution_scope: null,
  reason: null,
  created_at: "2026-04-11T12:00:00Z",
  resolved_at: null,
  action_envelope_json: null,
  decision_v2_json: null,
};

const workspacePayload = buildDecisionPayload({
  item: BASE_REQUEST,
  action: "allow",
  scope: "workspace",
  reason: "approved in review",
});

assert(
  workspacePayload.workspace === "/workspace/project",
  "T-AS-01: workspace scope sends the request workspace to the daemon"
);

for (const scope of ["artifact", "publisher", "harness", "global"] as const) {
  const payload = buildDecisionPayload({
    item: BASE_REQUEST,
    action: "allow",
    scope,
    reason: "approved in review",
  });
  assert(payload.workspace === undefined, `T-AS-02: ${scope} scope does not send a workspace`);
}

const fullScopeValues = scopeChoicesForRequest(BASE_REQUEST).map((choice) => choice.value);
assert(
  ["artifact", "workspace", "publisher", "harness", "global"].every((scope) => fullScopeValues.includes(scope)),
  "T-AS-03: requests with workspace and publisher expose all approval scope kinds"
);

const requestWithoutWorkspaceOrPublisher: GuardApprovalRequest = {
  ...BASE_REQUEST,
  request_id: "request-no-broad-source",
  publisher: null,
  workspace: null,
};
const limitedScopeValues = scopeChoicesForRequest(requestWithoutWorkspaceOrPublisher).map((choice) => choice.value);

assert(limitedScopeValues.includes("artifact"), "T-AS-04: artifact scope is always available");
assert(limitedScopeValues.includes("harness"), "T-AS-04: harness scope is available without source metadata");
assert(limitedScopeValues.includes("global"), "T-AS-04: global scope is available without source metadata");
assert(!limitedScopeValues.includes("workspace"), "T-AS-04: workspace scope is hidden when the request has no workspace");
assert(!limitedScopeValues.includes("publisher"), "T-AS-04: publisher scope is hidden when the request has no publisher");
