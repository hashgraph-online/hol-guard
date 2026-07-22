import {
  ADVANCED_SCOPE_VALUES,
  advancedScopeChoicesForRequest,
  buildDecisionPayload,
  isAdvancedScope,
  normalizeDecisionScope,
  recommendedScopeForAction,
  requestSupportsScope,
  scopeChoicesForRequest,
  standardScopeChoicesForRequest,
  taskCapabilityExplanation,
} from "./approval-scopes";
import type { GuardApprovalRequest } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function assertThrows(callback: () => void, expected: string, message: string): void {
  try {
    callback();
  } catch (error) {
    assert(error instanceof Error && error.message.includes(expected), message);
    return;
  }
  throw new Error(message);
}

const BASE_REQUEST: GuardApprovalRequest = {
  request_id: "request-scope-test",
  harness: "codex",
  artifact_id: "codex:project:bash",
  artifact_name: "bash",
  artifact_type: "tool_action_request",
  artifact_hash: "sha256-scope",
  publisher: "codex-local",
  policy_action: "require-reapproval",
  recommended_scope: "artifact",
  allowed_scopes: ["artifact"],
  scope_contract_version: "guard.approval-scopes.v2",
  scope_contract_digest: "scope-digest",
  allowed_scopes_by_action: {
    allow: ["artifact"],
    block: ["artifact", "workspace", "publisher", "harness", "global"],
  },
  recommended_scope_by_action: { allow: "artifact", block: "artifact" },
  scope_restrictions: ["broad_allow_requires_positive_proof", "task_capability_not_enabled"],
  task_capability_eligibility: {
    eligible: false,
    reason_codes: ["task_capability_not_enabled"],
  },
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

const allowPayload = buildDecisionPayload({
  item: BASE_REQUEST,
  action: "allow",
  scope: "global",
  reason: "approved in review",
});

assert(allowPayload.scope === "artifact", "T-AS-01: stale broad allow selection narrows to eligible artifact scope");
assert(allowPayload.workspace === undefined, "T-AS-02: artifact allow does not send a workspace");
assert(
  allowPayload.scope_contract_version === "guard.approval-scopes.v2" &&
    allowPayload.scope_contract_digest === "scope-digest",
  "T-AS-03: resolution payload binds the displayed scope contract",
);

const blockPayload = buildDecisionPayload({
  item: BASE_REQUEST,
  action: "block",
  scope: "workspace",
  reason: "blocked in review",
});
assert(blockPayload.workspace === "/workspace/project", "T-AS-04: workspace block sends the request workspace");

const allowScopes = scopeChoicesForRequest(BASE_REQUEST, "allow").map((choice) => choice.value);
const blockScopes = scopeChoicesForRequest(BASE_REQUEST, "block").map((choice) => choice.value);
assert(allowScopes.join(",") === "artifact", "T-AS-05: UI shows only the server-provided allow scope");
assert(
  blockScopes.join(",") === "artifact,workspace,publisher,harness,global",
  "T-AS-06: UI preserves every server-provided block scope",
);
assert(!requestSupportsScope(BASE_REQUEST, "allow", "global"), "T-AS-07: Everywhere is unavailable for allow");
assert(requestSupportsScope(BASE_REQUEST, "block", "global"), "T-AS-08: Everywhere remains available for block");

const legacyRequest: GuardApprovalRequest = {
  ...BASE_REQUEST,
  request_id: "legacy-request",
  allowed_scopes: undefined,
  allowed_scopes_by_action: undefined,
  recommended_scope_by_action: undefined,
  scope_contract_version: undefined,
  scope_contract_digest: undefined,
  scope_restrictions: undefined,
  task_capability_eligibility: undefined,
};
assert(
  scopeChoicesForRequest(legacyRequest, "allow").map((choice) => choice.value).join(",") === "artifact",
  "T-AS-09: missing metadata fails closed to artifact-only allow",
);
assert(
  scopeChoicesForRequest(legacyRequest, "block").map((choice) => choice.value).join(",") === "artifact",
  "T-AS-10: missing metadata fails closed to artifact-only block",
);

const incompleteContractRequest: GuardApprovalRequest = {
  ...BASE_REQUEST,
  request_id: "incomplete-contract-request",
  scope_contract_digest: null,
};
assert(
  scopeChoicesForRequest(incompleteContractRequest, "allow").length === 0 &&
    scopeChoicesForRequest(incompleteContractRequest, "block").length === 0,
  "T-AS-10a: incomplete contract bindings expose no decision scopes",
);
assertThrows(
  () =>
    buildDecisionPayload({
      item: incompleteContractRequest,
      action: "allow",
      scope: "artifact",
      reason: "no",
    }),
  "scope contract is incomplete",
  "T-AS-10b: incomplete contract bindings cannot downgrade to legacy resolution",
);

const nonOverridableRequest: GuardApprovalRequest = {
  ...BASE_REQUEST,
  request_id: "blocked-request",
  policy_action: "block",
  recommended_scope: null,
  allowed_scopes: [],
  allowed_scopes_by_action: { allow: [], block: ["artifact", "global"] },
  recommended_scope_by_action: { allow: null, block: "artifact" },
  scope_restrictions: ["current_action_not_overridable"],
};
assert(
  normalizeDecisionScope(nonOverridableRequest, "allow", "artifact") === null,
  "T-AS-11: an action with no allow scope stays unapprovable",
);
assert(
  recommendedScopeForAction(nonOverridableRequest, "block") === "artifact",
  "T-AS-12: block uses its independent recommendation",
);
assertThrows(
  () => buildDecisionPayload({ item: nonOverridableRequest, action: "allow", scope: "artifact", reason: "no" }),
  "No eligible allow scope",
  "T-AS-13: payload construction rejects an unavailable action",
);
assert(
  taskCapabilityExplanation(nonOverridableRequest)?.includes("cannot override") === true,
  "T-AS-14: task access copy explains protected actions",
);
assert(
  taskCapabilityExplanation(BASE_REQUEST)?.includes("not available") === true,
  "T-AS-15: task access copy truthfully explains disabled eligibility",
);

assert(ADVANCED_SCOPE_VALUES.has("global"), "T-AS-16: global remains the only advanced scope");
assert(isAdvancedScope("global") && !isAdvancedScope("workspace"), "T-AS-17: advanced scope classification is stable");
assert(
  advancedScopeChoicesForRequest(BASE_REQUEST, "allow").length === 0,
  "T-AS-18: advanced allow is absent when the contract excludes it",
);
assert(
  advancedScopeChoicesForRequest(BASE_REQUEST, "block").map((choice) => choice.value).join(",") === "global",
  "T-AS-19: advanced block renders only eligible global scope",
);
assert(
  standardScopeChoicesForRequest(BASE_REQUEST, "block").map((choice) => choice.value).join(",") ===
    "artifact,workspace,publisher,harness",
  "T-AS-20: standard block scopes exclude the advanced choice",
);
