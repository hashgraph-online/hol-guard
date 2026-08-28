import assert from "node:assert/strict";
import { parseActionExplanation } from "./action-explanation-normalize";

const explanation = {
  schema_version: "guard.action-explanation.v1",
  explanation_version: "1.0.0",
  renderer_version: "1.0.0",
  action_identity: "approval:1",
  canonical_identity: null,
  catalog_digest: null,
  locale: "en-US",
  kind: "unknown_action",
  confidence: "limited",
  uncertainty_reasons: ["semantic_rule_unavailable"],
  everyday: {
    headline_message_id: "guard.everyday.unknown_action.headline",
    headline: "Run an action Guard could not fully explain",
    summary_message_id: "guard.everyday.unknown_action.summary",
    summary: "Guard could not confirm the exact intent.",
    impact_message_id: "guard.everyday.unknown_action.impact",
    impact: "The action may change resources.",
    why_guard_intervened_message_id: null,
    why_guard_intervened: null,
    recommendation_message_id: "guard.everyday.unknown_action.recommendation",
    recommendation: "Review first.",
    actor_label: "Codex",
    targets: [],
    consequences: [],
    safer_alternatives: [],
  },
  technical: {
    available: false,
    unavailable_reason: "The exact action was not retained.",
    action_type: "shell_command",
    command_display: null,
    normalized_command_display: null,
    executable: null,
    arguments_display: null,
    dialect: null,
    transport: null,
    working_scope_display: null,
    wrappers: [],
    segments: [],
    extension_ids: [],
    rule_ids: [],
    reason_codes: [],
    policy_source: null,
    parse_confidence: null,
    proof_level: null,
    receipt_id: null,
    action_id: "approval:1",
  },
  redaction: {
    level: "redacted",
    policy_version: "1",
    omitted_fields: ["technical.command_display"],
    truncated_fields: [],
    secret_like_values_removed: false,
  },
};

assert.equal(parseActionExplanation(explanation, "approval:1").error, null);
assert.notEqual(parseActionExplanation(explanation, "approval:1").explanation, explanation);
assert.equal(parseActionExplanation(explanation, "approval:2").error, "identity_mismatch");
assert.equal(parseActionExplanation({ ...explanation, technical: { ...explanation.technical, unavailable_reason: null } }).error, "malformed");
assert.equal(parseActionExplanation({ ...explanation, schema_version: "future" }).error, "malformed");
assert.equal(
  parseActionExplanation({ ...explanation, everyday: { ...explanation.everyday, impact: { unsafe: true } } }).error,
  "malformed",
);
assert.equal(
  parseActionExplanation({ ...explanation, everyday: { ...explanation.everyday, recommendation: ["Review first."] } }).error,
  "malformed",
);
assert.equal(
  parseActionExplanation({ ...explanation, technical: { ...explanation.technical, command_display: { raw: "echo" } } }).error,
  "malformed",
);
assert.equal(
  parseActionExplanation({ ...explanation, everyday: { ...explanation.everyday, targets: [{ kind: "filesystem_item" }] } }).error,
  "malformed",
);
assert.equal(
  parseActionExplanation({ ...explanation, technical: { ...explanation.technical, segments: [{ executable: null }] } }).error,
  "malformed",
);
