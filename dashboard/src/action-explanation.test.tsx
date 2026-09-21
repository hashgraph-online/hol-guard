import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";

import { ActionExplanation } from "./action-explanation";
import { PresentationModeProvider } from "./presentation-mode-provider";
import { resolvePresentationMode } from "./presentation-mode";
import type { GuardActionExplanationV1 } from "./guard-types";

const EXPLANATION: GuardActionExplanationV1 = {
  schema_version: "guard.action-explanation.v1",
  explanation_version: "1.0.0",
  renderer_version: "1.0.0",
  action_identity: "approval:123",
  canonical_identity: "command:v1:abc",
  catalog_digest: "a".repeat(64),
  locale: "en-US",
  kind: "file_delete",
  confidence: "exact",
  uncertainty_reasons: [],
  everyday: {
    headline_message_id: "guard.everyday.filesystem.delete.headline",
    headline: "Delete a folder and everything inside it",
    summary_message_id: "guard.everyday.filesystem.delete.summary",
    summary: "Cursor wants to permanently remove the item named build.",
    impact_message_id: "guard.everyday.filesystem.delete.impact",
    impact: "Files may be difficult or impossible to recover.",
    why_guard_intervened_message_id: null,
    why_guard_intervened: null,
    recommendation_message_id: "guard.everyday.filesystem.delete.recommendation",
    recommendation: "Confirm the folder and back up important work.",
    actor_label: "Cursor",
    targets: [{ kind: "filesystem_item", label: "the item named build", scope: null, sensitivity: "normal" }],
    consequences: [
      {
        message_id: "guard.everyday.filesystem.delete.consequence",
        message: "Files may be difficult or impossible to recover.",
        severity: "high",
        confirmed: false,
      },
    ],
    safer_alternatives: [
      {
        message_id: "guard.everyday.filesystem.delete.alternative.preview",
        message: "Preview the folder contents first.",
        kind: "preview",
      },
    ],
  },
  technical: {
    available: true,
    unavailable_reason: null,
    action_type: "file_delete",
    command_display: "rm -rf ./build",
    normalized_command_display: "rm -rf ./build",
    executable: "rm",
    arguments_display: ["-rf", "./build"],
    dialect: "posix",
    transport: "shell_string",
    working_scope_display: null,
    wrappers: [],
    segments: [],
    extension_ids: [],
    rule_ids: [],
    reason_codes: [],
    policy_source: null,
    parse_confidence: "exact",
    proof_level: null,
    receipt_id: null,
    action_id: "approval:123",
  },
  redaction: {
    level: "none",
    policy_version: "1",
    omitted_fields: [],
    truncated_fields: [],
    secret_like_values_removed: false,
  },
};

function render(mode: "everyday" | "technical", explanation = EXPLANATION): string {
  const resolved = resolvePresentationMode({
    value: mode,
    explicit: true,
    schemaVersion: 1,
    revision: 4,
  });
  return renderToStaticMarkup(
    <PresentationModeProvider initialResolved={resolved} loadFromCore={false}>
      <ActionExplanation
        explanation={explanation}
        actionIdentity="approval:123"
        canonicalIdentity="command:v1:abc"
      />
    </PresentationModeProvider>,
  );
}

const everyday = render("everyday");
const technical = render("technical");

for (const markup of [everyday, technical]) {
  assert.match(markup, /data-action-identity="approval:123"/);
  assert.match(markup, /Delete a folder and everything inside it/);
  assert.match(markup, /Preview the folder contents first/);
  assert.match(markup, /Exact action/);
  assert.match(markup, /rm -rf \.\/build/);
}
assert.match(everyday, /data-presentation-mode="everyday"/);
assert.match(technical, /data-presentation-mode="technical"/);
assert.match(everyday, /hidden=""/);
assert.doesNotMatch(technical, /hidden=""/);

const mismatch = render("everyday", { ...EXPLANATION, action_identity: "approval:stale" });
assert.match(mismatch, /data-explanation-identity-mismatch/);
assert.match(mismatch, /no longer matches this action/);

const unavailable = render("technical", {
  ...EXPLANATION,
  technical: {
    ...EXPLANATION.technical,
    available: false,
    unavailable_reason: "not_retained",
    command_display: null,
    normalized_command_display: null,
    arguments_display: null,
  },
});
assert.match(unavailable, /because they were not retained/);
assert.doesNotMatch(unavailable, /rm -rf \.\/build/);
