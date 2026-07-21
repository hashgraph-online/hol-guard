import {
  normalizeCommandActivityAnalytics,
  normalizeCommandActivityDeletion,
  normalizeCommandActivityDiagnostics,
  normalizeCommandActivityInvalidation,
  normalizeCommandActivityPage,
  normalizeCommandExtensionsPage,
  normalizeCommandFeedbackResult,
} from "./command-activity-normalizers";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function activityItem() {
  return {
    activity_id: "activity:01",
    occurred_at: "2026-07-19T12:00:00+00:00",
    harness: "codex",
    hook_phase: "pre",
    execution_status: "allowed_unconfirmed",
    proof_level: "pre_hook",
    policy_action: "allow",
    decision_reason_code: "extension_match",
    controlling_rule_id: "command.git.fetch",
    parse_confidence: "exact",
    uncertainty_class: null,
    match_count: 1,
    prompted: false,
    approval_reuse_status: "not-applicable",
    receipt_link_status: "not_applicable",
    receipt_id: null,
    evaluation_latency_bucket: "le_2_ms",
    persistence_latency_bucket: "le_1_ms",
    feedback_label: null,
    schema_version: "1.0.0",
    matches: [
      {
        ordinal: 0,
        extension_id: "command.git",
        extension_version: "1.0.0",
        rule_id: "command.git.fetch",
        rule_version: "1.0.0",
        match_class: "safe_variant",
        severity: "low",
        default_floor: "review",
        safe_variant_id: "command.git.fetch.public",
        effect_classes: ["remote-state-read"],
        schema_version: "1.0.0",
      },
    ],
  };
}

const longOpaqueCursor = `gca1.${"a".repeat(300)}`;
const page = normalizeCommandActivityPage({
  schema_version: "guard.command-activity-api.v1",
  items: [activityItem()],
  next_cursor: longOpaqueCursor,
});
assert(page.items[0]?.execution_status === "allowed_unconfirmed", "activity execution proof is preserved");
assert(page.items[0]?.policy_action === "allow", "activity decision remains independent from execution proof");
assert(page.next_cursor === longOpaqueCursor, "signed opaque cursors above 256 characters survive normalization");

const dimensions = Object.fromEntries(
  ["harness", "extension", "rule", "disposition", "execution_status", "prompt_status", "proof_level", "latency"].map(
    (key) => [key, []],
  ),
);
const analytics = normalizeCommandActivityAnalytics({
  schema_version: "guard.command-activity-api.v1",
  window: { from: "2026-07-13", through: "2026-07-19", days: 7 },
  scope: { dimension: null, dimension_value: null },
  commands_checked: 1,
  trend: [{ day: "2026-07-19", count: 1 }],
  dimensions,
  dimension_breakdowns_scope: "global",
  feedback: [],
  health: {
    status: "degraded",
    dropped_events: 1,
    persistence_errors: 0,
    last_error_class: "pre_record_failed",
    last_error_at: "2026-07-19T12:00:00+00:00",
  },
});
assert(analytics.commands_checked === 1, "analytics counts normalize");
assert(analytics.health.status === "degraded", "degraded evidence health remains explicit");

const extensions = normalizeCommandExtensionsPage({
  schema_version: 2,
  source: "built-in",
  items: [
    {
      extension_id: "command.git",
      version: "1.0.0",
      name: "Git",
      description: "Git command checks",
      enabled: true,
      required: true,
      source: "built-in",
      dependencies: [],
      conflicts: [],
      delegated_protection: null,
      action_classes: ["git"],
      risk_classes: ["remote-write"],
      rule_count: 1,
      rules: [
        {
          rule_id: "command.git.fetch",
          title: "Fetch",
          description: "Classifies fetch operations",
          severity: "low",
          risk_classes: ["remote-read"],
          action_classes: ["git"],
          default_mode: "review",
          safe_variant_ids: ["command.git.fetch.public"],
          compatibility_fallback: false,
        },
      ],
    },
  ],
  next_cursor: longOpaqueCursor,
});
assert(extensions.items[0]?.rules[0]?.rule_id === "command.git.fetch", "extension rules normalize");
assert(extensions.next_cursor === longOpaqueCursor, "extension cursors use the explicit 2,048-character bound");

const feedback = normalizeCommandFeedbackResult({
  schema_version: "guard.command-activity-api.v1",
  activity_id: "activity:01",
  label: "should_not_have_interrupted",
  created_at: "2026-07-19T12:00:00+00:00",
  updated_at: "2026-07-19T12:00:00+00:00",
  changed: true,
});
assert(feedback.changed, "feedback mutation results normalize");

const countKeys = [
  "activities",
  "matches",
  "effects",
  "correlations",
  "rollup_days",
  "rollup_cells",
  "rollup_memberships",
  "rollup_pending",
  "feedback",
  "invalidations",
];
const baseCounts = Object.fromEntries(countKeys.map((key) => [key, 0]));
const diagnostics = normalizeCommandActivityDiagnostics({
  schema_version: "guard.command-activity-diagnostics.v1",
  schemas: { activity: "1.0.0", api: "guard.command-activity-api.v1", health: "1.0.0", maintenance: "1.0.0" },
  counts: { ...baseCounts, dropped_events: 0, persistence_errors: 0 },
  proof_coverage: [
    { proof_level: "pre_hook", count: 1 },
    { proof_level: "post_hook", count: 0 },
    { proof_level: "unpaired_post", count: 0 },
  ],
  stable_ids: { harnesses: ["codex"], extensions: ["command.git"], rules: ["command.git.fetch"] },
  error_classes: [],
});
assert(diagnostics.stable_ids.harnesses[0] === "codex", "diagnostic identifiers remain bounded");

const deleted = normalizeCommandActivityDeletion({
  schema_version: "guard.command-activity-diagnostics.v1",
  deleted: { ...baseCounts, activities: 1 },
});
assert(deleted.deleted.activities === 1, "deletion counts normalize");

const invalidation = normalizeCommandActivityInvalidation(4, {
  event: "command_activity_invalidated",
  activity_id: "activity:01",
});
assert(invalidation.event === "command_activity_invalidated" && invalidation.sequence === 4, "ID-only invalidations normalize");
const reset = normalizeCommandActivityInvalidation(5, { event: "command_activity_reset", reset_required: true });
assert(reset.event === "command_activity_reset", "reset invalidations normalize");

const secretSentinel = "SECRET_SENTINEL_VALUE";
let privacyError = "";
try {
  normalizeCommandActivityPage({
    schema_version: "guard.command-activity-api.v1",
    items: [{ ...activityItem(), raw_command: secretSentinel }],
    next_cursor: null,
  });
} catch (error) {
  privacyError = error instanceof Error ? error.message : String(error);
}
assert(privacyError === "Invalid command activity payload", "forbidden fields fail closed with a fixed error");
assert(!privacyError.includes(secretSentinel), "normalizer errors never serialize forbidden values");

let oversizedUnknownArrayError = false;
try {
  normalizeCommandActivityPage({
    schema_version: "guard.command-activity-api.v1",
    items: [activityItem()],
    next_cursor: null,
    unknown: new Array(4_097).fill(null),
  });
} catch {
  oversizedUnknownArrayError = true;
}
assert(oversizedUnknownArrayError, "oversized unknown arrays fail before recursive traversal");

let malformedError = false;
try {
  normalizeCommandActivityPage({
    schema_version: "guard.command-activity-api.v1",
    items: [{ ...activityItem(), match_count: 2 }],
    next_cursor: null,
  });
} catch {
  malformedError = true;
}
assert(malformedError, "inconsistent match counts fail closed");
