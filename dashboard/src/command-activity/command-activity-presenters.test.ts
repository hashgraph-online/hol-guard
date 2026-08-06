import {
  analyticsBucketCount,
  commandBreakdownsAreGlobalOnly,
  commandDecisionLabel,
  commandEffectLabels,
  commandExecutionEvidenceCopy,
  commandExecutionLabel,
  commandHealthCopy,
  commandInteractionLabel,
  commandMetricSummary,
  commandProofCoveragePercent,
  commandProofLabel,
  commandReasonLabel,
  commandTrendPoints,
  homeCommandActivityModel,
  safeEvidenceId,
  safeVersion,
} from "./command-activity-presenters";
import type { CommandActivityAnalytics, CommandActivityItem } from "./command-activity-types";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

const item: CommandActivityItem = {
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
      effect_classes: ["remote-state-read", "SECRET_EFFECT_SENTINEL"],
      schema_version: "1.0.0",
    },
  ],
};

const dimensions: CommandActivityAnalytics["dimensions"] = {
  harness: [],
  extension: [],
  rule: [],
  disposition: [],
  execution_status: [],
  prompt_status: [],
  proof_level: [],
  latency: [],
};
dimensions.prompt_status = [{ value: "prompted", count: 2 }];
dimensions.proof_level = [{ value: "post_hook", count: 3 }];
dimensions.execution_status = [{ value: "allowed_unconfirmed", count: 4 }];

const analytics: CommandActivityAnalytics = {
  schema_version: "guard.command-activity-api.v1",
  window: { from: "2026-07-13", through: "2026-07-19", days: 7 },
  scope: { dimension: null, dimension_value: null },
  commands_checked: 9,
  trend: [],
  dimensions,
  dimension_breakdowns_scope: "global",
  feedback: [],
  health: { status: "degraded", dropped_events: 1, persistence_errors: 0, last_error_class: null, last_error_at: null },
};

assert(commandDecisionLabel(item.policy_action) === "Allowed", "decision copy is independent");
assert(commandExecutionLabel(item.execution_status) === "Allowed; execution not confirmed", "unconfirmed copy is exact");
assert(commandProofLabel(item.proof_level) === "Pre-execution check only", "proof copy is exact");
assert(commandInteractionLabel(item) === "No review prompt recorded", "prompt copy stays factual");
assert(commandReasonLabel(item.decision_reason_code) === "A command rule controlled the decision", "known reasons map");
assert(commandReasonLabel("SECRET_REASON_SENTINEL") === "Other recorded reason", "unknown reasons never render raw");
assert(safeEvidenceId("https://private.example/path") === "Unavailable", "URL-like identifiers do not render");
assert(safeVersion("SECRET_VERSION_SENTINEL") === "Unavailable", "unknown versions do not render");
assert(commandEffectLabels(item.matches[0] as NonNullable<typeof item.matches[0]>).join() === "Remote state read", "only known effects render");
assert(analyticsBucketCount(analytics, "prompt_status", "prompted") === 2, "bucket lookup is exact");
assert(JSON.stringify(commandMetricSummary(analytics)) === JSON.stringify({ commandsChecked: 9, prompted: 2, postProof: 3, unconfirmed: 4 }), "metric summary uses supported facts");
assert(!commandBreakdownsAreGlobalOnly(analytics), "global analytics expose global breakdowns normally");
assert(
  commandBreakdownsAreGlobalOnly({ ...analytics, scope: { dimension: "harness", dimension_value: "codex" } }),
  "narrow analytics do not present global breakdowns as scoped metrics",
);
assert(commandProofCoveragePercent(analytics) === 33, "proof coverage uses commands checked as its denominator");
assert(
  commandTrendPoints({ ...analytics, trend: [{ day: "2026-07-19", count: 3 }] }, 3).map((point) => point.count).join() === "0,0,3",
  "sparse trends are zero-filled through the analytics window",
);
assert(
  commandExecutionEvidenceCopy("codex", false).includes("Codex") &&
    commandExecutionEvidenceCopy("codex", false).includes("remain unconfirmed"),
  "per-app proof disclosure names the harness and retains uncertainty",
);
assert(homeCommandActivityModel({ ...analytics, commands_checked: 0 }) === null, "home card stays absent without activity");
assert(homeCommandActivityModel(analytics)?.health?.includes("incomplete") === true, "home model carries degraded health");
assert(
  commandHealthCopy(analytics)?.includes("Guard retries automatically") === true,
  "degraded health explains automatic recovery",
);
assert(!Object.values(commandMetricSummary(analytics)).some((value) => Number.isNaN(value)), "zero denominators are unnecessary");
