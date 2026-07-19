import {
  DEFAULT_COMMAND_ACTIVITY_QUERY,
  CommandActivityRequestError,
  advanceCommandActivityCursor,
  commandActivityAnalyticsPath,
  commandActivityListPath,
  parseCommandActivityUrlState,
  serializeCommandActivityUrlState,
  updateCommandActivityFilters,
} from "./command-activity-api";
import {
  CommandActivityContractError,
  normalizeCommandActivityAnalytics,
  normalizeCommandActivityFeedback,
  normalizeCommandActivityPage,
  normalizeCommandExtensionsPage,
} from "./command-activity-normalizers";
import { beginCommandActivityLoad, failCommandActivityLoad, loadCommandActivity } from "./command-activity-state";
import {
  COMMAND_ACTIVITY_TRUTH_COPY,
  COMMAND_DECISIONS_SIBLING,
  COMMANDS_INFORMATION_ARCHITECTURE,
  commandActivityPathForHarness,
  commandsSurface,
  shouldShowHomeCommands,
} from "./commands-information-architecture";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function expectContractError(run: () => unknown, field: string): void {
  try {
    run();
  } catch (error) {
    assert(error instanceof CommandActivityContractError, `${field}: expected contract error`);
    assert(error.field === field, `${field}: error identifies field`);
    return;
  }
  throw new Error(`${field}: expected failure`);
}

function expectRequestError(run: () => unknown, message: string): void {
  try {
    run();
  } catch (error) {
    assert(error instanceof CommandActivityRequestError, `${message}: expected request error`);
    return;
  }
  throw new Error(message);
}

function activity(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    activity_id: "activity-1",
    occurred_at: "2026-07-19T10:00:00+00:00",
    harness: "codex",
    hook_phase: "pre",
    execution_status: "allowed_unconfirmed",
    proof_level: "pre_hook",
    policy_action: "allow",
    decision_reason_code: "extension_match",
    controlling_rule_id: "command.git.status",
    parse_confidence: "exact",
    uncertainty_class: null,
    match_count: 1,
    prompted: false,
    approval_reuse_status: "not-applicable",
    receipt_link_status: "not_applicable",
    receipt_id: null,
    evaluation_latency_bucket: "le_2_ms",
    persistence_latency_bucket: "le_5_ms",
    feedback_label: null,
    schema_version: "1.0.0",
    matches: [{
      ordinal: 0,
      extension_id: "command.git",
      extension_version: "1.0.0",
      rule_id: "command.git.status",
      rule_version: "1.0.0",
      match_class: "safe_variant",
      severity: "low",
      default_floor: "review",
      safe_variant_id: "status-read",
      effect_classes: ["workspace-or-public-read"],
      schema_version: "1.0.0",
    }],
    ...overrides,
  };
}

function analytics(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema_version: "guard.command-activity-api.v1",
    window: { from: "2026-07-13", through: "2026-07-19", days: 7 },
    scope: { dimension: null, dimension_value: null },
    commands_checked: 3,
    trend: [{ day: "2026-07-19", count: 3 }],
    dimensions: {
      harness: [{ value: "codex", count: 3 }],
      extension: [{ value: "command.git", count: 3 }],
      rule: [{ value: "command.git.status", count: 3 }],
      disposition: [{ value: "allow", count: 3 }],
      execution_status: [{ value: "allowed_unconfirmed", count: 3 }],
      prompt_status: [{ value: "not_prompted", count: 3 }],
      proof_level: [{ value: "pre_hook", count: 3 }],
      latency: [{ value: "evaluation:le_2_ms", count: 3 }],
    },
    dimension_breakdowns_scope: "global",
    feedback: [{ label: "should_not_have_interrupted", count: 1 }],
    health: {
      status: "healthy",
      dropped_events: 0,
      persistence_errors: 0,
      last_error_class: null,
      last_error_at: null,
    },
    ...overrides,
  };
}

const normalizedPage = normalizeCommandActivityPage({
  schema_version: "guard.command-activity-api.v1",
  items: [activity({ raw_command: "secret", environment: { TOKEN: "secret" } })],
  next_cursor: "gca1.payload.signature",
  raw_command: "must-not-survive",
});
assert(normalizedPage.items.length === 1, "list normalizer preserves valid activity");
assert(normalizedPage.next_cursor === "gca1.payload.signature", "list normalizer preserves opaque cursor");
assert(!("raw_command" in normalizedPage.items[0]), "list normalizer allowlists privacy-safe fields");
assert(!("environment" in normalizedPage.items[0]), "list normalizer drops environment data");
assert(normalizedPage.items[0].execution_status === "allowed_unconfirmed", "execution status is literal");
assert(normalizedPage.items[0].matches[0].effect_classes[0] === "workspace-or-public-read", "effect is retained");

expectContractError(
  () => normalizeCommandActivityPage({ schema_version: "future", items: [], next_cursor: null }),
  "response.schema_version",
);
expectContractError(
  () => normalizeCommandActivityPage({
    schema_version: "guard.command-activity-api.v1",
    items: [activity({ execution_status: "executed" })],
    next_cursor: null,
  }),
  "response.items[0].execution_status",
);
expectContractError(
  () => normalizeCommandActivityPage({
    schema_version: "guard.command-activity-api.v1",
    items: [activity({ match_count: 2 })],
    next_cursor: null,
  }),
  "response.items[0].match_count",
);
expectContractError(
  () => normalizeCommandActivityPage({
    schema_version: "guard.command-activity-api.v1",
    items: [activity({ receipt_id: undefined })],
    next_cursor: null,
  }),
  "response.items[0].receipt_id",
);

const normalizedAnalytics = normalizeCommandActivityAnalytics(analytics());
assert(normalizedAnalytics.commands_checked === 3, "analytics preserves total");
assert(normalizedAnalytics.dimension_breakdowns_scope === "global", "global breakdown scope is explicit");
assert(normalizedAnalytics.health.status === "healthy", "health is normalized");
expectContractError(
  () => normalizeCommandActivityAnalytics(analytics({ dimension_breakdowns_scope: "filtered" })),
  "response.dimension_breakdowns_scope",
);
expectContractError(
  () => normalizeCommandActivityAnalytics(analytics({ dimensions: { harness: [] } })),
  "response.dimensions.extension",
);
expectContractError(
  () => normalizeCommandActivityAnalytics(analytics({ scope: { dimension: "harness", dimension_value: null } })),
  "response.scope",
);
expectContractError(
  () => normalizeCommandActivityAnalytics(analytics({ window: { from: "2026-02-30", through: "2026-03-01", days: 1 } })),
  "response.window.from",
);
expectContractError(
  () => normalizeCommandActivityAnalytics(analytics({ window: { from: "0000-01-01", through: "2026-03-01", days: 1 } })),
  "response.window.from",
);

const normalizedExtensions = normalizeCommandExtensionsPage({
  schema_version: 2,
  source: "built-in",
  items: [{
    extension_id: "command.git",
    version: "1.0.0",
    name: "Git",
    description: "Git command checks",
    enabled: true,
    required: false,
    source: "built-in",
    dependencies: [],
    conflicts: [],
    delegated_protection: null,
    action_classes: ["git-read"],
    risk_classes: ["remote-state"],
    rule_count: 1,
    rules: [{
      rule_id: "command.git.status",
      title: "Git status",
      description: "Checks repository status",
      severity: "low",
      risk_classes: ["remote-state"],
      action_classes: ["git-read"],
      default_mode: "review",
      safe_variant_ids: ["status-read"],
      compatibility_fallback: false,
    }],
  }],
  next_cursor: null,
});
assert(normalizedExtensions.items[0].rules[0].default_mode === "review", "extension rule mode is normalized");
expectContractError(
  () => normalizeCommandExtensionsPage({
    schema_version: 2,
    source: "built-in",
    items: [{ ...normalizedExtensions.items[0], rule_count: 2 }],
    next_cursor: null,
  }),
  "response.items[0].rule_count",
);

const feedback = normalizeCommandActivityFeedback({
  schema_version: "guard.command-activity-api.v1",
  activity_id: "activity-1",
  label: "expected_guard_to_stop_this",
  created_at: "2026-07-19T10:00:00Z",
  updated_at: "2026-07-19T10:01:00Z",
  changed: true,
});
assert(feedback.changed && feedback.label === "expected_guard_to_stop_this", "feedback response is typed");

const filtered = updateCommandActivityFilters(
  advanceCommandActivityCursor(DEFAULT_COMMAND_ACTIVITY_QUERY, "gca1.cursor.signature"),
  {
    harness: "codex",
    executionStatus: "confirmed_success",
    proofLevel: "post_hook",
    prompted: false,
    extensionId: "command.git",
    occurredFrom: "2026-07-01",
    occurredThrough: "2026-07-19",
  },
);
assert(filtered.cursor === null, "any filter update clears the filter-bound cursor");
const withCursor = advanceCommandActivityCursor(filtered, "gca1.next.signature");
const listPath = commandActivityListPath(withCursor);
assert(listPath.startsWith("/v1/command-activity?"), "list path targets local command API");
assert(listPath.includes("harness=codex"), "list path includes harness filter");
assert(listPath.includes("prompted=false"), "list path preserves explicit false");
assert(listPath.includes("cursor=gca1.next.signature"), "list path includes opaque cursor");
assert(
  commandActivityAnalyticsPath({ days: 7, topLimit: 8, dimension: "harness", dimensionValue: "codex" }) ===
    "/v1/command-activity/analytics?days=7&top_limit=8&dimension=harness&dimension_value=codex",
  "analytics query is deterministic",
);
expectRequestError(
  () => commandActivityAnalyticsPath({ days: 7, topLimit: 8, dimension: "harness", dimensionValue: "not-a-harness" }),
  "unknown analytics harness is rejected locally",
);
expectRequestError(
  () => updateCommandActivityFilters(DEFAULT_COMMAND_ACTIVITY_QUERY, {
    occurredFrom: "2026-02-30",
  }),
  "impossible list date is rejected locally",
);
expectRequestError(
  () => updateCommandActivityFilters(DEFAULT_COMMAND_ACTIVITY_QUERY, {
    occurredFrom: "0000-01-01",
  }),
  "year-zero list date is rejected locally",
);
expectRequestError(
  () => updateCommandActivityFilters(DEFAULT_COMMAND_ACTIVITY_QUERY, {
    occurredFrom: "2025-01-01",
    occurredThrough: "2026-02-02",
  }),
  "397-day list span is rejected locally",
);

const serialized = serializeCommandActivityUrlState(withCursor);
const roundTrip = parseCommandActivityUrlState(serialized);
assert(JSON.stringify(roundTrip) === JSON.stringify(withCursor), "filter and cursor URL state round trips");
const malformedUrl = parseCommandActivityUrlState(new URLSearchParams({
  commandLimit: "1000",
  commandHarness: "unknown",
  commandFrom: "2026-08-01",
  commandThrough: "2026-07-01",
  commandCursor: "",
}));
assert(malformedUrl.filters.limit === 50, "malformed URL limit falls back safely");
assert(malformedUrl.filters.harness === null, "unknown URL harness is ignored");
assert(malformedUrl.filters.occurredFrom === null, "reversed URL range is cleared");
assert(malformedUrl.cursor === null, "empty URL cursor is cleared");

const readyState = { kind: "ready" as const, data: normalizedPage };
const loadingState = beginCommandActivityLoad(readyState);
assert(loadingState.kind === "loading" && loadingState.previous === normalizedPage, "refresh retains last good data");
const failedState = failCommandActivityLoad(loadingState, new Error("daemon unavailable"));
assert(failedState.kind === "error" && failedState.previous === normalizedPage, "refresh error retains last good data");
const opaqueFailure = failCommandActivityLoad(loadingState, "raw command detail must not render");
assert(
  opaqueFailure.kind === "error" && opaqueFailure.message === "Command activity is temporarily unavailable.",
  "non-Error throws use privacy-safe fallback copy",
);
const emptyState = await loadCommandActivity(
  { kind: "idle" },
  async () => ({ ...normalizedPage, items: [] }),
  (page) => page.items.length === 0,
);
assert(emptyState.kind === "empty", "loader distinguishes an empty successful response");

assert(COMMANDS_INFORMATION_ARCHITECTURE.length === 3, "Commands IA owns three surfaces");
assert(COMMAND_DECISIONS_SIBLING.route === "/evidence?view=actions", "decision receipts remain a sibling surface");
assert(commandsSurface("evidence").route === "/evidence?view=commands", "Evidence owns global Commands");
assert(commandsSurface("app-activity").scope === "selected-app", "app Commands are harness scoped");
assert(commandsSurface("home").visibility === "when-command-data-exists", "Home card is data conditional");
assert(
  commandActivityPathForHarness("claude-code") === "/apps/claude-code?tab=activity&activity=commands",
  "app route is deterministic",
);
assert(!shouldShowHomeCommands(0) && shouldShowHomeCommands(1), "Home card appears only after data exists");
assert(COMMAND_ACTIVITY_TRUTH_COPY.activityMeaning.includes("not a threat"), "activity is not a threat claim");
assert(COMMAND_ACTIVITY_TRUTH_COPY.allowedUnconfirmed.includes("not confirmed"), "unconfirmed is truthful");
