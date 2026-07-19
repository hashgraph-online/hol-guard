import {
  commandActivityAnalyticsQueryForFilters,
  commandSummaryIsOutsideTableFilters,
  DEFAULT_COMMAND_ACTIVITY_FILTERS,
  INITIAL_COMMAND_ACTIVITY_CURSOR_STATE,
  advanceCommandActivityCursor,
  buildCommandActivityAnalyticsQuery,
  buildCommandActivityQuery,
  commandActivityLoadFailed,
  commandActivityLoadStarted,
  commandActivityLoadSucceeded,
  parseCommandActivityFilters,
  retreatCommandActivityCursor,
  serializeCommandActivityFilters,
  updateCommandActivityFilters,
} from "./command-activity-state";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

const parsed = parseCommandActivityFilters(
  new URLSearchParams(
    "command_limit=25&command_harness=codex&command_status=allowed_unconfirmed&command_proof=pre_hook" +
      "&command_prompted=false&command_extension=command.git&command_from=2026-07-01&command_through=2026-07-19",
  ),
);
assert(parsed.limit === 25, "command filters preserve bounded limits");
assert(parsed.harness === "codex", "command filters preserve stable harness IDs");
assert(parsed.prompted === false, "command filters preserve explicit false values");
assert(parsed.occurred_through === "2026-07-19", "command filters preserve canonical dates");

const roundTrip = parseCommandActivityFilters(serializeCommandActivityFilters(parsed));
assert(JSON.stringify(roundTrip) === JSON.stringify(parsed), "command filter URL state round trips exactly");

const clearedHarness = updateCommandActivityFilters(parsed, { harness: null }, null);
assert(clearedHarness.harness === null, "global app filters can return to all apps");
const lockedHarness = updateCommandActivityFilters(parsed, { harness: null }, "claude-code");
assert(lockedHarness.harness === "claude-code", "per-app activity cannot clear its harness scope");

const malformed = parseCommandActivityFilters(
  new URLSearchParams(
    "command_limit=999&command_harness=../../private&command_status=executed&command_prompted=1&command_from=2026-02-30",
  ),
);
assert(malformed.limit === 50, "unbounded limits fall back safely");
assert(malformed.harness === null, "unstable harness IDs are discarded");
assert(malformed.execution_status === null, "unknown execution states are discarded");
assert(malformed.prompted === null, "non-canonical booleans are discarded");
assert(malformed.occurred_from === null, "impossible dates are discarded");
assert(
  parseCommandActivityFilters(new URLSearchParams("command_from=0000-01-01")).occurred_from === null,
  "year zero is rejected before transport",
);

const query = buildCommandActivityQuery(parsed, "gca1.opaque.signature");
assert(query.includes("prompted=false"), "server queries preserve explicit false values");
const ruleAnalyticsQuery = commandActivityAnalyticsQueryForFilters({
  ...parsed,
  harness: null,
  extension_id: "command.git",
  rule_id: "command.git.fetch",
});
assert(
  ruleAnalyticsQuery.dimension === "rule" && ruleAnalyticsQuery.dimension_value === "command.git.fetch",
  "rule analytics scope takes priority over its parent extension",
);
assert(
  commandSummaryIsOutsideTableFilters({ ...parsed, execution_status: "confirmed_success" }),
  "table-only filters require an explicit analytics-scope disclosure",
);
assert(query.includes("cursor=gca1.opaque.signature"), "signed cursors remain opaque query values");
assert(!query.includes("command_"), "browser-only filter prefixes never reach the daemon");

let rejectedCursor = false;
try {
  buildCommandActivityQuery(DEFAULT_COMMAND_ACTIVITY_FILTERS, "x".repeat(2_049));
} catch {
  rejectedCursor = true;
}
assert(rejectedCursor, "oversized signed cursors fail before transport");

let rejectedProgrammaticFilter = false;
try {
  buildCommandActivityQuery({ ...DEFAULT_COMMAND_ACTIVITY_FILTERS, harness: "../../private" });
} catch {
  rejectedProgrammaticFilter = true;
}
assert(rejectedProgrammaticFilter, "programmatic filters receive the same stable-ID validation as URL state");

const analytics = buildCommandActivityAnalyticsQuery({
  days: 7,
  top_limit: 5,
  dimension: "harness",
  dimension_value: "codex",
});
assert(analytics === "days=7&top_limit=5&dimension=harness&dimension_value=codex", "analytics query is bounded");

let rejectedPartialDimension = false;
try {
  buildCommandActivityAnalyticsQuery({ days: 7, top_limit: 5, dimension: "harness", dimension_value: null });
} catch {
  rejectedPartialDimension = true;
}
assert(rejectedPartialDimension, "partial analytics scopes fail before transport");

let rejectedProgrammaticDimension = false;
try {
  buildCommandActivityAnalyticsQuery({
    days: 7,
    top_limit: 5,
    dimension: "extension",
    dimension_value: "../../private",
  });
} catch {
  rejectedProgrammaticDimension = true;
}
assert(rejectedProgrammaticDimension, "programmatic analytics dimensions require stable IDs");

const firstPage = advanceCommandActivityCursor(INITIAL_COMMAND_ACTIVITY_CURSOR_STATE, "cursor-2");
const secondPage = advanceCommandActivityCursor(firstPage, "cursor-3");
assert(retreatCommandActivityCursor(secondPage).current === "cursor-2", "cursor history supports bounded back navigation");
assert(retreatCommandActivityCursor(firstPage).current === null, "cursor history returns to the first page");

const loading = commandActivityLoadStarted<string[]>(7, ["previous"]);
const staleReady = commandActivityLoadSucceeded(loading, 6, ["stale"], (items) => items.length === 0);
assert(staleReady.kind === "loading", "stale success cannot overwrite a newer request");
const ready = commandActivityLoadSucceeded(loading, 7, ["current"], (items) => items.length === 0);
assert(ready.kind === "ready" && ready.data[0] === "current", "current success produces ready state");
const empty = commandActivityLoadSucceeded(loading, 7, [], (items) => items.length === 0);
assert(empty.kind === "empty", "empty payloads have a distinct state");
const staleError = commandActivityLoadFailed(loading, 6, new Error("stale"));
assert(staleError.kind === "loading", "stale errors cannot overwrite a newer request");
const error = commandActivityLoadFailed(loading, 7, new Error("SECRET_TRANSPORT_DETAIL".repeat(1_000)));
assert(
  error.kind === "error" &&
    error.message === "Unable to load command activity." &&
    error.previous?.[0] === "previous",
  "current failures preserve prior data behind fixed privacy-safe copy",
);
