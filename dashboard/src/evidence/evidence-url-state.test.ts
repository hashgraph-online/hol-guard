import {
  parseEvidenceUrlState,
  serializeEvidenceUrlState,
  DEFAULT_FILTER_STATE,
} from "./evidence-url-state";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`FAIL: ${message}`);
}

// Default state serializes to empty params
const defaultParams = serializeEvidenceUrlState(DEFAULT_FILTER_STATE);
assert(defaultParams.toString() === "", "default state: no params serialized");

// Round-trip: all fields
const fullState = {
  search: "hello",
  time: "last7d" as const,
  decision: "block" as const,
  harness: "codex",
  category: "secret",
  sourceScope: "workspace",
  day: "",
  sort: "oldest" as const,
  view: "insights" as const,
  selectedId: "receipt-123",
};
const serialized = serializeEvidenceUrlState(fullState);
const roundTripped = parseEvidenceUrlState(serialized);
assert(roundTripped.search === fullState.search, "round-trip: search");
assert(roundTripped.time === fullState.time, "round-trip: time");
assert(roundTripped.decision === fullState.decision, "round-trip: decision");
assert(roundTripped.harness === fullState.harness, "round-trip: harness");
assert(roundTripped.category === fullState.category, "round-trip: category");
assert(roundTripped.sourceScope === fullState.sourceScope, "round-trip: sourceScope");
assert(roundTripped.day === fullState.day, "round-trip: day");
assert(roundTripped.sort === fullState.sort, "round-trip: sort");
assert(roundTripped.view === fullState.view, "round-trip: view");
assert(roundTripped.selectedId === fullState.selectedId, "round-trip: selectedId");

// Invalid values fall back to defaults
const invalidParams = new URLSearchParams({
  time: "not-a-valid-time",
  decision: "neither",
  sort: "random-sort",
  view: "unknown-view",
});
const parsed = parseEvidenceUrlState(invalidParams);
assert(parsed.time === DEFAULT_FILTER_STATE.time, "invalid time: fallback to default");
assert(parsed.decision === DEFAULT_FILTER_STATE.decision, "invalid decision: fallback to default");
assert(parsed.sort === DEFAULT_FILTER_STATE.sort, "invalid sort: fallback to default");
assert(parsed.view === DEFAULT_FILTER_STATE.view, "invalid view: fallback to default");

// Partial state: only non-default fields in params
const partialState = { ...DEFAULT_FILTER_STATE, decision: "allow" as const };
const partialParams = serializeEvidenceUrlState(partialState);
assert(partialParams.has("decision"), "partial: decision param present");
assert(!partialParams.has("time"), "partial: time not present (is default)");
assert(!partialParams.has("sort"), "partial: sort not present (is default)");
assert(!partialParams.has("view"), "partial: view not present (is default)");

// Empty search not stored
const noSearchParams = serializeEvidenceUrlState({ ...DEFAULT_FILTER_STATE, search: "" });
assert(!noSearchParams.has("search"), "search: empty not serialized");

// Non-empty search stored
const withSearch = serializeEvidenceUrlState({ ...DEFAULT_FILTER_STATE, search: "foo" });
assert(withSearch.get("search") === "foo", "search: non-empty serialized");

// selectedId round-trip
const withSelected = serializeEvidenceUrlState({ ...DEFAULT_FILTER_STATE, selectedId: "abc-123" });
assert(withSelected.get("selected") === "abc-123", "selectedId: serialized as 'selected'");
const parsedSelected = parseEvidenceUrlState(withSelected);
assert(parsedSelected.selectedId === "abc-123", "selectedId: parsed correctly");

const dayDrillParams = new URLSearchParams({ day: "2026-06-07", view: "insights" });
const dayDrillParsed = parseEvidenceUrlState(dayDrillParams);
assert(dayDrillParsed.view === "actions", "day param: forces actions view");
assert(dayDrillParsed.day === "2026-06-07", "day param: preserves day");

const dayDrillSerialized = serializeEvidenceUrlState({
  ...DEFAULT_FILTER_STATE,
  day: "2026-06-07",
  view: "actions",
});
assert(dayDrillSerialized.get("day") === "2026-06-07", "day serialize: includes day");
assert(dayDrillSerialized.get("view") === "actions", "day serialize: includes actions view");

console.log("evidence-url-state.test.ts: all tests passed");
