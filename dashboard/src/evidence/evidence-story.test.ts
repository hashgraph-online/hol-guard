import type { GuardReceipt } from "../guard-types";
import { parseEvidenceUrlState, serializeEvidenceUrlState, DEFAULT_FILTER_STATE } from "./evidence-url-state";
import { filterEvidence } from "./evidence-filters";
import { computeMetrics } from "./evidence-metrics";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`FAIL: ${message}`);
}

function makeReceipt(id: string, overrides: Partial<GuardReceipt> = {}): GuardReceipt {
  return {
    receipt_id: id,
    harness: "codex",
    artifact_id: `artifact-${id}`,
    artifact_hash: `hash-${id}`,
    policy_decision: "allow",
    capabilities_summary: `Summary ${id}`,
    changed_capabilities: [],
    provenance_summary: `Provenance ${id}`,
    user_override: null,
    artifact_name: `Tool ${id}`,
    source_scope: null,
    timestamp: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
    ...overrides,
  };
}

const r1 = makeReceipt("r1", { timestamp: "2024-06-15T10:00:00.000Z", policy_decision: "allow" });
const r2 = makeReceipt("r2", { timestamp: "2024-06-15T11:00:00.000Z", policy_decision: "block" });
const r3 = makeReceipt("r3", { timestamp: "2024-06-16T09:00:00.000Z", policy_decision: "allow" });
const r4 = makeReceipt("r4", { timestamp: "invalid-timestamp", policy_decision: "allow" });

const ALL = [r1, r2, r3, r4];

function assert_noThrow(fn: () => void, message: string): void {
  try {
    fn();
  } catch {
    throw new Error(`FAIL: ${message} - threw unexpectedly`);
  }
}

assert_noThrow(() => computeMetrics(ALL), "GR226: computeMetrics handles malformed timestamps without throwing");

const metricsNoMalformed = computeMetrics([r1, r2, r3]);
assert(metricsNoMalformed.total === 3, "GR226: total counts valid receipts correctly");

const metricsWithMalformed = computeMetrics([r1, r2, r3, r4]);
assert(metricsWithMalformed.total === 3, "GR226: malformed-timestamp receipt is gracefully skipped (not counted in total)");

assert_noThrow(
  () => filterEvidence(ALL, { ...DEFAULT_FILTER_STATE, time: "today" }),
  "GR226: filterEvidence handles malformed timestamps gracefully"
);

const filtered = filterEvidence([r1, r2, r3], { ...DEFAULT_FILTER_STATE });
assert(filtered.length === 3, "GR227: filterEvidence returns all receipts with default filters");

const filteredBlocked = filterEvidence([r1, r2, r3], { ...DEFAULT_FILTER_STATE, decision: "block" });
assert(filteredBlocked.length === 1, "GR227: story narrative - filtered view shows only blocked actions");
assert(filteredBlocked[0].receipt_id === "r2", "GR227: correct receipt in blocked filter");

const metricsStory = computeMetrics([r1, r2, r3]);
assert(metricsStory.blocked === 1, "GR227: metrics report correct blocked count for narrative");
assert(metricsStory.allowed === 2, "GR227: metrics report correct allowed count for narrative");

const storyParams = new URLSearchParams();
storyParams.set("view", "story");
const storyState = parseEvidenceUrlState(storyParams);
assert(storyState.view === "story", "GR236: story view survives URL round-trip");

const categoriesParams = new URLSearchParams();
categoriesParams.set("view", "categories");
const categoriesState = parseEvidenceUrlState(categoriesParams);
assert(categoriesState.view === "categories", "GR236: categories view survives URL round-trip");

const actionsParams = new URLSearchParams();
actionsParams.set("view", "actions");
const actionsState = parseEvidenceUrlState(actionsParams);
assert(actionsState.view === "actions", "GR236: actions view still works");

const roundTripStory = serializeEvidenceUrlState({ ...DEFAULT_FILTER_STATE, view: "story" });
const reRead = parseEvidenceUrlState(new URLSearchParams(roundTripStory));
assert(reRead.view === "story", "GR236: serialize then parse preserves story view");

const roundTripCats = serializeEvidenceUrlState({ ...DEFAULT_FILTER_STATE, view: "categories" });
const reReadCats = parseEvidenceUrlState(new URLSearchParams(roundTripCats));
assert(reReadCats.view === "categories", "GR236: serialize then parse preserves categories view");

const codexR = makeReceipt("ca1", { harness: "codex" });
const claudeR = makeReceipt("ca2", { harness: "claude" });
const codexR2 = makeReceipt("ca3", { harness: "codex" });
const allApps = [codexR, claudeR, codexR2];
const filteredCodex = filterEvidence(allApps, { ...DEFAULT_FILTER_STATE, harness: "codex" });
assert(filteredCodex.length === 2, "GR237: app grouping - filter by harness returns correct count");
assert(filteredCodex.every((r) => r.harness === "codex"), "GR237: app grouping - all returned receipts match harness");

const filteredClaude = filterEvidence(allApps, { ...DEFAULT_FILTER_STATE, harness: "claude" });
assert(filteredClaude.length === 1, "GR237: app grouping - claude filter returns 1");

const emptyMetrics = computeMetrics([]);
assert(emptyMetrics.total === 0, "GR245: empty state - metrics total is 0 for no receipts");
assert(emptyMetrics.blocked === 0, "GR245: empty state - metrics blocked is 0 for no receipts");
assert(emptyMetrics.allowed === 0, "GR245: empty state - metrics allowed is 0 for no receipts");
assert(emptyMetrics.trendBuckets.length > 0, "GR245: empty state - trendBuckets still produced (for chart rendering)");

const emptyFiltered = filterEvidence([], { ...DEFAULT_FILTER_STATE });
assert(emptyFiltered.length === 0, "GR245: empty state - filterEvidence returns empty array for no receipts");

console.log("evidence-story.test.ts: all tests passed");
