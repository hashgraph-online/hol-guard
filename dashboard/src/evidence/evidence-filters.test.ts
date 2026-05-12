import type { GuardReceipt } from "../guard-types";
import {
  filterBySearch,
  filterByDecision,
  filterByHarness,
  filterByCategory,
  filterByTime,
  filterBySourceScope,
  filterEvidence,
} from "./evidence-filters";
import type { EvidenceFilterState } from "./evidence-types";
import { DEFAULT_FILTER_STATE } from "./evidence-url-state";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`FAIL: ${message}`);
}

function makeReceipt(
  id: string,
  overrides: Partial<GuardReceipt & { artifact_type?: string }> = {}
): GuardReceipt {
  return {
    receipt_id: id,
    harness: "codex",
    artifact_id: `artifact-${id}`,
    artifact_hash: `hash-${id}-abcdef1234`,
    policy_decision: "allow",
    capabilities_summary: `Summary for ${id}`,
    changed_capabilities: [],
    provenance_summary: `Provenance ${id}`,
    user_override: null,
    artifact_name: `Tool ${id}`,
    source_scope: null,
    timestamp: new Date(Date.now() - 1000).toISOString(),
    ...overrides,
  };
}

const NOW = new Date("2024-06-15T12:00:00.000Z");

const r1 = makeReceipt("r1", { harness: "codex", policy_decision: "allow", artifact_name: "my-secret-tool", capabilities_summary: "reads .env file", source_scope: "workspace" });
const r2 = makeReceipt("r2", { harness: "claude", policy_decision: "block", artifact_name: "network-fetch", capabilities_summary: "calls http://example.com", source_scope: "global" });
const r3 = makeReceipt("r3", { harness: "cursor", policy_decision: "ask", artifact_name: "file-writer", capabilities_summary: "writes to disk" });
const r4 = makeReceipt("r4", { harness: "codex", policy_decision: "allow", artifact_name: "token-helper", capabilities_summary: "handles api token" });
const r5 = makeReceipt("r5", {
  harness: "claude",
  policy_decision: "block",
  artifact_name: null,
  artifact_id: "artifact-xyz123",
  artifact_hash: "abcdef789012",
  capabilities_summary: "mcp tool call",
  timestamp: new Date("2024-06-15T08:00:00.000Z").toISOString(),
});
const r6 = makeReceipt("r6", {
  harness: "gemini",
  policy_decision: "allow",
  timestamp: new Date("2024-06-14T10:00:00.000Z").toISOString(),
});
const r7 = makeReceipt("r7", {
  harness: "gemini",
  policy_decision: "allow",
  timestamp: new Date("2024-06-09T00:00:00.000Z").toISOString(),
});
const r8 = makeReceipt("r8", {
  harness: "copilot",
  policy_decision: "allow",
  timestamp: new Date("2024-05-01T00:00:00.000Z").toISOString(),
});

const ALL = [r1, r2, r3, r4, r5, r6, r7, r8];

// filterBySearch
const byName = filterBySearch(ALL, "my-secret");
assert(byName.length === 1 && byName[0].receipt_id === "r1", "search: artifact_name");

const byHarness = filterBySearch(ALL, "cursor");
assert(byHarness.length === 1 && byHarness[0].receipt_id === "r3", "search: harness");

const byCaps = filterBySearch(ALL, "http://example.com");
assert(byCaps.length === 1 && byCaps[0].receipt_id === "r2", "search: capabilities_summary");

const byDecisionText = filterBySearch(ALL, "ask");
assert(byDecisionText.some((r) => r.receipt_id === "r3"), "search: policy_decision text");

const byArtifactId = filterBySearch(ALL, "artifact-xyz123");
assert(byArtifactId.length >= 1 && byArtifactId[0].receipt_id === "r5", "search: artifact_id");

const byHashPrefix = filterBySearch(ALL, "abcdef78");
assert(byHashPrefix.length >= 1 && byHashPrefix[0].receipt_id === "r5", "search: artifact_hash prefix");

const noMatch = filterBySearch(ALL, "zzznomatch999");
assert(noMatch.length === 0, "search: no match returns empty");

const emptySearch = filterBySearch(ALL, "");
assert(emptySearch.length === ALL.length, "search: empty returns all");

// filterByDecision
const allowed = filterByDecision(ALL, "allow");
assert(allowed.every((r) => r.policy_decision === "allow"), "decision: allow filter");
assert(allowed.length === 5, "decision: allow count");

const blocked = filterByDecision(ALL, "block");
assert(blocked.every((r) => r.policy_decision === "block"), "decision: block filter");
assert(blocked.length === 2, "decision: block count");

const asked = filterByDecision(ALL, "ask");
assert(asked.length === 1 && asked[0].receipt_id === "r3", "decision: ask filter");

const allDecision = filterByDecision(ALL, "all");
assert(allDecision.length === ALL.length, "decision: all returns all");

// filterByHarness
const codexOnly = filterByHarness(ALL, "codex");
assert(codexOnly.every((r) => r.harness === "codex"), "harness: codex only");
assert(codexOnly.length === 2, "harness: codex count");

const allHarness = filterByHarness(ALL, "all");
assert(allHarness.length === ALL.length, "harness: all returns all");

// filterByCategory
const secrets = filterByCategory(ALL, "secret");
assert(secrets.length >= 1, "category: secret filter returns results");
assert(secrets.every((r) => ["r1", "r4"].includes(r.receipt_id)), "category: secret items correct");

const network = filterByCategory(ALL, "network");
assert(network.length >= 1, "category: network filter returns results");

const emptyCategory = filterByCategory(ALL, "");
assert(emptyCategory.length === ALL.length, "category: empty returns all");

// filterByTime - compute local-time-relative timestamps so tests pass in any timezone
function localMidnight(date: Date, dayOffset: number = 0): Date {
  const d = new Date(date.getFullYear(), date.getMonth(), date.getDate());
  d.setDate(d.getDate() + dayOffset);
  return d;
}

function msAfterMidnight(date: Date, dayOffset: number, ms: number): string {
  const midnight = localMidnight(date, dayOffset);
  return new Date(midnight.getTime() + ms).toISOString();
}

const todayReceipts = [
  makeReceipt("t1", { timestamp: msAfterMidnight(NOW, 0, 9 * 3600000) }),
  makeReceipt("t2", { timestamp: msAfterMidnight(NOW, 0, 1 * 3600000) }),
  makeReceipt("t3", { timestamp: msAfterMidnight(NOW, -1, 23 * 3600000) }),
  makeReceipt("t4", { timestamp: msAfterMidnight(NOW, -7, 0) }),
  makeReceipt("t5", { timestamp: msAfterMidnight(NOW, -36, 0) }),
];

const startOfTodayMs = localMidnight(NOW).getTime();
const startOfYesterdayMs = localMidnight(NOW, -1).getTime();

const todayResult = filterByTime(todayReceipts, "today", "", NOW);
assert(todayResult.every((r) => new Date(r.timestamp).getTime() >= startOfTodayMs), "time: today");
assert(todayResult.length === 2, "time: today count");

const yesterdayResult = filterByTime(todayReceipts, "yesterday", "", NOW);
assert(
  yesterdayResult.every(
    (r) =>
      new Date(r.timestamp).getTime() >= startOfYesterdayMs &&
      new Date(r.timestamp).getTime() < startOfTodayMs
  ),
  "time: yesterday"
);
assert(yesterdayResult.length === 1, "time: yesterday count");

const last7Result = filterByTime(todayReceipts, "last7d", "", NOW);
assert(last7Result.length >= 3, "time: last7d");

const last30Result = filterByTime(todayReceipts, "last30d", "", NOW);
assert(last30Result.length >= 4, "time: last30d");

const weekResult = filterByTime(todayReceipts, "week", "", NOW);
assert(weekResult.length >= 1, "time: week");

const allTime = filterByTime(todayReceipts, "all", "", NOW);
assert(allTime.length === todayReceipts.length, "time: all");

const dayDateStr = (() => {
  const yd = localMidnight(NOW, -1);
  return `${yd.getFullYear()}-${String(yd.getMonth() + 1).padStart(2, "0")}-${String(yd.getDate()).padStart(2, "0")}`;
})();
const dayResult = filterByTime(todayReceipts, "all", dayDateStr, NOW);
assert(dayResult.length === 1 && dayResult[0].receipt_id === "t3", "time: day filter");

// filterBySourceScope
const scopeWs = filterBySourceScope(ALL, "workspace");
assert(scopeWs.length === 1 && scopeWs[0].receipt_id === "r1", "sourceScope: workspace");

const scopeEmpty = filterBySourceScope(ALL, "");
assert(scopeEmpty.length === ALL.length, "sourceScope: empty returns all");

// filterEvidence combined
const filters: EvidenceFilterState = {
  ...DEFAULT_FILTER_STATE,
  search: "secret",
  decision: "allow",
  harness: "codex",
};
const combined = filterEvidence(ALL, filters);
assert(combined.every((r) => r.policy_decision === "allow" && r.harness === "codex"), "combined: decision+harness");
assert(combined.length >= 1, "combined: returns results");

const emptyFilters: EvidenceFilterState = { ...DEFAULT_FILTER_STATE };
const noFilter = filterEvidence(ALL, emptyFilters);
assert(noFilter.length === ALL.length, "combined: default returns all");

console.log("evidence-filters.test.ts: all tests passed");
