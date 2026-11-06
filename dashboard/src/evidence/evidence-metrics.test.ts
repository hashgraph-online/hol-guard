import type { GuardReceipt } from "../guard-types";
import {
  computeMetrics,
  computeTrendBuckets,
  metricsSummaryText,
} from "./evidence-metrics";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`FAIL: ${message}`);
}

function makeReceipt(
  id: string,
  overrides: Partial<GuardReceipt> = {}
): GuardReceipt {
  return {
    receipt_id: id,
    harness: "codex",
    artifact_id: `artifact-${id}`,
    artifact_hash: `hash-${id}`,
    policy_decision: "allow",
    capabilities_summary: "",
    changed_capabilities: [],
    provenance_summary: "",
    user_override: null,
    artifact_name: `Tool ${id}`,
    source_scope: null,
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

const NOW = new Date("2024-06-15T12:00:00.000Z");

const receipts = [
  makeReceipt("r1", { harness: "codex", policy_decision: "allow", timestamp: "2024-06-15T08:00:00.000Z" }),
  makeReceipt("r2", { harness: "codex", policy_decision: "block", timestamp: "2024-06-15T09:00:00.000Z" }),
  makeReceipt("r3", { harness: "claude", policy_decision: "allow", timestamp: "2024-06-14T10:00:00.000Z" }),
  makeReceipt("r4", { harness: "claude", policy_decision: "block", timestamp: "2024-06-13T00:00:00.000Z" }),
  makeReceipt("r5", { harness: "cursor", policy_decision: "review", timestamp: "2024-06-12T00:00:00.000Z" }),
  makeReceipt("r6", { harness: "codex", policy_decision: "allow", artifact_name: "Tool r1", timestamp: "2024-06-11T00:00:00.000Z" }),
];

const metrics = computeMetrics(receipts, NOW);

assert(metrics.total === 6, "total: 6 receipts");
assert(metrics.allowed === 3, "allowed: 3");
assert(metrics.blocked === 2, "blocked: 2");
assert(metrics.reviewed === 1, "reviewed: 1 (review)");

// byHarness
assert(metrics.byHarness.has("codex"), "byHarness: codex present");
assert(metrics.byHarness.has("claude"), "byHarness: claude present");
assert(metrics.byHarness.get("codex")!.total === 3, "byHarness: codex total 3");
assert(metrics.byHarness.get("codex")!.blocked === 1, "byHarness: codex blocked 1");
assert(metrics.byHarness.get("codex")!.allowed === 2, "byHarness: codex allowed 2");
assert(metrics.byHarness.get("claude")!.blocked === 1, "byHarness: claude blocked 1");

// byCategory
assert(metrics.byCategory.size > 0, "byCategory: has entries");

// lastActivityAt
assert(metrics.lastActivityAt === "2024-06-15T09:00:00.000Z", "lastActivityAt: newest timestamp");

// topRecurring
assert(metrics.topRecurring.length > 0, "topRecurring: has entries");
const toolR1 = metrics.topRecurring.find((r) => r.name === "Tool r1");
assert(toolR1 !== undefined && toolR1.total >= 2, "topRecurring: tool r1 has 2 occurrences");

// insights
assert(metrics.insights.length > 0, "insights: has entries");
const totalInsight = metrics.insights.find((i) => i.id === "total");
assert(totalInsight !== undefined, "insights: total entry exists");
assert(totalInsight!.value === "6", "insights: total value is 6");

// computeTrendBuckets
const buckets = computeTrendBuckets(receipts, 7, NOW);
assert(buckets.length === 7, "trendBuckets: 7 buckets");
assert(buckets[buckets.length - 1].dateKey === "2024-06-15", "trendBuckets: last bucket is today");
const todayBucket = buckets.find((b) => b.dateKey === "2024-06-15");
assert(todayBucket !== undefined, "trendBuckets: today bucket exists");
assert(todayBucket!.allowed === 1 && todayBucket!.blocked === 1, "trendBuckets: today has 1 allowed + 1 blocked");

// invalid timestamps skip gracefully
const withBadTs = [
  ...receipts,
  makeReceipt("bad", { timestamp: "NOT_A_DATE" }),
];
const metricsWithBad = computeMetrics(withBadTs, NOW);
assert(metricsWithBad.total === 6, "invalid timestamp: skipped, total still 6");

// empty receipts
const emptyMetrics = computeMetrics([], NOW);
assert(emptyMetrics.total === 0, "empty: total 0");
assert(emptyMetrics.lastActivityAt === null, "empty: lastActivityAt null");
assert(emptyMetrics.insights.length > 0, "empty: still returns insights array");

// metricsSummaryText
const text = metricsSummaryText(metrics);
assert(text.includes("6"), "summary text: includes total");
assert(text.includes("3"), "summary text: includes allowed");

const emptyText = metricsSummaryText(emptyMetrics);
assert(emptyText.length > 0, "summary text: not empty for zero metrics");

console.log("evidence-metrics.test.ts: all tests passed");
