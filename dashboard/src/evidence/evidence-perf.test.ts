import type { GuardReceipt } from "../guard-types";
import { filterEvidence } from "./evidence-filters";
import { sortEvidence } from "./evidence-sort";
import { computeMetrics } from "./evidence-metrics";
import { DEFAULT_FILTER_STATE } from "./evidence-url-state";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`FAIL: ${message}`);
}

const PAGE_SIZE = 50;
const TOTAL = 100_000;
const PERF_BUDGET_MS = 2000;

function makeCapsSummary(i: number): string {
  if (i % 5 === 0) return "reads .env secrets";
  if (i % 7 === 0) return "calls http://example.com";
  return `action ${i}`;
}

function makeReceipt(i: number): GuardReceipt {
  const decisions = ["allow", "block", "review"] as const;
  const harnesses = ["codex", "claude", "cursor", "gemini"] as const;
  return {
    receipt_id: `perf-${i}`,
    harness: harnesses[i % harnesses.length],
    artifact_id: `artifact-${i}`,
    artifact_hash: `hash${i}`,
    policy_decision: decisions[i % decisions.length],
    capabilities_summary: makeCapsSummary(i),
    changed_capabilities: [],
    provenance_summary: `Provenance ${i}`,
    user_override: null,
    artifact_name: `tool-${i}`,
    source_scope: i % 3 === 0 ? "workspace" : null,
    timestamp: new Date(Date.now() - i * 1000).toISOString(),
  };
}

const receipts: GuardReceipt[] = [];
for (let i = 0; i < TOTAL; i++) {
  receipts.push(makeReceipt(i));
}

assert(receipts.length === TOTAL, `GR248: fixture has ${TOTAL} receipts`);

const filterStart = performance.now();
const filtered = filterEvidence(receipts, DEFAULT_FILTER_STATE);
const filterMs = performance.now() - filterStart;

assert(filterMs < PERF_BUDGET_MS, `GR248: filterEvidence(100k) completes in <${PERF_BUDGET_MS}ms (took ${filterMs.toFixed(0)}ms)`);
assert(filtered.length > 0, "GR248: filterEvidence returns results on 100k fixture");

const sortStart = performance.now();
const sorted = sortEvidence(filtered, "newest");
const sortMs = performance.now() - sortStart;

assert(sortMs < PERF_BUDGET_MS, `GR248: sortEvidence(100k) completes in <${PERF_BUDGET_MS}ms (took ${sortMs.toFixed(0)}ms)`);
assert(sorted.length === filtered.length, "GR248: sortEvidence preserves count");

const metricsStart = performance.now();
const metrics = computeMetrics(filtered);
const metricsMs = performance.now() - metricsStart;

assert(metricsMs < PERF_BUDGET_MS, `GR248: computeMetrics(100k) completes in <${PERF_BUDGET_MS}ms (took ${metricsMs.toFixed(0)}ms)`);
assert(metrics.total === filtered.length, "GR248: computeMetrics total matches filtered count");

const page0 = sorted.slice(0, PAGE_SIZE);
assert(page0.length === PAGE_SIZE, `GR248: page 0 shows exactly ${PAGE_SIZE} items`);

const page1 = sorted.slice(PAGE_SIZE, PAGE_SIZE * 2);
assert(page1.length === PAGE_SIZE, `GR248: page 1 shows exactly ${PAGE_SIZE} items`);

assert(page0[page0.length - 1]?.receipt_id !== page1[0]?.receipt_id, "GR248: pages do not overlap");

const totalPages = Math.ceil(sorted.length / PAGE_SIZE);
const lastPage = sorted.slice((totalPages - 1) * PAGE_SIZE);
assert(lastPage.length > 0 && lastPage.length <= PAGE_SIZE, "GR248: last page has between 1 and PAGE_SIZE items");

console.log(`evidence-perf.test.ts: all tests passed (filter=${filterMs.toFixed(0)}ms sort=${sortMs.toFixed(0)}ms metrics=${metricsMs.toFixed(0)}ms)`);
