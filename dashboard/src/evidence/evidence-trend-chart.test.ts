import assert from "node:assert/strict";
import { selectRecentTrendBuckets } from "./evidence-trend-chart";
import type { GuardReceiptAnalyticsBucket } from "../guard-types";

const buckets: GuardReceiptAnalyticsBucket[] = Array.from({ length: 7 }, (_, index) => ({
  date_key: `2026-06-0${index + 1}`,
  label: `Day ${index + 1}`,
  allowed: index,
  blocked: 0,
  reviewed: 0,
}));

assert.equal(selectRecentTrendBuckets(buckets, 4).length, 4);
assert.equal(selectRecentTrendBuckets(buckets, 4)[0]?.date_key, "2026-06-04");
assert.equal(selectRecentTrendBuckets(buckets, 4)[3]?.date_key, "2026-06-07");
assert.deepEqual(selectRecentTrendBuckets(buckets, 0), []);

console.log("evidence-trend-chart.test.ts: all tests passed");
