import assert from "node:assert/strict";
import type { GuardReceiptAnalyticsBucket } from "../guard-types";
import { bucketTotal, computeTrendBarHeight } from "./evidence-trend-chart";

const bucket: GuardReceiptAnalyticsBucket = {
  date_key: "2026-06-08",
  label: "Jun 8",
  allowed: 2800,
  blocked: 12,
  reviewed: 310,
};

assert.equal(bucketTotal(bucket), 3122);
assert.equal(bucketTotal({ ...bucket, allowed: 0, blocked: 0, reviewed: 0 }), 0);
assert.equal(computeTrendBarHeight(0, 100), 0);
assert.equal(computeTrendBarHeight(50, 100, 100), 50);
assert.equal(computeTrendBarHeight(5, 100, 100), 10);

console.log("evidence-trend-chart.test.ts: all tests passed");
