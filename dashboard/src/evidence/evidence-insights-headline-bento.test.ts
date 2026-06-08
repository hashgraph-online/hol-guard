import assert from "node:assert/strict";
import { buildBentoItems, buildInsightMetrics } from "./evidence-insights-headline-bento";
import type { GuardReceiptAnalytics } from "../guard-types";

const analytics: GuardReceiptAnalytics = {
  total: 746_300,
  allowed: 744_280,
  blocked: 2_020,
  reviewed: 0,
  first_activity_at: null,
  last_activity_at: null,
  active_day_streak: 49,
  peak_day_total: 12_400,
  daily_activity: [],
  trend_buckets: [],
  by_harness: [{ harness: "copilot", total: 100, allowed: 80, blocked: 20 }],
  top_artifacts: [],
  loaded_sample_limit: 0,
};

const compact = buildBentoItems(analytics, "compact");
assert.equal(compact.length, 4);
assert.equal(compact[0]?.label, "Current streak");
assert.equal(compact[1]?.label, "Peak day");
assert.equal(compact[2]?.label, "Stopped");
assert.equal(compact[2]?.unit, "<1% of recorded actions");
assert.equal(compact[3]?.label, "Top app");
assert.ok(
  !compact.some((item) => item.label === "Lifetime actions"),
  "compact home insights should not repeat the recorded total",
);

const zeroStreak = buildInsightMetrics({ ...analytics, active_day_streak: 0 }, "compact");
assert.equal(zeroStreak[0]?.value, "—");
assert.equal(zeroStreak[0]?.heroUnit, "No active streak");

console.log("evidence-insights-headline-bento.test.ts: all tests passed");
