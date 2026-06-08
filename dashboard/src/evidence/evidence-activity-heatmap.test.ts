import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { selectRecentDailyActivity } from "./evidence-activity-heatmap";
import type { GuardReceiptDailyActivity } from "../guard-types";

const days: GuardReceiptDailyActivity[] = Array.from({ length: 10 }, (_, index) => ({
  date_key: `2026-06-${String(index + 1).padStart(2, "0")}`,
  total: index,
}));

assert.equal(selectRecentDailyActivity(days, 5).length, 5);
assert.equal(selectRecentDailyActivity(days, 5)[0]?.date_key, "2026-06-06");
assert.equal(selectRecentDailyActivity(days, 5)[4]?.date_key, "2026-06-10");
assert.deepEqual(selectRecentDailyActivity(days, 0), []);

const __dirname = dirname(fileURLToPath(import.meta.url));
const heatmapSource = readFileSync(join(__dirname, "evidence-activity-heatmap.tsx"), "utf8");
const homePreviewSource = readFileSync(join(__dirname, "evidence-insights-home-preview.tsx"), "utf8");

assert(heatmapSource.includes("EvidenceActivityHeatmapMini"), "heatmap: exports mini variant");
assert(heatmapSource.includes("evidence-heatmap-4"), "heatmap mini: reuses intensity scale");
assert(homePreviewSource.includes("EvidenceActivityHeatmapMini"), "home stats card: uses mini heatmap");
assert(homePreviewSource.includes("daily_activity"), "home stats card: reads daily activity data");
assert(homePreviewSource.includes("Recent Activity"), "home stats card: labels recent activity section");
assert(!homePreviewSource.includes("EvidenceTrendChart"), "home stats card: no bar chart");

console.log("evidence-activity-heatmap.test.ts: all tests passed");
