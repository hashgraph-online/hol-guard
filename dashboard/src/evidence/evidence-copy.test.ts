import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { periodComparisonText } from "./evidence-period";
import type { PeriodComparison } from "./evidence-metrics";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`FAIL: ${message}`);
}

const __dirname = dirname(fileURLToPath(import.meta.url));

const base: PeriodComparison = {
  periodDays: 7,
  currentTotal: 10,
  previousTotal: 8,
  currentBlocked: 2,
  previousBlocked: 1,
  blockedDelta: 1,
  totalDelta: 2,
};

const textUp = periodComparisonText(base);
assert(typeof textUp === "string" && textUp.length > 0, "GR241: periodComparisonText returns non-empty string");
assert(!textUp.includes("\u2014"), "GR241: no em dash in period comparison text");
assert(!textUp.toLowerCase().includes("earn"), "GR241: no 'earn' in period comparison text");
assert(textUp.includes("2 more"), "GR241: upward total delta described correctly");
assert(textUp.includes("2"), "GR241: blocked count present in text");

const noChange: PeriodComparison = { ...base, totalDelta: 0, blockedDelta: 0, currentBlocked: 2, previousBlocked: 2 };
const textNoChange = periodComparisonText(noChange);
assert(textNoChange.includes("Same"), "GR241: zero delta described as same");

const textDown = periodComparisonText({ ...base, totalDelta: -3, currentTotal: 5, previousTotal: 8, blockedDelta: -1, currentBlocked: 0, previousBlocked: 1 });
assert(textDown.includes("fewer"), "GR241: downward delta described with 'fewer'");
assert(textDown.includes("No actions were stopped"), "GR241: zero blocked described correctly");

const zeroZero: PeriodComparison = { ...base, currentTotal: 0, previousTotal: 0, currentBlocked: 0, previousBlocked: 0, totalDelta: 0, blockedDelta: 0 };
const textZero = periodComparisonText(zeroZero);
assert(textZero.length > 0, "GR241: handles zero/zero period gracefully");

const workspaceSource = readFileSync(join(__dirname, "../receipts-workspace.tsx"), "utf8");
assert(
  workspaceSource.includes("HOL Guard Cloud") || workspaceSource.includes("cloud") || workspaceSource.includes("Cloud backup"),
  "GR246: cloud upsell copy present in receipts-workspace"
);

const categoryTabSource = readFileSync(join(__dirname, "category-tab.tsx"), "utf8");
assert(
  !categoryTabSource.includes("\u2014"),
  "GR247: no em dash in category-tab.tsx"
);
assert(
  !categoryTabSource.toLowerCase().includes("earn "),
  "GR247: no 'earn' word in category-tab.tsx"
);

const storyTabSource = readFileSync(join(__dirname, "story-tab.tsx"), "utf8");
assert(!storyTabSource.includes("\u2014"), "GR247: no em dash in story-tab.tsx");

const analyticsSource = readFileSync(join(__dirname, "evidence-analytics-panel.tsx"), "utf8");
const surfaceSource = readFileSync(join(__dirname, "evidence-insights-surface.tsx"), "utf8");
assert(!analyticsSource.includes("\u2014"), "GR247: no em dash in evidence-analytics-panel.tsx");
assert(!surfaceSource.includes("\u2014"), "GR247: no em dash in evidence-insights-surface.tsx");

const filterBarSource = readFileSync(join(__dirname, "evidence-filter-bar.tsx"), "utf8");
assert(
  filterBarSource.includes("aria-label") || filterBarSource.includes("aria-labelledby"),
  "GR228: filter bar contains aria-label for accessibility"
);

const actionListSource = readFileSync(join(__dirname, "evidence-action-list.tsx"), "utf8");
assert(
  actionListSource.includes("aria-label") || actionListSource.includes("aria-sort"),
  "GR228: action list contains aria-label for accessibility"
);

assert(
  analyticsSource.includes("brand-blue") || analyticsSource.includes("brand-") || surfaceSource.includes("brand-"),
  "GR230: analytics uses brand color class names"
);

assert(
  filterBarSource.includes("brand-") || filterBarSource.includes("brand-blue"),
  "GR230: filter bar uses brand color class names"
);

console.log("evidence-copy.test.ts: all tests passed");
