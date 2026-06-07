import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const previewSource = readFileSync(join(here, "evidence-insights-home-preview.tsx"), "utf8");
const homeSource = readFileSync(join(here, "..", "home-dashboard.tsx"), "utf8");

assert.match(
  previewSource,
  /HomeGuardOverviewRow/,
  "home preview should render an overview row inside the stats card",
);
assert.match(
  previewSource,
  /label: "Pending"/,
  "overview row should include pending count",
);
assert.match(
  previewSource,
  /label: "Apps"/,
  "overview row should include apps count",
);
assert.match(
  previewSource,
  /label: "History"/,
  "overview row should include history count",
);
assert.doesNotMatch(
  previewSource,
  /if \(analytics\.total <= 0\) \{\s*return null;/,
  "stats card should stay visible even without analytics history",
);

assert.doesNotMatch(
  homeSource,
  /<ProofStrip/,
  "home page should not render a standalone proof strip above the stats card",
);
assert.match(
  homeSource,
  /overview=\{\{/,
  "home page should pass overview stats into the stats card",
);

console.log("evidence-insights-home-preview.test.ts: all tests passed");
