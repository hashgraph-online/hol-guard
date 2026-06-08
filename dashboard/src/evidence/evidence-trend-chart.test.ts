import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const chartSource = readFileSync(join(__dirname, "evidence-trend-chart.tsx"), "utf8");
const stylesSource = readFileSync(join(__dirname, "../styles.css"), "utf8");

assert(chartSource.includes('role="group"'), "trend chart: uses accessible group role");
assert(!chartSource.includes('role="img"'), "trend chart: avoids presentational img role");
assert(chartSource.includes("formatEvidenceCount"), "trend chart: formats large totals");
assert(chartSource.includes("flexGrow"), "trend chart: proportional segment sizing");
assert(chartSource.includes("min-h-[3px]"), "trend chart: minimum visible segment height");
assert(chartSource.includes("evidence-trend-chart-well"), "trend chart: column well background");
assert(chartSource.includes("createPortal"), "trend chart: portals tooltip above modals");
assert(chartSource.includes("prefers-reduced-motion"), "trend chart: respects reduced motion");
assert(stylesSource.includes(".evidence-trend-chart-bar-motion"), "styles: bar entrance animation");
assert(stylesSource.includes(".evidence-trend-chart-bar-active"), "styles: active bar elevation");

console.log("evidence-trend-chart.test.ts: all tests passed");
