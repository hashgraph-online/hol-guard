import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`FAIL: ${message}`);
}

const __dirname = dirname(fileURLToPath(import.meta.url));

const surfaceSource = readFileSync(join(__dirname, "evidence-insights-surface.tsx"), "utf8");
const panelSource = readFileSync(join(__dirname, "evidence-analytics-panel.tsx"), "utf8");
const heatmapSource = readFileSync(join(__dirname, "evidence-activity-heatmap.tsx"), "utf8");
const provenanceSource = readFileSync(join(__dirname, "evidence-data-provenance-strip.tsx"), "utf8");
const workspaceSource = readFileSync(join(__dirname, "../receipts-workspace.tsx"), "utf8");

assert(surfaceSource.includes("EvidenceInsightsSurface"), "insights layout: surface component exists");
assert(!surfaceSource.includes("Activity Insights"), "insights layout: removed redundant Activity Insights card");
assert(surfaceSource.includes("EvidenceDataProvenanceStrip"), "insights layout: provenance strip wired");
assert(provenanceSource.includes("full local store"), "insights layout: provenance mentions full local store");
assert(surfaceSource.includes("EvidenceShareBar"), "insights layout: unified share bars for apps and actions");
assert(heatmapSource.includes("createPortal"), "insights heatmap: cell-following tooltip portal");
assert(heatmapSource.includes('role="grid"'), "insights heatmap: grid role for keyboard nav");
assert(heatmapSource.includes("onSelectDay"), "insights heatmap: supports drill-down callback");
assert(panelSource.includes("EvidenceInsightsSurface"), "insights panel: delegates to surface");
assert(
  workspaceSource.includes("onFilterDay={handleFilterDay}"),
  "insights workspace: drill-down handler wired",
);
assert(
  workspaceSource.includes("full local store"),
  "insights workspace: header description mentions full local store",
);

console.log("evidence-insights-layout.test.ts: all tests passed");
