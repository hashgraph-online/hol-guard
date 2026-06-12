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
const shareModalSource = readFileSync(join(__dirname, "evidence-insights-share-modal.tsx"), "utf8");
const shareSheetSource = readFileSync(join(__dirname, "evidence-insights-share-sheet.tsx"), "utf8");
const modalLayerSource = readFileSync(join(__dirname, "../guard-modal-layer.tsx"), "utf8");
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
assert(shareModalSource.includes("GuardModalLayer"), "insights share modal: uses viewport modal layer");
assert(shareSheetSource.includes("useCopyFeedbackTimeout"), "insights share sheet: clears copy reset timers");
assert(surfaceSource.includes("handleShareClose"), "insights surface: stable share modal close handler");
assert(heatmapSource.includes("if (!displayKey) return"), "insights heatmap: avoids idle global scroll listeners");
assert(modalLayerSource.includes("onCloseRef"), "insights share modal: stable escape close handler");
assert(modalLayerSource.includes("createPortal"), "insights share modal: portal layer renders to body");

console.log("evidence-insights-layout.test.ts: all tests passed");
