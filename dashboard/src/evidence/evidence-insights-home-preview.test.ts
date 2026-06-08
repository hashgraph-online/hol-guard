import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`FAIL: ${message}`);
}

const __dirname = dirname(fileURLToPath(import.meta.url));

const homePreviewSource = readFileSync(join(__dirname, "evidence-insights-home-preview.tsx"), "utf8");
const homeDashboardSource = readFileSync(join(__dirname, "../home-dashboard.tsx"), "utf8");
const shareModalSource = readFileSync(join(__dirname, "evidence-insights-share-modal.tsx"), "utf8");
const shareSheetSource = readFileSync(join(__dirname, "evidence-insights-share-sheet.tsx"), "utf8");
const modalLayerSource = readFileSync(join(__dirname, "../guard-modal-layer.tsx"), "utf8");

assert(homePreviewSource.includes("overviewStats"), "home stats card: accepts overview stats");
assert(homePreviewSource.includes("patterns from recorded actions"), "home stats card: explains overview vs insights");
assert(homePreviewSource.includes("GuardStatMetric"), "home stats card: uses shared metric cells");
assert(homePreviewSource.includes("HomeInsightsMetrics"), "home stats card: renders distinct insight metrics");
assert(!homePreviewSource.includes("EvidenceInsightsHeadlineBento"), "home stats card: avoids duplicate lifetime metric row");
assert(homeDashboardSource.includes('label: "Recorded"'), "home dashboard: uses recorded label instead of history");
assert(!homeDashboardSource.includes("ProofStrip"), "home dashboard: removed standalone proof strip");
assert(homeDashboardSource.includes("EvidenceInsightsHomePreview"), "home dashboard: uses unified stats card");
assert(modalLayerSource.includes("createPortal"), "modal layer: portals to document body");
assert(modalLayerSource.includes("useFocusTrap"), "modal layer: traps focus inside dialog");
assert(modalLayerSource.includes("Escape"), "modal layer: supports escape to close");
assert(shareModalSource.includes("GuardModalLayer"), "share modal: uses viewport modal layer");
assert(shareSheetSource.includes("GuardModalLayer"), "share sheet: uses viewport modal layer");
assert(!shareModalSource.includes('className="fixed inset-0 z-50'), "share modal: no inline fixed overlay");

console.log("evidence-insights-home-preview.test.ts: all tests passed");
