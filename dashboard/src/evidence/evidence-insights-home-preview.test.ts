import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`FAIL: ${message}`);
}

const __dirname = dirname(fileURLToPath(import.meta.url));

const homePreviewSource = readFileSync(join(__dirname, "evidence-insights-home-preview.tsx"), "utf8");
const homeDashboardSource = readFileSync(join(__dirname, "../home-dashboard.tsx"), "utf8");
const shareButtonSource = readFileSync(join(__dirname, "evidence-insights-share-button.tsx"), "utf8");
const shareModalSource = readFileSync(join(__dirname, "evidence-insights-share-modal.tsx"), "utf8");
const shareSheetSource = readFileSync(join(__dirname, "evidence-insights-share-sheet.tsx"), "utf8");
const modalLayerSource = readFileSync(join(__dirname, "../guard-modal-layer.tsx"), "utf8");
const heatmapSource = readFileSync(join(__dirname, "evidence-activity-heatmap.tsx"), "utf8");

assert(homePreviewSource.includes("overviewStats"), "home stats card: accepts overview stats");
assert(homePreviewSource.includes("patterns from recorded actions"), "home stats card: explains overview vs insights");
assert(homePreviewSource.includes("GuardStatMetric"), "home stats card: uses shared metric cells");
assert(homePreviewSource.includes("HomeInsightsMetrics"), "home stats card: renders distinct insight metrics");
assert(homePreviewSource.includes("EvidenceActivityHeatmapMini"), "home stats card: includes mini activity heatmap");
assert(homePreviewSource.includes("Last 5 days"), "home stats card: labels recent activity section");
assert(homePreviewSource.includes("daily_activity"), "home stats card: uses daily activity series");
assert(!homePreviewSource.includes("EvidenceInsightsHeadlineBento"), "home stats card: avoids duplicate lifetime metric row");
assert(homeDashboardSource.includes('label: "Recorded"'), "home dashboard: uses recorded label instead of history");
assert(!homeDashboardSource.includes("ProofStrip"), "home dashboard: removed standalone proof strip");
assert(homeDashboardSource.includes("EvidenceInsightsHomePreview"), "home dashboard: uses unified stats card");
assert(homePreviewSource.includes("EvidenceInsightsShareButton"), "home stats card: primary share button");
assert(homePreviewSource.includes("onShare && insightsAvailable"), "home stats card: share button when insights exist");
assert(!homePreviewSource.includes("cloudConnected && onShare"), "home stats card: share not gated on cloud pair state");
assert(shareButtonSource.includes("Share publicly"), "share button: clear sharing label");
assert(!shareButtonSource.includes('variant="outline"'), "share button: uses primary styling");
assert(modalLayerSource.includes("createPortal"), "modal layer: portals to document body");
assert(modalLayerSource.includes("useFocusTrap"), "modal layer: traps focus inside dialog");
assert(modalLayerSource.includes("Escape"), "modal layer: supports escape to close");
assert(modalLayerSource.includes("z-[200]"), "modal layer: stacks above heatmap tooltips");
assert(modalLayerSource.includes("guardModalOpen"), "modal layer: signals open state for tooltip suppression");
assert(modalLayerSource.includes("previousCount"), "modal layer: reference counts nested modals");
assert(heatmapSource.includes("isGuardModalOpen"), "heatmap: suppresses tooltips while modal is open");
assert(shareModalSource.includes("GuardModalLayer"), "share modal: uses viewport modal layer");
assert(shareSheetSource.includes("GuardModalLayer"), "share sheet: uses viewport modal layer");
assert(shareSheetSource.includes("useCopyFeedbackTimeout"), "share sheet: clears copy reset timers");
assert(modalLayerSource.includes("onCloseRef"), "modal layer: stable escape handler");
assert(heatmapSource.includes("if (!displayKey) return"), "heatmap: avoids global scroll listeners without active tooltip");
assert(!shareModalSource.includes('className="fixed inset-0 z-50'), "share modal: no inline fixed overlay");

console.log("evidence-insights-home-preview.test.ts: all tests passed");
