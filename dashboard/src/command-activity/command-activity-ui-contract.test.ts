import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

const dashboardSource = dirname(dirname(fileURLToPath(import.meta.url)));
const readSource = (path: string): string => readFileSync(join(dashboardSource, path), "utf8");

const receipts = readSource("receipts-workspace.tsx");
const evidenceViews = readSource("evidence/evidence-view-shell.tsx");
const appDetail = readSource("apps/app-detail-workspace.tsx");
const appModes = readSource("command-activity/app-command-activity-mode-tabs.tsx");
const workspace = readSource("command-activity/command-activity-workspace.tsx");
const detail = readSource("command-activity/command-activity-detail.tsx");
const home = readSource("command-activity/command-activity-home-card.tsx");

assert(evidenceViews.includes('{ key: "commands", label: "Commands" }'), "Evidence exposes Commands as a sibling view");
assert(receipts.includes('readEvidenceUrlState().view === "commands"'), "Commands remains reachable without receipt data");
assert(receipts.includes("<CommandActivityWorkspace />"), "Evidence renders the bounded command activity workbench");
assert(appDetail.includes("<CommandActivityWorkspace harness={props.harness} />"), "per-app activity locks the server query to its harness");
assert(appModes.includes('label="Command protection"'), "per-app activity exposes the approved command-protection mode");
assert(appModes.includes('role="tab"') && appModes.includes("aria-selected"), "app activity modes expose tab semantics");
assert(appModes.includes("ArrowLeft") && appModes.includes("ArrowRight"), "app activity modes support arrow navigation");
assert(workspace.includes("commandExecutionEvidenceCopy(props.harness ?? null"), "execution-proof disclosure is harness aware");
assert(workspace.includes("Showing the last loaded command activity page"), "refresh failures retain prior valid page data");
assert(workspace.includes('activity.page.kind === "empty"'), "empty command pages render an explicit state");
const summary = readSource("command-activity/command-activity-summary.tsx");
assert(
  summary.includes("Summary and trend totals do not include every active filter below."),
  "unsupported filter intersections use generic truthful scope copy",
);
assert(detail.includes('label="Containment evidence"'), "detail separates containment evidence");
assert(detail.includes('label="Workflow capability"'), "detail separates workflow capability evidence");
assert(detail.includes("FEEDBACK_LABELS.should_not_have_interrupted"), "detail exposes bounded interruption feedback");
assert(detail.includes("FEEDBACK_LABELS.expected_guard_to_stop_this"), "detail exposes bounded missed-stop feedback");
assert(!detail.includes("clearPolicy") && !detail.includes("updatePolicy"), "feedback UI cannot mutate policy");
assert(home.includes("homeCommandActivityModel"), "Home uses the zero-data and degraded-health model");
