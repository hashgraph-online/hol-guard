import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";

import {
  GuardRepairControl,
  GuardRepairStepList,
  repairHeadline,
  repairStepLabel,
  repairStepTone,
} from "./guard-repair-control";
import {
  describeAffectedHarness,
  GuardHookRemovalPanel,
  remainingHooksMessage,
  removalOutcomeMessage,
} from "./guard-hook-removal-panel";
import { normalizeHookRemovalReport, normalizeRepairReport } from "./guard-repair-api";

const report = normalizeRepairReport({
  schema: "guard.repair.v1",
  dry_run: false,
  status: "partial",
  summary: "x",
  steps: [
    { step: "daemon", title: "Guard daemon", status: "ok", summary: "Healthy." },
    { step: "hooks", title: "Harness hooks", status: "error", summary: "Could not reinstall codex." },
    { step: "bad", title: "Odd", status: "weird", summary: 5 },
    "junk",
  ],
});
assert.equal(report.steps.length, 3);
assert.equal(report.steps[2].status, "error");
assert.equal(report.steps[2].summary, "");
assert.throws(() => normalizeRepairReport({ status: "x" }));

assert.deepEqual(report.steps[0].needs_attention, []);
assert.equal(repairStepTone(report.steps[1]), "attention");
assert.equal(repairStepLabel({ ...report.steps[0], status: "changed" }), "Fixed");
assert.match(repairHeadline(report), /hol-guard repair/);

const listMarkup = renderToStaticMarkup(<GuardRepairStepList steps={report.steps} />);
assert.match(listMarkup, /Guard daemon/);
assert.match(listMarkup, /Failed/);
assert.equal(renderToStaticMarkup(<GuardRepairStepList steps={[]} />), "");

// A run where nothing failed but a step still needs the user is reported as
// "partial" too. Advising another run there sends the user round a loop: the
// next run reads the same broken app and says the same thing.
const attentionReport = normalizeRepairReport({
  schema: "guard.repair.v1",
  dry_run: false,
  status: "partial",
  summary: "x",
  steps: [
    { step: "daemon", title: "Guard daemon", status: "ok", summary: "Healthy." },
    {
      step: "hooks",
      title: "Harness hooks",
      status: "changed",
      summary: "Reinstalled hooks for: claude-code. Still needs attention: codex.",
      needs_attention: ["codex", 7],
    },
  ],
});
assert.deepEqual(attentionReport.steps[1].needs_attention, ["codex"]);
assert.doesNotMatch(repairHeadline(attentionReport), /Run Repair Guard again/);
assert.match(repairHeadline(attentionReport), /reaches the same answer/);
assert.match(repairHeadline(attentionReport), /Harness hooks/);
assert.equal(repairStepTone(attentionReport.steps[1]), "attention");
assert.equal(repairStepLabel(attentionReport.steps[1]), "Needs you");
const attentionMarkup = renderToStaticMarkup(<GuardRepairStepList steps={attentionReport.steps} />);
assert.match(attentionMarkup, /Needs you/);
assert.doesNotMatch(attentionMarkup, /Fixed/);

// A step that stopped at its own cleanup budget left work behind, so another
// run does advance even though the hooks step is still waiting on the user.
const mixedReport = normalizeRepairReport({
  schema: "guard.repair.v1",
  dry_run: false,
  status: "partial",
  summary: "x",
  steps: [
    {
      step: "onefile_leaks",
      title: "Leaked extraction folders",
      status: "changed",
      summary: "Reclaimed 25 leaked folder(s), about 40 MB. Run repair again to continue.",
      budget_exhausted: true,
    },
    {
      step: "hooks",
      title: "Harness hooks",
      status: "changed",
      summary: "Reinstalled hooks for: claude-code. Still needs attention: codex.",
      needs_attention: ["codex"],
    },
  ],
});
assert.equal(mixedReport.steps[0].budget_exhausted, true);
assert.equal(mixedReport.steps[1].budget_exhausted, false);
assert.match(repairHeadline(mixedReport), /Run Repair Guard again to continue the cleanup/);
assert.doesNotMatch(repairHeadline(mixedReport), /reaches the same answer/);
assert.match(repairHeadline(mixedReport), /Harness hooks/);

const idleRepair = renderToStaticMarkup(<GuardRepairControl description="Hooks timing out?" />);
assert.match(idleRepair, /Repair Guard/);
assert.doesNotMatch(idleRepair, /role="dialog"/);

const removal = normalizeHookRemovalReport({
  dry_run: false,
  status: "removed",
  harnesses: [{ harness: "codex", hook_count: 2 }, { harness: "cursor" }, 7],
  removed_hook_count: 2,
  backup_dir: "/tmp/b",
  post_state: { clean: true, remaining_harnesses: [] },
});
assert.equal(removal.harnesses.length, 2);
assert.equal(describeAffectedHarness(removal.harnesses[0]), "codex (2 hooks)");
assert.equal(describeAffectedHarness(removal.harnesses[1]), "cursor");
assert.equal(removal.reinstall_command, "hol-guard install --all");
assert.match(removalOutcomeMessage(removal), /removed/);
assert.match(removalOutcomeMessage({ ...removal, status: "partial" }), /could not be removed/);
assert.equal(remainingHooksMessage(removal), "Check: no Guard hooks remain in any app.");
assert.equal(
  remainingHooksMessage({
    ...removal,
    post_state: { clean: false, remaining_harnesses: [{ harness: "codex" }, { harness: "cursor" }] },
  }),
  "Still has Guard hooks: codex, cursor.",
);
assert.throws(() => normalizeHookRemovalReport(null));

const idleRemoval = renderToStaticMarkup(<GuardHookRemovalPanel />);
assert.match(idleRemoval, /Remove Guard from all apps/);
assert.match(idleRemoval, /Review and remove/);
assert.doesNotMatch(idleRemoval, /role="dialog"/);

console.log("guard repair dashboard tests passed");
