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

assert.equal(repairStepTone("error"), "attention");
assert.equal(repairStepLabel("changed"), "Fixed");
assert.match(repairHeadline(report), /hol-guard repair/);

const listMarkup = renderToStaticMarkup(<GuardRepairStepList steps={report.steps} />);
assert.match(listMarkup, /Guard daemon/);
assert.match(listMarkup, /Failed/);
assert.equal(renderToStaticMarkup(<GuardRepairStepList steps={[]} />), "");

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
assert.throws(() => normalizeHookRemovalReport(null));

const idleRemoval = renderToStaticMarkup(<GuardHookRemovalPanel />);
assert.match(idleRemoval, /Remove Guard from all apps/);
assert.match(idleRemoval, /Review and remove/);
assert.doesNotMatch(idleRemoval, /role="dialog"/);

console.log("guard repair dashboard tests passed");
