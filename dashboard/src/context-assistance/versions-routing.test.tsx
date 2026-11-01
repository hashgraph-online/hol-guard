import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { parseContextAssistanceStatus } from "./status";
import { CigarRuntimeSelection } from "./runtime-selection";
import { ContextSettingsControls } from "./settings-controls";
import { cigarTutorial } from "./tutorial-content";
import { parseTutorialProgress } from "./tutorial-progress";
import { CigarTutorials, CigarWalkthrough } from "./tutorials";
import { CigarGuide } from "./workspace-guide";
const fixture = JSON.parse(readFileSync(new URL("./fixtures/intent-state.json", import.meta.url), "utf8"));
const state = parseContextAssistanceStatus(fixture.native_test.ready_observation);
const target = { runtime_id: "cigar:other", qualification: "local_candidate" as const, python_version: [3, 14, 7] as [number, number, number],
  platform: "darwin-arm64", worker_fingerprint: "a".repeat(64) };
const effect = () => { throw new Error("Rendering runtime metadata or lessons must not invoke an effect"); };
const controls = renderToStaticMarkup(<ContextSettingsControls value={state.preferences} status={state} installations={[target]} loading={false}
  busy={false} disabled={false} locked={false} dirty={false} error={null} onChange={effect} onRefresh={effect}
  onChooseRuntime={effect} onManageVersions={effect} onControl={effect} />);
assert.match(controls, /Choose or switch runtime/);
assert.doesNotMatch(controls, /<option value="cigar:other"/,
  "an installed SDK cannot be drafted into the general settings form");
assert.doesNotMatch(controls, /label="Local runtime"/);
const pending = renderToStaticMarkup(<CigarRuntimeSelection value={{ ...state.preferences, runtime_id: target.runtime_id }} status={state}
  installations={[target]} disabled={false} onManage={effect} onRefresh={effect} onRestore={effect} />);
assert.match(pending, /pending runtime choice/);
assert.match(pending, /Use current selection/);
const locked = renderToStaticMarkup(<CigarRuntimeSelection value={state.preferences} status={state} installations={[]}
  disabled={true} onManage={effect} onRefresh={effect} onRestore={effect} />);
assert.match(locked, /disabled="">Choose or switch runtime/);
assert.match(locked, /No registered CIGAR runtime is available/);
const previous = { schema: 1 as const, tutorial: "first-brief" as const, step: 5 };
assert.deepEqual(parseTutorialProgress(previous), previous, "existing lesson IDs and step bounds remain valid");
const tutorial = cigarTutorial("cigar-updates");
assert.equal(tutorial.steps.length, 6);
for (let step = 0; step < tutorial.steps.length; step++) {
  const progress = { schema: 1, tutorial: "cigar-updates", step };
  assert.deepEqual(parseTutorialProgress(progress), progress);
  assert.ok(["versions", "access"].includes(tutorial.steps[step].target));
}
const hub = renderToStaticMarkup(<CigarTutorials progress={{ schema: 1, tutorial: "cigar-updates", step: 2 }} onBegin={effect} />);
assert.match(hub, /Update CIGAR with less interruption/);
assert.match(hub, /Resume walkthrough/);
const learning = renderToStaticMarkup(<CigarWalkthrough tutorial={tutorial} step={3} status={null} dirty={false}
  onMove={effect} onOpen={effect} onExit={effect} />);
assert.match(learning, /Switch now/);
assert.match(learning, /Select &amp; keep CIGAR off/);
assert.match(learning, /Status unavailable/);
assert.doesNotMatch(learning, /type="password"|role="switch"/);
const guide = renderToStaticMarkup(<CigarGuide onSelect={effect} />);
assert.match(guide, /Choose a runtime in Versions &amp; updates/);
assert.doesNotMatch(guide, /runtime selector/);
assert.ok(cigarTutorial("first-brief").steps[0].instructions[0].includes("Versions & updates"));
console.log("Runtime selection stays outside ordinary drafts; update walkthroughs preserve prior progress and never grant or infer native readiness.");
