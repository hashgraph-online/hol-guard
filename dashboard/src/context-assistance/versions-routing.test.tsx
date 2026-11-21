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
  onChooseRuntime={effect} onControl={effect} />);
assert.doesNotMatch(controls, /Change version/, "only the built-in engine exists, so there is no version to change");
assert.doesNotMatch(controls, /<option value="cigar:other"/,
  "an installed SDK cannot be drafted into the general settings form");
assert.doesNotMatch(controls, /label="Local runtime"/);
const pending = renderToStaticMarkup(<CigarRuntimeSelection value={{ ...state.preferences, runtime_id: target.runtime_id }} status={state}
  installations={[target]} disabled={false} onRefresh={effect} onRestore={effect} />);
assert.match(pending, /different version picked/);
assert.match(pending, /Keep current version/);
const locked = renderToStaticMarkup(<CigarRuntimeSelection value={state.preferences} status={state} installations={[]}
  disabled={true} onRefresh={effect} onRestore={effect} />);
assert.match(locked, /CIGAR is not set up on this computer yet/);
const previous = { schema: 1 as const, tutorial: "first-brief" as const, step: 5 };
assert.deepEqual(parseTutorialProgress(previous), previous, "existing lesson IDs and step bounds remain valid");
assert.deepEqual(parseTutorialProgress({ schema: 1, tutorial: "cigar-updates", step: 2 }), { schema: 1, tutorial: "first-brief", step: 0 },
  "progress saved for the retired version-switch lesson starts over");
const hub = renderToStaticMarkup(<CigarTutorials progress={{ schema: 1, tutorial: "first-brief", step: 2 }} onBegin={effect} />);
assert.doesNotMatch(hub, /Update CIGAR with less interruption/);
const tutorial = cigarTutorial("first-brief");
const learning = renderToStaticMarkup(<CigarWalkthrough tutorial={tutorial} step={0} status={null} dirty={false}
  onMove={effect} onOpen={effect} onExit={effect} />);
assert.match(learning, /Status unavailable/);
assert.doesNotMatch(learning, /type="password"|role="switch"/);
const guide = renderToStaticMarkup(<CigarGuide onSelect={effect} />);
assert.doesNotMatch(guide, /Choose a version in Updates/);
assert.doesNotMatch(guide, /runtime selector/);
assert.ok(!cigarTutorial("first-brief").steps.some((step) => step.instructions.some((line) => line.includes("Updates"))));
console.log("Runtime selection stays outside ordinary drafts; retired lesson progress resets and walkthroughs never grant or infer native readiness.");
