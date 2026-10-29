import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { CIGAR_FULL_NAME, cigarTutorial } from "./tutorial-content";
import { parseTutorialProgress } from "./tutorial-progress";
import { CigarTutorials, CigarWalkthrough } from "./tutorials";
import { parseContextAssistanceStatus } from "./status";

const progress = { schema: 1 as const, tutorial: "first-brief" as const, step: 3 };
assert.deepEqual(parseTutorialProgress(progress), progress);
for (const invalid of [null, {}, { ...progress, schema: 2 }, { ...progress, tutorial: "removed-lesson" },
  { ...progress, step: -1 }, { ...progress, step: 100 }, { ...progress, step: 1.5 }]) {
  assert.deepEqual(parseTutorialProgress(invalid), { schema: 1, tutorial: "first-brief", step: 0 },
    "stale or malformed browser progress must not break the CIGAR workspace");
}
const hub = renderToStaticMarkup(<CigarTutorials progress={progress} onBegin={() => {}} />);
assert.match(hub, new RegExp(CIGAR_FULL_NAME));
assert.match(hub, /Resume walkthrough/);
assert.match(hub, /you choose every setting, start, and access grant/);
const receipt = JSON.parse(readFileSync(new URL("../../../docs/guard/cigar-integration/evidence/intent-state-verification.json", import.meta.url), "utf8"));
const ready = parseContextAssistanceStatus(receipt.native_test.ready_observation);
const tutorial = cigarTutorial("first-brief");
const render = (status: typeof ready | null, step = 3) => renderToStaticMarkup(<CigarWalkthrough tutorial={tutorial} step={step}
  status={status} dirty={false} onMove={() => {}} onOpen={() => {}} onExit={() => {}} />);
assert.match(render(null), /Status unavailable/);
assert.doesNotMatch(render(null), /Live runtime: <strong>Ready/);
assert.match(render(ready), /Live runtime: <strong>Ready/);
assert.match(render(ready), /reading ahead|Reading ahead/);
assert.match(render(ready), /Example question/);
assert.match(render(ready), /Copy question/);
assert.match(render(ready, tutorial.steps.length - 1), /Finish walkthrough/);
assert.doesNotMatch(render(ready), /role="switch"|type="password"/,
  "learning controls must not replace live feature or permission controls");
assert.match(renderToStaticMarkup(<CigarWalkthrough tutorial={cigarTutorial("execution")} step={0}
  status={null} dirty={false} onMove={() => {}} onOpen={() => {}} onExit={() => {}} />), /Full delivery from external apps has not yet been qualified/);
console.log("CIGAR tutorial identity, resumable progress, native-status separation and qualification guidance passed.");
