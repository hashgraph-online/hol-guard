import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { parseContextAssistanceStatus } from "./status";
import { CigarWorkspace, type CigarWorkspaceProps } from "./workspace";
import { CigarGuide } from "./workspace-guide";
import { CigarOverview } from "./workspace-overview";
import { CIGAR_TABS, canStartCigar, cigarRuntimeSummary, cigarSetupSteps, cigarTabFromSearch } from "./workspace-model";
import type { ContextInstallation } from "./types";

const receipt = JSON.parse(readFileSync(new URL("./fixtures/intent-state.json", import.meta.url), "utf8"));
const ready = parseContextAssistanceStatus(receipt.native_test.ready_observation);
const registered: ContextInstallation[] = [{
  runtime_id: ready.preferences.runtime_id,
  qualification: "local_candidate",
  python_version: [3, 14, 7],
  platform: "darwin-arm64",
  worker_fingerprint: ready.runtime!.worker_fingerprint,
}];
const off = parseContextAssistanceStatus({ ...ready, availability: "off", diagnostic: null,
  requested_enabled: false, effective_enabled: false, runtime: null, last_check: null,
  preferences: { ...ready.preferences, enabled: false, runtime_id: "" },
  effective_preferences: { ...ready.effective_preferences, enabled: false, runtime_id: "" },
  job: null, qualification: null });

assert.deepEqual(cigarSetupSteps(off, []).map((step) => step.complete), [false, false, false]);
assert.deepEqual(cigarSetupSteps(off, registered).map((step) => step.complete), [true, false, false],
  "registration must never imply saved consent or an active runtime");
const saved = { ...off, availability: "unavailable" as const, requested_enabled: true,
  preferences: { ...ready.preferences, enabled: true },
  effective_preferences: { ...ready.effective_preferences, enabled: true }, diagnostic: "runtime_not_verified" };
assert.deepEqual(cigarSetupSteps(saved, registered).map((step) => step.complete), [true, true, false]);
assert.deepEqual(cigarSetupSteps({ ...saved, last_check: ready.runtime }, registered).map((step) => step.complete), [true, true, false],
  "a cached compilation check must not complete activation");
assert.deepEqual(cigarSetupSteps(ready, registered).map((step) => step.complete), [true, true, true]);
assert.equal(cigarSetupSteps({ ...saved, preferences: { ...saved.preferences, runtime_id: "missing" } }, registered)[1].complete, false,
  "an unavailable saved selection cannot complete setup");
assert.equal(cigarSetupSteps(parseContextAssistanceStatus(receipt.restriction_observation), registered)[2].complete, false);
assert.equal(canStartCigar(saved, false), true);
assert.equal(canStartCigar(saved, true), false, "unsaved choices cannot start a stale selection");
assert.equal(canStartCigar(off, false), false, "an off preference must never activate CIGAR");
assert.equal(canStartCigar(null, false), false);
assert.equal(canStartCigar(ready, false), false, "an active runtime is not started twice");
assert.equal(canStartCigar({ ...saved, verification_permitted: false }, false), false);
assert.equal(canStartCigar({ ...saved, effective_preferences: { ...saved.effective_preferences, enabled: false } }, false), false);
assert.equal(canStartCigar({ ...saved, preferences: { ...saved.preferences, runtime_id: "" } }, false), false);
assert.equal(canStartCigar({ ...saved, job: { id: "19", operation: "activate", phase: "verifying" } }, false), false);

assert.equal(cigarTabFromSearch("?section=access&guardDaemon=http%3A%2F%2F127.0.0.1%3A5041"), "access");
assert.equal(cigarTabFromSearch("?section=unknown"), "overview");
assert.equal(cigarTabFromSearch(""), "overview");
assert.equal(new Set(CIGAR_TABS.map((tab) => tab.value)).size, CIGAR_TABS.length);
assert.equal(cigarRuntimeSummary(off, []).label, "Runtime setup needed");
assert.equal(cigarRuntimeSummary(off, registered).label, "Python 3.14.7");
assert.match(cigarRuntimeSummary(off, registered).detail, /Registered/);
assert.doesNotMatch(cigarRuntimeSummary(off, registered).detail, /running/);
assert.match(cigarRuntimeSummary(ready, registered).detail, /running locally/);
assert.match(cigarRuntimeSummary({ ...ready, runtime: { ...ready.runtime!, package_version: "0.99.2" } }, registered).detail, /0\.99\.2/,
  "the UI must display the native runtime's package version without pinning a release label");

const base: CigarWorkspaceProps = {
  status: off, installations: registered, loading: false, busy: false, disabled: false,
  dirty: false, error: null, controls: <p>Runtime controls</p>, access: <p>Workspace access</p>,
  data: <p>Context data</p>, onRefresh: () => {}, onStart: () => {}, onStop: () => {},
};
const render = (props: Partial<CigarWorkspaceProps> = {}) => renderToStaticMarkup(<CigarWorkspace {...base} {...props} />);
assert.match(render(), /<h1>.*CIGAR<\/h1>/);
assert.match(render(), /Python 3\.14\.7/);
assert.match(render(), /role="tablist" aria-label="CIGAR sections"/);
assert.match(render(), /role="tabpanel" aria-labelledby=/);
assert.match(render(), /1 of 3 complete/);
assert.match(render(), /Get started/);
assert.doesNotMatch(render(), />Turn off CIGAR</);
assert.match(render({ status: ready }), />Turn off CIGAR</);
assert.match(render({ status: ready }), /3 of 3 complete/);
assert.match(render({ status: ready }), />Use CIGAR</);
assert.match(render({ status: saved }), />Start CIGAR</);
assert.match(render({ status: saved }), />Not started</);
assert.match(render({ status: saved, dirty: true }), />Save preferences first</);
assert.match(render({ status: null, error: "Service unavailable", stopAvailable: true }), />Turn off CIGAR</,
  "loss of status must not remove the saved preference's off switch");
assert.match(render({ status: null, error: "Service unavailable" }), /role="alert"/);
assert.doesNotMatch(render({ status: null, loading: true }), /0 of 3 complete/);

const overview = renderToStaticMarkup(<CigarOverview status={off} installations={[]} loading={false} onSelect={() => {}} />);
assert.match(overview, /Register an approved CIGAR bundle/);
assert.match(overview, /Guard keeps authority over approvals and execution/);
const guide = renderToStaticMarkup(<CigarGuide onSelect={() => {}} />);
assert.match(guide, /An empty list means no bundle is registered/);
assert.match(guide, /Python 3\.14\.7 qualifies/);
assert.match(guide, /it does not scan your machine or install packages/);
assert.match(guide, /Saving records your preferences/);
assert.match(guide, /Restoring evidence never restores app access or approvals/);
console.log("CIGAR setup state, runtime registration, live readiness, guide, version display and tab contracts passed.");
