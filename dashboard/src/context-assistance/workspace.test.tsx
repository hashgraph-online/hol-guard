import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { parseContextAssistanceStatus } from "./status";
import { CigarWorkspace, type CigarWorkspaceProps } from "./workspace";
import { CigarGuide } from "./workspace-guide";
import { CigarOverview } from "./workspace-overview";
import { CIGAR_TABS, canStartCigar, cigarSetupSteps, cigarTabFromSearch } from "./workspace-model";
import type { CigarSetupPlan } from "./one-click";
import type { CigarOneClick } from "./one-click-setup";
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

const saved = { ...off, availability: "unavailable" as const, requested_enabled: true,
  preferences: { ...ready.preferences, enabled: true },
  effective_preferences: { ...ready.effective_preferences, enabled: true }, diagnostic: "runtime_not_verified" };
assert.deepEqual(cigarSetupSteps(off).map((step) => step.complete), [false, false, false]);
assert.deepEqual(cigarSetupSteps(saved).map((step) => step.complete), [false, false, false],
  "a saved preference is not proof that CIGAR is on");
assert.deepEqual(cigarSetupSteps({ ...saved, last_check: ready.runtime }).map((step) => step.complete), [false, false, false],
  "a cached compilation check must not complete activation");
assert.deepEqual(cigarSetupSteps(ready).map((step) => step.complete), [true, false, false]);
assert.deepEqual(cigarSetupSteps(off).map((step) => step.action), [null, null, null],
  "folder and app steps stay closed until CIGAR is on");
assert.equal(cigarSetupSteps(parseContextAssistanceStatus(receipt.restriction_observation))[0].complete, false);
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
const idle = (plan: CigarOneClick["plan"], run: CigarOneClick["run"] = { phase: "idle" }): CigarOneClick => ({
  plan, loadError: null, run, busy: run.phase === "running", start: () => {}, confirm: () => {}, cancelProof: () => {},
  dismiss: () => {}, stop: () => {}, refresh: async () => {},
});
const install: CigarSetupPlan = { kind: "run", runtime_id: null, build_id: "b", interpreter_id: null, python_build_id: "p",
  stages: ["python", "download", "check", "start"], approval: true };
const base: CigarWorkspaceProps = {
  status: off, installations: registered, loading: false, busy: false, disabled: false,
  dirty: false, error: null, setup: idle(install), controls: <p>Runtime controls</p>, access: <p>Workspace access</p>,
  data: <p>Context data</p>, onRefresh: () => {}, onStop: () => {},
};
const render = (props: Partial<CigarWorkspaceProps> = {}) => renderToStaticMarkup(<CigarWorkspace {...base} {...props} />);
assert.match(render(), /<h1>.*CIGAR<\/h1>/);
assert.doesNotMatch(render(), /cigar-eyebrow|Context Intelligence Graph/, "the header explains CIGAR without jargon or a kicker");
assert.match(render(), /class="cigar-beta-note" aria-label="CIGAR beta status"/);
assert.match(render(), /cigar-beta-note__chip">Beta</);
assert.match(render(), /CIGAR is still being iterated on\. Screens and settings may change between releases\./);
assert.match(render(), /href="https:\/\/github\.com\/hashgraph-online\/hol-cigar\/issues"[^>]*>Share feedback</);
assert.doesNotMatch(render({ error: "Service unavailable" }), /class="cigar-beta-note"[^>]*role="alert"/,
  "the beta disclosure informs; only failures alert");
assert.match(render(), /role="tablist" aria-label="CIGAR sections"/);
assert.match(render(), /role="tabpanel" aria-labelledby=/);
assert.match(render(), />Turn on CIGAR</);
assert.match(render(), /Get Python ready/);
assert.match(render(), /About a minute/);
assert.doesNotMatch(render(), /token|faster|smarter/i, "CIGAR copy must not promise savings or speed");
assert.doesNotMatch(render(), />Turn off CIGAR</);
assert.match(render({ status: ready }), />Turn off CIGAR</);
assert.match(render({ status: ready }), />Pick a project folder</);
assert.match(render({ status: ready }), /CIGAR is on/);
assert.match(render({ status: saved, setup: idle({ ...install, build_id: null, python_build_id: null, runtime_id: "r", stages: ["start"], approval: false }) }), />Not started</);
const blocked = render({ setup: idle({ kind: "blocked", block: { title: "Waiting for Guard's safety check", detail: "Not approved yet." } }) });
assert.match(blocked, /Waiting for Guard&#x27;s safety check/);
assert.match(blocked, /<button type="button" class="cigar-button cigar-button-primary" disabled="">Turn on CIGAR/,
  "a blocked plan explains itself and never starts work");
const running = render({ setup: idle(install, { phase: "running", stages: install.kind === "run" ? install.stages : [], stage: "download" }) });
assert.match(running, />Stop setup</);
assert.match(running, /data-state="done"/);
assert.match(running, /data-state="active"/);
assert.match(running, />Working</);
const failed = render({ setup: idle(install, { phase: "failed", stages: ["python", "download", "check", "start"], stage: "check", message: "Fingerprint mismatch." }) });
assert.match(failed, />Try again</);
assert.match(failed, /Fingerprint mismatch\./);
assert.match(render({ status: null, error: "Service unavailable", stopAvailable: true }), />Turn off CIGAR</,
  "loss of status must not remove the saved preference's off switch");
assert.match(render({ status: null, error: "Service unavailable" }), /role="alert"/);

const overview = renderToStaticMarkup(<CigarOverview status={off} onSelect={() => {}} />);
assert.match(overview, /Know why Guard paused/);
assert.match(overview, /Guard still decides what your AI may do/);
const guide = renderToStaticMarkup(<CigarGuide onSelect={() => {}} />);
assert.match(guide, /Do I need to install anything\?/);
assert.match(guide, /Guard never installs a version it has not checked/);
assert.match(guide, /CIGAR does not promise either/);
assert.match(guide, /Restoring evidence never restores app access or approvals/);
console.log("CIGAR one-click states, live readiness, plain-language copy, guide and tab contracts passed.");
