import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { parseContextAssistanceStatus } from "./status";
import { CigarWorkspace, type CigarWorkspaceProps } from "./workspace";
import { CigarGuide } from "./workspace-guide";
import { CIGAR_TABS, canStartCigar, cigarHelpsPrompts, cigarHomeCopy, cigarTabFromSearch } from "./workspace-model";
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
const homeCopy = (status: typeof off | null, loading = false, running = false) => cigarHomeCopy(status, loading, running);
assert.equal(homeCopy(off).headline, "CIGAR is off");
assert.equal(homeCopy(saved).headline, "CIGAR is not running", "a saved preference is not proof that CIGAR is on");
assert.equal(homeCopy({ ...saved, last_check: ready.runtime }).headline, "CIGAR is not running",
  "a cached compilation check must not complete activation");
const promise = /Every prompt you send in Claude Code or Codex gets the few project files that match it\./;
const noFiles = /Prompts get no project files until Context for AI apps and workspace documents are on in Settings\./;
const withFiles = (agentContext: boolean, documents: boolean) => parseContextAssistanceStatus({ ...ready, effective_preferences: { ...ready.effective_preferences,
  features: { ...ready.effective_preferences.features, agent_context: agentContext },
  sources: { ...ready.effective_preferences.sources, workspace_documents: documents, source_set_id: documents ? "selected-workspaces" : "" } } });
assert.equal(homeCopy(ready).headline, "CIGAR is on");
assert.match(homeCopy(ready).detail, noFiles, "the ready fixture has both switches off, so no promise of project files");
assert.doesNotMatch(homeCopy(ready).detail, promise);
assert.equal(homeCopy(ready).setupHint, true);
assert.match(homeCopy(withFiles(true, true)).detail, promise, "both switches on earn the promise");
assert.equal(homeCopy(withFiles(true, true)).setupHint, false);
for (const [agentContext, documents] of [[true, false], [false, true], [false, false]] as const) {
  const partial = homeCopy(withFiles(agentContext, documents));
  assert.equal(partial.headline, "CIGAR is on");
  assert.match(partial.detail, noFiles, "one switch alone must not promise project files");
  assert.doesNotMatch(partial.detail, promise);
  assert.equal(partial.setupHint, true);
}
assert.match(homeCopy(off).detail, /Turn it on and every prompt you send/, "a fresh install gets project files when it is turned on");
const choseNoDocuments = parseContextAssistanceStatus({ ...off, preferences: { ...off.preferences,
  sources: { ...off.preferences.sources, workspace_documents: false, source_set_id: "selected-workspaces" } } });
assert.doesNotMatch(homeCopy(choseNoDocuments).detail, promise, "an earlier choice survives, so turning on promises nothing");
assert.match(homeCopy(choseNoDocuments).detail, noFiles);
assert.equal(homeCopy(choseNoDocuments).setupHint, true);
assert.equal(homeCopy(parseContextAssistanceStatus(receipt.restriction_observation)).headline.startsWith("CIGAR is on"), false);
const restricted = parseContextAssistanceStatus(receipt.restriction_observation);
assert.ok(restricted.restriction && !restricted.effective_preferences.enabled, "fixture is an organization restriction");
assert.doesNotMatch(homeCopy(restricted).detail, promise, "a managed install cannot be turned on, so it promises nothing");
assert.match(homeCopy(restricted).detail, /Your organization manages CIGAR/);
assert.equal(homeCopy(restricted).setupHint, false);
assert.equal(homeCopy(null, true).headline, "Checking CIGAR");
assert.equal(homeCopy(null).headline, "CIGAR status unavailable");
assert.equal(homeCopy(off, false, true).headline, "Turning on CIGAR");
assert.equal(cigarHelpsPrompts(ready), false, "prompts get files only when both switches are on");
assert.equal(cigarHelpsPrompts(null), false);
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
assert.equal(cigarTabFromSearch("?section=tutorials"), "guide", "the old Tutorials link opens the merged Guides section");
assert.equal(new Set(CIGAR_TABS.map((tab) => tab.value)).size, CIGAR_TABS.length);
assert.deepEqual(CIGAR_TABS.map((tab) => tab.label), ["Settings", "Projects & AI apps", "Updates", "Privacy", "Guides"],
  "everything beyond the on/off switch lives in five Advanced sections");
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
assert.doesNotMatch(render(), /cigar-eyebrow|Context Intelligence Graph/, "the home screen explains CIGAR without jargon or a kicker");
assert.doesNotMatch(render(), /role="tablist"|role="tabpanel"/, "the default screen has no tabs");
assert.doesNotMatch(render(), /Runtime controls|Workspace access|Context data/, "Advanced sections stay closed by default");
assert.match(render(), /<button type="button" class="cigar-advanced-toggle" aria-expanded="false"/);
assert.match(render(), /<strong>Advanced<\/strong>/);
assert.match(render(), /CIGAR is off/);
assert.match(render(), /Turn it on and every prompt you send in Claude Code or Codex gets the few project files that match it\./);
assert.match(render(), /Skips secrets, keys, hidden files and anything your \.gitignore leaves out\./);
assert.match(render(), /Adds nothing when nothing matches\./);
assert.doesNotMatch(render(), /only the folders you pick|reads only/i, "copy must match how prompts are matched to the project");
assert.match(render(), /href="https:\/\/github\.com\/hashgraph-online\/hol-cigar\/issues"[^>]*>share feedback</);
assert.doesNotMatch(render(), /class="cigar-beta-note"/, "the beta notice is one quiet footer line");
assert.match(render({ error: "Service unavailable" }), /role="alert"/);
assert.match(render(), />Turn on CIGAR</);
assert.match(render(), /About a minute/);
assert.match(render(), /aria-label="Refresh status"/);
assert.doesNotMatch(render(), /Python|fingerprint|interpreter/i, "setup copy stays free of technical detail");
assert.doesNotMatch(render(), /token|faster|smarter/i, "CIGAR copy must not promise savings or speed");
assert.doesNotMatch(render(), />Turn off CIGAR</);
const on = render({ status: ready });
assert.match(on, />Turn off CIGAR</, "the one button flips to turn off");
assert.doesNotMatch(on, />Turn on CIGAR</);
assert.doesNotMatch(on, />Pick a project folder</, "picking a folder is optional and lives in Advanced");
assert.match(on, /<h2[^>]*>CIGAR is on<\/h2>/);
assert.match(on, noFiles, "with project context off, the card says why prompts get no files");
assert.doesNotMatch(on, promise, "with project context off, the card does not promise project files");
assert.match(on, />Open Settings</, "a button opens Advanced and Settings so the switches are one click away");
const sharingHome = render({ status: withFiles(true, true) });
assert.match(sharingHome, /<h2[^>]*>CIGAR is on<\/h2>/);
assert.match(sharingHome, promise);
assert.doesNotMatch(sharingHome, noFiles);
assert.doesNotMatch(sharingHome, />Open Settings</);
assert.doesNotMatch(render({ status: withFiles(true, false) }), promise, "one switch alone must not promise project files");
assert.doesNotMatch(render({ status: withFiles(false, true) }), promise, "one switch alone must not promise project files");
assert.match(render({ status: saved, setup: idle({ ...install, build_id: null, python_build_id: null, runtime_id: "r", stages: ["start"], approval: false }) }), />Not started</);
const resting = render({ status: { ...saved, diagnostic: "runtime_resting" }, setup: idle(install) });
assert.match(resting, />Resting</);
assert.match(resting, /CIGAR is on and waking up/, "a resting opt-in never asks to be turned on again");
assert.doesNotMatch(resting, /<button[^>]*>Turn on CIGAR/);
assert.match(resting, /You do not need to turn it on again/);
const blocked = render({ setup: idle({ kind: "blocked", block: { title: "Waiting for Guard's safety check", detail: "Not approved yet." } }) });
assert.match(blocked, /Waiting for Guard&#x27;s safety check/);
assert.match(blocked, /<button type="button" class="cigar-button cigar-button-primary cigar-button-solid" disabled="">Turn on CIGAR/,
  "a blocked plan explains itself and never starts work");
const running = render({ setup: idle(install, { phase: "running", stages: install.kind === "run" ? install.stages : [], stage: "download" }) });
assert.match(running, />Stop setup</);
assert.match(running, /data-state="done"/);
assert.match(running, /data-state="active"/);
assert.match(running, />Working</);
assert.match(running, /Downloading CIGAR… step 2 of/);
const runningWithOff = render({ stopAvailable: true, setup: idle(install, { phase: "running", stages: install.kind === "run" ? install.stages : [], stage: "download" }) });
assert.match(runningWithOff, />Stop setup</);
assert.match(runningWithOff, />Turn off CIGAR</, "the global off switch stays available while setup runs");
assert.doesNotMatch(running, />Turn off CIGAR</, "no saved or running CIGAR means no off switch to show");
const failed = render({ setup: idle(install, { phase: "failed", stages: ["python", "download", "check", "start"], stage: "check", message: "Fingerprint mismatch." }) });
assert.match(failed, />Try again</);
assert.match(failed, /Fingerprint mismatch\./);
assert.match(render({ status: null, error: "Service unavailable", stopAvailable: true }), />Turn off CIGAR</,
  "loss of status must not remove the saved preference's off switch");
assert.match(render({ status: null, error: "Service unavailable" }), /role="alert"/);

const advancedOpen = (section: string) => {
  const url = "?section=" + section;
  const original = (globalThis as { window?: unknown }).window;
  (globalThis as { window?: unknown }).window = { location: { search: url } };
  try { return render({ status: ready }); } finally { (globalThis as { window?: unknown }).window = original; }
};
const settingsOpen = advancedOpen("runtime");
assert.match(settingsOpen, /aria-expanded="true"/);
assert.match(settingsOpen, /role="tablist" aria-label="CIGAR sections"/);
assert.match(settingsOpen, /role="tabpanel" aria-labelledby=/);
for (const label of ["Settings", "Projects &amp; AI apps", "Updates", "Privacy", "Guides"]) assert.match(settingsOpen, new RegExp(">" + label + "<"));
assert.match(settingsOpen, /Runtime controls/);
assert.match(advancedOpen("access"), /Workspace access/);
assert.match(advancedOpen("data"), /Context data/);
assert.match(advancedOpen("data"), /By default, CIGAR keeps its notes in memory only/, "privacy intro must not promise memory-only storage unconditionally");
const guide = renderToStaticMarkup(<CigarGuide onSelect={() => {}} />);
assert.match(guide, /How CIGAR works/);
assert.match(guide, /build a to-do app/);
assert.match(guide, /Do I need to install anything\?/);
assert.match(guide, /Guard never installs a version it has not checked/);
assert.match(guide, /CIGAR does not promise either/);
assert.match(guide, /Restoring evidence never restores app access or approvals/);
assert.doesNotMatch(guide, /compile|scoped|grant a workspace/i, "the guide avoids implementation jargon");
console.log("CIGAR one-click states, live readiness, plain-language copy, guide and tab contracts passed.");
