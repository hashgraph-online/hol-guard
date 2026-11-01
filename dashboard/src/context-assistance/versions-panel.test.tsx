import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { parseContextAssistanceStatus } from "./status";
import { canCommitCigarJob, cigarBuildBlock, cigarPythonBlock } from "./versions-actions";
import { parseCigarCatalog } from "./versions-catalog";
import type { CigarVersionsData } from "./versions-data";
import { parseCigarInterpreters } from "./versions-interpreters";
import { parseCigarVersionJob, type CigarSelectionJob } from "./versions-jobs";
import { parseCigarUpdateSettings } from "./versions-preferences";
import { CigarVersionBuildsPanel } from "./versions-builds-panel";
import { CigarVersionJobsPanel } from "./versions-jobs-panel";
import { CigarVersionsPanel } from "./versions-panel";
import { CigarUpdatePreferencesPanel } from "./versions-preferences-panel";
const fixture = JSON.parse(readFileSync(new URL("./fixtures/intent-state.json", import.meta.url), "utf8"));
const state = { ...parseContextAssistanceStatus(fixture.native_test.ready_observation), generation: "9007199254740993" };
const document = JSON.parse(readFileSync(new URL("../../../integrations/cigar/release-catalog.v1.json", import.meta.url), "utf8"));
const catalog = parseCigarCatalog({ schema: "guard-cigar-releases.v1", host_platform: "darwin-arm64", builds: document.builds, interpreter_builds: document.interpreters,
  catalog: { source: "bundled", fresh_for_preparation: true, diagnostic: null, trust_configured: false, trust_diagnostic: null, remote_feed_configured: false, feed_diagnostic: null, activation_granted: false } });
const requested = { mode: "manual" as const, allow_preview: false, retain_last_good: true };
const updates = parseCigarUpdateSettings({ schema: "guard-cigar-update-preferences.v1", requested, effective: requested,
  revision: "sha256:" + "a".repeat(64), diagnostic: null, locked_settings: [], capabilities: { modes: ["manual", "notify"], automatic_preparation: false, automatic_selection: false, retention_reduction: false } });
const interpreter = { interpreter_id: "python:one", python_version: [3, 14, 7], platform: "darwin-arm64", implementation: "cpython", abi: "cp314", managed: false, build_id: null };
assert.equal(parseCigarInterpreters({ interpreters: [interpreter] })[0].managed, false);
for (const interpreters of [[interpreter, interpreter], [{ ...interpreter, managed: true }], [{ ...interpreter, interpreter_id: "/caller/python" }], [{ ...interpreter, python_version: [3, 14] }]]) {
  assert.throws(() => parseCigarInterpreters({ interpreters }), /incompatible Python registration/);
}
const job = parseCigarVersionJob({ schema: "guard-cigar-switch-job.v1", job_id: "dashboard:ready", operation: "switch", phase: "ready", code: "ready",
  created_at_ms: 1000, updated_at_ms: 2000, deadline_at_ms: 121000, worker_live: true, cancel_requested: false, recovery_available: false,
  target_runtime_id: "cigar:target", source_runtime_id: state.preferences.runtime_id, expected_generation: state.generation,
  can_commit: true, keeps_disabled: false, reconnect_required: true, initial_selection: false, cleanup_pending: false, authority_restored: false }) as CigarSelectionJob;
assert.equal(canCommitCigarJob(job, state), true);
assert.equal(canCommitCigarJob(job, { ...state, generation: "9007199254740992" }), false);
assert.equal(canCommitCigarJob(job, { ...state, preferences: { ...state.preferences, runtime_id: "other:source" } }), false);
assert.equal(canCommitCigarJob({ ...job, cleanup_pending: true }, state), false);
assert.equal(canCommitCigarJob({ ...job, initial_selection: true }, state), false);
const noAction = () => { throw new Error("Rendering metadata must not submit an action"); };
const jobs = (value: CigarSelectionJob, status = state) => renderToStaticMarkup(<CigarVersionJobsPanel jobs={[value]} status={status} disabled={false} selectionDisabled={false} onAction={noAction} />);
assert.match(jobs(job), /disabled="">Switch now/);
assert.match(jobs(job), /I am ready to reconnect context sources and apps/);
assert.match(jobs(job), /Your Guard approvals remain in place/);
const recovery = { ...job, operation: "recover" as const, phase: "preparing_recovery", can_commit: false,
  keeps_disabled: true, reconnect_required: false,
  recovery_attempt: { id: "a".repeat(32), expected_generation: job.expected_generation, started_at_ms: 500000, deadline_at_ms: 620000 } };
assert.match(jobs(recovery), /Recovery keeps CIGAR off/);
assert.match(jobs(recovery), /Recovery deadline: <time dateTime="1970-01-01T00:10:20.000Z"/);
assert.match(jobs(recovery), /Original preparation deadline: <time dateTime="1970-01-01T00:02:01.000Z"/);
const initial = { ...job, operation: "select" as const, initial_selection: true, source_runtime_id: null, keeps_disabled: true, reconnect_required: false };
const off = { ...state, preferences: { ...state.preferences, enabled: false, runtime_id: "" } };
assert.match(jobs(initial, off), /Select &amp; keep CIGAR off/);
assert.doesNotMatch(jobs(initial, off), /type="checkbox"/);
assert.match(jobs(initial, off), />Select &amp; keep CIGAR off<\/button>/);
assert.match(jobs(job, { ...state, generation: "1" }), /live selection changed/);
const build = structuredClone(catalog.builds[0]);
const host = build.platforms.find((p) => p.platform === catalog.host_platform)!;
host.qualification = "guard_qualified"; host.has_wheel = true; host.qualification_receipt_sha256 = "f".repeat(64);
assert.equal(cigarBuildBlock(catalog, build, updates), null, "eligible bundled entries need no remote trust configuration");
assert.match(cigarBuildBlock(catalog, { ...build, withdrawn: true }, updates)!, /withdrawn/);
assert.match(cigarBuildBlock(catalog, { ...build, channel: "preview" }, updates)!, /unavailable/);
assert.match(cigarBuildBlock(catalog, build, { ...updates, effective: { ...requested, pinned_build: "other:build" } })!, /pin another/);
assert.match(cigarBuildBlock({ ...catalog, host_platform: null }, build, updates)!, /Guard host/);
assert.match(cigarBuildBlock({ ...catalog, catalog: { ...catalog.catalog, fresh_for_preparation: false } }, build, updates)!, /Refresh/);
const python = { ...catalog.interpreter_builds[0], qualification: "upstream_only" as const };
assert.match(cigarPythonBlock(catalog, python)!, /qualification/);
const data: CigarVersionsData = { catalog, updates, interpreters: [], jobs: [], installations: [], state };
const builds = renderToStaticMarkup(<CigarVersionBuildsPanel data={data} status={state} disabled={false} selectionDisabled={false} onAction={noAction} />);
assert.match(builds, /No Python interpreter registered for this host/);
assert.match(builds, /disabled="">Prepare this build/);
assert.match(builds, /Build identity/);
const preferences = renderToStaticMarkup(<CigarUpdatePreferencesPanel value={updates} builds={catalog.builds} disabled={false} onAction={noAction} />);
assert.match(preferences, /notifications and automatic preparation are not available/);
assert.match(preferences, /disabled="">Notify/);
assert.doesNotMatch(preferences, /Enable automatic/);
const panel = renderToStaticMarkup(<CigarVersionsPanel status={state} gate={null} disabled={false} locked={false} dirty={false} captureStatus={() => () => {}} />);
assert.match(panel, /Versions &amp; updates/);
assert.match(panel, /only reads registration and update metadata/);
assert.doesNotMatch(panel, /Switch now|Prepare this build/);
console.log("CIGAR Versions controls preserve native readiness, stale-generation rejection, reconnect consent, disabled selection and honest capability labels.");
