import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { parseContextAssistanceStatus } from "./status";
import { canCommitCigarJob } from "./versions-actions";
import { parseCigarVersionJob, type CigarSelectionJob } from "./versions-jobs";
import { CigarVersionJobsPanel } from "./versions-jobs-panel";
import { CigarVersionsPanel } from "./versions-panel";
import { platformLabel } from "./versions-view";
const fixture = JSON.parse(readFileSync(new URL("./fixtures/intent-state.json", import.meta.url), "utf8"));
const state = { ...parseContextAssistanceStatus(fixture.native_test.ready_observation), generation: "9007199254740993" };
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
assert.match(jobs(job), />Ready to switch</, "a switch waiting for the person does not look busy");
assert.match(jobs({ ...job, phase: "preparing", can_commit: false }), />Working</);
const waiting = { ...job, worker_live: true };
assert.doesNotMatch(jobs(waiting), /animate-spin/, "a switch waiting for the person has no busy spinner");
assert.match(jobs(waiting), />Stop<\/button>/, "a prepared switch can still be stopped");
assert.match(jobs({ ...waiting, phase: "preparing", can_commit: false }), /animate-spin/);
const stopped = { ...job, phase: "extracting", worker_live: false, recovery_available: true, can_commit: false };
assert.match(jobs(stopped), />Stopped partway</);
assert.match(jobs(stopped), />Clean up<\/button>/);
assert.match(jobs(stopped), /stopped partway\. Choose Clean up/);
assert.doesNotMatch(jobs(stopped), /extracting|Recover job|recovery required/);
assert.match(jobs({ ...stopped, phase: "recovery_required" }), />Needs cleanup</);
assert.match(jobs({ ...job, phase: "failed", worker_live: false }), />Did not finish</);
assert.match(jobs(recovery), /Recovery deadline: <time dateTime="1970-01-01T00:10:20.000Z"/);
assert.match(jobs(recovery), /Original preparation deadline: <time dateTime="1970-01-01T00:02:01.000Z"/);
const initial = { ...job, operation: "select" as const, initial_selection: true, source_runtime_id: null, keeps_disabled: true, reconnect_required: false };
const off = { ...state, preferences: { ...state.preferences, enabled: false, runtime_id: "" } };
assert.match(jobs(initial, off), /Select &amp; keep CIGAR off/);
assert.doesNotMatch(jobs(initial, off), /type="checkbox"/);
assert.match(jobs(initial, off), />Select &amp; keep CIGAR off<\/button>/);
assert.match(jobs(job, { ...state, generation: "1" }), /live selection changed/);
const panel = renderToStaticMarkup(<CigarVersionsPanel status={state} gate={null} disabled={false} locked={false} dirty={false} captureStatus={() => () => {}} />);
assert.match(panel, /<h2>Updates<\/h2>/);
assert.match(panel, /built into Guard and updates when Guard does/);
assert.doesNotMatch(panel, /Switch now|Get this version|Check for new versions|Python/);
console.log("CIGAR Versions controls preserve native readiness, stale-generation rejection, reconnect consent, disabled selection and honest capability labels.");

assert.equal(platformLabel("linux-x64-gnu"), "Linux · Intel");
assert.equal(platformLabel("linux-arm64-musl"), "Linux · Arm");
assert.equal(platformLabel("darwin-arm64"), "macOS · Apple silicon");
