import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import type { GuardContextAssistanceConfig } from "../guard-types";
import { ContextAssistanceApiError } from "./api";
import {
  CigarSetupError, CigarSetupStopped, cigarSetupHold, planCigarAdopt, planCigarHeldJob, planCigarSetup, planCigarStart, runCigarSetup,
  type CigarSetupDeps, type CigarSetupRun, type CigarSetupStage,
} from "./one-click";
import { parseContextAssistanceStatus } from "./status";
import type { ContextAssistanceStatus } from "./types";
import type { CigarVersionsReply, CigarVersionsRequest } from "./versions-api";
import type { CigarVersionsData } from "./versions-data";
import { parseCigarVersionJob } from "./versions-jobs";

const fixture = JSON.parse(readFileSync(new URL("./fixtures/intent-state.json", import.meta.url), "utf8"));
const ready = { ...parseContextAssistanceStatus(fixture.native_test.ready_observation), generation: "7" };
const off: ContextAssistanceStatus = { ...ready, availability: "off", diagnostic: null, requested_enabled: false,
  effective_enabled: false, runtime: null, last_check: null, job: null, qualification: null,
  preferences: { ...ready.preferences, enabled: false, runtime_id: "" },
  effective_preferences: { ...ready.effective_preferences, enabled: false, runtime_id: "" } };
const builtin = { runtime_id: "builtin", qualification: "guard_builtin" as const, python_version: null, platform: "darwin-arm64",
  worker_fingerprint: "a".repeat(64), sdk_version: "0.14.2", core_version: "0.14.2", build_id: null,
  adapter_id: "guard-cigar-builtin-v1", adapter_revision: 1, managed: false, builtin: true };
const data = (patch: Partial<CigarVersionsData> = {}): CigarVersionsData => ({ jobs: [], installations: [builtin], state: off, ...patch });
const open = { locked: false, dirty: false };

// Planning: the shortest truthful path, from native metadata only.
assert.deepEqual(planCigarSetup(data({ state: ready }), open), { kind: "ready" });
assert.equal(planCigarSetup(data(), { ...open, dirty: true }).kind, "blocked");
const managed = planCigarSetup(data(), { ...open, locked: true });
assert.ok(managed.kind === "blocked" && /organization/.test(managed.block.title));
const stoppedManaged = planCigarSetup(data({ state: { ...ready, effective_enabled: false, runtime: null } }), { ...open, locked: true });
assert.deepEqual(stoppedManaged.kind === "run" ? stoppedManaged.stages : stoppedManaged, ["start"],
  "a managed computer still starts the selection its administrator turned on, without changing preferences");
assert.equal((stoppedManaged as CigarSetupRun).approval, false);
const install = planCigarSetup(data(), open) as CigarSetupRun;
assert.equal(install.kind, "run");
assert.deepEqual([install.runtime_id, install.stages, install.approval], ["builtin", ["check", "start"], true],
  "a first setup selects the engine built into Guard, with no download or Python");
assert.ok(!("build_id" in install) && !("python_build_id" in install) && !("interpreter_id" in install));
const missing = planCigarSetup(data({ installations: [] }), open);
assert.ok(missing.kind === "blocked" && /Update Guard/.test(missing.block.title), "a Guard without the built-in engine asks for an update");
const retired = planCigarSetup(data({ state: { ...off, preferences: { ...off.preferences, runtime_id: "cigar:old" } } }), open);
assert.ok(retired.kind === "run" && retired.runtime_id === "builtin" && retired.stages.length === 2,
  "an old engine still saved in settings is replaced by the built-in one");
const selected = { ...off, preferences: { ...off.preferences, runtime_id: "builtin" } };
const selectedPlan = planCigarSetup(data({ state: selected }), open);
assert.deepEqual(selectedPlan.kind === "run" && [selectedPlan.stages, selectedPlan.approval], [["start"], true],
  "turning the saved preference on still needs approval");
const saved = { ...selected, requested_enabled: true, preferences: { ...selected.preferences, enabled: true },
  effective_preferences: { ...selected.effective_preferences, enabled: true, runtime_id: "builtin" } };
const startOnly = planCigarSetup(data({ state: saved }), open);
assert.deepEqual(startOnly.kind === "run" && [startOnly.stages, startOnly.approval], [["start"], false],
  "starting an already-approved preference asks for no password");
assert.equal(planCigarStart(saved, false)?.approval, false);
assert.equal(planCigarStart(saved, true), null);
assert.equal(planCigarStart(off, false), null);
const job = (patch: Record<string, unknown>) => parseCigarVersionJob({ schema: "guard-cigar-switch-job.v1", operation: "select",
  job_id: "dashboard:x", phase: "preparing", code: "preparing", created_at_ms: 1, updated_at_ms: 1, deadline_at_ms: 10, worker_live: true,
  cancel_requested: false, recovery_available: false, target_runtime_id: "builtin", source_runtime_id: null, expected_generation: "7",
  can_commit: false, keeps_disabled: true, reconnect_required: false, initial_selection: true, cleanup_pending: false,
  authority_restored: false, ...patch });
const busy = planCigarSetup(data({ jobs: [job({})] }), open);
assert.ok(busy.kind === "blocked" && busy.block.title === "CIGAR is busy");
const stopped = { ...ready, effective_enabled: false, runtime: null };
const busyManaged = planCigarSetup(data({ state: stopped, jobs: [job({})] }),
  { ...open, locked: true });
assert.ok(busyManaged.kind === "blocked" && busyManaged.block.title === "CIGAR is busy", "a managed start waits for a running task too");
const pausedManaged = planCigarSetup(data({ state: stopped, jobs: [job({ phase: "recovery_required", code: "recovery_required", worker_live: false })] }), { ...open, locked: true });
assert.ok(pausedManaged.kind === "blocked" && pausedManaged.block.title === "An earlier setup did not finish" && pausedManaged.block.tab === "versions",
  "a paused task blocks a managed start and says why");

// Coming back to a safety check this tab prepared commits it instead of waiting for it to expire.
const prepared = job({ job_id: "dashboard:mine", phase: "ready", code: "ready", can_commit: true });
const adopted = planCigarSetup(data({ jobs: [prepared] }), { ...open, adopt: "dashboard:mine" }) as CigarSetupRun;
assert.equal(adopted.kind, "run");
assert.deepEqual([adopted.runtime_id, adopted.stages, adopted.commit],
  ["builtin", ["check", "start"], { job_id: "dashboard:mine", expected_generation: "7", reconnect: false }]);
assert.equal(planCigarSetup(data({ jobs: [prepared] }), open).kind, "blocked",
  "someone else's prepared switch still blocks setup");
const stalePrepared = planCigarSetup(data({ jobs: [prepared], state: { ...off, generation: "8" } }),
  { ...open, adopt: "dashboard:mine" });
assert.equal(stalePrepared.kind, "blocked", "a check prepared for an older generation is not committed");
// Guard answers "busy" to the full version list while that check is open, so the job alone must be enough.
assert.deepEqual(planCigarAdopt(prepared, off)?.commit, { job_id: "dashboard:mine", expected_generation: "7", reconnect: false });
assert.equal(planCigarAdopt(prepared, ready), null, "nothing to finish once CIGAR is on");
assert.equal(planCigarAdopt(undefined, off), null);
// The fallback that adopts a prepared check without the version list keeps the same holds.
assert.ok(cigarSetupHold(off, { locked: false, dirty: true })?.kind === "blocked", "unsaved settings stop a commit");
assert.ok(cigarSetupHold(off, { locked: true, dirty: false })?.kind === "blocked", "an administrator lock stops a commit");
assert.equal(cigarSetupHold(off, { locked: false, dirty: false }), null);
assert.equal(cigarSetupHold(ready, { locked: true, dirty: true }), null, "nothing to hold once CIGAR is on");
const heldAdopt = planCigarSetup(data({ state: off, jobs: [prepared] }), { locked: false, dirty: true, adopt: "dashboard:mine" });
assert.ok(heldAdopt.kind === "blocked" && heldAdopt.block.title === "Save your changes first");
// A lock stops adopting a settled held job but leaves the managed start; unsaved settings stop both.
const settled = { ...prepared, worker_live: false };
assert.equal(planCigarHeldJob(settled, off, saved, { locked: true, dirty: false }), null, "a managed computer falls through to its saved start");
assert.ok(planCigarHeldJob(settled, off, off, { locked: true, dirty: false })?.kind === "blocked", "no saved selection keeps the lock");
assert.ok(planCigarHeldJob(prepared, off, saved, { locked: false, dirty: true })?.kind === "blocked", "unsaved settings stay a hard hold");
// A live worker or a paused task still owns the selection, so neither the commit nor the saved start may run.
const heldBusy = planCigarHeldJob(prepared, off, saved, { locked: true, dirty: false });
assert.ok(heldBusy?.kind === "blocked" && heldBusy.block.title === "CIGAR is busy");
const heldPaused = planCigarHeldJob({ ...settled, phase: "recovery_required" }, off, saved, { locked: false, dirty: false });
assert.ok(heldPaused?.kind === "blocked" && heldPaused.block.title === "An earlier setup did not finish");

// Running: a fake Guard that answers each step the way the daemon does.
type Script = { calls: string[]; stages: CigarSetupStage[]; jobs: (string | null)[]; saved: GuardContextAssistanceConfig[] };
function fakeGuard(options: { submitError?: Record<string, unknown>; failPhase?: string; failCode?: string; busyPolls?: number; slowPollMs?: number; neverReady?: boolean;
  stopAt?: string; initial?: ContextAssistanceStatus } = {}) {
  const script: Script = { calls: [], stages: [], jobs: [], saved: [] };
  let state: ContextAssistanceStatus = options.initial ?? off, clock = 0, stopped = false, busy = options.busyPolls ?? 0;
  const submitted = new Map<string, CigarVersionsRequest>();
  const reply = (result: Record<string, unknown> = {}): CigarVersionsReply => ({ state, result });
  const base = { created_at_ms: 1, updated_at_ms: 2, deadline_at_ms: 999999, worker_live: true, cancel_requested: false,
    recovery_available: false };
  const deps: CigarSetupDeps = {
    versions: async (input) => {
      script.calls.push(input.action);
      if (options.stopAt === input.action) stopped = true;
      if (input.action !== "job") {
        submitted.set((input as { job_id: string }).job_id, input);
        const error = options.submitError?.[input.action];
        if (error) throw error;
        return reply();
      }
      if (busy > 0) { busy -= 1; clock += options.slowPollMs ?? 0; throw new TypeError("Failed to fetch"); }
      const sent = submitted.get(input.job_id)!;
      if (sent.action === "prepare_switch" && options.failPhase) return reply({ ...base, schema: "guard-cigar-switch-job.v1", operation: "select",
        job_id: input.job_id, phase: options.failPhase, code: options.failCode ?? "failed", worker_live: false, target_runtime_id: "builtin",
        source_runtime_id: null, expected_generation: state.generation, can_commit: false, keeps_disabled: true, reconnect_required: false,
        initial_selection: true, cleanup_pending: false, authority_restored: false });
      if (sent.action === "prepare_switch") return reply({ ...base, schema: "guard-cigar-switch-job.v1", operation: "select", job_id: input.job_id,
        phase: "ready", code: "ready", target_runtime_id: "builtin", source_runtime_id: null, expected_generation: state.generation,
        can_commit: true, keeps_disabled: true, reconnect_required: false, initial_selection: true, cleanup_pending: false, authority_restored: false });
      if (sent.action === "commit") {
        state = { ...state, generation: "8", preferences: { ...state.preferences, runtime_id: "builtin" } };
        return reply({ ...base, schema: "guard-cigar-switch-job.v1", operation: "select", job_id: input.job_id, phase: "completed",
          code: "completed", worker_live: false, target_runtime_id: "builtin", source_runtime_id: null, expected_generation: "7",
          can_commit: false, keeps_disabled: true, reconnect_required: false, initial_selection: true, cleanup_pending: false, authority_restored: false });
      }
      throw new Error("unexpected job " + sent.action);
    },
    saveSettings: async (config) => {
      script.calls.push("settings"); script.saved.push(config);
      state = { ...state, requested_enabled: true, preferences: config, effective_preferences: { ...state.effective_preferences, ...config } };
      return config;
    },
    activate: async () => {
      script.calls.push("activate");
      state = { ...state, job: { id: "1", operation: "activate", phase: "verifying" } };
      return state;
    },
    status: async () => {
      script.calls.push("status");
      if (!options.neverReady) state = { ...ready, generation: state.generation, preferences: state.preferences };
      else state = { ...state, job: null, availability: "unavailable", diagnostic: "runtime_not_verified" };
      return state;
    },
    sleep: async () => { clock += 800; },
    now: () => clock,
    stopped: () => stopped,
    onStage: (stage) => { script.stages.push(stage); },
    onJob: (id) => { script.jobs.push(id); },
    onState: () => {},
    onSaved: () => {},
  };
  return { deps, script, stop: () => { stopped = true; } };
}
const plan = install;

{
  const { deps, script } = fakeGuard();
  const commitOnly: CigarSetupRun = { kind: "run", runtime_id: "builtin",
    stages: ["check", "start"], approval: true, commit: { job_id: "dashboard:mine", expected_generation: "7", reconnect: false } };
  const result = await runCigarSetup(commitOnly, off, deps);
  assert.equal(result.effective_enabled, true);
  assert.deepEqual(script.calls.filter((call) => call !== "job" && call !== "status"), ["commit", "settings", "activate"],
    "an adopted safety check is committed, not prepared again");
}

{
  const { deps, script } = fakeGuard();
  const result = await runCigarSetup(plan, off, deps);
  assert.equal(result.effective_enabled, true, "setup ends only on Guard's live Ready state");
  assert.deepEqual(script.stages, ["check", "start"]);
  assert.deepEqual(script.calls.filter((call) => call !== "job" && call !== "status"),
    ["prepare_switch", "commit", "settings", "activate"], "turning on never downloads anything or sets up Python");
  assert.deepEqual(script.saved.map((config) => [config.enabled, config.runtime_id]), [[true, "builtin"]]);
  assert.equal(script.jobs.at(-1), null, "no job is left for Stop to cancel after the last step");
}
{
  const { deps, script } = fakeGuard({ stopAt: "prepare_switch" });
  await assert.rejects(runCigarSetup(plan, off, deps), CigarSetupStopped);
  assert.ok(!script.calls.includes("commit") && !script.calls.includes("settings"), "Stop wins before the next step");
  assert.equal(script.jobs.at(-1)?.startsWith("dashboard:"), true, "Stop knows which job to cancel");
}
{
  const { deps, script } = fakeGuard({ submitError: { prepare_switch: new ContextAssistanceApiError("approval_gate_proof_required", "Approve") } });
  await assert.rejects(runCigarSetup(plan, off, deps), (cause: unknown) => cause instanceof CigarSetupError && cause.needsProof && cause.stage === "check");
  assert.deepEqual(script.calls, ["prepare_switch"], "a refused approval starts nothing");
}
{
  const { deps, script } = fakeGuard({ submitError: { prepare_switch: new ContextAssistanceApiError("versions_outcome_unknown", "Lost") } });
  await runCigarSetup(plan, off, deps);
  assert.equal(script.calls.filter((call) => call === "prepare_switch").length, 1, "an unknown outcome is observed, never resent");
}
{
  // Raw codes such as native_context_assistance_switch_inputs_invalid never reach the page.
  for (const failCode of ["native_context_assistance_switch_inputs_invalid", "native_context_assistance_something_new"]) {
    const { deps } = fakeGuard({ failPhase: "failed", failCode });
    await assert.rejects(runCigarSetup(plan, off, deps), (cause: unknown) => cause instanceof CigarSetupError
      && /Nothing was turned on/.test(cause.message) && !/native|context assistance|_/.test(cause.message));
  }
}
{
  const { deps } = fakeGuard({ failPhase: "failed", failCode: "native_context_assistance_runtime_deadline_exceeded" });
  await assert.rejects(runCigarSetup(plan, off, deps), (cause: unknown) => cause instanceof CigarSetupError
    && /took too long/.test(cause.message) && !/native context assistance/.test(cause.message));
}
{
  const { deps } = fakeGuard({ busyPolls: 15 });
  const result = await runCigarSetup(plan, off, deps);
  assert.equal(result.effective_enabled, true, "twelve seconds of a busy Guard does not end a setup that is still running");
}
{
  const { deps, script } = fakeGuard({ busyPolls: 1_000 });
  await assert.rejects(runCigarSetup(plan, off, deps), /did not confirm/);
  assert.ok(script.calls.filter((call) => call === "job").length < 45, "a Guard that stays silent ends the wait after about 30 seconds");
}
{
  // Each poll here takes 12 seconds to time out; the 30-second limit still counts from Guard's last answer.
  const { deps, script } = fakeGuard({ busyPolls: 1_000, slowPollMs: 12_000 });
  await assert.rejects(runCigarSetup(plan, off, deps), /did not confirm/);
  assert.equal(script.calls.filter((call) => call === "job").length, 3, "slow failing polls do not stretch the silence limit");
}
{
  const { deps } = fakeGuard({ failPhase: "recovery_required" });
  await assert.rejects(runCigarSetup(plan, off, deps), /Open Updates/);
}
{
  const { deps } = fakeGuard({ neverReady: true });
  await assert.rejects(runCigarSetup(plan, off, deps), (cause: unknown) => cause instanceof CigarSetupError && cause.stage === "start");
}
{
  const { deps, script } = fakeGuard({ initial: saved });
  await runCigarSetup(planCigarStart(saved, false)!, saved, deps);
  assert.deepEqual(script.calls.filter((call) => call !== "status"), ["activate"], "a start-only run saves nothing and switches nothing");
}
{
  // Guard accepted the safety check but its reply was lost and the job showed up one poll late.
  const { deps, script } = fakeGuard({ submitError: { prepare_switch: new ContextAssistanceApiError("versions_outcome_unknown", "Lost") } });
  let late = true;
  const versions = deps.versions;
  deps.versions = async (input, proof) => {
    if (input.action === "job" && late && script.calls.includes("prepare_switch")) { late = false; throw new ContextAssistanceApiError("context_assistance_switch_job_missing", "Missing"); }
    return versions(input, proof);
  };
  await runCigarSetup(plan, off, deps);
  assert.equal(script.calls.filter((call) => call === "prepare_switch").length, 1, "a late job is followed, not resubmitted");
}
{
  const { deps } = fakeGuard();
  const versions = deps.versions;
  deps.versions = async (input, proof) => {
    if (input.action === "job") throw new ContextAssistanceApiError("context_assistance_switch_job_missing", "Missing");
    return versions(input, proof);
  };
  await assert.rejects(runCigarSetup(plan, off, deps), (cause: unknown) => cause instanceof CigarSetupError && cause.stage === "check",
    "a missing job after a confirmed submit is a real failure");
}
{
  // The activate reply was lost after Guard scheduled the check: follow status instead of failing.
  const { deps, script } = fakeGuard({ initial: saved });
  const activate = deps.activate;
  deps.activate = async () => { await activate(); throw new ContextAssistanceApiError("context_assistance_unavailable", "Lost"); };
  const result = await runCigarSetup(planCigarStart(saved, false)!, saved, deps);
  assert.equal(result.effective_enabled, true);
  assert.equal(script.calls.filter((call) => call === "activate").length, 1, "an uncertain start is observed, never resent");
}
{
  const { deps } = fakeGuard({ initial: saved });
  deps.status = async () => { throw new ContextAssistanceApiError("context_assistance_unavailable", "Down"); };
  await assert.rejects(runCigarSetup(planCigarStart(saved, false)!, saved, deps),
    (cause: unknown) => cause instanceof CigarSetupError && /longer than expected/.test(cause.message), "status outages still end at the start deadline");
}
{
  // The activate request never reached Guard: say so instead of quietly resetting the button.
  const { deps } = fakeGuard({ initial: saved });
  deps.activate = async () => { throw new ContextAssistanceApiError("context_assistance_unavailable", "Lost"); };
  deps.status = async () => ({ ...saved, requested_enabled: false, job: null });
  await assert.rejects(runCigarSetup(planCigarStart(saved, false)!, saved, deps),
    (cause: unknown) => cause instanceof CigarSetupError && cause.stage === "start" && /Try again/.test(cause.message));
}
{
  // Guard did get the lost activate request and later turned it off: that is a stop, not a lost request.
  const { deps } = fakeGuard({ initial: saved });
  let polls = 0;
  deps.activate = async () => { throw new ContextAssistanceApiError("context_assistance_unavailable", "Lost"); };
  deps.status = async () => (++polls === 1
    ? { ...saved, requested_enabled: true, job: { id: "1", operation: "activate", phase: "verifying" } }
    : { ...saved, requested_enabled: false, job: null });
  await assert.rejects(runCigarSetup(planCigarStart(saved, false)!, saved, deps), CigarSetupStopped);
}
{
  // The browser's "Failed to fetch" is not something a person can act on.
  const { deps } = fakeGuard({ initial: saved });
  deps.saveSettings = async () => { throw new TypeError("Failed to fetch"); };
  const elsewhere = { ...saved, preferences: { ...saved.preferences, enabled: false } };
  await assert.rejects(runCigarSetup(planCigarStart(saved, false)!, elsewhere, deps),
    (cause: unknown) => cause instanceof CigarSetupError && /Guard did not answer/.test(cause.message) && !/fetch/i.test(cause.message));
}
console.log("CIGAR one-click planning, approval, stop, retry and live-readiness contracts passed.");

{
  const { turnOnPreferences } = await import("./one-click");
  const base = JSON.parse(readFileSync(new URL("./fixtures/intent-state.json", import.meta.url), "utf8")).native_test.ready_observation.preferences;
  const off = { ...base.features, agent_context: false };
  const fresh = turnOnPreferences({ ...base, enabled: false, features: off, sources: { ...base.sources, workspace_documents: false, source_set_id: "" } }, "runtime-a");
  assert.equal(fresh.enabled, true);
  assert.equal(fresh.runtime_id, "runtime-a");
  assert.deepEqual([fresh.sources.workspace_documents, fresh.sources.source_set_id], [true, "selected-workspaces"]);
  // A first turn-on lets prompts carry matching project files.
  assert.equal(fresh.features.agent_context, true);
  // Someone who turned project files off keeps that choice, and prompts stay as they were.
  const chosen = turnOnPreferences({ ...base, enabled: false, features: off, sources: { ...base.sources, workspace_documents: false, source_set_id: "selected-workspaces" } }, "runtime-a");
  assert.equal(chosen.sources.workspace_documents, false);
  assert.equal(chosen.features.agent_context, false);
}
{
  // A slow safety check gets its own window; the wait follows the job's window, not a fixed one.
  const slowCheck = (window: number) => {
    const { deps } = fakeGuard();
    const answer = deps.versions;
    let check = "";
    deps.versions = async (input, proof) => {
      if (input.action === "prepare_switch") check = input.job_id;
      const reply = await answer(input, proof);
      if (input.action !== "job" || input.job_id !== check || deps.now() >= 250_000) return reply;
      return { ...reply, result: { ...reply.result, phase: "preparing", code: "preparing", can_commit: false, created_at_ms: 0, deadline_at_ms: window } };
    };
    return deps;
  };
  assert.equal((await runCigarSetup(plan, off, slowCheck(300_000))).effective_enabled, true,
    "a check that needs four minutes inside its five-minute window finishes");
  await assert.rejects(runCigarSetup(plan, off, slowCheck(120_000)), /taking longer/);
}
