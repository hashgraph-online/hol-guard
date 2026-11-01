import type { GuardContextAssistanceConfig } from "../guard-types";
import { ContextAssistanceApiError } from "./api";
import { contextStatusCopy } from "./status";
import type { ContextAssistanceStatus } from "./types";
import { canCommitCigarJob, cigarBuildBlock, cigarJobPending, cigarPythonBlock, cigarVersionJobId } from "./versions-actions";
import type { CigarVersionsReply, CigarVersionsRequest } from "./versions-api";
import type { CigarVersionsData } from "./versions-data";
import { parseCigarVersionJob, type CigarVersionJob } from "./versions-jobs";
import type { ContextProof } from "./workspaces-api";
import { canStartCigar, type CigarTab } from "./workspace-model";

export type CigarSetupStage = "python" | "download" | "check" | "start";
export const CIGAR_SETUP_STAGE_LABELS: Record<CigarSetupStage, string> = {
  python: "Get Python ready",
  download: "Download CIGAR",
  check: "Check it is the approved copy",
  start: "Start CIGAR",
};
/** `wait` marks a block that clears by itself, so the page re-checks instead of waiting for a click. */
export type CigarSetupBlock = { title: string; detail: string; tab?: CigarTab; wait?: boolean };
export type CigarSetupRun = {
  kind: "run";
  runtime_id: string | null;
  build_id: string | null;
  interpreter_id: string | null;
  python_build_id: string | null;
  stages: CigarSetupStage[];
  /** False only when the saved preference already permits a start, which needs no proof. */
  approval: boolean;
};
export type CigarSetupPlan = { kind: "ready" } | { kind: "blocked"; block: CigarSetupBlock } | CigarSetupRun;

const python314 = (version: readonly number[]) => version[0] === 3 && version[1] === 14;
const blocked = (title: string, detail: string, tab?: CigarTab, wait?: boolean): CigarSetupPlan => ({ kind: "blocked", block: { title, detail, tab, wait } });

/**
 * Choose the shortest path from native metadata. Every input is something
 * Guard already reported; the plan never invents a build, a URL or a path.
 */
export function planCigarSetup(data: CigarVersionsData, options: { locked: boolean; dirty: boolean }): CigarSetupPlan {
  const { state, catalog } = data;
  if (state.effective_enabled) return { kind: "ready" };
  if (options.dirty) return blocked("Save your changes first", "You have unsaved settings on this page. Save or undo them, then turn CIGAR on.");
  if (options.locked || (state.restriction && !state.effective_preferences.enabled)) {
    return blocked("Your organization manages CIGAR", "An administrator controls CIGAR on this computer. Ask them if you need it turned on.");
  }
  if (state.job || data.jobs.some(cigarJobPending)) return blocked("CIGAR is busy", "Another CIGAR task is still finishing. This button comes back when it is done.", "versions", true);
  if (data.jobs.some((job) => job.phase === "recovery_required")) {
    return blocked("An earlier setup did not finish", "Guard paused an earlier CIGAR task so nothing breaks. Open Updates to finish or undo it.", "versions");
  }
  const selected = state.preferences.runtime_id;
  const installed = data.installations;
  const current = selected && installed.some((item) => item.runtime_id === selected) ? selected : null;
  const reusable = current ?? (installed.find((item) => item.qualification === "guard_qualified") ?? installed[0])?.runtime_id ?? null;
  const tail: CigarSetupStage[] = reusable === current && current !== null ? ["start"] : ["check", "start"];
  if (reusable) {
    return { kind: "run", runtime_id: reusable, build_id: null, interpreter_id: null, python_build_id: null, stages: tail,
      approval: tail.length > 1 || !state.preferences.enabled };
  }

  const host = catalog.host_platform;
  if (!host) return blocked("Not available for this computer yet", "CIGAR does not have a version for this kind of computer yet. Guard keeps protecting you without it.");
  const build = catalog.builds.find((item) => cigarBuildBlock(catalog, item, data.updates) === null);
  if (!build) {
    const forHost = catalog.builds.filter((item) => !item.withdrawn && item.platforms.some((p) => p.platform === host));
    if (forHost.length === 0) {
      return blocked("Not available for this computer yet", "CIGAR does not have a version for this kind of computer yet. Guard keeps protecting you without it.");
    }
    if (!catalog.catalog.fresh_for_preparation) {
      return blocked("Guard needs a fresh version list", "Guard's list of CIGAR versions is out of date. Open Updates to refresh it.", "versions");
    }
    return blocked("No version can be installed right now", "Open Updates to see which CIGAR versions are available and why.", "versions");
  }
  const interpreter = data.interpreters.find((item) => item.platform === host && python314(item.python_version)
    && item.implementation.toLowerCase() === "cpython");
  const pythonBuild = interpreter ? null : catalog.interpreter_builds.find((item) => python314(item.python_version) && cigarPythonBlock(catalog, item) === null);
  if (!interpreter && !pythonBuild) {
    return blocked("Not available for this computer yet", "CIGAR needs its own copy of Python 3.14, and Guard does not have one for this kind of computer yet. Guard keeps protecting you without it.");
  }
  return { kind: "run", runtime_id: null, build_id: build.identity.build_id, interpreter_id: interpreter?.interpreter_id ?? null,
    python_build_id: pythonBuild?.build_id ?? null, stages: [...(pythonBuild ? ["python" as const] : []), "download", "check", "start"],
    approval: true };
}

/** A saved, selected preference can start without version metadata (for example on an older daemon). */
export function planCigarStart(status: ContextAssistanceStatus | null, dirty: boolean): CigarSetupRun | null {
  return status && canStartCigar(status, dirty) ? { kind: "run", runtime_id: status.preferences.runtime_id, build_id: null,
    interpreter_id: null, python_build_id: null, stages: ["start"], approval: false } : null;
}

export class CigarSetupError extends Error {
  constructor(public readonly stage: CigarSetupStage | null, message: string, public readonly needsProof = false) {
    super(message);
    this.name = "CigarSetupError";
  }
}
export class CigarSetupStopped extends Error {
  constructor() { super("CIGAR setup stopped."); this.name = "CigarSetupStopped"; }
}

export type CigarSetupDeps = {
  versions: (input: CigarVersionsRequest, proof?: ContextProof) => Promise<CigarVersionsReply>;
  saveSettings: (config: GuardContextAssistanceConfig, proof?: ContextProof) => Promise<GuardContextAssistanceConfig>;
  activate: () => Promise<ContextAssistanceStatus>;
  status: () => Promise<ContextAssistanceStatus>;
  sleep: (ms: number) => Promise<void>;
  now: () => number;
  stopped: () => boolean;
  onStage: (stage: CigarSetupStage) => void;
  /** The job a Stop should cancel, or null between jobs. */
  onJob: (jobId: string | null) => void;
  onState: (state: ContextAssistanceStatus) => void;
  onSaved: (config: GuardContextAssistanceConfig, previous: GuardContextAssistanceConfig) => void;
};

const JOB_LIMIT_MS = 180_000, START_LIMIT_MS = 120_000, POLL_MS = 800;
const failedPhases = new Set(["failed", "cancelled", "recovery_required"]);
export const isCigarProofError = (cause: unknown) => cause instanceof ContextAssistanceApiError
  && (cause.code.startsWith("approval_gate") || cause.code === "approval_required");
const transient = (cause: unknown) => !(cause instanceof ContextAssistanceApiError)
  || cause.code.endsWith("context_stale") || cause.code.endsWith("outcome_unknown") || cause.code === "context_assistance_unavailable";
const missingJob = (cause: unknown) => cause instanceof ContextAssistanceApiError && cause.code.endsWith("job_missing");

function guard(deps: CigarSetupDeps) {
  if (deps.stopped()) throw new CigarSetupStopped();
}
function failure(stage: CigarSetupStage, cause: unknown): never {
  if (cause instanceof CigarSetupStopped || cause instanceof CigarSetupError) throw cause;
  if (isCigarProofError(cause)) throw new CigarSetupError(stage, "Guard needs your approval password to continue.", true);
  throw new CigarSetupError(stage, cause instanceof Error ? cause.message : "Guard did not confirm this step.");
}

/** Submit once, then follow the job by id. An unknown submit outcome is observed, never resent. */
async function follow(
  deps: CigarSetupDeps, stage: CigarSetupStage, input: CigarVersionsRequest & { job_id: string }, proof: ContextProof | undefined,
  done: (job: CigarVersionJob, state: ContextAssistanceStatus) => boolean,
): Promise<{ job: CigarVersionJob; state: ContextAssistanceStatus }> {
  guard(deps);
  deps.onJob(input.job_id);
  // After an unknown submit outcome Guard may register the job late, so a missing job is not yet an answer.
  let uncertain = false;
  try {
    deps.onState((await deps.versions(input, proof)).state);
  } catch (cause) {
    if (!transient(cause)) failure(stage, cause);
    uncertain = true;
  }
  const started = deps.now();
  let misses = 0;
  for (;;) {
    guard(deps);
    let reply: CigarVersionsReply | null = null;
    try {
      reply = await deps.versions({ action: "job", job_id: input.job_id });
      misses = 0;
      uncertain = false;
    } catch (cause) {
      const retry = transient(cause) || (uncertain && missingJob(cause));
      if (!retry) failure(stage, cause);
      if (++misses > 5) {
        throw new CigarSetupError(stage, "Guard did not confirm this step. Check Updates before trying again.");
      }
    }
    if (reply) {
      deps.onState(reply.state);
      const job = parseCigarVersionJob(reply.result);
      if (done(job, reply.state)) { deps.onJob(null); return { job, state: reply.state }; }
      if (failedPhases.has(job.phase)) {
        throw new CigarSetupError(stage, job.phase === "recovery_required"
          ? "Guard paused this step so nothing breaks. Open Updates to finish or undo it."
          : "This step did not finish (" + job.code.replace(/_/g, " ") + "). Nothing was turned on.");
      }
    }
    if (deps.now() - started > JOB_LIMIT_MS) throw new CigarSetupError(stage, "This is taking longer than expected. Guard is still working; check Updates in a minute.");
    await deps.sleep(POLL_MS);
  }
}

/** Run the plan to a verified Ready state. Stop wins at every boundary. */
export async function runCigarSetup(plan: CigarSetupRun, initial: ContextAssistanceStatus, deps: CigarSetupDeps, proof?: ContextProof): Promise<ContextAssistanceStatus> {
  let state = initial;
  let interpreter = plan.interpreter_id;
  let runtime = plan.runtime_id;
  if (plan.python_build_id) {
    deps.onStage("python");
    const { job } = await follow(deps, "python", { action: "setup_interpreter", job_id: cigarVersionJobId(), build_id: plan.python_build_id }, proof,
      (item) => (item.phase === "ready" || item.phase === "completed") && item.family === "preparation" && Boolean(item.interpreter_id));
    interpreter = job.family === "preparation" ? job.interpreter_id ?? null : null;
  }
  if (plan.build_id) {
    if (!interpreter) throw new CigarSetupError("download", "Guard did not report a Python 3.14 copy for CIGAR.");
    deps.onStage("download");
    const { job, state: next } = await follow(deps, "download",
      { action: "install", job_id: cigarVersionJobId(), build_id: plan.build_id, interpreter_id: interpreter }, proof,
      (item) => (item.phase === "ready" || item.phase === "completed") && item.family === "preparation" && Boolean(item.runtime_id));
    runtime = job.family === "preparation" ? job.runtime_id ?? null : null;
    state = next;
  }
  if (!runtime) throw new CigarSetupError("download", "Guard did not report an installed CIGAR copy.");
  if (state.preferences.runtime_id !== runtime) {
    deps.onStage("check");
    const id = cigarVersionJobId();
    const ready = await follow(deps, "check",
      { action: "prepare_switch", job_id: id, target_runtime_id: runtime, expected_generation: state.generation }, proof,
      (item, current) => item.family === "selection" && canCommitCigarJob(item, current));
    const job = ready.job;
    if (job.family !== "selection") throw new CigarSetupError("check", "Guard returned an unexpected job.");
    const committed = await follow(deps, "check",
      { action: "commit", job_id: id, expected_generation: job.expected_generation, reconnect: job.reconnect_required }, proof,
      (item) => item.phase === "completed");
    state = committed.state;
  }
  guard(deps);
  deps.onStage("start");
  if (!state.preferences.enabled || state.preferences.runtime_id !== runtime) {
    const previous = state.preferences;
    let saved: GuardContextAssistanceConfig;
    try {
      saved = await deps.saveSettings({ ...previous, enabled: true, runtime_id: runtime }, proof);
    } catch (cause) { failure("start", cause); }
    deps.onSaved(saved, previous);
  }
  guard(deps);
  // A lost activate reply is followed through live status; only a check that never appears allows another try.
  let fresh = true, unconfirmed = false;
  try { state = await deps.activate(); } catch (cause) { if (!transient(cause)) failure("start", cause); fresh = false; unconfirmed = true; }
  if (fresh) deps.onState(state);
  const started = deps.now();
  let sawJob = fresh && state.job !== null;
  for (;;) {
    if (fresh && state.effective_enabled) return state;
    guard(deps);
    if (fresh && !state.requested_enabled) {
      if (unconfirmed) throw new CigarSetupError("start", "Guard did not get the request to start CIGAR. Try again.");
      throw new CigarSetupStopped();
    }
    if (fresh && state.job === null && (sawJob || deps.now() - started > 3_000)) throw new CigarSetupError("start", contextStatusCopy(state).detail);
    if (deps.now() - started > START_LIMIT_MS) {
      throw new CigarSetupError("start", "CIGAR is taking longer than expected to start. Refresh status in a minute.");
    }
    await deps.sleep(POLL_MS);
    try { state = await deps.status(); fresh = true; } catch (cause) { if (!transient(cause)) failure("start", cause); fresh = false; continue; }
    // Once Guard shows the request, a later off state is a real stop, not a lost request.
    if (state.requested_enabled) unconfirmed = false;
    sawJob ||= state.job !== null;
    deps.onState(state);
  }
}
