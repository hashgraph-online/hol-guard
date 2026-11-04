import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { GuardApprovalGatePublicConfig, GuardContextAssistanceConfig } from "../guard-types";
import { controlContextAssistance, fetchContextAssistance } from "./api";
import { saveCigarPreference } from "./one-click-api";
import {
  CigarSetupError, CigarSetupStopped, planCigarAdopt, planCigarSetup, planCigarStart, runCigarSetup,
  type CigarSetupPlan, type CigarSetupRun, type CigarSetupStage,
} from "./one-click";
import type { ContextAssistanceStatus } from "./types";
import { forgetTurnOn, forgetTurnOnClick, rememberTurnOn, rememberTurnOnJob, shouldResumeTurnOn, turnOnJob, turnOnRequestedAt } from "./setup-resume";
import { cigarJobPending } from "./versions-actions";
import { requestCigarVersions } from "./versions-api";
import { loadCigarVersionsData, type CigarVersionsData } from "./versions-data";
import { parseCigarVersionJob, type CigarVersionJob } from "./versions-jobs";
import type { ContextProof } from "./workspaces-api";

export type CigarOneClickRun =
  | { phase: "idle" }
  | { phase: "proof"; plan: CigarSetupRun; error: string | null }
  | { phase: "running"; stages: CigarSetupStage[]; stage: CigarSetupStage }
  | { phase: "failed"; stages: CigarSetupStage[]; stage: CigarSetupStage | null; message: string };

type Options = {
  /** False keeps the hook inert, for the compact settings view that has no setup button. */
  active: boolean;
  status: ContextAssistanceStatus | null;
  locked: boolean;
  dirty: boolean;
  disabled: boolean;
  gate: GuardApprovalGatePublicConfig | null;
  publish: (state: ContextAssistanceStatus) => void;
  onSaved: (config: GuardContextAssistanceConfig, previous: GuardContextAssistanceConfig) => void;
  /** Called when Stop lands after the start step began, so CIGAR ends up off like "Turn off CIGAR". */
  onTurnOff: () => void;
};

/** Guard may register a just-submitted job after Stop, so keep asking briefly until the cancel lands. */
async function cancelJob(job: string) {
  const deadline = AbortSignal.timeout(15_000);
  for (let attempt = 0; attempt < 6 && !deadline.aborted; attempt++) {
    try { await requestCigarVersions({ action: "cancel", job_id: job }, undefined, deadline); return; }
    catch { await new Promise((resolve) => setTimeout(resolve, 1_000)); }
  }
}

type OwnJob = { job: CigarVersionJob; state: ContextAssistanceStatus };
/**
 * While the safety check this tab started is open, Guard answers "busy" to the
 * full version list. The check itself can still be read and finished by id.
 */
async function fetchOwnJob(signal: AbortSignal): Promise<OwnJob | null> {
  const id = turnOnJob();
  if (!id) return null;
  try {
    const reply = await requestCigarVersions({ action: "job", job_id: id }, undefined, signal);
    return { job: parseCigarVersionJob(reply.result), state: reply.state };
  } catch { return null; }
}

const wait = (ms: number, signal: AbortSignal) => new Promise<void>((resolve) => {
  const timer = setTimeout(resolve, ms);
  signal.addEventListener("abort", () => { clearTimeout(timer); resolve(); }, { once: true });
});

/** Reads metadata on open; only an explicit click starts preparation work. */
export function useCigarOneClick(options: Options) {
  const [data, setData] = useState<CigarVersionsData | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [run, setRun] = useState<CigarOneClickRun>({ phase: "idle" });
  const [own, setOwn] = useState<OwnJob | null>(null);
  const controller = useRef<AbortController | null>(null);
  const activeJob = useRef<string | null>(null);
  const starting = useRef(false);
  const running = useRef(false), mounted = useRef(false), revision = useRef(0);
  const latest = useRef(options); latest.current = options;

  const refresh = useCallback(async () => {
    if (running.current || !latest.current.active) return;
    const current = ++revision.current;
    try {
      const value = await loadCigarVersionsData(AbortSignal.timeout(15_000));
      if (!mounted.current || current !== revision.current) return;
      setData(value); setLoadError(null); setOwn(null);
    } catch (cause) {
      const job = await fetchOwnJob(AbortSignal.timeout(15_000));
      if (!mounted.current || current !== revision.current) return;
      setOwn(job);
      if (job) latest.current.publish(job.state);
      setLoadError(cause instanceof Error ? cause.message : "Guard did not report CIGAR setup details.");
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    void refresh();
    return () => { mounted.current = false; ++revision.current; controller.current?.abort(); };
  }, [refresh]);

  const plan: CigarSetupPlan | null = useMemo(() => data
    ? planCigarSetup({ ...data, state: options.status ?? data.state }, { locked: options.locked, dirty: options.dirty, adopt: turnOnJob() })
    : (own && planCigarAdopt(own.job, options.status ?? own.state)) ?? planCigarStart(options.status, options.dirty),
  [data, own, options.status, options.locked, options.dirty]);

  // A busy block clears on its own; re-check so the button comes back without a manual refresh.
  const waiting = run.phase === "idle" && ((plan?.kind === "blocked" && plan.block.wait === true)
    || (data === null && own !== null && cigarJobPending(own.job)));
  useEffect(() => {
    if (!waiting) return;
    const timer = setInterval(() => void refresh(), 3_000);
    return () => clearInterval(timer);
  }, [waiting, refresh]);

  // Leaving the page stops the steps this page drives. Coming back finishes a
  // recent click, reusing whatever Guard already prepared, so it never lands on Off.
  const resumed = useRef(false);
  const resume = (data !== null || own !== null) && run.phase === "idle" && !resumed.current && options.active && !options.disabled
    && shouldResumeTurnOn(turnOnRequestedAt(), Date.now(), options.status ?? data?.state ?? own?.state ?? null, plan,
      options.gate?.enabled === true);
  useEffect(() => {
    if (!resume) return;
    resumed.current = true;
    void execute();
    // execute reads the latest options itself.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resume]);
  useEffect(() => {
    if (options.status?.effective_enabled) forgetTurnOn();
  }, [options.status?.effective_enabled]);

  async function execute(proof?: ContextProof) {
    if (running.current || latest.current.disabled || !latest.current.active) return;
    running.current = true;
    ++revision.current;
    const abort = new AbortController(); controller.current = abort;
    let stages: CigarSetupStage[] = [];
    let stage: CigarSetupStage | null = null;
    let planned: CigarSetupRun | null = null;
    let progressed = false;
    // Remember the click before the first request, so leaving at any point still finishes it later.
    rememberTurnOn(Date.now());
    try {
      let failure: unknown = null;
      const fresh = await loadCigarVersionsData(abort.signal).catch((cause: unknown) => { failure = cause; return null; });
      if (abort.signal.aborted) throw new CigarSetupStopped();
      let initial = fresh?.state ?? latest.current.status;
      let next: CigarSetupPlan | null = null;
      if (fresh) {
        setData(fresh); latest.current.publish(fresh.state);
        next = planCigarSetup(fresh, { locked: latest.current.locked, dirty: latest.current.dirty, adopt: turnOnJob() });
      } else {
        const job = await fetchOwnJob(abort.signal);
        if (abort.signal.aborted) throw new CigarSetupStopped();
        next = job && planCigarAdopt(job.job, job.state);
        if (job && next) { initial = job.state; latest.current.publish(job.state); }
        next ??= planCigarStart(latest.current.status, latest.current.dirty);
        if (!next) throw failure;
      }
      if (!next || next.kind !== "run" || !initial) { forgetTurnOn(); setRun({ phase: "idle" }); return; }
      // Asking for approval hands the decision back to the person; an old click must not finish it later.
      if (latest.current.gate?.enabled && next.approval && !proof) { forgetTurnOnClick(); setRun({ phase: "proof", plan: next, error: null }); return; }
      planned = next; stages = next.stages;
      setRun({ phase: "running", stages, stage: stages[0] });
      // A TOTP code is single use; Guard accepts its recent same-session proof for the later steps.
      let credentials = proof;
      // Spend it once a request is sent, whatever the outcome: Guard may have used it even if the reply was lost.
      const spend = () => {
        if (credentials?.totpCode) credentials = credentials.currentPassword ? { currentPassword: credentials.currentPassword } : undefined;
      };
      await runCigarSetup(next, initial, {
        versions: async (input) => {
          try {
            const reply = await requestCigarVersions(input, credentials, abort.signal);
            if (input.action !== "job") progressed = true;
            return reply;
          } finally { if (input.action !== "job") spend(); }
        },
        saveSettings: async (config) => {
          try {
            const saved = await saveCigarPreference(config, credentials, abort.signal);
            progressed = true;
            return saved;
          } finally { spend(); }
        },
        activate: () => controlContextAssistance("activate", abort.signal),
        status: () => fetchContextAssistance(abort.signal),
        sleep: (ms) => wait(ms, abort.signal),
        now: () => Date.now(),
        stopped: () => abort.signal.aborted,
        onJob: (id) => {
          activeJob.current = id;
          if (id && stage === "check") rememberTurnOnJob(id);
        },
        onStage: (value) => {
          stage = value;
          if (value === "start") starting.current = true;
          if (mounted.current) setRun({ phase: "running", stages, stage: value });
        },
        onState: (state) => { if (mounted.current && !abort.signal.aborted) latest.current.publish(state); },
        onSaved: (config, previous) => { if (mounted.current) latest.current.onSaved(config, previous); },
      });
      forgetTurnOn();
      if (mounted.current) setRun({ phase: "idle" });
    } catch (cause) {
      // Unmounting aborts the steps; keep the click so the page can finish it later.
      if (!mounted.current) return;
      if (cause instanceof CigarSetupError && cause.needsProof) forgetTurnOnClick();
      else forgetTurnOn();
      if (cause instanceof CigarSetupStopped || abort.signal.aborted) setRun({ phase: "idle" });
      else if (cause instanceof CigarSetupError && cause.needsProof) {
        // The next attempt re-plans from fresh metadata, so finished steps (Python, the download) are reused.
        const error = progressed ? "Your approval expired while Guard was working. The finished steps are kept. Approve once more to finish."
          : proof ? "That approval did not work. Try again." : null;
        setRun(planned ? { phase: "proof", plan: planned, error } : { phase: "failed", stages, stage, message: cause.message });
      } else {
        setRun({ phase: "failed", stages, stage: cause instanceof CigarSetupError ? cause.stage : stage,
          message: cause instanceof Error ? cause.message : "CIGAR did not finish turning on. Nothing else changed." });
      }
    } finally {
      running.current = false;
      activeJob.current = null;
      starting.current = false;
      if (controller.current === abort) controller.current = null;
      if (mounted.current) void refresh();
    }
  }

  return {
    plan, loadError, run,
    busy: run.phase === "running",
    start: () => void execute(),
    confirm: (proof: ContextProof) => void execute(proof),
    cancelProof: () => { forgetTurnOn(); setRun({ phase: "idle" }); },
    dismiss: () => setRun({ phase: "idle" }),
    /** Stop always wins: abort in-flight polling so no later step runs. */
    stop: () => {
      forgetTurnOn();
      const job = activeJob.current, turnOff = starting.current;
      activeJob.current = null; starting.current = false;
      controller.current?.abort();
      // Past the start step the preference may already be on and a check running; turn CIGAR off for real.
      if (turnOff) latest.current.onTurnOff();
      if (job) void cancelJob(job).finally(() => { if (mounted.current) void refresh(); });
    },
    refresh,
  };
}
