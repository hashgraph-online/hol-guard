import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { GuardApprovalGatePublicConfig, GuardContextAssistanceConfig } from "../guard-types";
import { controlContextAssistance, fetchContextAssistance } from "./api";
import { saveCigarPreference } from "./one-click-api";
import {
  CigarSetupError, CigarSetupStopped, planCigarSetup, planCigarStart, runCigarSetup,
  type CigarSetupPlan, type CigarSetupRun, type CigarSetupStage,
} from "./one-click";
import type { ContextAssistanceStatus } from "./types";
import { requestCigarVersions } from "./versions-api";
import { loadCigarVersionsData, type CigarVersionsData } from "./versions-data";
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
};

const wait = (ms: number, signal: AbortSignal) => new Promise<void>((resolve) => {
  const timer = setTimeout(resolve, ms);
  signal.addEventListener("abort", () => { clearTimeout(timer); resolve(); }, { once: true });
});

/** Reads metadata on open; only an explicit click starts preparation work. */
export function useCigarOneClick(options: Options) {
  const [data, setData] = useState<CigarVersionsData | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [run, setRun] = useState<CigarOneClickRun>({ phase: "idle" });
  const controller = useRef<AbortController | null>(null);
  const activeJob = useRef<string | null>(null);
  const running = useRef(false), mounted = useRef(false), revision = useRef(0);
  const latest = useRef(options); latest.current = options;

  const refresh = useCallback(async () => {
    if (running.current || !latest.current.active) return;
    const current = ++revision.current;
    try {
      const value = await loadCigarVersionsData(AbortSignal.timeout(15_000));
      if (!mounted.current || current !== revision.current) return;
      setData(value); setLoadError(null);
    } catch (cause) {
      if (!mounted.current || current !== revision.current) return;
      setLoadError(cause instanceof Error ? cause.message : "Guard did not report CIGAR setup details.");
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    void refresh();
    return () => { mounted.current = false; ++revision.current; controller.current?.abort(); };
  }, [refresh]);

  const plan: CigarSetupPlan | null = useMemo(() => data
    ? planCigarSetup({ ...data, state: options.status ?? data.state }, { locked: options.locked, dirty: options.dirty })
    : planCigarStart(options.status, options.dirty),
  [data, options.status, options.locked, options.dirty]);

  async function execute(proof?: ContextProof) {
    if (running.current || latest.current.disabled || !latest.current.active) return;
    running.current = true;
    ++revision.current;
    const abort = new AbortController(); controller.current = abort;
    let stages: CigarSetupStage[] = [];
    let stage: CigarSetupStage | null = null;
    let planned: CigarSetupRun | null = null;
    try {
      const fresh = await loadCigarVersionsData(abort.signal).catch((cause: unknown) => {
        if (planCigarStart(latest.current.status, latest.current.dirty)) return null;
        throw cause;
      });
      if (abort.signal.aborted) throw new CigarSetupStopped();
      if (fresh) { setData(fresh); latest.current.publish(fresh.state); }
      const initial = fresh?.state ?? latest.current.status;
      const next = fresh ? planCigarSetup(fresh, { locked: latest.current.locked, dirty: latest.current.dirty })
        : planCigarStart(latest.current.status, latest.current.dirty);
      if (!next || next.kind !== "run" || !initial) { setRun({ phase: "idle" }); return; }
      if (latest.current.gate?.enabled && next.approval && !proof) { setRun({ phase: "proof", plan: next, error: null }); return; }
      planned = next; stages = next.stages;
      setRun({ phase: "running", stages, stage: stages[0] });
      // A TOTP code is single use; Guard accepts its recent same-session proof for the later steps.
      let credentials = proof;
      const spend = () => {
        if (credentials?.totpCode) credentials = credentials.currentPassword ? { currentPassword: credentials.currentPassword } : undefined;
      };
      await runCigarSetup(next, initial, {
        versions: async (input) => {
          const reply = await requestCigarVersions(input, credentials, abort.signal);
          if (input.action !== "job") spend();
          return reply;
        },
        saveSettings: async (config) => {
          const saved = await saveCigarPreference(config, credentials, abort.signal);
          spend();
          return saved;
        },
        activate: () => controlContextAssistance("activate", abort.signal),
        status: () => fetchContextAssistance(abort.signal),
        sleep: (ms) => wait(ms, abort.signal),
        now: () => Date.now(),
        stopped: () => abort.signal.aborted,
        onJob: (id) => { activeJob.current = id; },
        onStage: (value) => { stage = value; if (mounted.current) setRun({ phase: "running", stages, stage: value }); },
        onState: (state) => { if (mounted.current && !abort.signal.aborted) latest.current.publish(state); },
        onSaved: (config, previous) => { if (mounted.current) latest.current.onSaved(config, previous); },
      });
      if (mounted.current) setRun({ phase: "idle" });
    } catch (cause) {
      if (!mounted.current) return;
      if (cause instanceof CigarSetupStopped || abort.signal.aborted) setRun({ phase: "idle" });
      else if (cause instanceof CigarSetupError && cause.needsProof) {
        // Nothing past the approval check started; the next attempt re-plans from fresh metadata.
        setRun(planned ? { phase: "proof", plan: planned, error: proof ? "That approval did not work. Try again." : null }
          : { phase: "failed", stages, stage, message: cause.message });
      } else {
        setRun({ phase: "failed", stages, stage: cause instanceof CigarSetupError ? cause.stage : stage,
          message: cause instanceof Error ? cause.message : "CIGAR did not finish turning on. Nothing else changed." });
      }
    } finally {
      running.current = false;
      activeJob.current = null;
      if (controller.current === abort) controller.current = null;
      if (mounted.current) void refresh();
    }
  }

  return {
    plan, loadError, run,
    busy: run.phase === "running",
    start: () => void execute(),
    confirm: (proof: ContextProof) => void execute(proof),
    cancelProof: () => setRun({ phase: "idle" }),
    dismiss: () => setRun({ phase: "idle" }),
    /** Stop always wins: abort in-flight polling so no later step runs. */
    stop: () => {
      const job = activeJob.current;
      controller.current?.abort();
      // Best effort: ask Guard to cancel the job that was running; it rolls back on its own terms.
      if (job) void requestCigarVersions({ action: "cancel", job_id: job }, undefined, AbortSignal.timeout(10_000)).catch(() => undefined);
    },
    refresh,
  };
}
