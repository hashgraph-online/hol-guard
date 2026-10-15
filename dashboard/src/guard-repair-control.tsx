import { useCallback, useState } from "react";
import { ActionButton, Tag } from "./approval-center-primitives";
import { ApprovalProofModal } from "./approval-proof-modal";
import {
  GuardRepairRequestError,
  runGuardRepair,
  type GuardRepairCredentials,
  type GuardRepairReport,
  type GuardRepairStep,
} from "./guard-repair-api";
import type { GuardApprovalGatePublicConfig } from "./guard-types";
import { fetchResolvedApprovalGate } from "./use-resolved-approval-gate";

type StepTone = "green" | "blue" | "attention" | "slate";

export function repairStepTone(status: GuardRepairStep["status"]): StepTone {
  if (status === "error") return "attention";
  if (status === "changed") return "green";
  if (status === "planned") return "blue";
  return "slate";
}

export function repairStepLabel(status: GuardRepairStep["status"]): string {
  if (status === "error") return "Failed";
  if (status === "changed") return "Fixed";
  if (status === "planned") return "Needs repair";
  if (status === "skipped") return "Skipped";
  return "Healthy";
}

export function repairHeadline(report: GuardRepairReport): string {
  if (report.status === "partial") return "Some repair steps failed. Run Repair Guard again, or run `hol-guard repair` in a terminal.";
  if (report.status === "repaired") return "Guard was repaired. Restart any coding-agent session that was blocked.";
  if (report.status === "needs_repair") return "Guard found problems to repair.";
  return "Nothing needed repair.";
}

export function GuardRepairStepList({ steps }: { steps: GuardRepairStep[] }) {
  if (steps.length === 0) return null;
  return (
    <ul className="divide-y divide-slate-100 rounded-xl border border-slate-100 bg-white" aria-label="Repair steps">
      {steps.map((step) => (
        <li key={step.step} className="flex flex-wrap items-start justify-between gap-x-3 gap-y-1 px-3 py-2">
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium text-brand-dark">{step.title}</p>
            <p className="break-words text-xs text-slate-500">{step.summary}</p>
          </div>
          <Tag tone={repairStepTone(step.status)}>{repairStepLabel(step.status)}</Tag>
        </li>
      ))}
    </ul>
  );
}

type RepairPhase =
  | { kind: "idle" }
  | { kind: "proof"; gate: GuardApprovalGatePublicConfig | null; error: string | null }
  | { kind: "working" }
  | { kind: "done"; report: GuardRepairReport }
  | { kind: "error"; message: string };

type GuardRepairControlProps = {
  /** Extra copy shown above the button. */
  description?: string;
  buttonVariant?: "primary" | "secondary" | "outline";
  onFinished?: (report: GuardRepairReport) => void;
};

export function GuardRepairControl({
  description,
  buttonVariant = "secondary",
  onFinished,
}: GuardRepairControlProps) {
  const [phase, setPhase] = useState<RepairPhase>({ kind: "idle" });

  const run = useCallback(
    async (credentials?: GuardRepairCredentials, gate: GuardApprovalGatePublicConfig | null = null) => {
      setPhase({ kind: "working" });
      try {
        const report = await runGuardRepair({ credentials });
        setPhase({ kind: "done", report });
        onFinished?.(report);
      } catch (error) {
        const message = error instanceof Error ? error.message : "Guard could not run repair.";
        if (error instanceof GuardRepairRequestError && gate?.enabled && error.status >= 400 && error.status < 500) {
          setPhase({ kind: "proof", gate, error: message });
          return;
        }
        setPhase({ kind: "error", message });
      }
    },
    [onFinished],
  );

  const handleStart = useCallback(async () => {
    setPhase({ kind: "working" });
    let gate: GuardApprovalGatePublicConfig | null = null;
    try {
      gate = await fetchResolvedApprovalGate();
    } catch {
      setPhase({ kind: "error", message: "Guard could not check the approval gate. Try again." });
      return;
    }
    if (gate?.enabled) {
      setPhase({ kind: "proof", gate, error: null });
      return;
    }
    await run(undefined, gate);
  }, [run]);

  const handleConfirm = useCallback(
    (credentials: GuardRepairCredentials) => {
      if (phase.kind !== "proof") return;
      void run(credentials, phase.gate);
    },
    [phase, run],
  );

  const handleCancel = useCallback(() => setPhase({ kind: "idle" }), []);
  const handleStartClick = useCallback(() => {
    void handleStart();
  }, [handleStart]);

  const working = phase.kind === "working";
  return (
    <div className="space-y-3">
      {description ? <p className="text-xs text-slate-500">{description}</p> : null}
      <div>
        <ActionButton onClick={handleStartClick} disabled={working} variant={buttonVariant}>
          {working ? "Repairing…" : "Repair Guard"}
        </ActionButton>
      </div>
      <div aria-live="polite">
        {phase.kind === "done" ? (
          <div className="space-y-2">
            <p className="text-sm font-medium text-brand-dark">{repairHeadline(phase.report)}</p>
            <GuardRepairStepList steps={phase.report.steps} />
          </div>
        ) : null}
        {phase.kind === "error" ? (
          <p role="alert" className="text-sm text-brand-attention">{phase.message}</p>
        ) : null}
      </div>
      {phase.kind === "proof" ? (
        <ApprovalProofModal
          title="Repair Guard"
          detail="Enter local approval proof before Guard repairs its daemon, hooks, and stale local state."
          confirmLabel="Repair Guard"
          approvalGate={phase.gate}
          error={phase.error}
          onCancel={handleCancel}
          onConfirm={handleConfirm}
        />
      ) : null}
    </div>
  );
}
