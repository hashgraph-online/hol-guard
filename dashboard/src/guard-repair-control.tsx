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

export function stepNeedsAttention(step: GuardRepairStep): boolean {
  return step.needs_attention.length > 0;
}

export function repairAttentionTitles(steps: GuardRepairStep[]): string[] {
  return steps.filter(stepNeedsAttention).map((step) => step.title);
}

export function repairStepTone(step: GuardRepairStep): StepTone {
  if (step.status === "error" || stepNeedsAttention(step)) return "attention";
  if (step.status === "changed") return "green";
  if (step.status === "planned") return "blue";
  return "slate";
}

export function repairStepLabel(step: GuardRepairStep): string {
  if (step.status === "error") return "Failed";
  // A step that fixed some apps and left others broken is not simply "Fixed":
  // the part it could not settle is the part the user came here for.
  if (stepNeedsAttention(step)) return "Needs you";
  if (step.status === "changed") return "Fixed";
  if (step.status === "planned") return "Needs repair";
  if (step.status === "skipped") return "Skipped";
  return "Healthy";
}

export function repairHeadline(report: GuardRepairReport): string {
  if (report.status === "partial") {
    if (report.steps.some((step) => step.status === "error")) {
      return "Some repair steps failed. Run Repair Guard again, or run `hol-guard repair` in a terminal.";
    }
    // Repair reports "partial" for a step that needs the user as well as for
    // one that failed. Only the second is worth another run; telling the user
    // to repair again when nothing failed sends them round a loop that ends
    // where it started. A step that ran out of budget is the exception: it
    // left work another run picks up.
    const waiting = repairAttentionTitles(report.steps);
    const named = waiting.length > 0 ? ` Still waiting on you: ${waiting.join(", ")}.` : "";
    if (report.steps.some((step) => step.budget_exhausted)) {
      return `No repair step failed. Run Repair Guard again to continue the cleanup it could not finish.${named}`;
    }
    return `No repair step failed, and running repair again reaches the same answer.${named}`;
  }
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
          <Tag tone={repairStepTone(step)}>{repairStepLabel(step)}</Tag>
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
