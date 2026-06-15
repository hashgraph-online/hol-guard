import { HiMiniArrowPath, HiMiniCheckCircle } from "react-icons/hi2";
import type { AuditRunPhase } from "./use-supply-chain-audit-session";

type AuditProgressProps = {
  phase: AuditRunPhase;
  running: boolean;
};

type StepState = "pending" | "active" | "done";

const STEPS: Array<{ id: AuditRunPhase; label: string }> = [
  { id: "preparing", label: "Prepare workspace" },
  { id: "scanning", label: "Scan manifests and lockfiles" },
  { id: "evaluating", label: "Evaluate packages against Guard intel" },
  { id: "finalizing", label: "Prepare results" },
];

function stepState(stepId: AuditRunPhase, phase: AuditRunPhase, running: boolean): StepState {
  const order = STEPS.map((step) => step.id);
  const stepIndex = order.indexOf(stepId);
  const phaseIndex = order.indexOf(phase);
  if (!running && phase === "idle") {
    return "pending";
  }
  if (phase === "finalizing" && stepId !== "finalizing") {
    return "done";
  }
  if (stepIndex < phaseIndex) {
    return "done";
  }
  if (stepIndex === phaseIndex) {
    return "active";
  }
  return "pending";
}

function stepTextClass(state: StepState): string {
  if (state === "active") {
    return "font-medium text-brand-dark";
  }
  if (state === "done") {
    return "text-slate-600";
  }
  return "text-slate-400";
}

function stepBubbleClass(state: StepState): string {
  if (state === "active") {
    return "bg-brand-blue text-white";
  }
  if (state === "done") {
    return "bg-brand-green/15 text-brand-green-text";
  }
  return "border border-slate-200 bg-white text-slate-400";
}

export function AuditProgressStepList({ phase, running }: AuditProgressProps) {
  return (
    <ol className="space-y-2" aria-live="polite" aria-busy={running} data-testid="audit-run-progress">
      {STEPS.map((step, index) => {
        const state = stepState(step.id, phase, running);
        return (
          <li key={step.id} className={`flex items-center gap-2 text-sm ${stepTextClass(state)}`}>
            <span
              className={`inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[10px] font-semibold ${stepBubbleClass(state)}`}
              aria-hidden="true"
            >
              {state === "done" ? "✓" : index + 1}
            </span>
            {step.label}
          </li>
        );
      })}
    </ol>
  );
}

export function auditProgressActive(phase: AuditRunPhase, running: boolean): boolean {
  return running || phase !== "idle";
}

export function AuditRunProgress({ phase, running }: AuditProgressProps) {
  if (!auditProgressActive(phase, running)) {
    return null;
  }

  return (
    <section className="rounded-2xl border border-brand-blue/15 bg-brand-blue/[0.03] px-4 py-4">
      <div className="flex items-center gap-2">
        {running ? (
          <HiMiniArrowPath className="h-4 w-4 shrink-0 animate-spin text-brand-blue" aria-hidden="true" />
        ) : (
          <HiMiniCheckCircle className="h-4 w-4 shrink-0 text-brand-green" aria-hidden="true" />
        )}
        <p className="text-sm font-medium text-brand-dark">
          {running ? "Workspace audit in progress" : "Workspace audit complete"}
        </p>
      </div>
      <div className="mt-4">
        <AuditProgressStepList phase={phase} running={running} />
      </div>
    </section>
  );
}
