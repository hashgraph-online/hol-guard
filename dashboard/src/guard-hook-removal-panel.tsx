import { useCallback, useState } from "react";
import { ActionButton, Tag } from "./approval-center-primitives";
import { ApprovalProofModal } from "./approval-proof-modal";
import {
  GuardRepairRequestError,
  planGuardHookRemoval,
  removeAllGuardHooks,
  type GuardHookRemovalHarness,
  type GuardHookRemovalReport,
  type GuardRepairCredentials,
} from "./guard-repair-api";
import type { GuardApprovalGatePublicConfig } from "./guard-types";
import { fetchResolvedApprovalGate } from "./use-resolved-approval-gate";

type RemovalPhase =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "review"; plan: GuardHookRemovalReport; gate: GuardApprovalGatePublicConfig | null }
  | { kind: "proof"; plan: GuardHookRemovalReport; gate: GuardApprovalGatePublicConfig | null; error: string | null }
  | { kind: "removing"; plan: GuardHookRemovalReport; gate: GuardApprovalGatePublicConfig | null }
  | { kind: "done"; report: GuardHookRemovalReport }
  | { kind: "error"; message: string };

export function describeAffectedHarness(item: GuardHookRemovalHarness): string {
  const count = item.hook_count ?? item.swept_hook_count;
  if (typeof count === "number" && count > 0) {
    return `${item.harness} (${count} hook${count === 1 ? "" : "s"})`;
  }
  return item.harness;
}

export function removalOutcomeMessage(report: GuardHookRemovalReport): string {
  if (report.status === "nothing_to_remove") return "No Guard hooks were found. Nothing was removed.";
  if (report.status === "partial") {
    return "Some Guard hooks could not be removed. Review the apps below, then try again or run `hol-guard hooks remove --all` in a terminal.";
  }
  return "Guard hooks were removed. Your coding apps now run without Guard protection.";
}

function AffectedList({ items, label }: { items: GuardHookRemovalHarness[]; label: string }) {
  if (items.length === 0) return null;
  return (
    <ul className="flex flex-wrap gap-1.5" aria-label={label}>
      {items.map((item) => (
        <li key={item.harness}>
          <Tag tone="slate">{describeAffectedHarness(item)}</Tag>
        </li>
      ))}
    </ul>
  );
}

export function GuardHookRemovalPanel() {
  const [phase, setPhase] = useState<RemovalPhase>({ kind: "idle" });

  const handleReview = useCallback(async () => {
    setPhase({ kind: "loading" });
    try {
      const [plan, gate] = await Promise.all([planGuardHookRemoval(), fetchResolvedApprovalGate()]);
      setPhase(
        plan.status === "nothing_to_remove"
          ? { kind: "done", report: plan }
          : { kind: "review", plan, gate },
      );
    } catch (error) {
      setPhase({ kind: "error", message: error instanceof Error ? error.message : "Guard could not list its hooks." });
    }
  }, []);

  const handleReviewClick = useCallback(() => {
    void handleReview();
  }, [handleReview]);

  const handleContinue = useCallback(() => {
    setPhase((current) =>
      current.kind === "review" ? { kind: "proof", plan: current.plan, gate: current.gate, error: null } : current,
    );
  }, []);

  const handleCancel = useCallback(() => setPhase({ kind: "idle" }), []);

  const handleConfirm = useCallback(
    async (credentials: GuardRepairCredentials) => {
      if (phase.kind !== "proof") return;
      const { plan, gate } = phase;
      setPhase({ kind: "removing", plan, gate });
      try {
        setPhase({ kind: "done", report: await removeAllGuardHooks(credentials) });
      } catch (error) {
        const message = error instanceof Error ? error.message : "Guard could not remove its hooks.";
        const retryable = error instanceof GuardRepairRequestError && error.status >= 400 && error.status < 500;
        setPhase(retryable ? { kind: "proof", plan, gate, error: message } : { kind: "error", message });
      }
    },
    [phase],
  );

  const handleConfirmClick = useCallback(
    (credentials: GuardRepairCredentials) => {
      void handleConfirm(credentials);
    },
    [handleConfirm],
  );

  const gateMissing =
    (phase.kind === "review" || phase.kind === "proof" || phase.kind === "removing") && !phase.gate?.enabled;
  const remaining = phase.kind === "done" ? (phase.report.post_state?.remaining_harnesses ?? []) : [];
  return (
    <div className="space-y-3">
      <div>
        <p className="text-sm font-semibold text-brand-dark">Remove Guard from all apps</p>
        <p className="text-xs text-slate-500">
          Removes every Guard hook from every connected app, including ones Guard no longer tracks. Other hooks are
          left alone and each changed file is backed up. Needs your approval password or authenticator code.
        </p>
      </div>
      {phase.kind === "idle" || phase.kind === "loading" || phase.kind === "error" ? (
        <div>
          <ActionButton onClick={handleReviewClick} disabled={phase.kind === "loading"} variant="outline">
            {phase.kind === "loading" ? "Checking apps…" : "Review and remove"}
          </ActionButton>
        </div>
      ) : null}
      {phase.kind === "review" || phase.kind === "proof" || phase.kind === "removing" ? (
        <div className="space-y-2 rounded-xl border border-brand-attention/20 bg-brand-attention/[0.04] p-3">
          <p className="text-sm font-medium text-brand-dark">
            Guard hooks will be removed from {phase.plan.harnesses.length} app
            {phase.plan.harnesses.length === 1 ? "" : "s"}. They stop being protected until you reinstall.
          </p>
          <AffectedList items={phase.plan.harnesses} label="Apps affected" />
          {gateMissing ? (
            <p className="text-xs text-slate-600">
              Removal from the dashboard needs the local approval gate. Enable it in Settings, Approval gate, or run{" "}
              <code className="font-mono">hol-guard hooks remove --all</code> in a terminal.
            </p>
          ) : (
            <div className="flex gap-2">
              <ActionButton variant="danger" onClick={handleContinue} disabled={phase.kind !== "review"}>
                Remove Guard from all apps
              </ActionButton>
              <ActionButton variant="outline" onClick={handleCancel} disabled={phase.kind === "removing"}>
                Cancel
              </ActionButton>
            </div>
          )}
          {gateMissing ? (
            <ActionButton variant="outline" onClick={handleCancel}>
              Close
            </ActionButton>
          ) : null}
        </div>
      ) : null}
      <div aria-live="polite">
        {phase.kind === "done" ? (
          <div className="space-y-2">
            <p className="text-sm font-medium text-brand-dark">{removalOutcomeMessage(phase.report)}</p>
            {phase.report.status !== "nothing_to_remove" ? (
              <>
                <AffectedList items={phase.report.harnesses} label="Apps changed" />
                <p className="text-xs text-slate-500">
                  {remaining.length === 0
                    ? "Check: no Guard hooks remain in any app."
                    : `Still has Guard hooks: ${remaining.map((item) => item.harness).join(", ")}.`}
                </p>
                {phase.report.backup_dir ? (
                  <p className="break-all text-xs text-slate-500">Backups: {phase.report.backup_dir}</p>
                ) : null}
                <p className="text-xs text-slate-500">
                  Reinstall with <code className="font-mono">{phase.report.reinstall_command}</code>.
                </p>
              </>
            ) : null}
          </div>
        ) : null}
        {phase.kind === "error" ? (
          <p role="alert" className="text-sm text-brand-attention">{phase.message}</p>
        ) : null}
      </div>
      {phase.kind === "proof" || phase.kind === "removing" ? (
        <ApprovalProofModal
          title="Remove Guard from all apps"
          detail={`Enter local approval proof. Guard hooks will be removed from: ${phase.plan.harnesses.map((item) => item.harness).join(", ")}.`}
          confirmLabel="Remove Guard"
          busy={phase.kind === "removing"}
          busyLabel="Removing…"
          approvalGate={phase.gate}
          error={phase.kind === "proof" ? phase.error : null}
          onCancel={handleCancel}
          onConfirm={handleConfirmClick}
        />
      ) : null}
    </div>
  );
}
