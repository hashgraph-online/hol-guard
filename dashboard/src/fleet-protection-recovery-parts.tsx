import { useCallback } from "react";
import { HiMiniExclamationCircle } from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import { harnessDisplayName } from "./approval-center-utils";
import type { GuardProtectionCheck } from "./guard-types";
import { isUnsupportedPlatformCheck } from "./protection-health";
import { protectionReasonText } from "./protection-reason-copy";
import {
  RUNTIME_START_COMMAND,
  RUNTIME_STOP_COMMAND,
  STALLED_RECHECK_SUMMARY,
  STALLED_REPAIR_SUMMARY,
} from "./fleet-protection-recovery-copy";
import {
  RECHECK_UNAVAILABLE_SIGNATURE,
} from "./protection-repair-flow";
import type { ProtectionRepairOutcomeTracker } from "./protection-repair-flow";

const INLINE_COMMAND_CLASS =
  "rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[11px]";

export type GapAction = {
  label: string;
  detail: string;
};

const PROTECTION_CHECK_ACTIONS: Record<string, GapAction> = {
  harness_hooks: {
    label: "App hooks",
    detail: "One or more app hooks need setup or repair.",
  },
  daemon: {
    label: "Local runtime",
    detail:
      "The local Guard runtime needs attention before protection can finish.",
  },
  policy_engine: {
    label: "Local policy engine",
    detail: "Guard could not confirm the local policy engine is ready.",
  },
  rule_packs: {
    label: "Local rule packs",
    detail: "Guard cannot confirm the active local rule-pack proof yet.",
  },
  decision_plane_compatibility: {
    label: "Decision plane",
    detail:
      "Guard reruns the decision-plane compatibility probe during repair. Retry here if it remains unproven.",
  },
  containment_compatibility: {
    label: "Containment",
    detail:
      "Guard reruns the containment compatibility probe during repair. Retry here if it remains unproven.",
  },
  sandbox: {
    label: "Sandbox",
    detail:
      "Guard reruns the sandbox enforcement probe during repair. Retry here if it remains unproven.",
  },
  decision_stream: {
    label: "Command evidence",
    detail:
      "Guard attempts evidence-store recovery during repair. Run a protected command only if fresh proof is still needed.",
  },
  tamper_checks: {
    label: "Local integrity checks",
    detail: "Managed Guard files or hooks did not pass integrity checks.",
  },
};

export function actionForCheck(
  check: GuardProtectionCheck,
  repairHarness?: string,
): GapAction {
  if (isUnsupportedPlatformCheck(check)) {
    return {
      label: "Unsupported on this platform",
      detail:
        "Containment controls are unavailable on this platform. Guard remains fail-closed; no repair is available.",
    };
  }
  if (check.check_id === "harness_hooks" && repairHarness) {
    return {
      label: "App hooks",
      detail: `${harnessDisplayName(repairHarness)} hooks need setup or repair.`,
    };
  }
  const action = PROTECTION_CHECK_ACTIONS[check.check_id];
  return action
    ? action
    : {
        label: check.check_id.replace(/_/g, " "),
        detail: "Guard could not confirm this protection proof.",
      };
}

function ProtectionGapReason({ check }: { check: GuardProtectionCheck }) {
  const reasonText = protectionReasonText(check.reason_code);
  if (reasonText === null) {
    return (
      <span className="mt-0.5 block font-mono text-[10px] text-slate-400">
        Reason code: {check.reason_code}
      </span>
    );
  }
  return <span className="mt-0.5 block text-slate-500">{reasonText}</span>;
}

export function ProtectionGapItem({
  action,
  check,
}: {
  action: GapAction;
  check: GuardProtectionCheck;
}) {
  const unsupported = isUnsupportedPlatformCheck(check);
  let statusLabel = "Unproven";
  if (unsupported) {
    statusLabel = "Unsupported";
  } else if (check.status === "fail") {
    statusLabel = "Failed";
  }
  return (
    <li className="flex items-start gap-2 border-t border-brand-attention/10 py-3 first:border-t-0">
      <div className="flex items-start gap-2 text-xs text-slate-600">
        <HiMiniExclamationCircle
          className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${check.status === "fail" ? "text-brand-attention" : "text-slate-400"}`}
          aria-hidden="true"
        />
        <span>
          <strong className="font-semibold text-brand-dark">
            {action.label}
          </strong>
          <span className="ml-1 text-[10px] font-medium uppercase tracking-wide text-slate-400">
            {statusLabel}
          </span>
          <span className="mt-0.5 block">{action.detail}</span>
          <ProtectionGapReason check={check} />
        </span>
      </div>
    </li>
  );
}

export function StalledRepairPanel({
  tracker,
  repairableGaps,
  repairHarness,
}: {
  tracker: ProtectionRepairOutcomeTracker | null;
  repairableGaps: GuardProtectionCheck[];
  repairHarness?: string;
}) {
  return (
    <div className="mt-3 text-sm text-slate-600" aria-live="polite" role="status">
      <p className="font-medium text-brand-dark">
        {tracker?.signature === RECHECK_UNAVAILABLE_SIGNATURE
          ? STALLED_RECHECK_SUMMARY
          : STALLED_REPAIR_SUMMARY}
      </p>
      <ul className="mt-1 list-disc space-y-0.5 pl-4">
        {repairableGaps.map((check) => (
          <li key={check.check_id}>
            {actionForCheck(check, repairHarness).label}
            {" — "}
            {protectionReasonText(check.reason_code) ?? (
              <code className="font-mono text-[11px]">Reason code: {check.reason_code}</code>
            )}
          </li>
        ))}
      </ul>
      <p className="mt-2">
        Quit and reopen HOL Guard to restart the local runtime. Without the desktop app, run{" "}
        <code className={INLINE_COMMAND_CLASS}>{RUNTIME_STOP_COMMAND}</code>, then{" "}
        <code className={INLINE_COMMAND_CLASS}>{RUNTIME_START_COMMAND}</code>.
      </p>
    </div>
  );
}

export function TargetedRepairButton({
  harness,
  onRepair,
}: {
  harness: string;
  onRepair: (harness: string) => void;
}) {
  const handleRepair = useCallback(() => onRepair(harness), [harness, onRepair]);
  return (
    <ActionButton onClick={handleRepair} variant="outline">
      Open {harnessDisplayName(harness)} repair
    </ActionButton>
  );
}
