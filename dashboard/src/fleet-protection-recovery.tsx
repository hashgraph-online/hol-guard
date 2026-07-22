import { useCallback, useState } from "react";
import {
  HiMiniCheckCircle,
  HiMiniChevronDown,
  HiMiniExclamationCircle,
  HiMiniWrenchScrewdriver,
} from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import { harnessDisplayName } from "./approval-center-utils";
import type {
  GuardProtectionCheck,
  GuardProtectionHealth,
} from "./guard-types";

type GapAction = {
  label: string;
  detail: string;
};

type RepairState = { status: "working" | "success" | "error"; message: string };

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
    label: "Policy engine",
    detail: "Guard could not confirm the local policy engine is ready.",
  },
  rule_packs: {
    label: "Rule packs",
    detail: "Guard cannot confirm the active rule-pack proof yet.",
  },
  decision_plane_compatibility: {
    label: "Decision plane",
    detail:
      "Run a protected action to refresh decision-plane proof. Retry repair here if it remains unproven.",
  },
  containment_compatibility: {
    label: "Containment",
    detail:
      "Run a protected action to refresh containment proof. Retry repair here if it remains unproven.",
  },
  sandbox: {
    label: "Sandbox",
    detail:
      "Run a protected action to refresh sandbox proof. Retry repair here if it remains unproven.",
  },
  decision_stream: {
    label: "Command evidence",
    detail:
      "Run a protected command to create fresh evidence. Guard will recheck it here.",
  },
  tamper_checks: {
    label: "Integrity checks",
    detail: "Managed Guard files or hooks did not pass integrity checks.",
  },
};

function actionForCheck(
  check: GuardProtectionCheck,
  repairHarness?: string,
): GapAction {
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

function ProtectionGapItem({
  action,
  check,
}: {
  action: GapAction;
  check: GuardProtectionCheck;
}) {
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
            {check.status === "fail" ? "Failed" : "Unproven"}
          </span>
          <span className="mt-0.5 block">{action.detail}</span>
        </span>
      </div>
    </li>
  );
}

type FleetProtectionRecoveryProps = {
  health: GuardProtectionHealth;
  repairHarness?: string;
  repairHarnesses: string[];
  onRepairProtection: (harnesses: string[]) => Promise<string>;
};

function recoverySummary(failCount: number, unknownCount: number): string {
  if (failCount === 0) {
    return "Complete the remaining proof here. Guard repairs and rechecks every protection layer in one pass.";
  }
  const failedChecks = `${failCount} failed check${failCount === 1 ? "" : "s"}`;
  let remainingProofs = "";
  if (unknownCount > 0) {
    remainingProofs = `, then confirm the remaining ${unknownCount} proof${unknownCount === 1 ? "" : "s"}`;
  }
  return `Repair the ${failedChecks} here${remainingProofs}. Guard repairs and rechecks every protection layer in one pass.`;
}

function repairButtonLabel(repairState: RepairState | null): string {
  if (repairState?.status === "working") return "Repairing…";
  if (repairState?.status === "error") return "Retry repair";
  return "Repair protection";
}

export function FleetProtectionRecovery(props: FleetProtectionRecoveryProps) {
  const [repairState, setRepairState] = useState<RepairState | null>(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const gaps = props.health.checks.filter((check) => check.status !== "pass");
  const failCount = gaps.filter((check) => check.status === "fail").length;
  const unknownCount = gaps.length - failCount;

  const handleRepair = useCallback(async () => {
    setRepairState({
      status: "working",
      message: "Repairing app hooks, runtime, rule packs, and integrity…",
    });
    try {
      const message = await props.onRepairProtection(props.repairHarnesses);
      setRepairState({ status: "success", message });
      setDetailsOpen(true);
    } catch (error: unknown) {
      const message =
        error instanceof Error
          ? error.message
          : "Repair paused before every protection step completed. Retry to continue safely.";
      setRepairState({ status: "error", message });
      setDetailsOpen(true);
    }
  }, [props.onRepairProtection, props.repairHarnesses]);
  const handleRepairClick = useCallback(() => {
    void handleRepair();
  }, [handleRepair]);
  const handleDetailsToggle = useCallback(() => {
    setDetailsOpen((open) => !open);
  }, []);

  if (gaps.length === 0) return null;
  const working = repairState?.status === "working";

  return (
    <section
      id="protection-recovery"
      className="border-y border-brand-attention/20 bg-brand-attention/[0.04] px-4 py-4 sm:px-5"
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <HiMiniWrenchScrewdriver
              className="h-4 w-4 shrink-0 text-brand-attention"
              aria-hidden="true"
            />
            <h2 className="text-sm font-semibold text-brand-dark">
              Restore full protection
            </h2>
          </div>
          <p className="mt-1 text-sm text-slate-600">
            {recoverySummary(failCount, unknownCount)}
          </p>
        </div>
        <ActionButton onClick={handleRepairClick} disabled={working}>
          {repairButtonLabel(repairState)}
        </ActionButton>
      </div>
      {repairState ? (
        <p
          className={`mt-3 flex items-start gap-2 text-sm ${repairState.status === "error" ? "text-red-600" : "text-slate-600"}`}
          aria-live="polite"
        >
          {repairState.status === "success" ? (
            <HiMiniCheckCircle
              className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500"
              aria-hidden="true"
            />
          ) : null}
          {repairState.message}
        </p>
      ) : null}
      <button
        type="button"
        onClick={handleDetailsToggle}
        aria-expanded={detailsOpen}
        className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-brand-primary hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2"
      >
        View repair details
        <HiMiniChevronDown
          className={`h-4 w-4 transition-transform ${detailsOpen ? "rotate-180" : ""}`}
          aria-hidden="true"
        />
      </button>
      {detailsOpen ? (
        <ul className="mt-2 border-t border-brand-attention/10">
          {gaps.map((check) => (
            <ProtectionGapItem
              key={check.check_id}
              action={actionForCheck(check, props.repairHarness)}
              check={check}
            />
          ))}
        </ul>
      ) : null}
    </section>
  );
}
