import { useCallback, useState } from "react";
import {
  HiMiniCheckCircle,
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
  checkId: string;
  label: string;
  detail: string;
  fallbackHref: string;
  cta: string;
  repairable: boolean;
};

type RepairState = { status: "working" | "success" | "error"; message: string };

const PROTECTION_CHECK_ACTIONS: Record<string, Omit<GapAction, "checkId">> = {
  harness_hooks: {
    label: "App hooks",
    detail: "One or more app hooks need setup or repair.",
    fallbackHref: "/settings?section=apps",
    cta: "Repair app hooks",
    repairable: true,
  },
  daemon: {
    label: "Local runtime",
    detail:
      "The local Guard runtime needs attention before protection can finish.",
    fallbackHref: "/settings",
    cta: "Repair local runtime",
    repairable: true,
  },
  policy_engine: {
    label: "Policy engine",
    detail: "Guard could not confirm the local policy engine is ready.",
    fallbackHref: "/policy",
    cta: "Repair policy engine",
    repairable: true,
  },
  rule_packs: {
    label: "Rule packs",
    detail: "Guard cannot confirm the active rule-pack proof yet.",
    fallbackHref: "/policy",
    cta: "Repair rule packs",
    repairable: true,
  },
  decision_plane_compatibility: {
    label: "Decision plane",
    detail: "Local decision-plane compatibility is unproven or failed.",
    fallbackHref: "/settings",
    cta: "Open diagnostics",
    repairable: false,
  },
  containment_compatibility: {
    label: "Containment",
    detail: "Containment compatibility is unproven or failed.",
    fallbackHref: "/settings",
    cta: "Open diagnostics",
    repairable: false,
  },
  sandbox: {
    label: "Sandbox",
    detail: "Sandbox enforcement could not be confirmed.",
    fallbackHref: "/settings",
    cta: "Open diagnostics",
    repairable: false,
  },
  decision_stream: {
    label: "Command evidence",
    detail: "Command activity evidence is incomplete or unavailable.",
    fallbackHref: "/evidence?view=commands",
    cta: "Check command evidence",
    repairable: true,
  },
  tamper_checks: {
    label: "Integrity checks",
    detail: "Managed Guard files or hooks did not pass integrity checks.",
    fallbackHref: "/settings?section=security",
    cta: "Repair integrity",
    repairable: true,
  },
};

function actionForCheck(
  check: GuardProtectionCheck,
  repairHarness?: string,
): GapAction {
  if (check.check_id === "harness_hooks" && repairHarness) {
    return {
      checkId: check.check_id,
      label: "App hooks",
      detail: `${harnessDisplayName(repairHarness)} hooks need setup or repair.`,
      fallbackHref: `/apps/${repairHarness}?tab=settings`,
      cta: `Repair ${harnessDisplayName(repairHarness)}`,
      repairable: true,
    };
  }
  const action = PROTECTION_CHECK_ACTIONS[check.check_id];
  return action
    ? { checkId: check.check_id, ...action }
    : {
        checkId: check.check_id,
        label: check.check_id.replace(/_/g, " "),
        detail: "Guard could not confirm this protection proof.",
        fallbackHref: "/settings",
        cta: "Open diagnostics",
        repairable: false,
      };
}

export function primaryProtectionRecoveryAction(
  health: GuardProtectionHealth,
  repairHarness?: string,
): GapAction | null {
  const gaps = health.checks.filter((check) => check.status !== "pass");
  const ordered = [
    ...gaps.filter((check) => check.status === "fail"),
    ...gaps.filter((check) => check.status !== "fail"),
  ];
  const first = ordered[0];
  return first ? actionForCheck(first, repairHarness) : null;
}

type ProtectionGapItemProps = {
  action: GapAction;
  check: GuardProtectionCheck;
  repairState?: RepairState;
  onRepair: (checkId: string) => Promise<void>;
};

function ProtectionGapItem({
  action,
  check,
  repairState,
  onRepair,
}: ProtectionGapItemProps) {
  const handleRepair = useCallback(() => {
    void onRepair(check.check_id);
  }, [check.check_id, onRepair]);
  const working = repairState?.status === "working";

  return (
    <li className="flex flex-col gap-2 rounded-xl border border-brand-attention/10 bg-white/70 px-3 py-3">
      <div className="flex items-start gap-2 text-xs text-slate-600">
        {repairState?.status === "success" ? (
          <HiMiniCheckCircle
            className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-500"
            aria-hidden="true"
          />
        ) : (
          <HiMiniExclamationCircle
            className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${check.status === "fail" ? "text-brand-attention" : "text-slate-400"}`}
            aria-hidden="true"
          />
        )}
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
      <div className="flex flex-wrap items-center gap-2">
        {action.repairable ? (
          <ActionButton
            onClick={handleRepair}
            disabled={working}
            variant="outline"
          >
            {working ? "Repairing…" : action.cta}
          </ActionButton>
        ) : (
          <ActionButton href={action.fallbackHref} variant="outline">
            {action.cta}
          </ActionButton>
        )}
        {repairState?.status === "error" ? (
          <ActionButton href={action.fallbackHref} variant="ghost">
            Open diagnostics
          </ActionButton>
        ) : null}
      </div>
      {repairState ? (
        <p
          className={`text-xs ${repairState.status === "error" ? "text-red-600" : "text-slate-500"}`}
          aria-live="polite"
        >
          {repairState.message}
        </p>
      ) : null}
    </li>
  );
}

type FleetProtectionRecoveryProps = {
  health: GuardProtectionHealth;
  repairHarness?: string;
  repairHarnesses: string[];
  onRepairProtectionCheck: (
    checkId: string,
    harnesses: string[],
  ) => Promise<string>;
};

function recoverySummary(failCount: number, unknownCount: number): string {
  if (failCount === 0) {
    return "Complete the remaining proof here. Guard rechecks protection after each step.";
  }
  const failedChecks = `${failCount} failed check${failCount === 1 ? "" : "s"}`;
  let remainingProofs = "";
  if (unknownCount > 0) {
    remainingProofs = `, then confirm the remaining ${unknownCount} proof${unknownCount === 1 ? "" : "s"}`;
  }
  return `Repair the ${failedChecks} here${remainingProofs}. Guard rechecks protection after each step.`;
}

export function FleetProtectionRecovery(props: FleetProtectionRecoveryProps) {
  const [repairStates, setRepairStates] = useState<Record<string, RepairState>>(
    {},
  );
  const gaps = props.health.checks.filter((check) => check.status !== "pass");
  const failCount = gaps.filter((check) => check.status === "fail").length;
  const unknownCount = gaps.length - failCount;

  const handleRepair = useCallback(
    async (checkId: string) => {
      setRepairStates((current) => ({
        ...current,
        [checkId]: { status: "working", message: "Repairing now…" },
      }));
      try {
        const message = await props.onRepairProtectionCheck(
          checkId,
          props.repairHarnesses,
        );
        setRepairStates((current) => ({
          ...current,
          [checkId]: { status: "success", message },
        }));
      } catch (error: unknown) {
        const message =
          error instanceof Error
            ? error.message
            : "Guard could not complete this repair.";
        setRepairStates((current) => ({
          ...current,
          [checkId]: { status: "error", message },
        }));
      }
    },
    [props.onRepairProtectionCheck, props.repairHarnesses],
  );

  const handleRepairAll = useCallback(async () => {
    const repairedGroups = new Set<string>();
    for (const check of gaps) {
      if (!actionForCheck(check, props.repairHarness).repairable) continue;
      const group =
        check.check_id === "rule_packs" ||
        check.check_id === "tamper_checks" ||
        check.check_id === "policy_engine"
          ? "integrity"
          : check.check_id;
      if (repairedGroups.has(group)) continue;
      repairedGroups.add(group);
      await handleRepair(check.check_id);
    }
  }, [gaps, handleRepair]);
  const handleRepairAllClick = useCallback(() => {
    void handleRepairAll();
  }, [handleRepairAll]);

  if (gaps.length === 0) return null;
  const anyWorking = Object.values(repairStates).some(
    (state) => state.status === "working",
  );

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
        <ActionButton onClick={handleRepairAllClick} disabled={anyWorking}>
          {anyWorking ? "Repairing…" : "Repair failed checks"}
        </ActionButton>
      </div>
      <ul className="mt-4 grid gap-3 sm:grid-cols-2">
        {gaps.map((check) => (
          <ProtectionGapItem
            key={check.check_id}
            action={actionForCheck(check, props.repairHarness)}
            check={check}
            repairState={repairStates[check.check_id]}
            onRepair={handleRepair}
          />
        ))}
      </ul>
    </section>
  );
}
