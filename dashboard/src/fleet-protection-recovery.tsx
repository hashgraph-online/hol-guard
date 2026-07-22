import { HiMiniExclamationCircle, HiMiniWrenchScrewdriver } from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import { harnessDisplayName } from "./approval-center-utils";
import type { GuardProtectionCheck, GuardProtectionHealth } from "./guard-types";

type GapAction = {
  label: string;
  detail: string;
  href: string;
  cta: string;
};

const PROTECTION_CHECK_ACTIONS: Record<string, GapAction> = {
  harness_hooks: {
    label: "App hooks",
    detail: "One or more app hooks need setup or repair.",
    href: "/settings?section=apps",
    cta: "Repair app hooks",
  },
  daemon: {
    label: "Local runtime",
    detail: "The local Guard runtime needs attention before protection can finish.",
    href: "/settings",
    cta: "Open settings",
  },
  policy_engine: {
    label: "Policy engine",
    detail: "Guard could not confirm the local policy engine is ready.",
    href: "/policy",
    cta: "Review policy",
  },
  rule_packs: {
    label: "Rule packs",
    detail: "Guard cannot confirm the active rule-pack proof yet.",
    href: "/policy",
    cta: "Open policy",
  },
  decision_plane_compatibility: {
    label: "Decision plane",
    detail: "Local decision-plane compatibility is unproven or failed.",
    href: "/settings",
    cta: "Open settings",
  },
  containment_compatibility: {
    label: "Containment",
    detail: "Containment compatibility is unproven or failed.",
    href: "/settings",
    cta: "Open settings",
  },
  sandbox: {
    label: "Sandbox",
    detail: "Sandbox enforcement could not be confirmed.",
    href: "/settings",
    cta: "Open settings",
  },
  decision_stream: {
    label: "Command evidence",
    detail: "Command activity evidence is incomplete or unavailable.",
    href: "/evidence?view=commands",
    cta: "Open command diagnostics",
  },
  tamper_checks: {
    label: "Integrity checks",
    detail: "Managed Guard files or hooks did not pass integrity checks.",
    href: "/settings?section=security",
    cta: "Repair integrity",
  },
};

function actionForCheck(check: GuardProtectionCheck, repairHarness?: string): GapAction {
  if (check.check_id === "harness_hooks" && repairHarness) {
    return {
      label: "App hooks",
      detail: `${harnessDisplayName(repairHarness)} hooks need setup or repair.`,
      href: `/apps/${repairHarness}?tab=settings`,
      cta: `Repair ${harnessDisplayName(repairHarness)}`,
    };
  }
  return (
    PROTECTION_CHECK_ACTIONS[check.check_id] ?? {
      label: check.check_id.replace(/_/g, " "),
      detail: "Guard could not confirm this protection proof.",
      href: "/settings",
      cta: "Open settings",
    }
  );
}

export function primaryProtectionRecoveryAction(
  health: GuardProtectionHealth,
  repairHarness?: string
): GapAction | null {
  const gaps = health.checks.filter((check) => check.status !== "pass");
  if (gaps.length === 0) return null;
  const ordered = [
    ...gaps.filter((check) => check.status === "fail"),
    ...gaps.filter((check) => check.status !== "fail"),
  ];
  const first = ordered[0];
  if (first === undefined) return null;
  return actionForCheck(first, repairHarness);
}

type FleetProtectionRecoveryProps = {
  health: GuardProtectionHealth;
  repairHarness?: string;
};

export function FleetProtectionRecovery(props: FleetProtectionRecoveryProps) {
  const gaps = props.health.checks.filter((check) => check.status !== "pass");
  if (gaps.length === 0) return null;

  const primary = primaryProtectionRecoveryAction(props.health, props.repairHarness);
  const failCount = gaps.filter((check) => check.status === "fail").length;
  const unknownCount = gaps.length - failCount;

  return (
    <section
      id="protection-recovery"
      className="border-y border-brand-attention/20 bg-brand-attention/[0.04] px-4 py-4 sm:px-5"
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <HiMiniWrenchScrewdriver className="h-4 w-4 shrink-0 text-brand-attention" aria-hidden="true" />
            <h2 className="text-sm font-semibold text-brand-dark">Restore full protection</h2>
          </div>
          <p className="mt-1 text-sm text-slate-600">
            {failCount > 0
              ? `Fix the ${failCount} failed check${failCount === 1 ? "" : "s"} below${
                  unknownCount > 0 ? `, then confirm the remaining ${unknownCount} proof${unknownCount === 1 ? "" : "s"}` : ""
                }. Each step opens the control that can clear it.`
              : "Complete the proofs below to reach full protection. Each step opens the control that can clear it."}
          </p>
        </div>
        {primary ? (
          <div className="flex shrink-0 flex-wrap gap-2">
            <ActionButton href={primary.href}>{primary.cta}</ActionButton>
          </div>
        ) : null}
      </div>
      <ul className="mt-4 grid gap-3 sm:grid-cols-2">
        {gaps.map((check) => {
          const action = actionForCheck(check, props.repairHarness);
          return (
            <li
              key={check.check_id}
              className="flex flex-col gap-2 rounded-xl border border-brand-attention/10 bg-white/70 px-3 py-3"
            >
              <div className="flex items-start gap-2 text-xs text-slate-600">
                <HiMiniExclamationCircle
                  className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${
                    check.status === "fail" ? "text-brand-attention" : "text-slate-400"
                  }`}
                  aria-hidden="true"
                />
                <span>
                  <strong className="font-semibold text-brand-dark">{action.label}</strong>
                  <span className="ml-1 text-[10px] font-medium uppercase tracking-wide text-slate-400">
                    {check.status === "fail" ? "Failed" : "Unproven"}
                  </span>
                  <span className="mt-0.5 block">{action.detail}</span>
                </span>
              </div>
              <div>
                <ActionButton href={action.href} variant="outline">
                  {action.cta}
                </ActionButton>
              </div>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
