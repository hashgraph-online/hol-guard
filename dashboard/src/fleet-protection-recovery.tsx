import { HiMiniExclamationCircle, HiMiniWrenchScrewdriver } from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import { harnessDisplayName } from "./approval-center-utils";
import type { GuardProtectionHealth } from "./guard-types";

const PROTECTION_CHECK_COPY: Record<string, { label: string; detail: string }> = {
  harness_hooks: { label: "App hooks", detail: "One or more app hooks need setup or repair." },
  rule_packs: { label: "Rule packs", detail: "Guard cannot confirm the active rule-pack proof yet." },
  decision_stream: { label: "Command evidence", detail: "Command activity evidence is incomplete or unavailable." },
  tamper_checks: { label: "Integrity checks", detail: "Managed Guard files or hooks did not pass integrity checks." },
};

type FleetProtectionRecoveryProps = {
  health: GuardProtectionHealth;
  repairHarness?: string;
};

export function FleetProtectionRecovery(props: FleetProtectionRecoveryProps) {
  const gaps = props.health.checks.filter((check) => check.status !== "pass");
  const hasCommandEvidenceGap = gaps.some((check) => check.check_id === "decision_stream");
  if (gaps.length === 0) return null;

  return (
    <section className="border-y border-brand-attention/20 bg-brand-attention/[0.04] px-4 py-4 sm:px-5">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <HiMiniWrenchScrewdriver className="h-4 w-4 shrink-0 text-brand-attention" aria-hidden="true" />
            <h2 className="text-sm font-semibold text-brand-dark">Protection needs attention</h2>
          </div>
          <p className="mt-1 text-sm text-slate-600">
            {props.repairHarness
              ? `${harnessDisplayName(props.repairHarness)} needs repair. Complete that step, then return here to confirm the remaining proofs.`
              : "Review the incomplete proofs below, then return here to confirm protection."}
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">
          {props.repairHarness ? (
            <ActionButton href={`/apps/${props.repairHarness}?tab=settings`}>
              Repair {harnessDisplayName(props.repairHarness)}
            </ActionButton>
          ) : null}
          {hasCommandEvidenceGap ? (
            <ActionButton href="/evidence?view=commands" variant="outline">
              Open command diagnostics
            </ActionButton>
          ) : null}
        </div>
      </div>
      <ul className="mt-4 grid gap-x-5 gap-y-2 sm:grid-cols-2">
        {gaps.map((check) => {
          const copy = PROTECTION_CHECK_COPY[check.check_id] ?? {
            label: check.check_id.replace(/_/g, " "),
            detail: "Guard could not confirm this protection proof.",
          };
          return (
            <li key={check.check_id} className="flex items-start gap-2 text-xs text-slate-600">
              <HiMiniExclamationCircle
                className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${check.status === "fail" ? "text-brand-attention" : "text-slate-400"}`}
                aria-hidden="true"
              />
              <span>
                <strong className="font-semibold text-brand-dark">{copy.label}</strong>: {copy.detail}
              </span>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
