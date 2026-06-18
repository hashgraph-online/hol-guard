import { HiMiniShieldCheck } from "react-icons/hi2";
import { SectionLabel } from "./approval-center-primitives";
import type { GuardRuntimeSnapshot } from "./guard-types";
import { POLICY_SUMMARY_CARD_CLASS } from "./policy-summary-surfaces";
import { resolveSecurityModeCopy } from "./policy-workspace-helpers";

type PolicyActiveModeCardProps = {
  snapshot: GuardRuntimeSnapshot;
};

export function PolicyActiveModeCard({ snapshot }: PolicyActiveModeCardProps) {
  const modeCopy = resolveSecurityModeCopy(snapshot.security_level);

  return (
    <div className={`${POLICY_SUMMARY_CARD_CLASS} self-start p-4`}>
      <SectionLabel>Active mode</SectionLabel>
      <div className="mt-2 flex items-start gap-2.5">
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue">
          <HiMiniShieldCheck className="h-4 w-4" aria-hidden="true" />
        </span>
        <div className="min-w-0">
          <p className="text-sm font-semibold text-brand-dark">{modeCopy.label}</p>
          <p className="mt-0.5 line-clamp-3 text-sm leading-snug text-slate-600">{modeCopy.description}</p>
        </div>
      </div>
    </div>
  );
}
