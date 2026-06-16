import { HiMiniShieldCheck } from "react-icons/hi2";
import { SectionLabel } from "./approval-center-primitives";
import type { GuardRuntimeSnapshot } from "./guard-types";
import { resolveSecurityModeCopy } from "./policy-workspace-helpers";

type PolicyActiveModeCardProps = {
  snapshot: GuardRuntimeSnapshot;
};

export function PolicyActiveModeCard({ snapshot }: PolicyActiveModeCardProps) {
  const modeCopy = resolveSecurityModeCopy(snapshot.security_level);

  return (
    <div className="rounded-2xl border border-slate-200/70 bg-white p-4 shadow-sm">
      <SectionLabel>Active mode</SectionLabel>
      <div className="mt-3 flex items-start gap-3">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue">
          <HiMiniShieldCheck className="h-5 w-5" aria-hidden="true" />
        </span>
        <div className="min-w-0">
          <p className="text-sm font-semibold text-brand-dark">{modeCopy.label}</p>
          <p className="mt-1 text-sm leading-relaxed text-slate-600">{modeCopy.description}</p>
        </div>
      </div>
    </div>
  );
}
