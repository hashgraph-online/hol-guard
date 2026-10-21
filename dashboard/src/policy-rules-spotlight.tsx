import { HiMiniArrowTopRightOnSquare, HiMiniCheckCircle, HiMiniNoSymbol } from "react-icons/hi2";
import { formatRelativeTime, harnessDisplayName, scopeLabel } from "./approval-center-utils";
import type { GuardPolicyDecision } from "./guard-types";
import { isCloudManagedPolicy, resolvePolicyDisplay, resolvePolicyRowTitle } from "./policy-workspace-helpers";
import { resolvePolicyRowSourceLabel } from "./policy-managed-authority";
import { policySelectionKey } from "./policy-rules-overview-model";
import { isBroadAllow } from "./policy-rules-hero-model";

function spotlightReason(policy: GuardPolicyDecision): string {
  if (isBroadAllow(policy)) {
    return policy.scope === "global"
      ? "Allows this everywhere on this device"
      : `Allows this every time ${harnessDisplayName(policy.harness)} runs it`;
  }
  if (isCloudManagedPolicy(policy.source)) return "Synced from Guard Cloud — read-only here";
  return "Most recently remembered on this device";
}

export function PolicyRulesSpotlight(props: {
  policies: GuardPolicyDecision[];
  onInspect: (policy: GuardPolicyDecision) => void;
}) {
  if (props.policies.length === 0) return null;
  return (
    <section aria-labelledby="rules-spotlight-heading" className="space-y-3">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h2 id="rules-spotlight-heading" className="text-base font-semibold text-brand-dark">Worth a second look</h2>
        <p className="text-sm text-slate-500">The widest-reaching rules Guard is repeating right now.</p>
      </div>
      <div className="guard-spotlight-grid">
        {props.policies.map((policy) => {
          const display = resolvePolicyDisplay(policy);
          const title = resolvePolicyRowTitle(policy, display);
          const allowed = policy.action === "allow";
          return (
            <article key={policySelectionKey(policy)} className="guard-spotlight-card">
              <div className="flex items-start justify-between gap-3">
                <span
                  className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-semibold ${
                    allowed
                      ? "border-emerald-300 bg-emerald-50 text-emerald-800"
                      : "border-rose-300 bg-rose-50 text-rose-800"
                  }`}
                >
                  {allowed ? <HiMiniCheckCircle className="h-3.5 w-3.5" aria-hidden="true" /> : <HiMiniNoSymbol className="h-3.5 w-3.5" aria-hidden="true" />}
                  {allowed ? "Allow" : "Block"}
                </span>
                <span className="guard-state-pill" data-tone={isCloudManagedPolicy(policy.source) ? "info" : undefined}>
                  <span className="guard-state-pill-dot" aria-hidden="true" />
                  {resolvePolicyRowSourceLabel(policy)}
                </span>
              </div>
              <div className="min-w-0">
                <h3 className="truncate text-[15px] font-semibold leading-snug text-brand-dark" title={title}>{title}</h3>
                <p className="mt-1 text-sm leading-relaxed text-slate-600">{display.rememberSentence}</p>
              </div>
              <div className="mt-auto flex flex-wrap items-center justify-between gap-2">
                <p className="text-xs text-slate-500">
                  {spotlightReason(policy)} · {scopeLabel(policy.scope, "policy")}
                  {policy.updated_at ? ` · ${formatRelativeTime(policy.updated_at)}` : ""}
                </p>
                <button
                  type="button"
                  onClick={() => props.onInspect(policy)}
                  className="guard-discover-cta guard-discover-cta-quiet"
                  aria-label={`Inspect rule ${title}`}
                >
                  Inspect
                  <HiMiniArrowTopRightOnSquare className="h-4 w-4" aria-hidden="true" />
                </button>
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}
