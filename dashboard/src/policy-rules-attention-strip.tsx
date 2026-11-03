import { useMemo } from "react";
import { HiMiniExclamationTriangle } from "react-icons/hi2";
import type { GuardPolicyDecision } from "./guard-types";
import { resolvePolicyDisplay, resolvePolicyRowTitle } from "./policy-workspace-helpers";
import { widestBroadAllow } from "./policy-rules-hero-model";

/**
 * One quiet line for the widest rule in force — the only proactive nudge
 * on the page. Replaces the spotlight shelf: the same rule appears once
 * here and once in the list, not as a full duplicate card.
 */
export function PolicyRulesAttentionStrip(props: {
  broadAllows: GuardPolicyDecision[];
  onInspect: (policy: GuardPolicyDecision) => void;
}) {
  // Name the widest rule, not whichever broad allow happens to list first.
  const first = useMemo(() => widestBroadAllow(props.broadAllows), [props.broadAllows]);
  if (!first) return null;
  const display = resolvePolicyDisplay(first);
  const title = resolvePolicyRowTitle(first, display);
  const extra = props.broadAllows.length - 1;
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-xl border border-amber-200/80 bg-amber-50/60 px-3 py-2" role="status">
      <HiMiniExclamationTriangle className="h-4 w-4 shrink-0 text-amber-600" aria-hidden="true" />
      <p className="min-w-0 flex-1 text-sm text-slate-700">
        <span className="font-medium text-brand-dark">Broad allow:</span>{" "}
        <span className="font-medium">{title}</span> applies everywhere it matches
        {extra > 0 ? ` — and ${extra} more ${extra === 1 ? "does" : "do"} too.` : "."}
      </p>
      <button
        type="button"
        onClick={() => props.onInspect(first)}
        className="shrink-0 text-sm font-semibold text-brand-blue hover:underline"
        aria-label={`Inspect broad allow ${title}`}
      >
        Inspect
      </button>
    </div>
  );
}
