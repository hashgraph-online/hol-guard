import { useCallback, useState } from "react";
import {
  HiMiniCheckCircle,
  HiMiniChevronDown,
  HiMiniExclamationCircle,
} from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import { BrandHero, BrandHeroBadge, BrandHeroFacts } from "./brand-hero";
import type { SupplyChainFixAllState } from "./supply-chain-fix-all";
import {
  supplyChainFixAllButtonLabel,
  supplyChainFixAllIsPending,
  supplyChainFixAllNeedsCloudConnect,
} from "./supply-chain-fix-all";
import type { SupplyChainIssue } from "./supply-chain-issues";
import { setupStepsLabel } from "./supply-chain-workspace-hero-state";

type SupplyChainRecoveryProps = {
  issues: SupplyChainIssue[];
  state: SupplyChainFixAllState;
  onFixAll: () => void;
  guidance?: string | null;
  /** One-line facts under the summary, from the workspace hero state. */
  facts?: string[];
  /** Local package protection is on, so Cloud or audit steps alone are not a repair. */
  locallyProtected?: boolean;
};

const LOCAL_PROTECTION_ACTIONS = new Set<SupplyChainIssue["action"]["kind"]>(["firewall_unprotected", "firewall_repair"]);

function recoverySummary(issueCount: number, needsLocalRepair: boolean): string {
  if (!needsLocalRepair) {
    return `${issueCount} step${issueCount === 1 ? "" : "s"} left. Package protection is already on for this device.`;
  }
  return `${issueCount} issue${issueCount === 1 ? "" : "s"} to resolve. Check Cloud access, approve device changes once, then restore package protection.`;
}

export function SupplyChainRecovery({
  issues,
  state,
  onFixAll,
  guidance = null,
  facts = [],
  locallyProtected = false,
}: SupplyChainRecoveryProps) {
  const [detailsOpen, setDetailsOpen] = useState(false);
  const handleDetailsToggle = useCallback(() => {
    setDetailsOpen((open) => !open);
  }, []);
  const pending = supplyChainFixAllIsPending(state.phase);
  const showResult = state.message !== null;
  const remainingSteps = state.remainingSteps ?? [];
  const failures = [...new Set(state.failedSteps)].filter((message) => message !== state.message);
  const needsCloudConnect = supplyChainFixAllNeedsCloudConnect(state);
  const isHardFailure =
    state.phase === "error" || (state.phase === "incomplete" && state.failedSteps.length > 0);
  const needsLocalRepair =
    !locallyProtected || issues.some((issue) => LOCAL_PROTECTION_ACTIONS.has(issue.action.kind));
  const tone = needsLocalRepair ? "review" : "clear";
  const buttonLabel = supplyChainFixAllButtonLabel(
    state.phase,
    state.remainingAction ?? null,
    state.failedSteps.length,
  );

  return (
    <BrandHero
      tone={tone}
      liveLabel={setupStepsLabel(issues.length)}
      ariaLabel="Supply-chain recovery"
      testId="supply-chain-recovery"
      markOnSmall="inline"
      compact
    >
      <BrandHeroBadge tone={tone}>{needsLocalRepair ? "Needs repair" : "Protected on this device"}</BrandHeroBadge>
      <div className="max-w-2xl">
        <h2 className="guard-hero-title text-2xl font-semibold tracking-tight text-white sm:text-3xl">
          {needsLocalRepair ? "Restore supply-chain protection" : "Finish supply-chain setup"}
        </h2>
        <p className="mt-3 max-w-xl text-[15px] leading-relaxed text-white/80">
          {recoverySummary(issues.length, needsLocalRepair)}
        </p>
        {guidance ? (
          <p
            className="mt-2 max-w-xl text-sm font-medium text-white"
            data-testid="supply-chain-restart-guidance"
          >
            {guidance}
          </p>
        ) : null}
      </div>
      <div className="guard-hero-ctas flex flex-wrap gap-3">
        <ActionButton onClick={onFixAll} disabled={pending} aria-busy={pending} data-primary="true">
          {buttonLabel}
        </ActionButton>
      </div>

      <div className={showResult ? undefined : "!mt-0"} aria-live="polite">
        {showResult ? (
          <>
            <p
              className={`flex items-start gap-2 text-sm ${
                isHardFailure ? "text-[#fecaca]" : "text-white/80"
              }`}
            >
              {state.phase === "success" || needsCloudConnect ? (
                <HiMiniCheckCircle
                  className="mt-0.5 h-4 w-4 shrink-0 text-brand-green"
                  aria-hidden="true"
                />
              ) : null}
              {state.message}
            </p>
            {failures.length > 0 ? (
              <ul className="mt-2 space-y-1 text-xs text-[#fecaca]">
                {failures.map((failure, index) => (
                  <li key={`failed:${index}:${failure}`}>{failure}</li>
                ))}
              </ul>
            ) : null}
            {state.phase === "access_required" ? (
              <a className="mt-2 inline-block text-sm font-medium text-white underline underline-offset-4 focus-visible:outline focus-visible:outline-2 focus-visible:outline-white" href="https://hol.org/guard/pricing" target="_blank" rel="noopener noreferrer">
                Review Cloud plan
              </a>
            ) : null}
            {remainingSteps.length > 0 ? (
              <ul className="mt-2 space-y-1 text-xs font-medium text-white">
                {remainingSteps.map((remaining, index) => (
                  <li key={`remaining:${index}:${remaining}`}>{remaining}</li>
                ))}
              </ul>
            ) : null}
          </>
        ) : null}
      </div>

      <BrandHeroFacts facts={facts} />
      <button
        type="button"
        onClick={handleDetailsToggle}
        aria-expanded={detailsOpen}
        className="-ml-1 inline-flex min-h-11 items-center gap-1 rounded-md px-1 text-sm font-medium text-white/85 hover:text-white hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-white"
      >
        View issue details
        <HiMiniChevronDown
          className={`h-4 w-4 transition-transform ${detailsOpen ? "rotate-180" : ""}`}
          aria-hidden="true"
        />
      </button>
      {detailsOpen ? (
        <ul className="!mt-2 rounded-xl border border-white/15 bg-white/[0.06] px-3">
          {issues.map((issue) => (
            <li
              key={issue.id}
              className="flex items-start gap-2 border-t border-white/10 py-3 first:border-t-0"
            >
              <HiMiniExclamationCircle
                className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[#ffd58a]"
                aria-hidden="true"
              />
              <span className="text-sm text-white/80">
                <strong className="block font-semibold text-white">{issue.title}</strong>
                {issue.detail}
              </span>
            </li>
          ))}
        </ul>
      ) : null}
    </BrandHero>
  );
}
