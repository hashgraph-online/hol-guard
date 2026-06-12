import { useCallback, useEffect, useState } from "react";
import {
  HiMiniArrowLeft,
  HiMiniArrowRight,
  HiMiniArrowPath,
  HiMiniCloudArrowUp,
  HiMiniExclamationTriangle,
  HiMiniInformationCircle,
  HiMiniShieldExclamation,
  HiMiniWrenchScrewdriver,
} from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import type { SupplyChainIssue, SupplyChainIssueAction } from "./supply-chain-issues";

type SupplyChainIssueFocusProps = {
  issues: SupplyChainIssue[];
  onIssueAction: (action: SupplyChainIssueAction) => void;
  actionPending?: boolean;
  tagline?: React.ReactNode;
};

function issueSurfaceClass(tone: SupplyChainIssue["tone"]): string {
  if (tone === "blue") {
    return "border-brand-blue/25 bg-gradient-to-b from-brand-blue/[0.07] to-white";
  }
  if (tone === "attention") {
    return "border-amber-200/90 bg-gradient-to-b from-amber-50/90 to-white";
  }
  return "border-slate-200 bg-gradient-to-b from-slate-50/90 to-white";
}

function issueIcon(issue: SupplyChainIssue) {
  if (issue.id.startsWith("cloud")) {
    return HiMiniCloudArrowUp;
  }
  if (issue.id.startsWith("path")) {
    return issue.tone === "blue" ? HiMiniInformationCircle : HiMiniWrenchScrewdriver;
  }
  if (issue.id === "stale_intel") {
    return HiMiniArrowPath;
  }
  if (issue.id.includes("protection") || issue.id.includes("unprotected")) {
    return HiMiniShieldExclamation;
  }
  return HiMiniExclamationTriangle;
}

function issueIconClass(tone: SupplyChainIssue["tone"]): string {
  if (tone === "blue") {
    return "text-brand-blue";
  }
  if (tone === "attention") {
    return "text-amber-600";
  }
  return "text-slate-500";
}

export function SupplyChainIssueFocus({
  issues,
  onIssueAction,
  actionPending = false,
  tagline,
}: SupplyChainIssueFocusProps) {
  const [activeIndex, setActiveIndex] = useState(0);

  useEffect(() => {
    if (activeIndex >= issues.length) {
      setActiveIndex(Math.max(0, issues.length - 1));
    }
  }, [activeIndex, issues.length]);

  const goPrevious = useCallback(() => {
    setActiveIndex((index) => (index <= 0 ? issues.length - 1 : index - 1));
  }, [issues.length]);

  const goNext = useCallback(() => {
    setActiveIndex((index) => (index >= issues.length - 1 ? 0 : index + 1));
  }, [issues.length]);

  if (issues.length === 0) {
    return null;
  }

  const issue = issues[activeIndex] ?? issues[0];
  const Icon = issueIcon(issue);
  const titleClass = issue.tone === "attention" ? "text-amber-950" : "text-brand-dark";
  const detailClass = issue.tone === "attention" ? "text-amber-900/85" : "text-slate-600";

  return (
    <section
      className={`overflow-hidden rounded-2xl border shadow-sm ${issueSurfaceClass(issue.tone)}`}
      aria-label="Supply chain next steps"
      data-testid="supply-chain-issue-focus"
    >
      <div className="flex items-center justify-between gap-3 border-b border-black/[0.04] px-4 py-3 sm:px-5">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
          {issues.length === 1 ? "Next step" : `Next step ${activeIndex + 1} of ${issues.length}`}
        </p>
        {issues.length > 1 ? (
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={goPrevious}
              className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200/80 bg-white/80 text-slate-600 transition-colors hover:bg-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue"
              aria-label="Previous issue"
            >
              <HiMiniArrowLeft className="h-4 w-4" aria-hidden="true" />
            </button>
            <button
              type="button"
              onClick={goNext}
              className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200/80 bg-white/80 text-slate-600 transition-colors hover:bg-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue"
              aria-label="Next issue"
            >
              <HiMiniArrowRight className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
        ) : null}
      </div>

      {tagline ? (
        <div className="border-b border-black/[0.04] px-4 py-2.5 sm:px-5 bg-white/60">
          {tagline}
        </div>
      ) : null}

      <div className="px-4 py-5 sm:px-6 sm:py-6">
        <div className="flex items-start gap-3">
          <span
            className={`inline-flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-white/90 ring-1 ring-black/[0.05] ${issueIconClass(issue.tone)}`}
            aria-hidden="true"
          >
            <Icon className="h-5 w-5" />
          </span>
          <div className="min-w-0 flex-1">
            <h2 className={`text-lg font-semibold tracking-tight sm:text-xl ${titleClass}`}>
              {issue.title}
            </h2>
            <p className={`mt-2 max-w-2xl text-sm leading-relaxed ${detailClass}`}>{issue.detail}</p>
          </div>
        </div>

        <div className="mt-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <ActionButton
            variant="primary"
            onClick={() => onIssueAction(issue.action)}
            disabled={actionPending}
            aria-busy={actionPending}
          >
            {issue.actionLabel}
          </ActionButton>
          {issues.length > 1 ? (
            <div className="flex items-center gap-2" role="tablist" aria-label="Issue progress">
              {issues.map((entry, index) => (
                <button
                  key={entry.id}
                  type="button"
                  role="tab"
                  aria-selected={index === activeIndex}
                  aria-label={`Issue ${index + 1}: ${entry.title}`}
                  onClick={() => setActiveIndex(index)}
                  className={[
                    "h-2.5 rounded-full transition-all",
                    index === activeIndex ? "w-7 bg-brand-blue" : "w-2.5 bg-slate-300/80",
                  ].join(" ")}
                />
              ))}
            </div>
          ) : null}
        </div>
      </div>
    </section>
  );
}
