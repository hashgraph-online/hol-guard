import { useCallback, useEffect, useState } from "react";
import {
  HiMiniArrowLeft,
  HiMiniArrowRight,
  HiMiniArrowPath,
  HiMiniCloud,
  HiMiniCloudArrowUp,
  HiMiniComputerDesktop,
  HiMiniExclamationTriangle,
  HiMiniInformationCircle,
  HiMiniShieldExclamation,
  HiMiniWrenchScrewdriver,
} from "react-icons/hi2";
import { ActionButton, Tag } from "./approval-center-primitives";
import type { SupplyChainWorkspaceHeroState } from "./supply-chain-workspace-hero-state";
import type { SupplyChainIssue, SupplyChainIssueAction } from "./supply-chain-issues";

type SupplyChainIssueFocusProps = {
  hero: SupplyChainWorkspaceHeroState;
  issues: SupplyChainIssue[];
  onIssueAction: (action: SupplyChainIssueAction) => void;
  actionPending?: boolean;
};

function issueSurfaceClass(tone: SupplyChainIssue["tone"]): string {
  if (tone === "blue") {
    return "border-brand-blue/20 bg-brand-blue/[0.04]";
  }
  if (tone === "attention") {
    return "border-brand-attention/20 bg-brand-attention/[0.04]";
  }
  return "border-slate-200 bg-slate-50/80";
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
    return "text-brand-attention";
  }
  return "text-slate-500";
}

function cloudTagTone(mode: SupplyChainWorkspaceHeroState["cloudMode"]): "green" | "blue" | "attention" {
  if (mode === "paired_active") {
    return "green";
  }
  if (mode === "paired_waiting") {
    return "blue";
  }
  return "attention";
}

export function SupplyChainIssueFocus({
  hero,
  issues,
  onIssueAction,
  actionPending = false,
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
  const titleClass = "text-brand-dark";
  const detailClass = "text-slate-600";

  return (
    <section
      className={`overflow-hidden rounded-2xl border shadow-sm ${issueSurfaceClass(issue.tone)}`}
      aria-label="Supply chain status"
      data-testid="supply-chain-issue-focus"
    >
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100/80 px-4 py-3 sm:px-5">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <Tag tone={cloudTagTone(hero.cloudMode)}>
            {hero.cloudMode === "local_only" ? (
              <HiMiniComputerDesktop className="mr-1 inline h-3.5 w-3.5" aria-hidden="true" />
            ) : (
              <HiMiniCloud className="mr-1 inline h-3.5 w-3.5" aria-hidden="true" />
            )}
            {hero.cloudLabel}
          </Tag>
          <span className="text-xs text-slate-500">{hero.statLine}</span>
        </div>
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
          {issues.length === 1 ? "Next step" : `Step ${activeIndex + 1} of ${issues.length}`}
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
