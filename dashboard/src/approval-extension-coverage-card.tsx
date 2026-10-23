import { useCallback } from "react";
import { HiMiniAdjustmentsHorizontal, HiMiniArrowTopRightOnSquare } from "react-icons/hi2";
import { coverageScopeLine, coverageStepLabel } from "./approval-extension-coverage";
import type { GuardApprovalExtensionCoverage, GuardCoveredSegment } from "./approval-extension-coverage-types";
import { commitDashboardLocation } from "./dashboard-location";
import { extensionPatternHref } from "./extension-pattern-href";

function segmentDetail(segment: GuardCoveredSegment): string | null {
  const titles = segment.rules.map((rule) => rule.title);
  const labels = segment.permissions.filter((permission) => permission.configurable).map((item) => item.label);
  const parts = titles.length > 0 ? titles : labels;
  return parts.length > 0 ? parts.join(" · ") : null;
}

/** Names the extension behind each step of a paused command, and links to it.
 *
 * This card never changes a setting and never approves anything. It exists
 * because most paused commands cannot be settled by flipping a few permissions
 * — so they get no recommendation — and the person reviewing still has no way
 * to find out that an extension governs the command at all.
 */
export function ApprovalExtensionCoverageCard(props: {
  coverage: GuardApprovalExtensionCoverage | undefined;
  /** True when the recommendation card above already offers an allow. */
  hasRecommendation: boolean;
}) {
  const { coverage, hasRecommendation } = props;
  const open = useCallback((extensionId: string, ruleId: string | null) => {
    commitDashboardLocation(extensionPatternHref(extensionId, ruleId));
  }, []);
  if (!coverage) return null;
  const scopeLine = coverageScopeLine(coverage);

  return (
    <section
      className="mt-5 rounded-xl border border-slate-200 bg-slate-50/70 p-4"
      aria-labelledby="approval-extension-coverage-title"
      data-testid="approval-extension-coverage"
    >
      <div className="flex items-start gap-3">
        <HiMiniAdjustmentsHorizontal className="mt-0.5 h-5 w-5 shrink-0 text-slate-500" aria-hidden="true" />
        <div className="min-w-0 flex-1">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Set this up in advance</p>
          <h3 id="approval-extension-coverage-title" className="mt-1 text-sm font-semibold text-brand-dark">
            {hasRecommendation ? "Where this command is configured" : "Extensions cover this command"}
          </h3>
          <p className="mt-1 text-sm leading-relaxed text-brand-dark/80">
            Decide ahead of time how commands like these are handled, so the ones you trust stop coming here.
          </p>
          <ul className="mt-3 space-y-2" aria-label="Steps an extension covers">
            {coverage.segments.map((segment) => {
              const detail = segmentDetail(segment);
              return (
                <li key={segment.index} className="flex flex-wrap items-baseline gap-x-2 gap-y-1 text-sm">
                  <span className="font-mono text-xs text-slate-500">{coverageStepLabel(segment)}</span>
                  {detail && <span className="text-brand-dark/80">{detail}</span>}
                  {segment.extensions.map((extension) => (
                    <button
                      key={extension.extension_id}
                      type="button"
                      onClick={() => open(extension.extension_id, extension.focus_rule_id)}
                      className="inline-flex min-h-7 items-center gap-1 rounded-lg px-1.5 text-sm font-medium text-brand-blue underline-offset-2 hover:underline focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                    >
                      {extension.name}
                      <HiMiniArrowTopRightOnSquare className="h-3.5 w-3.5" aria-hidden="true" />
                    </button>
                  ))}
                </li>
              );
            })}
          </ul>
          {scopeLine && <p className="mt-3 text-xs text-slate-500">{scopeLine}</p>}
        </div>
      </div>
    </section>
  );
}
