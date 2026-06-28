import { useCallback, useEffect, useState, type ReactNode } from "react";
import { HiMiniChevronRight, HiMiniInformationCircle } from "react-icons/hi2";

export interface EvidenceItem {
  id: string;
  title: string;
  tone: "blue" | "purple" | "amber" | "slate";
  content: ReactNode;
}

/**
 * Consolidates multiple evidence cards into a single alert with a Next button.
 * The caller must pre-filter to non-empty items — this component renders all
 * items it receives.
 */
export function ConsolidatedEvidenceAlert({ items }: { items: EvidenceItem[] }) {
  const [index, setIndex] = useState(0);

  useEffect(() => {
    if (index >= items.length) {
      setIndex(0);
    }
  }, [items.length, index]);

  const handleNext = useCallback(() => {
    setIndex((prev) => (prev + 1) % items.length);
  }, [items.length]);

  if (items.length === 0) return null;

  const current = items[Math.min(index, items.length - 1)];
  const hasMultiple = items.length > 1;

  const iconClasses: Record<EvidenceItem["tone"], string> = {
    blue: "text-brand-blue",
    purple: "text-brand-purple",
    amber: "text-brand-attention",
    slate: "text-slate-400",
  };

  return (
    <div className="space-y-2">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-2.5 min-w-0 flex-1">
          <HiMiniInformationCircle
            className={`mt-0.5 h-4 w-4 shrink-0 ${iconClasses[current.tone]}`}
            aria-hidden="true"
          />
          <div className="min-w-0 flex-1">
            <p className="text-xs font-semibold uppercase tracking-[0.16em] text-muted-foreground">
              {current.title}
            </p>
          </div>
        </div>
        {hasMultiple && (
          <div className="flex items-center gap-2 shrink-0">
            <span className="text-xs font-medium text-muted-foreground tabular-nums">
              {index + 1} of {items.length}
            </span>
            <button
              type="button"
              onClick={handleNext}
              className="flex items-center gap-1 rounded-lg border border-slate-200 px-2.5 py-1 text-xs font-medium text-brand-dark transition-colors hover:bg-slate-50 focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
              aria-label="Next insight"
            >
              Next
              <HiMiniChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          </div>
        )}
      </div>
      <div className="text-sm text-brand-dark">
        {current.content}
      </div>
    </div>
  );
}
