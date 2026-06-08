import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import type { GuardReceiptAnalyticsBucket } from "../guard-types";
import { formatEvidenceCount } from "./evidence-format";

const CHART_HEIGHT_PX = 112;
const TOOLTIP_ID = "evidence-trend-chart-tooltip";

function bucketTotal(bucket: GuardReceiptAnalyticsBucket): number {
  return bucket.allowed + bucket.blocked + bucket.reviewed;
}

function isGuardModalOpen(): boolean {
  if (typeof document === "undefined") return false;
  const count = Number(document.documentElement.dataset.guardModalOpen ?? 0);
  return Number.isFinite(count) && count > 0;
}

interface TooltipState {
  label: string;
  allowed: number;
  blocked: number;
  reviewed: number;
  top: number;
  left: number;
  placement: "above" | "below";
}

interface EvidenceTrendChartProps {
  buckets: GuardReceiptAnalyticsBucket[];
}

export function EvidenceTrendChart({ buckets }: EvidenceTrendChartProps) {
  const cellRefs = useRef<Map<string, HTMLButtonElement>>(new Map());
  const [hoveredKey, setHoveredKey] = useState<string | null>(null);
  const [tooltip, setTooltip] = useState<TooltipState | null>(null);
  const [reduceMotion, setReduceMotion] = useState(false);

  const maxTotal = useMemo(() => Math.max(...buckets.map((bucket) => bucketTotal(bucket)), 1), [buckets]);
  const hasAnyData = useMemo(() => buckets.some((bucket) => bucketTotal(bucket) > 0), [buckets]);

  useEffect(() => {
    setReduceMotion(window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  }, []);

  const updateTooltipForKey = useCallback(
    (dateKey: string | null) => {
      if (!dateKey || isGuardModalOpen()) {
        setTooltip(null);
        return;
      }
      const bucket = buckets.find((entry) => entry.date_key === dateKey);
      const element = cellRefs.current.get(dateKey);
      if (!bucket || !element || bucketTotal(bucket) <= 0) {
        setTooltip(null);
        return;
      }
      const rect = element.getBoundingClientRect();
      const aboveTop = rect.top - 8;
      const belowTop = rect.bottom + 8;
      const placement = aboveTop > 80 ? "above" : "below";
      setTooltip({
        label: bucket.label,
        allowed: bucket.allowed,
        blocked: bucket.blocked,
        reviewed: bucket.reviewed,
        left: rect.left + rect.width / 2,
        top: placement === "above" ? aboveTop : belowTop,
        placement,
      });
    },
    [buckets],
  );

  useLayoutEffect(() => {
    updateTooltipForKey(hoveredKey);
  }, [hoveredKey, updateTooltipForKey, buckets]);

  useEffect(() => {
    if (!hoveredKey) return;
    const onScrollOrResize = () => updateTooltipForKey(hoveredKey);
    window.addEventListener("scroll", onScrollOrResize, true);
    window.addEventListener("resize", onScrollOrResize);
    return () => {
      window.removeEventListener("scroll", onScrollOrResize, true);
      window.removeEventListener("resize", onScrollOrResize);
    };
  }, [hoveredKey, updateTooltipForKey]);

  useEffect(() => {
    if (typeof document === "undefined") return;
    const dismissWhenModalOpens = () => {
      if (isGuardModalOpen()) {
        setTooltip(null);
        setHoveredKey(null);
      }
    };
    const observer = new MutationObserver(dismissWhenModalOpens);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-guard-modal-open"] });
    return () => observer.disconnect();
  }, []);

  if (!hasAnyData) {
    return <p className="px-5 py-6 text-sm text-slate-400">No activity in this period.</p>;
  }

  const tooltipNode =
    tooltip && !isGuardModalOpen() && typeof document !== "undefined"
      ? createPortal(
          <div
            id={TOOLTIP_ID}
            className="pointer-events-none fixed z-40 -translate-x-1/2 rounded-lg bg-brand-dark px-3 py-2 text-xs text-white shadow-lg"
            style={{
              left: tooltip.left,
              top: tooltip.top,
              transform: `translate(-50%, ${tooltip.placement === "above" ? "-100%" : "0"})`,
            }}
            role="tooltip"
          >
            <div className="font-semibold">{tooltip.label}</div>
            <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5">
              {tooltip.allowed > 0 && (
                <span className="text-emerald-300">{formatEvidenceCount(tooltip.allowed)} allowed</span>
              )}
              {tooltip.blocked > 0 && (
                <span className="text-amber-300">{formatEvidenceCount(tooltip.blocked)} stopped</span>
              )}
              {tooltip.reviewed > 0 && (
                <span className="text-sky-300">{formatEvidenceCount(tooltip.reviewed)} reviewed</span>
              )}
            </div>
          </div>,
          document.body,
        )
      : null;

  return (
    <div className="px-5 pb-5 pt-4">
      {tooltipNode}
      <div
        className="relative flex items-end gap-1.5 sm:gap-2"
        style={{ minHeight: CHART_HEIGHT_PX + 44 }}
        role="group"
        aria-label="Seven day activity chart"
      >
        <div
          className="pointer-events-none absolute inset-x-0 bottom-[26px] flex flex-col justify-between"
          style={{ height: CHART_HEIGHT_PX }}
          aria-hidden="true"
        >
          {[0, 1, 2].map((line) => (
            <div
              key={line}
              className="h-px w-full bg-slate-200/70"
              style={{ opacity: line === 0 ? 0.35 : 0.55 }}
            />
          ))}
        </div>

        {buckets.map((bucket, index) => {
          const total = bucketTotal(bucket);
          const barHeight =
            total > 0 ? Math.max(Math.round((total / maxTotal) * CHART_HEIGHT_PX), 10) : 0;
          const isActive = hoveredKey === bucket.date_key;
          const showTooltip = isActive && tooltip !== null;

          return (
            <div key={bucket.date_key} className="relative z-[1] flex min-w-0 flex-1 flex-col items-center justify-end">
              <span
                className={`mb-2 text-[11px] font-semibold tabular-nums tracking-tight transition-colors ${
                  isActive ? "text-brand-blue" : "text-brand-dark"
                }`}
                aria-hidden={total <= 0}
              >
                {total > 0 ? formatEvidenceCount(total) : ""}
              </span>

              <div className="relative w-full max-w-[3.25rem]" style={{ height: CHART_HEIGHT_PX }}>
                <div className="evidence-trend-chart-well absolute inset-0 rounded-lg" aria-hidden="true" />

                {total > 0 ? (
                  <button
                    type="button"
                    ref={(node) => {
                      if (node) cellRefs.current.set(bucket.date_key, node);
                      else cellRefs.current.delete(bucket.date_key);
                    }}
                    aria-label={`${bucket.label}: ${formatEvidenceCount(total)} actions`}
                    aria-describedby={showTooltip ? TOOLTIP_ID : undefined}
                    className={`evidence-trend-chart-bar absolute inset-x-0 bottom-0 flex w-full flex-col-reverse overflow-hidden rounded-t-lg shadow-[inset_0_1px_0_rgba(255,255,255,0.35)] outline-none ${
                      isActive ? "evidence-trend-chart-bar-active" : ""
                    } ${reduceMotion ? "" : "evidence-trend-chart-bar-motion"}`}
                    style={{
                      height: barHeight,
                      animationDelay: reduceMotion ? undefined : `${index * 45}ms`,
                    }}
                    onMouseEnter={() => setHoveredKey(bucket.date_key)}
                    onMouseLeave={() => setHoveredKey(null)}
                    onFocus={() => setHoveredKey(bucket.date_key)}
                    onBlur={() => setHoveredKey(null)}
                  >
                    {bucket.blocked > 0 && (
                      <div
                        className="evidence-chart-stopped min-h-[3px] w-full shrink-0"
                        style={{ flexGrow: bucket.blocked }}
                      />
                    )}
                    {bucket.allowed > 0 && (
                      <div
                        className="evidence-chart-allowed min-h-[3px] w-full shrink-0"
                        style={{ flexGrow: bucket.allowed }}
                      />
                    )}
                    {bucket.reviewed > 0 && (
                      <div
                        className="evidence-chart-reviewed min-h-[3px] w-full shrink-0"
                        style={{ flexGrow: bucket.reviewed }}
                      />
                    )}
                  </button>
                ) : (
                  <div
                    className="absolute inset-x-2 bottom-0 h-1.5 rounded-full bg-slate-200/90"
                    aria-hidden="true"
                  />
                )}
              </div>

              <span
                className={`mt-2.5 w-full truncate text-center text-[10px] font-medium leading-none transition-colors ${
                  isActive ? "text-brand-dark" : "text-slate-500"
                }`}
              >
                {bucket.label}
              </span>
            </div>
          );
        })}
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-slate-100 pt-3 text-[11px] text-slate-500">
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2 w-2 rounded-full evidence-chart-allowed" />
          Allowed
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2 w-2 rounded-full evidence-chart-stopped" />
          Stopped
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2 w-2 rounded-full evidence-chart-reviewed" />
          Reviewed
        </span>
      </div>
    </div>
  );
}
