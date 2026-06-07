import { formatEvidenceCount } from "./evidence-format";

export interface EvidenceShareBarProps {
  label: string;
  count: number;
  shareOfTotal: number;
  onClick?: () => void;
  animate?: boolean;
}

export function EvidenceShareBar({ label, count, shareOfTotal, onClick, animate = true }: EvidenceShareBarProps) {
  const widthPct = Math.max(Math.min(Math.round(shareOfTotal), 100), shareOfTotal > 0 ? 4 : 0);
  const Wrapper = onClick ? "button" : "div";
  const wrapperProps = onClick
    ? {
        type: "button" as const,
        onClick,
        className:
          "group flex w-full min-h-11 items-center gap-3 rounded-lg px-2 py-2 text-left transition-colors hover:bg-slate-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue",
      }
    : {
        className: "flex w-full min-h-11 items-center gap-3 rounded-lg px-2 py-2",
      };

  return (
    <Wrapper {...wrapperProps}>
      <div className="min-w-0 flex-1">
        <div className="flex items-center justify-between gap-2">
          <span className="truncate text-sm font-medium text-brand-dark">{label}</span>
          <span className="shrink-0 text-xs tabular-nums text-slate-500">
            {formatEvidenceCount(count)}
            {shareOfTotal > 0 ? ` · ${widthPct}%` : ""}
          </span>
        </div>
        <div className="mt-2 h-2 overflow-hidden rounded-full bg-surface-2">
          <div
            className={`evidence-share-bar-fill h-full origin-left rounded-full bg-brand-blue ${animate ? "evidence-share-bar-fill-animate" : ""} ${onClick ? "group-hover:bg-[color-mix(in_srgb,var(--brand-blue)_85%,var(--brand-dark))]" : ""}`}
            style={{ ["--share-scale" as string]: widthPct / 100, transform: `scaleX(${widthPct / 100})` }}
            aria-hidden="true"
          />
        </div>
      </div>
    </Wrapper>
  );
}
