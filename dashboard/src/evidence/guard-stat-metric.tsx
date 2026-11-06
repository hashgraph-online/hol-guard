import type { ReactNode } from "react";

export type GuardStatMetricTone = "blue" | "green" | "purple" | "slate" | "default";

function metricValueClass(tone: GuardStatMetricTone): string {
  switch (tone) {
    case "blue":
      return "text-brand-blue";
    case "green":
      return "text-emerald-600";
    case "purple":
      return "text-brand-purple";
    case "slate":
      return "text-slate-500";
    default:
      return "text-brand-dark";
  }
}

export function GuardStatMetric(props: {
  label: string;
  value: ReactNode;
  detail?: string | null;
  tone?: GuardStatMetricTone;
  animationDelayMs?: number;
  compact?: boolean;
}) {
  const tone = props.tone ?? "default";
  const valueClass = metricValueClass(tone);

  return (
    <div
      className={`bg-white px-4 evidence-metric-enter ${props.compact ? "py-3.5 sm:py-4" : "py-4 sm:py-5"}`}
      style={props.animationDelayMs !== undefined ? { animationDelay: `${props.animationDelayMs}ms` } : undefined}
    >
      <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-500">{props.label}</p>
      <p
        className={`mt-1 font-semibold tabular-nums tracking-tight ${valueClass} ${
          props.compact ? "text-lg" : "text-xl sm:text-2xl"
        }`}
      >
        {props.value}
      </p>
      {props.detail ? <p className="mt-0.5 text-xs text-slate-500">{props.detail}</p> : null}
    </div>
  );
}
