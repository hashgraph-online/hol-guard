import type { ReactNode } from "react";
import { planToneClass } from "./mcp-policy-request-copy";

export function SummaryField(props: { label: string; children: ReactNode }) {
  return <div className="bg-white px-4 py-3">
    <dt className="text-[11px] font-medium uppercase tracking-wider text-slate-500">{props.label}</dt>
    <dd className="mt-1 min-w-0">{props.children}</dd>
  </div>;
}
export function PlanCountCard(props: {
  label: string; count: number; items: readonly string[]; tone: "emerald" | "amber" | "rose"; icon: ReactNode;
}) {
  const extraItems = props.items.length > 8 ? <li className="text-slate-400">+{props.items.length - 8} more</li> : null;
  return <div className={`rounded-xl border px-4 py-3 ${planToneClass(props.tone)}`}>
    <div className="flex items-center justify-between">
      <span className="inline-flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider">{props.icon}{props.label}</span>
      <span className="text-lg font-semibold">{props.count}</span>
    </div>
    {props.items.length > 0 ? <ul className="mt-2 space-y-1 text-[13px] leading-5 text-slate-700">
      {props.items.slice(0, 8).map((item,index) => <li key={`${props.label}-${index}-${item}`} className="break-all">{item}</li>)}
      {extraItems}
    </ul> : null}
  </div>;
}
