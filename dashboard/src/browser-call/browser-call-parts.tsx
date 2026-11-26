import type { ComponentType, ReactNode } from "react";

/** One labelled line of the browser card: an icon, a short label and its value. */
export function CardRow(props: {
  icon: ComponentType<{ className?: string; "aria-hidden"?: boolean | "true" }>;
  label: string;
  children: ReactNode;
}) {
  const Icon = props.icon;
  return (
    <div className="grid grid-cols-[auto_minmax(4.5rem,auto)_minmax(0,1fr)] items-start gap-x-2.5 py-1.5 text-sm">
      <Icon className="mt-0.5 h-4 w-4 shrink-0 text-brand-dark/50" aria-hidden="true" />
      <span className="pt-px text-brand-dark/60">{props.label}</span>
      <span className="flex min-w-0 flex-col items-start">{props.children}</span>
    </div>
  );
}

const FLAG_TONES = {
  note: "border-slate-200 bg-slate-50 text-brand-dark/80",
  attention: "border-brand-attention/30 bg-brand-attention/[0.08] text-brand-dark",
} as const;

/** A short status tag. Its text is its accessible name, so it never relies on color. */
export function Flag({ tone, children }: { tone: keyof typeof FLAG_TONES; children: ReactNode }) {
  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${FLAG_TONES[tone]}`}>
      {children}
    </span>
  );
}
