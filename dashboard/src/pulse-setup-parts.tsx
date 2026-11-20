import type { ReactNode } from "react";

// Where a new user gets the YID app. `referrer_id` tells Yanez the visit came
// from HOL Guard; it carries nothing about the user or machine.
export const PULSE_SITE_URL = "https://pulse.yanez.ai/?referrer_id=holguard";

export const PULSE_LABEL_CLASS = "text-xs font-semibold uppercase tracking-[0.18em] text-slate-500";
export const PULSE_INPUT_CLASS =
  "mt-2 min-h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20";

export function pulseCooldownLabel(seconds: number): string {
  if (seconds === 900) return "15 minutes, same kind of action";
  if (seconds === 3600) return "1 hour, same kind of action";
  return "Every action (recommended)";
}

export function ErrorNote({ message }: { message: string | null }) {
  if (message === null) return null;
  return (
    <p role="alert" className="rounded-xl border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2 text-xs text-brand-dark">
      {message}
    </p>
  );
}

export function Field(props: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="block">
      <span className={PULSE_LABEL_CLASS}>{props.label}</span>
      {props.children}
      {props.hint ? <p className="mt-1 text-xs text-slate-500">{props.hint}</p> : null}
    </label>
  );
}
