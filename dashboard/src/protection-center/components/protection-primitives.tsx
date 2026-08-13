import { useCallback, useState } from "react";
import {
  HiMiniCheckCircle,
  HiMiniChevronDown,
  HiMiniChevronRight,
  HiMiniExclamationTriangle,
  HiMiniInformationCircle,
  HiMiniShieldCheck,
} from "react-icons/hi2";

import type { ProtectionDensity, ProtectionStatusView } from "../model/protection-presentation";
import { readProtectionDensity, writeProtectionDensity } from "../model/protection-presentation";
import {
  EXTENSION_KICKER_CLASS,
  EXTENSION_PANEL_CLASS,
  EXTENSION_ROW_CLASS,
} from "../protection-surface";

export function useProtectionDensity(): [ProtectionDensity, (density: ProtectionDensity) => void] {
  const [density, setDensity] = useState<ProtectionDensity>(() => readProtectionDensity());
  const update = useCallback((next: ProtectionDensity) => {
    writeProtectionDensity(next);
    setDensity(next);
  }, []);
  return [density, update];
}

export function ProtectionDensityControl(props: {
  value: ProtectionDensity;
  onChange: (density: ProtectionDensity) => void;
}) {
  const choices: Array<{ value: ProtectionDensity; label: string }> = [
    { value: "simple", label: "Simple" },
    { value: "advanced", label: "Advanced" },
    { value: "developer", label: "Developer" },
  ];
  return <div role="radiogroup" aria-label="Information detail" className="flex w-full max-w-full flex-wrap rounded-2xl border border-[rgba(63,65,116,0.1)] bg-white/70 p-1 sm:inline-flex sm:w-auto sm:flex-nowrap">
    {choices.map((choice) => <button
      key={choice.value}
      type="button"
      role="radio"
      aria-checked={props.value === choice.value}
      onClick={() => props.onChange(choice.value)}
      className={`min-h-10 min-w-0 flex-1 rounded-lg px-2.5 text-xs font-semibold focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue sm:flex-none sm:px-3 ${props.value === choice.value ? "bg-white text-brand-blue shadow-sm" : "text-brand-dark/70 hover:bg-white"}`}
    >{choice.label}</button>)}
  </div>;
}

const HERO_TONE: Record<ProtectionStatusView["tone"], string> = {
  safe: `${EXTENSION_PANEL_CLASS} guard-extensions-tone-safe`,
  attention: `${EXTENSION_PANEL_CLASS} guard-extensions-tone-attention`,
  danger: `${EXTENSION_PANEL_CLASS} guard-extensions-tone-danger`,
  neutral: `${EXTENSION_PANEL_CLASS} guard-extensions-tone-neutral`,
};

export function ProtectionStatusHero(props: {
  status: ProtectionStatusView;
  busy?: boolean;
  onPrimaryAction?: () => void;
  children?: React.ReactNode;
}) {
  const safe = props.status.tone === "safe";
  return <section aria-labelledby="protection-status-heading" className={HERO_TONE[props.status.tone]}>
    <div className="flex flex-col gap-5 sm:flex-row sm:items-start sm:justify-between">
      <div className="min-w-0">
        <div className="flex items-center gap-3">
          <span className="grid size-11 shrink-0 place-items-center rounded-2xl bg-white/80" aria-hidden="true">
            {safe ? <HiMiniShieldCheck className="size-6" /> : <HiMiniExclamationTriangle className="size-6" />}
          </span>
          <div>
            <p className={EXTENSION_KICKER_CLASS}>Local protection</p>
            <h2 id="protection-status-heading" className="mt-1 text-2xl font-semibold tracking-tight">{props.status.title}</h2>
          </div>
        </div>
        <p className="mt-4 max-w-2xl text-sm leading-6">{props.status.summary}</p>
      </div>
      {props.status.primaryActionLabel && props.onPrimaryAction ? <button
        type="button"
        aria-busy={props.busy}
        disabled={props.busy}
        onClick={props.onPrimaryAction}
        className="min-h-11 shrink-0 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white shadow-sm hover:bg-brand-dark disabled:cursor-wait disabled:opacity-60"
      >{props.busy ? "Working…" : props.status.primaryActionLabel}</button> : <span className="inline-flex min-h-10 items-center gap-2 self-start rounded-full border border-current/15 bg-white/70 px-3 text-xs font-semibold"><HiMiniCheckCircle className="size-4" />No action required</span>}
    </div>
    {props.children ? <div className="mt-5 border-t border-current/10 pt-4">{props.children}</div> : null}
  </section>;
}

export function ProtectionDecisionBadge({ result }: { result: "allowed" | "ask-first" | "blocked" }) {
  const label = result === "allowed" ? "Allowed" : result === "ask-first" ? "Ask first" : "Blocked";
  const classes = result === "allowed" ? "border-emerald-200 bg-emerald-50 text-emerald-800" : result === "ask-first" ? "border-amber-200 bg-amber-50 text-amber-800" : "border-red-200 bg-red-50 text-red-800";
  return <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${classes}`}>{label}</span>;
}

export function ProtectionModuleRow(props: {
  name: string;
  description: string;
  behavior: string;
  required?: boolean;
  managed?: boolean;
  onOpen: () => void;
}) {
  return <button type="button" onClick={props.onOpen} className={`${EXTENSION_ROW_CLASS} motion-reduce:transition-none`}>
    <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-[rgba(85,153,254,0.1)] text-brand-blue" aria-hidden="true"><HiMiniShieldCheck className="size-5" /></span>
    <span className="min-w-0 flex-1">
      <span className="flex flex-wrap items-center gap-2"><strong className="text-sm text-brand-dark">{props.name}</strong>{props.required ? <span className="rounded-full bg-[rgba(85,153,254,0.1)] px-2 py-0.5 text-[10px] font-semibold text-brand-blue">Required</span> : null}{props.managed ? <span className="rounded-full bg-[rgba(181,108,255,0.12)] px-2 py-0.5 text-[10px] font-semibold text-brand-purple">Managed</span> : null}</span>
      <span className="mt-1 block line-clamp-2 text-sm leading-5 text-brand-dark/70">{props.description}</span>
    </span>
    <span className="hidden shrink-0 text-xs font-semibold text-brand-dark/70 sm:inline">{props.behavior}</span>
    <HiMiniChevronRight className="size-5 shrink-0 text-brand-dark/40" aria-hidden="true" />
  </button>;
}

export function SettingSource({ source }: { source: "built-in" | "device" | "organization" }) {
  const label = source === "organization" ? "Managed by your organization" : source === "device" ? "Set on this device" : "Built in to Guard";
  return <span className="inline-flex items-center gap-1.5 text-xs font-medium text-brand-dark/70"><HiMiniInformationCircle className="size-4" aria-hidden="true" />{label}</span>;
}

export function WhyThisHappened(props: { summary: string; children?: React.ReactNode }) {
  return <details className={`${EXTENSION_PANEL_CLASS}`}><summary className="cursor-pointer list-none font-semibold text-brand-dark"><span className="inline-flex items-center gap-2">Why this setting?<HiMiniChevronDown className="size-4" aria-hidden="true" /></span></summary><p className="mt-3 text-sm leading-6 text-brand-dark/80">{props.summary}</p>{props.children ? <div className="mt-3">{props.children}</div> : null}</details>;
}

export function TechnicalDetails(props: { title?: string; children: React.ReactNode }) {
  return <details className={`${EXTENSION_PANEL_CLASS}`}><summary className="cursor-pointer list-none text-sm font-semibold text-brand-dark"><span className="inline-flex items-center gap-2">{props.title ?? "Technical details"}<HiMiniChevronDown className="size-4" aria-hidden="true" /></span></summary><div className="mt-4 text-sm text-brand-dark/80">{props.children}</div></details>;
}

export function RecoveryProgress(props: { currentStep: number; steps: readonly string[] }) {
  return <ol aria-label="Repair progress" className="space-y-2">{props.steps.map((step, index) => <li key={step} className={`flex items-center gap-2 text-sm ${index < props.currentStep ? "text-emerald-800" : index === props.currentStep ? "font-semibold text-brand-dark" : "text-brand-dark/45"}`}><span className="grid size-6 shrink-0 place-items-center rounded-full border border-current/30 text-xs">{index < props.currentStep ? "✓" : index + 1}</span>{step}</li>)}</ol>;
}

export function InlineError({ message }: { message: string }) {
  return <p role="alert" className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{message}</p>;
}

export function AsyncActionButton(props: React.ButtonHTMLAttributes<HTMLButtonElement> & { busy?: boolean; busyLabel?: string }) {
  const { busy, busyLabel, children, className = "", disabled, ...buttonProps } = props;
  return <button {...buttonProps} type={buttonProps.type ?? "button"} aria-busy={busy} disabled={disabled || busy} className={`min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white disabled:opacity-60 ${className}`}>{busy ? busyLabel ?? "Working…" : children}</button>;
}
