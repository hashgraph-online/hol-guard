import {
  HiMiniCheckCircle,
  HiMiniChevronDown,
  HiMiniChevronRight,
  HiMiniExclamationTriangle,
  HiMiniInformationCircle,
  HiMiniShieldCheck,
} from "react-icons/hi2";

import type { ProtectionStatusView } from "../model/protection-presentation";
import {
  EXTENSION_PANEL_CLASS,
  EXTENSION_ROW_CLASS,
} from "../protection-surface";
import { ExtensionBrandMark } from "./extension-brand-mark";

export function ProtectionStatusHero(props: {
  status: ProtectionStatusView;
  busy?: boolean;
  onPrimaryAction?: () => void;
  children?: React.ReactNode;
}) {
  const safe = props.status.tone === "safe";
  return <section aria-labelledby="protection-status-heading" className="guard-status-bar">
    <span className="guard-status-bar-icon" data-tone={props.status.tone} aria-hidden="true">
      {safe ? <HiMiniShieldCheck className="size-4" /> : <HiMiniExclamationTriangle className="size-4" />}
    </span>
    <div className="min-w-0 flex-1">
      <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Local protection</p>
      <div className="mt-0.5 flex flex-wrap items-baseline gap-x-2">
        <h2 id="protection-status-heading" className="text-sm font-semibold text-brand-dark">{props.status.title}</h2>
        <p className="text-sm leading-5 text-brand-dark/70">{props.status.summary}</p>
      </div>
    </div>
    <ProtectionStatusAction
      busy={props.busy === true}
      safe={safe}
      primaryActionLabel={props.status.primaryActionLabel}
      onPrimaryAction={props.onPrimaryAction}
    />
    {props.children ? <div className="w-full border-t border-[rgba(63,65,116,0.08)] pt-2">{props.children}</div> : null}
  </section>;
}

function ProtectionStatusAction(props: {
  busy: boolean;
  safe: boolean;
  primaryActionLabel?: string;
  onPrimaryAction?: () => void;
}) {
  if (props.primaryActionLabel && props.onPrimaryAction) {
    return (
      <button
        type="button"
        aria-busy={props.busy}
        disabled={props.busy}
        onClick={props.onPrimaryAction}
        className="min-h-11 shrink-0 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white shadow-sm hover:bg-brand-dark disabled:cursor-wait disabled:opacity-60"
      >
        {props.busy ? "Working…" : props.primaryActionLabel}
      </button>
    );
  }
  if (props.safe) {
    return (
      <span className="inline-flex min-h-9 shrink-0 items-center gap-1.5 self-center rounded-full border border-emerald-200 bg-[#e8f7ee] px-3 text-xs font-semibold text-emerald-800">
        <HiMiniCheckCircle className="size-3.5" />
        No action required
      </span>
    );
  }
  return null;
}

export function ProtectionDecisionBadge({ result }: { result: "allowed" | "ask-first" | "blocked" }) {
  return (
    <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${decisionBadgeClasses(result)}`}>
      {decisionBadgeLabel(result)}
    </span>
  );
}

function decisionBadgeLabel(result: "allowed" | "ask-first" | "blocked"): string {
  if (result === "allowed") return "Allowed";
  if (result === "ask-first") return "Ask once";
  return "Blocked";
}

function decisionBadgeClasses(result: "allowed" | "ask-first" | "blocked"): string {
  if (result === "allowed") return "border-emerald-200 bg-emerald-50 text-emerald-800";
  if (result === "ask-first") return "border-amber-200 bg-amber-50 text-amber-800";
  return "border-red-200 bg-red-50 text-red-800";
}

export function ProtectionModuleRow(props: {
  extensionId: string;
  name: string;
  description: string;
  behavior: string;
  required?: boolean;
  managed?: boolean;
  managedLabel?: string;
  custom?: boolean;
  mcp?: boolean;
  external?: boolean;
  executables?: readonly string[];
  ecosystemIds?: readonly string[];
  onOpen: () => void;
}) {
  return <button type="button" onClick={props.onOpen} className={`${EXTENSION_ROW_CLASS} motion-reduce:transition-none`}>
    <ExtensionBrandMark
      extension_id={props.extensionId}
      name={props.name}
      executables={props.executables}
      ecosystem_ids={props.ecosystemIds}
      size="md"
    />
    <span className="min-w-0 flex-1">
      <span className="flex flex-wrap items-center gap-2"><strong className="text-sm text-brand-dark">{props.name}</strong>{props.required ? <span className="text-[11px] font-semibold text-brand-dark/55">Required by Guard</span> : null}{props.mcp ? <span className="text-[11px] font-semibold text-brand-dark/55">MCP</span> : null}{props.external ? <span className="text-[11px] font-semibold text-brand-dark/55">External</span> : null}{props.managed ? <span className="text-[11px] font-semibold text-brand-dark/55">{props.managedLabel ?? "Synced from Guard Cloud"}</span> : null}{props.custom ? <span className="text-[11px] font-semibold text-brand-dark/55">Custom</span> : null}</span>
      <span className="mt-0.5 block truncate text-sm text-brand-dark/70">{props.behavior}</span>
    </span>
    <HiMiniChevronRight className="size-5 shrink-0 text-brand-dark/35" aria-hidden="true" />
  </button>;
}

export function SettingSource({ source }: { source: "built-in" | "device" | "organization" }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-brand-dark/70">
      <HiMiniInformationCircle className="size-4" aria-hidden="true" />
      {settingSourceLabel(source)}
    </span>
  );
}

function settingSourceLabel(source: "built-in" | "device" | "organization"): string {
  if (source === "organization") return "Managed by your organization";
  if (source === "device") return "Set on this device";
  return "Built in to Guard";
}

export function WhyThisHappened(props: { summary: string; children?: React.ReactNode }) {
  return <details className={`${EXTENSION_PANEL_CLASS}`}><summary className="cursor-pointer list-none font-semibold text-brand-dark"><span className="inline-flex items-center gap-2">Why this setting?<HiMiniChevronDown className="size-4" aria-hidden="true" /></span></summary><p className="mt-3 text-sm leading-6 text-brand-dark/80">{props.summary}</p>{props.children ? <div className="mt-3">{props.children}</div> : null}</details>;
}

export function TechnicalDetails(props: { title?: string; testId?: string; children: React.ReactNode }) {
  return <details className={`${EXTENSION_PANEL_CLASS}`} data-testid={props.testId}><summary className="cursor-pointer list-none text-sm font-semibold text-brand-dark"><span className="inline-flex items-center gap-2">{props.title ?? "Technical details"}<HiMiniChevronDown className="size-4" aria-hidden="true" /></span></summary><div className="mt-4 text-sm text-brand-dark/80">{props.children}</div></details>;
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
