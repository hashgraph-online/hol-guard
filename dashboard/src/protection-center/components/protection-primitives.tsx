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
      <div className="flex flex-wrap items-baseline gap-x-2">
        <p className="text-sm text-brand-dark/60">Local protection</p>
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
      <span className="inline-flex shrink-0 items-center gap-1.5 self-center text-xs font-semibold text-emerald-800">
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
  brand?: string;
  badge?: string;
  actionLabel?: string;
  state?: ExtensionRowState;
  ruleCount?: number;
  permissionCount?: number;
  publisher?: string;
  onOpen: () => void;
}) {
  const meta = rowTrustMeta(props.ruleCount, props.permissionCount, props.publisher);
  return <button type="button" onClick={props.onOpen} className={`${EXTENSION_ROW_CLASS} group motion-reduce:transition-none`}>
    <ExtensionBrandMark
      extension_id={props.extensionId}
      name={props.name}
      executables={props.executables}
      ecosystem_ids={props.ecosystemIds}
      brand={props.brand}
      size="md"
    />
    <span className="min-w-0 flex-1">
      <span className="flex flex-wrap items-center gap-2"><strong className="text-sm text-brand-dark">{props.name}</strong>{props.required ? <span className="text-[11px] font-semibold text-brand-dark/55">Required by Guard</span> : null}{props.mcp ? <span className="text-[11px] font-semibold text-brand-dark/55">MCP</span> : null}{props.external ? <span className="text-[11px] font-semibold text-brand-dark/55">External</span> : null}{props.managed ? <span className="text-[11px] font-semibold text-brand-dark/55">{props.managedLabel ?? "Synced from Guard Cloud"}</span> : null}{props.custom ? <span className="text-[11px] font-semibold text-brand-dark/55">Custom</span> : null}{props.badge ? <span className="rounded-full border border-brand-blue/30 bg-brand-blue/5 px-2 py-0.5 text-[11px] font-semibold text-brand-dark" data-testid="custom-extension-badge">{props.badge}</span> : null}</span>
      <span className="mt-0.5 block truncate text-sm text-brand-dark/70">{props.behavior}</span>{meta ? <span className="mt-1 block truncate font-mono text-[11px] text-brand-dark/50" data-testid="extension-row-meta">{meta}</span> : null}{props.actionLabel ? <span className="mt-1 block text-sm font-semibold text-brand-blue">{props.actionLabel}</span> : null}
    </span>
    {props.state ? <ExtensionStatePill state={props.state} /> : null}
    <HiMiniChevronRight className="size-5 shrink-0 text-brand-dark/35 transition-transform duration-150 group-hover:translate-x-0.5 motion-reduce:transition-none" aria-hidden="true" />
  </button>;
}

export type ExtensionRowState = "Allowed" | "Blocked" | "Required" | "Managed" | "Lockdown" | "Unavailable";

const STATE_PILL: Record<ExtensionRowState, { label: string; tone: string; description: string }> = {
  Allowed: { label: "On", tone: "safe", description: "Guard allows this tool" },
  Blocked: { label: "Off", tone: "neutral", description: "Guard blocks this tool" },
  Required: { label: "Always on", tone: "info", description: "Guard needs this tool to protect the device" },
  Managed: { label: "Policy", tone: "info", description: "Your organization sets this tool" },
  Lockdown: { label: "Locked", tone: "danger", description: "Lockdown blocks every tool" },
  Unavailable: { label: "Paused", tone: "attention", description: "Protection is not running, so this setting is not enforced" },
};

/** The word a person actually sees for a state, for reuse in accessible names. */
export function extensionStatePillLabel(state: ExtensionRowState): string {
  return STATE_PILL[state].label;
}

/** Compact, color-plus-word state so the list scans without opening a row. */
export function ExtensionStatePill({ state }: { state: ExtensionRowState }) {
  const pill = STATE_PILL[state];
  return (
    <span className="guard-state-pill shrink-0" data-tone={pill.tone} data-testid="extension-state-pill" title={pill.description}>
      <span className="guard-state-pill-dot" aria-hidden="true" />
      <span className="sr-only">Status: </span>{pill.label}
    </span>
  );
}

function rowTrustMeta(ruleCount?: number, permissionCount?: number, publisher?: string): string {
  const parts: string[] = [];
  if (ruleCount && ruleCount > 0) parts.push(`${ruleCount} ${ruleCount === 1 ? "rule" : "rules"}`);
  if (permissionCount && permissionCount > 0) parts.push(`${permissionCount} ${permissionCount === 1 ? "permission" : "permissions"}`);
  if (publisher && publisher.trim()) parts.push(`by ${publisher.trim()}`);
  return parts.join(" · ");
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
