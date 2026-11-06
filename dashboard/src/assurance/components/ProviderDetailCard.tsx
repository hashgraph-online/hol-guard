/**
 * ProviderDetailCard — surfaces GuardProviderDetailViewModel with distinct
 * visuals for every health state, boundary labels, guarantee chips, freshness
 * badge, drift indicator, and guided remediation callout.
 */

import { useMemo, type ButtonHTMLAttributes, type ComponentType } from "react";
import {
  HiMiniCheckCircle,
  HiMiniExclamationTriangle,
  HiMiniInformationCircle,
  HiMiniXCircle,
} from "react-icons/hi2";
import type {
  GuardProviderDetailViewModel,
  GuardUiBoundary,
  GuardUiProviderHealth,
  GuardUiStateCallout,
} from "../assurance-view-model";

// ---------------------------------------------------------------------------
// Boundary label mapping
// ---------------------------------------------------------------------------

const BOUNDARY_LABELS: Record<GuardUiBoundary, string> = {
  observed_host: "Host observation only",
  controlled_host: "Host-contained",
  os_isolated: "OS-level isolation",
  hardware_isolated: "Hardware isolation",
};

// ---------------------------------------------------------------------------
// Health-state appearance
// ---------------------------------------------------------------------------

type HealthAppearance = {
  statusLabel: string;
  statusColor: string;
  statusBg: string;
  cardBorder: string;
  cardBg: string;
  icon: string;
};

const HEALTH_APPEARANCE: Record<GuardUiProviderHealth, HealthAppearance> = {
  healthy: {
    statusLabel: "Healthy",
    statusColor: "text-brand-green-text",
    statusBg: "bg-brand-green-bg",
    cardBorder: "border-brand-green/30",
    cardBg: "bg-white",
    icon: "ok",
  },
  verifying: {
    statusLabel: "Verifying",
    statusColor: "text-brand-attention",
    statusBg: "bg-brand-attention-bg",
    cardBorder: "border-brand-attention/30",
    cardBg: "bg-white",
    icon: "info",
  },
  degraded: {
    statusLabel: "Degraded",
    statusColor: "text-brand-blue",
    statusBg: "bg-blue-50",
    cardBorder: "border-brand-blue/30",
    cardBg: "bg-white",
    icon: "warn",
  },
  unavailable: {
    statusLabel: "Unavailable",
    statusColor: "text-red-700",
    statusBg: "bg-red-50",
    cardBorder: "border-red-400",
    cardBg: "bg-red-50/60",
    icon: "critical",
  },
  revoked: {
    statusLabel: "Revoked",
    statusColor: "text-red-700",
    statusBg: "bg-red-50",
    cardBorder: "border-red-400",
    cardBg: "bg-red-50/60",
    icon: "critical",
  },
  incompatible: {
    statusLabel: "Incompatible",
    statusColor: "text-brand-blue",
    statusBg: "bg-blue-50",
    cardBorder: "border-brand-blue/30",
    cardBg: "bg-white",
    icon: "warn",
  },
  unknown: {
    statusLabel: "Unknown",
    statusColor: "text-muted-foreground",
    statusBg: "bg-muted",
    cardBorder: "border-muted-foreground/20",
    cardBg: "bg-white",
    icon: "info",
  },
};

// ---------------------------------------------------------------------------
// Icon map — react-icons/hi2 keyed by health/icon string
// ---------------------------------------------------------------------------

const ICON_MAP: Record<string, ComponentType<{ className?: string }>> = {
  ok: HiMiniCheckCircle,
  info: HiMiniInformationCircle,
  warn: HiMiniExclamationTriangle,
  critical: HiMiniXCircle,
};

interface StatusIconProps {
  kind: string;
  className?: string;
}

function StatusIcon({ kind, className = "h-4 w-4 shrink-0" }: StatusIconProps) {
  const Icon = ICON_MAP[kind];
  return Icon ? <Icon className={className} /> : null;
}

// ---------------------------------------------------------------------------
// Guarantee chip
// ---------------------------------------------------------------------------

interface GuaranteeChipProps {
  label: string;
}

export function GuaranteeChip({ label }: GuaranteeChipProps) {
  return (
    <span
      className="inline-flex items-center rounded-full border border-brand-attention/20 bg-brand-attention/10 px-2 py-0.5 text-[11px] font-medium text-brand-dark/80"
      aria-label={`Guarantee: ${label}`}
    >
      {label}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Freshness badge — Record maps instead of nested ternaries
// ---------------------------------------------------------------------------

interface FreshnessBadgeProps {
  freshness: "fresh" | "stale" | "unknown";
}

const FRESHNESS_LABEL: Record<FreshnessBadgeProps["freshness"], string> = {
  fresh: "Fresh",
  stale: "Stale",
  unknown: "Unknown",
};

const FRESHNESS_STYLE: Record<FreshnessBadgeProps["freshness"], string> = {
  fresh: "text-brand-green-text bg-brand-green-bg",
  stale: "text-brand-blue bg-blue-50",
  unknown: "text-muted-foreground bg-muted",
};

function FreshnessBadge({ freshness }: FreshnessBadgeProps) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${FRESHNESS_STYLE[freshness]}`}
      aria-label={`Health freshness: ${FRESHNESS_LABEL[freshness]}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {FRESHNESS_LABEL[freshness]}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Drift indicator
// ---------------------------------------------------------------------------

function DriftIndicator() {
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full border border-amber-300 bg-amber-50 px-2 py-0.5 text-[11px] font-medium text-amber-700"
      role="alert"
    >
      <HiMiniExclamationTriangle className="h-3.5 w-3.5 shrink-0" />
      Drift detected
    </span>
  );
}

// ---------------------------------------------------------------------------
// Remediation callout — Record maps instead of nested ternaries
// ---------------------------------------------------------------------------

interface RemediationCalloutProps {
  callout: GuardUiStateCallout;
  onAction?: () => void;
}

interface ActionButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary";
}

function ActionButton({
  variant = "primary",
  className = "",
  ...props
}: ActionButtonProps) {
  const base =
    "inline-flex min-h-11 items-center justify-center gap-1.5 rounded-lg border px-3 py-2 text-sm font-semibold transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40";
  const style =
    variant === "primary"
      ? "border-brand-blue/30 bg-white text-brand-blue hover:bg-brand-blue/5"
      : "border-brand-attention/30 bg-white text-brand-attention hover:bg-brand-attention/10";

  return (
    <button type="button" className={`${base} ${style} ${className}`} {...props} />
  );
}

const TONE_BORDER: Record<GuardUiStateCallout["tone"], string> = {
  critical: "border-l-red-400 bg-red-50/60",
  warn: "border-l-amber-300 bg-amber-50/60",
  info: "border-l-brand-attention bg-brand-attention-bg/60",
  ok: "border-l-brand-green bg-brand-green-bg/60",
};

const TONE_TEXT: Record<GuardUiStateCallout["tone"], string> = {
  critical: "text-red-800",
  warn: "text-amber-800",
  info: "text-brand-attention",
  ok: "text-brand-green-text",
};

const TONE_ICON: Record<GuardUiStateCallout["tone"], string> = {
  ok: "ok",
  info: "info",
  warn: "warn",
  critical: "critical",
};

function RemediationCallout({ callout, onAction }: RemediationCalloutProps) {
  return (
    <div
      className={`mt-3 rounded-r-lg border border-l-[3px] ${TONE_BORDER[callout.tone]} p-3`}
      role="region"
      aria-label="Remediation"
    >
      <div className="flex items-start gap-2">
        <StatusIcon
          kind={TONE_ICON[callout.tone]}
          className="mt-0.5 h-4 w-4 shrink-0"
        />
        <div className="min-w-0 flex-1">
          <p className={`text-[13px] font-semibold ${TONE_TEXT[callout.tone]}`}>
            {callout.headline}
          </p>
          <p
            className={`mt-0.5 text-[12px] leading-relaxed ${TONE_TEXT[callout.tone]} opacity-85`}
          >
            {callout.explanation}
          </p>
          {callout.actionLabel && onAction ? (
            <div className="mt-2">
              <ActionButton onClick={onAction}>
                {callout.actionLabel}
              </ActionButton>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// ProviderDetailCard
// ---------------------------------------------------------------------------

export interface ProviderDetailCardProps {
  model: GuardProviderDetailViewModel;
  onRemediationAction?: () => void;
}

export function ProviderDetailCard({
  model,
  onRemediationAction,
}: ProviderDetailCardProps) {
  const appearance = useMemo(
    () => HEALTH_APPEARANCE[model.health],
    [model.health],
  );

  return (
    <div
      className={`rounded-xl border bg-card shadow-sm ${appearance.cardBorder} ${appearance.cardBg} transition-colors`}
    >
      {/* Header */}
      <div className="border-b border-brand-attention/10 px-4 py-3">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <h3 className="truncate text-[13px] font-semibold text-brand-dark">
              {model.providerLabel}
            </h3>
            <p className="mt-0.5 text-[11px] text-muted-foreground">
              {BOUNDARY_LABELS[model.computedLevel]}
            </p>
          </div>
          <div className="shrink-0">
            <span
              className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-semibold ${appearance.statusColor} ${appearance.statusBg}`}
            >
              <StatusIcon kind={appearance.icon} className="h-3.5 w-3.5" />
              {appearance.statusLabel}
            </span>
          </div>
        </div>
      </div>

      {/* Body */}
      <div className="space-y-2.5 px-4 py-3">
        {/* Guarantees */}
        <div className="flex flex-wrap gap-1.5">
          {model.actualGuarantees.length > 0 ? (
            model.actualGuarantees.map((g) => (
              <GuaranteeChip key={g} label={g} />
            ))
          ) : (
            <span className="text-[11px] italic text-muted-foreground">
              No guarantees active
            </span>
          )}
        </div>

        {/* Freshness + drift row */}
        <div className="flex items-center gap-2">
          <FreshnessBadge freshness={model.healthFreshness} />
          {model.driftDetected ? <DriftIndicator /> : null}
        </div>

        {/* Remediation */}
        {model.remediation ? (
          <RemediationCallout
            callout={model.remediation}
            onAction={onRemediationAction}
          />
        ) : null}
      </div>
    </div>
  );
}
