/**
 * ProviderDetailCard — surfaces GuardProviderDetailViewModel with distinct
 * visuals for every health state, boundary labels, guarantee chips, freshness
 * badge, drift indicator, and guided remediation callout.
 */

import { useMemo, type ButtonHTMLAttributes } from "react";
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

const BOUNDARY_LEVEL_ORDER: Record<GuardUiBoundary, number> = {
  observed_host: 1,
  controlled_host: 2,
  os_isolated: 3,
  hardware_isolated: 4,
};

// ---------------------------------------------------------------------------
// Health-state appearance
// ---------------------------------------------------------------------------

type HealthAppearance = {
  statusLabel: string;
  statusColor: string;
  statusBg: string;
  statusText: string;
  cardBorder: string;
  cardBg: string;
  icon: string;
};

const HEALTH_APPEARANCE: Record<GuardUiProviderHealth, HealthAppearance> = {
  healthy: {
    statusLabel: "Healthy",
    statusColor: "text-brand-green-text",
    statusBg: "bg-brand-green-bg",
    statusText: "text-brand-green-text",
    cardBorder: "border-brand-green/30",
    cardBg: "bg-white",
    icon: "ok",
  },
  verifying: {
    statusLabel: "Verifying",
    statusColor: "text-brand-attention",
    statusBg: "bg-brand-attention-bg",
    statusText: "text-brand-attention",
    cardBorder: "border-brand-attention/30",
    cardBg: "bg-white",
    icon: "info",
  },
  degraded: {
    statusLabel: "Degraded",
    statusColor: "text-brand-blue",
    statusBg: "bg-blue-50",
    statusText: "text-brand-blue",
    cardBorder: "border-brand-blue/30",
    cardBg: "bg-white",
    icon: "warn",
  },
  unavailable: {
    statusLabel: "Unavailable",
    statusColor: "text-red-700",
    statusBg: "bg-red-50",
    statusText: "text-red-700",
    cardBorder: "border-red-400",
    cardBg: "bg-red-50/60",
    icon: "critical",
  },
  revoked: {
    statusLabel: "Revoked",
    statusColor: "text-red-700",
    statusBg: "bg-red-50",
    statusText: "text-red-700",
    cardBorder: "border-red-400",
    cardBg: "bg-red-50/60",
    icon: "critical",
  },
  incompatible: {
    statusLabel: "Incompatible",
    statusColor: "text-brand-blue",
    statusBg: "bg-blue-50",
    statusText: "text-brand-blue",
    cardBorder: "border-brand-blue/30",
    cardBg: "bg-white",
    icon: "warn",
  },
  unknown: {
    statusLabel: "Unknown",
    statusColor: "text-muted-foreground",
    statusBg: "bg-muted",
    statusText: "text-muted-foreground",
    cardBorder: "border-muted-foreground/20",
    cardBg: "bg-white",
    icon: "info",
  },
};

// ---------------------------------------------------------------------------
// Icon helper (SVG inline — no external icon lib dependency)
// ---------------------------------------------------------------------------

interface StatusIconProps {
  kind: string;
  className?: string;
}

function StatusIcon({ kind, className = "h-4 w-4 shrink-0" }: StatusIconProps) {
  switch (kind) {
    case "ok":
      return (
        <svg
          className={className}
          viewBox="0 0 20 20"
          fill="currentColor"
          aria-hidden="true"
        >
          <path
            fillRule="evenodd"
            d="M10 18a8 8 0 1 0 0-16 8 8 0 0 0 0 16Zm3.857-9.809a.75.75 0 0 0-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 1 0-1.06 1.061l2.5 2.5a.75.75 0 0 0 1.137-.089l4-5.5Z"
            clipRule="evenodd"
          />
        </svg>
      );
    case "info":
      return (
        <svg
          className={className}
          viewBox="0 0 20 20"
          fill="currentColor"
          aria-hidden="true"
        >
          <path
            fillRule="evenodd"
            d="M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0ZM8.97 6.69a.75.75 0 0 1 .05 1.06L8.56 9.5h2.19a.75.75 0 0 1 0 1.5H7.75a.75.75 0 0 1-.75-.75V7.75a.75.75 0 0 1 1.3-.06Z"
            clipRule="evenodd"
          />
        </svg>
      );
    case "warn":
      return (
        <svg
          className={className}
          viewBox="0 0 20 20"
          fill="currentColor"
          aria-hidden="true"
        >
          <path
            fillRule="evenodd"
            d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495ZM10 5a.75.75 0 0 1 .75.75v3.5a.75.75 0 0 1-1.5 0v-3.5A.75.75 0 0 1 10 5Zm0 9a1 1 0 1 0 0-2 1 1 0 0 0 0 2Z"
            clipRule="evenodd"
          />
        </svg>
      );
    case "critical":
      return (
        <svg
          className={className}
          viewBox="0 0 20 20"
          fill="currentColor"
          aria-hidden="true"
        >
          <path
            fillRule="evenodd"
            d="M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0Zm-8-5a.75.75 0 0 1 .75.75v4a.75.75 0 0 1-1.5 0v-4A.75.75 0 0 1 10 5Zm0 8a1 1 0 1 0 0-2 1 1 0 0 0 0 2Z"
            clipRule="evenodd"
          />
        </svg>
      );
    default:
      return null;
  }
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
// Freshness badge
// ---------------------------------------------------------------------------

interface FreshnessBadgeProps {
  freshness: "fresh" | "stale" | "unknown";
}

function FreshnessBadge({ freshness }: FreshnessBadgeProps) {
  const label = freshness === "fresh" ? "Fresh" : freshness === "stale" ? "Stale" : "Unknown";
  const base =
    freshness === "fresh"
      ? "text-brand-green-text bg-brand-green-bg"
      : freshness === "stale"
        ? "text-brand-blue bg-blue-50"
        : "text-muted-foreground bg-muted";

  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${base}`}
      aria-label={`Health freshness: ${label}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {label}
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
      <svg
        className="h-3.5 w-3.5 shrink-0"
        viewBox="0 0 20 20"
        fill="currentColor"
        aria-hidden="true"
      >
        <path
          fillRule="evenodd"
          d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495ZM10 6a.75.75 0 0 1 .75.75v3.5a.75.75 0 0 1-1.5 0v-3.5A.75.75 0 0 1 10 6Zm0 5a1 1 0 1 0 0 2 1 1 0 0 0 0-2Z"
          clipRule="evenodd"
        />
      </svg>
      Drift detected
    </span>
  );
}

// ---------------------------------------------------------------------------
// Remediation callout
// ---------------------------------------------------------------------------

interface RemediationCalloutProps {
  callout: GuardUiStateCallout;
  onAction?: () => void;
}

interface ActionButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary";
}

function ActionButton({ variant = "primary", className = "", ...props }: ActionButtonProps) {
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

function RemediationCallout({ callout, onAction }: RemediationCalloutProps) {
  const toneStyle =
    callout.tone === "critical"
      ? "border-l-red-400 bg-red-50/60"
      : callout.tone === "warn"
        ? "border-l-amber-300 bg-amber-50/60"
        : callout.tone === "info"
          ? "border-l-brand-attention bg-brand-attention-bg/60"
          : "border-l-brand-green bg-brand-green-bg/60";

  const textCol =
    callout.tone === "critical"
      ? "text-red-800"
      : callout.tone === "warn"
        ? "text-amber-800"
        : callout.tone === "info"
          ? "text-brand-attention"
          : "text-brand-green-text";

  return (
    <div
      className={`mt-3 rounded-r-lg border border-l-[3px] ${toneStyle} p-3`}
      role="region"
      aria-label="Remediation"
    >
      <div className="flex items-start gap-2">
        <StatusIcon kind={callout.tone === "ok" ? "ok" : callout.tone === "critical" ? "critical" : "info"} className="mt-0.5 h-4 w-4 shrink-0" />
        <div className="min-w-0 flex-1">
          <p className={`text-[13px] font-semibold ${textCol}`}>{callout.headline}</p>
          <p className={`mt-0.5 text-[12px] leading-relaxed ${textCol} opacity-85`}>{callout.explanation}</p>
          {callout.actionLabel && onAction ? (
            <div className="mt-2">
              <ActionButton onClick={onAction}>{callout.actionLabel}</ActionButton>
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

export function ProviderDetailCard({ model, onRemediationAction }: ProviderDetailCardProps) {
  const appearance = useMemo(
    () => HEALTH_APPEARANCE[model.health],
    [model.health],
  );
  const boundaryLabel = useMemo(
    () => BOUNDARY_LABELS[model.computedLevel],
    [model.computedLevel],
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
              {boundaryLabel}
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
