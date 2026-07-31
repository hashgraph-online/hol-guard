import type { ReactNode } from "react";
import {
  HiMiniShieldCheck,
  HiMiniExclamationTriangle,
  HiMiniPauseCircle,
  HiMiniQuestionMarkCircle,
} from "react-icons/hi2";
import type {
  GuardUiProtectionChannelState,
  GuardUiStateCallout,
} from "./protection-status-view-model";

// ---------------------------------------------------------------------------
// Channel metadata
// ---------------------------------------------------------------------------

interface ChannelMeta {
  label: string;
  stateLabel: string;
  explanation: string;
}

const CHANNEL_META: Record<string, ChannelMeta> = {
  interception: {
    label: "Interception",
    stateLabel: "Active",
    explanation: "All commands are intercepted by Guard before execution.",
  },
  policy: {
    label: "Policy",
    stateLabel: "Active",
    explanation: "Commands are evaluated against your policy before execution.",
  },
  assurance: {
    label: "Assurance",
    stateLabel: "Active",
    explanation: "Isolation provider is running and verified.",
  },
  selfProtection: {
    label: "Self-protection",
    stateLabel: "Active",
    explanation: "Guard protects its own processes and configuration.",
  },
  cloudSync: {
    label: "Cloud sync",
    stateLabel: "Active",
    explanation: "Receipts and evidence are syncing to the cloud.",
  },
};

// ---------------------------------------------------------------------------
// State → visual mapping
// ---------------------------------------------------------------------------

interface ChannelRowStyles {
  badgeTone: "success" | "warning" | "destructive" | "default";
  stateColor: string;
  Icon: React.ComponentType<{ className?: string }>;
  stateColorClass: string;
}

function resolveStyles(
  state: GuardUiProtectionChannelState,
): ChannelRowStyles {
  if (state === "active") {
    return {
      badgeTone: "success",
      stateColor: "text-brand-green",
      Icon: HiMiniShieldCheck,
      stateColorClass: "bg-brand-green/10 text-brand-green",
    };
  }
  if (state === "degraded") {
    return {
      badgeTone: "warning",
      stateColor: "text-amber-600",
      Icon: HiMiniExclamationTriangle,
      stateColorClass: "bg-amber-50 text-amber-700",
    };
  }
  if (state === "inactive") {
    return {
      badgeTone: "destructive",
      stateColor: "text-red-600",
      Icon: HiMiniPauseCircle,
      stateColorClass: "bg-red-50 text-red-700",
    };
  }
  // unknown
  return {
    badgeTone: "default",
    stateColor: "text-slate-400",
    Icon: HiMiniQuestionMarkCircle,
    stateColorClass: "bg-slate-50 text-slate-500",
  };
}

// ---------------------------------------------------------------------------
// State label helper
// ---------------------------------------------------------------------------

function stateLabelFor(state: GuardUiProtectionChannelState): string {
  if (state === "active") return "Active";
  if (state === "degraded") return "Degraded";
  if (state === "inactive") return "Inactive";
  return "Unknown";
}

// ---------------------------------------------------------------------------
// ChannelRow
// ---------------------------------------------------------------------------

interface ChannelRowProps {
  readonly channelKey: string;
  readonly state: GuardUiProtectionChannelState;
}

export function ChannelRow({ channelKey, state }: ChannelRowProps) {
  const meta = CHANNEL_META[channelKey];
  if (!meta) return null;

  const { badgeTone, stateColor, Icon, stateColorClass } = resolveStyles(state);
  const sl = stateLabelFor(state);

  return (
    <div className="flex items-center justify-between gap-3 py-2.5">
      <div className="flex items-center gap-3 min-w-0">
        <span
          className={`inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-full ${stateColorClass}`}
          aria-hidden="true"
        >
          <Icon className="h-3.5 w-3.5" />
        </span>
        <div className="min-w-0">
          <p className="text-sm font-medium text-brand-dark">{meta.label}</p>
          <p className="text-xs text-muted-foreground">{meta.explanation}</p>
        </div>
      </div>
      <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${stateColor}`}>
        <Icon className="h-3.5 w-3.5" aria-hidden="true" />
        {sl}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// SummaryCallout
// ---------------------------------------------------------------------------

interface SummaryCalloutProps {
  readonly callout: GuardUiStateCallout;
  readonly onAction?: () => void;
}

export function SummaryCallout({ callout, onAction }: SummaryCalloutProps) {
  const toneBorder: Record<string, string> = {
    ok: "border-brand-green/20 bg-brand-green/[0.03]",
    info: "border-brand-blue/20 bg-brand-blue/[0.03]",
    warn: "border-amber-200 bg-amber-50/60",
    critical: "border-red-200 bg-red-50/60",
  };

  const toneIconColor: Record<string, string> = {
    ok: "text-brand-green",
    info: "text-brand-blue",
    warn: "text-amber-600",
    critical: "text-red-600",
  };

  const Icon = callout.tone === "ok" ? HiMiniShieldCheck : HiMiniExclamationTriangle;

  return (
    <div
      className={`mt-4 rounded-xl border px-4 py-3 ${toneBorder[callout.tone]}`}
      role="region"
      aria-label="Protection summary"
    >
      <div className="flex items-start gap-3">
        <Icon
          className={`mt-0.5 h-4 w-4 shrink-0 ${toneIconColor[callout.tone]}`}
          aria-hidden="true"
        />
        <div className="min-w-0 flex-1 space-y-1.5">
          <p className="text-sm font-semibold text-brand-dark">
            {callout.headline}
          </p>
          <p className="text-xs leading-relaxed text-muted-foreground">
            {callout.explanation}
          </p>
          {callout.actionLabel && onAction && (
            <button
              type="button"
              onClick={onAction}
              className="inline-flex items-center gap-1 text-xs font-medium text-brand-blue hover:underline focus:outline-none focus:ring-2 focus:ring-brand-blue/30 rounded"
            >
              {callout.actionLabel}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
