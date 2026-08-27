import { useCallback } from "react";
import {
  HiMiniShieldCheck,
  HiMiniExclamationTriangle,
} from "react-icons/hi2";
import { SectionLabel } from "../approval-center-primitives";
import { ChannelRow, SummaryCallout } from "./protection-status-channels";
import type {
  GuardLocalProtectionStatusViewModel,
  GuardUiProtectionChannelState,
} from "./protection-status-view-model";

// ---------------------------------------------------------------------------
// Channel keys in display order
// ---------------------------------------------------------------------------

const CHANNEL_KEYS = [
  "interception" as const,
  "policy" as const,
  "assurance" as const,
  "selfProtection" as const,
  "cloudSync" as const,
] as const;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function worstChannel(
  vm: GuardLocalProtectionStatusViewModel,
): GuardUiProtectionChannelState {
  // Scan worst→best so an inactive/unknown/degraded channel takes precedence
  // over active channels and the header never overstates protection posture.
  const order: GuardUiProtectionChannelState[] = [
    "inactive",
    "unknown",
    "degraded",
    "active",
  ];
  for (const level of order) {
    for (const key of CHANNEL_KEYS) {
      if (vm[key] === level) return level;
    }
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// ProtectionStatusPanel
// ---------------------------------------------------------------------------

export interface ProtectionStatusPanelProps {
  readonly vm: GuardLocalProtectionStatusViewModel;
  readonly onAction?: () => void;
}

export function ProtectionStatusPanel({
  vm,
  onAction,
}: ProtectionStatusPanelProps) {
  const handleAction = useCallback(() => {
    onAction?.();
  }, [onAction]);

  const worst = worstChannel(vm);

  const HeaderIcon =
    worst === "active" ? HiMiniShieldCheck : HiMiniExclamationTriangle;
  let headerIconClass = "text-red-600";
  let headerBorder = "border-red-200 bg-red-50/60";
  if (worst === "active") {
    headerIconClass = "text-brand-green";
    headerBorder = "border-brand-green/20 bg-brand-green/[0.04]";
  } else if (worst === "degraded") {
    headerIconClass = "text-amber-600";
    headerBorder = "border-amber-200 bg-amber-50/60";
  }

  return (
    <section
      className={`rounded-2xl border ${headerBorder} p-5 shadow-sm`}
      aria-label="Local protection status"
    >
      <div className="flex items-start gap-3">
        <span
          className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-white/80"
          aria-hidden="true"
        >
          <HeaderIcon className={`h-5 w-5 ${headerIconClass}`} />
        </span>
        <div className="min-w-0 flex-1 space-y-4">
          <div>
            <SectionLabel>Local protection status</SectionLabel>
            <p className="mt-1 text-sm font-medium text-brand-dark">
              {vm.summary.headline}
            </p>
          </div>

          {/* Five channel rows */}
          <div
            className="divide-y divide-slate-100 rounded-xl border border-slate-100 bg-white/80 overflow-hidden"
            role="list"
            aria-label="Protection channels"
          >
            {CHANNEL_KEYS.map((key) => (
              <div key={key} className="px-4" role="listitem">
                <ChannelRow channelKey={key} state={vm[key]} />
              </div>
            ))}
          </div>

          {/* Summary callout */}
          <SummaryCallout callout={vm.summary} onAction={handleAction} />
        </div>
      </div>
    </section>
  );
}
