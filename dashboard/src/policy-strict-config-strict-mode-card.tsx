import {
  HiMiniArrowPath,
  HiMiniCheckCircle,
  HiMiniClipboardDocument,
  HiMiniShieldCheck,
} from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import { formatRelativeTime } from "./approval-center-utils";
import { POLICY_PANEL_CARD_CLASS } from "./policy-strict-config-surfaces";
import { formatPolicyDateTime } from "./policy-workspace-helpers";

type PolicyStrictModeCardProps = {
  isStrict: boolean;
  controlsDisabled: boolean;
  localPolicyHash: string | null;
  daemonAckSynced: boolean;
  daemonAckLabel: string;
  lastAckAt: string | null;
  lastReloadFormatted: string | null;
  lastReloadAt: string | null;
  reloadingPolicy: boolean;
  onStrictToggle: () => void;
  onCopyHash: () => void;
  onOpenSettings?: () => void;
  onReloadPolicy?: () => void;
};

export function PolicyStrictModeCard({
  isStrict,
  controlsDisabled,
  localPolicyHash,
  daemonAckSynced,
  daemonAckLabel,
  lastAckAt,
  lastReloadFormatted,
  lastReloadAt,
  reloadingPolicy,
  onStrictToggle,
  onCopyHash,
  onOpenSettings,
  onReloadPolicy,
}: PolicyStrictModeCardProps) {
  return (
    <div className={`${POLICY_PANEL_CARD_CLASS} p-5`}>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex min-w-0 items-start gap-3">
          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue">
            <HiMiniShieldCheck className="h-5 w-5" aria-hidden="true" />
          </span>
          <div className="min-w-0">
            <h3 className="text-base font-semibold text-brand-dark">Strict mode</h3>
            <p className="mt-1 text-sm leading-relaxed text-slate-600">
              Local enforcement tuning when no remembered rule, Cloud policy, or Cloud exception matches.
            </p>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <span className="text-xs font-medium text-slate-500">{isStrict ? "Enabled" : "Disabled"}</span>
          <button
            type="button"
            role="switch"
            aria-checked={isStrict}
            aria-label="Toggle strict mode"
            disabled={controlsDisabled}
            onClick={onStrictToggle}
            className={`relative h-7 w-12 shrink-0 rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/60 ${
              isStrict ? "bg-brand-blue" : "bg-slate-200"
            } ${controlsDisabled ? "cursor-not-allowed opacity-50" : "cursor-pointer"}`}
          >
            <span
              className={`absolute top-0.5 left-0.5 h-6 w-6 rounded-full bg-white shadow-sm transition-transform ${
                isStrict ? "translate-x-5" : "translate-x-0"
              }`}
            />
          </button>
        </div>
      </div>

      <dl className="mt-5 grid gap-4 border-t border-slate-100 pt-4 sm:grid-cols-2 xl:grid-cols-4">
        <div>
          <dt className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Strict mode</dt>
          <dd className="mt-1.5 text-sm font-medium text-brand-dark">{isStrict ? "Enabled" : "Disabled"}</dd>
        </div>
        <div className="min-w-0">
          <dt className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Policy hash</dt>
          <dd className="mt-1.5 flex min-w-0 items-center gap-1.5 font-mono text-sm text-brand-dark">
            <span className="truncate" title={localPolicyHash ?? undefined}>
              {localPolicyHash}
            </span>
            <button
              type="button"
              onClick={onCopyHash}
              className="shrink-0 rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-brand-dark"
              aria-label="Copy policy hash"
            >
              <HiMiniClipboardDocument className="h-4 w-4" aria-hidden="true" />
            </button>
          </dd>
        </div>
        <div>
          <dt className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Daemon ack</dt>
          <dd className="mt-1.5 flex items-center gap-1.5 text-sm text-brand-dark">
            {daemonAckSynced ? (
              <HiMiniCheckCircle className="h-4 w-4 shrink-0 text-emerald-600" aria-hidden="true" />
            ) : null}
            <span>
              {daemonAckLabel}
              {lastAckAt ? ` · ${formatRelativeTime(lastAckAt)}` : ""}
            </span>
          </dd>
        </div>
        <div>
          <dt className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Last reload</dt>
          <dd className="mt-1.5 text-sm text-brand-dark">
            {lastReloadFormatted ?? (lastReloadAt ? formatRelativeTime(lastReloadAt) : "Unavailable")}
          </dd>
          <p className="mt-1 flex items-center gap-1 text-xs text-emerald-700">
            <HiMiniCheckCircle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
            Auto-reload on
          </p>
        </div>
      </dl>

      {!isStrict && onOpenSettings ? (
        <div className="mt-4 border-t border-slate-100 pt-4">
          <ActionButton variant="secondary" onClick={onOpenSettings}>
            Enable in Settings
          </ActionButton>
        </div>
      ) : null}

      {onReloadPolicy ? (
        <div className="mt-4 flex justify-end border-t border-slate-100 pt-4">
          <ActionButton variant="secondary" onClick={onReloadPolicy} disabled={reloadingPolicy}>
            <HiMiniArrowPath className={`mr-1.5 h-4 w-4 ${reloadingPolicy ? "animate-spin" : ""}`} aria-hidden="true" />
            Reload policy
          </ActionButton>
        </div>
      ) : null}
    </div>
  );
}
