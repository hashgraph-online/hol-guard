import { HiMiniAdjustmentsHorizontal, HiMiniInformationCircle } from "react-icons/hi2";
import { ActionButton, SectionLabel } from "./approval-center-primitives";
import type { GuardRuntimeSnapshot } from "./guard-types";
import { PolicyEnforcementPreviewCard } from "./policy-strict-config-enforcement-preview";
import { POLICY_PANEL_CARD_CLASS } from "./policy-strict-config-surfaces";

type PolicyStrictConfigTabProps = {
  snapshot: GuardRuntimeSnapshot;
  cloudControlsUrl?: string | null;
  onOpenSettings?: () => void;
};

export function PolicyStrictConfigTab({
  snapshot,
  cloudControlsUrl = null,
  onOpenSettings,
}: PolicyStrictConfigTabProps) {
  const pendingInboxCount = snapshot.queue_summary?.remaining_pending_count ?? snapshot.pending_count ?? 0;

  return (
    <div className="space-y-4">
      <section className={`${POLICY_PANEL_CARD_CLASS} p-4 sm:p-6`}>
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex min-w-0 gap-3">
            <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue">
              <HiMiniInformationCircle className="h-5 w-5" aria-hidden="true" />
            </span>
            <div>
              <SectionLabel>Decision order</SectionLabel>
              <h2 className="mt-1 text-base font-semibold text-brand-dark">Policy explains. Settings configures.</h2>
              <p className="mt-1 max-w-2xl text-sm leading-relaxed text-slate-600">
                Use this page to understand which rule wins. Change security presets, risky action handling, and advanced fallback behavior in one place under Settings.
              </p>
              {pendingInboxCount > 0 ? (
                <p className="mt-2 text-xs leading-relaxed text-slate-500">
                  {pendingInboxCount.toLocaleString()} pending {pendingInboxCount === 1 ? "request may" : "requests may"} be affected by future rule changes.
                </p>
              ) : null}
            </div>
          </div>
          {onOpenSettings ? (
            <div className="shrink-0 sm:pt-1">
              <ActionButton onClick={onOpenSettings} variant="primary">
                <HiMiniAdjustmentsHorizontal className="mr-1.5 h-4 w-4" aria-hidden="true" />
                Open protection rules
              </ActionButton>
            </div>
          ) : null}
        </div>
      </section>

      <PolicyEnforcementPreviewCard cloudControlsUrl={cloudControlsUrl} />
    </div>
  );
}
