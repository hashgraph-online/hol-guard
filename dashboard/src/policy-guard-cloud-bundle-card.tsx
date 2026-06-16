import { useCallback } from "react";
import { HiMiniCheckCircle, HiMiniClipboardDocument, HiMiniCloudArrowUp } from "react-icons/hi2";
import { ActionButton, SectionLabel, Tag } from "./approval-center-primitives";
import { formatRelativeTime } from "./approval-center-utils";
import type { GuardRuntimeSnapshot } from "./guard-types";
import {
  formatCloudBundleHashDisplay,
  resolveCloudBundleStatusSubtitle,
} from "./policy-guard-cloud-bundle-helpers";
import {
  resolveCloudPolicyBundleCopy,
  resolveCloudExceptionsConnected,
  resolveCloudPolicyControlsUrl,
} from "./policy-workspace-helpers";

type PolicyGuardCloudBundleCardProps = {
  snapshot: GuardRuntimeSnapshot;
};

export function PolicyGuardCloudBundleCard({ snapshot }: PolicyGuardCloudBundleCardProps) {
  const cloudBundleCopy = resolveCloudPolicyBundleCopy(snapshot);
  const cloudControlsUrl = resolveCloudPolicyControlsUrl(snapshot);
  const cloudConnected = resolveCloudExceptionsConnected(snapshot);
  const lastAckAt =
    snapshot.cloud_policy_last_ack_at?.trim() ??
    snapshot.runtime_state?.last_heartbeat_at?.trim() ??
    snapshot.generated_at?.trim() ??
    null;
  const policyHash = cloudBundleCopy?.hash?.trim() ?? null;
  const policyHashDisplay = formatCloudBundleHashDisplay(policyHash);
  const bundleVersion = snapshot.cloud_policy_bundle_version?.trim() ?? null;

  const handleCopyHash = useCallback(() => {
    if (!policyHash || !navigator.clipboard?.writeText) {
      return;
    }
    void navigator.clipboard.writeText(policyHash);
  }, [policyHash]);

  if (!cloudBundleCopy) {
    return (
      <div className="rounded-2xl border border-slate-200/70 bg-white p-4 shadow-sm">
        <SectionLabel>Guard Cloud bundle</SectionLabel>
        {cloudConnected ? (
          <>
            <p className="mt-2 text-sm font-medium text-brand-dark">
              {snapshot.cloud_state_label?.trim() || "Connected to Guard Cloud"}
            </p>
            <p className="mt-1 text-sm leading-relaxed text-brand-dark/75">
              {snapshot.cloud_state_detail?.trim() ||
                "Guard Cloud is connected. Policy bundle details will appear after the next successful sync."}
            </p>
          </>
        ) : (
          <p className="mt-2 text-sm leading-relaxed text-brand-dark/75">
            Guard Cloud is not connected. Remembered Cloud rules appear when Guard Cloud syncs a bundle.
          </p>
        )}
        {cloudControlsUrl ? (
          <div className="mt-3">
            <ActionButton href={cloudControlsUrl} variant="secondary">
              <HiMiniCloudArrowUp className="mr-1.5 h-4 w-4" aria-hidden="true" />
              Open Guard Cloud
            </ActionButton>
          </div>
        ) : null}
      </div>
    );
  }

  const synced = cloudBundleCopy.tone === "green";
  const statusSubtitle = resolveCloudBundleStatusSubtitle(cloudBundleCopy);
  const showDetail = !synced;

  return (
    <div className="rounded-2xl border border-slate-200/70 bg-white p-4 shadow-sm">
      <SectionLabel>Guard Cloud bundle</SectionLabel>

      <div className="mt-3 space-y-3">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <dl className="grid min-w-0 flex-1 grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
            <div className="min-w-0">
              <dt className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Status</dt>
              <dd className="mt-1.5">
                <div className="flex min-w-0 items-center gap-1.5">
                  {synced ? (
                    <HiMiniCheckCircle className="h-4 w-4 shrink-0 text-emerald-600" aria-hidden="true" />
                  ) : null}
                  <Tag tone={synced ? "green" : "amber"}>{synced ? "Synced" : cloudBundleCopy.label}</Tag>
                </div>
                <p className="mt-1 text-xs leading-relaxed text-slate-500">{statusSubtitle}</p>
              </dd>
            </div>

            <div className="min-w-0">
              <dt className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Bundle hash</dt>
              <dd className="mt-1.5 flex min-w-0 items-center gap-1.5">
                <p className="truncate font-mono text-sm text-brand-dark" title={policyHash ?? undefined}>
                  {policyHashDisplay}
                </p>
                {policyHash ? (
                  <button
                    type="button"
                    onClick={handleCopyHash}
                    className="shrink-0 rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-brand-dark"
                    aria-label="Copy bundle hash"
                  >
                    <HiMiniClipboardDocument className="h-4 w-4" aria-hidden="true" />
                  </button>
                ) : null}
              </dd>
            </div>

            <div className="min-w-0 sm:col-span-2 xl:col-span-1">
              <dt className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Last ack</dt>
              <dd className="mt-1.5">
                <div className="flex min-w-0 items-center gap-1.5">
                  {lastAckAt && synced ? (
                    <HiMiniCheckCircle className="h-4 w-4 shrink-0 text-emerald-600" aria-hidden="true" />
                  ) : null}
                  <p className="text-sm text-brand-dark">{lastAckAt ? formatRelativeTime(lastAckAt) : "Not yet"}</p>
                </div>
                {bundleVersion ? (
                  <p className="mt-1 truncate text-xs text-slate-500" title={bundleVersion}>
                    {bundleVersion}
                  </p>
                ) : null}
              </dd>
            </div>
          </dl>

          {cloudControlsUrl ? (
            <div className="w-full shrink-0 sm:w-auto lg:pt-5">
              <ActionButton href={cloudControlsUrl} variant="secondary">
                <HiMiniCloudArrowUp className="mr-1.5 h-4 w-4" aria-hidden="true" />
                Open Guard Cloud
              </ActionButton>
            </div>
          ) : null}
        </div>

        {showDetail ? (
          <p className="rounded-xl border border-amber-200/80 bg-amber-50/60 px-3 py-2 text-sm leading-relaxed text-slate-700">
            {cloudBundleCopy.detail}
          </p>
        ) : null}
      </div>
    </div>
  );
}
