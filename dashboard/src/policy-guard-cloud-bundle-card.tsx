import { useCallback } from "react";
import { HiMiniCheckCircle, HiMiniClipboardDocument, HiMiniCloudArrowUp } from "react-icons/hi2";
import { ActionButton, SectionLabel, Tag } from "./approval-center-primitives";
import { formatRelativeTime } from "./approval-center-utils";
import type { GuardRuntimeSnapshot } from "./guard-types";
import {
  resolveCloudBundleSurfaceClass,
  resolveCloudPolicyBundleCopy,
  resolveCloudPolicyControlsUrl,
} from "./policy-workspace-helpers";

type PolicyGuardCloudBundleCardProps = {
  snapshot: GuardRuntimeSnapshot;
};

export function PolicyGuardCloudBundleCard({ snapshot }: PolicyGuardCloudBundleCardProps) {
  const cloudBundleCopy = resolveCloudPolicyBundleCopy(snapshot);
  const cloudControlsUrl = resolveCloudPolicyControlsUrl(snapshot);
  const lastAckAt =
    snapshot.runtime_state?.last_heartbeat_at?.trim() ?? snapshot.generated_at?.trim() ?? null;
  const policyHash = cloudBundleCopy?.hash?.slice(0, 8) ?? null;

  const handleCopyHash = useCallback(() => {
    const fullHash = cloudBundleCopy?.hash?.trim();
    if (!fullHash || !navigator.clipboard?.writeText) {
      return;
    }
    void navigator.clipboard.writeText(fullHash);
  }, [cloudBundleCopy?.hash]);

  if (!cloudBundleCopy) {
    return (
      <div className="rounded-2xl border border-slate-200/70 bg-slate-50/70 p-4 shadow-sm">
        <SectionLabel>Guard Cloud bundle</SectionLabel>
        <p className="mt-2 text-sm text-brand-dark/75">
          Not connected. Remembered Cloud rules appear when Guard Cloud syncs a bundle.
        </p>
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

  return (
    <div className={resolveCloudBundleSurfaceClass(cloudBundleCopy.tone)}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <SectionLabel>Guard Cloud bundle</SectionLabel>
          <div className="mt-3 grid gap-4 sm:grid-cols-3">
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Status</p>
              <div className="mt-1.5 flex items-center gap-1.5">
                {synced ? (
                  <HiMiniCheckCircle className="h-4 w-4 text-emerald-600" aria-hidden="true" />
                ) : null}
                <Tag tone={synced ? "green" : "amber"}>{cloudBundleCopy.label}</Tag>
              </div>
              <p className="mt-1 text-xs text-slate-500">{cloudBundleCopy.detail}</p>
            </div>
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Policy hash</p>
              <div className="mt-1.5 flex items-center gap-1.5">
                <p className="font-mono text-sm text-brand-dark">{policyHash ?? "Unavailable"}</p>
                {policyHash ? (
                  <button
                    type="button"
                    onClick={handleCopyHash}
                    className="rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-brand-dark"
                    aria-label="Copy policy hash"
                  >
                    <HiMiniClipboardDocument className="h-4 w-4" aria-hidden="true" />
                  </button>
                ) : null}
              </div>
            </div>
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Last ack</p>
              <div className="mt-1.5 flex items-center gap-1.5">
                {lastAckAt ? (
                  <HiMiniCheckCircle className="h-4 w-4 text-emerald-600" aria-hidden="true" />
                ) : null}
                <p className="text-sm text-brand-dark">{lastAckAt ? formatRelativeTime(lastAckAt) : "Not yet"}</p>
              </div>
            </div>
          </div>
        </div>
        {cloudControlsUrl ? (
          <ActionButton href={cloudControlsUrl} variant="secondary">
            <HiMiniCloudArrowUp className="mr-1.5 h-4 w-4" aria-hidden="true" />
            Open Guard Cloud
          </ActionButton>
        ) : null}
      </div>
    </div>
  );
}
