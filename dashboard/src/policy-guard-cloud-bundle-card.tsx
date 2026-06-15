import { useCallback } from "react";
import { HiMiniCheckCircle, HiMiniClipboardDocument, HiMiniCloudArrowUp } from "react-icons/hi2";
import { ActionButton, SectionLabel, Tag } from "./approval-center-primitives";
import { formatRelativeTime } from "./approval-center-utils";
import type { GuardRuntimeSnapshot } from "./guard-types";
import {
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
  const policyHash = cloudBundleCopy?.hash?.trim() ?? null;
  const policyHashShort = policyHash?.slice(0, 8) ?? null;
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
    <div className="rounded-2xl border border-slate-200/70 bg-white p-4 shadow-sm">
      <SectionLabel>Guard Cloud bundle</SectionLabel>
      <div className="mt-3 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="grid flex-1 gap-4 sm:grid-cols-3">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Status</p>
            <div className="mt-1.5 flex items-center gap-1.5">
              {synced ? (
                <HiMiniCheckCircle className="h-4 w-4 text-emerald-600" aria-hidden="true" />
              ) : null}
              <Tag tone={synced ? "green" : "amber"}>{synced ? "Synced" : cloudBundleCopy.label}</Tag>
            </div>
            <p className="mt-1 text-xs text-slate-500">
              {synced ? "All policies up to date" : cloudBundleCopy.detail}
            </p>
          </div>
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Bundle hash</p>
            <div className="mt-1.5 flex items-center gap-1.5">
              <p className="font-mono text-sm text-brand-dark">{policyHashShort ?? "Unavailable"}</p>
              {policyHashShort ? (
                <button
                  type="button"
                  onClick={handleCopyHash}
                  className="rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-brand-dark"
                  aria-label="Copy bundle hash"
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
            {bundleVersion ? <p className="mt-1 text-xs text-slate-500">{bundleVersion}</p> : null}
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
