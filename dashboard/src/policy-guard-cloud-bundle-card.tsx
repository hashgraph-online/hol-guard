import { HiMiniCloudArrowUp } from "react-icons/hi2";
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

  return (
    <div className={resolveCloudBundleSurfaceClass(cloudBundleCopy.tone)}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <SectionLabel>Guard Cloud bundle</SectionLabel>
          <div className="mt-3 grid gap-3 sm:grid-cols-3">
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Status</p>
              <div className="mt-1">
                <Tag tone={cloudBundleCopy.tone === "green" ? "green" : "amber"}>{cloudBundleCopy.label}</Tag>
              </div>
            </div>
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Bundle hash</p>
              <p className="mt-1 font-mono text-sm text-brand-dark">
                {cloudBundleCopy.hash?.slice(0, 8) ?? "Unavailable"}
              </p>
            </div>
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Last ack</p>
              <p className="mt-1 text-sm text-brand-dark">
                {lastAckAt ? formatRelativeTime(lastAckAt) : "Not yet"}
              </p>
            </div>
          </div>
          <p className="mt-2 text-sm text-brand-dark/75">{cloudBundleCopy.detail}</p>
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
