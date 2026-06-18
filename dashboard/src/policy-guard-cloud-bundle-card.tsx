import { useCallback, type ReactNode } from "react";
import { HiMiniCheckCircle, HiMiniClipboardDocument, HiMiniCloudArrowUp } from "react-icons/hi2";
import { ActionButton, SectionLabel, Tag } from "./approval-center-primitives";
import { formatRelativeTime } from "./approval-center-utils";
import type { GuardRuntimeSnapshot } from "./guard-types";
import {
  formatCloudBundleHashDisplay,
  resolveCloudBundleStatusSubtitle,
} from "./policy-guard-cloud-bundle-helpers";
import { POLICY_SUMMARY_CARD_CLASS } from "./policy-summary-surfaces";
import {
  resolveCloudPolicyBundleCopy,
  resolveCloudExceptionsConnected,
  resolveCloudPolicyControlsUrl,
} from "./policy-workspace-helpers";

type PolicyGuardCloudBundleCardProps = {
  snapshot: GuardRuntimeSnapshot;
};

function CloudBundleHeader({ cloudControlsUrl }: { cloudControlsUrl: string | null }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2">
      <SectionLabel>Guard Cloud bundle</SectionLabel>
      {cloudControlsUrl ? (
        <ActionButton href={cloudControlsUrl} variant="secondary">
          <HiMiniCloudArrowUp className="mr-1.5 h-4 w-4" aria-hidden="true" />
          Open Guard Cloud
        </ActionButton>
      ) : null}
    </div>
  );
}

function BundleStat({
  label,
  children,
  className = "",
}: {
  label: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={`min-w-0 ${className}`}>
      <dt className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{label}</dt>
      <dd className="mt-1 min-w-0">{children}</dd>
    </div>
  );
}

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
      <div className={`${POLICY_SUMMARY_CARD_CLASS} self-start p-4`}>
        <CloudBundleHeader cloudControlsUrl={cloudControlsUrl} />
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
      </div>
    );
  }

  const synced = cloudBundleCopy.tone === "green";
  const statusSubtitle = resolveCloudBundleStatusSubtitle(cloudBundleCopy);

  return (
    <div className={`${POLICY_SUMMARY_CARD_CLASS} self-start p-4`}>
      <CloudBundleHeader cloudControlsUrl={cloudControlsUrl} />

      <dl className="mt-3 flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-start sm:gap-x-8 sm:gap-y-3">
        <BundleStat label="Status" className="sm:min-w-[7.5rem] sm:max-w-[9rem]">
          <div className="flex items-center gap-1.5">
            {synced ? (
              <HiMiniCheckCircle className="h-3.5 w-3.5 shrink-0 text-emerald-600" aria-hidden="true" />
            ) : null}
            <Tag tone={synced ? "green" : "amber"}>{synced ? "Synced" : cloudBundleCopy.label}</Tag>
          </div>
        </BundleStat>

        <BundleStat label="Bundle hash" className="min-w-0 flex-1 sm:min-w-[10rem]">
          <div className="flex min-w-0 items-center gap-1">
            <span
              className="min-w-0 font-mono text-sm text-brand-dark break-all sm:break-normal sm:truncate"
              title={policyHash ?? undefined}
            >
              {policyHashDisplay}
            </span>
            {policyHash ? (
              <button
                type="button"
                onClick={handleCopyHash}
                className="shrink-0 rounded-md p-0.5 text-slate-400 hover:bg-slate-100 hover:text-brand-dark"
                aria-label="Copy bundle hash"
              >
                <HiMiniClipboardDocument className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            ) : null}
          </div>
        </BundleStat>

        <BundleStat label="Last ack" className="sm:min-w-[6.5rem] sm:max-w-[9rem]">
          <p className="text-sm text-brand-dark">{lastAckAt ? formatRelativeTime(lastAckAt) : "Not yet"}</p>
          {bundleVersion ? (
            <p className="mt-0.5 truncate text-xs text-slate-500" title={bundleVersion}>
              {bundleVersion}
            </p>
          ) : null}
        </BundleStat>
      </dl>

      {synced ? (
        <p className="mt-2 text-xs text-slate-500">{statusSubtitle}</p>
      ) : (
        <p className="mt-3 rounded-xl border border-amber-200/80 bg-amber-50/60 px-3 py-2 text-sm leading-snug text-slate-700">
          {cloudBundleCopy.detail}
        </p>
      )}
    </div>
  );
}
