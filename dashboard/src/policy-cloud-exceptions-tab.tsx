import { useCallback } from "react";
import { HiMiniCloudArrowUp } from "react-icons/hi2";
import { ActionButton, EmptyState, SectionLabel } from "./approval-center-primitives";
import type { GuardRuntimeSnapshot } from "./guard-types";
import { resolveCloudPolicyControlsUrl } from "./policy-workspace-helpers";

type PolicyCloudExceptionsTabProps = {
  snapshot: GuardRuntimeSnapshot;
  onRequestCloudException?: () => void;
};

function resolveCloudExceptionsConnected(snapshot: GuardRuntimeSnapshot): boolean {
  return snapshot.cloud_state === "paired_active" || snapshot.cloud_state === "paired_waiting";
}

export function PolicyCloudExceptionsTab({
  snapshot,
  onRequestCloudException,
}: PolicyCloudExceptionsTabProps) {
  const cloudControlsUrl = resolveCloudPolicyControlsUrl(snapshot);
  const cloudConnected = resolveCloudExceptionsConnected(snapshot);
  const connectUrl = snapshot.connect_url?.trim() || null;

  const handleRequestCloudException = useCallback(() => {
    onRequestCloudException?.();
  }, [onRequestCloudException]);

  return (
    <div className="space-y-4">
      <div className="rounded-2xl border border-brand-blue/10 bg-brand-blue/[0.03] p-5 shadow-sm">
        <SectionLabel>Cloud risk acceptances</SectionLabel>
        <p className="mt-2 text-sm text-brand-dark/75">
          Cloud exceptions are governed risk acceptances with an owner, approver, reason, expiry, and
          signed bundle. They are managed in Guard Cloud and synced to this device after approval.
        </p>
        <p className="mt-2 text-sm text-slate-600">
          Fast remembered approvals from Review stay on the Remembered rules tab. They are separate
          from Cloud exceptions.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <ActionButton
          variant="primary"
          onClick={handleRequestCloudException}
          disabled={!cloudConnected || onRequestCloudException === undefined}
        >
          Request cloud exception
        </ActionButton>
        {cloudControlsUrl ? (
          <ActionButton href={cloudControlsUrl} variant="secondary">
            <HiMiniCloudArrowUp className="mr-1.5 h-4 w-4" aria-hidden="true" />
            Open Guard Cloud
          </ActionButton>
        ) : null}
        {!cloudConnected && connectUrl ? (
          <ActionButton href={connectUrl} variant="secondary">
            Connect Guard Cloud
          </ActionButton>
        ) : null}
      </div>

      {!cloudConnected ? (
        <EmptyState
          title="Guard Cloud is not connected"
          body="Cloud exceptions are managed in Guard Cloud. Connect this device to request a risk acceptance or view synced exceptions here."
          tone="teach"
        />
      ) : (
        <EmptyState
          title="No Cloud exceptions synced yet"
          body="Approved Cloud risk acceptances will appear here after Guard Cloud syncs a signed policy bundle to this device."
          tone="teach"
        />
      )}
    </div>
  );
}

export function PolicyRememberedRulesHelper() {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50/80 p-4 text-sm text-slate-600">
      <p className="font-medium text-brand-dark">Remembered approvals vs Cloud exceptions</p>
      <ul className="mt-2 list-disc space-y-1 pl-5">
        <li>Review and Inbox keep fast allow/block decisions for the work in front of you.</li>
        <li>Remembered rules on this tab explain what Guard will do next time for matching actions.</li>
        <li>Cloud exceptions are separate governed risk acceptances managed in Guard Cloud.</li>
      </ul>
    </div>
  );
}
