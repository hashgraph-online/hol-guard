import { useCallback, useState } from "react";
import { HiMiniCloudArrowUp } from "react-icons/hi2";
import { ActionButton, EmptyState, SectionLabel } from "./approval-center-primitives";
import type { GuardRuntimeSnapshot } from "./guard-types";
import { PolicyCloudExceptionRequestPanel } from "./policy-cloud-exception-request-panel";
import { resolveCloudPolicyControlsUrl } from "./policy-workspace-helpers";

type PolicyCloudExceptionsTabProps = {
  snapshot: GuardRuntimeSnapshot;
};

function resolveCloudExceptionsConnected(snapshot: GuardRuntimeSnapshot): boolean {
  return snapshot.cloud_state === "paired_active" || snapshot.cloud_state === "paired_waiting";
}

export function PolicyCloudExceptionsTab({
  snapshot,
}: PolicyCloudExceptionsTabProps) {
  const [requestOpen, setRequestOpen] = useState(false);
  const cloudControlsUrl = resolveCloudPolicyControlsUrl(snapshot);
  const cloudConnected = resolveCloudExceptionsConnected(snapshot);
  const connectUrl = snapshot.connect_url?.trim() || null;

  const handleOpenRequestPanel = useCallback(() => {
    setRequestOpen(true);
  }, []);

  const handleCloseRequestPanel = useCallback(() => {
    setRequestOpen(false);
  }, []);

  const handleRequestSubmitted = useCallback(() => {
    setRequestOpen(false);
  }, []);

  if (requestOpen) {
    return (
      <PolicyCloudExceptionRequestPanel
        snapshot={snapshot}
        onSubmitted={handleRequestSubmitted}
        onCancel={handleCloseRequestPanel}
      />
    );
  }

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
          onClick={handleOpenRequestPanel}
          disabled={!cloudConnected}
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
