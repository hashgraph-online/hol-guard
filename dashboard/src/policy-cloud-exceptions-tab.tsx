import { useCallback, useEffect, useMemo, useState } from "react";
import { ActionButton, EmptyState } from "./approval-center-primitives";
import { fetchCloudExceptionRequests, fetchCloudExceptions } from "./guard-api";
import type { GuardCloudException } from "./guard-types";
import type { GuardCloudExceptionRequestItem } from "./guard-api";
import type { GuardRuntimeSnapshot } from "./guard-types";
import { PolicyCloudExceptionDetailPanel } from "./policy-cloud-exception-detail-panel";
import { PolicyCloudExceptionRequestPanel } from "./policy-cloud-exception-request-panel";
import { PolicyCloudExceptionsList, PolicyCloudExceptionsListSkeleton } from "./policy-cloud-exceptions-list";
import { PolicyCloudExceptionsSummary } from "./policy-cloud-exceptions-summary";
import {
  groupCloudExceptions,
  summarizeCloudExceptions,
} from "./policy-cloud-exceptions-utils";
import { resolveCloudPolicyControlsUrl } from "./policy-workspace-helpers";

type PolicyCloudExceptionsTabProps = {
  snapshot: GuardRuntimeSnapshot;
  requestOpen?: boolean;
  onRequestOpenChange?: (open: boolean) => void;
};

type LoadState = "loading" | "ready" | "error";

function resolveCloudExceptionsConnected(snapshot: GuardRuntimeSnapshot): boolean {
  return snapshot.cloud_state === "paired_active" || snapshot.cloud_state === "paired_waiting";
}

export function PolicyCloudExceptionsTab({
  snapshot,
  requestOpen: requestOpenProp,
  onRequestOpenChange,
}: PolicyCloudExceptionsTabProps) {
  const [requestOpenInternal, setRequestOpenInternal] = useState(false);
  const requestOpen = requestOpenProp ?? requestOpenInternal;
  const setRequestOpen = onRequestOpenChange ?? setRequestOpenInternal;
  const [loadState, setLoadState] = useState<LoadState>("loading");
  const [loadError, setLoadError] = useState<string | null>(null);
  const [exceptions, setExceptions] = useState<GuardCloudException[]>([]);
  const [pendingRequests, setPendingRequests] = useState<GuardCloudExceptionRequestItem[]>([]);
  const [selectedExceptionId, setSelectedExceptionId] = useState<string | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const [scopeFilter, setScopeFilter] = useState("all");
  const [actionFilter, setActionFilter] = useState("all");

  const cloudControlsUrl = resolveCloudPolicyControlsUrl(snapshot);
  const cloudConnected = resolveCloudExceptionsConnected(snapshot);
  const connectUrl = snapshot.connect_url?.trim() || null;

  const reloadData = useCallback(async () => {
    if (!cloudConnected) {
      setExceptions([]);
      setPendingRequests([]);
      setLoadState("ready");
      setLoadError(null);
      return;
    }
    setLoadState("loading");
    setLoadError(null);
    try {
      const [nextExceptions, nextRequests] = await Promise.all([
        fetchCloudExceptions(),
        fetchCloudExceptionRequests(),
      ]);
      setExceptions(nextExceptions);
      setPendingRequests(nextRequests.items ?? []);
      setLoadState("ready");
    } catch (error) {
      setLoadState("error");
      setLoadError(error instanceof Error ? error.message : "Unable to load Cloud exceptions.");
    }
  }, [cloudConnected]);

  useEffect(() => {
    void reloadData();
  }, [reloadData, reloadToken]);

  const handleCloseRequestPanel = useCallback(() => {
    setRequestOpen(false);
  }, [setRequestOpen]);

  const handleRequestSubmitted = useCallback(() => {
    setRequestOpen(false);
    setReloadToken((current) => current + 1);
  }, [setRequestOpen]);

  const handleRetryLoad = useCallback(() => {
    setReloadToken((current) => current + 1);
  }, []);

  const handleSelectException = useCallback((exception: GuardCloudException) => {
    setSelectedExceptionId(exception.id);
  }, []);

  const handleCloseDetail = useCallback(() => {
    setSelectedExceptionId(null);
  }, []);

  const handleScopeFilterChange = useCallback((value: string) => {
    setScopeFilter(value);
  }, []);

  const handleActionFilterChange = useCallback((value: string) => {
    setActionFilter(value);
  }, []);

  const summary = useMemo(
    () => summarizeCloudExceptions(exceptions, pendingRequests),
    [exceptions, pendingRequests],
  );
  const groups = useMemo(
    () => groupCloudExceptions(exceptions, pendingRequests),
    [exceptions, pendingRequests],
  );
  const selectedException = useMemo(
    () => exceptions.find((item) => item.id === selectedExceptionId) ?? null,
    [exceptions, selectedExceptionId],
  );

  return (
    <>
      {requestOpen ? (
        <PolicyCloudExceptionRequestPanel
          snapshot={snapshot}
          onSubmitted={handleRequestSubmitted}
          onCancel={handleCloseRequestPanel}
        />
      ) : null}

      <div className="space-y-4">
        <div className="rounded-2xl border border-brand-blue/10 bg-brand-blue/[0.03] px-4 py-3 text-sm text-brand-dark/80">
          Exceptions are approved in Guard Cloud, then enforced locally as signed policy bundle entries.
        </div>

        {!cloudConnected ? (
          <EmptyState
            title="Guard Cloud is not connected"
            body="Cloud exceptions are managed in Guard Cloud. Connect this device to request a risk acceptance or view synced exceptions here."
            tone="teach"
          />
        ) : loadState === "error" ? (
          <EmptyState
            title="Could not load Cloud exceptions"
            body={`${loadError ?? "Try again after Guard Cloud sync completes."} Local remembered rules and strict config still apply on this device.`}
            action={
              <ActionButton variant="secondary" onClick={handleRetryLoad}>
                Retry
              </ActionButton>
            }
          />
        ) : (
          <>
            <PolicyCloudExceptionsSummary
              activeCount={summary.activeCount}
              pendingCount={summary.pendingCount}
              expiringSoonCount={summary.expiringSoonCount}
              ackFailureCount={summary.ackFailureCount}
              loading={loadState === "loading"}
            />

            <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_340px] lg:items-start">
              {loadState === "loading" ? (
                <PolicyCloudExceptionsListSkeleton />
              ) : (
                <PolicyCloudExceptionsList
                  active={groups.active}
                  pending={groups.pending}
                  expiringSoon={groups.expiringSoon}
                  selectedExceptionId={selectedExceptionId}
                  onSelectException={handleSelectException}
                  cloudConnected={cloudConnected}
                  scopeFilter={scopeFilter}
                  actionFilter={actionFilter}
                  onScopeFilterChange={handleScopeFilterChange}
                  onActionFilterChange={handleActionFilterChange}
                />
              )}
              {selectedException ? (
                <PolicyCloudExceptionDetailPanel
                  exception={selectedException}
                  cloudControlsUrl={cloudControlsUrl}
                  onClose={handleCloseDetail}
                />
              ) : null}
            </div>
          </>
        )}
      </div>
    </>
  );
}
