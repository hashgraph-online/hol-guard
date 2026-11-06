import { useCallback, useEffect, useMemo, useState } from "react";
import type {
  GuardCloudConnectFlow,
  GuardInsightsShareResult,
  GuardReceiptAnalytics,
  GuardRuntimeSnapshot,
} from "../guard-types";
import { ActionButton } from "../approval-center-primitives";
import { GuardModalLayer } from "../guard-modal-layer";
import {
  fetchGuardCloudConnectStatus,
  fetchRuntimeSnapshot,
  publishInsightsShare,
  startGuardCloudConnect,
} from "../guard-api";
import { ConnectFlowCard } from "../supply-chain-firewall-views";
import {
  openPackageFirewallAuthorizeFallback,
  PACKAGE_FIREWALL_CONNECT_POPUP_BLOCKED_MESSAGE,
} from "../package-firewall-connect-browser";
import { EvidenceInsightsShareSheet } from "./evidence-insights-share-sheet";
import { GuardStatMetric } from "./guard-stat-metric";
import { HomeInsightsMetrics } from "./evidence-insights-headline-bento";
import { EvidenceActivityHeatmapMini, getHeatmapLevel } from "./evidence-activity-heatmap-mini";
import { formatEvidenceCount } from "./evidence-format";
import { insightsSharePublishErrorMessage, isInsightsShareScopeError } from "./evidence-insights-share-errors";

interface EvidenceInsightsShareModalProps {
  analytics: GuardReceiptAnalytics;
  runtime: GuardRuntimeSnapshot | null;
  onClose: () => void;
}

function insightsShareCloudReady(runtime: GuardRuntimeSnapshot | null): boolean {
  if (runtime === null) {
    return false;
  }
  if (runtime.cloud_state === "paired_active") {
    return true;
  }
  return runtime.sync_configured;
}

export function EvidenceInsightsShareModal({
  analytics,
  runtime: initialRuntime,
  onClose,
}: EvidenceInsightsShareModalProps) {
  const [runtime, setRuntime] = useState(initialRuntime);
  const [includeTopArtifacts, setIncludeTopArtifacts] = useState(false);
  const [showDisplayName, setShowDisplayName] = useState(true);
  const [displayName, setDisplayName] = useState("");
  const [publishing, setPublishing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rawError, setRawError] = useState<string | null>(null);
  const [shareResult, setShareResult] = useState<GuardInsightsShareResult | null>(null);
  const [connectFlow, setConnectFlow] = useState<GuardCloudConnectFlow | null>(null);
  const [connectStarting, setConnectStarting] = useState(false);
  const [connectError, setConnectError] = useState<string | null>(null);

  const cloudConnected = insightsShareCloudReady(runtime);
  const connectMode =
    runtime?.cloud_state === "local_only" || runtime?.cloud_state === "paired_waiting" ? "connect" : "repair";

  const refreshConnectState = useCallback(async () => {
    const [connectStatus, runtimeSnapshot] = await Promise.all([
      fetchGuardCloudConnectStatus(),
      fetchRuntimeSnapshot({ includeItems: false }),
    ]);
    setRuntime(runtimeSnapshot);
    setConnectFlow(connectStatus.connect_flow);
    return connectStatus;
  }, []);

  useEffect(() => {
    if (cloudConnected) {
      setConnectFlow(null);
      return;
    }
    void refreshConnectState().catch((refreshError) => {
      setConnectError(
        refreshError instanceof Error ? refreshError.message : "Unable to load Guard Cloud connect status.",
      );
    });
  }, [cloudConnected, refreshConnectState]);

  useEffect(() => {
    if (connectFlow?.state !== "running" && connectFlow?.state !== "starting") {
      return;
    }
    const handle = window.setTimeout(() => {
      void refreshConnectState().catch(() => undefined);
    }, connectFlow.poll_after_ms ?? 1500);
    return () => window.clearTimeout(handle);
  }, [connectFlow, refreshConnectState]);

  const handleStartConnect = useCallback(async () => {
    setConnectStarting(true);
    setConnectError(null);
    try {
      const status = await startGuardCloudConnect();
      setConnectFlow(status.connect_flow);
      if (
        status.connect_flow?.authorize_url &&
        !openPackageFirewallAuthorizeFallback(
          status.connect_flow.authorize_url,
          status.connect_flow.browser_opened,
        )
      ) {
        setConnectError(PACKAGE_FIREWALL_CONNECT_POPUP_BLOCKED_MESSAGE);
      }
      if (!status.connect_required) {
        await refreshConnectState();
      }
    } catch (startError) {
      setConnectError(
        startError instanceof Error ? startError.message : "Unable to start Guard Cloud connect.",
      );
    } finally {
      setConnectStarting(false);
    }
  }, [refreshConnectState]);

  const handlePublish = useCallback(async () => {
    setPublishing(true);
    setError(null);
    setRawError(null);
    try {
      const result = await publishInsightsShare({
        includeTopArtifacts,
        showDisplayName,
        displayName: showDisplayName && displayName.trim() ? displayName.trim() : undefined,
      });
      setShareResult(result);
    } catch (publishError) {
      const rawMessage = publishError instanceof Error ? publishError.message : "Unable to publish share link.";
      setRawError(rawMessage);
      setError(insightsSharePublishErrorMessage(rawMessage));
    } finally {
      setPublishing(false);
    }
  }, [displayName, includeTopArtifacts, showDisplayName]);

  const activeConnectFlow = useMemo((): GuardCloudConnectFlow => {
    if (connectFlow !== null) {
      return connectFlow;
    }
    return {
      state: "idle",
      title: "Connect Guard Cloud to publish insights",
      detail:
        "Local Guard remains available. Connect Guard Cloud here so the daemon can publish a public share link with preview image support.",
      action_label: "Connect Guard Cloud",
      connect_url: runtime?.connect_url ?? "https://hol.org/guard/connect",
      authorize_url: null,
      browser_opened: null,
      request_id: null,
      poll_after_ms: null,
    };
  }, [connectFlow, runtime?.connect_url]);

  const isScopeError = Boolean(rawError) && isInsightsShareScopeError(rawError ?? "");
  const errorIsReauth = isScopeError || (rawError?.toLowerCase().includes("unauthorized") ?? false);

  if (shareResult) {
    return (
      <EvidenceInsightsShareSheet
        publicUrl={shareResult.publicUrl}
        onClose={() => {
          setShareResult(null);
          onClose();
        }}
      />
    );
  }

  return (
    <GuardModalLayer ariaLabel="Share your Guard stats" onClose={onClose}>
      <div className="rounded-2xl border border-slate-200 bg-white shadow-xl">
        <div className="border-b border-slate-100 px-5 py-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold text-brand-dark">Share publicly</h2>
              {cloudConnected ? (
                <p className="mt-1 text-sm text-slate-500">
                  Publish a redacted stats card with a public link and preview image.
                </p>
              ) : null}
            </div>
            <button type="button" onClick={onClose} className="text-sm font-medium text-slate-500 hover:text-brand-dark">
              Close
            </button>
          </div>
        </div>

        {!cloudConnected ? (
          <ConnectFlowCard
            minimal
            purpose="insights_share"
            mode={connectMode}
            connectFlow={activeConnectFlow}
            connectStarting={connectStarting}
            connectError={connectError}
            onStartConnect={handleStartConnect}
          />
        ) : (
          <>
            <div className="space-y-4 px-5 py-5">
              <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white">
                <div className="grid grid-cols-3 gap-px bg-slate-100">
                  <GuardStatMetric
                    label="Pending"
                    value={formatEvidenceCount(runtime?.pending_count ?? 0)}
                    compact
                  />
                  <GuardStatMetric
                    label="Apps"
                    value={formatEvidenceCount(runtime?.managed_installs?.length ?? 0)}
                    compact
                  />
                  <GuardStatMetric
                    label="Recorded"
                    value={formatEvidenceCount(runtime?.receipt_count ?? 0)}
                    compact
                  />
                </div>
                <HomeInsightsMetrics analytics={analytics} />
                <div className="px-4 py-3">
                  <p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">Last 5 days</p>
                  <div className="mt-2">
                    <EvidenceActivityHeatmapMini
                      cells={
                        analytics.daily_activity.slice(-5).map((day) => ({
                          date: day.date_key,
                          level: getHeatmapLevel(day.total, analytics.peak_day_total || 1),
                        }))
                      }
                    />
                  </div>
                </div>
              </div>

              <hr className="border-slate-100" />

              <label className="flex items-center gap-3 text-sm text-brand-dark">
                <input
                  type="checkbox"
                  checked={showDisplayName}
                  onChange={(event) => setShowDisplayName(event.target.checked)}
                  className="h-4 w-4 rounded border-slate-300"
                />
                Show display name on the public card
              </label>

              {showDisplayName ? (
                <label className="block text-sm text-brand-dark">
                  <span className="mb-1 block text-slate-500">Display name</span>
                  <input
                    type="text"
                    value={displayName}
                    onChange={(event) => setDisplayName(event.target.value)}
                    placeholder="Your name"
                    className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm"
                    maxLength={120}
                  />
                </label>
              ) : null}

              <label className="flex items-center gap-3 text-sm text-brand-dark">
                <input
                  type="checkbox"
                  checked={includeTopArtifacts}
                  onChange={(event) => setIncludeTopArtifacts(event.target.checked)}
                  className="h-4 w-4 rounded border-slate-300"
                />
                Include top recurring action labels (redacted)
              </label>

              {error ? (
                <div
                  className={`rounded-xl border px-3 py-2 text-sm ${errorIsReauth ? "border-amber-200 bg-amber-50 text-amber-900" : "border-rose-200 bg-rose-50 text-rose-900"}`}
                  role="alert"
                >
                  <p>{error}</p>
                  {errorIsReauth ? (
                    <ActionButton variant="outline" onClick={handleStartConnect} className="mt-2 w-full">
                      Reconnect Guard Cloud
                    </ActionButton>
                  ) : null}
                </div>
              ) : null}
            </div>

            <div className="flex items-center justify-end gap-2 border-t border-slate-100 px-5 py-4">
              <ActionButton variant="outline" onClick={onClose}>
                Cancel
              </ActionButton>
              <ActionButton onClick={handlePublish} disabled={publishing}>
                {publishing ? "Publishing…" : "Publish public link"}
              </ActionButton>
            </div>
          </>
        )}
      </div>
    </GuardModalLayer>
  );
}
