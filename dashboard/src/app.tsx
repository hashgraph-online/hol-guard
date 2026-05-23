import { useEffect, useState, useCallback, useRef, useMemo, lazy, Suspense } from "react";

import {
  clearPolicy,
  fetchDiff,
  fetchInventory,
  fetchLatestReceipt,
  fetchPolicies,
  fetchPolicy,
  fetchReceipts,
  fetchRequest,
  fetchRuntimeSnapshot,
  fetchSettings,
  guardAwareHref,
  repairApprovalCenter,
  resolveRequestWithQueueResult,
  retryResume,
} from "./guard-api";
import { ApprovalCenterLayout } from "./approval-center-layout";
import { buildClearPayload } from "./clear-policy-payload";
import { normalizeHarnessSlug } from "./approval-center-utils";
import { ErrorBoundary } from "./error-boundary";
import { selectNextAfterResolution } from "./queue-state";
import { useRouteFocus } from "./use-route-focus";

const HomeWorkspace = lazy(() => import("./home-dashboard").then((m) => ({ default: m.HomeWorkspace })));
const FleetWorkspace = lazy(() => import("./fleet-workspace").then((m) => ({ default: m.FleetWorkspace })));
const SettingsWorkspace = lazy(() => import("./settings-workspace").then((m) => ({ default: m.SettingsWorkspace })));
const AppDetailWorkspace = lazy(() => import("./apps/app-detail-workspace").then((m) => ({ default: m.AppDetailWorkspace })));
const HelpModal = lazy(() => import("./help-modal").then((m) => ({ default: m.HelpModal })));

function LazyFallback() {
  return (
    <div className="flex min-h-[200px] items-center justify-center">
      <div className="guard-skeleton h-8 w-48" />
    </div>
  );
}
import type {
  GuardApprovalGatePublicConfig,
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardCodexResumeResult,
  GuardPolicyDecision,
  GuardReceipt,
  GuardRuntimeSnapshot,
  GuardInventoryItem,
  DecisionScope,
} from "./guard-types";

type RequestState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardApprovalRequest[] };

type DetailState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "stale" }
  | {
      kind: "ready";
      item: GuardApprovalRequest;
      diff: GuardArtifactDiff | null;
      receipt: GuardReceipt | null;
      policy: GuardPolicyDecision[];
    };

type ReceiptsState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardReceipt[] };

type RuntimeState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; snapshot: GuardRuntimeSnapshot };

type PolicyState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardPolicyDecision[] };
type InventoryState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardInventoryItem[] };

function usePathname(): string {
  const [pathname, setPathname] = useState(window.location.pathname);

  useEffect(() => {
    const onPopState = () => setPathname(window.location.pathname);
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  return pathname;
}

function navigate(pathname: string): void {
  window.history.pushState({}, "", guardAwareHref(pathname));
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function parseRequestId(pathname: string): string | null {
  if (pathname.startsWith("/requests/")) {
    return pathname.slice("/requests/".length);
  }
  if (pathname.startsWith("/approvals/")) {
    return pathname.slice("/approvals/".length);
  }
  return null;
}

type AppView = "home" | "inbox" | "fleet" | "evidence" | "settings" | "app-detail";

export function parseAppDetail(pathname: string): string | null {
  if (!pathname.startsWith("/apps/")) {
    return null;
  }
  const rawSlug = pathname.slice("/apps/".length);
  try {
    return normalizeHarnessSlug(decodeURIComponent(rawSlug));
  } catch {
    return null;
  }
}

export function resolveView(pathname: string): AppView {
  if (parseAppDetail(pathname) !== null) {
    return "app-detail";
  }
  if (pathname.startsWith("/apps/")) {
    return "fleet";
  }
  if (pathname === "/settings") {
    return "settings";
  }
  if (pathname === "/fleet") {
    return "fleet";
  }
  if (pathname === "/evidence") {
    return "evidence";
  }
  if (
    pathname === "/inbox" ||
    pathname === "/requests" ||
    pathname === "/approvals" ||
    pathname.startsWith("/requests/") ||
    pathname.startsWith("/approvals/")
  ) {
    return "inbox";
  }
  return "home";
}

async function loadDetail(requestId: string): Promise<Exclude<DetailState, { kind: "idle" | "loading" }>> {
  try {
    const item = await fetchRequest(requestId);
    const [diff, receipt, policy] = await Promise.all([
      fetchDiff(item.artifact_id, item.harness),
      fetchLatestReceipt(item.artifact_id, item.harness),
      fetchPolicy(item.harness)
    ]);
    return { kind: "ready", item, diff, receipt, policy };
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (message.includes("404")) {
      return { kind: "stale" };
    }
    return {
      kind: "error",
      message: message.length > 0 ? message : "Unable to load the approval request."
    };
  }
}

export function App() {
  const pathname = usePathname();
  const view = resolveView(pathname);
  useRouteFocus(view);
  const requestId = parseRequestId(pathname);
  const appDetailHarness = parseAppDetail(pathname);
  const [requests, setRequests] = useState<RequestState>({ kind: "loading" });
  const [detail, setDetail] = useState<DetailState>({ kind: "idle" });
  const [receipts, setReceipts] = useState<ReceiptsState>({ kind: "loading" });
  const [runtime, setRuntime] = useState<RuntimeState>({ kind: "loading" });
  const [policies, setPolicies] = useState<PolicyState>({ kind: "loading" });
  const [inventory, setInventory] = useState<InventoryState>({ kind: "idle" });
  const [resolutionMessage, setResolutionMessage] = useState<string | null>(null);
  const [codexResume, setCodexResume] = useState<GuardCodexResumeResult | null>(null);
  const [resolvedRequestId, setResolvedRequestId] = useState<string | null>(null);
  const [helpOpen, setHelpOpen] = useState(false);
  const [clearConfirm, setClearConfirm] = useState<{ harness?: string; all?: boolean } | null>(null);
  const [approvalGate, setApprovalGate] = useState<GuardApprovalGatePublicConfig | null>(null);
  const resolutionInFlight = useRef(false);

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      const target = event.target as HTMLElement;
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return;
      if (event.key === "?") {
        event.preventDefault();
        setHelpOpen((open) => !open);
      }
      if (event.key === "/") {
        event.preventDefault();
        const searchInput = document.querySelector('input[type="search"]') as HTMLInputElement | null;
        searchInput?.focus();
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  useEffect(() => {
    let cancelled = false;
    let pollId: number | undefined;
    const loadRuntimeSnapshot = () => {
      fetchRuntimeSnapshot()
        .then((snapshot) => {
          if (!cancelled && !resolutionInFlight.current) {
            setRuntime({ kind: "ready", snapshot });
            setRequests({ kind: "ready", items: snapshot.items });
          }
        })
        .catch((error: unknown) => {
          if (!cancelled && !resolutionInFlight.current) {
            const message =
              error instanceof Error ? error.message : "Unable to load the local approval queue.";
            setRuntime({ kind: "error", message });
            setRequests({ kind: "error", message });
          }
        });
    };
    loadRuntimeSnapshot();
    pollId = window.setInterval(loadRuntimeSnapshot, 4000);
    return () => {
      cancelled = true;
      if (pollId !== undefined) {
        window.clearInterval(pollId);
      }
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    fetchInventory()
      .then((items) => {
        if (!cancelled) {
          setInventory({ kind: "ready", items });
        }
      })
      .catch(() => {
        if (!cancelled) {
          setInventory({ kind: "ready", items: [] });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    fetchSettings()
      .then((payload) => {
        if (!cancelled && payload.settings.approval_gate !== undefined) {
          setApprovalGate(payload.settings.approval_gate);
        }
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    let cancelled = false;
    Promise.allSettled([fetchReceipts(), fetchPolicies()])
      .then(([receiptsResult, policiesResult]) => {
        if (cancelled) {
          return;
        }
        if (receiptsResult.status === "fulfilled") {
          setReceipts({ kind: "ready", items: receiptsResult.value });
        } else {
          setReceipts({
            kind: "error",
            message: receiptsResult.reason instanceof Error ? receiptsResult.reason.message : "Unable to load local approval history."
          });
        }
        if (policiesResult.status === "fulfilled") {
          setPolicies({ kind: "ready", items: policiesResult.value });
        } else {
          setPolicies({
            kind: "error",
            message: policiesResult.reason instanceof Error ? policiesResult.reason.message : "Unable to load saved approvals."
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (view !== "fleet") {
      return;
    }
    let cancelled = false;
    setInventory({ kind: "loading" });
    fetchInventory()
      .then((items) => {
        if (!cancelled) {
          setInventory({ kind: "ready", items });
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setInventory({
            kind: "error",
            message: error instanceof Error ? error.message : "Unable to load watched app inventory."
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, [view]);

  const queuedItems = requests.kind === "ready" ? requests.items : [];
  const activeRequestId = requestId ?? queuedItems[0]?.request_id ?? null;

  useEffect(() => {
    if (activeRequestId === null) {
      setDetail({ kind: "idle" });
      return;
    }
    let cancelled = false;
    setDetail({ kind: "loading" });
    loadDetail(activeRequestId).then((nextState) => {
      if (!cancelled) {
        setDetail(nextState);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [activeRequestId]);

  const handleOpenInbox = useCallback(() => navigate("/inbox"), []);
  const handleOpenFleet = useCallback(() => navigate("/fleet"), []);
  const handleOpenEvidence = useCallback(() => navigate("/evidence"), []);
  const handleOpenSettings = useCallback(() => navigate("/settings"), []);
  const handleOpenHelp = useCallback(() => setHelpOpen(true), []);
  const handleCloseHelp = useCallback(() => setHelpOpen(false), []);
  const handleGoHome = useCallback(() => navigate("/"), []);
  const handleOpenRequest = useCallback((nextRequestId: string) => {
    navigate(`/requests/${nextRequestId}`);
  }, []);
  const handleOpenAppDetail = useCallback((harness: string) => {
    const slug = normalizeHarnessSlug(harness);
    if (slug !== null) {
      navigate(`/apps/${encodeURIComponent(slug)}`);
    }
  }, []);

  const refreshStateAfterAction = useCallback(async () => {
    const [snapshotResult, receiptsResult, policiesResult, inventoryResult] = await Promise.allSettled([
      fetchRuntimeSnapshot(),
      fetchReceipts(),
      fetchPolicies(),
      fetchInventory(),
    ]);
    if (snapshotResult.status === "fulfilled") {
      setRuntime({ kind: "ready", snapshot: snapshotResult.value });
      setRequests({ kind: "ready", items: snapshotResult.value.items });
    } else {
      const message =
        snapshotResult.reason instanceof Error ? snapshotResult.reason.message : "Unable to load the local approval queue.";
      setRuntime({ kind: "error", message });
      setRequests({ kind: "error", message });
    }
    if (receiptsResult.status === "fulfilled") {
      setReceipts({ kind: "ready", items: receiptsResult.value });
    } else {
      setReceipts({
        kind: "error",
        message: receiptsResult.reason instanceof Error ? receiptsResult.reason.message : "Unable to load local approval history.",
      });
    }
    if (policiesResult.status === "fulfilled") {
      setPolicies({ kind: "ready", items: policiesResult.value });
    } else {
      setPolicies({
        kind: "error",
        message: policiesResult.reason instanceof Error ? policiesResult.reason.message : "Unable to load remembered decisions.",
      });
    }
    if (inventoryResult.status === "fulfilled") {
      setInventory({ kind: "ready", items: inventoryResult.value });
    } else {
      setInventory({
        kind: "error",
        message: inventoryResult.reason instanceof Error ? inventoryResult.reason.message : "Unable to load watched app inventory.",
      });
    }
  }, [setRuntime, setRequests, setReceipts, setPolicies, setInventory]);

  const handleClearPolicies = useCallback(async (scope: { harness?: string; all?: boolean }) => {
    setClearConfirm(scope);
  }, []);

  const handleConfirmClear = useCallback(async () => {
    if (clearConfirm === null) return;
    await clearPolicy(clearConfirm);
    setClearConfirm(null);
    const [snapshotResult, policiesResult] = await Promise.allSettled([fetchRuntimeSnapshot(), fetchPolicies()]);
    if (snapshotResult.status === "fulfilled") {
      setRuntime({ kind: "ready", snapshot: snapshotResult.value });
      setRequests({ kind: "ready", items: snapshotResult.value.items });
    } else {
      const message =
        snapshotResult.reason instanceof Error ? snapshotResult.reason.message : "Unable to load the local approval queue.";
      setRuntime({ kind: "error", message });
      setRequests({ kind: "error", message });
    }
    if (policiesResult.status === "fulfilled") {
      setPolicies({ kind: "ready", items: policiesResult.value });
    } else {
      setPolicies({
        kind: "error",
        message: policiesResult.reason instanceof Error ? policiesResult.reason.message : "Unable to load saved approvals.",
      });
    }
  }, [clearConfirm, setRuntime, setRequests, setPolicies]);

  const handleCancelClear = useCallback(() => {
    setClearConfirm(null);
  }, []);

  const handleClearAppPolicies = useCallback(async (harness: string) => {
    await clearPolicy({ harness });
    const [snapshotResult, policiesResult] = await Promise.allSettled([fetchRuntimeSnapshot(), fetchPolicies()]);
    if (snapshotResult.status === "fulfilled") {
      setRuntime({ kind: "ready", snapshot: snapshotResult.value });
      setRequests({ kind: "ready", items: snapshotResult.value.items });
    }
    if (policiesResult.status === "fulfilled") {
      setPolicies({ kind: "ready", items: policiesResult.value });
    } else {
      setPolicies({
        kind: "error",
        message: policiesResult.reason instanceof Error ? policiesResult.reason.message : "Unable to load saved approvals.",
      });
    }
  }, [setRuntime, setRequests, setPolicies]);

  const handleClearPolicy = useCallback(async (policy: GuardPolicyDecision) => {
    await clearPolicy(buildClearPayload(policy));
    const [snapshotResult, policiesResult] = await Promise.allSettled([fetchRuntimeSnapshot(), fetchPolicies()]);
    if (snapshotResult.status === "fulfilled") {
      setRuntime({ kind: "ready", snapshot: snapshotResult.value });
      setRequests({ kind: "ready", items: snapshotResult.value.items });
    }
    if (policiesResult.status === "fulfilled") {
      setPolicies({ kind: "ready", items: policiesResult.value });
    } else {
      setPolicies({
        kind: "error",
        message: policiesResult.reason instanceof Error ? policiesResult.reason.message : "Unable to load saved approvals.",
      });
    }
  }, [setRuntime, setRequests, setPolicies]);

  const handleClearEvidence = useCallback(() => {
    setReceipts({ kind: "ready", items: [] });
  }, [setReceipts]);

  const handleResolve = useCallback(async (payload: {
    requestId: string;
    action: "allow" | "block";
    scope: DecisionScope;
    workspace?: string;
    reason: string;
    approval_password?: string;
    approval_gate_use_cooldown?: boolean;
  }) => {
    resolutionInFlight.current = true;
    const queuedItemsSnapshot = requests.kind === "ready" ? requests.items : [];
    try {
      const result = await resolveRequestWithQueueResult(payload);
      const nextId = selectNextAfterResolution(result, queuedItemsSnapshot);
      const resume = result.codex_resume ?? null;
      setCodexResume(resume);
      setResolvedRequestId(resume !== null ? payload.requestId : null);
      if (nextId !== null) {
        setResolutionMessage(null);
        navigate(`/requests/${nextId}`);
      } else {
        setResolutionMessage(resume !== null ? null : (result.resolution_summary || "Decision saved. Return to your chat and retry the command."));
        navigate("/inbox");
      }
      await refreshStateAfterAction();
    } finally {
      resolutionInFlight.current = false;
    }
  }, [requests, refreshStateAfterAction, setResolutionMessage]);

  const handleRetryResume = useCallback(async () => {
    if (resolvedRequestId === null) return;
    const updated = await retryResume(resolvedRequestId);
    setCodexResume(updated);
  }, [resolvedRequestId]);

  const handleBulkApprove = useCallback(async (ids: string[]) => {
    const results = await Promise.allSettled(
      ids.map((id) =>
        resolveRequestWithQueueResult({ requestId: id, action: "allow", scope: "artifact", reason: "" })
      )
    );
    const succeeded = results.filter((r) => r.status === "fulfilled").length;
    const failed = results.length - succeeded;
    const label =
      failed === 0
        ? `${succeeded} item${succeeded !== 1 ? "s" : ""} approved.`
        : `${succeeded} approved, ${failed} failed. Retry the failed items manually.`;
    setResolutionMessage(label);
    navigate("/inbox");
    await refreshStateAfterAction();
  }, [refreshStateAfterAction, setResolutionMessage]);

  const handleBulkBlock = useCallback(async (ids: string[], reason: string) => {
    const results = await Promise.allSettled(
      ids.map((id) =>
        resolveRequestWithQueueResult({ requestId: id, action: "block", scope: "artifact", reason })
      )
    );
    const succeeded = results.filter((result) => result.status === "fulfilled").length;
    const failed = results.length - succeeded;
    const label =
      failed === 0
        ? `${succeeded} item${succeeded !== 1 ? "s" : ""} blocked.`
        : `${succeeded} blocked, ${failed} failed. Retry the failed items manually.`;
    setResolutionMessage(label);
    navigate("/inbox");
    await refreshStateAfterAction();
  }, [refreshStateAfterAction, setResolutionMessage]);

  const handleRetry = useCallback(() => {
    setRuntime({ kind: "loading" });
    setRequests({ kind: "loading" });
    fetchRuntimeSnapshot()
      .then((snapshot) => {
        setRuntime({ kind: "ready", snapshot });
        setRequests({ kind: "ready", items: snapshot.items });
      })
      .catch((error: unknown) => {
        const message =
          error instanceof Error ? error.message : "Unable to load the local approval queue.";
        setRuntime({ kind: "error", message });
        setRequests({ kind: "error", message });
      });
  }, []);

  const handleRepair = useCallback(async () => {
    await repairApprovalCenter();
    await new Promise<void>((resolve) => setTimeout(resolve, 1200));
    fetchRuntimeSnapshot()
      .then((snapshot) => {
        setRuntime({ kind: "ready", snapshot });
        setRequests({ kind: "ready", items: snapshot.items });
      })
      .catch((error: unknown) => {
        const message =
          error instanceof Error ? error.message : "Unable to reconnect to Guard daemon.";
        setRuntime({ kind: "error", message });
        setRequests({ kind: "error", message });
      });
  }, []);

  const handleConnectHarness = useCallback((harness: string) => {
    const slug = normalizeHarnessSlug(harness);
    if (slug !== null) {
      navigate(`/apps/${encodeURIComponent(slug)}?tab=settings`);
    }
  }, []);

  const handleTestHarness = useCallback((harness: string) => {
    const slug = normalizeHarnessSlug(harness);
    if (slug !== null) {
      navigate(`/apps/${encodeURIComponent(slug)}?tab=settings`);
    }
  }, []);

  const handleRepairHarness = useCallback((harness: string) => {
    const slug = normalizeHarnessSlug(harness);
    if (slug !== null) {
      navigate(`/apps/${encodeURIComponent(slug)}?tab=settings`);
    }
  }, []);

  const appDetailContent = useMemo(() => {
    if (view !== "app-detail" || !appDetailHarness || runtime.kind !== "ready") {
      return null;
    }
    return (
      <AppDetailWorkspace
        harness={appDetailHarness}
        runtime={runtime.snapshot}
        receipts={receipts.kind === "ready" ? receipts.items : []}
        policies={policies.kind === "ready" ? policies.items : []}
        inventory={inventory.kind === "ready" ? inventory.items : []}
        requests={requests.kind === "ready" ? requests.items : []}
        onGoHome={handleGoHome}
        onOpenRequest={handleOpenRequest}
        onClearAppPolicies={handleClearAppPolicies}
        onClearPolicy={handleClearPolicy}
        onManagedInstallChanged={refreshStateAfterAction}
      />
    );
  }, [view, appDetailHarness, runtime, receipts, policies, inventory, requests, handleGoHome, handleOpenRequest, handleClearAppPolicies, handleClearPolicy, refreshStateAfterAction]);

  return (
    <>
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:rounded-lg focus:bg-brand-blue focus:px-4 focus:py-2 focus:text-white focus:outline-none"
      >
        Skip to content
      </a>
      <div aria-live="polite" aria-atomic="true" className="sr-only">
        {view === "home" ? "Home" : view === "inbox" ? "Inbox" : view === "fleet" ? "Protect" : view === "evidence" ? "Evidence" : view === "settings" ? "Settings" : "App detail"}
      </div>
    <ApprovalCenterLayout
      view={view}
      requests={requests}
      detail={detail}
      receipts={receipts}
      runtime={runtime}
      inventory={inventory.kind === "ready" ? inventory.items : []}
      activeRequestId={activeRequestId}
      resolutionMessage={resolutionMessage}
      codexResume={codexResume}
      approvalGate={approvalGate}
      onRetryResume={handleRetryResume}
      homeContent={
        <Suspense fallback={<LazyFallback />}>
          <HomeWorkspace
            requests={requests}
            runtime={runtime}
            policies={policies}
            onOpenInbox={handleOpenInbox}
            onOpenFleet={handleOpenFleet}
            onOpenEvidence={handleOpenEvidence}
            onOpenSettings={handleOpenSettings}
            onClearPolicies={handleClearPolicies}
            onOpenAppDetail={handleOpenAppDetail}
            clearConfirm={clearConfirm}
            onConfirmClear={handleConfirmClear}
            onCancelClear={handleCancelClear}
            onOpenHelp={handleOpenHelp}
          />
        </Suspense>
      }
      onGoHome={handleGoHome}
      onNavigate={navigate}
      onOpenRequest={handleOpenRequest}
      onResolve={handleResolve}
      onBulkApprove={handleBulkApprove}
      onBulkBlock={handleBulkBlock}
      onRetry={handleRetry}
      onRepair={handleRepair}
      onClearEvidence={handleClearEvidence}
      fleetContent={
        runtime.kind === "ready" ? (
          <Suspense fallback={<LazyFallback />}>
            <FleetWorkspace
              runtime={runtime.snapshot}
              policies={policies.kind === "ready" ? policies.items : []}
              inventory={inventory}
              onConnectHarness={handleConnectHarness}
              onTestHarness={handleTestHarness}
              onRepairHarness={handleRepairHarness}
              onOpenAppDetail={handleOpenAppDetail}
            />
          </Suspense>
        ) : null
      }
      appDetailContent={
        <ErrorBoundary onReset={handleGoHome}>
          <Suspense fallback={<LazyFallback />}>
            {appDetailContent}
          </Suspense>
        </ErrorBoundary>
      }
      settingsContent={
        <Suspense fallback={<LazyFallback />}>
          <SettingsWorkspace />
        </Suspense>
      }
    />
    {helpOpen && (
      <Suspense fallback={null}>
        <HelpModal open={helpOpen} onClose={handleCloseHelp} />
      </Suspense>
    )}
    </>);
}
