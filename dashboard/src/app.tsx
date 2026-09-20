import { useMemo, Suspense } from "react";
import { ApprovalCenterLayout } from "./approval-center-layout";
import { ErrorBoundary } from "./error-boundary";
import { lazyWorkspace } from "./lazy-workspace";
import { navigate, viewTitle } from "./app-routing";
import { useAppData } from "./use-app-data";
import { useAppActions } from "./use-app-actions";

export { PROTECT_ROUTE, TODAY_EVIDENCE_ROUTE, viewTitle, parseAppDetail, resolveView } from "./app-routing";
export { refreshStaleScopeContractSelection, shouldFetchArtifactDiff } from "./app-detail-state";

const HomeWorkspace = lazyWorkspace("home-dashboard", () => import("./home-dashboard").then((m) => ({ default: m.HomeWorkspace })));
const FleetWorkspace = lazyWorkspace("fleet-workspace", () => import("./fleet-workspace").then((m) => ({ default: m.FleetWorkspace })));
const SettingsWorkspace = lazyWorkspace("settings-workspace", () => import("./settings-workspace").then((m) => ({ default: m.SettingsWorkspace })));
const ExtensionsWorkspace = lazyWorkspace("extensions-workspace", () =>
  import("./extensions-workspace").then((module) => ({ default: module.ExtensionsWorkspace }))
);
const AppDetailWorkspace = lazyWorkspace("app-detail-workspace", () => import("./apps/app-detail-workspace").then((m) => ({ default: m.AppDetailWorkspace })));
const HelpModal = lazyWorkspace("help-modal", () => import("./help-modal").then((m) => ({ default: m.HelpModal })));
const SupplyChainHubWorkspace = lazyWorkspace("supply-chain-hub-workspace", () =>
  import("./supply-chain-hub-workspace").then((m) => ({ default: m.SupplyChainHubWorkspace }))
);
const PolicyWorkspacePage = lazyWorkspace("policy-workspace-page", () =>
  import("./policy-workspace-page").then((m) => ({ default: m.PolicyWorkspacePage }))
);
const AboutWorkspace = lazyWorkspace("about-workspace", () =>
  import("./about/about-workspace").then((m) => ({ default: m.AboutWorkspace }))
);

function LazyFallback() {
  return (
    <div className="flex min-h-[200px] items-center justify-center">
      <div className="guard-skeleton h-8 w-48" />
    </div>
  );
}

export function App() {
  const data = useAppData();
  const {
    view,
    appDetailHarness,
    requests,
    detail,
    receipts,
    runtime,
    policies,
    inventory,
    resolutionMessage,
    codexResume,
    helpOpen,
    clearConfirm,
    approvalGate,
    setApprovalGate,
    guardVersion,
    activeRequestId,
  } = data;
  const {
    handleOpenInbox,
    handleOpenFleet,
    handleOpenEvidence,
    handleOpenTodayEvidence,
    handleOpenInsights,
    handleOpenCommands,
    handleOpenSettings,
    handleOpenSupplyChain,
    handleOpenHelp,
    handleCloseHelp,
    handleGoHome,
    handleOpenRequest,
    handleOpenAppDetail,
    refreshStateAfterAction,
    refreshStateWithoutResult,
    handleReconnectSession,
    handleClearPolicies,
    handleConfirmClear,
    handleCancelClear,
    handleClearAppPolicies,
    handleRefreshPolicies,
    handleClearPolicy,
    handleClearEvidence,
    handleResolve,
    handleRetryResume,
    handleBulkApprove,
    handleRetry,
    handleRepair,
    handleConnectHarness,
    handleTestHarness,
    handleRepairHarness,
    handleRepairProtection,
  } = useAppActions(data);

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
        onOpenApps={handleOpenFleet}
        onOpenRequest={handleOpenRequest}
        onClearAppPolicies={handleClearAppPolicies}
        onClearPolicy={handleClearPolicy}
        onManagedInstallChanged={refreshStateWithoutResult}
      />
    );
  }, [view, appDetailHarness, runtime, receipts, policies, inventory, requests, handleGoHome, handleOpenFleet, handleOpenRequest, handleClearAppPolicies, handleClearPolicy, refreshStateWithoutResult]);

  const policyContent = useMemo(() => {
    if (runtime.kind !== "ready") {
      return null;
    }
    if (policies.kind === "ready") {
      return (
        <Suspense fallback={<LazyFallback />}>
          <PolicyWorkspacePage
            snapshot={runtime.snapshot}
            policies={policies.items}
            onClearPolicy={handleClearPolicy}
            onOpenSettings={handleOpenSettings}
            onOpenInbox={handleOpenInbox}
            onRefreshPolicies={handleRefreshPolicies}
            onNavigate={navigate}
          />
        </Suspense>
      );
    }
    if (policies.kind === "error") {
      return (
        <div className="rounded-2xl border border-red-200 bg-red-50/80 px-4 py-3 text-sm text-red-700">
          {policies.message}
        </div>
      );
    }
    return <LazyFallback />;
  }, [
    runtime,
    policies,
    handleClearPolicy,
    handleOpenSettings,
    handleOpenInbox,
    handleRefreshPolicies,
    navigate,
  ]);

  return (
    <>
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:rounded-lg focus:bg-brand-blue focus:px-4 focus:py-2 focus:text-white focus:outline-none"
      >
        Skip to content
      </a>
      <div aria-live="polite" aria-atomic="true" className="sr-only">
        {viewTitle(view)}
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
            onOpenTodayEvidence={handleOpenTodayEvidence}
            onOpenInsights={handleOpenInsights}
            onOpenCommands={handleOpenCommands}
            onOpenSettings={handleOpenSettings}
            onRefreshRuntime={async () => { await refreshStateAfterAction(); }}
            onReconnectSession={handleReconnectSession}
            onOpenSupplyChain={handleOpenSupplyChain}
            onClearPolicies={handleClearPolicies}
            onOpenAppDetail={handleOpenAppDetail}
            clearConfirm={clearConfirm}
            approvalGate={approvalGate}
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
      onRetry={handleRetry}
      onRepair={handleRepair}
      onGuardReconnected={handleRetry}
      enableUpdateStatus={view !== "inbox"}
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
              onRepairProtection={handleRepairProtection}
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
      extensionsContent={
        <ErrorBoundary onReset={handleGoHome}>
          <Suspense fallback={<LazyFallback />}>
            <ExtensionsWorkspace runtime={runtime.kind === "ready" ? runtime.snapshot : null} onRefreshRuntime={refreshStateAfterAction} onNavigate={navigate} />
          </Suspense>
        </ErrorBoundary>
      }
      settingsContent={
        <Suspense fallback={<LazyFallback />}>
          <SettingsWorkspace onApprovalGateChange={setApprovalGate} />
        </Suspense>
      }
      supplyChainHubContent={
        runtime.kind === "ready" ? (
          <Suspense fallback={<LazyFallback />}>
	            <SupplyChainHubWorkspace
	              activeView={view}
	              snapshot={runtime.snapshot}
	              receipts={receipts.kind === "ready" ? receipts.items : []}
	              policies={policies.kind === "ready" ? policies.items : []}
	              approvalGate={approvalGate}
	              onClearPolicy={handleClearPolicy}
	              onOpenSettings={handleOpenSettings}
	              onGoHome={handleGoHome}
              onNavigate={navigate}
              onRuntimeRefresh={refreshStateWithoutResult}
            />
          </Suspense>
        ) : null
      }
      policyContent={policyContent}
      aboutContent={
        <Suspense fallback={<LazyFallback />}>
          <AboutWorkspace runtimeSummary={
            runtime.kind === "ready"
              ? {
                  // TODO: GuardRuntimeSnapshot does not yet expose guard_version or protected_app_count.
                  // When those fields are added, populate them here instead of null/0.
                  guardVersion: guardVersion,
                  cloudState: runtime.snapshot.cloud_state ?? "unknown",
                  cloudStateLabel: runtime.snapshot.cloud_state_label ?? "Unknown",
                  syncConfigured: runtime.snapshot.sync_configured ?? false,
                  pendingCount: runtime.snapshot.pending_count ?? 0,
                  receiptCount: runtime.snapshot.receipt_count ?? 0,
                  protectedAppCount: 0,
                }
              : null
          } />
        </Suspense>
      }
    />
    {helpOpen && (
      <ErrorBoundary onReset={handleCloseHelp}>
        <Suspense fallback={null}>
          <HelpModal open={helpOpen} onClose={handleCloseHelp} />
        </Suspense>
      </ErrorBoundary>
    )}
    </>);
}
