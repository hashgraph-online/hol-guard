import { useState, useEffect, useCallback } from "react";
import {
  HiMiniArrowPath,
  HiMiniBugAnt,
  HiMiniExclamationTriangle,
} from "react-icons/hi2";
import { ApprovalProofModal } from "./approval-proof-modal";
import { SectionLabel, ActionButton, EmptyState } from "./approval-center-primitives";
import type {
  GuardApprovalGatePublicConfig,
  PackageFirewallStatusResponse,
  PackageFirewallActionType,
} from "./guard-types";
import {
  fetchPackageFirewallStatus,
  GuardHarnessActionError,
  runPackageFirewallAction,
  runPackageAudit,
  runPackageSync,
  startPackageFirewallConnect,
} from "./guard-api";
import { EntitlementNotice, ActionResultPanel, ActivationSummary } from "./supply-chain-firewall-views";
import type { CompletedOp } from "./supply-chain-firewall-views";
import { ManagerActionCard } from "./supply-chain-manager-card";
import { useResolvedApprovalGate } from "./use-resolved-approval-gate";

type PanelLoadState =
  | { phase: "loading" }
  | { phase: "error"; message: string }
  | { phase: "loaded"; data: PackageFirewallStatusResponse };

type OpKey = PackageFirewallActionType | "audit" | "sync";

type PendingOp = {
  op: OpKey;
  manager: string | null;
};

type FailedOp = {
  op: OpKey;
  manager: string | null;
  message: string;
};

type ApprovalOp = {
  op: PackageFirewallActionType;
  manager: string;
};

type LoadingRowProps = { width: string };

function LoadingRow({ width }: LoadingRowProps) {
  return (
    <div className={`h-4 animate-pulse rounded-md bg-slate-100 ${width}`} aria-hidden="true" />
  );
}

function LoadingSkeleton() {
  return (
    <div
      className="space-y-3 px-4 py-5"
      aria-label="Loading package firewall status"
      aria-busy="true"
    >
      <LoadingRow width="w-1/3" />
      <LoadingRow width="w-2/3" />
      <LoadingRow width="w-1/2" />
    </div>
  );
}

type ErrorBannerProps = {
  message: string;
  onRetry: () => void;
};

function ErrorBanner({ message, onRetry }: ErrorBannerProps) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-4">
      <div className="flex items-start gap-2">
        <HiMiniExclamationTriangle
          className="mt-0.5 h-4 w-4 shrink-0 text-brand-attention"
          aria-hidden="true"
        />
        <p className="text-sm text-brand-attention">{message}</p>
      </div>
      <ActionButton variant="outline" onClick={onRetry}>
        Retry
      </ActionButton>
    </div>
  );
}

type GlobalActionsBarProps = {
  anyPending: boolean;
  pendingOp: PendingOp | null;
  onAudit: () => void;
  onSync: () => void;
};

function GlobalActionsBar({ anyPending, pendingOp, onAudit, onSync }: GlobalActionsBarProps) {
  const auditRunning = pendingOp?.op === "audit";
  const syncRunning = pendingOp?.op === "sync";
  return (
    <div className="flex flex-wrap items-center gap-2">
      <ActionButton
        variant="outline"
        onClick={onAudit}
        disabled={anyPending}
        aria-busy={auditRunning}
      >
        {auditRunning ? (
          <HiMiniArrowPath className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden="true" />
        ) : (
          <HiMiniBugAnt className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
        )}
        Audit
      </ActionButton>
      <ActionButton
        variant="outline"
        onClick={onSync}
        disabled={anyPending}
        aria-busy={syncRunning}
      >
        <HiMiniArrowPath
          className={`mr-1.5 h-3.5 w-3.5 ${syncRunning ? "animate-spin" : ""}`}
          aria-hidden="true"
        />
        Sync
      </ActionButton>
    </div>
  );
}

type FailureBannerProps = {
  failed: FailedOp;
};

function FailureBanner({ failed }: FailureBannerProps) {
  return (
    <div
      className="flex items-start gap-2 rounded-xl border border-brand-attention/30 bg-brand-attention/[0.04] px-3 py-2.5"
      role="alert"
      aria-live="assertive"
    >
      <HiMiniExclamationTriangle
        className="mt-0.5 h-4 w-4 shrink-0 text-brand-attention"
        aria-hidden="true"
      />
      <div className="min-w-0">
        <p className="text-sm font-medium text-brand-dark">
          {failed.op} failed{failed.manager !== null ? ` for ${failed.manager}` : ""}
        </p>
        <p className="mt-0.5 text-xs text-slate-600">{failed.message}</p>
      </div>
    </div>
  );
}

type FirewallControlsViewProps = {
  data: PackageFirewallStatusResponse;
  pendingOp: PendingOp | null;
  lastCompleted: CompletedOp | null;
  lastFailed: FailedOp | null;
  confirmRemoveManager: string | null;
  showGlobalActions: boolean;
  onInstall: (manager: string) => void;
  onRepair: (manager: string) => void;
  onTest: (manager: string) => void;
  onRemoveRequest: (manager: string) => void;
  onRemoveConfirm: (manager: string) => void;
  onRemoveCancel: () => void;
  onAudit: () => void;
  onSync: () => void;
  onDismissResult: () => void;
};

function FirewallControlsView({
  data,
  pendingOp,
  lastCompleted,
  lastFailed,
  confirmRemoveManager,
  showGlobalActions,
  onInstall,
  onRepair,
  onTest,
  onRemoveRequest,
  onRemoveConfirm,
  onRemoveCancel,
  onAudit,
  onSync,
  onDismissResult,
}: FirewallControlsViewProps) {
  const anyPending = pendingOp !== null;
  return (
    <div className="space-y-4 px-4 py-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm font-medium text-brand-dark">Per-manager controls</p>
        {showGlobalActions && (
          <GlobalActionsBar
            anyPending={anyPending}
            pendingOp={pendingOp}
            onAudit={onAudit}
            onSync={onSync}
          />
        )}
      </div>

      <ActivationSummary protection={data.protection} />

      {lastFailed !== null && <FailureBanner failed={lastFailed} />}

      {lastCompleted !== null && (
        <ActionResultPanel completed={lastCompleted} onDismiss={onDismissResult} />
      )}

      {data.package_shims.length === 0 ? (
        <EmptyState
          title="No package managers detected"
          body="Guard has not detected any package managers on this machine."
          tone="teach"
        />
      ) : (
        <div className="grid gap-3 sm:grid-cols-2">
          {data.package_shims.map((shim) => (
            <ManagerActionCard
              key={shim.manager}
              shim={shim}
              actions={data.actions}
              anyPending={anyPending}
              isMine={pendingOp?.manager === shim.manager}
              isConfirmingRemove={confirmRemoveManager === shim.manager}
              onInstall={onInstall}
              onRepair={onRepair}
              onTest={onTest}
              onRemoveRequest={onRemoveRequest}
              onRemoveConfirm={onRemoveConfirm}
              onRemoveCancel={onRemoveCancel}
            />
          ))}
        </div>
      )}
    </div>
  );
}

type RefreshButtonProps = {
  disabled: boolean;
  spinning: boolean;
  onRefresh: () => void;
};

function RefreshButton({ disabled, spinning, onRefresh }: RefreshButtonProps) {
  return (
    <ActionButton
      variant="ghost"
      onClick={onRefresh}
      disabled={disabled}
      aria-label="Refresh status"
    >
      <HiMiniArrowPath
        className={`h-4 w-4 ${spinning ? "animate-spin" : ""}`}
        aria-hidden="true"
      />
    </ActionButton>
  );
}

export function PackageFirewallPanel(props: {
  approvalGate: GuardApprovalGatePublicConfig | null;
  onStateChanged?: () => Promise<void> | void;
}) {
  const { approvalGate, onStateChanged } = props;
  const [panelLoad, setPanelLoad] = useState<PanelLoadState>({ phase: "loading" });
  const [pendingOp, setPendingOp] = useState<PendingOp | null>(null);
  const [lastCompleted, setLastCompleted] = useState<CompletedOp | null>(null);
  const [lastFailed, setLastFailed] = useState<FailedOp | null>(null);
  const [connectError, setConnectError] = useState<string | null>(null);
  const [startingConnect, setStartingConnect] = useState(false);
  const [confirmRemoveManager, setConfirmRemoveManager] = useState<string | null>(null);
  const [pendingApprovalOp, setPendingApprovalOp] = useState<ApprovalOp | null>(null);
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(approvalGate);

  const load = useCallback(async () => {
    setPanelLoad({ phase: "loading" });
    try {
      const data = await fetchPackageFirewallStatus();
      setPanelLoad({ phase: "loaded", data });
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to load package firewall status.";
      setPanelLoad({ phase: "error", message });
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const refreshAfterOp = useCallback(async () => {
    try {
      const data = await fetchPackageFirewallStatus();
      setPanelLoad({ phase: "loaded", data });
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to refresh package firewall status.";
      setPanelLoad({ phase: "error", message });
    }
  }, []);

  useEffect(() => {
    if (panelLoad.phase !== "loaded") {
      return;
    }
    const flow = panelLoad.data.connect_flow;
    if (flow === null || flow.state !== "running") {
      return;
    }
    const handle = window.setTimeout(() => {
      void refreshAfterOp();
    }, flow.poll_after_ms ?? 1500);
    return () => window.clearTimeout(handle);
  }, [panelLoad, refreshAfterOp]);

  const handleAction = useCallback(
    async (
      op: PackageFirewallActionType,
      manager: string | null,
      credentials?: { approval_password?: string; approval_totp_code?: string },
    ) => {
      setPendingOp({ op, manager });
      setLastFailed(null);
      setConnectError(null);
      try {
        const response = await runPackageFirewallAction(op, manager, credentials);
        setLastCompleted({ op, manager, response });
        await refreshAfterOp();
        await onStateChanged?.();
      } catch (err) {
        if (
          credentials === undefined &&
          manager !== null &&
          err instanceof GuardHarnessActionError &&
          err.payload?.error === "approval_gate_required"
        ) {
          await resolveApprovalGate();
          setPendingApprovalOp({ op, manager });
          return;
        }
        const message = err instanceof Error ? err.message : "Action failed.";
        setLastFailed({ op, manager, message });
      } finally {
        setPendingOp(null);
      }
    },
    [onStateChanged, refreshAfterOp, resolveApprovalGate],
  );

  const handleGlobalOp = useCallback(
    async (op: "audit" | "sync") => {
      setPendingOp({ op, manager: null });
      setLastFailed(null);
      setConnectError(null);
      try {
        const response = op === "audit" ? await runPackageAudit() : await runPackageSync();
        setLastCompleted({ op, manager: null, response });
        await refreshAfterOp();
        await onStateChanged?.();
      } catch (err) {
        const message = err instanceof Error ? err.message : "Operation failed.";
        setLastFailed({ op, manager: null, message });
      } finally {
        setPendingOp(null);
      }
    },
    [onStateChanged, refreshAfterOp],
  );

  const handleInstall = useCallback(
    (manager: string) => void handleAction("install", manager),
    [handleAction],
  );
  const handleRepair = useCallback(
    (manager: string) => void handleAction("repair", manager),
    [handleAction],
  );
  const handleTest = useCallback(
    (manager: string) => void handleAction("test", manager),
    [handleAction],
  );
  const handleRemoveRequest = useCallback(
    (manager: string) => setConfirmRemoveManager(manager),
    [],
  );
  const handleRemoveConfirm = useCallback(
    (manager: string) => {
      setConfirmRemoveManager(null);
      void handleAction("remove", manager);
    },
    [handleAction],
  );
  const handleRemoveCancel = useCallback(() => setConfirmRemoveManager(null), []);
  const handleAudit = useCallback(() => void handleGlobalOp("audit"), [handleGlobalOp]);
  const handleSync = useCallback(() => void handleGlobalOp("sync"), [handleGlobalOp]);
  const handleDismissResult = useCallback(() => setLastCompleted(null), []);
  const handleRetry = useCallback(() => void load(), [load]);
  const handleStartConnect = useCallback(async () => {
    setStartingConnect(true);
    setConnectError(null);
    try {
      await startPackageFirewallConnect();
      await refreshAfterOp();
      await onStateChanged?.();
    } catch (error) {
      setConnectError(
        error instanceof Error ? error.message : "Unable to start Guard Cloud connect.",
      );
    } finally {
      setStartingConnect(false);
    }
  }, [onStateChanged, refreshAfterOp]);
  const handleApprovalCancel = useCallback(() => setPendingApprovalOp(null), []);
  const handleApprovalConfirm = useCallback(
    (credentials: { approval_password?: string; approval_totp_code?: string }) => {
      const pendingApproval = pendingApprovalOp;
      if (pendingApproval === null) return;
      setPendingApprovalOp(null);
      void handleAction(pendingApproval.op, pendingApproval.manager, credentials);
    },
    [handleAction, pendingApprovalOp],
  );

  const anyPending = pendingOp !== null;
  return (
    <div className="rounded-2xl border border-slate-100 bg-white shadow-sm">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 px-4 py-3">
        <div>
          <SectionLabel>Package manager firewall</SectionLabel>
          <p className="mt-0.5 text-sm text-slate-500">
            Install Guard shims, activate PATH routing, and verify protection on this machine.
          </p>
        </div>
        {panelLoad.phase === "loaded" && (
          <RefreshButton disabled={anyPending} spinning={anyPending} onRefresh={handleRetry} />
        )}
      </div>

      {panelLoad.phase === "loading" && <LoadingSkeleton />}

      {panelLoad.phase === "error" && (
        <ErrorBanner message={panelLoad.message} onRetry={handleRetry} />
      )}

      {panelLoad.phase === "loaded" && (
        <>
          {!panelLoad.data.entitlement.allowed && (
            <div className="border-b border-slate-100">
              <EntitlementNotice
                connectError={connectError}
                connectStarting={startingConnect}
                data={panelLoad.data}
                onStartConnect={handleStartConnect}
              />
            </div>
          )}
          <FirewallControlsView
            data={panelLoad.data}
            pendingOp={pendingOp}
            lastCompleted={lastCompleted}
            lastFailed={lastFailed}
            confirmRemoveManager={confirmRemoveManager}
            showGlobalActions={panelLoad.data.entitlement.allowed}
            onInstall={handleInstall}
            onRepair={handleRepair}
            onTest={handleTest}
            onRemoveRequest={handleRemoveRequest}
            onRemoveConfirm={handleRemoveConfirm}
            onRemoveCancel={handleRemoveCancel}
            onAudit={handleAudit}
            onSync={handleSync}
            onDismissResult={handleDismissResult}
          />
        </>
      )}

      {pendingApprovalOp !== null && (
        <ApprovalProofModal
          title={`${actionLabel(pendingApprovalOp.op)} ${pendingApprovalOp.manager}`}
          detail="Enter local approval proof before Guard changes package-manager protection on this device."
          confirmLabel={actionLabel(pendingApprovalOp.op)}
          approvalGate={resolvedApprovalGate}
          onCancel={handleApprovalCancel}
          onConfirm={handleApprovalConfirm}
        />
      )}
    </div>
  );
}

function actionLabel(op: PackageFirewallActionType): string {
  return op.charAt(0).toUpperCase() + op.slice(1);
}
