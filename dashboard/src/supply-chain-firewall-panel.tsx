import { useState, useEffect, useCallback, forwardRef, useImperativeHandle, useRef } from "react";
import type { ChangeEvent, MutableRefObject } from "react";
import { HiMiniArrowPath, HiMiniExclamationTriangle } from "react-icons/hi2";
import { ApprovalProofModal } from "./approval-proof-modal";
import { SectionLabel, ActionButton } from "./approval-center-primitives";
import type {
  GuardApprovalGatePublicConfig,
  PackageFirewallStatusResponse,
  PackageFirewallActionType,
} from "./guard-types";
import {
  fetchPackageFirewallStatus,
  GuardHarnessActionError,
  openPackageFirewallShell,
  runPackageFirewallAction,
  runPackageAudit,
  runPackageSync,
  startPackageFirewallConnect,
} from "./guard-api";
import { EntitlementNotice, ConnectFlowCard } from "./supply-chain-firewall-views";
import type { CompletedOp } from "./supply-chain-firewall-views";
import {
  isSupplyChainAuditConnectError,
  packageAuditNeedsCloudConnect,
  resolveSupplyChainAuditConnectGate,
  resolveSupplyChainAuditFailure,
  supplyChainAuditUserMessage,
  type SupplyChainAuditConnectGate,
} from "./supply-chain-audit-connect";
import { resolveSupplyChainAuditWorkspaceTarget } from "./supply-chain-audit-workspace";
import {
  FirewallControlsView,
  type FirewallFailedOp,
  type FirewallPendingOp,
  type FirewallStatusFilter,
} from "./supply-chain-firewall-controls";
import { useResolvedApprovalGate } from "./use-resolved-approval-gate";
import { parseInterceptProofSnapshot, type InterceptProofSnapshot } from "./supply-chain-firewall-action-result";
import { InterceptProofModal } from "./supply-chain-intercept-proof-modal";
import { SupplyChainManagerDrawer } from "./supply-chain-manager-drawer";
import { resolveSupplyChainAuditRecoveryGate, type SupplyChainAuditRecoveryGate } from "./supply-chain-audit-recovery";
import {
  AuditRecoveryModal,
  type AuditRecoveryModalPhase,
} from "./supply-chain-audit-recovery-modal";

type PanelLoadState =
  | { phase: "loading" }
  | { phase: "error"; message: string }
  | { phase: "loaded"; data: PackageFirewallStatusResponse };

type PendingOp = FirewallPendingOp;
type FailedOp = FirewallFailedOp;

type ApprovalOp = {
  op: PackageFirewallActionType;
  manager: string;
};

type StatusFilter = FirewallStatusFilter;

export type PackageFirewallPanelHandle = {
  scrollIntoView: () => void;
  focusUnprotected: () => void;
  focusActionable: () => void;
  runAudit: () => void;
  startConnect: () => Promise<void>;
  openShell: () => Promise<void>;
};

function actionLabel(op: PackageFirewallActionType): string {
  return op.charAt(0).toUpperCase() + op.slice(1);
}

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

export type AuditConnectGateViewState = {
  gate: SupplyChainAuditConnectGate;
  connectError: string | null;
  connectStarting: boolean;
  connectFlow: NonNullable<PackageFirewallStatusResponse["connect_flow"]>;
  onStartConnect: () => void;
};

export const PackageFirewallPanel = forwardRef(function PackageFirewallPanel(
  props: {
  approvalGate: GuardApprovalGatePublicConfig | null;
  auditWorkspaceDir?: string | null;
  onAuditConnectGateChange?: (state: AuditConnectGateViewState | null) => void;
  onAuditErrorChange?: (message: string | null) => void;
  onStateChanged?: () => Promise<void> | void;
  onAuditCompleted?: (resultDetail: Record<string, unknown>) => void;
  onAuditRunningChange?: (running: boolean) => void;
  runAuditRef?: MutableRefObject<(() => void) | null>;
},
  ref,
) {
  const {
    approvalGate,
    auditWorkspaceDir,
    onAuditConnectGateChange,
    onAuditErrorChange,
    onStateChanged,
    onAuditCompleted,
    onAuditRunningChange,
    runAuditRef,
  } = props;
  const rootRef = useRef<HTMLDivElement>(null);
  const recoveryConnectHandledRef = useRef(false);
  const [panelLoad, setPanelLoad] = useState<PanelLoadState>({ phase: "loading" });
  const [pendingOp, setPendingOp] = useState<PendingOp | null>(null);
  const [lastCompleted, setLastCompleted] = useState<CompletedOp | null>(null);
  const [lastFailed, setLastFailed] = useState<FailedOp | null>(null);
  const [connectError, setConnectError] = useState<string | null>(null);
  const [activationAssistError, setActivationAssistError] = useState<string | null>(null);
  const [startingConnect, setStartingConnect] = useState(false);
  const [openingShell, setOpeningShell] = useState(false);
  const [confirmRemoveManager, setConfirmRemoveManager] = useState<string | null>(null);
  const [pendingApprovalOp, setPendingApprovalOp] = useState<ApprovalOp | null>(null);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [managerFilter, setManagerFilter] = useState("");
  const [interceptProof, setInterceptProof] = useState<InterceptProofSnapshot | null>(null);
  const [managerDrawerTarget, setManagerDrawerTarget] = useState<string | null>(null);
  const [auditConnectGateActive, setAuditConnectGateActive] = useState(false);
  const [resumeAuditAfterConnect, setResumeAuditAfterConnect] = useState(false);
  const [auditRecoveryGate, setAuditRecoveryGate] = useState<SupplyChainAuditRecoveryGate | null>(null);
  const [auditRecoveryPhase, setAuditRecoveryPhase] = useState<AuditRecoveryModalPhase>("ready");
  const [auditRecoveryError, setAuditRecoveryError] = useState<string | null>(null);
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(approvalGate);

  const closeAuditRecovery = useCallback(() => {
    setAuditRecoveryGate(null);
    setAuditRecoveryPhase("ready");
    setAuditRecoveryError(null);
  }, []);

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

  const openAuditConnectGate = useCallback((resumeAfterConnect: boolean) => {
    setAuditConnectGateActive(true);
    setResumeAuditAfterConnect(resumeAfterConnect);
    setLastFailed(null);
    rootRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);

  const clearAuditConnectGate = useCallback(() => {
    setAuditConnectGateActive(false);
    setResumeAuditAfterConnect(false);
  }, []);

  const runAuditOperation = useCallback(
    async (options?: { openRecoveryModal?: boolean }) => {
      const openRecoveryModal = options?.openRecoveryModal ?? true;
      setPendingOp({ op: "audit", manager: null });
      setLastFailed(null);
      setConnectError(null);
      setActivationAssistError(null);
      onAuditErrorChange?.(null);
      onAuditRunningChange?.(true);
      const statusWorkspaceDir =
        panelLoad.phase === "loaded" ? panelLoad.data.audit_workspace_dir ?? null : null;
      const workspaceDir = resolveSupplyChainAuditWorkspaceTarget({
        managedWorkspaceDir: auditWorkspaceDir,
        statusWorkspaceDir,
      });
      try {
        const response = await runPackageAudit({ workspaceDir });
        const recoveryGate = resolveSupplyChainAuditRecoveryGate(response.result_detail);
        const failureMessage = resolveSupplyChainAuditFailure(response.result_detail);
        if (failureMessage !== null) {
          if (openRecoveryModal && recoveryGate !== null) {
            setAuditRecoveryGate(recoveryGate);
            setAuditRecoveryPhase("ready");
            setAuditRecoveryError(null);
            onAuditErrorChange?.(null);
            clearAuditConnectGate();
            await refreshAfterOp();
            await onStateChanged?.();
            return false;
          }
          setLastFailed({ op: "audit", manager: null, message: failureMessage });
          setLastCompleted(null);
          onAuditErrorChange?.(failureMessage);
          clearAuditConnectGate();
          await refreshAfterOp();
          await onStateChanged?.();
          return false;
        }
        setLastCompleted({ op: "audit", manager: null, response });
        onAuditCompleted?.(response.result_detail);
        clearAuditConnectGate();
        closeAuditRecovery();
        onAuditErrorChange?.(null);
        await refreshAfterOp();
        await onStateChanged?.();
        return true;
      } catch (err) {
        if (isSupplyChainAuditConnectError(err)) {
          openAuditConnectGate(true);
          return false;
        }
        const message = supplyChainAuditUserMessage(err) ?? "Operation failed.";
        setLastFailed({ op: "audit", manager: null, message });
        onAuditErrorChange?.(message);
        setAuditRecoveryPhase("failed");
        setAuditRecoveryError(message);
        return false;
      } finally {
        onAuditRunningChange?.(false);
        setPendingOp(null);
      }
    },
    [
      auditWorkspaceDir,
      clearAuditConnectGate,
      closeAuditRecovery,
      onAuditCompleted,
      onAuditErrorChange,
      onAuditRunningChange,
      onStateChanged,
      openAuditConnectGate,
      panelLoad,
      refreshAfterOp,
    ],
  );

  const continueAuditAfterRecovery = useCallback(async () => {
    setAuditRecoveryPhase("auditing");
    setAuditRecoveryError(null);
    const succeeded = await runAuditOperation({ openRecoveryModal: true });
    if (succeeded) {
      return;
    }
    setAuditRecoveryPhase((currentPhase) => (currentPhase === "failed" ? "failed" : "ready"));
  }, [runAuditOperation]);

  const runRecoverySync = useCallback(
    async (credentials?: { approval_password?: string; approval_totp_code?: string }) => {
      setAuditRecoveryPhase("syncing");
      setAuditRecoveryError(null);
      try {
        const response = await runPackageSync(credentials);
        setLastCompleted({ op: "sync", manager: null, response });
        await refreshAfterOp();
        await onStateChanged?.();
        if (auditRecoveryGate?.autoRetryAuditAfterPrimary) {
          await continueAuditAfterRecovery();
          return;
        }
        setAuditRecoveryPhase("ready");
      } catch (err) {
        if (isSupplyChainAuditConnectError(err)) {
          const connectGate = resolveSupplyChainAuditRecoveryGate({
            audit_status: "incomplete",
            audit_outcome: "not_connected",
          });
          if (connectGate !== null) {
            setAuditRecoveryGate(connectGate);
          }
          setAuditRecoveryPhase("ready");
          setAuditRecoveryError(null);
          return;
        }
        if (
          credentials === undefined &&
          err instanceof GuardHarnessActionError &&
          err.payload?.error === "approval_gate_required"
        ) {
          await resolveApprovalGate();
          setAuditRecoveryPhase("approval");
          setAuditRecoveryError(null);
          return;
        }
        const message = err instanceof Error ? err.message : "Sync failed.";
        setAuditRecoveryError(message);
        setAuditRecoveryPhase(credentials === undefined ? "failed" : "approval");
        setLastFailed({ op: "sync", manager: null, message });
      }
    },
    [
      auditRecoveryGate,
      continueAuditAfterRecovery,
      onStateChanged,
      refreshAfterOp,
      resolveApprovalGate,
    ],
  );

  const handleRecoveryApprovalBack = useCallback(() => {
    setAuditRecoveryPhase("ready");
    setAuditRecoveryError(null);
  }, []);

  const handleRecoveryApprovalSubmit = useCallback(
    (credentials: { approval_password?: string; approval_totp_code?: string }) => {
      void runRecoverySync(credentials);
    },
    [runRecoverySync],
  );

  const handleStartConnect = useCallback(async () => {
    setStartingConnect(true);
    setConnectError(null);
    setActivationAssistError(null);
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

  const handleRecoveryPrimary = useCallback(() => {
    if (
      auditRecoveryGate === null ||
      (auditRecoveryPhase !== "ready" && auditRecoveryPhase !== "failed")
    ) {
      return;
    }
    if (auditRecoveryGate.primaryAction === "sync") {
      void runRecoverySync();
      return;
    }
    if (auditRecoveryGate.primaryAction === "connect") {
      setAuditRecoveryPhase("connecting");
      setAuditRecoveryError(null);
      void handleStartConnect();
      return;
    }
    void continueAuditAfterRecovery();
  }, [
    auditRecoveryGate,
    auditRecoveryPhase,
    continueAuditAfterRecovery,
    handleStartConnect,
    runRecoverySync,
  ]);

  useEffect(() => {
    if (panelLoad.phase !== "loaded" || !auditConnectGateActive) {
      onAuditConnectGateChange?.(null);
      return;
    }
    const gate = resolveSupplyChainAuditConnectGate(panelLoad.data, {
      resumeAfterConnect: resumeAuditAfterConnect,
    });
    if (gate === null || panelLoad.data.connect_flow === null) {
      onAuditConnectGateChange?.(null);
      return;
    }
    onAuditConnectGateChange?.({
      gate,
      connectError,
      connectStarting: startingConnect,
      connectFlow: panelLoad.data.connect_flow,
      onStartConnect: () => {
        void handleStartConnect();
      },
    });
  }, [
    auditConnectGateActive,
    connectError,
    handleStartConnect,
    onAuditConnectGateChange,
    panelLoad,
    resumeAuditAfterConnect,
    startingConnect,
  ]);

  useEffect(() => {
    if (panelLoad.phase !== "loaded" || !resumeAuditAfterConnect) {
      return;
    }
    if (!panelLoad.data.entitlement.allowed || packageAuditNeedsCloudConnect(panelLoad.data)) {
      return;
    }
    setResumeAuditAfterConnect(false);
    void runAuditOperation();
  }, [panelLoad, resumeAuditAfterConnect, runAuditOperation]);

  useEffect(() => {
    if (auditRecoveryPhase === "connecting") {
      recoveryConnectHandledRef.current = false;
    }
  }, [auditRecoveryPhase]);

  useEffect(() => {
    if (panelLoad.phase !== "loaded" || auditRecoveryGate === null) {
      return;
    }
    if (auditRecoveryPhase !== "connecting") {
      return;
    }
    if (recoveryConnectHandledRef.current) {
      return;
    }
    if (!panelLoad.data.entitlement.allowed || packageAuditNeedsCloudConnect(panelLoad.data)) {
      return;
    }
    recoveryConnectHandledRef.current = true;
    void runRecoverySync();
  }, [auditRecoveryGate, auditRecoveryPhase, panelLoad, runRecoverySync]);

  const handleAction = useCallback(
    async (
      op: PackageFirewallActionType,
      manager: string | null,
      credentials?: { approval_password?: string; approval_totp_code?: string },
    ) => {
      setPendingOp({ op, manager });
      setLastFailed(null);
      setConnectError(null);
      setActivationAssistError(null);
      try {
        const response = await runPackageFirewallAction(op, manager, credentials);
        setLastCompleted({ op, manager, response });
        if (op === "test") {
          const proof = parseInterceptProofSnapshot(response);
          if (proof !== null) {
            setManagerDrawerTarget(null);
            setInterceptProof(proof);
          }
        }
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
      if (op === "audit") {
        if (panelLoad.phase === "loaded" && packageAuditNeedsCloudConnect(panelLoad.data)) {
          openAuditConnectGate(true);
          return;
        }
        await runAuditOperation();
        return;
      }
      setPendingOp({ op, manager: null });
      setLastFailed(null);
      setConnectError(null);
      setActivationAssistError(null);
      try {
        const response = await runPackageSync();
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
    [onStateChanged, openAuditConnectGate, panelLoad, refreshAfterOp, runAuditOperation],
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
  const handleAudit = useCallback(() => {
    if (panelLoad.phase === "loaded" && packageAuditNeedsCloudConnect(panelLoad.data)) {
      openAuditConnectGate(true);
      return;
    }
    void runAuditOperation();
  }, [openAuditConnectGate, panelLoad, runAuditOperation]);
  const handleSync = useCallback(() => void handleGlobalOp("sync"), [handleGlobalOp]);

  useEffect(() => {
    if (runAuditRef === undefined) {
      return;
    }
    runAuditRef.current = handleAudit;
    return () => {
      runAuditRef.current = null;
    };
  }, [handleAudit, runAuditRef]);
  const handleDismissResult = useCallback(() => setLastCompleted(null), []);
  const handleRetry = useCallback(() => void load(), [load]);
  const handleOpenShell = useCallback(async () => {
    setOpeningShell(true);
    setActivationAssistError(null);
    try {
      await openPackageFirewallShell();
    } catch (error) {
      setActivationAssistError(error instanceof Error ? error.message : "Unable to open a new shell.");
    } finally {
      setOpeningShell(false);
    }
  }, []);
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

  const handleStatusFilterChange = useCallback((filter: StatusFilter) => {
    setStatusFilter(filter);
  }, []);

  const handleManagerFilterChange = useCallback((e: ChangeEvent<HTMLInputElement>) => {
    setManagerFilter(e.target.value);
  }, []);

  const handleOpenManagerDetails = useCallback((manager: string) => {
    setManagerDrawerTarget(manager);
  }, []);

  const handleCloseManagerDrawer = useCallback(() => {
    setManagerDrawerTarget(null);
  }, []);

  const handleCloseInterceptProof = useCallback(() => {
    setInterceptProof(null);
  }, []);

  useImperativeHandle(
    ref,
    () => ({
      scrollIntoView: () => {
        rootRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      },
      focusUnprotected: () => {
        setStatusFilter("unprotected");
        setManagerFilter("");
      },
      focusActionable: () => {
        setStatusFilter("actionable");
        setManagerFilter("");
      },
      runAudit: () => {
        handleAudit();
      },
      startConnect: handleStartConnect,
      openShell: handleOpenShell,
    }),
    [handleAudit, handleOpenShell, handleStartConnect],
  );


  const managerDrawerShim =
    panelLoad.phase === "loaded" && managerDrawerTarget !== null
      ? panelLoad.data.package_shims.find((entry) => entry.manager === managerDrawerTarget)
      : undefined;

  const auditConnectGate =
    panelLoad.phase === "loaded" && auditConnectGateActive
      ? resolveSupplyChainAuditConnectGate(panelLoad.data, { resumeAfterConnect: resumeAuditAfterConnect })
      : null;

  const anyPending = pendingOp !== null;
  return (
    <div ref={rootRef} className="rounded-2xl border border-slate-100 bg-white shadow-sm" data-testid="package-firewall-panel">
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
                connectPurpose={auditConnectGateActive ? "audit" : "package_firewall"}
                connectStarting={startingConnect}
                data={panelLoad.data}
                headline={auditConnectGate?.headline}
                detail={auditConnectGate?.detail}
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
            statusFilter={statusFilter}
            managerFilter={managerFilter}
            onStatusFilterChange={handleStatusFilterChange}
            onManagerFilterChange={handleManagerFilterChange}
            onInstall={handleInstall}
            onRepair={handleRepair}
            onTest={handleTest}
            onRemoveRequest={handleRemoveRequest}
            onRemoveConfirm={handleRemoveConfirm}
            onRemoveCancel={handleRemoveCancel}
            onAudit={handleAudit}
            onSync={handleSync}
            onDismissResult={handleDismissResult}
            onOpenShell={handleOpenShell}
            onRefreshStatus={handleRetry}
            onOpenManagerDetails={handleOpenManagerDetails}
            openingShell={openingShell}
            activationAssistError={activationAssistError}
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

      {panelLoad.phase === "loaded" && managerDrawerTarget !== null && (
        <SupplyChainManagerDrawer
          manager={managerDrawerTarget}
          shim={managerDrawerShim}
          actions={panelLoad.data.actions}
          anyPending={anyPending}
          isMine={pendingOp?.manager === managerDrawerTarget}
          actionHandlers={{
            install: handleInstall,
            repair: handleRepair,
            test: handleTest,
            removeRequest: handleRemoveRequest,
          }}
          onClose={handleCloseManagerDrawer}
        />
      )}

      {interceptProof !== null && (
        <InterceptProofModal proof={interceptProof} onClose={handleCloseInterceptProof} />
      )}

      {auditRecoveryGate !== null ? (
        <AuditRecoveryModal
          gate={auditRecoveryGate}
          phase={auditRecoveryPhase}
          error={auditRecoveryError}
          connectError={connectError}
          connectStarting={startingConnect}
          connectFlow={panelLoad.phase === "loaded" ? panelLoad.data.connect_flow : null}
          approvalGate={resolvedApprovalGate}
          onClose={closeAuditRecovery}
          onPrimaryAction={handleRecoveryPrimary}
          onStartConnect={() => {
            setAuditRecoveryPhase("connecting");
            void handleStartConnect();
          }}
          onApprovalSubmit={handleRecoveryApprovalSubmit}
          onApprovalBack={handleRecoveryApprovalBack}
        />
      ) : null}
    </div>
  );
});
