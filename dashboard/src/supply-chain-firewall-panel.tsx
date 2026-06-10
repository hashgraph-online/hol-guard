import { useState, useEffect, useCallback, useMemo } from "react";
import type { ChangeEvent, ReactNode } from "react";
import {
  HiMiniArrowPath,
  HiMiniBugAnt,
  HiMiniExclamationTriangle,
  HiMiniShieldCheck,
  HiMiniWrenchScrewdriver,
  HiMiniBeaker,
  HiMiniTrash,
  HiMiniCheckCircle,
  HiMiniClock,
  HiMiniMagnifyingGlass,
  HiMiniXCircle,
} from "react-icons/hi2";
import { formatRelativeTime } from "./approval-center-utils";
import { ApprovalProofModal } from "./approval-proof-modal";
import { SectionLabel, Tag, ActionButton, IconActionButton, EmptyState } from "./approval-center-primitives";
import type {
  GuardApprovalGatePublicConfig,
  PackageFirewallStatusResponse,
  PackageFirewallActionType,
  PackageShimEntry,
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
import {
  EntitlementNotice,
  ActionResultPanel,
  ActivationSummary,
  NextActionHero,
} from "./supply-chain-firewall-views";
import { resolvePackageFirewallNextAction } from "./supply-chain-firewall-next-action";
import type { CompletedOp } from "./supply-chain-firewall-views";
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

type StatusFilter = "all" | "protected" | "actionable" | "unprotected";

function resolveShimStatus(shim: PackageShimEntry | undefined): {
  label: string;
  tone: "green" | "blue" | "attention" | "slate";
  icon: "check" | "restart" | "warning" | "none";
} {
  if (!shim) {
    return { label: "Unprotected", tone: "attention", icon: "warning" };
  }
  if (!shim.installed && shim.detected) {
    return { label: "Detected, not protected", tone: "slate", icon: "warning" };
  }
  if (!shim.installed) {
    return { label: "Unprotected", tone: "attention", icon: "warning" };
  }
  if (shim.path_broken) {
    return { label: "PATH broken", tone: "attention", icon: "warning" };
  }
  if (shim.activation_state === "protected") {
    return { label: "Protected", tone: "green", icon: "check" };
  }
  if (shim.activation_state === "restart_required") {
    return { label: "Restart required", tone: "blue", icon: "restart" };
  }
  if (shim.activation_state === "repair_required") {
    return { label: "Needs PATH repair", tone: "attention", icon: "warning" };
  }
  return { label: "Unprotected", tone: "attention", icon: "warning" };
}

function actionIsAvailable(state: string | undefined): boolean {
  return state === "available";
}

function actionLabel(op: PackageFirewallActionType): string {
  return op.charAt(0).toUpperCase() + op.slice(1);
}

type ManagerRowProps = {
  manager: string;
  shim: PackageShimEntry | undefined;
  actions: PackageFirewallStatusResponse["actions"];
  anyPending: boolean;
  isMine: boolean;
  isConfirmingRemove: boolean;
  onInstall: (manager: string) => void;
  onRepair: (manager: string) => void;
  onTest: (manager: string) => void;
  onRemoveRequest: (manager: string) => void;
  onRemoveConfirm: (manager: string) => void;
  onRemoveCancel: () => void;
};

function ManagerRow({
  manager,
  shim,
  actions,
  anyPending,
  isMine,
  isConfirmingRemove,
  onInstall,
  onRepair,
  onTest,
  onRemoveRequest,
  onRemoveConfirm,
  onRemoveCancel,
}: ManagerRowProps) {
  const status = resolveShimStatus(shim);
  const installState = actions.install ?? "disabled";
  const repairState = actions.repair ?? "disabled";
  const testState = actions.test ?? "disabled";
  const removeState = actions.remove ?? "disabled";
  const installAvailable = actionIsAvailable(installState);
  const repairAvailable = actionIsAvailable(repairState);
  const testAvailable = actionIsAvailable(testState);
  const removeAvailable = actionIsAvailable(removeState);

  const showInstall = (!shim || !shim.installed) && installAvailable;
  const showRepair =
    shim?.installed &&
    (shim.activation_state === "repair_required" || shim.path_broken) &&
    repairAvailable;
  const showTest = shim?.installed && shim.activation_state === "protected" && testAvailable;
  const showRemove = shim?.installed && removeAvailable;

  const handleInstall = useCallback(() => onInstall(manager), [onInstall, manager]);
  const handleRepair = useCallback(() => onRepair(manager), [onRepair, manager]);
  const handleTest = useCallback(() => onTest(manager), [onTest, manager]);
  const handleRemoveRequest = useCallback(() => onRemoveRequest(manager), [onRemoveRequest, manager]);
  const handleRemoveConfirm = useCallback(() => onRemoveConfirm(manager), [onRemoveConfirm, manager]);

  return (
    <div className="border-b border-slate-100 last:border-b-0" role="row">
      <div className="flex flex-col gap-2 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex min-w-0 flex-col gap-1 sm:flex-1" role="cell">
          <div className="flex min-w-0 items-center gap-2">
            {status.icon === "check" ? (
              <HiMiniCheckCircle className="h-4 w-4 shrink-0 text-brand-green" aria-hidden="true" />
            ) : status.icon === "restart" ? (
              <HiMiniArrowPath className="h-4 w-4 shrink-0 text-brand-blue" aria-hidden="true" />
            ) : (
              <HiMiniExclamationTriangle className="h-4 w-4 shrink-0 text-brand-attention" aria-hidden="true" />
            )}
            <span className="truncate font-mono text-sm font-semibold text-brand-dark">{manager}</span>
            {shim?.detected && (
              <Tag tone="green">Detected</Tag>
            )}
            {isMine && (
              <HiMiniArrowPath
                className="h-3.5 w-3.5 shrink-0 animate-spin text-brand-blue"
                aria-label="Running…"
              />
            )}
          </div>
          {shim?.path_summary !== null && shim?.path_summary !== undefined && (
            <p className="break-all pl-6 font-mono text-[11px] leading-relaxed text-slate-500">
              PATH: {shim.path_summary}
            </p>
          )}
          {shim?.last_intercept_proof_at !== null && shim?.last_intercept_proof_at !== undefined ? (
            <p className="flex items-center gap-1.5 pl-6 text-[11px] text-slate-500">
              <HiMiniCheckCircle className="h-3.5 w-3.5 shrink-0 text-brand-green" aria-hidden="true" />
              Last intercept proof {formatRelativeTime(shim.last_intercept_proof_at)}
            </p>
          ) : shim?.installed ? (
            <p className="flex items-center gap-1.5 pl-6 text-[11px] text-slate-500">
              <HiMiniClock className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              No intercept proof recorded yet
            </p>
          ) : null}
        </div>

        <div className="flex flex-wrap items-center gap-2 sm:gap-3" role="cell">
          <div className="shrink-0">
            <Tag tone={status.tone}>{status.label}</Tag>
          </div>

          <div className="shrink-0 [&_button]:min-h-11 [&_button]:h-11">
            {isConfirmingRemove ? (
              <div className="flex items-center gap-1.5">
                <IconActionButton
                  variant="ghost"
                  label="Cancel"
                  icon={<HiMiniXCircle className="h-4 w-4" />}
                  onClick={onRemoveCancel}
                  disabled={anyPending}
                />
                <IconActionButton
                  variant="danger"
                  label="Confirm"
                  icon={<HiMiniTrash className="h-4 w-4" />}
                  onClick={handleRemoveConfirm}
                  disabled={anyPending}
                />
              </div>
            ) : (
              <div className="flex flex-wrap items-center gap-1.5">
                {showInstall && (
                  <IconActionButton
                    variant="primary"
                    label="Protect"
                    icon={<HiMiniShieldCheck className="h-4 w-4" />}
                    onClick={handleInstall}
                    disabled={anyPending}
                  />
                )}
                {showRepair && (
                  <IconActionButton
                    variant="primary"
                    label="Fix PATH"
                    icon={<HiMiniWrenchScrewdriver className="h-4 w-4" />}
                    onClick={handleRepair}
                    disabled={anyPending}
                  />
                )}
                {showTest && (
                  <IconActionButton
                    variant="outline"
                    label="Test"
                    icon={<HiMiniBeaker className="h-4 w-4" />}
                    onClick={handleTest}
                    disabled={anyPending}
                  />
                )}
                {showRemove && (
                  <IconActionButton
                    variant="danger"
                    label="Remove"
                    icon={<HiMiniTrash className="h-4 w-4" />}
                    onClick={handleRemoveRequest}
                    disabled={anyPending}
                  />
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {shim?.activation_state === "restart_required" && (
        <div className="px-4 pb-2">
          <p className="text-xs text-slate-500">
            Guard updated your shell profile. Open a new shell or restart AI apps to activate this shim.
          </p>
        </div>
      )}

      {shim?.activation_state === "repair_required" && (
        <div className="px-4 pb-2">
          <p className="text-xs text-slate-500">
            Guard can add the shim directory to your shell profile automatically, then this manager will be ready after a restart.
          </p>
        </div>
      )}

      {shim?.path_broken && (
        <div className="px-4 pb-2">
          <p className="text-xs text-brand-attention">
            Restart your shell after repair so PATH exports reload.
          </p>
        </div>
      )}
    </div>
  );
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
  activationAssistError: string | null;
  openingShell: boolean;
  data: PackageFirewallStatusResponse;
  pendingOp: PendingOp | null;
  lastCompleted: CompletedOp | null;
  lastFailed: FailedOp | null;
  confirmRemoveManager: string | null;
  showGlobalActions: boolean;
  statusFilter: StatusFilter;
  managerFilter: string;
  onStatusFilterChange: (filter: StatusFilter) => void;
  onManagerFilterChange: (e: ChangeEvent<HTMLInputElement>) => void;
  onInstall: (manager: string) => void;
  onRepair: (manager: string) => void;
  onTest: (manager: string) => void;
  onRemoveRequest: (manager: string) => void;
  onRemoveConfirm: (manager: string) => void;
  onRemoveCancel: () => void;
  onAudit: () => void;
  onSync: () => void;
  onDismissResult: () => void;
  onOpenShell: () => void;
  onRefreshStatus: () => void;
};

function FirewallControlsView({
  activationAssistError,
  openingShell,
  data,
  pendingOp,
  lastCompleted,
  lastFailed,
  confirmRemoveManager,
  showGlobalActions,
  statusFilter,
  managerFilter,
  onStatusFilterChange,
  onManagerFilterChange,
  onInstall,
  onRepair,
  onTest,
  onRemoveRequest,
  onRemoveConfirm,
  onRemoveCancel,
  onAudit,
  onSync,
  onDismissResult,
  onOpenShell,
  onRefreshStatus,
}: FirewallControlsViewProps) {
  const anyPending = pendingOp !== null;
  const nextAction = useMemo(() => resolvePackageFirewallNextAction(data), [data]);
  const handleNextAction = useCallback(
    (op: "install" | "repair" | "test" | "sync", manager: string | null) => {
      if (op === "install" && manager !== null) {
        onInstall(manager);
        return;
      }
      if (op === "repair" && manager !== null) {
        onRepair(manager);
        return;
      }
      if (op === "test" && manager !== null) {
        onTest(manager);
        return;
      }
      if (op === "sync") {
        onSync();
      }
    },
    [onInstall, onRepair, onSync, onTest],
  );

  const filteredManagers = useMemo(() => {
    const shimsByManager = new Map(data.package_shims.map((s) => [s.manager, s]));
    const visibleManagers = data.package_shims
      .filter((shim) => shim.detected || shim.installed || shim.tested)
      .map((shim) => shim.manager);
    let managers =
      visibleManagers.length > 0
        ? Array.from(new Set(visibleManagers)).sort()
        : data.supported_managers;

    if (managerFilter) {
      const q = managerFilter.toLowerCase();
      managers = managers.filter((m) => m.toLowerCase().includes(q));
    }

    if (statusFilter !== "all") {
      managers = managers.filter((m) => {
        const shim = shimsByManager.get(m);
        const status = resolveShimStatus(shim);
        if (statusFilter === "protected") return status.tone === "green";
        if (statusFilter === "actionable") return status.tone === "attention";
        if (statusFilter === "unprotected") return status.tone !== "green";
        return true;
      });
    }

    return managers;
  }, [data, managerFilter, statusFilter]);

  return (
    <div className="space-y-4 px-4 py-4">
      <NextActionHero action={nextAction} anyPending={anyPending} onRunAction={handleNextAction} />

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

      <ActivationSummary
        activationAssistError={activationAssistError}
        lastAuditProofAt={data.last_audit_proof_at}
        openingShell={openingShell}
        onOpenShell={onOpenShell}
        onRefreshStatus={onRefreshStatus}
        protection={data.protection}
      />

      {lastFailed !== null && <FailureBanner failed={lastFailed} />}

      {lastCompleted !== null && (
        <ActionResultPanel completed={lastCompleted} onDismiss={onDismissResult} />
      )}

      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5">
          <HiMiniMagnifyingGlass className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
          <input
            type="search"
            placeholder="Filter by manager…"
            value={managerFilter}
            onChange={onManagerFilterChange}
            aria-label="Filter package managers"
            className="bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none w-40"
          />
        </div>
        {(["all", "protected", "actionable", "unprotected"] as const).map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => onStatusFilterChange(s)}
            aria-pressed={statusFilter === s}
            className={`rounded-full px-3 py-1 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${
              statusFilter === s
                ? "bg-brand-blue text-white"
                : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
            }`}
          >
            {s === "all"
              ? "All"
              : s === "protected"
              ? "Protected"
              : s === "actionable"
              ? "Needs action"
              : "Unprotected"}
          </button>
        ))}
      </div>

      {filteredManagers.length === 0 ? (
        <EmptyState
          title="No package managers found"
          body="No package managers match the current filter, or Guard has not detected any on this machine."
          tone="teach"
        />
      ) : (
        <div role="table" aria-label="Package manager firewall status">
          <div
            className="hidden sm:flex sm:items-center sm:justify-between border-b border-slate-100 bg-slate-50 px-4 py-2"
            role="row"
          >
            <span
              className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400"
              role="columnheader"
            >
              Manager
            </span>
            <div className="flex items-center gap-3">
              <span
                className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400"
                role="columnheader"
              >
                Status
              </span>
              <span
                className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400"
                role="columnheader"
              >
                Actions
              </span>
            </div>
          </div>
          <div role="rowgroup">
            {filteredManagers.map((manager) => {
              const shim = data.package_shims.find((s) => s.manager === manager);
              return (
                <ManagerRow
                  key={manager}
                  manager={manager}
                  shim={shim}
                  actions={data.actions}
                  anyPending={anyPending}
                  isMine={pendingOp?.manager === manager}
                  isConfirmingRemove={confirmRemoveManager === manager}
                  onInstall={onInstall}
                  onRepair={onRepair}
                  onTest={onTest}
                  onRemoveRequest={onRemoveRequest}
                  onRemoveConfirm={onRemoveConfirm}
                  onRemoveCancel={onRemoveCancel}
                />
              );
            })}
          </div>
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
  const [activationAssistError, setActivationAssistError] = useState<string | null>(null);
  const [startingConnect, setStartingConnect] = useState(false);
  const [openingShell, setOpeningShell] = useState(false);
  const [confirmRemoveManager, setConfirmRemoveManager] = useState<string | null>(null);
  const [pendingApprovalOp, setPendingApprovalOp] = useState<ApprovalOp | null>(null);
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [managerFilter, setManagerFilter] = useState("");
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
      setActivationAssistError(null);
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
      setActivationAssistError(null);
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
    </div>
  );
}
