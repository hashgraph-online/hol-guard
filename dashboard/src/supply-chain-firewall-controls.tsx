import { useCallback, useMemo } from "react";
import type { ChangeEvent } from "react";
import {
  HiMiniArrowPath,
  HiMiniBugAnt,
  HiMiniExclamationTriangle,
  HiMiniMagnifyingGlass,
} from "react-icons/hi2";
import { ActionButton, EmptyState } from "./approval-center-primitives";
import type { PackageFirewallActionType, PackageFirewallStatusResponse } from "./guard-types";
import {
  ActionResultPanel,
  ActivationSummary,
  NextActionHero,
  type CompletedOp,
} from "./supply-chain-firewall-views";
import { resolvePackageFirewallNextAction } from "./supply-chain-firewall-next-action";
import { ManagerRow, resolveShimStatus } from "./supply-chain-firewall-manager-row";

export type FirewallOpKey = PackageFirewallActionType | "audit" | "sync";

export type FirewallPendingOp = {
  op: FirewallOpKey;
  manager: string | null;
};

export type FirewallFailedOp = {
  op: FirewallOpKey;
  manager: string | null;
  message: string;
};

export type FirewallStatusFilter = "all" | "protected" | "actionable" | "unprotected";

type GlobalActionsBarProps = {
  anyPending: boolean;
  pendingOp: FirewallPendingOp | null;
  onAudit: () => void;
  onSync: () => void;
};

function GlobalActionsBar({ anyPending, pendingOp, onAudit, onSync }: GlobalActionsBarProps) {
  const auditRunning = pendingOp?.op === "audit";
  const syncRunning = pendingOp?.op === "sync";
  return (
    <div className="flex flex-wrap items-center gap-2">
      <ActionButton variant="outline" onClick={onAudit} disabled={anyPending} aria-busy={auditRunning}>
        {auditRunning ? (
          <HiMiniArrowPath className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden="true" />
        ) : (
          <HiMiniBugAnt className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
        )}
        Audit
      </ActionButton>
      <ActionButton variant="outline" onClick={onSync} disabled={anyPending} aria-busy={syncRunning}>
        <HiMiniArrowPath
          className={`mr-1.5 h-3.5 w-3.5 ${syncRunning ? "animate-spin" : ""}`}
          aria-hidden="true"
        />
        Sync
      </ActionButton>
    </div>
  );
}

function FailureBanner({ failed }: { failed: FirewallFailedOp }) {
  return (
    <div
      className="flex items-start gap-2 rounded-xl border border-brand-attention/30 bg-brand-attention/[0.04] px-3 py-2.5"
      role="alert"
      aria-live="assertive"
    >
      <HiMiniExclamationTriangle className="mt-0.5 h-4 w-4 shrink-0 text-brand-attention" aria-hidden="true" />
      <div className="min-w-0">
        <p className="text-sm font-medium text-brand-dark">
          {failed.op} failed{failed.manager !== null ? ` for ${failed.manager}` : ""}
        </p>
        <p className="mt-0.5 text-xs text-slate-600">{failed.message}</p>
      </div>
    </div>
  );
}

export type FirewallControlsViewProps = {
  activationAssistError: string | null;
  openingShell: boolean;
  data: PackageFirewallStatusResponse;
  pendingOp: FirewallPendingOp | null;
  lastCompleted: CompletedOp | null;
  lastFailed: FirewallFailedOp | null;
  confirmRemoveManager: string | null;
  showGlobalActions: boolean;
  statusFilter: FirewallStatusFilter;
  managerFilter: string;
  onStatusFilterChange: (filter: FirewallStatusFilter) => void;
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
  onOpenManagerDetails: (manager: string) => void;
};

export function FirewallControlsView({
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
  onOpenManagerDetails,
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
      if (op === "test") {
        if (manager !== null) {
          onTest(manager);
          return;
        }
        onOpenShell();
        return;
      }
      if (op === "sync") {
        onSync();
      }
    },
    [onInstall, onOpenShell, onRepair, onSync, onTest],
  );

  const noDetectedManagers = data.detected_managers.length === 0;
  const filteredManagers = useMemo(() => {
    const shimsByManager = new Map(data.package_shims.map((s) => [s.manager, s]));
    const visibleManagers = data.package_shims
      .filter((shim) => shim.detected || shim.installed || shim.tested)
      .map((shim) => shim.manager);
    let managers: string[];
    if (visibleManagers.length > 0) {
      managers = Array.from(new Set(visibleManagers)).sort();
    } else if (noDetectedManagers) {
      managers = [];
    } else {
      managers = data.supported_managers;
    }

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
  }, [data, managerFilter, noDetectedManagers, statusFilter]);

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

      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <div className="flex min-w-0 flex-1 items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 sm:flex-none sm:w-44">
          <HiMiniMagnifyingGlass className="h-3.5 w-3.5 shrink-0 text-slate-400" aria-hidden="true" />
          <input
            type="search"
            placeholder="Search tools…"
            value={managerFilter}
            onChange={onManagerFilterChange}
            aria-label="Filter package managers"
            className="min-w-0 flex-1 bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none"
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
          title={
            noDetectedManagers && managerFilter.length === 0 && statusFilter === "all"
              ? "No package managers detected"
              : "No package managers found"
          }
          body={
            noDetectedManagers && managerFilter.length === 0 && statusFilter === "all"
              ? "Guard did not find npm, pip, pnpm, or other supported managers on this PATH. Install a package manager, open a new shell, then refresh status."
              : "No package managers match the current filter, or Guard has not detected any on this machine."
          }
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
                  onOpenDetails={onOpenManagerDetails}
                />
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
