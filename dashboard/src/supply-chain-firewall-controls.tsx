import { useMemo } from "react";
import type { ChangeEvent } from "react";
import {
  HiMiniArrowPath,
  HiMiniBugAnt,
  HiMiniExclamationTriangle,
  HiMiniMagnifyingGlass,
} from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import type { PackageFirewallActionType, PackageFirewallStatusResponse } from "./guard-types";
import {
  ActionResultPanel,
  ActivationSummary,
  type CompletedOp,
} from "./supply-chain-firewall-views";
import { ManagerRow, resolveShimStatus } from "./supply-chain-firewall-manager-row";

export type FirewallOpKey = PackageFirewallActionType | "audit" | "sync" | "fix_all";

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

const FAILURE_SUBJECTS: Record<FirewallOpKey, string> = {
  install: "Enabling protection",
  repair: "Repairing protection",
  test: "The intercept test",
  remove: "Removing protection",
  audit: "The audit",
  sync: "The sync",
  fix_all: "Restoring protection",
};

export function describeFirewallFailure(failed: FirewallFailedOp): string {
  const subject = FAILURE_SUBJECTS[failed.op] ?? "The action";
  return `${subject} failed${failed.manager !== null ? ` for ${failed.manager}` : ""}`;
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
          {describeFirewallFailure(failed)}
        </p>
        <p className="mt-0.5 text-xs text-slate-600">{failed.message}</p>
      </div>
    </div>
  );
}

export type FirewallControlsViewProps = {
  activationAssistError: string | null;
  activatingRuntime: boolean;
  data: PackageFirewallStatusResponse;
  pendingOp: FirewallPendingOp | null;
  repairAwaitingRefresh: string | null;
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
  onActivateRuntime: () => void;
  onRefreshStatus: () => void;
  onOpenManagerDetails: (manager: string) => void;
};

export function FirewallControlsView({
  activationAssistError,
  activatingRuntime,
  data,
  pendingOp,
  repairAwaitingRefresh,
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
  onActivateRuntime,
  onRefreshStatus,
  onOpenManagerDetails,
}: FirewallControlsViewProps) {
  const anyPending = pendingOp !== null;

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
    <div className="space-y-4">
      <ActivationSummary
        activationAssistError={activationAssistError}
        lastAuditProofAt={data.last_audit_proof_at}
        activatingRuntime={activatingRuntime}
        onActivateRuntime={onActivateRuntime}
        onRefreshStatus={onRefreshStatus}
        protection={data.protection}
      />

      {lastFailed !== null && <FailureBanner failed={lastFailed} />}

      {lastCompleted !== null && (
        <ActionResultPanel completed={lastCompleted} onDismiss={onDismissResult} />
      )}

      <div className="flex min-w-0 flex-col gap-2 sm:flex-row sm:items-center">
        <div className="flex min-h-11 w-full min-w-0 items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 sm:min-h-9 sm:w-48 sm:shrink-0">
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
        {/* One row on phones that scrolls sideways, so the filters never
            push the first manager below the fold. */}
        <div className="-mx-1 flex min-w-0 gap-2 overflow-x-auto px-1 py-0.5">
        {(["all", "protected", "actionable", "unprotected"] as const).map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => onStatusFilterChange(s)}
            aria-pressed={statusFilter === s}
            className={`inline-flex min-h-11 shrink-0 items-center rounded-full px-3.5 text-xs font-medium transition-colors sm:min-h-8 focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${
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
      </div>

      {filteredManagers.length === 0 ? (
        <div className="border-y border-slate-200 py-6">
          <h3 className="text-sm font-semibold text-brand-dark">
            {noDetectedManagers && managerFilter.length === 0 && statusFilter === "all"
              ? "No package managers detected"
              : "No package managers found"}
          </h3>
          <p className="mt-1 max-w-[68ch] text-sm leading-6 text-slate-600">
            {noDetectedManagers && managerFilter.length === 0 && statusFilter === "all"
              ? "Guard did not find npm, pip, pnpm, or other supported managers on this PATH. Install a package manager, open a new shell, then refresh status."
              : "No package managers match the current filter, or Guard has not detected any on this machine."}
          </p>
        </div>
      ) : (
        // One ruled row per manager, read as a ledger rather than a card grid.
        <ul
          className="min-w-0 divide-y divide-slate-200 border-y border-slate-200"
          aria-label="Package manager controls"
        >
          {filteredManagers.map((manager) => {
            const shim = data.package_shims.find((s) => s.manager === manager);
            return (
              <ManagerRow
                key={manager}
                manager={manager}
                shim={shim}
                actions={data.actions}
                anyPending={anyPending}
                repairAwaitingRefresh={repairAwaitingRefresh === manager}
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
        </ul>
      )}

      {/* Audit and Sync act on the whole roster, so they close it. */}
      {showGlobalActions && (
        <div className="flex justify-end">
          <GlobalActionsBar
            anyPending={anyPending}
            pendingOp={pendingOp}
            onAudit={onAudit}
            onSync={onSync}
          />
        </div>
      )}
    </div>
  );
}
