import { useCallback, useEffect, useMemo, useState } from "react";
import type { ChangeEvent, ReactNode } from "react";
import {
  HiMiniArrowPath,
  HiMiniBugAnt,
  HiMiniChevronDown,
  HiMiniExclamationTriangle,
  HiMiniMagnifyingGlass,
} from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import type { PackageFirewallActionType, PackageFirewallStatusResponse, PackageShimEntry } from "./guard-types";
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

/** Where a manager sits in the roster: something to fix, done, or not set up yet. */
export type RosterGroup = "fix" | "protected" | "unprotected";

export function rosterGroupFor(shim: PackageShimEntry | undefined): RosterGroup {
  if (!shim?.installed) return "unprotected";
  return resolveShimStatus(shim).tone === "green" ? "protected" : "fix";
}

// Past this many tools the roster gets a search box, and a longer
// not-yet-protected group folds into one line until asked for.
const SEARCH_THRESHOLD = 8;
const COLLAPSE_THRESHOLD = 3;

type GlobalActionsBarProps = {
  anyPending: boolean;
  pendingOp: FirewallPendingOp | null;
  onAudit: () => void;
  onSync: () => void;
};

/** Audit and Sync act on the whole roster, so they sit in its header. */
export function GlobalActionsBar({ anyPending, pendingOp, onAudit, onSync }: GlobalActionsBarProps) {
  const auditRunning = pendingOp?.op === "audit";
  const syncRunning = pendingOp?.op === "sync";
  return (
    <div className="flex flex-wrap items-center gap-2">
      <ActionButton variant="ghost" onClick={onAudit} disabled={anyPending} aria-busy={auditRunning}>
        {auditRunning ? (
          <HiMiniArrowPath className="mr-1.5 h-3.5 w-3.5 animate-spin" aria-hidden="true" />
        ) : (
          <HiMiniBugAnt className="mr-1.5 h-3.5 w-3.5" aria-hidden="true" />
        )}
        Audit
      </ActionButton>
      <ActionButton variant="ghost" onClick={onSync} disabled={anyPending} aria-busy={syncRunning}>
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
  managerFilter: string;
  /** Open the not-yet-protected group, for links that point at it. */
  /** Bumped each time a link asks to show every unprotected tool. */
  expandUnprotectedRequest?: number;
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
  managerFilter,
  expandUnprotectedRequest = 0,
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
  const shimsByManager = useMemo(() => new Map(data.package_shims.map((s) => [s.manager, s])), [data.package_shims]);
  const allManagers = useMemo(() => {
    const visibleManagers = data.package_shims
      .filter((shim) => shim.detected || shim.installed || shim.tested)
      .map((shim) => shim.manager);
    if (visibleManagers.length > 0) return Array.from(new Set(visibleManagers)).sort();
    if (noDetectedManagers) return [];
    return data.supported_managers;
  }, [data, noDetectedManagers]);
  const searchable = allManagers.length > SEARCH_THRESHOLD;
  // A query only applies while its box is on screen, so a shrinking roster cannot hide rows behind it.
  const query = searchable ? managerFilter.trim().toLowerCase() : "";
  const groups = useMemo(() => {
    const byGroup: Record<RosterGroup, string[]> = { fix: [], protected: [], unprotected: [] };
    for (const manager of allManagers) {
      if (query && !manager.toLowerCase().includes(query)) continue;
      byGroup[rosterGroupFor(shimsByManager.get(manager))].push(manager);
    }
    return byGroup;
  }, [allManagers, query, shimsByManager]);
  const [unprotectedOpen, setUnprotectedOpen] = useState(false);
  const toggleUnprotected = useCallback(() => setUnprotectedOpen((open) => !open), []);
  useEffect(() => {
    if (expandUnprotectedRequest > 0) setUnprotectedOpen(true);
  }, [expandUnprotectedRequest]);
  const shownCount = groups.fix.length + groups.protected.length + groups.unprotected.length;
  const foldUnprotected =
    !unprotectedOpen && query.length === 0 && groups.unprotected.length > COLLAPSE_THRESHOLD;

  const renderRow = (manager: string, showStatus: boolean) => (
    <ManagerRow
      key={manager}
      manager={manager}
      shim={shimsByManager.get(manager)}
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
      showStatus={showStatus}
    />
  );

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

      {searchable && (
        <div className="flex min-h-11 w-full min-w-0 items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 sm:min-h-9 sm:w-56">
          <HiMiniMagnifyingGlass className="h-3.5 w-3.5 shrink-0 text-slate-400" aria-hidden="true" />
          <input
            type="search"
            placeholder="Find a tool…"
            value={managerFilter}
            onChange={onManagerFilterChange}
            aria-label="Filter package managers"
            className="min-w-0 flex-1 bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none"
          />
        </div>
      )}

      {shownCount === 0 ? (
        <div className="border-y border-slate-200 py-6">
          <h3 className="text-sm font-semibold text-brand-dark">
            {noDetectedManagers && query.length === 0 ? "No package managers detected" : "No package managers found"}
          </h3>
          <p className="mt-1 max-w-[68ch] text-sm leading-6 text-slate-600">
            {noDetectedManagers && query.length === 0
              ? "Guard did not find npm, pip, pnpm, or other supported managers on this PATH. Install a package manager, open a new shell, then refresh status."
              : "No package manager matches that name."}
          </p>
        </div>
      ) : (
        // Ruled groups, worst first: what to fix, what is done, what is not set up.
        <div className="space-y-6" role="group" aria-label="Package manager controls">
          {groups.fix.length > 0 && (
            <RosterSection title="Needs a fix" count={groups.fix.length}>
              {groups.fix.map((manager) => renderRow(manager, true))}
            </RosterSection>
          )}
          {groups.protected.length > 0 && (
            <RosterSection title="Protected" count={groups.protected.length}>
              {groups.protected.map((manager) => renderRow(manager, false))}
            </RosterSection>
          )}
          {groups.unprotected.length > 0 && (
            <RosterSection
              title="Not protected yet"
              count={groups.unprotected.length}
              toggle={
                groups.unprotected.length > COLLAPSE_THRESHOLD && query.length === 0
                  ? { open: !foldUnprotected, onToggle: toggleUnprotected }
                  : undefined
              }
            >
              {foldUnprotected ? (
                <li className="py-3.5 text-sm leading-6 text-slate-600">
                  {previewNames(groups.unprotected)}. Installs from these tools are not checked yet.
                </li>
              ) : (
                groups.unprotected.map((manager) => renderRow(manager, false))
              )}
            </RosterSection>
          )}
        </div>
      )}

    </div>
  );
}

function previewNames(managers: string[]): string {
  const shown = managers.slice(0, 3).join(", ");
  const rest = managers.length - 3;
  return rest > 0 ? `${shown} and ${rest} more` : shown;
}

function RosterSection({
  title,
  count,
  toggle,
  children,
}: {
  title: string;
  count: number;
  toggle?: { open: boolean; onToggle: () => void };
  children: ReactNode;
}) {
  return (
    <section aria-label={title} className="min-w-0">
      <div className="flex min-h-9 items-center justify-between gap-3">
        <h3 className="text-sm font-semibold text-brand-dark">
          {title} <span className="font-normal text-slate-500">{count}</span>
        </h3>
        {toggle && (
          <button
            type="button"
            onClick={toggle.onToggle}
            aria-expanded={toggle.open}
            className="inline-flex min-h-11 items-center gap-1 rounded-md px-2 text-sm font-medium text-slate-600 hover:text-brand-dark focus:outline-none focus:ring-2 focus:ring-brand-blue/30 sm:min-h-9"
          >
            {toggle.open ? "Show less" : `Show all ${count}`}
            <HiMiniChevronDown
              className={`h-4 w-4 transition-transform ${toggle.open ? "rotate-180" : ""}`}
              aria-hidden="true"
            />
          </button>
        )}
      </div>
      <ul className="mt-1 min-w-0 divide-y divide-slate-200 border-y border-slate-200" aria-label={title}>
        {children}
      </ul>
    </section>
  );
}
