import { useMemo, useState, useCallback } from "react";
import type { ChangeEvent } from "react";
import {
  HiMiniShieldCheck,
  HiMiniExclamationTriangle,
  HiMiniCheckCircle,
  HiMiniXCircle,
  HiMiniArrowPath,
  HiMiniInformationCircle,
  HiMiniChevronDown,
  HiMiniChevronUp,
} from "react-icons/hi2";
import { SectionLabel, Badge, Tag, ActionButton, EmptyState } from "./approval-center-primitives";
import { harnessDisplayName, formatRelativeTime } from "./approval-center-utils";
import type {
  GuardApprovalGatePublicConfig,
  GuardManagedInstall,
  GuardRuntimeSnapshot,
  PackageManagerProtection,
} from "./guard-types";
import { PackageFirewallPanel } from "./supply-chain-firewall-panel";

export type SupplyChainFilterState = {
  statusFilter: "all" | "protected" | "unprotected";
  managerFilter: string;
};

type ManagerCoverageStatus = "protected" | "restart_required" | "path_repair" | "unprotected";

function resolveManagerCoverageStatus(
  protection: PackageManagerProtection | undefined,
  manager: string,
): ManagerCoverageStatus {
  if (!protection) return "unprotected";
  if (protection.protected_managers.includes(manager)) return "protected";
  if (protection.installed_managers.includes(manager)) {
    if (protection.path_status === "restart_required") return "restart_required";
    if (protection.path_status === "missing_from_path") return "path_repair";
  }
  return "unprotected";
}

export function buildSupplyChainStats(
  snapshot: GuardRuntimeSnapshot,
): {
  totalApps: number;
  activeApps: number;
  preventedInstalls: number;
  protectedManagers: number;
  stagedManagers: number;
  repairRequiredManagers: number;
  unprotectedManagers: number;
} {
  const managedInstalls = snapshot.managed_installs ?? [];
  const protection = snapshot.supply_chain?.package_manager_protection;
  const supportedManagers = protection?.supported_managers ?? [];
  const protectedManagers = supportedManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "protected",
  ).length;
  const stagedManagers = supportedManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "restart_required",
  ).length;
  const repairRequiredManagers = supportedManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "path_repair",
  ).length;
  const unprotectedManagers = supportedManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "unprotected",
  ).length;
  return {
    totalApps: managedInstalls.length,
    activeApps: managedInstalls.filter((i) => i.active).length,
    preventedInstalls: managedInstalls.filter((i) => !i.active).length,
    protectedManagers,
    stagedManagers,
    repairRequiredManagers,
    unprotectedManagers,
  };
}

type StatCardProps = {
  label: string;
  value: number | string;
  tone?: "green" | "attention" | "slate" | "blue";
};

function StatCard({ label, value, tone = "slate" }: StatCardProps) {
  const toneClass =
    tone === "green"
      ? "text-brand-green"
      : tone === "attention"
      ? "text-brand-attention"
      : tone === "blue"
      ? "text-brand-blue"
      : "text-brand-dark";
  return (
    <div className="rounded-xl border border-slate-100 bg-white p-4 shadow-sm">
      <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">{label}</p>
      <p className={`mt-1.5 text-2xl font-bold tabular-nums ${toneClass}`}>{value}</p>
    </div>
  );
}

type AppFirewallRowProps = {
  install: GuardManagedInstall;
  protection: PackageManagerProtection | undefined;
};

function AppFirewallRow({ install, protection }: AppFirewallRowProps) {
  const [open, setOpen] = useState(false);
  const toggle = useCallback(() => setOpen((p) => !p), []);
  const protectedManagers = protection?.protected_managers ?? [];

  return (
    <div className="border-b border-slate-100 last:border-b-0">
      <button
        type="button"
        onClick={toggle}
        aria-expanded={open}
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left hover:bg-slate-50/60 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-brand-blue/30"
      >
        <div className="flex min-w-0 items-center gap-2.5">
          {install.active ? (
            <HiMiniCheckCircle className="h-4 w-4 shrink-0 text-brand-green" aria-hidden="true" />
          ) : (
            <HiMiniXCircle className="h-4 w-4 shrink-0 text-brand-attention" aria-hidden="true" />
          )}
          <span className="text-sm font-medium text-brand-dark">
            {harnessDisplayName(install.harness)}
          </span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Badge tone={install.active ? "success" : "attention"}>
            {install.active ? "Active" : "Inactive"}
          </Badge>
          {open ? (
            <HiMiniChevronUp className="h-4 w-4 text-slate-400" aria-hidden="true" />
          ) : (
            <HiMiniChevronDown className="h-4 w-4 text-slate-400" aria-hidden="true" />
          )}
        </div>
      </button>
      {open && (
        <div className="px-4 pb-3 pt-1">
          <p className="text-xs font-semibold uppercase tracking-[0.15em] text-slate-400 mb-2">
            Shim coverage
          </p>
          {protectedManagers.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {protectedManagers.map((mgr) => (
                <span
                  key={mgr}
                  className="inline-flex items-center gap-1 rounded-full border border-brand-green/25 bg-brand-green/[0.06] px-2.5 py-0.5 text-xs font-medium text-brand-green-text"
                >
                  <HiMiniCheckCircle className="h-3 w-3" aria-hidden="true" />
                  {mgr}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-xs text-slate-500">No package manager shims active for this app.</p>
          )}
          {install.updated_at && (
            <p className="mt-2 text-xs text-slate-400">
              Updated {formatRelativeTime(install.updated_at)}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

type SupplyChainWorkspaceProps = {
  snapshot: GuardRuntimeSnapshot;
  approvalGate: GuardApprovalGatePublicConfig | null;
  onGoHome: () => void;
  onRuntimeRefresh?: () => Promise<void> | void;
};

export function SupplyChainWorkspace({
  snapshot,
  approvalGate,
  onGoHome,
  onRuntimeRefresh,
}: SupplyChainWorkspaceProps) {
  const [filter, setFilter] = useState<SupplyChainFilterState>({
    statusFilter: "all",
    managerFilter: "",
  });

  const handleManagerFilterChange = useCallback((e: ChangeEvent<HTMLInputElement>) => {
    setFilter((f) => ({ ...f, managerFilter: e.target.value }));
  }, []);

  const handleStatusFilterChange = useCallback((status: SupplyChainFilterState["statusFilter"]) => {
    setFilter((f) => ({ ...f, statusFilter: status }));
  }, []);

  const stats = useMemo(() => buildSupplyChainStats(snapshot), [snapshot]);
  const protection = snapshot.supply_chain?.package_manager_protection;

  const allManagers = useMemo(() => {
    if (!protection) return [];
    const all = new Set([...protection.protected_managers, ...protection.unprotected_managers]);
    return Array.from(all).sort();
  }, [protection]);

  const filteredManagers = useMemo(() => {
    return allManagers.filter((mgr) => {
      const matchesText =
        filter.managerFilter === "" ||
        mgr.toLowerCase().includes(filter.managerFilter.toLowerCase());
      const isProtected = resolveManagerCoverageStatus(protection, mgr) === "protected";
      const matchesStatus =
        filter.statusFilter === "all" ||
        (filter.statusFilter === "protected" && isProtected) ||
        (filter.statusFilter === "unprotected" && !isProtected);
      return matchesText && matchesStatus;
    });
  }, [allManagers, filter, protection]);

  const managedInstalls = useMemo(
    () => snapshot.managed_installs ?? [],
    [snapshot.managed_installs],
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-sm text-slate-500">
            Package manager firewall status, prevented installs, and feed health.
          </p>
        </div>
        <ActionButton variant="ghost" onClick={onGoHome}>
          Back to Home
        </ActionButton>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Active apps" value={stats.activeApps} tone="green" />
        <StatCard label="Prevented installs" value={stats.preventedInstalls} tone={stats.preventedInstalls > 0 ? "attention" : "slate"} />
        <StatCard
          label={
            stats.stagedManagers > 0
              ? "Ready after restart"
              : stats.repairRequiredManagers > 0
              ? "Needs PATH repair"
              : "Protected managers"
          }
          value={
            stats.stagedManagers > 0
              ? stats.stagedManagers
              : stats.repairRequiredManagers > 0
              ? stats.repairRequiredManagers
              : stats.protectedManagers
          }
          tone={
            stats.stagedManagers > 0
              ? "blue"
              : stats.repairRequiredManagers > 0
              ? "attention"
              : "green"
          }
        />
        <StatCard label="Unprotected managers" value={stats.unprotectedManagers} tone={stats.unprotectedManagers > 0 ? "attention" : "slate"} />
      </div>

      <PackageFirewallPanel approvalGate={approvalGate} onStateChanged={onRuntimeRefresh} />

      <div className="rounded-2xl border border-slate-100 bg-white shadow-sm">
        <div className="border-b border-slate-100 px-4 py-3">
          <SectionLabel>Coverage by manager</SectionLabel>
          <p className="mt-1 text-sm text-slate-500">
            Live protection state and next activation step for each supported package manager.
          </p>
        </div>

        <div className="border-b border-slate-100 px-4 py-3">
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5">
              <HiMiniInformationCircle className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
              <input
                type="search"
                placeholder="Filter by manager..."
                value={filter.managerFilter}
                onChange={handleManagerFilterChange}
                aria-label="Filter package managers"
                className="bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none w-40"
              />
            </div>
            {(["all", "protected", "unprotected"] as const).map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => handleStatusFilterChange(s)}
                aria-pressed={filter.statusFilter === s}
                className={`rounded-full px-3 py-1 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${
                  filter.statusFilter === s
                    ? "bg-brand-blue text-white"
                    : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
                }`}
              >
                {s.charAt(0).toUpperCase() + s.slice(1)}
              </button>
            ))}
          </div>
        </div>

        {filteredManagers.length === 0 ? (
          <EmptyState
            title="No package managers found"
            body="No package managers match the current filter, or Guard has not detected any on this machine."
            tone="teach"
          />
        ) : (
          <div role="table" aria-label="Package manager firewall status">
            <div className="grid grid-cols-[1fr_auto] gap-2 border-b border-slate-100 bg-slate-50 px-4 py-2" role="row">
              <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400" role="columnheader">
                Manager
              </span>
              <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400" role="columnheader">
                Status
              </span>
            </div>
            <div role="rowgroup">
              {filteredManagers.map((mgr) => {
                const status = resolveManagerCoverageStatus(protection, mgr);
                return (
                  <div
                    key={mgr}
                    role="row"
                    className="grid grid-cols-[1fr_auto] gap-2 border-b border-slate-100 px-4 py-2.5 last:border-b-0"
                  >
                    <span className="text-sm font-mono text-brand-dark" role="cell">
                      {mgr}
                    </span>
                    <span role="cell">
                      {status === "protected" ? (
                        <Tag tone="green">
                          <HiMiniCheckCircle className="h-3.5 w-3.5 mr-1 inline" aria-hidden="true" />
                          Protected
                        </Tag>
                      ) : status === "restart_required" ? (
                        <Tag tone="blue">
                          <HiMiniArrowPath className="h-3.5 w-3.5 mr-1 inline" aria-hidden="true" />
                          Restart required
                        </Tag>
                      ) : status === "path_repair" ? (
                        <Tag tone="attention">
                          <HiMiniExclamationTriangle className="h-3.5 w-3.5 mr-1 inline" aria-hidden="true" />
                          Needs PATH repair
                        </Tag>
                      ) : (
                        <Tag tone="attention">
                          <HiMiniExclamationTriangle className="h-3.5 w-3.5 mr-1 inline" aria-hidden="true" />
                          Unprotected
                        </Tag>
                      )}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      <div className="rounded-2xl border border-slate-100 bg-white shadow-sm">
        <div className="border-b border-slate-100 px-4 py-3">
          <SectionLabel>App shim coverage</SectionLabel>
          <p className="mt-1 text-sm text-slate-500">
            Package manager hooks active per connected app.
          </p>
        </div>
        {managedInstalls.length === 0 ? (
          <EmptyState
            title="No apps connected"
            body="Connect an AI app to see per-app package manager coverage here."
            tone="teach"
          />
        ) : (
          <div>
            {managedInstalls.map((install) => (
              <AppFirewallRow
                key={`${install.harness}-${install.workspace ?? "global"}`}
                install={install}
                protection={protection}
              />
            ))}
          </div>
        )}
      </div>

      <div className="rounded-2xl border border-slate-100 bg-white shadow-sm">
        <div className="border-b border-slate-100 px-4 py-3">
          <SectionLabel>Feed health</SectionLabel>
          <p className="mt-1 text-sm text-slate-500">
            Intel feed source mode and freshness.
          </p>
        </div>
        <FeedHealthPanel snapshot={snapshot} />
      </div>
    </div>
  );
}

function FeedHealthPanel({ snapshot }: { snapshot: GuardRuntimeSnapshot }) {
  const cloudState = snapshot.cloud_state;
  const isSample = cloudState === "local_only";
  const isStale =
    snapshot.latest_receipts.length > 0 &&
    Date.now() - new Date(snapshot.latest_receipts[0].timestamp).getTime() > 7 * 24 * 60 * 60 * 1000;

  return (
    <div className="px-4 py-4 space-y-3">
      <div className="flex flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-[0.15em]">
            Source mode:
          </span>
          <Tag tone={isSample ? "attention" : "green"}>
            {isSample ? "Local-only (sample intel)" : "Live cloud feed"}
          </Tag>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-[0.15em]">
            Freshness:
          </span>
          <Tag tone={isStale ? "attention" : "green"}>
            {isStale ? "Stale (7+ days)" : "Fresh"}
          </Tag>
        </div>
      </div>
      {isSample && (
        <div className="flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50/60 px-3 py-2.5">
          <HiMiniExclamationTriangle
            className="mt-0.5 h-4 w-4 shrink-0 text-amber-600"
            aria-hidden="true"
          />
          <p className="text-xs text-amber-800">
            Running on local-only (sample) intel. Connect this machine to Guard Cloud for live feed data and cross-device protection.
          </p>
        </div>
      )}
      {isStale && !isSample && (
        <div className="flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50/60 px-3 py-2.5">
          <HiMiniArrowPath
            className="mt-0.5 h-4 w-4 shrink-0 text-amber-600"
            aria-hidden="true"
          />
          <p className="text-xs text-amber-800">
            Feed data is stale. Guard has not processed new actions recently. Check that the daemon is running.
          </p>
        </div>
      )}
    </div>
  );
}
