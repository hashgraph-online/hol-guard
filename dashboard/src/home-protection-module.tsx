import { useMemo, useState } from "react";
import {
  HiMiniShieldCheck,
  HiMiniExclamationTriangle,
  HiMiniCheckCircle,
  HiMiniXCircle,
  HiMiniInformationCircle,
  HiMiniArrowRight,
  HiMiniChevronDown,
  HiMiniChevronUp,
} from "react-icons/hi2";
import { ActionButton, SectionLabel, Tag } from "./approval-center-primitives";
import { formatRelativeTime } from "./approval-center-utils";
import type { GuardManagedInstall, GuardRuntimeSnapshot } from "./guard-types";

export type HomeProtectionStatus = "protected" | "partial" | "staged" | "unprotected" | "unknown";

export function resolveHomeProtectionStatus(
  snapshot: GuardRuntimeSnapshot,
): HomeProtectionStatus {
  const protection = snapshot.supply_chain?.package_manager_protection;
  if (!protection) return "unknown";
  if (protection.path_status === "restart_required" && protection.installed_managers.length > 0) {
    return "staged";
  }
  if (protection.unprotected_managers.length === 0 && protection.protected_managers.length > 0) {
    return "protected";
  }
  if (protection.protected_managers.length > 0) return "partial";
  return "unprotected";
}

export function resolveLastBlockedInstall(
  managedInstalls: GuardManagedInstall[],
): GuardManagedInstall | null {
  const inactive = managedInstalls.filter((i) => !i.active);
  if (inactive.length === 0) return null;
  return inactive.sort((a, b) => +new Date(b.updated_at) - +new Date(a.updated_at))[0] ?? null;
}

export function resolveIntelStaleness(
  snapshot: GuardRuntimeSnapshot,
): { stale: boolean; label: string } {
  const receipts = snapshot.latest_receipts;
  if (receipts.length === 0) {
    return { stale: false, label: "" };
  }
  const latest = receipts[0];
  const ageMs = Date.now() - new Date(latest.timestamp).getTime();
  const stale = ageMs > 7 * 24 * 60 * 60 * 1000;
  return {
    stale,
    label: stale ? `Last activity ${formatRelativeTime(latest.timestamp)} -- intel may be stale` : "",
  };
}

type ProtectedManagerRowProps = {
  manager: string;
  protected: boolean;
};

function ProtectedManagerRow({ manager, protected: isProtected }: ProtectedManagerRowProps) {
  return (
    <div className="flex items-center justify-between gap-2 py-1.5 border-b border-slate-100 last:border-b-0">
      <span className="text-sm font-mono text-brand-dark">{manager}</span>
      {isProtected ? (
        <Tag tone="green">
          <HiMiniCheckCircle className="h-3.5 w-3.5 mr-1" aria-hidden="true" />
          Protected
        </Tag>
      ) : (
        <Tag tone="attention">
          <HiMiniXCircle className="h-3.5 w-3.5 mr-1" aria-hidden="true" />
          Unprotected
        </Tag>
      )}
    </div>
  );
}

type HomeProtectionModuleProps = {
  snapshot: GuardRuntimeSnapshot;
  managedInstalls: GuardManagedInstall[];
  onOpenFleet: () => void;
  onOpenSupplyChain?: () => void;
};

export function HomeProtectionModule({
  snapshot,
  managedInstalls,
  onOpenFleet,
  onOpenSupplyChain,
}: HomeProtectionModuleProps) {
  const status = useMemo(() => resolveHomeProtectionStatus(snapshot), [snapshot]);
  const lastBlocked = useMemo(() => resolveLastBlockedInstall(managedInstalls), [managedInstalls]);
  const intelState = useMemo(() => resolveIntelStaleness(snapshot), [snapshot]);
  const protection = snapshot.supply_chain?.package_manager_protection;

  const allManagers = useMemo(() => {
    if (!protection) return [];
    const all = new Set([
      ...protection.protected_managers,
      ...protection.unprotected_managers,
    ]);
    return Array.from(all).sort();
  }, [protection]);

  const protectedCount = protection?.protected_managers.length ?? 0;
  const totalCount = allManagers.length;
  const defaultExpanded = totalCount <= 4;
  const [expanded, setExpanded] = useState(defaultExpanded);
  const hasManagers = totalCount > 0;

  const statusBorderClass =
    status === "protected"
      ? "border-brand-green/20 bg-brand-green/[0.04]"
      : status === "staged"
      ? "border-brand-blue/20 bg-brand-blue/[0.04]"
      : status === "partial"
      ? "border-brand-attention/20 bg-brand-attention/[0.04]"
      : status === "unprotected"
      ? "border-red-200 bg-red-50/60"
      : "border-slate-200 bg-slate-50/60";

  const StatusIcon =
    status === "protected"
      ? HiMiniShieldCheck
      : status === "staged"
      ? HiMiniInformationCircle
      : status === "partial" || status === "unprotected"
      ? HiMiniExclamationTriangle
      : HiMiniInformationCircle;

  const statusIconClass =
    status === "protected"
      ? "text-brand-green"
      : status === "staged"
      ? "text-brand-blue"
      : status === "partial" || status === "unprotected"
      ? "text-brand-attention"
      : "text-slate-400";

  const statusLabel =
    status === "protected"
      ? "Package managers protected"
      : status === "staged"
      ? "Protection staged, finish activation"
      : status === "partial"
      ? "Some package managers unprotected"
      : status === "unprotected"
      ? "Package managers unprotected"
      : "Supply chain status unknown";

  const handleToggle = () => setExpanded((prev) => !prev);

  return (
    <section
      className={`rounded-2xl border ${statusBorderClass} p-5 shadow-sm`}
      aria-label="Package manager protection"
    >
      <div className="flex items-start gap-3">
        <span
          className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-white/80"
          aria-hidden="true"
        >
          <StatusIcon className={`h-5 w-5 ${statusIconClass}`} />
        </span>
        <div className="min-w-0 flex-1 space-y-3">
          <div>
            <SectionLabel>Package manager protection</SectionLabel>
            <p className="mt-1 text-sm font-medium text-brand-dark">{statusLabel}</p>
            {protection?.shim_dir && (
              <p className="mt-0.5 text-xs text-slate-500 font-mono">
                Shim dir:{" "}
                <span className="text-brand-dark/70">{protection.shim_dir}</span>
              </p>
            )}
          </div>

          {(status === "unprotected" || status === "unknown") && (
            <div className="flex items-center gap-3">
              <ActionButton onClick={onOpenSupplyChain ?? onOpenFleet} variant="secondary">
                Set up protection
                <HiMiniArrowRight className="ml-1.5 h-3.5 w-3.5" aria-hidden="true" />
              </ActionButton>
              {onOpenSupplyChain && (
                <button
                  type="button"
                  onClick={onOpenSupplyChain}
                  className="inline-flex items-center gap-1 text-xs font-medium text-brand-blue hover:underline focus:outline-none focus:ring-2 focus:ring-brand-blue/30 rounded"
                >
                  View supply chain
                  <HiMiniArrowRight className="h-3 w-3" aria-hidden="true" />
                </button>
              )}
            </div>
          )}

          {status === "staged" && onOpenSupplyChain && (
            <div className="flex items-center gap-3">
              <ActionButton onClick={onOpenSupplyChain} variant="secondary">
                Finish activation
                <HiMiniArrowRight className="ml-1.5 h-3.5 w-3.5" aria-hidden="true" />
              </ActionButton>
            </div>
          )}

          {hasManagers && (
            <div className="space-y-2">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <Tag
                    tone={
                      status === "staged"
                        ? "blue"
                        : protectedCount === totalCount
                        ? "green"
                        : protectedCount > 0
                        ? "attention"
                        : "slate"
                    }
                  >
                    {status === "staged"
                      ? `${protection?.installed_managers.length ?? totalCount} ready after restart`
                      : `${protectedCount} of ${totalCount} protected`}
                  </Tag>
                  {lastBlocked && (
                    <span className="text-xs text-slate-500">
                      Last blocked{" "}
                      <span className="font-medium text-brand-dark">{lastBlocked.harness}</span>{" "}
                      {formatRelativeTime(lastBlocked.updated_at)}
                    </span>
                  )}
                </div>
                <button
                  type="button"
                  onClick={handleToggle}
                  className="inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs font-medium text-brand-blue transition-colors hover:bg-brand-blue/[0.06] focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                  aria-expanded={expanded}
                >
                  {expanded ? (
                    <>
                      Hide managers
                      <HiMiniChevronUp className="h-3.5 w-3.5" aria-hidden="true" />
                    </>
                  ) : (
                    <>
                      Show all managers
                      <HiMiniChevronDown className="h-3.5 w-3.5" aria-hidden="true" />
                    </>
                  )}
                </button>
              </div>

              {expanded && (
                <div
                  className="divide-y divide-slate-100 rounded-xl border border-slate-100 bg-white/80 overflow-hidden"
                  role="table"
                  aria-label="Package manager coverage"
                >
                  <div
                    className="flex items-center justify-between gap-2 px-3 py-1.5 bg-slate-50"
                    role="row"
                  >
                    <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400" role="columnheader">
                      Manager
                    </span>
                    <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400" role="columnheader">
                      Status
                    </span>
                  </div>
                  <div role="rowgroup">
                    {allManagers.map((mgr) => (
                      <div key={mgr} className="px-3" role="row">
                        <ProtectedManagerRow
                          manager={mgr}
                          protected={protection?.protected_managers.includes(mgr) ?? false}
                        />
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {intelState.stale && (
            <div className="flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50/60 px-3 py-2.5">
              <HiMiniExclamationTriangle
                className="mt-0.5 h-4 w-4 shrink-0 text-amber-600"
                aria-hidden="true"
              />
              <p className="text-xs text-amber-800">{intelState.label}</p>
            </div>
          )}

          {status === "partial" && onOpenSupplyChain && (
            <div>
              <button
                type="button"
                onClick={onOpenSupplyChain}
                className="inline-flex items-center gap-1 text-xs font-medium text-brand-blue hover:underline focus:outline-none focus:ring-2 focus:ring-brand-blue/30 rounded"
              >
                View full supply chain status
                <HiMiniArrowRight className="h-3 w-3" aria-hidden="true" />
              </button>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
