import { useCallback, useMemo, useState } from "react";
import type { ChangeEvent, ReactNode } from "react";
import {
  HiMiniArrowDown,
  HiMiniArrowUp,
  HiMiniBugAnt,
  HiMiniExclamationTriangle,
  HiMiniMagnifyingGlass,
} from "react-icons/hi2";
import { SectionLabel, Tag, ActionButton, EmptyState } from "./approval-center-primitives";
import { formatRelativeTime } from "./approval-center-utils";
import type {
  PackageWorkbenchFilters,
  PackageWorkbenchSortKey,
  SupplyChainAuditDecision,
  SupplyChainAuditFinding,
  SupplyChainAuditSeverity,
  SupplyChainAuditSnapshot,
} from "./guard-types";
import {
  filterPackageWorkbenchFindings,
  packageWorkbenchEcosystems,
  sortPackageWorkbenchFindings,
} from "./supply-chain-audit-normalize";
import { ConnectFlowCard } from "./supply-chain-firewall-views";
import type { AuditConnectGateViewState } from "./supply-chain-firewall-panel";

type PackageWorkbenchPanelProps = {
  auditConnectGate?: AuditConnectGateViewState | null;
  auditError?: string | null;
  auditSnapshot: SupplyChainAuditSnapshot | null;
  onRunAudit?: () => void;
  auditRunning?: boolean;
};

const decisionTone = (
  decision: SupplyChainAuditDecision,
): "destructive" | "attention" | "warning" | "info" | "green" | "default" => {
  if (decision === "block") {
    return "destructive";
  }
  if (decision === "ask") {
    return "attention";
  }
  if (decision === "warn") {
    return "warning";
  }
  if (decision === "monitor") {
    return "info";
  }
  if (decision === "allow") {
    return "green";
  }
  return "default";
};

const severityTone = (
  severity: SupplyChainAuditSeverity,
): "destructive" | "attention" | "warning" | "info" | "default" => {
  if (severity === "critical") {
    return "destructive";
  }
  if (severity === "high") {
    return "attention";
  }
  if (severity === "medium") {
    return "warning";
  }
  if (severity === "low") {
    return "info";
  }
  return "default";
};

type WorkbenchHeaderProps = {
  auditSnapshot: SupplyChainAuditSnapshot;
};

function WorkbenchHeader({ auditSnapshot }: WorkbenchHeaderProps) {
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
      <Tag tone={decisionTone(auditSnapshot.decision)}>{auditSnapshot.decision}</Tag>
      <span>
        {auditSnapshot.inventory.totalPackages} package
        {auditSnapshot.inventory.totalPackages === 1 ? "" : "s"} indexed
      </span>
      <span aria-hidden="true">·</span>
      <span>Last audit {formatRelativeTime(auditSnapshot.generatedAt)}</span>
      {auditSnapshot.source !== null && (
        <>
          <span aria-hidden="true">·</span>
          <span className="capitalize">{auditSnapshot.source} intel</span>
        </>
      )}
    </div>
  );
}

type FindingDetailPanelProps = {
  finding: SupplyChainAuditFinding;
};

function FindingDetailPanel({ finding }: FindingDetailPanelProps) {
  return (
    <div className="rounded-xl border border-slate-100 bg-slate-50/70 px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-sm font-semibold text-brand-dark">{finding.packageName}</p>
        <Tag tone="default">{finding.ecosystem}</Tag>
        <Tag tone={decisionTone(finding.decision)}>{finding.decision}</Tag>
        <Tag tone={severityTone(finding.severity)}>{finding.severity}</Tag>
      </div>
      {finding.reasons.length > 0 ? (
        <ul className="mt-3 space-y-2">
          {finding.reasons.map((reason) => (
            <li key={`${finding.id}-${reason.code}`} className="text-xs leading-relaxed text-slate-600">
              <span className="font-semibold text-slate-700">{reason.code}</span>
              <span className="text-slate-400"> · </span>
              {reason.message}
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-3 text-xs text-slate-500">No advisory detail recorded for this package yet.</p>
      )}
      <div className="mt-4">
        <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">
          Advisory aliases
        </p>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {finding.advisoryAliases.map((alias) => (
            <span
              key={`${finding.id}-${alias}`}
              className="rounded-full border border-slate-200 bg-white px-2.5 py-0.5 font-mono text-[11px] text-slate-600"
            >
              {alias}
            </span>
          ))}
        </div>
        {finding.advisoryAliases.length === 0 ? (
          <p className="mt-2 text-[11px] text-slate-500">
            No linked CVE or GHSA aliases for this finding.
          </p>
        ) : null}
      </div>
    </div>
  );
}

type FindingRowProps = {
  finding: SupplyChainAuditFinding;
  selected: boolean;
  onSelect: (id: string) => void;
};

function FindingRow({ finding, selected, onSelect }: FindingRowProps) {
  const handleSelect = useCallback(() => {
    onSelect(finding.id);
  }, [finding.id, onSelect]);

  return (
    <button
      type="button"
      onClick={handleSelect}
      aria-pressed={selected}
      className={`flex w-full items-center justify-between gap-3 border-b border-slate-100 px-4 py-3 text-left transition-colors last:border-b-0 hover:bg-slate-50/70 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-brand-blue/30 ${
        selected ? "bg-brand-blue/[0.04]" : ""
      }`}
    >
      <div className="min-w-0">
        <p className="truncate text-sm font-medium text-brand-dark">{finding.packageName}</p>
        <p className="mt-0.5 truncate text-xs text-slate-500">
          {finding.ecosystem}
          {finding.namespace !== null ? ` · ${finding.namespace}` : ""}
        </p>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <Tag tone={decisionTone(finding.decision)}>{finding.decision}</Tag>
        <Tag tone={severityTone(finding.severity)}>{finding.severity}</Tag>
      </div>
    </button>
  );
}

type SortButtonProps = {
  label: string;
  sortKey: PackageWorkbenchSortKey;
  activeSort: PackageWorkbenchSortKey;
  direction: "asc" | "desc";
  onSort: (sortKey: PackageWorkbenchSortKey) => void;
};

function SortButton({ label, sortKey, activeSort, direction, onSort }: SortButtonProps) {
  const handleClick = useCallback(() => {
    onSort(sortKey);
  }, [onSort, sortKey]);
  const active = activeSort === sortKey;
  let sortIcon: ReactNode = null;
  if (active) {
    sortIcon =
      direction === "desc" ? (
        <HiMiniArrowDown className="h-3 w-3" aria-hidden="true" />
      ) : (
        <HiMiniArrowUp className="h-3 w-3" aria-hidden="true" />
      );
  }
  return (
    <button
      type="button"
      onClick={handleClick}
      aria-pressed={active}
      className={`inline-flex items-center gap-1 rounded-full px-3 py-1 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${
        active
          ? "bg-brand-blue text-white"
          : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
      }`}
    >
      {label}
      {sortIcon}
    </button>
  );
}

type FilterChipProps = {
  label: string;
  active: boolean;
  onSelect: () => void;
};

function FilterChip({ label, active, onSelect }: FilterChipProps) {
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={active}
      className={`rounded-full px-3 py-1 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${
        active
          ? "bg-brand-dark text-white"
          : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
      }`}
    >
      {label}
    </button>
  );
}

type WorkbenchControlsProps = {
  filters: PackageWorkbenchFilters;
  ecosystems: string[];
  sortKey: PackageWorkbenchSortKey;
  sortDirection: "asc" | "desc";
  onSearchChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onEcosystemChange: (ecosystem: string) => void;
  onDecisionChange: (decision: PackageWorkbenchFilters["decision"]) => void;
  onSeverityChange: (severity: PackageWorkbenchFilters["severity"]) => void;
  onSortChange: (sortKey: PackageWorkbenchSortKey) => void;
};

function WorkbenchControls({
  filters,
  ecosystems,
  sortKey,
  sortDirection,
  onSearchChange,
  onEcosystemChange,
  onDecisionChange,
  onSeverityChange,
  onSortChange,
}: WorkbenchControlsProps) {
  const handleEcosystemAll = useCallback(() => onEcosystemChange("all"), [onEcosystemChange]);
  const handleDecisionAll = useCallback(() => onDecisionChange("all"), [onDecisionChange]);
  const handleDecisionBlock = useCallback(() => onDecisionChange("block"), [onDecisionChange]);
  const handleDecisionAsk = useCallback(() => onDecisionChange("ask"), [onDecisionChange]);
  const handleDecisionWarn = useCallback(() => onDecisionChange("warn"), [onDecisionChange]);
  const handleSeverityAll = useCallback(() => onSeverityChange("all"), [onSeverityChange]);
  const handleSeverityCritical = useCallback(() => onSeverityChange("critical"), [onSeverityChange]);
  const handleSeverityHigh = useCallback(() => onSeverityChange("high"), [onSeverityChange]);
  const handleSeverityMedium = useCallback(() => onSeverityChange("medium"), [onSeverityChange]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5">
          <HiMiniMagnifyingGlass className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
          <input
            type="search"
            placeholder="Search packages…"
            value={filters.search}
            onChange={onSearchChange}
            aria-label="Search package findings"
            className="w-44 bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none"
          />
        </div>
        <FilterChip label="All ecosystems" active={filters.ecosystem === "all"} onSelect={handleEcosystemAll} />
        {ecosystems.map((ecosystem) => (
          <EcosystemChip
            key={ecosystem}
            ecosystem={ecosystem}
            active={filters.ecosystem === ecosystem}
            onSelect={onEcosystemChange}
          />
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <FilterChip label="All decisions" active={filters.decision === "all"} onSelect={handleDecisionAll} />
        <FilterChip label="Block" active={filters.decision === "block"} onSelect={handleDecisionBlock} />
        <FilterChip label="Ask" active={filters.decision === "ask"} onSelect={handleDecisionAsk} />
        <FilterChip label="Warn" active={filters.decision === "warn"} onSelect={handleDecisionWarn} />
        <span className="mx-1 h-4 w-px bg-slate-200" aria-hidden="true" />
        <FilterChip label="All severities" active={filters.severity === "all"} onSelect={handleSeverityAll} />
        <FilterChip label="Critical" active={filters.severity === "critical"} onSelect={handleSeverityCritical} />
        <FilterChip label="High" active={filters.severity === "high"} onSelect={handleSeverityHigh} />
        <FilterChip label="Medium" active={filters.severity === "medium"} onSelect={handleSeverityMedium} />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">Sort</span>
        <SortButton label="Severity" sortKey="severity" activeSort={sortKey} direction={sortDirection} onSort={onSortChange} />
        <SortButton label="Package" sortKey="package" activeSort={sortKey} direction={sortDirection} onSort={onSortChange} />
        <SortButton label="Ecosystem" sortKey="ecosystem" activeSort={sortKey} direction={sortDirection} onSort={onSortChange} />
        <SortButton label="Decision" sortKey="decision" activeSort={sortKey} direction={sortDirection} onSort={onSortChange} />
      </div>
    </div>
  );
}

type EcosystemChipProps = {
  ecosystem: string;
  active: boolean;
  onSelect: (ecosystem: string) => void;
};

function EcosystemChip({ ecosystem, active, onSelect }: EcosystemChipProps) {
  const handleSelect = useCallback(() => {
    onSelect(ecosystem);
  }, [ecosystem, onSelect]);
  return <FilterChip label={ecosystem} active={active} onSelect={handleSelect} />;
}

type WorkbenchEmptyStateProps = {
  auditConnectGate?: AuditConnectGateViewState | null;
  auditError?: string | null;
  onRunAudit?: () => void;
  auditRunning?: boolean;
};

function WorkbenchAuditErrorBanner({ message }: { message: string }) {
  return (
    <div
      className="mb-4 flex items-start gap-2 rounded-xl border border-brand-attention/30 bg-brand-attention/[0.04] px-3 py-2.5"
      role="alert"
      aria-live="assertive"
      data-testid="workbench-audit-error"
    >
      <HiMiniExclamationTriangle className="mt-0.5 h-4 w-4 shrink-0 text-brand-attention" aria-hidden="true" />
      <div className="min-w-0">
        <p className="text-sm font-medium text-brand-dark">Workspace audit could not start</p>
        <p className="mt-0.5 text-xs leading-relaxed text-slate-600">{message}</p>
      </div>
    </div>
  );
}

function WorkbenchEmptyState({ auditConnectGate, auditError, onRunAudit, auditRunning }: WorkbenchEmptyStateProps) {
  if (auditConnectGate !== null && auditConnectGate !== undefined) {
    return (
      <ConnectFlowCard
        compact
        connectError={auditConnectGate.connectError}
        connectStarting={auditConnectGate.connectStarting}
        connectFlow={auditConnectGate.connectFlow}
        detail={auditConnectGate.gate.detail}
        headline={auditConnectGate.gate.headline}
        mode={auditConnectGate.gate.mode}
        onStartConnect={auditConnectGate.onStartConnect}
        purpose="audit"
      />
    );
  }

  return (
    <>
      {auditError ? <WorkbenchAuditErrorBanner message={auditError} /> : null}
      <EmptyState
        title="No workspace audit yet"
        body="Run a package audit to index dependencies and surface flagged packages here."
        tone="teach"
        action={
          onRunAudit !== undefined ? (
            <ActionButton variant="outline" onClick={onRunAudit} disabled={auditRunning} aria-busy={auditRunning}>
              <HiMiniBugAnt className="mr-1.5 h-4 w-4" aria-hidden="true" />
              Run audit
            </ActionButton>
          ) : undefined
        }
      />
    </>
  );
}

export function PackageWorkbenchPanel({
  auditConnectGate = null,
  auditError = null,
  auditSnapshot,
  onRunAudit,
  auditRunning = false,
}: PackageWorkbenchPanelProps) {
  const [filters, setFilters] = useState<PackageWorkbenchFilters>({
    ecosystem: "all",
    decision: "all",
    severity: "all",
    search: "",
  });
  const [sortState, setSortState] = useState<{
    sortKey: PackageWorkbenchSortKey;
    sortDirection: "asc" | "desc";
  }>({ sortKey: "severity", sortDirection: "desc" });
  const { sortKey, sortDirection } = sortState;
  const [selectedId, setSelectedId] = useState("");

  const findings = auditSnapshot?.findings ?? [];
  const ecosystems = useMemo(() => packageWorkbenchEcosystems(findings), [findings]);
  const filteredFindings = useMemo(
    () => filterPackageWorkbenchFindings(findings, filters),
    [findings, filters],
  );
  const sortedFindings = useMemo(() => {
    const sorted = sortPackageWorkbenchFindings(filteredFindings, sortKey);
    if (sortDirection === "asc") {
      return [...sorted].reverse();
    }
    return sorted;
  }, [filteredFindings, sortDirection, sortKey]);
  const selectedFinding = useMemo(
    () => sortedFindings.find((finding) => finding.id === selectedId) ?? null,
    [selectedId, sortedFindings],
  );

  const handleSearchChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setFilters((prev) => ({ ...prev, search: event.target.value }));
    setSelectedId("");
  }, []);

  const handleEcosystemChange = useCallback((ecosystem: string) => {
    setFilters((prev) => ({ ...prev, ecosystem }));
    setSelectedId("");
  }, []);

  const handleDecisionChange = useCallback((decision: PackageWorkbenchFilters["decision"]) => {
    setFilters((prev) => ({ ...prev, decision }));
    setSelectedId("");
  }, []);

  const handleSeverityChange = useCallback((severity: PackageWorkbenchFilters["severity"]) => {
    setFilters((prev) => ({ ...prev, severity }));
    setSelectedId("");
  }, []);

  const handleSortChange = useCallback((nextSortKey: PackageWorkbenchSortKey) => {
    setSortState((prev) => {
      if (prev.sortKey === nextSortKey) {
        return {
          sortKey: prev.sortKey,
          sortDirection: prev.sortDirection === "desc" ? "asc" : "desc",
        };
      }
      return { sortKey: nextSortKey, sortDirection: "desc" };
    });
  }, []);

  const handleSelectFinding = useCallback((id: string) => {
    setSelectedId((prev) => (prev === id ? "" : id));
  }, []);

  return (
    <div className="rounded-2xl border border-slate-100 bg-white shadow-sm">
      <div className="border-b border-slate-100 px-4 py-3">
        <SectionLabel>Audit findings</SectionLabel>
        <p className="mt-0.5 text-sm text-slate-500">
          Review flagged packages from the latest workspace audit. Filter, sort, and inspect advisory detail.
        </p>
        {auditSnapshot !== null && (
          <div className="mt-2">
            <WorkbenchHeader auditSnapshot={auditSnapshot} />
          </div>
        )}
      </div>

      {auditSnapshot === null && (
        <div className="px-4 py-6">
          <WorkbenchEmptyState
            auditConnectGate={auditConnectGate}
            auditError={auditError}
            onRunAudit={onRunAudit}
            auditRunning={auditRunning}
          />
        </div>
      )}
      {auditSnapshot !== null && findings.length === 0 && (
        <div className="px-4 py-6">
          <EmptyState
            title="No flagged packages"
            body="The latest workspace audit completed without packages that need review."
            tone="teach"
          />
        </div>
      )}
      {auditSnapshot !== null && findings.length > 0 && (
        <div className="space-y-4 px-4 py-4">
          <WorkbenchControls
            filters={filters}
            ecosystems={ecosystems}
            sortKey={sortKey}
            sortDirection={sortDirection}
            onSearchChange={handleSearchChange}
            onEcosystemChange={handleEcosystemChange}
            onDecisionChange={handleDecisionChange}
            onSeverityChange={handleSeverityChange}
            onSortChange={handleSortChange}
          />
          {sortedFindings.length === 0 ? (
            <p className="py-6 text-center text-sm text-slate-500">No packages match the current filters.</p>
          ) : (
            <div className="overflow-hidden rounded-xl border border-slate-100" role="table" aria-label="Package audit findings">
              <div
                className="hidden border-b border-slate-100 bg-slate-50 px-4 py-2 sm:grid sm:grid-cols-[minmax(0,1fr)_auto] sm:gap-3"
                role="row"
              >
                <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400" role="columnheader">
                  Package
                </span>
                <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400" role="columnheader">
                  Decision · Severity
                </span>
              </div>
              <div role="rowgroup">
                {sortedFindings.map((finding) => (
                  <FindingRow
                    key={finding.id}
                    finding={finding}
                    selected={selectedId === finding.id}
                    onSelect={handleSelectFinding}
                  />
                ))}
              </div>
            </div>
          )}
          {selectedFinding !== null && <FindingDetailPanel finding={selectedFinding} />}
        </div>
      )}
    </div>
  );
}
