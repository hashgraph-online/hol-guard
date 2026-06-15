import { useState, useCallback, useMemo } from "react";
import type { ChangeEvent, ReactNode } from "react";
import {
  HiMiniExclamationTriangle,
  HiMiniCheckCircle,
  HiMiniXCircle,
  HiMiniInformationCircle,
  HiMiniMagnifyingGlass,
  HiMiniFunnel,
  HiMiniArrowDown,
  HiMiniArrowUp,
  HiMiniChevronRight,
  HiMiniWrenchScrewdriver,
  HiMiniShieldCheck,
  HiMiniDocumentText,
  HiMiniArrowPath,
} from "react-icons/hi2";
import { SectionLabel, Badge, Tag, ActionButton, IconActionButton, EmptyState } from "./approval-center-primitives";
import { ApprovalProofModal } from "./approval-proof-modal";
import { formatRelativeTime, harnessDisplayName } from "./approval-center-utils";
import { runAuditRemediation, guardAwareHref } from "./guard-api";
import { isApprovalGateRequiredError } from "./harness-action-errors";
import type { AuditRemediationAction } from "./guard-api";
import type { GuardApprovalGatePublicConfig, GuardReceipt, GuardRuntimeSnapshot } from "./guard-types";
import { useResolvedApprovalGate } from "./use-resolved-approval-gate";
import { resolveManagerCoverageStatus } from "./supply-chain-protection-stats";
import { PackageWorkbenchPanel } from "./package-workbench-panel";
import { AuditRunProgress } from "./audit-run-progress";
import type { SupplyChainAuditSession } from "./use-supply-chain-audit-session";

export type AuditSeverity = "critical" | "high" | "medium" | "low" | "info";

export type AuditResult = {
  id: string;
  severity: AuditSeverity;
  title: string;
  detail: string;
  harness: string;
  workspace: string | null;
  timestamp: string;
  remediation: string | null;
  remediationAction: AuditRemediationRequest | null;
  resolved: boolean;
  evidenceHref: string | null;
};

export type AuditRemediationRequest = {
  action: AuditRemediationAction;
  manager: string;
  label: string;
};

function isSupplyChainAuditEvidence(value: unknown): value is Record<string, unknown> & { operation: "audit" } {
  return typeof value === "object" && value !== null && (value as Record<string, unknown>).operation === "audit";
}

function auditSeverityForDecision(decision: string, blockedCount: number): AuditSeverity {
  if (decision === "block" || blockedCount > 0) {
    return "high";
  }
  if (decision === "ask") {
    return "medium";
  }
  if (decision === "warn") {
    return "medium";
  }
  return "info";
}

function workspaceAuditTitle(decision: string): string {
  if (decision === "block") {
    return "Workspace audit found blocked packages";
  }
  if (decision === "ask") {
    return "Workspace audit needs review";
  }
  return "Workspace audit completed";
}

function workspaceAuditRemediation(decision: string, blockedCount: number): string {
  if (blockedCount > 0) {
    return "Review blocked packages in Evidence and update lockfiles before retrying installs.";
  }
  if (decision === "ask") {
    return "Review flagged packages and repair lockfiles before continuing.";
  }
  return "Re-run workspace audit after dependency changes.";
}

export type AuditFilterState = {
  severityFilter: AuditSeverity | "all";
  harnessFilter: string;
  resolvedFilter: "all" | "open" | "resolved";
  searchQuery: string;
};

function buildPackageManagerAuditResult(
  manager: string,
  protection: NonNullable<GuardRuntimeSnapshot["supply_chain"]>["package_manager_protection"],
  generatedAt: string,
): AuditResult | null {
  const coverage = resolveManagerCoverageStatus(protection, manager);
  if (coverage === "protected") {
    return null;
  }

  if (coverage === "restart_required") {
    return {
      id: `unprotected-${manager}`,
      severity: "medium",
      title: `${manager} is waiting for restart`,
      detail: `Guard already updated your shell profile for ${manager}. Open a new shell or restart AI apps so ${manager} resolves through Guard.`,
      harness: "global",
      workspace: null,
      timestamp: generatedAt,
      remediation: "Open a new shell or restart AI apps to finish package-manager interception.",
      remediationAction: null,
      resolved: false,
      evidenceHref: null,
    };
  }

  if (coverage === "path_repair") {
    return {
      id: `unprotected-${manager}`,
      severity: "medium",
      title: `${manager} shim is installed but PATH still needs repair`,
      detail: `Guard already installed the ${manager} shim on this machine. Repair PATH so ${manager} commands resolve through Guard before package installs run.`,
      harness: "global",
      workspace: null,
      timestamp: generatedAt,
      remediation: "Repair PATH from Supply chain or run hol-guard package-shims repair for this manager.",
      remediationAction: {
        action: "package_shim_path",
        manager,
        label: "Repair PATH",
      },
      resolved: false,
      evidenceHref: `/evidence?harness=global&search=${encodeURIComponent(manager)}`,
    };
  }

  return {
    id: `unprotected-${manager}`,
    severity: "high",
    title: `${manager} is not intercepted by Guard`,
    detail: `The ${manager} shim is missing from PATH. Installs via ${manager} bypass Guard's supply chain protection.`,
    harness: "global",
    workspace: null,
    timestamp: generatedAt,
    remediation: `Guard can install the shim and update PATH for ${manager} from this dashboard.`,
    remediationAction: {
      action: "package_shim_path",
      manager,
      label: "Install Guard",
    },
    resolved: false,
    evidenceHref: `/evidence?harness=global&search=${encodeURIComponent(manager)}`,
  };
}

export function deriveFrontendAuditResults(
  receipts: GuardReceipt[],
  snapshot: GuardRuntimeSnapshot,
): AuditResult[] {
  const results: AuditResult[] = [];

  const protection = snapshot.supply_chain?.package_manager_protection;
  if (protection) {
    const managersNeedingAttention = protection.supported_managers.filter(
      (manager) => resolveManagerCoverageStatus(protection, manager) !== "protected",
    );
    for (const mgr of managersNeedingAttention) {
      const auditResult = buildPackageManagerAuditResult(mgr, protection, snapshot.generated_at);
      if (auditResult !== null) {
        results.push(auditResult);
      }
    }
  }

  const blockedReceipts = receipts.filter((r) => r.policy_decision === "block");
  for (const r of blockedReceipts.slice(0, 20)) {
    const evidenceParams = new URLSearchParams();
    evidenceParams.set("harness", r.harness || "global");
    if (r.artifact_name) {
      evidenceParams.set("search", r.artifact_name);
    }
    results.push({
      id: `blocked-${r.receipt_id}`,
      severity: "medium",
      title: r.artifact_name ? `Blocked: ${r.artifact_name}` : "Blocked action",
      detail: r.capabilities_summary || "Guard blocked this action based on policy.",
      harness: r.harness,
      workspace: r.source_scope ?? null,
      timestamp: r.timestamp,
      remediation: "Review the action in evidence and adjust policy if it was a false positive.",
      remediationAction: null,
      resolved: true,
      evidenceHref: `/evidence?${evidenceParams.toString()}`,
    });
  }

  for (const receipt of receipts) {
    if (receipt.harness !== "package-firewall") {
      continue;
    }
    const evidence = receipt.scanner_evidence?.find(isSupplyChainAuditEvidence);
    if (evidence === undefined) {
      continue;
    }
    const decision =
      typeof evidence.audit_decision === "string" ? evidence.audit_decision : "monitor";
    const blockedCount =
      typeof evidence.blocked_package_count === "number" ? evidence.blocked_package_count : 0;
    const totalPackages =
      typeof evidence.total_packages === "number" ? evidence.total_packages : blockedCount;
    const manifestPaths = Array.isArray(evidence.manifest_paths)
      ? evidence.manifest_paths.filter((entry): entry is string => typeof entry === "string")
      : [];
    const lockfilePaths = Array.isArray(evidence.lockfile_paths)
      ? evidence.lockfile_paths.filter((entry): entry is string => typeof entry === "string")
      : [];
    const inventorySummary = [
      manifestPaths.length > 0 ? `${manifestPaths.length} manifest(s)` : null,
      lockfilePaths.length > 0 ? `${lockfilePaths.length} lockfile(s)` : null,
      `${totalPackages} package(s)`,
    ]
      .filter((entry): entry is string => entry !== null)
      .join(", ");
    results.push({
      id: `workspace-audit-${receipt.receipt_id}`,
      severity: auditSeverityForDecision(decision, blockedCount),
      title: workspaceAuditTitle(decision),
      detail:
        receipt.capabilities_summary ||
        `Guard scanned ${inventorySummary} and returned a ${decision} decision.`,
      harness: "package-firewall",
      workspace: receipt.source_scope,
      timestamp: receipt.timestamp,
      remediation: workspaceAuditRemediation(decision, blockedCount),
      remediationAction: null,
      resolved: decision === "monitor" && blockedCount === 0,
      evidenceHref: `/evidence?harness=package-firewall&search=${encodeURIComponent(receipt.receipt_id)}`,
    });
  }

  if (snapshot.runtime_state === null) {
    results.push({
      id: "daemon-offline",
      severity: "critical",
      title: "Guard daemon is offline",
      detail: "The local Guard service is not running. No protection is active.",
      harness: "global",
      workspace: null,
      timestamp: snapshot.generated_at,
      remediation: "Start Guard with hol-guard bootstrap or check system logs.",
      remediationAction: null,
      resolved: false,
      evidenceHref: null,
    });
  }

  return results;
}

function severityBadgeTone(
  severity: AuditSeverity,
): "destructive" | "attention" | "warning" | "info" | "default" {
  if (severity === "critical") return "destructive";
  if (severity === "high") return "attention";
  if (severity === "medium") return "warning";
  if (severity === "low") return "info";
  return "default";
}

type AuditResultRowProps = {
  result: AuditResult;
  onMarkResolved?: (id: string) => void;
  onRunRemediation: (result: AuditResult) => void;
  running: boolean;
  actionMessage: string | null;
};

function AuditResultRow({ result, onMarkResolved, onRunRemediation, running, actionMessage }: AuditResultRowProps) {
  const [expanded, setExpanded] = useState(false);
  const toggle = useCallback(() => setExpanded((p) => !p), []);
  const handleResolve = useCallback(() => onMarkResolved?.(result.id), [onMarkResolved, result.id]);
  const showInlineAction = !result.resolved && (result.remediationAction !== null || onMarkResolved);

  return (
    <div className={`border-b border-slate-100 last:border-b-0 ${result.resolved ? "opacity-60" : ""}`}>
      <div className="flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-start sm:justify-between sm:gap-4 hover:bg-slate-50/60">
        <button
          type="button"
          onClick={toggle}
          aria-expanded={expanded}
          className="flex min-w-0 flex-1 items-start gap-3 text-left focus:outline-none focus:ring-2 focus:ring-inset focus:ring-brand-blue/30"
        >
          <span className="mt-0.5 shrink-0" aria-hidden="true">
            {result.resolved ? (
              <HiMiniCheckCircle className="h-4 w-4 text-brand-green" />
            ) : result.severity === "critical" || result.severity === "high" ? (
              <HiMiniXCircle className="h-4 w-4 text-red-500" />
            ) : (
              <HiMiniExclamationTriangle className="h-4 w-4 text-brand-attention" />
            )}
          </span>
          <div className="min-w-0 flex-1 space-y-0.5">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-medium text-brand-dark">{result.title}</span>
              <Badge tone={severityBadgeTone(result.severity)}>
                {result.severity}
              </Badge>
              {result.resolved && <Badge tone="success">Resolved</Badge>}
            </div>
            <p className="text-xs text-slate-500">
              {harnessDisplayName(result.harness)}
              {result.workspace ? ` / ${result.workspace}` : ""}
              <span className="mx-1.5 text-slate-300">·</span>
              {formatRelativeTime(result.timestamp)}
            </p>
          </div>
          <HiMiniChevronRight
            className={`mt-0.5 h-4 w-4 shrink-0 text-slate-300 transition-transform ${expanded ? "rotate-90" : ""}`}
            aria-hidden="true"
          />
        </button>
        {showInlineAction && (
          <div className="shrink-0 pl-7 sm:pl-0 sm:pt-0.5">
            <AuditRowActions
              result={result}
              onMarkResolved={onMarkResolved}
              onRunRemediation={onRunRemediation}
              running={running}
            />
          </div>
        )}
      </div>
      {actionMessage !== null && (
        <p className="px-4 pb-2 text-xs text-slate-500">{actionMessage}</p>
      )}
      {expanded && (
        <div className="border-t border-slate-100 bg-slate-50/40 px-4 py-3 space-y-3">
          <p className="text-sm text-brand-dark/80">{result.detail}</p>
          {result.remediation && (
            <p className="text-sm text-brand-dark/70">{result.remediation}</p>
          )}
          {!result.resolved && onMarkResolved && (
            <ActionButton variant="outline" onClick={handleResolve}>
              Mark as resolved
            </ActionButton>
          )}
        </div>
      )}
    </div>
  );
}

function AuditRowActions(props: {
  result: AuditResult;
  onMarkResolved?: (id: string) => void;
  onRunRemediation: (result: AuditResult) => void;
  running: boolean;
}) {
  const { result, onMarkResolved, onRunRemediation, running } = props;
  const handleMarkResolved = useCallback(() => onMarkResolved?.(result.id), [onMarkResolved, result.id]);
  const handleRunRemediation = useCallback(() => onRunRemediation(result), [onRunRemediation, result]);

  if (result.remediationAction !== null) {
    return (
      <div className="flex flex-wrap items-center gap-1.5">
        {result.evidenceHref && (
          <a
            href={guardAwareHref(result.evidenceHref)}
            className="inline-flex h-9 w-9 items-center justify-center rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/30 transition-colors"
            aria-label={`View evidence for ${result.title}`}
            title="View evidence"
          >
            <HiMiniDocumentText className="h-4 w-4" aria-hidden="true" />
          </a>
        )}
        <IconActionButton
          variant="primary"
          label={result.remediationAction.label}
          icon={running ? <HiMiniArrowPath className="h-4 w-4" /> : <HiMiniShieldCheck className="h-4 w-4" />}
          onClick={handleRunRemediation}
          disabled={running}
          spinning={running}
        />
      </div>
    );
  }

  if (onMarkResolved) {
    return (
      <div className="flex flex-wrap items-center gap-1.5">
        {result.evidenceHref && (
          <a
            href={guardAwareHref(result.evidenceHref)}
            className="inline-flex h-9 w-9 items-center justify-center rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/30 transition-colors"
            aria-label={`View evidence for ${result.title}`}
            title="View evidence"
          >
            <HiMiniDocumentText className="h-4 w-4" aria-hidden="true" />
          </a>
        )}
        <IconActionButton
          variant="outline"
          label="Resolve"
          icon={<HiMiniCheckCircle className="h-4 w-4" />}
          onClick={handleMarkResolved}
        />
      </div>
    );
  }

  return null;
}

type AuditWorkspaceProps = {
  snapshot: GuardRuntimeSnapshot;
  receipts: GuardReceipt[];
  approvalGate: GuardApprovalGatePublicConfig | null;
  auditSession: SupplyChainAuditSession;
};

export function AuditWorkspace({ snapshot, receipts, approvalGate, auditSession }: AuditWorkspaceProps) {
  const [filter, setFilter] = useState<AuditFilterState>({
    severityFilter: "all",
    harnessFilter: "",
    resolvedFilter: "open",
    searchQuery: "",
  });
  const [resolvedIds, setResolvedIds] = useState<Set<string>>(new Set());
  const [pendingRemediation, setPendingRemediation] = useState<AuditResult | null>(null);
  const [runningRemediationId, setRunningRemediationId] = useState<string | null>(null);
  const [remediationMessages, setRemediationMessages] = useState<Record<string, string>>({});
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(approvalGate);

  const handleSearchChange = useCallback((e: ChangeEvent<HTMLInputElement>) => {
    setFilter((f) => ({ ...f, searchQuery: e.target.value }));
  }, []);

  const handleSeverityChange = useCallback((sev: AuditFilterState["severityFilter"]) => {
    setFilter((f) => ({ ...f, severityFilter: sev }));
  }, []);

  const handleResolvedFilterChange = useCallback(
    (val: AuditFilterState["resolvedFilter"]) => {
      setFilter((f) => ({ ...f, resolvedFilter: val }));
    },
    [],
  );

  const handleMarkResolved = useCallback((id: string) => {
    setResolvedIds((prev) => new Set([...prev, id]));
  }, []);

  const executeRemediation = useCallback(
    async (
      result: AuditResult,
      credentials?: { approval_password?: string; approval_totp_code?: string },
    ) => {
      if (result.remediationAction === null) return;
      setRunningRemediationId(result.id);
      setRemediationMessages((prev) => ({ ...prev, [result.id]: "Running remediation through the local daemon." }));
      try {
        await runAuditRemediation({
          ...result.remediationAction,
          ...credentials,
        });
        setResolvedIds((prev) => new Set([...prev, result.id]));
        setRemediationMessages((prev) => ({
          ...prev,
          [result.id]: "Remediation completed. Restart your shell before retrying package installs.",
        }));
      } catch (error) {
        if (credentials === undefined && isApprovalGateRequiredError(error)) {
          await resolveApprovalGate();
          setPendingRemediation(result);
          setRemediationMessages((prev) => {
            const next = { ...prev };
            delete next[result.id];
            return next;
          });
          return;
        }
        const message = error instanceof Error ? error.message : "Unable to run remediation.";
        setRemediationMessages((prev) => ({ ...prev, [result.id]: message }));
      } finally {
        setRunningRemediationId(null);
      }
    },
    [resolveApprovalGate],
  );

  const handleRunRemediation = useCallback(
    (result: AuditResult) => {
      if (result.remediationAction === null) return;
      void executeRemediation(result);
    },
    [executeRemediation],
  );

  const handleCancelRemediationGate = useCallback(() => setPendingRemediation(null), []);

  const handleConfirmRemediationGate = useCallback(
    (credentials: { approval_password?: string; approval_totp_code?: string }) => {
      const result = pendingRemediation;
      if (result === null) return;
      setPendingRemediation(null);
      void executeRemediation(result, credentials);
    },
    [executeRemediation, pendingRemediation],
  );

  const baseResults = useMemo(
    () => deriveFrontendAuditResults(receipts, snapshot),
    [receipts, snapshot],
  );

  const results = useMemo(() => {
    return baseResults
      .map((r) => ({ ...r, resolved: r.resolved || resolvedIds.has(r.id) }))
      .filter((r) => {
        const matchesSeverity =
          filter.severityFilter === "all" || r.severity === filter.severityFilter;
        const matchesResolved =
          filter.resolvedFilter === "all" ||
          (filter.resolvedFilter === "open" && !r.resolved) ||
          (filter.resolvedFilter === "resolved" && r.resolved);
        const matchesSearch =
          filter.searchQuery === "" ||
          r.title.toLowerCase().includes(filter.searchQuery.toLowerCase()) ||
          r.detail.toLowerCase().includes(filter.searchQuery.toLowerCase());
        return matchesSeverity && matchesResolved && matchesSearch;
      })
      .sort((a, b) => {
        const order: Record<AuditSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        return order[a.severity] - order[b.severity];
      });
  }, [baseResults, filter, resolvedIds]);

  const openCount = useMemo(
    () => baseResults.filter((r) => !r.resolved && !resolvedIds.has(r.id)).length,
    [baseResults, resolvedIds],
  );

  const criticalCount = useMemo(
    () =>
      baseResults.filter(
        (r) =>
          (r.severity === "critical" || r.severity === "high") &&
          !r.resolved &&
          !resolvedIds.has(r.id),
      ).length,
    [baseResults, resolvedIds],
  );

  return (
    <div className="space-y-6">
      <AuditRunProgress phase={auditSession.auditPhase} running={auditSession.auditRunning} />

      <PackageWorkbenchPanel
        auditConnectGate={auditSession.auditConnectGate}
        auditError={auditSession.auditError}
        auditSnapshot={auditSession.auditSnapshot}
        auditRunning={auditSession.auditRunning}
        onRunAudit={auditSession.handleRunAudit}
      />

      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-sm text-slate-500">
            Workspace audit results and open issues. Fix high-priority items inline.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {criticalCount > 0 && (
            <Badge tone="destructive">{criticalCount} critical</Badge>
          )}
          {openCount > 0 ? (
            <Badge tone="attention">{openCount} open</Badge>
          ) : (
            <Badge tone="success">All clear</Badge>
          )}
        </div>
      </div>

      <div className="rounded-2xl border border-slate-100 bg-white shadow-sm">
        <div className="border-b border-slate-100 px-4 py-3 space-y-3">
          <SectionLabel>Filters</SectionLabel>
          <div className="flex flex-wrap gap-2">
            <div className="flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5">
              <HiMiniMagnifyingGlass className="h-3.5 w-3.5 text-slate-400 shrink-0" aria-hidden="true" />
              <input
                type="search"
                placeholder="Search issues..."
                value={filter.searchQuery}
                onChange={handleSearchChange}
                aria-label="Search audit issues"
                className="bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none w-40"
              />
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <span className="text-xs font-semibold text-slate-500 self-center">Severity:</span>
            {(["all", "critical", "high", "medium", "low", "info"] as const).map((sev) => (
              <button
                key={sev}
                type="button"
                onClick={() => handleSeverityChange(sev)}
                aria-pressed={filter.severityFilter === sev}
                className={`rounded-full px-3 py-1 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${
                  filter.severityFilter === sev
                    ? "bg-brand-blue text-white"
                    : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
                }`}
              >
                {sev.charAt(0).toUpperCase() + sev.slice(1)}
              </button>
            ))}
          </div>
          <div className="flex flex-wrap gap-2">
            <span className="text-xs font-semibold text-slate-500 self-center">Status:</span>
            {(["all", "open", "resolved"] as const).map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => handleResolvedFilterChange(s)}
                aria-pressed={filter.resolvedFilter === s}
                className={`rounded-full px-3 py-1 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${
                  filter.resolvedFilter === s
                    ? "bg-brand-blue text-white"
                    : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
                }`}
              >
                {s.charAt(0).toUpperCase() + s.slice(1)}
              </button>
            ))}
          </div>
        </div>

        {results.length === 0 ? (
          <EmptyState
            title={openCount === 0 ? "No audit issues found" : "No results match your filter"}
            body={
              openCount === 0
                ? "Guard found no issues in the current workspace. Keep running to build more coverage."
                : "Try adjusting the severity or status filters to see more results."
            }
            tone="teach"
          />
        ) : (
          <div role="list" aria-label="Audit results">
            {results.map((result) => (
              <div key={result.id} role="listitem">
                <AuditResultRow
                  result={result}
                  onMarkResolved={handleMarkResolved}
                  onRunRemediation={handleRunRemediation}
                  running={runningRemediationId === result.id}
                  actionMessage={remediationMessages[result.id] ?? null}
                />
              </div>
            ))}
          </div>
        )}
      </div>

      {pendingRemediation !== null && (
        <RemediationApprovalModal
          result={pendingRemediation}
          approvalGate={resolvedApprovalGate}
          onCancel={handleCancelRemediationGate}
          onConfirm={handleConfirmRemediationGate}
        />
      )}
    </div>
  );
}

function RemediationApprovalModal(props: {
  result: AuditResult;
  approvalGate: GuardApprovalGatePublicConfig | null;
  onCancel: () => void;
  onConfirm: (credentials: { approval_password?: string; approval_totp_code?: string }) => void;
}) {
  const { approvalGate, onCancel, onConfirm, result } = props;
  return (
    <ApprovalProofModal
      title={result.remediationAction?.label ?? "Run remediation"}
      detail="Enter local approval proof before Guard changes package-manager protection on this device."
      confirmLabel="Run remediation"
      approvalGate={approvalGate}
      onCancel={onCancel}
      onConfirm={onConfirm}
    />
  );
}
