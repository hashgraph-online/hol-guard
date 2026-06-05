import { useState, useCallback, useMemo } from "react";
import type { ChangeEvent } from "react";
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
} from "react-icons/hi2";
import { SectionLabel, Badge, Tag, ActionButton, EmptyState } from "./approval-center-primitives";
import { formatRelativeTime, harnessDisplayName } from "./approval-center-utils";
import { GuardHarnessActionError, runAuditRemediation } from "./guard-api";
import type { AuditRemediationAction } from "./guard-api";
import type { GuardApprovalGatePublicConfig, GuardReceipt, GuardRuntimeSnapshot } from "./guard-types";

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
};

export type AuditRemediationRequest = {
  action: AuditRemediationAction;
  manager: string;
  label: string;
};

export type AuditFilterState = {
  severityFilter: AuditSeverity | "all";
  harnessFilter: string;
  resolvedFilter: "all" | "open" | "resolved";
  searchQuery: string;
};

export function deriveFrontendAuditResults(
  receipts: GuardReceipt[],
  snapshot: GuardRuntimeSnapshot,
): AuditResult[] {
  const results: AuditResult[] = [];

  const protection = snapshot.supply_chain?.package_manager_protection;
  if (protection && protection.unprotected_managers.length > 0) {
    for (const mgr of protection.unprotected_managers) {
      results.push({
        id: `unprotected-${mgr}`,
        severity: "high",
        title: `${mgr} is not intercepted by Guard`,
        detail: `The ${mgr} shim is missing from PATH. Installs via ${mgr} bypass Guard's supply chain protection.`,
        harness: "global",
        workspace: null,
        timestamp: snapshot.generated_at,
        remediation: `Add ${protection.shim_dir} to PATH and restart your shell. Then run hol-guard supply-chain verify.`,
        remediationAction: {
          action: "package_shim_path",
          manager: mgr,
          label: `Install Guard for ${mgr}`,
        },
        resolved: false,
      });
    }
  }

  const blockedReceipts = receipts.filter((r) => r.policy_decision === "block");
  for (const r of blockedReceipts.slice(0, 20)) {
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
  const handleRunRemediation = useCallback(() => onRunRemediation(result), [onRunRemediation, result]);

  return (
    <div className={`border-b border-slate-100 last:border-b-0 ${result.resolved ? "opacity-60" : ""}`}>
      <button
        type="button"
        onClick={toggle}
        aria-expanded={expanded}
        className="flex w-full items-start gap-3 px-4 py-3 text-left hover:bg-slate-50/60 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-brand-blue/30"
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
      {expanded && (
        <div className="border-t border-slate-100 bg-slate-50/40 px-4 py-3 space-y-3">
          <p className="text-sm text-brand-dark/80">{result.detail}</p>
          {result.remediation && (
            <div className="rounded-lg border border-brand-blue/15 bg-brand-blue/[0.04] px-3 py-2.5">
              <p className="text-xs font-semibold uppercase tracking-[0.15em] text-brand-blue mb-1">
                Remediation
              </p>
              <p className="text-sm text-brand-dark/80">{result.remediation}</p>
              {result.remediationAction && (
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <ActionButton onClick={handleRunRemediation} disabled={running}>
                    <HiMiniWrenchScrewdriver className="mr-1.5 h-4 w-4" aria-hidden="true" />
                    {running ? "Running..." : result.remediationAction.label}
                  </ActionButton>
                </div>
              )}
              {actionMessage !== null && (
                <p className="mt-2 text-xs text-slate-500">{actionMessage}</p>
              )}
            </div>
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

type AuditWorkspaceProps = {
  snapshot: GuardRuntimeSnapshot;
  receipts: GuardReceipt[];
  approvalGate: GuardApprovalGatePublicConfig | null;
};

export function AuditWorkspace({ snapshot, receipts, approvalGate }: AuditWorkspaceProps) {
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
        if (
          credentials === undefined &&
          error instanceof GuardHarnessActionError &&
          error.payload?.error === "approval_gate_required" &&
          approvalGate?.enabled === true &&
          approvalGate.configured === true
        ) {
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
    [approvalGate],
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
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold text-brand-dark">Audit</h1>
          <p className="mt-0.5 text-sm text-slate-500">
            Workspace audit results, open issues, and remediation queue.
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

      {openCount > 0 && (
        <RemediationQueue
          results={baseResults
            .map((r) => ({ ...r, resolved: r.resolved || resolvedIds.has(r.id) }))
            .filter((r) => !r.resolved && (r.severity === "critical" || r.severity === "high"))}
          onMarkResolved={handleMarkResolved}
          onRunRemediation={handleRunRemediation}
          runningRemediationId={runningRemediationId}
          remediationMessages={remediationMessages}
        />
      )}
      {pendingRemediation !== null && (
        <RemediationApprovalModal
          result={pendingRemediation}
          approvalGate={approvalGate}
          onCancel={handleCancelRemediationGate}
          onConfirm={handleConfirmRemediationGate}
        />
      )}
    </div>
  );
}

type RemediationQueueProps = {
  results: AuditResult[];
  onMarkResolved: (id: string) => void;
  onRunRemediation: (result: AuditResult) => void;
  runningRemediationId: string | null;
  remediationMessages: Record<string, string>;
};

function RemediationQueue({
  results,
  onMarkResolved,
  onRunRemediation,
  runningRemediationId,
  remediationMessages,
}: RemediationQueueProps) {
  if (results.length === 0) return null;
  return (
    <div className="rounded-2xl border border-red-100 bg-red-50/40 shadow-sm">
      <div className="border-b border-red-100 px-4 py-3">
        <SectionLabel>Remediation queue</SectionLabel>
        <p className="mt-1 text-sm text-slate-500">
          Critical and high severity issues that need attention.
        </p>
      </div>
      <div className="divide-y divide-red-100">
        {results.map((r) => (
          <div key={r.id} className="px-4 py-3 space-y-2">
            <div className="flex items-start justify-between gap-3">
              <div className="space-y-0.5 min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-semibold text-brand-dark">{r.title}</span>
                  <Badge tone={r.severity === "critical" ? "destructive" : "attention"}>
                    {r.severity}
                  </Badge>
                </div>
                {r.remediation && (
                  <p className="text-sm text-slate-600">{r.remediation}</p>
                )}
              </div>
              <RemediationQueueActions
                result={r}
                onMarkResolved={onMarkResolved}
                onRunRemediation={onRunRemediation}
                running={runningRemediationId === r.id}
              />
            </div>
            {remediationMessages[r.id] && (
              <p className="text-xs text-slate-500">{remediationMessages[r.id]}</p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function RemediationQueueActions(props: {
  result: AuditResult;
  onMarkResolved: (id: string) => void;
  onRunRemediation: (result: AuditResult) => void;
  running: boolean;
}) {
  const { result, onMarkResolved, onRunRemediation, running } = props;
  const handleMarkResolved = useCallback(() => onMarkResolved(result.id), [onMarkResolved, result.id]);
  const handleRunRemediation = useCallback(() => onRunRemediation(result), [onRunRemediation, result]);
  if (result.remediationAction !== null) {
    return (
      <ActionButton onClick={handleRunRemediation} disabled={running}>
        <HiMiniWrenchScrewdriver className="mr-1.5 h-4 w-4" aria-hidden="true" />
        {running ? "Running..." : result.remediationAction.label}
      </ActionButton>
    );
  }
  return (
    <ActionButton variant="outline" onClick={handleMarkResolved}>
      Resolve
    </ActionButton>
  );
}

function RemediationApprovalModal(props: {
  result: AuditResult;
  approvalGate: GuardApprovalGatePublicConfig | null;
  onCancel: () => void;
  onConfirm: (credentials: { approval_password?: string; approval_totp_code?: string }) => void;
}) {
  const { approvalGate, onCancel, onConfirm, result } = props;
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const handlePasswordChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setPassword(event.target.value);
  }, []);
  const handleTotpChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setTotpCode(event.target.value);
  }, []);
  const handleConfirm = useCallback(() => {
    onConfirm({
      approval_password: password,
      ...(approvalGate?.totp_enabled === true ? { approval_totp_code: totpCode } : {}),
    });
  }, [approvalGate, onConfirm, password, totpCode]);
  const confirmDisabled = password.trim() === "" || (approvalGate?.totp_enabled === true && totpCode.trim() === "");
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/40 px-4">
      <div className="w-full max-w-md rounded-xl border border-slate-200 bg-white p-5 shadow-xl">
        <SectionLabel>Approval required</SectionLabel>
        <h2 className="mt-2 text-base font-semibold text-brand-dark">{result.remediationAction?.label}</h2>
        <p className="mt-1 text-sm text-slate-500">
          Enter local approval proof before Guard changes package-manager protection on this device.
        </p>
        <label className="mt-4 block">
          <span className="text-xs font-semibold uppercase tracking-[0.15em] text-slate-500">Approval password</span>
          <input
            type="password"
            value={password}
            onChange={handlePasswordChange}
            autoComplete="current-password"
            className="mt-1 min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          />
        </label>
        {approvalGate?.totp_enabled === true && (
          <label className="mt-3 block">
            <span className="text-xs font-semibold uppercase tracking-[0.15em] text-slate-500">Authenticator code</span>
            <input
              type="text"
              inputMode="numeric"
              pattern="[0-9]*"
              value={totpCode}
              onChange={handleTotpChange}
              className="mt-1 min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
            />
          </label>
        )}
        <div className="mt-5 flex justify-end gap-2">
          <ActionButton variant="outline" onClick={onCancel}>
            Cancel
          </ActionButton>
          <ActionButton onClick={handleConfirm} disabled={confirmDisabled}>
            Run remediation
          </ActionButton>
        </div>
      </div>
    </div>
  );
}
