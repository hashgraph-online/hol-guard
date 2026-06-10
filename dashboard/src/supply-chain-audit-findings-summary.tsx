import { useMemo } from "react";
import { HiMiniBugAnt, HiMiniExclamationTriangle } from "react-icons/hi2";
import { SectionLabel, Tag, EmptyState, ActionButton } from "./approval-center-primitives";
import { formatRelativeTime } from "./approval-center-utils";
import type { SupplyChainAuditFinding, SupplyChainAuditSnapshot } from "./guard-types";

type SupplyChainAuditFindingsSummaryProps = {
  auditSnapshot: SupplyChainAuditSnapshot | null;
  auditRunning: boolean;
  onRunAudit?: () => void;
};

const decisionPriority: Record<string, number> = {
  block: 0,
  ask: 1,
  warn: 2,
  monitor: 3,
  allow: 4,
};

const severityPriority: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
};

function sortFindings(findings: SupplyChainAuditFinding[]): SupplyChainAuditFinding[] {
  return [...findings].sort((left, right) => {
    const decisionDelta =
      (decisionPriority[left.decision] ?? 9) - (decisionPriority[right.decision] ?? 9);
    if (decisionDelta !== 0) {
      return decisionDelta;
    }
    return (severityPriority[left.severity] ?? 9) - (severityPriority[right.severity] ?? 9);
  });
}

function countByDecision(findings: SupplyChainAuditFinding[]): {
  block: number;
  warn: number;
  ask: number;
} {
  return findings.reduce(
    (counts, finding) => {
      if (finding.decision === "block") {
        counts.block += 1;
      } else if (finding.decision === "warn") {
        counts.warn += 1;
      } else if (finding.decision === "ask") {
        counts.ask += 1;
      }
      return counts;
    },
    { block: 0, warn: 0, ask: 0 },
  );
}

type FindingSummaryRowProps = {
  finding: SupplyChainAuditFinding;
};

function FindingSummaryRow({ finding }: FindingSummaryRowProps) {
  const tone =
    finding.decision === "block"
      ? "destructive"
      : finding.decision === "ask"
      ? "attention"
      : finding.decision === "warn"
      ? "warning"
      : "default";

  return (
    <div className="flex min-w-0 items-center justify-between gap-3 border-b border-slate-100 px-4 py-2.5 last:border-b-0">
      <div className="min-w-0">
        <p className="truncate text-sm font-medium text-brand-dark">{finding.packageName}</p>
        <p className="truncate text-xs text-slate-500">{finding.ecosystem}</p>
      </div>
      <div className="flex shrink-0 items-center gap-1.5">
        <Tag tone={tone}>{finding.decision}</Tag>
        <Tag tone="default">{finding.severity}</Tag>
      </div>
    </div>
  );
}

export function SupplyChainAuditFindingsSummary({
  auditSnapshot,
  auditRunning,
  onRunAudit,
}: SupplyChainAuditFindingsSummaryProps) {
  const topFindings = useMemo(() => {
    if (auditSnapshot === null) {
      return [];
    }
    return sortFindings(auditSnapshot.findings).slice(0, 5);
  }, [auditSnapshot]);

  const counts = useMemo(() => {
    if (auditSnapshot === null) {
      return { block: 0, warn: 0, ask: 0 };
    }
    return countByDecision(auditSnapshot.findings);
  }, [auditSnapshot]);

  return (
    <section
      className="overflow-hidden rounded-2xl border border-slate-100 bg-white shadow-sm"
      aria-label="Local audit findings"
      data-testid="supply-chain-audit-findings"
    >
      <div className="border-b border-slate-100 px-4 py-3">
        <SectionLabel>Audit findings</SectionLabel>
        <p className="mt-1 text-sm leading-relaxed text-slate-500">
          Packages flagged the last time Guard audited this workspace.
        </p>
        {auditSnapshot !== null ? (
          <p className="mt-2 text-xs text-slate-500">
            Last audit {formatRelativeTime(auditSnapshot.generatedAt)}
            {auditSnapshot.source !== null ? ` · ${auditSnapshot.source} intel` : ""}
          </p>
        ) : null}
      </div>

      {auditSnapshot === null ? (
        <div className="px-4 py-4">
          <EmptyState
            title={auditRunning ? "Audit running" : "No audit findings yet"}
            body={
              auditRunning
                ? "Guard is scanning installed packages on this device."
                : "Run an audit from the firewall panel to see package risks here."
            }
            tone="teach"
            action={
              auditRunning || onRunAudit === undefined ? undefined : (
                <ActionButton variant="primary" onClick={onRunAudit}>
                  Run audit
                </ActionButton>
              )
            }
          />
        </div>
      ) : topFindings.length === 0 ? (
        <div className="px-4 py-4">
          <EmptyState
            title="No risky packages found"
            body="The last audit did not flag packages that need action on this device."
          />
        </div>
      ) : (
        <>
          <div className="flex flex-wrap gap-2 border-b border-slate-100 px-4 py-3">
            {counts.block > 0 ? (
              <Tag tone="destructive">
                <HiMiniExclamationTriangle className="mr-1 inline h-3.5 w-3.5" aria-hidden="true" />
                {counts.block} block
              </Tag>
            ) : null}
            {counts.ask > 0 ? <Tag tone="attention">{counts.ask} ask</Tag> : null}
            {counts.warn > 0 ? <Tag tone="warning">{counts.warn} warn</Tag> : null}
            <Tag tone="default">
              <HiMiniBugAnt className="mr-1 inline h-3.5 w-3.5" aria-hidden="true" />
              {auditSnapshot.findings.length} total
            </Tag>
          </div>
          <div>{topFindings.map((finding) => <FindingSummaryRow key={finding.id} finding={finding} />)}</div>
        </>
      )}
    </section>
  );
}
