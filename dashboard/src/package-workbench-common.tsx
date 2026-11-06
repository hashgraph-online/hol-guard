import { useCallback } from "react";
import { HiMiniChevronLeft, HiMiniChevronRight } from "react-icons/hi2";
import { SectionLabel, Tag, ActionButton } from "./approval-center-primitives";
import { formatRelativeTime } from "./approval-center-utils";
import type {
  SupplyChainAuditDecision,
  SupplyChainAuditSeverity,
  SupplyChainAuditSnapshot,
} from "./guard-types";

export const decisionTone = (
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

export const severityTone = (
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
  flaggedCount: number;
  packageCount: number;
  cloudState?: string | null;
};

function cloudIntelLabel(cloudState: string | null | undefined, source: string | null): string {
  if (cloudState === "local_only") {
    return "Local intel only";
  }
  if (source !== null && source.length > 0) {
    return `${source} intel`;
  }
  return "Guard Cloud";
}

function cloudIntelTone(cloudState: string | null | undefined): "attention" | "green" | "info" {
  if (cloudState === "local_only") {
    return "attention";
  }
  if (cloudState === "paired_active") {
    return "green";
  }
  return "info";
}

export function WorkbenchHeader({
  auditSnapshot,
  flaggedCount,
  packageCount,
  cloudState,
}: WorkbenchHeaderProps) {
  const manifestSummary =
    auditSnapshot.manifestPaths.length > 0
      ? `${auditSnapshot.manifestPaths.length} manifest${auditSnapshot.manifestPaths.length === 1 ? "" : "s"}`
      : null;
  const lockfileSummary =
    auditSnapshot.lockfilePaths.length > 0
      ? `${auditSnapshot.lockfilePaths.length} lockfile${auditSnapshot.lockfilePaths.length === 1 ? "" : "s"}`
      : null;
  const scanSummary = [manifestSummary, lockfileSummary].filter((entry) => entry !== null).join(" · ");

  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
        <Tag tone={decisionTone(auditSnapshot.decision)}>{auditSnapshot.decision}</Tag>
        <Tag tone={cloudIntelTone(cloudState)}>{cloudIntelLabel(cloudState, auditSnapshot.source)}</Tag>
        <span>
          {auditSnapshot.inventory.totalPackages} package
          {auditSnapshot.inventory.totalPackages === 1 ? "" : "s"} indexed
        </span>
        <span aria-hidden="true">·</span>
        <span>{packageCount} in table</span>
        <span aria-hidden="true">·</span>
        <span>{flaggedCount} need review</span>
        <span aria-hidden="true">·</span>
        <span>Last audit {formatRelativeTime(auditSnapshot.generatedAt)}</span>
      </div>
      {scanSummary.length > 0 ? (
        <p className="text-[11px] text-slate-400">Scanned {scanSummary} across this workspace.</p>
      ) : null}
    </div>
  );
}

type WorkbenchPaginationProps = {
  page: number;
  pageCount: number;
  total: number;
  onPageChange: (page: number) => void;
};

export function WorkbenchPagination({ page, pageCount, total, onPageChange }: WorkbenchPaginationProps) {
  const handlePrevious = useCallback(() => {
    onPageChange(Math.max(0, page - 1));
  }, [onPageChange, page]);
  const handleNext = useCallback(() => {
    onPageChange(Math.min(pageCount - 1, page + 1));
  }, [onPageChange, page, pageCount]);

  if (pageCount <= 1) {
    return (
      <p className="text-xs text-slate-500">
        Showing {total} finding{total === 1 ? "" : "s"}
      </p>
    );
  }

  return (
    <div className="flex flex-wrap items-center justify-between gap-2">
      <p className="text-xs text-slate-500">
        Page {page + 1} of {pageCount} · {total} finding{total === 1 ? "" : "s"}
      </p>
      <div className="flex items-center gap-1">
        <ActionButton variant="outline" onClick={handlePrevious} disabled={page === 0}>
          <HiMiniChevronLeft className="h-4 w-4" aria-hidden="true" />
          Previous
        </ActionButton>
        <ActionButton variant="outline" onClick={handleNext} disabled={page >= pageCount - 1}>
          Next
          <HiMiniChevronRight className="h-4 w-4" aria-hidden="true" />
        </ActionButton>
      </div>
    </div>
  );
}
