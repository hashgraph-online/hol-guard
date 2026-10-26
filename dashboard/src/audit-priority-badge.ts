import type { AuditResult } from "./audit-workspace";

/**
 * The header badge counts open critical and high results, so it must not call
 * them all critical: the Critical filter would then show fewer rows.
 */
export function auditPriorityBadgeLabel(
  results: readonly AuditResult[],
  resolvedIds: ReadonlySet<string>,
): string | null {
  const count = results.filter(
    (r) => (r.severity === "critical" || r.severity === "high") && !r.resolved && !resolvedIds.has(r.id),
  ).length;
  return count > 0 ? `${count} high priority` : null;
}
