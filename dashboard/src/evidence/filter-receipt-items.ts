import { normalizeHarnessFilter } from "../approval-center-utils";
import { guardActionDisposition } from "../guard-action";
import type { GuardReceipt } from "../guard-types";

export function filterReceiptItems(
  items: GuardReceipt[],
  searchTerm: string,
  harnessFilter: string,
  decisionFilter: string,
  dateRange: string
): GuardReceipt[] {
  const normalizedSearchTerm = searchTerm.trim().toLowerCase();
  const activeHarnessFilter = normalizeHarnessFilter(harnessFilter);
  const now = Date.now();
  const todayStart = new Date();
  todayStart.setHours(0, 0, 0, 0);
  const todayStartMs = todayStart.getTime();
  const last7Start = now - 7 * 24 * 60 * 60 * 1000;
  return items.filter((receipt) => {
    const matchesHarness = activeHarnessFilter === "all" || receipt.harness === activeHarnessFilter;
    const disposition = guardActionDisposition(receipt.policy_decision);
    const matchesDecision =
      decisionFilter === "all" ||
      (decisionFilter === "allow" && disposition === "allowed") ||
      ((decisionFilter === "ask" || decisionFilter === "review") && disposition === "reviewed") ||
      (decisionFilter === "block" && disposition === "blocked") ||
      receipt.policy_decision === decisionFilter;
    if (!matchesHarness || !matchesDecision) {
      return false;
    }
    if (dateRange === "today" || dateRange === "last7") {
      const ts = new Date(receipt.timestamp).getTime();
      if (dateRange === "today" && ts < todayStartMs) {
        return false;
      } else if (dateRange === "last7" && ts < last7Start) {
        return false;
      }
    }
    if (normalizedSearchTerm.length === 0) {
      return true;
    }
    const name = (receipt.artifact_name ?? receipt.artifact_id).toLowerCase();
    return name.includes(normalizedSearchTerm);
  });
}
