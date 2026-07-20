import type { GuardReceipt } from "../guard-types";
import type { EvidenceFilterState } from "./evidence-types";
import { detectCategory } from "./categories";
import { receiptUtcDateKey } from "./evidence-format";
import { guardActionDisposition } from "../guard-action";

export function filterByTime(
  receipts: GuardReceipt[],
  time: string,
  day: string,
  now?: Date
): GuardReceipt[] {
  const base = now ?? new Date();
  const startOfToday = new Date(base.getFullYear(), base.getMonth(), base.getDate());
  const startOfYesterday = new Date(startOfToday);
  startOfYesterday.setDate(startOfYesterday.getDate() - 1);
  const startOfWeek = new Date(startOfToday);
  startOfWeek.setDate(startOfWeek.getDate() - startOfWeek.getDay());
  const startOfLast7d = new Date(startOfToday);
  startOfLast7d.setDate(startOfLast7d.getDate() - 7);
  const startOfLast30d = new Date(startOfToday);
  startOfLast30d.setDate(startOfLast30d.getDate() - 30);

  if (day) {
    return receipts.filter((r) => receiptUtcDateKey(r.timestamp) === day);
  }

  if (time === "all") return receipts;

  return receipts.filter((r) => {
    const d = new Date(r.timestamp);
    if (time === "today") return d >= startOfToday;
    if (time === "yesterday") return d >= startOfYesterday && d < startOfToday;
    if (time === "week") return d >= startOfWeek;
    if (time === "last7d") return d >= startOfLast7d;
    if (time === "last30d") return d >= startOfLast30d;
    return true;
  });
}

export function filterByDecision(
  receipts: GuardReceipt[],
  decision: string
): GuardReceipt[] {
  if (decision === "all") return receipts;
  if (decision === "allow") {
    return receipts.filter((r) => guardActionDisposition(r.policy_decision) === "allowed");
  }
  if (decision === "block") {
    return receipts.filter((r) => guardActionDisposition(r.policy_decision) === "blocked");
  }
  if (decision === "ask") {
    return receipts.filter((r) => guardActionDisposition(r.policy_decision) === "reviewed");
  }
  return receipts.filter((r) => r.policy_decision === decision);
}

export function filterByHarness(
  receipts: GuardReceipt[],
  harness: string
): GuardReceipt[] {
  if (harness === "all") return receipts;
  return receipts.filter((r) => r.harness === harness);
}

export function filterByCategory(
  receipts: GuardReceipt[],
  category: string
): GuardReceipt[] {
  if (!category) return receipts;
  return receipts.filter((r) => detectCategory(r) === category);
}

export function filterBySearch(
  receipts: GuardReceipt[],
  search: string
): GuardReceipt[] {
  const q = search.trim().toLowerCase();
  if (!q) return receipts;
  return receipts.filter((r) => {
    const name = (r.artifact_name ?? r.artifact_id ?? "").toLowerCase();
    const id = r.artifact_id.toLowerCase();
    const receiptId = r.receipt_id.toLowerCase();
    const harness = r.harness.toLowerCase();
    const caps = (r.capabilities_summary ?? "").toLowerCase();
    const changed = (r.changed_capabilities ?? []).join(" ").toLowerCase();
    const provenance = (r.provenance_summary ?? "").toLowerCase();
    const scope = (r.source_scope ?? "").toLowerCase();
    const decision = (r.policy_decision ?? "").toLowerCase();
    const hashRaw = (r.artifact_hash ?? "").toLowerCase();
    const hashNormalized = hashRaw.replace(/^sha256:/, "");
    return (
      name.includes(q) ||
      id.includes(q) ||
      receiptId.includes(q) ||
      harness.includes(q) ||
      caps.includes(q) ||
      changed.includes(q) ||
      provenance.includes(q) ||
      scope.includes(q) ||
      decision.includes(q) ||
      hashRaw.startsWith(q) ||
      hashNormalized.includes(q)
    );
  });
}

export function filterBySourceScope(
  receipts: GuardReceipt[],
  sourceScope: string
): GuardReceipt[] {
  if (!sourceScope) return receipts;
  return receipts.filter((r) => r.source_scope === sourceScope);
}

export function filterEvidence(
  receipts: GuardReceipt[],
  filters: EvidenceFilterState,
  now?: Date
): GuardReceipt[] {
  let items = receipts;
  items = filterByDecision(items, filters.decision);
  items = filterByHarness(items, filters.harness);
  items = filterByCategory(items, filters.category);
  items = filterBySourceScope(items, filters.sourceScope);
  items = filterByTime(items, filters.time, filters.day, now);
  items = filterBySearch(items, filters.search);
  return items;
}
