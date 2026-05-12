import type { GuardReceipt } from "../guard-types";
import { detectCategory } from "./categories";
import { harnessDisplayName } from "../approval-center-utils";

export interface EvidenceMetrics {
  total: number;
  allowed: number;
  blocked: number;
  reviewed: number;
  byHarness: Map<string, { total: number; blocked: number; allowed: number }>;
  byCategory: Map<string, { total: number; blocked: number }>;
  trendBuckets: TrendBucket[];
  topRecurring: RecurringAction[];
  insights: EvidenceInsightData[];
  lastActivityAt: string | null;
}

export interface TrendBucket {
  label: string;
  dateKey: string;
  allowed: number;
  blocked: number;
  reviewed: number;
}

export interface RecurringAction {
  name: string;
  total: number;
  blocked: number;
  allowed: number;
}

export interface EvidenceInsightData {
  id: string;
  label: string;
  value: string;
  tone: "blue" | "green" | "purple" | "attention";
  filterKey?: string;
  filterValue?: string;
}

function formatDateKey(date: Date): string {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
}

function shortDateLabel(date: Date): string {
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

export function computeTrendBuckets(
  receipts: GuardReceipt[],
  days: number,
  now?: Date
): TrendBucket[] {
  const base = now ?? new Date();
  const startOfToday = new Date(
    base.getFullYear(),
    base.getMonth(),
    base.getDate()
  );

  const buckets: TrendBucket[] = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(startOfToday);
    d.setDate(d.getDate() - i);
    buckets.push({
      label: shortDateLabel(d),
      dateKey: formatDateKey(d),
      allowed: 0,
      blocked: 0,
      reviewed: 0,
    });
  }

  const bucketMap = new Map(buckets.map((b) => [b.dateKey, b]));

  for (const r of receipts) {
    try {
      const d = new Date(r.timestamp);
      const key = formatDateKey(d);
      const bucket = bucketMap.get(key);
      if (!bucket) continue;
      if (r.policy_decision === "allow") bucket.allowed++;
      else if (r.policy_decision === "block") bucket.blocked++;
      else bucket.reviewed++;
    } catch {
      // skip malformed timestamps
    }
  }

  return buckets;
}

export function computeMetrics(
  receipts: GuardReceipt[],
  now?: Date
): EvidenceMetrics {
  let allowed = 0;
  let blocked = 0;
  let reviewed = 0;
  let lastActivityAt: string | null = null;

  const byHarness = new Map<
    string,
    { total: number; blocked: number; allowed: number }
  >();
  const byCategory = new Map<string, { total: number; blocked: number }>();
  const recurringMap = new Map<
    string,
    { total: number; blocked: number; allowed: number }
  >();

  for (const r of receipts) {
    try {
      new Date(r.timestamp).toISOString();
    } catch {
      continue;
    }

    if (r.policy_decision === "allow") allowed++;
    else if (r.policy_decision === "block") blocked++;
    else reviewed++;

    if (!lastActivityAt || r.timestamp > lastActivityAt) {
      lastActivityAt = r.timestamp;
    }

    const harness = r.harness;
    const hEntry = byHarness.get(harness) ?? {
      total: 0,
      blocked: 0,
      allowed: 0,
    };
    hEntry.total++;
    if (r.policy_decision === "block") hEntry.blocked++;
    if (r.policy_decision === "allow") hEntry.allowed++;
    byHarness.set(harness, hEntry);

    const cat = detectCategory(r);
    const cEntry = byCategory.get(cat) ?? { total: 0, blocked: 0 };
    cEntry.total++;
    if (r.policy_decision === "block") cEntry.blocked++;
    byCategory.set(cat, cEntry);

    const name = r.artifact_name ?? r.artifact_id;
    const rEntry = recurringMap.get(name) ?? {
      total: 0,
      blocked: 0,
      allowed: 0,
    };
    rEntry.total++;
    if (r.policy_decision === "block") rEntry.blocked++;
    if (r.policy_decision === "allow") rEntry.allowed++;
    recurringMap.set(name, rEntry);
  }

  const total = allowed + blocked + reviewed;

  const topRecurring: RecurringAction[] = Array.from(recurringMap.entries())
    .map(([name, counts]) => ({ name, ...counts }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 10);

  const trendBuckets = computeTrendBuckets(receipts, 7, now);

  const insights: EvidenceInsightData[] = buildInsights(
    total,
    allowed,
    blocked,
    byHarness,
    byCategory
  );

  return {
    total,
    allowed,
    blocked,
    reviewed,
    byHarness,
    byCategory,
    trendBuckets,
    topRecurring,
    insights,
    lastActivityAt,
  };
}

function buildInsights(
  total: number,
  allowed: number,
  blocked: number,
  byHarness: Map<string, { total: number; blocked: number; allowed: number }>,
  byCategory: Map<string, { total: number; blocked: number }>
): EvidenceInsightData[] {
  const insights: EvidenceInsightData[] = [];

  insights.push({
    id: "total",
    label: "Total actions",
    value: String(total),
    tone: "blue",
  });

  if (blocked > 0) {
    insights.push({
      id: "blocked",
      label: "Stopped",
      value: String(blocked),
      tone: "attention",
      filterKey: "decision",
      filterValue: "block",
    });
  }

  if (allowed > 0) {
    insights.push({
      id: "allowed",
      label: "Allowed",
      value: String(allowed),
      tone: "green",
      filterKey: "decision",
      filterValue: "allow",
    });
  }

  const topHarness = Array.from(byHarness.entries()).sort(
    (a, b) => b[1].total - a[1].total
  )[0];
  if (topHarness) {
    insights.push({
      id: "top-app",
      label: "Most active app",
      value: harnessDisplayName(topHarness[0]),
      tone: "purple",
      filterKey: "harness",
      filterValue: topHarness[0],
    });
  }

  const topCat = Array.from(byCategory.entries()).sort(
    (a, b) => b[1].total - a[1].total
  )[0];
  if (topCat) {
    insights.push({
      id: "top-category",
      label: "Top category",
      value: topCat[0],
      tone: "blue",
      filterKey: "category",
      filterValue: topCat[0],
    });
  }

  return insights;
}

export function metricsSummaryText(metrics: EvidenceMetrics): string {
  const { total, blocked, allowed } = metrics;
  if (total === 0) return "No evidence recorded yet.";
  const stoppedPct =
    total > 0 ? Math.round((blocked / total) * 100) : 0;
  return `${total} actions total — ${allowed} allowed, ${blocked} stopped (${stoppedPct}%).`;
}
