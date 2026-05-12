import { useCallback, useMemo, useState } from "react";
import {
  HiMiniChevronLeft,
  HiMiniChevronRight,
  HiOutlineArrowTrendingDown,
  HiOutlineArrowTrendingUp,
  HiOutlineFire,
  HiOutlineShieldCheck,
  HiOutlineNoSymbol,
  HiMiniChevronDown,
  HiMiniChevronUp,
} from "react-icons/hi2";

import type { GuardReceipt } from "./guard-types";
import { harnessDisplayName } from "./approval-center-utils";
import { detectCategory } from "./evidence/categories";

// ──────────────────────────────────────────
// Types
// ──────────────────────────────────────────

type TimePeriod = "7d" | "30d" | "90d" | "all";

interface InsightCard {
  id: string;
  icon: React.ReactNode;
  label: string;
  value: string;
  tone: "blue" | "green" | "purple" | "attention";
  action?: { label: string; onClick: () => void };
}

// ──────────────────────────────────────────
// Insights
// ──────────────────────────────────────────

export function HistoryInsights({
  receipts,
  onFilterHarness,
  onFilterDay,
}: {
  receipts: GuardReceipt[];
  onFilterHarness?: (harness: string) => void;
  onFilterDay?: (date: string) => void;
}) {
  const [showAll, setShowAll] = useState(false);
  const insights = useMemo(() => {
    return computeInsights(receipts, onFilterHarness, onFilterDay);
  }, [receipts, onFilterHarness, onFilterDay]);

  if (insights.length === 0) {
    return (
      <div className="rounded-xl border border-slate-100 bg-white p-4 text-center">
        <p className="text-sm text-slate-500">No insights yet.</p>
        <p className="mt-1 text-xs text-slate-400">More activity will reveal patterns.</p>
      </div>
    );
  }

  const visible = showAll ? insights : insights.slice(0, 3);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-brand-dark">Insights</h3>
        {insights.length > 3 && (
          <button
            onClick={() => setShowAll((v) => !v)}
            className="flex items-center gap-1 text-xs font-medium text-brand-blue transition-colors hover:text-brand-dark"
          >
            {showAll ? (
              <>
                <HiMiniChevronUp className="h-3 w-3" aria-hidden="true" />
                Show less
              </>
            ) : (
              <>
                <HiMiniChevronDown className="h-3 w-3" aria-hidden="true" />
                Show all ({insights.length})
              </>
            )}
          </button>
        )}
      </div>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {visible.map((insight) => (
          <InsightCardComponent key={insight.id} insight={insight} />
        ))}
      </div>
    </div>
  );
}

function InsightCardComponent({
  insight,
}: {
  insight: InsightCard;
}) {
  const toneClasses = {
    blue: "bg-blue-50/60 border-blue-200/40 text-blue-700",
    green: "bg-emerald-50/60 border-emerald-200/40 text-emerald-700",
    purple: "bg-purple-50/60 border-purple-200/40 text-purple-700",
    attention: "bg-amber-50/60 border-amber-200/40 text-amber-700",
  };

  return (
    <div
      className={`rounded-xl border p-3 transition-colors hover:bg-opacity-80 ${toneClasses[insight.tone]}`}
    >
      <div className="flex items-start gap-2.5">
        <div className="mt-0.5 shrink-0 opacity-70">{insight.icon}</div>
        <div className="min-w-0 flex-1">
          <p className="text-xs opacity-80">{insight.label}</p>
          <p className="mt-0.5 text-sm font-semibold">{insight.value}</p>
          {insight.action && (
            <button
              onClick={insight.action.onClick}
              className="mt-1 text-xs underline opacity-70 transition-opacity hover:opacity-100"
            >
              {insight.action.label}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function computeInsights(
  receipts: GuardReceipt[],
  onFilterHarness?: (harness: string) => void,
  onFilterDay?: (date: string) => void
): InsightCard[] {
  const now = new Date();
  const weekAgo = new Date(now);
  weekAgo.setDate(weekAgo.getDate() - 7);
  const monthAgo = new Date(now);
  monthAgo.setDate(monthAgo.getDate() - 30);

  const weekReceipts = receipts.filter((r) => new Date(r.timestamp) >= weekAgo);
  const monthReceipts = receipts.filter((r) => new Date(r.timestamp) >= monthAgo);

  const insights: InsightCard[] = [];

  // Most blocked action this week
  const blockedWeek = weekReceipts.filter((r) => r.policy_decision === "block");
  if (blockedWeek.length > 0) {
    const topBlocked = aggregateByAction(blockedWeek)[0];
    if (topBlocked) {
      insights.push({
        id: "top-blocked-week",
        icon: <HiOutlineNoSymbol className="h-4 w-4" />,
        label: "Most blocked this week",
        value: topBlocked.name,
        tone: "attention",
      });
    }
  }

  // App with most activity
  const appActivity = new Map<string, number>();
  for (const r of weekReceipts) {
    appActivity.set(r.harness, (appActivity.get(r.harness) ?? 0) + 1);
  }
  const topApp = Array.from(appActivity.entries()).sort((a, b) => b[1] - a[1])[0];
  if (topApp) {
    insights.push({
      id: "top-app-week",
      icon: <HiOutlineFire className="h-4 w-4" />,
      label: "Most active app",
      value: harnessDisplayName(topApp[0]),
      tone: "purple",
      action: {
        label: "Filter",
        onClick: () => onFilterHarness?.(topApp[0]),
      },
    });
  }

  // Block rate
  if (weekReceipts.length >= 5) {
    const blockRate = Math.round((blockedWeek.length / weekReceipts.length) * 100);
    const prevWeekStart = new Date(weekAgo);
    prevWeekStart.setDate(prevWeekStart.getDate() - 7);
    const prevWeekReceipts = receipts.filter((r) => {
      const d = new Date(r.timestamp);
      return d >= prevWeekStart && d < weekAgo;
    });
    const prevBlockedCount = prevWeekReceipts.filter((r) => r.policy_decision === "block").length;
    const hasPrevWeek = prevWeekReceipts.length > 0;
    const prevBlockRate = hasPrevWeek
      ? Math.round((prevBlockedCount / prevWeekReceipts.length) * 100)
      : 0;
    const change = hasPrevWeek ? blockRate - prevBlockRate : 0;
    const value = !hasPrevWeek
      ? `${blockRate}%`
      : change === 0
        ? `${blockRate}% (flat)`
        : `${blockRate}% (${change > 0 ? "+" : ""}${change}%)`;
    insights.push({
      id: "block-rate",
      icon: !hasPrevWeek || change === 0
        ? <HiOutlineArrowTrendingUp className="h-4 w-4" />
        : change > 0
          ? <HiOutlineArrowTrendingUp className="h-4 w-4" />
          : <HiOutlineArrowTrendingDown className="h-4 w-4" />,
      label: "Block rate this week",
      value,
      tone: change > 0 ? "attention" : "green",
    });
  }

  // Secret reads stopped
  const secretReads = monthReceipts.filter((r) => {
    const name = (r.artifact_name ?? "").toLowerCase();
    return /\.env(\.[a-z]+)?$/.test(name) ||
      /\.(secrets?|key|token|password|credential)/i.test(name) ||
      (r.capabilities_summary ?? "").toLowerCase().includes("secret");
  });
  if (secretReads.length > 0) {
    insights.push({
      id: "secret-reads",
      icon: <HiOutlineShieldCheck className="h-4 w-4" />,
      label: "Secret reads stopped this month",
      value: String(secretReads.length),
      tone: "blue",
    });
  }

  // New app detected — only show if the app has few total receipts (truly new)
  const harnessFirstSeen = new Map<string, Date>();
  const harnessTotalCount = new Map<string, number>();
  for (const r of receipts) {
    const d = new Date(r.timestamp);
    const existing = harnessFirstSeen.get(r.harness);
    if (!existing || d < existing) {
      harnessFirstSeen.set(r.harness, d);
    }
    harnessTotalCount.set(r.harness, (harnessTotalCount.get(r.harness) ?? 0) + 1);
  }
  for (const [harness, firstSeen] of harnessFirstSeen.entries()) {
    if (firstSeen >= weekAgo && (harnessTotalCount.get(harness) ?? 0) <= 10) {
      insights.push({
        id: `new-app-${harness}`,
        icon: <HiOutlineFire className="h-4 w-4" />,
        label: "New app detected",
        value: harnessDisplayName(harness),
        tone: "purple",
        action: {
          label: "Filter",
          onClick: () => onFilterHarness?.(harness),
        },
      });
    }
  }

  return insights;
}

// ──────────────────────────────────────────
// Activity Calendar
// ──────────────────────────────────────────

export function ActivityCalendar({
  receipts,
  onSelectDay,
}: {
  receipts: GuardReceipt[];
  onSelectDay?: (date: string) => void;
}) {
  const [monthOffset, setMonthOffset] = useState(0);

  const { year, month, days, startOffset } = useMemo(() => {
    const now = new Date();
    const target = new Date(now.getFullYear(), now.getMonth() + monthOffset, 1);
    const y = target.getFullYear();
    const m = target.getMonth();
    const firstDay = new Date(y, m, 1);
    const lastDay = new Date(y, m + 1, 0);
    const so = firstDay.getDay(); // 0 = Sunday
    const totalDays = lastDay.getDate();
    return { year: y, month: m, days: totalDays, startOffset: so };
  }, [monthOffset]);

  const activityByDay = useMemo(() => {
    const map = new Map<string, number>();
    for (const r of receipts) {
      const d = new Date(r.timestamp);
      const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
      map.set(key, (map.get(key) ?? 0) + 1);
    }
    return map;
  }, [receipts]);

  const handlePrevMonth = useCallback(() => setMonthOffset((o) => o - 1), []);
  const handleNextMonth = useCallback(() => setMonthOffset((o) => o + 1), []);
  const handleToday = useCallback(() => setMonthOffset(0), []);

  const monthName = new Date(year, month).toLocaleDateString(undefined, { month: "long", year: "numeric" });
  const weekDays = ["Su", "Mo", "Tu", "We", "Th", "Fr", "Sa"];

  const today = new Date();
  const todayKey = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, "0")}-${String(today.getDate()).padStart(2, "0")}`;

  // Calculate total cells needed: startOffset + days, rounded up to 42 (6 weeks)
  const totalCells = Math.ceil((startOffset + days) / 7) * 7;
  const cells = Math.max(42, totalCells);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-brand-dark">Activity</h3>
        <div className="flex items-center gap-1">
          <button
            onClick={handlePrevMonth}
            className="rounded-md p-1 text-slate-400 transition-colors hover:bg-slate-100 hover:text-brand-dark"
            aria-label="Previous month"
          >
            <HiMiniChevronLeft className="h-4 w-4" aria-hidden="true" />
          </button>
          <span className="min-w-[120px] text-center text-xs font-medium text-brand-dark">{monthName}</span>
          <button
            onClick={handleNextMonth}
            className="rounded-md p-1 text-slate-400 transition-colors hover:bg-slate-100 hover:text-brand-dark"
            aria-label="Next month"
          >
            <HiMiniChevronRight className="h-4 w-4" aria-hidden="true" />
          </button>
          {monthOffset !== 0 && (
            <button
              onClick={handleToday}
              className="ml-1 rounded-md px-2 py-0.5 text-xs font-medium text-brand-blue hover:bg-blue-50"
            >
              Today
            </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-7 gap-1">
        {weekDays.map((d) => (
          <div key={d} className="text-center text-[10px] font-medium text-slate-400">
            {d}
          </div>
        ))}
        {Array.from({ length: cells }, (_, i) => {
          const dayIndex = i - startOffset + 1;
          if (dayIndex < 1 || dayIndex > days) {
            return <div key={i} className="aspect-square" />;
          }
          const dateKey = `${year}-${String(month + 1).padStart(2, "0")}-${String(dayIndex).padStart(2, "0")}`;
          const count = activityByDay.get(dateKey) ?? 0;
          const isToday = dateKey === todayKey;
          const intensity = count === 0 ? 0 : count <= 2 ? 1 : count <= 5 ? 2 : 3;
          const intensityClasses = [
            "bg-white text-slate-300 hover:bg-slate-50",
            "bg-blue-100 text-blue-700 hover:bg-blue-200",
            "bg-blue-300 text-white hover:bg-blue-400",
            "bg-blue-500 text-white hover:bg-blue-600",
          ];
          return (
            <button
              key={i}
              onClick={() => count > 0 && onSelectDay?.(dateKey)}
              disabled={count === 0}
              className={`aspect-square rounded-md text-[10px] font-medium transition-colors ${intensityClasses[intensity]} ${isToday ? "ring-2 ring-brand-blue ring-offset-1" : ""} ${count === 0 ? "cursor-default" : "cursor-pointer"}`}
              aria-label={`${dateKey}: ${count} actions`}
            >
              {dayIndex}
            </button>
          );
        })}
      </div>

      <div className="flex items-center gap-3 text-[10px] text-slate-400">
        <span>No activity</span>
        <span className="h-2.5 w-2.5 rounded-sm bg-blue-100" />
        <span>Light</span>
        <span className="h-2.5 w-2.5 rounded-sm bg-blue-300" />
        <span>Medium</span>
        <span className="h-2.5 w-2.5 rounded-sm bg-blue-500" />
        <span>Heavy</span>
      </div>
    </div>
  );
}

// ──────────────────────────────────────────
// Top Actions
// ──────────────────────────────────────────

export function TopActions({
  receipts,
  onFilterAction,
}: {
  receipts: GuardReceipt[];
  onFilterAction?: (name: string) => void;
}) {
  const [period, setPeriod] = useState<TimePeriod>("7d");
  const [expanded, setExpanded] = useState(false);

  const periodReceipts = useMemo(() => {
    if (period === "all") return receipts;
    const days = period === "7d" ? 7 : period === "30d" ? 30 : 90;
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - days);
    return receipts.filter((r) => new Date(r.timestamp) >= cutoff);
  }, [receipts, period]);

  const aggregated = useMemo(() => aggregateByAction(periodReceipts), [periodReceipts]);
  const topTotal = aggregated.slice(0, 10);
  const topBlocked = aggregated.filter((a) => a.blocked > 0).slice(0, 10);
  const topAllowed = aggregated.filter((a) => a.allowed > 0).slice(0, 10);

  const toggleExpanded = useCallback(() => setExpanded((p) => !p), []);

  if (aggregated.length === 0) {
    return (
      <div className="rounded-xl border border-slate-100 bg-white p-4 text-center">
        <p className="text-sm text-slate-500">No top actions yet.</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-brand-dark">Top actions</h3>
        <div className="flex items-center gap-1">
          {(["7d", "30d", "90d", "all"] as TimePeriod[]).map((p) => (
            <button
              key={p}
              onClick={() => setPeriod(p)}
              className={`rounded-md px-2 py-0.5 text-[11px] font-medium transition-colors ${
                period === p
                  ? "bg-brand-blue text-white"
                  : "text-slate-500 hover:bg-slate-100"
              }`}
            >
              {p === "7d" ? "7 days" : p === "30d" ? "30 days" : p === "90d" ? "90 days" : "All time"}
            </button>
          ))}
        </div>
      </div>

      {!expanded ? (
        <TopActionsList actions={topTotal} onFilterAction={onFilterAction} />
      ) : (
        <div className="space-y-4">
          <TopActionsSection title="Most frequent" actions={topTotal} onFilterAction={onFilterAction} />
          <TopActionsSection title="Most blocked" actions={topBlocked} onFilterAction={onFilterAction} />
          <TopActionsSection title="Most allowed" actions={topAllowed} onFilterAction={onFilterAction} />
        </div>
      )}

      <button
        onClick={toggleExpanded}
        className="flex items-center gap-1 text-xs font-medium text-brand-blue transition-colors hover:text-brand-dark"
      >
        {expanded ? (
          <>
            <HiMiniChevronUp className="h-3.5 w-3.5" aria-hidden="true" />
            Show less
          </>
        ) : (
          <>
            <HiMiniChevronDown className="h-3.5 w-3.5" aria-hidden="true" />
            Show top blocked and allowed
          </>
        )}
      </button>
    </div>
  );
}

function TopActionsSection({
  title,
  actions,
  onFilterAction,
}: {
  title: string;
  actions: ActionAggregate[];
  onFilterAction?: (name: string) => void;
}) {
  if (actions.length === 0) return null;
  return (
    <div className="space-y-1.5">
      <h4 className="text-xs font-medium text-slate-500">{title}</h4>
      <TopActionsList actions={actions} onFilterAction={onFilterAction} />
    </div>
  );
}

function TopActionsList({
  actions,
  onFilterAction,
}: {
  actions: ActionAggregate[];
  onFilterAction?: (name: string) => void;
}) {
  const maxTotal = actions[0]?.total ?? 1;

  return (
    <div className="space-y-1">
      {actions.map((action) => {
        const allowPct = action.total > 0 ? (action.allowed / action.total) * 100 : 0;
        const blockPct = action.total > 0 ? (action.blocked / action.total) * 100 : 0;
        return (
          <button
            key={action.name}
            onClick={() => onFilterAction?.(action.name)}
            className="group flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left transition-colors hover:bg-slate-50"
          >
            <div className="min-w-0 flex-1">
              <div className="flex items-center justify-between">
                <span className="truncate text-xs font-medium text-brand-dark">{action.name}</span>
                <span className="shrink-0 text-[10px] text-slate-400">{action.total}</span>
              </div>
              <div className="mt-1 flex h-1.5 w-full overflow-hidden rounded-full bg-slate-100">
                <div
                  className="bg-emerald-400 transition-all"
                  style={{ width: `${allowPct}%` }}
                />
                <div
                  className="bg-brand-attention transition-all"
                  style={{ width: `${blockPct}%` }}
                />
              </div>
            </div>
          </button>
        );
      })}
    </div>
  );
}

interface ActionAggregate {
  name: string;
  total: number;
  allowed: number;
  blocked: number;
  lastSeen: string;
}

function aggregateByAction(receipts: GuardReceipt[]): ActionAggregate[] {
  const map = new Map<string, ActionAggregate>();
  for (const r of receipts) {
    const name = r.artifact_name ?? r.artifact_id;
    const existing = map.get(name);
    if (existing) {
      existing.total += 1;
      if (r.policy_decision === "allow") existing.allowed += 1;
      if (r.policy_decision === "block") existing.blocked += 1;
      if (r.timestamp > existing.lastSeen) existing.lastSeen = r.timestamp;
    } else {
      map.set(name, {
        name,
        total: 1,
        allowed: r.policy_decision === "allow" ? 1 : 0,
        blocked: r.policy_decision === "block" ? 1 : 0,
        lastSeen: r.timestamp,
      });
    }
  }
  return Array.from(map.values()).sort((a, b) => b.total - a.total);
}
