import { useMemo } from "react";
import type { GuardReceipt } from "./guard-types";
import { harnessDisplayName } from "./approval-center-utils";

// ──────────────────────────────────────────
// Decision Pie Chart (SVG)
// ──────────────────────────────────────────

export function DecisionPieChart({ receipts }: { receipts: GuardReceipt[] }) {
  const { allow, block, total } = useMemo(() => {
    const allow = receipts.filter((r) => r.policy_decision === "allow").length;
    const block = receipts.filter((r) => r.policy_decision === "block").length;
    return { allow, block, total: receipts.length };
  }, [receipts]);

  if (total === 0) return null;

  const allowPct = Math.round((allow / total) * 100);
  const blockPct = Math.round((block / total) * 100);

  const radius = 40;
  const circumference = 2 * Math.PI * radius;
  const allowDash = (allow / total) * circumference;
  const blockDash = (block / total) * circumference;

  return (
    <div className="space-y-2">
      <h4 className="text-xs font-semibold text-brand-dark">Decisions</h4>
      <div className="flex items-center gap-4">
        <svg viewBox="0 0 100 100" className="h-20 w-20 -rotate-90">
          <circle cx="50" cy="50" r={radius} fill="none" stroke="#e2e8f0" strokeWidth="12" />
          {allow > 0 && (
            <circle
              cx="50"
              cy="50"
              r={radius}
              fill="none"
              stroke="#10b981"
              strokeWidth="12"
              strokeDasharray={`${allowDash} ${circumference - allowDash}`}
              strokeLinecap="round"
            />
          )}
          {block > 0 && (
            <circle
              cx="50"
              cy="50"
              r={radius}
              fill="none"
              stroke="#f59e0b"
              strokeWidth="12"
              strokeDasharray={`${blockDash} ${circumference - blockDash}`}
              strokeDashoffset={-allowDash}
              strokeLinecap="round"
            />
          )}
        </svg>
        <div className="space-y-1">
          <div className="flex items-center gap-1.5 text-xs">
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-500" />
            <span className="text-slate-500">Allowed</span>
            <span className="ml-auto font-medium text-brand-dark">{allowPct}%</span>
          </div>
          <div className="flex items-center gap-1.5 text-xs">
            <span className="h-2.5 w-2.5 rounded-full bg-amber-500" />
            <span className="text-slate-500">Blocked</span>
            <span className="ml-auto font-medium text-brand-dark">{blockPct}%</span>
          </div>
        </div>
      </div>
    </div>
  );
}

// ──────────────────────────────────────────
// Activity Bar Chart (div-based)
// ──────────────────────────────────────────

export function ActivityBarChart({ receipts }: { receipts: GuardReceipt[] }) {
  const days = useMemo(() => {
    const map = new Map<string, { allow: number; block: number }>();
    const now = new Date();
    // Initialize last 30 days with zeros
    for (let i = 29; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
      map.set(key, { allow: 0, block: 0 });
    }
    for (const r of receipts) {
      const d = new Date(r.timestamp);
      const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
      if (map.has(key)) {
        const existing = map.get(key)!;
        if (r.policy_decision === "allow") existing.allow += 1;
        if (r.policy_decision === "block") existing.block += 1;
      }
    }
    return Array.from(map.entries()).map(([date, counts]) => ({ date, ...counts }));
  }, [receipts]);

  const maxTotal = Math.max(1, ...days.map((d) => d.allow + d.block));

  if (days.every((d) => d.allow === 0 && d.block === 0)) return null;

  const formatDayLabel = (date: string) => {
    const d = new Date(date);
    return `${d.getMonth() + 1}/${d.getDate()}`;
  };

  return (
    <div className="space-y-2">
      <h4 className="text-xs font-semibold text-brand-dark">Activity (last 30 days)</h4>
      <div className="flex h-32 items-end gap-0.5">
        {days.map((day) => {
          const total = day.allow + day.block;
          const heightPct = total > 0 ? (total / maxTotal) * 100 : 0;
          const allowPctOfTotal = total > 0 ? (day.allow / total) * 100 : 0;
          return (
            <div key={day.date} className="group relative flex flex-1 flex-col justify-end" title={`${formatDayLabel(day.date)}: ${total} actions`}>
              <div className="flex w-full flex-col-reverse overflow-hidden rounded-t-sm" style={{ height: `${heightPct}%` }}>
                {day.allow > 0 && (
                  <div className="bg-emerald-400 transition-all" style={{ height: `${allowPctOfTotal}%`, minHeight: day.allow > 0 ? 1 : 0 }} />
                )}
                {day.block > 0 && (
                  <div className="bg-amber-400 transition-all" style={{ height: `${100 - allowPctOfTotal}%`, minHeight: day.block > 0 ? 1 : 0 }} />
                )}
              </div>
              <span className="mt-0.5 text-center text-[8px] text-slate-300 opacity-0 transition-opacity group-hover:opacity-100">
                {formatDayLabel(day.date)}
              </span>
            </div>
          );
        })}
      </div>
      <div className="flex items-center gap-3 text-[10px] text-slate-400">
        <span className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-sm bg-emerald-400" />
          Allowed
        </span>
        <span className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-sm bg-amber-400" />
          Blocked
        </span>
      </div>
    </div>
  );
}

// ──────────────────────────────────────────
// App Activity Bars
// ──────────────────────────────────────────

export function AppActivityBars({ receipts }: { receipts: GuardReceipt[] }) {
  const apps = useMemo(() => {
    const map = new Map<string, number>();
    for (const r of receipts) {
      map.set(r.harness, (map.get(r.harness) ?? 0) + 1);
    }
    return Array.from(map.entries())
      .map(([harness, count]) => ({ harness, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [receipts]);

  const maxCount = Math.max(1, ...apps.map((a) => a.count));

  if (apps.length === 0) return null;

  return (
    <div className="space-y-2">
      <h4 className="text-xs font-semibold text-brand-dark">Top apps</h4>
      <div className="space-y-2">
        {apps.map((app) => (
          <div key={app.harness} className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-600">{harnessDisplayName(app.harness)}</span>
              <span className="font-medium text-brand-dark">{app.count}</span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-100">
              <div
                className="h-full rounded-full bg-brand-blue transition-all"
                style={{ width: `${(app.count / maxCount) * 100}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ──────────────────────────────────────────
// Decision Trend Line
// ──────────────────────────────────────────

export function DecisionTrendLine({ receipts }: { receipts: GuardReceipt[] }) {
  const days = useMemo(() => {
    const map = new Map<string, { allow: number; block: number }>();
    const now = new Date();
    for (let i = 29; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
      map.set(key, { allow: 0, block: 0 });
    }
    for (const r of receipts) {
      const d = new Date(r.timestamp);
      const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
      if (map.has(key)) {
        const existing = map.get(key)!;
        if (r.policy_decision === "allow") existing.allow += 1;
        if (r.policy_decision === "block") existing.block += 1;
      }
    }
    return Array.from(map.entries()).map(([date, counts]) => ({ date, ...counts }));
  }, [receipts]);

  const hasData = days.some((d) => d.allow > 0 || d.block > 0);
  if (!hasData) return null;

  const width = 300;
  const height = 60;
  const padding = 4;
  const chartWidth = width - padding * 2;
  const chartHeight = height - padding * 2;
  const totalMax = Math.max(1, ...days.map((d) => d.allow + d.block));

  const allowPoints = days.map((day, i) => {
    const x = padding + (i / (days.length - 1)) * chartWidth;
    const y = padding + chartHeight - (day.allow / totalMax) * chartHeight;
    return `${x},${y}`;
  }).join(" ");

  const blockPoints = days.map((day, i) => {
    const x = padding + (i / (days.length - 1)) * chartWidth;
    const y = padding + chartHeight - (day.block / totalMax) * chartHeight;
    return `${x},${y}`;
  }).join(" ");

  return (
    <div className="space-y-2">
      <h4 className="text-xs font-semibold text-brand-dark">Decision trend (30 days)</h4>
      <svg viewBox={`0 0 ${width} ${height}`} className="w-full" preserveAspectRatio="none">
        <polyline
          fill="none"
          stroke="#10b981"
          strokeWidth="2"
          points={allowPoints}
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        <polyline
          fill="none"
          stroke="#f59e0b"
          strokeWidth="2"
          points={blockPoints}
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      <div className="flex items-center gap-3 text-[10px] text-slate-400">
        <span className="flex items-center gap-1">
          <span className="h-1 w-4 rounded-full bg-emerald-400" />
          Allowed
        </span>
        <span className="flex items-center gap-1">
          <span className="h-1 w-4 rounded-full bg-amber-400" />
          Blocked
        </span>
      </div>
    </div>
  );
}

// ──────────────────────────────────────────
// Block Reason Breakdown
// ──────────────────────────────────────────

export function BlockReasonBreakdown({ receipts }: { receipts: GuardReceipt[] }) {
  const reasons = useMemo(() => {
    const blocked = receipts.filter((r) => r.policy_decision === "block");
    const counts = new Map<string, number>();
    for (const r of blocked) {
      const name = (r.artifact_name ?? "").toLowerCase();
      const caps = (r.capabilities_summary ?? "").toLowerCase();
      if (name.includes(".env") || name.includes("secret") || caps.includes("secret")) {
        counts.set("Secret access", (counts.get("Secret access") ?? 0) + 1);
      } else if (caps.includes("network") || caps.includes("exfiltrat")) {
        counts.set("Network/Exfiltration", (counts.get("Network/Exfiltration") ?? 0) + 1);
      } else if (caps.includes("destructive") || caps.includes("rm ") || caps.includes("delete")) {
        counts.set("Destructive", (counts.get("Destructive") ?? 0) + 1);
      } else if (caps.includes("encoded") || caps.includes("decode")) {
        counts.set("Encoded payload", (counts.get("Encoded payload") ?? 0) + 1);
      } else {
        counts.set("Other", (counts.get("Other") ?? 0) + 1);
      }
    }
    return Array.from(counts.entries())
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count);
  }, [receipts]);

  if (reasons.length === 0) return null;

  const maxCount = Math.max(1, ...reasons.map((r) => r.count));
  const colors = ["bg-amber-500", "bg-amber-400", "bg-amber-300", "bg-amber-200", "bg-slate-300"];

  return (
    <div className="space-y-2">
      <h4 className="text-xs font-semibold text-brand-dark">Why Guard blocked</h4>
      <div className="space-y-2">
        {reasons.map((reason, i) => (
          <div key={reason.label} className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-600">{reason.label}</span>
              <span className="font-medium text-brand-dark">{reason.count}</span>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-100">
              <div
                className={`h-full rounded-full ${colors[i % colors.length]} transition-all`}
                style={{ width: `${(reason.count / maxCount) * 100}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ──────────────────────────────────────────
// Charts Section
// ──────────────────────────────────────────

export function HistoryCharts({ receipts }: { receipts: GuardReceipt[] }) {
  const hasData = receipts.length > 0;
  if (!hasData) return null;

  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
      <div className="rounded-xl border border-slate-100 bg-white p-4 shadow-sm">
        <DecisionPieChart receipts={receipts} />
      </div>
      <div className="rounded-xl border border-slate-100 bg-white p-4 shadow-sm">
        <ActivityBarChart receipts={receipts} />
      </div>
      <div className="rounded-xl border border-slate-100 bg-white p-4 shadow-sm">
        <AppActivityBars receipts={receipts} />
      </div>
      <div className="rounded-xl border border-slate-100 bg-white p-4 shadow-sm">
        <DecisionTrendLine receipts={receipts} />
      </div>
      <div className="rounded-xl border border-slate-100 bg-white p-4 shadow-sm">
        <BlockReasonBreakdown receipts={receipts} />
      </div>
    </div>
  );
}
