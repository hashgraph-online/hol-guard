import { useCallback, useMemo, useState, type ChangeEvent } from "react";
import {
  HiOutlineArrowTrendingUp,
  HiOutlineArrowTrendingDown,
  HiOutlineMinus,
} from "react-icons/hi2";
import type { GuardReceipt } from "./guard-types";

type Period = "7d" | "30d" | "90d";

function getPeriodDates(period: Period): { start: Date; end: Date; label: string } {
  const end = new Date();
  const start = new Date(end);
  switch (period) {
    case "7d":
      start.setDate(start.getDate() - 7);
      return { start, end, label: "Last 7 days" };
    case "30d":
      start.setDate(start.getDate() - 30);
      return { start, end, label: "Last 30 days" };
    case "90d":
      start.setDate(start.getDate() - 90);
      return { start, end, label: "Last 90 days" };
  }
}

function filterByPeriod(receipts: GuardReceipt[], period: Period): GuardReceipt[] {
  const { start, end } = getPeriodDates(period);
  return receipts.filter((r) => {
    const d = new Date(r.timestamp);
    return d >= start && d <= end;
  });
}

interface CompareMetrics {
  total: number;
  allowed: number;
  blocked: number;
  blockRate: number;
  appsActive: number;
}

function computeMetrics(receipts: GuardReceipt[]): CompareMetrics {
  const allowed = receipts.filter((r) => r.policy_decision === "allow").length;
  const blocked = receipts.filter((r) => r.policy_decision === "block").length;
  const appsActive = new Set(receipts.map((r) => r.harness)).size;
  return {
    total: receipts.length,
    allowed,
    blocked,
    blockRate: receipts.length > 0 ? Math.round((blocked / receipts.length) * 100) : 0,
    appsActive,
  };
}

export function CompareTimePeriods({ receipts }: { receipts: GuardReceipt[] }) {
  const [periodA, setPeriodA] = useState<Period>("30d");
  const [periodB, setPeriodB] = useState<Period>("7d");

  const metricsA = useMemo(() => computeMetrics(filterByPeriod(receipts, periodA)), [receipts, periodA]);
  const metricsB = useMemo(() => computeMetrics(filterByPeriod(receipts, periodB)), [receipts, periodB]);

  const handlePeriodAChange = useCallback(
    (p: Period) => {
      const prevA = periodA;
      setPeriodA(p);
      if (p === periodB) setPeriodB(prevA);
    },
    [periodA, periodB]
  );

  const handlePeriodBChange = useCallback(
    (p: Period) => {
      const prevB = periodB;
      setPeriodB(p);
      if (p === periodA) setPeriodA(prevB);
    },
    [periodA, periodB]
  );

  if (receipts.length < 10) {
    return (
      <div className="rounded-xl border border-slate-100 bg-white p-8 text-center">
        <p className="text-sm text-slate-500">Not enough data to compare periods.</p>
        <p className="mt-1 text-xs text-slate-400">Compare appears after 10+ decisions.</p>
      </div>
    );
  }

  const rows: { label: string; a: number | string; b: number | string }[] = [
    { label: "Total actions", a: metricsA.total, b: metricsB.total },
    { label: "Allowed", a: metricsA.allowed, b: metricsB.allowed },
    { label: "Blocked", a: metricsA.blocked, b: metricsB.blocked },
    { label: "Block rate", a: `${metricsA.blockRate}%`, b: `${metricsB.blockRate}%` },
    { label: "Apps active", a: metricsA.appsActive, b: metricsB.appsActive },
  ];

  const samePeriod = periodA === periodB;
  const periodsOverlap = !samePeriod;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-brand-dark">Compare periods</h3>
        <div className="flex items-center gap-2">
          <PeriodSelector value={periodA} onChange={handlePeriodAChange} />
          <span className="text-xs text-slate-400">vs</span>
          <PeriodSelector value={periodB} onChange={handlePeriodBChange} />
        </div>
      </div>

      {samePeriod && (
        <div className="rounded-lg border border-brand-attention/15 bg-brand-attention/[0.04] px-3 py-2">
          <p className="text-xs text-brand-attention">Select two different periods to compare.</p>
        </div>
      )}

      {periodsOverlap && (
        <div className="rounded-lg border border-slate-200 bg-slate-50/60 px-3 py-2">
          <p className="text-xs text-slate-500">
            Both windows end at today and share recent data. The change column shows the difference between window sizes, not period-over-period trends.
          </p>
        </div>
      )}

      <div className="overflow-hidden rounded-xl border border-slate-100 bg-white shadow-sm">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-100 bg-slate-50/50">
              <th className="px-4 py-2.5 text-left text-xs font-medium text-slate-500">Metric</th>
              <th className="px-4 py-2.5 text-right text-xs font-medium text-slate-500">{getPeriodDates(periodA).label}</th>
              <th className="px-4 py-2.5 text-right text-xs font-medium text-slate-500">{getPeriodDates(periodB).label}</th>
              <th className="px-4 py-2.5 text-right text-xs font-medium text-slate-500">Change</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row, i) => {
              const aNum = typeof row.a === "number" ? row.a : parseInt(row.a as string);
              const bNum = typeof row.b === "number" ? row.b : parseInt(row.b as string);
              const change = bNum - aNum;
              const changePct = aNum !== 0 ? Math.round((change / aNum) * 100) : 0;
              const isPositive = change > 0;
              const isNeutral = change === 0;
              const ChangeIcon = isNeutral ? HiOutlineMinus : isPositive ? HiOutlineArrowTrendingUp : HiOutlineArrowTrendingDown;
              const changeColor = isNeutral
                ? "text-slate-400"
                : row.label === "Allowed" || row.label === "Apps active"
                  ? isPositive
                    ? "text-emerald-600"
                    : "text-slate-500"
                  : isPositive
                    ? "text-amber-600"
                    : "text-emerald-600";

              return (
                <tr key={row.label} className={i < rows.length - 1 ? "border-b border-slate-50" : ""}>
                  <td className="px-4 py-2.5 font-medium text-brand-dark">{row.label}</td>
                  <td className="px-4 py-2.5 text-right tabular-nums text-slate-600">{row.a}</td>
                  <td className="px-4 py-2.5 text-right tabular-nums text-slate-600">{row.b}</td>
                  <td className="px-4 py-2.5 text-right">
                    <span className={`inline-flex items-center gap-1 text-xs font-medium ${changeColor}`}>
                      <ChangeIcon className="h-3.5 w-3.5" aria-hidden="true" />
                      {isNeutral ? "—" : `${change > 0 ? "+" : ""}${change} (${change > 0 ? "+" : ""}${changePct}%)`}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function PeriodSelector({ value, onChange }: { value: Period; onChange: (p: Period) => void }) {
  const handleChange = useCallback(
    (e: ChangeEvent<HTMLSelectElement>) => onChange(e.target.value as Period),
    [onChange]
  );
  return (
    <select
      value={value}
      onChange={handleChange}
      className="rounded-md border border-slate-200 bg-white px-2 py-1 text-xs font-medium text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
    >
      <option value="7d">Last 7 days</option>
      <option value="30d">Last 30 days</option>
      <option value="90d">Last 90 days</option>
    </select>
  );
}
