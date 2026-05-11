import { useMemo, useState } from "react";
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

  if (receipts.length < 10) return null;

  const rows: { label: string; a: number | string; b: number | string }[] = [
    { label: "Total actions", a: metricsA.total, b: metricsB.total },
    { label: "Allowed", a: metricsA.allowed, b: metricsB.allowed },
    { label: "Blocked", a: metricsA.blocked, b: metricsB.blocked },
    { label: "Block rate", a: `${metricsA.blockRate}%`, b: `${metricsB.blockRate}%` },
    { label: "Apps active", a: metricsA.appsActive, b: metricsB.appsActive },
  ];

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-brand-dark">Compare periods</h3>
        <div className="flex items-center gap-2">
          <PeriodSelector value={periodA} onChange={setPeriodA} />
          <span className="text-xs text-slate-400">vs</span>
          <PeriodSelector value={periodB} onChange={setPeriodB} />
        </div>
      </div>

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
              const isNegative = change < 0;
              const isBlockRate = row.label === "Block rate";
              const tone = isBlockRate
                ? isPositive ? "attention" : isNegative ? "green" : "slate"
                : isPositive ? "green" : isNegative ? "attention" : "slate";

              return (
                <tr key={row.label} className={i % 2 === 0 ? "bg-white" : "bg-slate-50/30"}>
                  <td className="px-4 py-2.5 font-medium text-brand-dark">{row.label}</td>
                  <td className="px-4 py-2.5 text-right text-slate-600">{row.a}</td>
                  <td className="px-4 py-2.5 text-right font-medium text-brand-dark">{row.b}</td>
                  <td className="px-4 py-2.5 text-right">
                    <span className={`inline-flex items-center gap-1 text-xs font-medium ${tone === "green" ? "text-emerald-600" : tone === "attention" ? "text-amber-600" : "text-slate-400"}`}>
                      {isPositive ? <HiOutlineArrowTrendingUp className="h-3 w-3" /> : isNegative ? <HiOutlineArrowTrendingDown className="h-3 w-3" /> : <HiOutlineMinus className="h-3 w-3" />}
                      {change !== 0 ? `${change > 0 ? "+" : ""}${change} (${change > 0 ? "+" : ""}${changePct}%)` : "—"}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <WhatChangedSection receipts={receipts} periodA={periodA} periodB={periodB} />
    </div>
  );
}

function PeriodSelector({ value, onChange }: { value: Period; onChange: (p: Period) => void }) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value as Period)}
      className="h-7 rounded-md border border-slate-200 bg-white px-2 py-0.5 text-xs font-medium text-brand-dark focus:border-brand-blue focus:outline-none"
    >
      <option value="7d">Last 7 days</option>
      <option value="30d">Last 30 days</option>
      <option value="90d">Last 90 days</option>
    </select>
  );
}

function WhatChangedSection({ receipts, periodA, periodB }: { receipts: GuardReceipt[]; periodA: Period; periodB: Period }) {
  const changes = useMemo(() => {
    const aDates = getPeriodDates(periodA);
    const bDates = getPeriodDates(periodB);
    const aReceipts = receipts.filter((r) => {
      const d = new Date(r.timestamp);
      return d >= aDates.start && d <= aDates.end;
    });
    const bReceipts = receipts.filter((r) => {
      const d = new Date(r.timestamp);
      return d >= bDates.start && d <= bDates.end;
    });

    const aApps = new Set(aReceipts.map((r) => r.harness));
    const bApps = new Set(bReceipts.map((r) => r.harness));
    const newApps = Array.from(bApps).filter((h) => !aApps.has(h));

    const aBlockRate = aReceipts.length > 0 ? (aReceipts.filter((r) => r.policy_decision === "block").length / aReceipts.length) : 0;
    const bBlockRate = bReceipts.length > 0 ? (bReceipts.filter((r) => r.policy_decision === "block").length / bReceipts.length) : 0;
    const blockRateShift = bBlockRate - aBlockRate;

    const aActionTypes = new Set(aReceipts.map((r) => r.artifact_name ?? ""));
    const bActionTypes = new Set(bReceipts.map((r) => r.artifact_name ?? ""));
    const newActions = Array.from(bActionTypes).filter((n) => !aActionTypes.has(n)).slice(0, 3);

    return { newApps, blockRateShift, newActions };
  }, [receipts, periodA, periodB]);

  if (changes.newApps.length === 0 && Math.abs(changes.blockRateShift) < 0.05 && changes.newActions.length === 0) {
    return null;
  }

  return (
    <div className="rounded-xl border border-slate-100 bg-white p-4 shadow-sm">
      <h4 className="text-xs font-semibold text-brand-dark">What changed</h4>
      <div className="mt-2 space-y-1 text-sm text-slate-600">
        {changes.newApps.length > 0 && (
          <p>New apps detected: {changes.newApps.join(", ")}</p>
        )}
        {Math.abs(changes.blockRateShift) >= 0.05 && (
          <p>
            Block rate {changes.blockRateShift > 0 ? "increased" : "decreased"} by {Math.abs(Math.round(changes.blockRateShift * 100))}%
          </p>
        )}
        {changes.newActions.length > 0 && (
          <p>New action types: {changes.newActions.join(", ")}</p>
        )}
      </div>
    </div>
  );
}
