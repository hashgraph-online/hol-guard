import { useCallback } from "react";
import { harnessDisplayName } from "../approval-center-utils";
import { getCategoryInfo } from "./categories";
import type { ReceiptCategory } from "./categories";
import { Badge } from "../approval-center-primitives";
import type { GuardReceipt } from "../guard-types";

interface AppBreakdownCardProps {
  harness: string;
  total: number;
  blocked: number;
  allowed: number;
  maxTotal: number;
  onFilter: (harness: string) => void;
}

export function AppBreakdownCard({
  harness,
  total,
  blocked,
  allowed,
  maxTotal,
  onFilter,
}: AppBreakdownCardProps) {
  const pct = maxTotal > 0 ? (total / maxTotal) * 100 : 0;
  const handleClick = useCallback(() => onFilter(harness), [harness, onFilter]);

  return (
    <button
      type="button"
      onClick={handleClick}
      className="w-full rounded-2xl border border-slate-100 bg-white p-4 text-left transition-all hover:shadow-md hover:border-slate-200"
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-semibold text-brand-dark">{harnessDisplayName(harness)}</span>
        <Badge tone="default">{total} actions</Badge>
      </div>
      <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden mb-2">
        <div
          className="bg-brand-blue h-2 rounded-full transition-all"
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="flex items-center gap-3 text-[11px] text-slate-500">
        <span className="text-emerald-600">{allowed} allowed</span>
        {blocked > 0 && <span className="text-amber-600">{blocked} stopped</span>}
      </div>
    </button>
  );
}

interface CategoryBreakdownCardProps {
  categoryKey: ReceiptCategory;
  total: number;
  blocked: number;
  maxTotal: number;
  onFilter: (category: ReceiptCategory) => void;
}

export function CategoryBreakdownCard({
  categoryKey,
  total,
  blocked,
  maxTotal,
  onFilter,
}: CategoryBreakdownCardProps) {
  const pct = maxTotal > 0 ? (total / maxTotal) * 100 : 0;
  const catInfo = getCategoryInfo(categoryKey);
  const handleClick = useCallback(() => onFilter(categoryKey), [categoryKey, onFilter]);

  return (
    <button
      type="button"
      onClick={handleClick}
      className="w-full rounded-2xl border border-slate-100 bg-white p-4 text-left transition-all hover:shadow-md hover:border-slate-200"
    >
      <div className="flex items-center gap-3 mb-2">
        <span className={`${catInfo.color}`} aria-hidden="true">{catInfo.icon}</span>
        <span className="text-sm font-semibold text-brand-dark">{catInfo.label}</span>
        <span className="ml-auto">
          <Badge tone="default">{total} actions</Badge>
        </span>
      </div>
      <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden mb-2">
        <div
          className="bg-purple-500 h-2 rounded-full transition-all"
          style={{ width: `${pct}%` }}
        />
      </div>
      {blocked > 0 && (
        <p className="text-[11px] text-amber-600">{blocked} stopped</p>
      )}
    </button>
  );
}
