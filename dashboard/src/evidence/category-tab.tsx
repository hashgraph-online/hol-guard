import { useMemo, useState, memo, useCallback } from "react";
import {
  HiMiniChevronRight,
  HiMiniChevronLeft,
  HiMiniFunnel,
  HiMiniShieldCheck,
  HiMiniNoSymbol,
  HiMiniQuestionMarkCircle,
} from "react-icons/hi2";
import type { GuardReceipt } from "../guard-types";
import { groupByCategory, getCategoryInfo, type ReceiptCategory, CATEGORIES, detectCategory } from "./categories";
import { plainEnglishDescription, humanFileName } from "./plain-english";
import { formatRelativeTime, harnessDisplayName } from "../approval-center-utils";
import { DecisionBadge } from "./decision-badge";
import { Badge } from "../approval-center-primitives";

interface CategoryTabProps {
  receipts: GuardReceipt[];
  onFilterCategory?: (category: ReceiptCategory) => void;
}

interface CategoryCardProps {
  cat: typeof CATEGORIES[0];
  count: number;
  blocked: number;
  onSelect: (key: ReceiptCategory) => void;
}

function CategoryCard({ cat, count, blocked, onSelect }: CategoryCardProps) {
  const handleClick = useCallback(() => {
    onSelect(cat.key);
  }, [cat.key, onSelect]);

  return (
    <button
      key={cat.key}
      onClick={handleClick}
      className="w-full rounded-2xl border border-slate-100 bg-white p-4 text-left transition-all hover:shadow-md hover:border-slate-200 shadow-sm"
    >
      <div className="flex items-center gap-3">
        <span className={`inline-flex h-10 w-10 items-center justify-center rounded-full bg-slate-50 ${cat.color}`}>
          {cat.icon}
        </span>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold text-brand-dark">{cat.label}</p>
          <p className="text-xs text-slate-500">{count} action{count !== 1 ? "s" : ""}</p>
        </div>
        {blocked > 0 && (
          <Badge tone="attention">{blocked} stopped</Badge>
        )}
        <HiMiniChevronRight className="h-4 w-4 text-slate-300 shrink-0" aria-hidden="true" />
      </div>
    </button>
  );
}

function CategoryTabRaw({ receipts, onFilterCategory }: CategoryTabProps) {
  const [selectedCategory, setSelectedCategory] = useState<ReceiptCategory | null>(null);
  const [decisionFilter, setDecisionFilter] = useState<string>("all");
  const [harnessFilter, setHarnessFilter] = useState<string>("");

  const groups = useMemo(() => groupByCategory(receipts), [receipts]);

  const handleBack = useCallback(() => {
    setSelectedCategory(null);
    setDecisionFilter("all");
    setHarnessFilter("");
  }, []);

  const handleSelectCategory = useCallback((key: ReceiptCategory) => {
    setSelectedCategory(key);
    setDecisionFilter("all");
    setHarnessFilter("");
    onFilterCategory?.(key);
  }, [onFilterCategory]);

  const selectedItems = useMemo(() => {
    if (!selectedCategory) return [];
    let items = groups.get(selectedCategory) ?? [];
    if (decisionFilter !== "all") {
      items = items.filter((r) => r.policy_decision === decisionFilter);
    }
    if (harnessFilter) {
      items = items.filter((r) => r.harness === harnessFilter);
    }
    return items;
  }, [groups, selectedCategory, decisionFilter, harnessFilter]);

  const harnesses = useMemo(() => {
    if (!selectedCategory) return [];
    const allItems = groups.get(selectedCategory) ?? [];
    return Array.from(new Set(allItems.map((r) => r.harness)));
  }, [groups, selectedCategory]);

  if (selectedCategory) {
    const allItems = groups.get(selectedCategory) ?? [];
    const info = getCategoryInfo(selectedCategory);

    return (
      <div className="space-y-5">
        <button
          onClick={handleBack}
          className="inline-flex items-center gap-1 rounded-lg px-3 py-1.5 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-100"
        >
          <HiMiniChevronLeft className="h-4 w-4" aria-hidden="true" />
          Back to categories
        </button>

        <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-sm">
          <div className="flex items-center gap-3">
            <span className={`inline-flex h-12 w-12 items-center justify-center rounded-full bg-slate-50 ${info.color}`}>
              {info.icon}
            </span>
            <div>
              <h2 className="text-base font-semibold text-brand-dark">{info.label}</h2>
              <p className="text-xs text-slate-500">{info.description}</p>
            </div>
          </div>
          <p className="mt-3 text-sm text-brand-dark">
            {allItems.length} action{allItems.length !== 1 ? "s" : ""} in this category
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1.5 text-xs text-slate-500">
            <HiMiniFunnel className="h-3.5 w-3.5" aria-hidden="true" />
            <span>Filter:</span>
          </div>
          <select
            value={decisionFilter}
            onChange={(e) => setDecisionFilter(e.target.value)}
            className="min-h-7 rounded-lg border border-slate-200 bg-white px-2 text-xs font-medium text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20"
          >
            <option value="all">All decisions</option>
            <option value="allow">Allowed</option>
            <option value="block">Stopped</option>
          </select>
          <select
            value={harnessFilter}
            onChange={(e) => setHarnessFilter(e.target.value)}
            className="min-h-7 rounded-lg border border-slate-200 bg-white px-2 text-xs font-medium text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20"
          >
            <option value="">All apps</option>
            {harnesses.map((h) => (
              <option key={h} value={h}>{harnessDisplayName(h)}</option>
            ))}
          </select>
          {(decisionFilter !== "all" || harnessFilter) && (
            <button
              type="button"
              onClick={() => { setDecisionFilter("all"); setHarnessFilter(""); }}
              className="text-xs font-medium text-brand-blue hover:text-brand-dark transition-colors"
            >
              Clear filters
            </button>
          )}
        </div>

        {selectedItems.length === 0 ? (
          <div className="py-8 text-center">
            <p className="text-sm text-slate-500">No actions match the selected filters.</p>
          </div>
        ) : (
          <div className="rounded-2xl border border-slate-100 bg-white overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-sm" aria-label={`${info.label} actions`}>
                <thead>
                  <tr className="border-b border-slate-100 bg-slate-50/80">
                    <th scope="col" className="w-8 px-3 py-2.5" />
                    <th scope="col" className="px-3 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wider text-slate-500">Artifact</th>
                    <th scope="col" className="px-3 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wider text-slate-500 hidden md:table-cell">App</th>
                    <th scope="col" className="px-3 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wider text-slate-500">Decision</th>
                    <th scope="col" className="px-3 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wider text-slate-500 hidden lg:table-cell">Time</th>
                  </tr>
                </thead>
                <tbody>
                  {selectedItems.map((receipt) => {
                    const category = detectCategory(receipt);
                    const catInfo = getCategoryInfo(category);
                    const artifactLabel = humanFileName(receipt.artifact_name ?? receipt.artifact_id);
                    return (
                      <tr key={receipt.receipt_id} className="border-b border-slate-100 last:border-0 hover:bg-slate-50 transition-colors">
                        <td className="px-3 py-2.5">
                          <span className={`${catInfo.color}`} aria-hidden="true">{catInfo.icon}</span>
                        </td>
                        <td className="px-3 py-2.5">
                          <span className="text-sm font-medium text-brand-dark truncate block max-w-[200px]">{artifactLabel}</span>
                        </td>
                        <td className="px-3 py-2.5 hidden md:table-cell">
                          <span className="text-xs text-slate-500">{harnessDisplayName(receipt.harness)}</span>
                        </td>
                        <td className="px-3 py-2.5">
                          <DecisionBadge decision={receipt.policy_decision} />
                        </td>
                        <td className="px-3 py-2.5 hidden lg:table-cell">
                          <span className="text-xs text-slate-400 whitespace-nowrap">{formatRelativeTime(receipt.timestamp)}</span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
      {CATEGORIES.map((cat) => {
        const items = groups.get(cat.key) ?? [];
        if (items.length === 0) return null;
        return (
          <CategoryCard
            key={cat.key}
            cat={cat}
            count={items.length}
            blocked={items.filter((r) => r.policy_decision === "block").length}
            onSelect={handleSelectCategory}
          />
        );
      })}

      {Array.from(groups.values()).every((items) => items.length === 0) && (
        <div className="col-span-full rounded-2xl border border-slate-100 bg-white/60 p-8 text-center">
          <p className="text-sm text-slate-500">No activity yet.</p>
        </div>
      )}
    </div>
  );
}

export const CategoryTab = memo(CategoryTabRaw);
