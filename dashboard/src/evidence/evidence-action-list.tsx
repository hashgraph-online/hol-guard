import { useCallback } from "react";
import type React from "react";
import {
  HiMiniShieldCheck,
  HiMiniNoSymbol,
  HiMiniQuestionMarkCircle,
  HiMiniChevronDown,
} from "react-icons/hi2";
import type { GuardReceipt } from "../guard-types";
import type { EvidenceSortKey } from "./evidence-types";
import { EVIDENCE_SORT_OPTIONS } from "./evidence-types";
import { harnessDisplayName, formatRelativeTime } from "../approval-center-utils";
import { detectCategory, getCategoryInfo } from "./categories";
import { humanFileName } from "./plain-english";
import { hasMore } from "./evidence-pagination";

interface EvidenceActionListProps {
  receipts: GuardReceipt[];
  selectedId: string;
  onSelectId: (id: string) => void;
  onFilterHarness: (harness: string) => void;
  onFilterCategory: (category: string) => void;
  sort: EvidenceSortKey;
  onSortChange: (sort: EvidenceSortKey) => void;
  page: number;
  pageSize: number;
  onLoadMore: () => void;
}

interface DecisionChipProps {
  decision: string;
}

function DecisionChip({ decision }: DecisionChipProps) {
  if (decision === "allow") {
    return (
      <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-green-50 px-2 py-0.5 text-[10px] font-semibold text-green-700 ring-1 ring-green-200">
        <HiMiniShieldCheck className="h-3 w-3" aria-hidden="true" />
        Allowed
      </span>
    );
  }
  if (decision === "block") {
    return (
      <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-amber-50 px-2 py-0.5 text-[10px] font-semibold text-amber-700 ring-1 ring-amber-200">
        <HiMiniNoSymbol className="h-3 w-3" aria-hidden="true" />
        Stopped
      </span>
    );
  }
  return (
    <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-blue-50 px-2 py-0.5 text-[10px] font-semibold text-blue-700 ring-1 ring-blue-200">
      <HiMiniQuestionMarkCircle className="h-3 w-3" aria-hidden="true" />
      Reviewed
    </span>
  );
}

interface ActionRowProps {
  receipt: GuardReceipt;
  isSelected: boolean;
  onSelect: (id: string) => void;
  onFilterHarness: (harness: string) => void;
  onFilterCategory: (category: string) => void;
}

function ActionRow({
  receipt,
  isSelected,
  onSelect,
  onFilterHarness,
  onFilterCategory,
}: ActionRowProps) {
  const category = detectCategory(receipt);
  const catInfo = getCategoryInfo(category);
  const artifactLabel = humanFileName(receipt.artifact_name ?? receipt.artifact_id);

  const handleClick = useCallback(() => {
    onSelect(receipt.receipt_id);
  }, [receipt.receipt_id, onSelect]);

  const handleHarnessClick = useCallback(
    (e: React.MouseEvent) => {
      e.stopPropagation();
      onFilterHarness(receipt.harness);
    },
    [receipt.harness, onFilterHarness]
  );

  const handleCategoryClick = useCallback(
    (e: React.MouseEvent) => {
      e.stopPropagation();
      onFilterCategory(category);
    },
    [category, onFilterCategory]
  );

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.target !== e.currentTarget) return;
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        onSelect(receipt.receipt_id);
      }
    },
    [receipt.receipt_id, onSelect]
  );

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={handleClick}
      onKeyDown={handleKeyDown}
      aria-selected={isSelected}
      className={`w-full text-left flex items-center gap-3 px-4 py-3 transition-colors border-b border-slate-100 last:border-0 hover:bg-slate-50 focus:outline-none focus:bg-slate-50 cursor-pointer ${
        isSelected ? "bg-brand-blue/5 border-l-2 border-l-brand-blue" : ""
      }`}
    >
      <span
        className={`shrink-0 ${catInfo.color}`}
        aria-hidden="true"
      >
        {catInfo.icon}
      </span>

      <div className="flex-1 min-w-0 space-y-0.5">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm font-medium text-brand-dark truncate">
            {artifactLabel}
          </span>
          <DecisionChip decision={receipt.policy_decision} />
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            type="button"
            onClick={handleHarnessClick}
            aria-label={`Filter by app ${harnessDisplayName(receipt.harness)}`}
            className="text-[11px] font-medium text-brand-blue hover:underline shrink-0"
          >
            {harnessDisplayName(receipt.harness)}
          </button>
          <span className="text-slate-300 text-[11px]">·</span>
          <button
            type="button"
            onClick={handleCategoryClick}
            aria-label={`Filter by category ${catInfo.label}`}
            className="text-[11px] text-slate-500 hover:text-brand-dark shrink-0"
          >
            {catInfo.label}
          </button>
          <span className="text-slate-300 text-[11px]">·</span>
          <span className="text-[11px] text-slate-400 shrink-0">
            {formatRelativeTime(receipt.timestamp)}
          </span>
        </div>
      </div>
    </div>
  );
}

export function EvidenceActionList({
  receipts,
  selectedId,
  onSelectId,
  onFilterHarness,
  onFilterCategory,
  sort,
  onSortChange,
  page,
  pageSize,
  onLoadMore,
}: EvidenceActionListProps) {
  const handleSortChange = useCallback(
    (e: React.ChangeEvent<HTMLSelectElement>) => {
      onSortChange(e.target.value as EvidenceSortKey);
    },
    [onSortChange]
  );

  const visible = receipts.slice(0, (page + 1) * pageSize);
  const showLoadMore = hasMore(page, pageSize, receipts.length);

  if (receipts.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-center">
        <p className="text-sm font-medium text-brand-dark">No actions match</p>
        <p className="mt-1 text-xs text-slate-500">
          Try adjusting the filters above.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between px-1">
        <span className="text-xs font-medium text-slate-500">
          {receipts.length} action{receipts.length !== 1 ? "s" : ""}
        </span>
        <label className="flex items-center gap-1.5 text-xs text-slate-500">
          Sort by:
          <select
            value={sort}
            onChange={handleSortChange}
            aria-label="Sort actions"
            className="rounded-md border-0 bg-transparent py-0.5 text-xs font-medium text-brand-dark focus:outline-none focus:ring-1 focus:ring-brand-blue/30"
          >
            {EVIDENCE_SORT_OPTIONS.map((opt) => (
              <option key={opt.key} value={opt.key}>
                {opt.label}
              </option>
            ))}
          </select>
          <HiMiniChevronDown className="h-3 w-3 text-slate-400 pointer-events-none" aria-hidden="true" />
        </label>
      </div>

      <div
        className="rounded-xl border border-slate-200 bg-white overflow-hidden"
        role="list"
        aria-label="Evidence actions"
      >
        {visible.map((receipt) => (
          <div role="listitem" key={receipt.receipt_id}>
            <ActionRow
              receipt={receipt}
              isSelected={selectedId === receipt.receipt_id}
              onSelect={onSelectId}
              onFilterHarness={onFilterHarness}
              onFilterCategory={onFilterCategory}
            />
          </div>
        ))}
      </div>

      {showLoadMore && (
        <div className="flex justify-center pt-2">
          <button
            type="button"
            onClick={onLoadMore}
            className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-brand-dark hover:bg-slate-50 transition-colors"
          >
            Load more
          </button>
        </div>
      )}
    </div>
  );
}
