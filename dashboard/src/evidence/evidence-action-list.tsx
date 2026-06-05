import { useCallback } from "react";
import type React from "react";
import {
  HiMiniShieldCheck,
  HiMiniNoSymbol,
  HiMiniQuestionMarkCircle,
  HiMiniChevronUp,
  HiMiniChevronDown,
} from "react-icons/hi2";
import type { GuardReceipt } from "../guard-types";
import type { EvidenceSortKey } from "./evidence-types";
import { harnessDisplayName, formatRelativeTime } from "../approval-center-utils";
import { detectCategory, getCategoryInfo } from "./categories";
import { humanFileName } from "./plain-english";
import { hasMore } from "./evidence-pagination";
import { Badge, SectionLabel } from "../approval-center-primitives";

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
      <Badge tone="success">
        <HiMiniShieldCheck className="h-3 w-3" aria-hidden="true" />
        Allowed
      </Badge>
    );
  }
  if (decision === "block") {
    return (
      <Badge tone="attention">
        <HiMiniNoSymbol className="h-3 w-3" aria-hidden="true" />
        Stopped
      </Badge>
    );
  }
  return (
    <Badge tone="info">
      <HiMiniQuestionMarkCircle className="h-3 w-3" aria-hidden="true" />
      Reviewed
    </Badge>
  );
}

const SORT_TOGGLE_MAP: Record<EvidenceSortKey, EvidenceSortKey> = {
  newest: "oldest",
  oldest: "newest",
  artifact: "artifact",
  app: "app",
  category: "category",
  decision: "decision",
};

function SortHeader({
  label,
  active,
  ascending,
  onClick,
  className = "",
}: {
  label: string;
  active: boolean;
  ascending: boolean;
  onClick: () => void;
  className?: string;
}) {
  return (
    <th
      scope="col"
      aria-sort={active ? (ascending ? "ascending" : "descending") : "none"}
      className={`px-3 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wider text-slate-500 ${className}`}
    >
      <button
        type="button"
        onClick={onClick}
        className="inline-flex items-center gap-1 hover:text-brand-dark transition-colors"
        aria-label={`Sort by ${label}${active ? (ascending ? ", ascending" : ", descending") : ""}`}
      >
        {label}
        {active && (
          ascending ? (
            <HiMiniChevronUp className="h-3 w-3" aria-hidden="true" />
          ) : (
            <HiMiniChevronDown className="h-3 w-3" aria-hidden="true" />
          )
        )}
      </button>
    </th>
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
  const visible = receipts.slice(0, (page + 1) * pageSize);
  const showLoadMore = hasMore(page, pageSize, receipts.length);

  const handleSort = useCallback(
    (key: EvidenceSortKey) => {
      if (sort === key) {
        onSortChange(SORT_TOGGLE_MAP[key]);
      } else {
        onSortChange(key);
      }
    },
    [sort, onSortChange]
  );

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
        <SectionLabel>{receipts.length} action{receipts.length !== 1 ? "s" : ""}</SectionLabel>
      </div>

      <div className="rounded-2xl border border-slate-100 bg-white overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-sm" aria-label="Evidence actions">
            <thead>
              <tr className="border-b border-slate-100 bg-slate-50/80">
                <th scope="col" className="w-8 px-3 py-2.5" />
                <SortHeader
                  label="Artifact"
                  active={sort === "artifact"}
                  ascending={sort === "artifact"}
                  onClick={() => handleSort("artifact")}
                  className="min-w-[180px]"
                />
                <SortHeader
                  label="App"
                  active={sort === "app"}
                  ascending={sort === "app"}
                  onClick={() => handleSort("app")}
                  className="hidden sm:table-cell"
                />
                <SortHeader
                  label="Category"
                  active={sort === "category"}
                  ascending={sort === "category"}
                  onClick={() => handleSort("category")}
                  className="hidden md:table-cell"
                />
                <SortHeader
                  label="Decision"
                  active={sort === "decision"}
                  ascending={sort === "decision"}
                  onClick={() => handleSort("decision")}
                />
                <SortHeader
                  label="Time"
                  active={sort === "newest" || sort === "oldest"}
                  ascending={sort === "oldest"}
                  onClick={() => handleSort("newest")}
                  className="hidden lg:table-cell"
                />
              </tr>
            </thead>
            <tbody>
              {visible.map((receipt) => (
                <ActionRow
                  key={receipt.receipt_id}
                  receipt={receipt}
                  isSelected={selectedId === receipt.receipt_id}
                  onSelect={onSelectId}
                  onFilterHarness={onFilterHarness}
                  onFilterCategory={onFilterCategory}
                />
              ))}
            </tbody>
          </table>
        </div>
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
    <tr
      tabIndex={0}
      onClick={handleClick}
      onKeyDown={handleKeyDown}
      aria-selected={isSelected}
      className={`border-b border-slate-100 last:border-0 transition-colors cursor-pointer ${
        isSelected ? "bg-brand-blue/[0.04]" : "hover:bg-slate-50"
      }`}
    >
      <td className="px-3 py-2.5">
        <span className={`${catInfo.color}`} aria-hidden="true">
          {catInfo.icon}
        </span>
      </td>
      <td className="px-3 py-2.5">
        <span className="text-sm font-medium text-brand-dark truncate block max-w-[200px]">
          {artifactLabel}
        </span>
      </td>
      <td className="px-3 py-2.5 hidden sm:table-cell">
        <button
          type="button"
          onClick={handleHarnessClick}
          aria-label={`Filter by app ${harnessDisplayName(receipt.harness)}`}
          className="text-xs font-medium text-brand-blue hover:underline"
        >
          {harnessDisplayName(receipt.harness)}
        </button>
      </td>
      <td className="px-3 py-2.5 hidden md:table-cell">
        <button
          type="button"
          onClick={handleCategoryClick}
          aria-label={`Filter by category ${catInfo.label}`}
          className="text-xs text-slate-500 hover:text-brand-dark"
        >
          {catInfo.label}
        </button>
      </td>
      <td className="px-3 py-2.5">
        <DecisionChip decision={receipt.policy_decision} />
      </td>
      <td className="px-3 py-2.5 hidden lg:table-cell">
        <span className="text-xs text-slate-400 whitespace-nowrap">
          {formatRelativeTime(receipt.timestamp)}
        </span>
      </td>
    </tr>
  );
}
