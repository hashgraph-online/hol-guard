import { useCallback, useState } from "react";
import {
  HiMiniMagnifyingGlass,
  HiMiniXMark,
  HiMiniChevronDown,
  HiMiniChevronUp,
  HiFunnel,
} from "react-icons/hi2";
import type { EvidenceFilterState, EvidenceDecision, EvidenceTimeFilter } from "./evidence-types";
import { EVIDENCE_TIME_LABELS, EVIDENCE_DECISION_LABELS } from "./evidence-types";
import { harnessDisplayName } from "../approval-center-utils";

interface EvidenceFilterBarProps {
  filters: EvidenceFilterState;
  onChange: (patch: Partial<EvidenceFilterState>) => void;
  totalCount: number;
  filteredCount: number;
  harnesses: string[];
  hideHarnessFilter?: boolean;
}

const CATEGORY_OPTIONS = [
  { value: "", label: "All categories" },
  { value: "secret", label: "Secrets" },
  { value: "network", label: "Network" },
  { value: "destructive", label: "Destructive" },
  { value: "hidden", label: "Hidden" },
  { value: "file-write", label: "File write" },
  { value: "tool-call", label: "Tool call" },
  { value: "other", label: "Other" },
];

interface ActiveChipProps {
  label: string;
  onRemove: () => void;
}

function ActiveChip({ label, onRemove }: ActiveChipProps) {
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-brand-blue/10 px-2.5 py-1 text-xs font-medium text-brand-blue">
      {label}
      <button
        type="button"
        onClick={onRemove}
        aria-label={`Remove filter: ${label}`}
        className="flex h-4 w-4 items-center justify-center rounded-full hover:bg-brand-blue/20 transition-colors"
      >
        <HiMiniXMark className="h-3 w-3" aria-hidden="true" />
      </button>
    </span>
  );
}

interface SearchInputProps {
  value: string;
  onChange: (value: string) => void;
}

function SearchInput({ value, onChange }: SearchInputProps) {
  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      onChange(e.target.value);
    },
    [onChange]
  );

  const handleClear = useCallback(() => {
    onChange("");
  }, [onChange]);

  return (
    <label className="relative flex flex-1 min-w-[160px] items-center">
      <span className="sr-only">Search evidence</span>
      <HiMiniMagnifyingGlass
        className="absolute left-2.5 h-3.5 w-3.5 text-slate-400 pointer-events-none"
        aria-hidden="true"
      />
      <input
        type="search"
        value={value}
        onChange={handleChange}
        placeholder="Search..."
        className="min-h-8 w-full rounded-lg border border-slate-200 bg-white pl-8 pr-7 text-xs text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
      />
      {value && (
        <button
          type="button"
          onClick={handleClear}
          aria-label="Clear search"
          className="absolute right-2 flex h-4 w-4 items-center justify-center rounded-full text-slate-400 hover:text-slate-600 transition-colors"
        >
          <HiMiniXMark className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      )}
    </label>
  );
}

export function EvidenceFilterBar({
  filters,
  onChange,
  totalCount,
  filteredCount,
  harnesses,
  hideHarnessFilter = false,
}: EvidenceFilterBarProps) {
  const [showMore, setShowMore] = useState(false);

  const handleSearchChange = useCallback(
    (value: string) => {
      onChange({ search: value });
    },
    [onChange]
  );

  const handleTimeChange = useCallback(
    (e: React.ChangeEvent<HTMLSelectElement>) => {
      onChange({ time: e.target.value as EvidenceTimeFilter, day: "" });
    },
    [onChange]
  );

  const handleDecisionChange = useCallback(
    (e: React.ChangeEvent<HTMLSelectElement>) => {
      onChange({ decision: e.target.value as EvidenceDecision });
    },
    [onChange]
  );

  const handleHarnessChange = useCallback(
    (e: React.ChangeEvent<HTMLSelectElement>) => {
      onChange({ harness: e.target.value });
    },
    [onChange]
  );

  const handleCategoryChange = useCallback(
    (e: React.ChangeEvent<HTMLSelectElement>) => {
      onChange({ category: e.target.value });
    },
    [onChange]
  );

  const handleSourceScopeChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      onChange({ sourceScope: e.target.value });
    },
    [onChange]
  );

  const handleClearAll = useCallback(() => {
    onChange({
      search: "",
      time: "all",
      decision: "all",
      harness: "all",
      category: "",
      sourceScope: "",
      day: "",
    });
  }, [onChange]);

  const handleRemoveSearch = useCallback(() => {
    onChange({ search: "" });
  }, [onChange]);

  const handleRemoveTime = useCallback(() => {
    onChange({ time: "all", day: "" });
  }, [onChange]);

  const handleRemoveDecision = useCallback(() => {
    onChange({ decision: "all" });
  }, [onChange]);

  const handleRemoveHarness = useCallback(() => {
    onChange({ harness: "all" });
  }, [onChange]);

  const handleRemoveCategory = useCallback(() => {
    onChange({ category: "" });
  }, [onChange]);

  const handleRemoveSourceScope = useCallback(() => {
    onChange({ sourceScope: "" });
  }, [onChange]);

  const handleToggleMore = useCallback(() => {
    setShowMore((prev) => !prev);
  }, []);

  const hasActiveFilters =
    filters.search ||
    filters.time !== "all" ||
    filters.decision !== "all" ||
    (!hideHarnessFilter && filters.harness !== "all") ||
    filters.category ||
    filters.sourceScope ||
    filters.day;

  const isFiltered = filteredCount !== totalCount;

  return (
    <div className="space-y-1.5" aria-label="Evidence filters">
      <div className="flex flex-wrap items-center gap-1.5">
        <SearchInput value={filters.search} onChange={handleSearchChange} />

        <select
          value={filters.time}
          onChange={handleTimeChange}
          aria-label="Time period"
          className="min-h-8 rounded-lg border border-slate-200 bg-white px-2 text-xs font-medium text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        >
          {(Object.entries(EVIDENCE_TIME_LABELS) as [EvidenceTimeFilter, string][]).map(
            ([val, label]) => (
              <option key={val} value={val}>
                {label}
              </option>
            )
          )}
        </select>

        <select
          value={filters.decision}
          onChange={handleDecisionChange}
          aria-label="Decision filter"
          className="min-h-8 rounded-lg border border-slate-200 bg-white px-2 text-xs font-medium text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        >
          {(Object.entries(EVIDENCE_DECISION_LABELS) as [EvidenceDecision, string][]).map(
            ([val, label]) => (
              <option key={val} value={val}>
                {label}
              </option>
            )
          )}
        </select>

        <button
          type="button"
          onClick={handleToggleMore}
          aria-expanded={showMore}
          aria-label="Toggle more filters"
          className="inline-flex min-h-8 items-center gap-1 rounded-lg border border-slate-200 bg-white px-2 text-xs font-medium text-brand-dark hover:bg-slate-50 transition-colors"
        >
          <HiFunnel className="h-3.5 w-3.5" aria-hidden="true" />
          {showMore ? (
            <HiMiniChevronUp className="h-3 w-3" aria-hidden="true" />
          ) : (
            <HiMiniChevronDown className="h-3 w-3" aria-hidden="true" />
          )}
        </button>
      </div>

      {showMore && (
        <div className="flex flex-wrap items-center gap-1.5 rounded-lg bg-slate-50/60 p-2">
          {!hideHarnessFilter && (
            <select
              value={filters.harness}
              onChange={handleHarnessChange}
              aria-label="App filter"
              className="min-h-8 rounded-lg border border-slate-200 bg-white px-2 text-xs font-medium text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
            >
              <option value="all">All apps</option>
              {harnesses.map((h) => (
                <option key={h} value={h}>
                  {harnessDisplayName(h)}
                </option>
              ))}
            </select>
          )}

          <select
            value={filters.category}
            onChange={handleCategoryChange}
            aria-label="Category filter"
            className="min-h-8 rounded-lg border border-slate-200 bg-white px-2 text-xs font-medium text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          >
            {CATEGORY_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>

          <label className="flex items-center gap-1.5 text-xs text-brand-dark">
            <span className="shrink-0 text-xs font-medium text-slate-500">
              Scope:
            </span>
            <input
              type="text"
              value={filters.sourceScope}
              onChange={handleSourceScopeChange}
              placeholder="e.g. workspace, global"
              className="min-h-8 rounded-md border border-slate-200 bg-white px-2 text-xs text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20"
            />
          </label>
          {filters.day && (
            <span className="text-xs text-slate-500">
              Day: <strong>{filters.day}</strong>
            </span>
          )}
        </div>
      )}

      {hasActiveFilters && (
        <div className="flex flex-wrap items-center gap-1">
          {filters.search && (
            <ActiveChip label={`"${filters.search}"`} onRemove={handleRemoveSearch} />
          )}
          {filters.time !== "all" && (
            <ActiveChip
              label={EVIDENCE_TIME_LABELS[filters.time]}
              onRemove={handleRemoveTime}
            />
          )}
          {filters.day && (
            <ActiveChip label={`Day: ${filters.day}`} onRemove={handleRemoveTime} />
          )}
          {filters.decision !== "all" && (
            <ActiveChip
              label={EVIDENCE_DECISION_LABELS[filters.decision]}
              onRemove={handleRemoveDecision}
            />
          )}
          {filters.harness !== "all" && !hideHarnessFilter && (
            <ActiveChip
              label={harnessDisplayName(filters.harness)}
              onRemove={handleRemoveHarness}
            />
          )}
          {filters.category && (
            <ActiveChip
              label={
                CATEGORY_OPTIONS.find((c) => c.value === filters.category)?.label ??
                filters.category
              }
              onRemove={handleRemoveCategory}
            />
          )}
          {filters.sourceScope && (
            <ActiveChip
              label={`Scope: ${filters.sourceScope}`}
              onRemove={handleRemoveSourceScope}
            />
          )}
          <button
            type="button"
            onClick={handleClearAll}
            className="ml-1 text-xs font-medium text-brand-blue hover:text-brand-dark transition-colors"
          >
            Clear all
          </button>
        </div>
      )}

      <p className="text-[11px] text-slate-400">
        {isFiltered
          ? `${filteredCount} of ${totalCount} shown`
          : `${totalCount} total`}
      </p>
    </div>
  );
}
