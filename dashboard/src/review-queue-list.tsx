import { forwardRef, useCallback, useMemo, useState, type ChangeEvent } from "react";
import { EmptyState, SectionLabel } from "./approval-center-primitives";
import { harnessDisplayName } from "./approval-center-utils";
import type { GuardApprovalRequest } from "./guard-types";
import {
  resolveQueueCategory,
  REVIEW_SEMANTIC_GROUPS,
  type QueueCategory,
  type QueueCategoryId,
  type QueueSortDirection,
  type SemanticGroupId,
} from "./queue-state";
import { REQUEST_READ_STATE_LIMIT, type RequestReadState } from "./request-read-state";
import { QueueItemRow } from "./review-queue-item";

const QUEUE_PAGE_SIZE = 10;

export function ReviewHeader({
  count,
  filteredCount,
  progress,
  activeHarness,
}: {
  count: number;
  filteredCount: number;
  progress: string;
  activeHarness: string;
}) {
  const isFiltered = filteredCount !== count;
  return (
    <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
      <div>
        <h1 className="text-xl font-semibold tracking-[-0.02em] text-brand-dark sm:text-2xl">Review</h1>
        <p className="mt-1 max-w-xl text-sm leading-relaxed text-muted-foreground">
          Guard paused these actions before they ran. Review each one and decide what should happen.
        </p>
      </div>
      <p className="text-sm text-muted-foreground">
        {progress}{isFiltered ? ` · ${filteredCount} of ${count} shown` : ""} · from {harnessDisplayName(activeHarness)}
      </p>
    </div>
  );
}

function resolveSemanticGroup(categoryId: QueueCategoryId): SemanticGroupId {
  for (const group of REVIEW_SEMANTIC_GROUPS) {
    if (group.matches.includes(categoryId)) return group.id;
  }
  return "other";
}

export const ReviewQueueList = forwardRef<HTMLDivElement, {
  requests: GuardApprovalRequest[];
  allFilteredRequests: GuardApprovalRequest[];
  totalCount: number;
  filteredCount: number;
  activeRequestId: string | null;
  readState: RequestReadState;
  categoryOptions: QueueCategory[];
  categoryFilter: QueueCategoryId | "all";
  searchTerm: string;
  sortDirection: QueueSortDirection;
  semanticFilter: SemanticGroupId;
  dateFrom: string;
  dateTo: string;
  page: number;
  totalPages: number;
  onCategoryFilterChange: (category: QueueCategoryId | "all") => void;
  onSearchTermChange: (term: string) => void;
  onSortDirectionChange: (direction: QueueSortDirection) => void;
  onSemanticFilterChange: (group: SemanticGroupId) => void;
  onDateFromChange: (date: string) => void;
  onDateToChange: (date: string) => void;
  onPageChange: (page: number) => void;
  onOpenRequest: (requestId: string) => void;
  selectionMode?: boolean;
  isBulkSelectable?: (item: GuardApprovalRequest) => boolean;
  isBulkSelected?: (item: GuardApprovalRequest) => boolean;
  onBulkToggleSelect?: (item: GuardApprovalRequest) => void;
  onBulkSelectAll?: () => void;
  onBulkClearAll?: () => void;
}>(({
  requests,
  allFilteredRequests,
  totalCount,
  filteredCount,
  activeRequestId,
  readState,
  categoryOptions,
  categoryFilter,
  searchTerm,
  sortDirection,
  semanticFilter,
  dateFrom,
  dateTo,
  page,
  totalPages,
  onCategoryFilterChange,
  onSearchTermChange,
  onSortDirectionChange,
  onSemanticFilterChange,
  onDateFromChange,
  onDateToChange,
  onPageChange,
  onOpenRequest,
  selectionMode = false,
  isBulkSelectable,
  isBulkSelected,
  onBulkToggleSelect,
  onBulkSelectAll,
  onBulkClearAll,
}, ref) => {
  const [showFilters, setShowFilters] = useState(false);

  const handleSearchChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    onSearchTermChange(event.target.value);
  }, [onSearchTermChange]);
  const handleCategoryChange = useCallback((event: ChangeEvent<HTMLSelectElement>) => {
    onCategoryFilterChange(event.target.value as QueueCategoryId | "all");
  }, [onCategoryFilterChange]);
  const handleSortChange = useCallback((event: ChangeEvent<HTMLSelectElement>) => {
    onSortDirectionChange(event.target.value as QueueSortDirection);
  }, [onSortDirectionChange]);
  const handleDateFromChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    onDateFromChange(event.target.value);
  }, [onDateFromChange]);
  const handleDateToChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    onDateToChange(event.target.value);
  }, [onDateToChange]);
  const handleToggleFilters = useCallback(() => {
    setShowFilters((visible) => !visible);
  }, []);
  const handleClearFilters = useCallback(() => {
    onSearchTermChange("");
    onCategoryFilterChange("all");
    onSortDirectionChange("newest");
    onSemanticFilterChange("all");
    onDateFromChange("");
    onDateToChange("");
  }, [
    onCategoryFilterChange,
    onDateFromChange,
    onDateToChange,
    onSearchTermChange,
    onSemanticFilterChange,
    onSortDirectionChange,
  ]);
  const handlePreviousPage = useCallback(() => {
    onPageChange(Math.max(1, page - 1));
  }, [page, onPageChange]);
  const handleNextPage = useCallback(() => {
    onPageChange(Math.min(totalPages, page + 1));
  }, [page, totalPages, onPageChange]);

  const activeSemanticGroup = semanticFilter;

  const visibleGroups = useMemo(() => {
    const available = new Set<SemanticGroupId>();
    for (const item of allFilteredRequests) {
      available.add(resolveSemanticGroup(resolveQueueCategory(item).id));
    }
    return REVIEW_SEMANTIC_GROUPS.filter((g) => g.id === "all" || available.has(g.id));
  }, [allFilteredRequests]);

  const isFiltered =
    searchTerm ||
    semanticFilter !== "all" ||
    categoryFilter !== "all" ||
    sortDirection !== "newest" ||
    dateFrom ||
    dateTo;
  const showPagination = filteredCount > QUEUE_PAGE_SIZE;

  // Page-level select-all state for the compact list header. Reflects only the
  // currently visible rows so the checkbox behaves like a standard list header
  // (indeterminate when some-but-not-all eligible rows on the page are selected).
  const pageSelectableItems = useMemo(
    () => requests.filter((item) => isBulkSelectable?.(item) === true),
    [requests, isBulkSelectable],
  );
  const pageSelectedCount = useMemo(
    () => pageSelectableItems.filter((item) => isBulkSelected?.(item) === true).length,
    [pageSelectableItems, isBulkSelected],
  );
  const pageAllSelected =
    pageSelectableItems.length > 0 && pageSelectedCount === pageSelectableItems.length;
  const pageSomeSelected = pageSelectedCount > 0 && !pageAllSelected;

  const handlePageSelectAll = useCallback(() => {
    if (pageAllSelected) {
      onBulkClearAll?.();
    } else {
      onBulkSelectAll?.();
    }
  }, [pageAllSelected, onBulkSelectAll, onBulkClearAll]);

  // Stable ref callback so React does not detach/reattach it every render.
  const setIndeterminate = useCallback(
    (el: HTMLInputElement | null) => {
      if (el) el.indeterminate = pageSomeSelected;
    },
    [pageSomeSelected],
  );

  return (
    <aside className="space-y-3" ref={ref}>
      <div className="flex items-center justify-between gap-3">
        <SectionLabel>Queue</SectionLabel>
        <div className="flex items-center gap-3">
          <button
            type="button"
            disabled={
              allFilteredRequests.length > 0 &&
              allFilteredRequests.length +
                readState.readCount -
                allFilteredRequests.filter((item) => readState.isRead(item.request_id)).length >
                REQUEST_READ_STATE_LIMIT
            }
            title={
              allFilteredRequests.length +
                readState.readCount -
                allFilteredRequests.filter((item) => readState.isRead(item.request_id)).length >
                REQUEST_READ_STATE_LIMIT
                ? `Cannot mark all read: doing so would exceed the read-state storage cap (${REQUEST_READ_STATE_LIMIT.toLocaleString()}). Reduce filters to shrink the visible queue, or mark requests read one by one.`
                : `Marks every visible filtered request as read (remembering up to ${REQUEST_READ_STATE_LIMIT.toLocaleString()}).`
            }
            onClick={() => readState.markAllRead(allFilteredRequests.map((item) => item.request_id))}
            className={`text-xs font-medium transition-colors ${
              allFilteredRequests.length +
                readState.readCount -
                allFilteredRequests.filter((item) => readState.isRead(item.request_id)).length >
                REQUEST_READ_STATE_LIMIT
                ? "text-slate-400 cursor-not-allowed"
                : "text-brand-blue hover:text-brand-dark"
            }`}
          >
            Mark all read
          </button>
          <span className="font-mono text-[11px] font-semibold text-muted-foreground">
            {filteredCount}/{totalCount}
          </span>
        </div>
      </div>
      <div className="space-y-2 rounded-xl border border-slate-100 bg-white p-3">
        <label className="block">
          <span className="sr-only">Search review queue</span>
          <input
            id="guard-review-queue-search"
            name="guard-review-queue-search"
            type="search"
            value={searchTerm}
            onChange={handleSearchChange}
            placeholder="Search queue..."
            className="min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          />
        </label>
        <button
          type="button"
          onClick={handleToggleFilters}
          className="flex items-center gap-1 text-xs font-medium text-brand-blue hover:text-brand-dark transition-colors"
        >
          {showFilters ? "Hide filters" : "Show filters"}
          {isFiltered && !showFilters && <span className="ml-1 h-1.5 w-1.5 rounded-full bg-brand-attention" />}
        </button>
        {showFilters && (
          <div className="space-y-2">
            <div className="flex flex-wrap gap-1">
              {visibleGroups.map((group) => (
                <SemanticFilterButton
                  key={group.id}
                  group={group}
                  selected={activeSemanticGroup === group.id}
                  onSelect={onSemanticFilterChange}
                />
              ))}
            </div>
            <label className="block">
              <span className="mb-1 block text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                Sort by date
              </span>
              <select
                value={sortDirection}
                onChange={handleSortChange}
                aria-label="Sort review queue"
                className="min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
              >
                <option value="newest">Newest first</option>
                <option value="oldest">Oldest first</option>
                <option value="highest_risk">Highest risk first</option>
                <option value="category">Category</option>
              </select>
            </label>
            <div className="grid gap-2 sm:grid-cols-2">
              <label className="block">
                <span className="mb-1 block text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                  From date
                </span>
                <input
                  type="date"
                  value={dateFrom}
                  onChange={handleDateFromChange}
                  aria-label="Filter requests from date"
                  className="min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                />
              </label>
              <label className="block">
                <span className="mb-1 block text-[11px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">
                  To date
                </span>
                <input
                  type="date"
                  value={dateTo}
                  onChange={handleDateToChange}
                  aria-label="Filter requests to date"
                  className="min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                />
              </label>
            </div>
            {isFiltered && (
              <button
                type="button"
                onClick={handleClearFilters}
                className="text-xs font-medium text-brand-blue hover:text-brand-dark transition-colors"
              >
                Clear all filters
              </button>
            )}
          </div>
        )}
      </div>
      <div
        role="listbox"
        aria-label="Review queue"
        className="space-y-2 rounded-lg border border-slate-100 bg-white p-1.5"
      >
        {selectionMode && pageSelectableItems.length > 0 && (
          <div className="flex items-center gap-2 border-b border-slate-100 px-2 pb-1.5 pt-1">
            <label className="flex shrink-0 cursor-pointer items-center gap-2">
              <input
                type="checkbox"
                checked={pageAllSelected}
                ref={setIndeterminate}
                onChange={handlePageSelectAll}
                aria-label={
                  pageAllSelected
                    ? "Clear selection of eligible reads on this page"
                    : "Select all eligible reads on this page"
                }
                className="h-4 w-4 rounded border-slate-300 text-brand-blue focus:ring-brand-blue/30"
              />
              <span className="text-[11px] font-medium text-muted-foreground">
                {pageSelectedCount > 0
                  ? `${pageSelectedCount} of ${pageSelectableItems.length} selected`
                  : `Select all eligible (${pageSelectableItems.length})`}
              </span>
            </label>
          </div>
        )}
        {requests.length > 0 ? (
          requests.map((item, index) => (
            <QueueItemRow
              key={item.request_id}
              item={item}
              active={item.request_id === activeRequestId}
              readState={readState}
              index={index}
              onOpenRequest={onOpenRequest}
              selectionMode={selectionMode}
              selectable={isBulkSelectable?.(item) === true}
              selected={isBulkSelected?.(item) === true}
              onToggleSelect={onBulkToggleSelect}
            />
          ))
        ) : (
          <div className="px-3 py-5">
            <EmptyState title="No matching actions" body="Try a different search or filter." tone="teach" />
          </div>
        )}
      </div>
      {showPagination && (
        <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
          <span>
            {((page - 1) * QUEUE_PAGE_SIZE) + 1}-{Math.min(filteredCount, page * QUEUE_PAGE_SIZE)} of {filteredCount}
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handlePreviousPage}
              disabled={page <= 1}
              className="min-h-9 rounded-lg border border-slate-200 bg-white px-3 font-semibold text-brand-dark transition-colors duration-150 hover:border-brand-blue/30 disabled:pointer-events-none disabled:opacity-40"
            >
              Previous
            </button>
            <span className="font-mono text-[11px] text-slate-400">
              {page}/{totalPages}
            </span>
            <button
              type="button"
              onClick={handleNextPage}
              disabled={page >= totalPages}
              className="min-h-9 rounded-lg border border-slate-200 bg-white px-3 font-semibold text-brand-dark transition-colors duration-150 hover:border-brand-blue/30 disabled:pointer-events-none disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </aside>
  );
});
ReviewQueueList.displayName = "ReviewQueueList";

function SemanticFilterButton(props: {
  group: (typeof REVIEW_SEMANTIC_GROUPS)[number];
  selected: boolean;
  onSelect: (group: SemanticGroupId) => void;
}) {
  const { group, selected, onSelect } = props;
  const handleSelect = useCallback(() => {
    onSelect(group.id);
  }, [group.id, onSelect]);

  return (
    <button
      type="button"
      onClick={handleSelect}
      className={`rounded-full px-2.5 py-1 text-[11px] font-medium transition-all ${
        selected
          ? "bg-brand-blue text-white"
          : "border border-slate-200 bg-white text-brand-dark hover:bg-slate-50"
      }`}
    >
      {group.label}
    </button>
  );
}
