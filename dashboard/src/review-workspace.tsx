import { forwardRef, useCallback, useEffect, useMemo, useRef, useState, type ChangeEvent } from "react";
import {
  HiMiniCheckCircle,
  HiMiniNoSymbol,
  HiMiniShieldCheck,
  HiMiniExclamationTriangle,
  HiMiniInformationCircle,
  HiMiniChevronLeft,
  HiMiniDocumentText,
  HiMiniArrowPath,
  HiMiniChevronDown,
  HiMiniChevronUp,
  HiMiniArrowTopRightOnSquare,
  HiMiniClock,
  HiMiniClipboardDocumentCheck,
  HiMiniCodeBracket,
  HiMiniCommandLine,
  HiMiniCog6Tooth,
  HiMiniCube,
  HiMiniDocumentMagnifyingGlass,
  HiMiniDocumentPlus,
  HiMiniGlobeAlt,
  HiMiniKey,
  HiMiniPencilSquare,
  HiMiniServerStack,
} from "react-icons/hi2";
import {
  ActionButton,
  Badge,
  EmptyState,
  SectionLabel,
  Tag,
  GuardHero,
  ProofStrip,
} from "./approval-center-primitives";
import {
  buildRetryAfterApprovalCopy,
  buildPrimaryReviewAction,
  resolveSecondaryRiskSummary,
  harnessDisplayName,
  displayArtifactName,
  formatRelativeTime,
  buildCodexResumeUx,
} from "./approval-center-utils";
import {
  SkillRiskCard,
  SupplyChainRiskCard,
  DecodedLayerCard,
} from "./risk-signal-cards";
import { DataFlowEvidenceCard } from "./data-flow-evidence-card";
import { ScannerEvidenceSection } from "./scanner-evidence-badge";
import {
  advancedScopeChoicesForRequest,
  buildDecisionPayload,
  normalizeDecisionScope,
  standardScopeChoicesForRequest,
} from "./approval-scopes";
import { ConsolidatedEvidenceAlert, type EvidenceItem } from "./consolidated-evidence-alert";
import { useRequestReadState, type RequestReadState, REQUEST_READ_STATE_LIMIT } from "./request-read-state";
import {
  deriveDataFlowEvidence,
  deriveSkillRiskSignals,
  deriveSupplyChainRiskSignals,
  deriveEncodedLayerSignals,
} from "./approval-center-utils";
import type {
  GuardApprovalGatePublicConfig,
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardCodexResumeResult,
  GuardPolicyDecision,
  GuardReceipt,
  GuardRuntimeSnapshot,
  DecisionScope,
} from "./guard-types";
import {
  filterQueueByCategory,
  filterQueueByDateRange,
  formatQueueRequestDate,
  queueCategoriesForItems,
  resolveQueueCategory,
  searchQueue,
  sortQueue,
  REVIEW_SEMANTIC_GROUPS,
  type QueueCategory,
  type QueueCategoryId,
  type QueueSortDirection,
  type SemanticGroupId,
} from "./queue-state";
import { plainEnglishRequestTitle, whyPaused } from "./evidence/plain-english";
import { requiresApprovalPasswordPrompt, type BulkGateCredentials } from "./approval-gate-utils";
import { ApprovalPasswordModal } from "./approval-center-review-cards";
import { approvalProofRequiresPassword } from "./approval-proof-inline";
import { guardAwareHref } from "./guard-api";
import { LoggedActionPanel } from "./logged-action-panel";
import {
  QueueBulkDrawer,
  QueueBulkGatePrompt,
  QueueBulkStickyBar,
  QueueBulkStatusBanner,
} from "./queue-bulk-approve-flow";
import { useQueueBulkApprove } from "./use-queue-bulk-approve";

export type ReviewViewModel = {
  item: GuardApprovalRequest;
  diff: GuardArtifactDiff | null;
  receipt: GuardReceipt | null;
  policy: GuardPolicyDecision[];
};

type ReviewWorkspaceProps = {
  requests: GuardApprovalRequest[];
  activeRequestId: string | null;
  detail: ReviewViewModel | null;
  runtime: GuardRuntimeSnapshot | null;
  resolutionMessage: string | null;
  codexResume: GuardCodexResumeResult | null;
  approvalGate?: GuardApprovalGatePublicConfig | null;
  onRetryResume?: () => void;
  onOpenRequest: (requestId: string) => void;
  onResolve: (payload: {
    requestId: string;
    action: "allow" | "block";
    scope: DecisionScope;
    workspace?: string;
    reason: string;
    approval_password?: string;
    approval_totp_code?: string;
    approval_gate_use_cooldown?: boolean;
  }) => Promise<void> | void;
  onGoHome: () => void;
  onBulkApprove?: (ids: string[], gateCredentials?: BulkGateCredentials) => void | Promise<void>;
};

const scopeChoices = [
  {
    value: "artifact" as DecisionScope,
    label: "Just this time",
    description: "Allow only this exact action. Guard will ask again for anything different.",
  },
  {
    value: "workspace" as DecisionScope,
    label: "This project",
    description: "Allow this action in the current workspace only.",
  },
  {
    value: "publisher" as DecisionScope,
    label: "This source",
    description: "Allow actions from the same source or publisher.",
  },
  {
    value: "harness" as DecisionScope,
    label: "This app",
    description: "Allow similar actions from this AI app everywhere.",
  },
  {
    value: "global" as DecisionScope,
    label: "Everywhere",
    description: "Allow this action across all your projects. Use with care.",
  },
];

const QUEUE_PAGE_SIZE = 10;
const commonScopeValues = new Set<DecisionScope>(["artifact"]);

export function ReviewWorkspace(props: ReviewWorkspaceProps) {
  const { requests, activeRequestId, detail } = props;
  const readState = useRequestReadState();
  const queueRef = useRef<HTMLDivElement>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<QueueCategoryId | "all">("all");
  const [sortDirection, setSortDirection] = useState<QueueSortDirection>("newest");
  const [semanticFilter, setSemanticFilter] = useState<SemanticGroupId>("all");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [mobileQueueOpen, setMobileQueueOpen] = useState(false);
  const [page, setPage] = useState(1);

  const selectRequest = useCallback((id: string) => {
    props.onOpenRequest(id);
    setMobileQueueOpen(false);
  }, [props.onOpenRequest]);

  const handleOpenRequest = useCallback((id: string) => {
    selectRequest(id);
    readState.markRead(id);
  }, [selectRequest, readState]);

  const handleToggleMobileQueue = useCallback(() => {
    setMobileQueueOpen((v) => !v);
  }, []);

  const filteredRequests = useMemo(() => {
    let items = requests;
    if (semanticFilter !== "all") {
      const group = REVIEW_SEMANTIC_GROUPS.find((g) => g.id === semanticFilter);
      if (group && group.matches.length > 0) {
        items = items.filter((item) => group.matches.includes(resolveQueueCategory(item).id));
      }
    } else if (categoryFilter !== "all") {
      items = filterQueueByCategory(items, categoryFilter);
    }
    items = filterQueueByDateRange(items, { from: dateFrom, to: dateTo });
    const searched = searchQueue(items, searchTerm);
    return sortQueue(searched, sortDirection);
  }, [categoryFilter, dateFrom, dateTo, requests, searchTerm, sortDirection, semanticFilter]);

  useEffect(() => {
    setPage(1);
  }, [searchTerm, categoryFilter, sortDirection, semanticFilter, dateFrom, dateTo]);

  const totalPages = Math.max(1, Math.ceil(filteredRequests.length / QUEUE_PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const pageStart = (currentPage - 1) * QUEUE_PAGE_SIZE;
  const pagedRequests = filteredRequests.slice(pageStart, pageStart + QUEUE_PAGE_SIZE);

  const categoryOptions = useMemo(() => queueCategoriesForItems(requests), [requests]);

  const activeRequest =
    activeRequestId !== null
      ? requests.find((r) => r.request_id === activeRequestId) ??
        (detail?.item.request_id === activeRequestId ? detail.item : null)
      : null;

  useEffect(() => {
    function isNestedQueueActionButton(target: EventTarget | null): boolean {
      return (
        target instanceof HTMLElement &&
        target.tagName.toLowerCase() === "button" &&
        target.getAttribute("role") !== "option"
      );
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (pagedRequests.length === 0) return;
      // Only fire queue navigation when focus is inside the review queue listbox
      // and not on a nested action button such as "Mark unread".
      if (
        !(event.target instanceof HTMLElement) ||
        !event.target.closest('[role="listbox"]') ||
        isNestedQueueActionButton(event.target)
      )
        return;
      const activeIdx = pagedRequests.findIndex((r) => r.request_id === activeRequestId);
      if (event.key === "ArrowDown") {
        event.preventDefault();
        const nextIdx = Math.min(activeIdx + 1, pagedRequests.length - 1);
        if (nextIdx !== activeIdx) handleOpenRequest(pagedRequests[nextIdx].request_id);
      }
      if (event.key === "ArrowUp") {
        event.preventDefault();
        const prevIdx = Math.max(activeIdx - 1, 0);
        if (prevIdx !== activeIdx) handleOpenRequest(pagedRequests[prevIdx].request_id);
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [pagedRequests, activeRequestId, handleOpenRequest]);

  useEffect(() => {
    if (filteredRequests.length === 0) {
      return;
    }
    const activeInRequests =
      requests.some((item) => item.request_id === activeRequestId) ||
      detail?.item.request_id === activeRequestId;
    if (activeRequestId !== null && activeInRequests) {
      return;
    }
    selectRequest(filteredRequests[0].request_id);
  }, [activeRequestId, requests, filteredRequests, detail?.item.request_id, selectRequest]);

  useEffect(() => {
    if (pagedRequests.length === 0) return;
    const activeOnPage =
      pagedRequests.some((item) => item.request_id === activeRequestId) ||
      detail?.item.request_id === activeRequestId;
    if (!activeOnPage) {
      selectRequest(pagedRequests[0].request_id);
    }
  }, [currentPage, pagedRequests, activeRequestId, detail?.item.request_id, selectRequest]);

  const bulkApprove = useQueueBulkApprove({
    items: filteredRequests,
    approvalGate: props.approvalGate ?? null,
    onBulkApprove: props.onBulkApprove,
    settingsHref: guardAwareHref("/settings"),
  });

  // Global bulk-selection shortcuts (only active in ambient selection mode).
  // Cmd/Ctrl+A selects all eligible in the filtered queue; Esc clears.
  useEffect(() => {
    if (!bulkApprove.bulkSelection.selectionMode) return;
    function handleBulkShortcut(event: KeyboardEvent) {
      const target = event.target as HTMLElement | null;
      if (
        target &&
        (target.tagName === "INPUT" ||
          target.tagName === "TEXTAREA" ||
          target.tagName === "SELECT" ||
          target.isContentEditable)
      ) {
        return;
      }
      if ((event.metaKey || event.ctrlKey) && (event.key === "a" || event.key === "A")) {
        event.preventDefault();
        bulkApprove.bulkSelection.onToggleMany(filteredRequests, true);
        return;
      }
      if (event.key === "Escape") {
        // Escape closes the review drawer first (standard modal behavior);
        // only when the drawer is shut does it clear the background selection.
        if (bulkApprove.drawer.open) {
          event.preventDefault();
          bulkApprove.drawer.onCancel();
        } else if (bulkApprove.bulkSelection.selectedGroupCount > 0) {
          event.preventDefault();
          bulkApprove.bulkSelection.onToggleMany(filteredRequests, false);
        }
      }
    }
    window.addEventListener("keydown", handleBulkShortcut);
    return () => window.removeEventListener("keydown", handleBulkShortcut);
  }, [
    bulkApprove.bulkSelection,
    bulkApprove.bulkSelection.selectedGroupCount,
    bulkApprove.drawer.open,
    bulkApprove.drawer.onCancel,
    filteredRequests,
  ]);

  if (requests.length === 0) {
    return <ReviewEmptyState runtime={props.runtime} resolutionMessage={props.resolutionMessage} codexResume={props.codexResume} onRetryResume={props.onRetryResume} />;
  }

  const activeItem = activeRequest ?? filteredRequests[0] ?? requests[0];

  const progressIndex = filteredRequests.findIndex((r) => r.request_id === activeItem.request_id);
  const progress =
    filteredRequests.length > 0
      ? `${Math.max(0, progressIndex) + 1} of ${filteredRequests.length}`
      : `0 of ${requests.length}`;

  return (
    <div className="space-y-6">
      <ReviewHeader
        count={requests.length}
        filteredCount={filteredRequests.length}
        progress={progress}
        activeHarness={activeItem.harness}
      />

      <QueueBulkStatusBanner
        visible={bulkApprove.status.visible}
        sensitiveFileReadCount={bulkApprove.status.sensitiveFileReadCount}
      />
      <QueueBulkGatePrompt
        visible={bulkApprove.gatePrompt.visible}
        eligibleActionCount={bulkApprove.gatePrompt.eligibleActionCount}
        settingsHref={bulkApprove.gatePrompt.settingsHref}
      />
      <QueueBulkStickyBar {...bulkApprove.stickyBar} />
      {bulkApprove.bulkSelection.selectionMode && (
        <span aria-live="polite" className="sr-only">
          {bulkApprove.bulkSelection.selectedActionCount} of {filteredRequests.length} reads selected for bulk approval.
        </span>
      )}
      <QueueBulkDrawer {...bulkApprove.drawer} />

      <div className="md:hidden">
        <button
          onClick={handleToggleMobileQueue}
          className="flex w-full items-center justify-between rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm font-medium text-brand-dark"
        >
          <span>Queue ({filteredRequests.length})</span>
          <HiMiniChevronDown className={`h-4 w-4 transition-transform ${mobileQueueOpen ? "rotate-180" : ""}`} />
        </button>
      </div>

      <div className="grid gap-4 md:grid-cols-[320px_minmax(0,1fr)] lg:grid-cols-[340px_minmax(0,1fr)] xl:grid-cols-[360px_minmax(0,1fr)] items-start">
        <div className={`${mobileQueueOpen ? "block" : "hidden"} md:block`}>
          <ReviewQueueList
            requests={pagedRequests}
            allFilteredRequests={filteredRequests}
            totalCount={requests.length}
            filteredCount={filteredRequests.length}
            activeRequestId={activeItem.request_id}
            readState={readState}
            categoryOptions={categoryOptions}
            categoryFilter={categoryFilter}
            searchTerm={searchTerm}
            sortDirection={sortDirection}
            semanticFilter={semanticFilter}
            dateFrom={dateFrom}
            dateTo={dateTo}
            page={currentPage}
            totalPages={totalPages}
            onCategoryFilterChange={setCategoryFilter}
            onSearchTermChange={setSearchTerm}
            onSortDirectionChange={setSortDirection}
            onSemanticFilterChange={setSemanticFilter}
            onDateFromChange={setDateFrom}
            onDateToChange={setDateTo}
            onPageChange={setPage}
            onOpenRequest={handleOpenRequest}
            selectionMode={bulkApprove.bulkSelection.selectionMode}
            isBulkSelectable={bulkApprove.bulkSelection.isSelectable}
            isBulkSelected={bulkApprove.bulkSelection.isSelected}
            onBulkToggleSelect={bulkApprove.bulkSelection.onToggle}
            onBulkSelectAll={() => bulkApprove.bulkSelection.onToggleMany(pagedRequests, true)}
            onBulkClearAll={() => bulkApprove.bulkSelection.onToggleMany(pagedRequests, false)}
            ref={queueRef}
          />
        </div>
        <ReviewDecisionCard
          detail={detail}
          onResolve={props.onResolve}
          onGoHome={props.onGoHome}
          approvalGate={props.approvalGate ?? null}
        />
      </div>
    </div>
  );
}

function ReviewHeader({
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

const ReviewQueueList = forwardRef<HTMLDivElement, {
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

function QueueItemRow({ item, active, readState, index, onOpenRequest, selectionMode = false, selectable = false, selected = false, onToggleSelect }: {
  item: GuardApprovalRequest;
  active: boolean;
  readState: RequestReadState;
  index: number;
  onOpenRequest: (requestId: string) => void;
  selectionMode?: boolean;
  selectable?: boolean;
  selected?: boolean;
  onToggleSelect?: (item: GuardApprovalRequest) => void;
}) {
  const isBlocked = item.policy_action === "block";
  const category = resolveQueueCategory(item);
  const CategoryIcon = iconForQueueCategory(category.id);
  const preview = queueItemPreview(item);
  const isRead = readState.isRead(item.request_id);
  // Checkboxes render whenever bulk selection is active so the affordance is
  // always discoverable. Non-eligible rows show a disabled checkbox with a
  // tooltip instead of silently hiding the control.
  const showCheckbox = selectionMode;
  const canSelect = selectionMode && selectable;

  const handleClick = useCallback(() => {
    onOpenRequest(item.request_id);
  }, [item.request_id, onOpenRequest]);

  const handleCheckboxChange = useCallback(
    (event: ChangeEvent<HTMLInputElement>) => {
      event.stopPropagation();
      if (!canSelect) return;
      onToggleSelect?.(item);
    },
    [item, onToggleSelect, canSelect],
  );

  const handleKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLLabelElement>) => {
      if (!canSelect) return;
      // Space is handled natively by the checkbox itself; only remap Enter
      // here so the wrapping label is also keyboard-activatable.
      if (event.key === "Enter") {
        event.preventDefault();
        event.stopPropagation();
        onToggleSelect?.(item);
      }
    },
    [item, onToggleSelect, canSelect],
  );

  const checkboxLabel = canSelect
    ? `Select ${preview} for bulk approval`
    : `Not eligible for bulk approval: ${category.shortLabel.toLowerCase()}`;

  return (
    <div
      role="none"
      className={`group w-full rounded-lg py-2.5 px-2 transition-all ${
        selected
          ? "border border-brand-blue/60 bg-brand-blue/[0.08] ring-1 ring-brand-blue/20"
          : active
            ? "border border-brand-blue bg-brand-blue/[0.06]"
            : "border border-transparent bg-white hover:bg-slate-50"
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        {showCheckbox ? (
          <label
            className={`flex shrink-0 items-center ${canSelect ? "cursor-pointer" : "cursor-not-allowed"}`}
            title={checkboxLabel}
            onClick={(event) => event.stopPropagation()}
            onKeyDown={handleKeyDown}
          >
            <input
              type="checkbox"
              checked={selected}
              disabled={!canSelect}
              onChange={handleCheckboxChange}
              aria-label={checkboxLabel}
              className="h-4 w-4 rounded border-slate-300 text-brand-blue focus:ring-brand-blue/30 disabled:opacity-40"
            />
          </label>
        ) : null}
        <button
          type="button"
          onClick={handleClick}
          role="option"
          aria-selected={active}
          aria-posinset={index + 1}
          aria-setsize={undefined}
          tabIndex={active ? 0 : -1}
          className="flex min-w-0 flex-1 items-center gap-2 text-left"
        >
          <span
            className={`h-2 w-2 shrink-0 rounded-full border-2 transition-colors ${
              isRead
                ? "border-slate-300 bg-transparent"
                : "border-transparent bg-brand-blue"
            }`}
            title={isRead ? "Read" : "Unread"}
            aria-label={isRead ? "Read" : "Unread"}
          />
          <div className="min-w-0 flex-1">
            <p className={`truncate text-sm ${isRead ? "font-medium text-slate-600" : "font-bold text-brand-dark"}`}>
              {!isRead && <span className="sr-only">Unread request:</span>}
              {preview}
            </p>
            <p className="truncate text-[11px] text-muted-foreground">
              {harnessDisplayName(item.harness)} · {category.shortLabel} · {formatQueueRequestDate(item)}
            </p>
          </div>
          <span
            className={`inline-flex h-2 w-2 shrink-0 rounded-full ${
              isBlocked ? "bg-brand-attention" : "bg-emerald-400"
            }`}
            title={isBlocked ? "Blocked by policy" : "Allowed by policy"}
            aria-label={isBlocked ? "Blocked by policy" : "Allowed by policy"}
          />
          <span
            className={`inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg ${
              active ? "bg-brand-blue/10 text-brand-blue" : "bg-slate-50 text-slate-500"
            }`}
            title={category.label}
            aria-label={category.label}
          >
            <CategoryIcon className="h-4 w-4" aria-hidden="true" />
          </span>
        </button>
      </div>
    </div>
  );
}

function iconForQueueCategory(categoryId: QueueCategoryId) {
  switch (categoryId) {
    case "credential_output":
      return HiMiniKey;
    case "secret_file_read":
      return HiMiniDocumentMagnifyingGlass;
    case "file_read":
      return HiMiniDocumentMagnifyingGlass;
    case "secret_exfiltration":
      return HiMiniArrowTopRightOnSquare;
    case "system_prompt_access":
      return HiMiniInformationCircle;
    case "prompt_injection":
      return HiMiniExclamationTriangle;
    case "guard_bypass":
      return HiMiniNoSymbol;
    case "generated_inventory_edit":
      return HiMiniClipboardDocumentCheck;
    case "docs_edit":
      return HiMiniDocumentText;
    case "source_edit":
      return HiMiniPencilSquare;
    case "config_change":
      return HiMiniCog6Tooth;
    case "file_upload":
      return HiMiniArrowTopRightOnSquare;
    case "file_delete_cleanup":
      return HiMiniNoSymbol;
    case "git_operation":
      return HiMiniCodeBracket;
    case "process_control":
      return HiMiniArrowPath;
    case "container_or_deploy":
      return HiMiniServerStack;
    case "persistence_change":
      return HiMiniClock;
    case "package_install":
      return HiMiniCube;
    case "package_script":
      return HiMiniCommandLine;
    case "destructive_shell":
      return HiMiniNoSymbol;
    case "encoded_shell":
      return HiMiniCodeBracket;
    case "network":
      return HiMiniGlobeAlt;
    case "mcp_tool":
      return HiMiniServerStack;
    case "browser_action":
      return HiMiniArrowTopRightOnSquare;
    case "harness_start":
      return HiMiniShieldCheck;
    case "shell_command":
      return HiMiniCommandLine;
    case "other":
      return HiMiniDocumentPlus;
  }
}

function queueItemPreview(item: GuardApprovalRequest): string {
  const envelope = item.action_envelope_json;
  return (
    envelope?.command ??
    item.raw_command_text ??
    envelope?.mcp_tool ??
    (envelope?.prompt_text ?? envelope?.prompt_excerpt) ??
    envelope?.package_name ??
    displayArtifactName(item)
  );
}

function ReviewDecisionCard(props: {
  detail: ReviewViewModel | null;
  onResolve: ReviewWorkspaceProps["onResolve"];
  onGoHome: () => void;
  approvalGate: GuardApprovalGatePublicConfig | null;
}) {
  const detail = props.detail;
  const item = detail?.item ?? null;
  const [scope, setScope] = useState<DecisionScope>(item?.recommended_scope ?? "artifact");
  const [submitting, setSubmitting] = useState<"allow" | "block" | null>(null);
  const [resolved, setResolved] = useState<"allow" | "block" | null>(null);
  const [showConsequences, setShowConsequences] = useState(false);
  const [showEvidence, setShowEvidence] = useState(false);
  const [lastAction, setLastAction] = useState<"allow" | "block" | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [approvalPassword, setApprovalPassword] = useState("");
  const [approvalTotpCode, setApprovalTotpCode] = useState("");
  const [useCooldown, setUseCooldown] = useState(false);
  const [pendingAction, setPendingAction] = useState<"allow" | "block" | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const allowButtonRef = useRef<HTMLButtonElement>(null);
  const availableScopeChoices = useMemo(
    () => (item ? standardScopeChoicesForRequest(item) : scopeChoices.filter((choice) => choice.value !== "global")),
    [item]
  );
  const commonScopeOptions = useMemo(
    () => availableScopeChoices.filter((choice) => commonScopeValues.has(choice.value)),
    [availableScopeChoices]
  );
  const broaderScopeOptions = useMemo(
    () => availableScopeChoices.filter((choice) => !commonScopeValues.has(choice.value)),
    [availableScopeChoices]
  );
  const advancedScopeOptions = useMemo(
    () => (item ? advancedScopeChoicesForRequest(item) : scopeChoices.filter((choice) => choice.value === "global")),
    [item]
  );

  const gateRequiresPassword = useMemo(() => {
    const gate = props.approvalGate;
    return (
      gate?.enabled === true &&
      gate?.configured === true &&
      requiresApprovalPasswordPrompt(gate.cooldown_active, gate.strict_all_decisions, scope)
    );
  }, [props.approvalGate, scope]);

  useEffect(() => {
    if (item) {
      setScope(normalizeDecisionScope(item, item.recommended_scope));
      setResolved(null);
      setSubmitting(null);
      setLastAction(null);
      setErrorMessage(null);
      setApprovalPassword("");
      setApprovalTotpCode("");
      setUseCooldown(false);
      setPendingAction(null);
    }
  }, [item?.request_id]);

  useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if (submitting !== null || pendingAction !== null) return;
      const target = event.target as HTMLElement;
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return;

      if (event.key === "a" || event.key === "A") {
        event.preventDefault();
        handleRequestResolve("allow");
      }
      if (event.key === "b" || event.key === "B") {
        event.preventDefault();
        handleRequestResolve("block");
      }
      const scopeIndex = parseInt(event.key, 10);
      if (scopeIndex >= 1 && scopeIndex <= availableScopeChoices.length) {
        event.preventDefault();
        setScope(availableScopeChoices[scopeIndex - 1].value);
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [submitting, pendingAction, scope, item?.request_id, availableScopeChoices]);

  const handleResolve = useCallback(
    async (action: "allow" | "block") => {
      if (!item) return;
      setSubmitting(action);
      setErrorMessage(null);
      try {
        const gate = props.approvalGate;
        const needsPassword = approvalProofRequiresPassword(gate);
        const includeGateFields =
          gate?.enabled === true &&
          gate?.configured === true &&
          requiresApprovalPasswordPrompt(gate.cooldown_active, gate.strict_all_decisions, scope);
        await props.onResolve({
          ...buildDecisionPayload({
            item,
            action,
            scope,
            reason: action === "allow" ? "approved in review" : "blocked in review",
          }),
          ...(includeGateFields && needsPassword ? { approval_password: approvalPassword } : {}),
          ...(includeGateFields && !needsPassword ? { approval_totp_code: approvalTotpCode } : {}),
          ...(includeGateFields ? { approval_gate_use_cooldown: useCooldown } : {}),
        });
        setResolved(action);
        setApprovalPassword("");
        setApprovalTotpCode("");
        setUseCooldown(false);
        setPendingAction(null);
        timerRef.current = setTimeout(() => setResolved(null), 2000);
      } catch (err) {
        setErrorMessage(err instanceof Error ? err.message : "Something went wrong. Try again.");
      } finally {
        setSubmitting(null);
      }
    },
    [item, scope, props.onResolve, props.approvalGate, approvalPassword, approvalTotpCode, useCooldown]
  );

  const handleRequestResolve = useCallback(
    (action: "allow" | "block") => {
      setLastAction(action);
      if (gateRequiresPassword) {
        setPendingAction(action);
        setErrorMessage(null);
        return;
      }
      void handleResolve(action);
    },
    [handleResolve, gateRequiresPassword]
  );

  const handleAllow = useCallback(() => {
    handleRequestResolve("allow");
  }, [handleRequestResolve]);
  const handleBlock = useCallback(() => {
    handleRequestResolve("block");
  }, [handleRequestResolve]);

  const handleModalSubmit = useCallback(() => {
    if (pendingAction !== null) {
      void handleResolve(pendingAction);
    }
  }, [pendingAction, handleResolve]);

  const handleModalCancel = useCallback(() => {
    setPendingAction(null);
    setApprovalPassword("");
    setApprovalTotpCode("");
    setUseCooldown(false);
  }, []);

  const handleToggleConsequences = useCallback(() => {
    setShowConsequences((visible) => !visible);
  }, []);
  const handleToggleEvidence = useCallback(() => {
    setShowEvidence((visible) => !visible);
  }, []);
  const handleRetryLastAction = useCallback(() => {
    setErrorMessage(null);
    if (lastAction !== null) {
      handleRequestResolve(lastAction);
    }
  }, [handleRequestResolve, lastAction]);

  const handleApprovalPasswordChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setApprovalPassword(event.target.value);
  }, []);
  const handleApprovalTotpCodeChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setApprovalTotpCode(event.target.value);
  }, []);

  const handleUseCooldownChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setUseCooldown(event.target.checked);
  }, []);

  if (!detail || !item) {
    return (
      <EmptyState
        title="Select an action"
        body="Choose a paused action from the queue to review and decide."
        tone="teach"
      />
    );
  }

  const plainTitle = plainEnglishRequestTitle(item);
  const harnessName = harnessDisplayName(item.harness);
  const whatWouldHappen = buildWhatWouldHappen(item);
  const secondaryRiskSummary = resolveSecondaryRiskSummary(item);
  const pauseReason = whyPaused(item);

  const topAlertItems: EvidenceItem[] = [];
  if (secondaryRiskSummary) {
    topAlertItems.push({
      id: "secondary-risk",
      title: "Additional risk",
      tone: "amber",
      icon: HiMiniExclamationTriangle,
      content: <p className="text-sm text-brand-dark">{secondaryRiskSummary}</p>,
    });
  }
  if (pauseReason) {
    topAlertItems.push({
      id: "why-paused",
      title: "Why paused",
      tone: "blue",
      icon: HiMiniInformationCircle,
      content: <p className="text-sm text-brand-dark">{pauseReason}</p>,
    });
  }

  const evidenceItems: EvidenceItem[] = [];
  const allSignals = item.decision_v2_json?.signals ?? [];
  if (allSignals.some((s) => s.category === "skill" || s.category === "mcp")) {
    evidenceItems.push({
      id: "scanner",
      title: "Scanner evidence",
      tone: "blue",
      content: <ScannerEvidenceSection signals={allSignals} />,
    });
  }
  if (item.why_now) {
    evidenceItems.push({
      id: "why-now",
      title: "Why now",
      tone: "purple",
      content: <p className="text-sm text-brand-dark">{item.why_now}</p>,
    });
  }
  if (deriveDataFlowEvidence(item) !== null) {
    evidenceItems.push({
      id: "data-flow",
      title: "Data flow detected",
      tone: "blue",
      content: <DataFlowEvidenceCard item={item} />,
    });
  }
  if (deriveSkillRiskSignals(item).length > 0) {
    evidenceItems.push({
      id: "skill-risk",
      title: "Skill risk",
      tone: "blue",
      content: <SkillRiskCard item={item} />,
    });
  }
  const isSupplyChainArtifact =
    item.artifact_type === "supply_chain" ||
    item.artifact_type === "package_request" ||
    (typeof item.artifact_type === "string" && item.artifact_type.endsWith("_package"));
  if (deriveSupplyChainRiskSignals(item).length > 0 || isSupplyChainArtifact) {
    evidenceItems.push({
      id: "supply-chain",
      title: "Supply chain risk",
      tone: "amber",
      content: <SupplyChainRiskCard item={item} />,
    });
  }
  if (deriveEncodedLayerSignals(item).length > 0) {
    evidenceItems.push({
      id: "decoded-layer",
      title: "Decoded layer",
      tone: "slate",
      content: <DecodedLayerCard item={item} />,
    });
  }

  return (
    <div className="space-y-5">
      {resolved && (
        <div
          className={`guard-fade-in flex items-center gap-3 rounded-xl border px-4 py-3 transition-all ${
            resolved === "allow"
              ? "border-brand-green/25 bg-brand-green-bg/30"
              : "border-brand-attention/25 bg-brand-attention/[0.04]"
          }`}
          role="status"
          aria-live="polite"
        >
          <HiMiniCheckCircle
            className={`h-5 w-5 shrink-0 ${resolved === "allow" ? "text-brand-green" : "text-brand-attention"}`}
            aria-hidden="true"
          />
          <p className={`text-sm font-medium ${resolved === "allow" ? "text-brand-green-text" : "text-brand-attention"}`}>
            {item ? buildRetryAfterApprovalCopy(item, resolved) : (resolved === "allow" ? "Approved: action can proceed" : "Blocked: action stopped")}
          </p>
        </div>
      )}

      <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <SectionLabel>Paused action</SectionLabel>
            <h2 className="mt-2 text-lg font-semibold text-brand-dark">{plainTitle}</h2>
            <p className="mt-1 text-sm text-muted-foreground">
              From {harnessName}
            </p>
          </div>
          <Badge tone={item.policy_action === "block" ? "attention" : "info"}>
            {item.policy_action === "block" ? "Blocked" : "Needs review"}
          </Badge>
        </div>

        <PrimaryActionCard item={item} />

        {topAlertItems.length > 0 && (
          <div className="mt-5 rounded-xl border border-slate-100 bg-slate-50/50 p-4">
            <ConsolidatedEvidenceAlert key={item.request_id} items={topAlertItems} />
          </div>
        )}

        {whatWouldHappen && (
          <div className="mt-5">
            <button
              type="button"
              onClick={handleToggleConsequences}
              className="flex items-center gap-2 text-sm font-medium text-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20 rounded-lg px-2 py-1 -ml-2"
              aria-expanded={showConsequences}
            >
              <HiMiniInformationCircle className="h-4 w-4" aria-hidden="true" />
              What would happen without Guard?
              {showConsequences ? (
                <HiMiniChevronUp className="h-3 w-3" aria-hidden="true" />
              ) : (
                <HiMiniChevronDown className="h-3 w-3" aria-hidden="true" />
              )}
            </button>
            {showConsequences && (
              <div className="mt-3 rounded-xl border border-slate-200/70 bg-slate-50 p-4">
                <p className="text-sm text-brand-dark">{whatWouldHappen}</p>
              </div>
            )}
          </div>
        )}

        <div className="mt-6 space-y-2">
          <SectionLabel>How long should this choice last?</SectionLabel>
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2" role="radiogroup" aria-label="Scope selection">
            {commonScopeOptions.map((choice) => (
              <ScopeChoiceButton
                key={choice.value}
                choice={choice}
                checked={scope === choice.value}
                onScopeChange={setScope}
              />
            ))}
          </div>
          {broaderScopeOptions.length > 0 && (
            <details className="rounded-xl border border-brand-blue/15 bg-brand-blue/[0.03] p-3">
              <summary className="cursor-pointer select-none text-xs font-semibold uppercase tracking-[0.16em] text-brand-blue">
                Save for project or app
              </summary>
              <p className="mt-2 text-xs text-brand-dark/70">
                These options save a decision that skips review for matching actions going forward. Choose the narrowest scope that fits what you meant to allow.
              </p>
              <div className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-2">
                {broaderScopeOptions.map((choice) => (
                  <ScopeChoiceButton
                    key={choice.value}
                    choice={choice}
                    checked={scope === choice.value}
                    onScopeChange={setScope}
                  />
                ))}
              </div>
            </details>
          )}
          {advancedScopeOptions.length > 0 && (
            <details className="rounded-xl border border-brand-attention/20 bg-brand-attention/[0.04] p-3">
              <summary className="cursor-pointer select-none text-xs font-semibold uppercase tracking-[0.16em] text-brand-attention">
                Advanced: save everywhere on this machine
              </summary>
              <p className="mt-2 text-xs text-brand-dark/70">
                This saves a decision that applies across all your projects on this machine. Matching actions skip review permanently. Only use this if you fully trust this action everywhere.
              </p>
              <div className="mt-3 grid grid-cols-1 gap-2">
                {advancedScopeOptions.map((choice) => (
                  <ScopeChoiceButton
                    key={choice.value}
                    choice={choice}
                    checked={scope === choice.value}
                    onScopeChange={setScope}
                  />
                ))}
              </div>
            </details>
          )}
        </div>

        {errorMessage && (
          <div className="guard-fade-in mt-4 rounded-xl border border-brand-purple/25 bg-brand-purple/[0.05] p-4">
            <div className="flex items-start gap-3">
              <HiMiniExclamationTriangle className="mt-0.5 h-4 w-4 shrink-0 text-brand-purple" aria-hidden="true" />
              <div className="flex-1">
                <p className="text-sm text-brand-purple">{errorMessage}</p>
                <button
                  type="button"
                  onClick={handleRetryLastAction}
                  className="mt-2 inline-flex min-h-9 items-center rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50"
                >
                  Retry
                </button>
              </div>
            </div>
          </div>
        )}

        <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-2">
          <ActionButton
            ref={allowButtonRef}
            variant="success"
            onClick={handleAllow}
            disabled={submitting !== null || pendingAction !== null}
          >
            {submitting === "allow" ? (
              <span className="flex items-center gap-2">
                <HiMiniArrowPath className="h-4 w-4 animate-spin" aria-hidden="true" />
                Approving...
              </span>
            ) : (
              <span className="flex items-center gap-2">
                <HiMiniCheckCircle className="h-4 w-4" aria-hidden="true" />
                {allowButtonLabel(scope)}
              </span>
            )}
          </ActionButton>
          <ActionButton
            variant="outline"
            onClick={handleBlock}
            disabled={submitting !== null || pendingAction !== null}
          >
            {submitting === "block" ? (
              <span className="flex items-center gap-2">
                <HiMiniArrowPath className="h-4 w-4 animate-spin" aria-hidden="true" />
                Blocking...
              </span>
            ) : (
              <span className="flex items-center gap-2">
                <HiMiniNoSymbol className="h-4 w-4" aria-hidden="true" />
                Keep blocked
              </span>
            )}
          </ActionButton>
        </div>

      </div>

      {evidenceItems.length > 0 && (
        <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
          <button
            type="button"
            onClick={handleToggleEvidence}
            className="flex w-full items-center justify-between text-left focus:outline-none focus:ring-2 focus:ring-brand-blue/20 rounded-lg px-2 py-1 -ml-2"
            aria-expanded={showEvidence}
          >
            <SectionLabel>Review details</SectionLabel>
            {showEvidence ? (
              <HiMiniChevronUp className="h-4 w-4 text-slate-400" aria-hidden="true" />
            ) : (
              <HiMiniChevronDown className="h-4 w-4 text-slate-400" aria-hidden="true" />
            )}
          </button>
          {showEvidence && (
            <div className="mt-4">
              <ConsolidatedEvidenceAlert key={item.request_id} items={evidenceItems} />
            </div>
          )}
        </div>
      )}

      {detail.receipt && (
        <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
          <SectionLabel>Last time</SectionLabel>
          <p className="mt-2 text-sm text-muted-foreground">
            You previously {pastDecisionVerb(detail.receipt.policy_decision)} a similar action{" "}
            {formatRelativeTime(detail.receipt.timestamp)}.
          </p>
          {detail.diff && detail.diff.changed_fields.length > 0 && (
            <div className="mt-3 rounded-xl border border-slate-200/70 bg-slate-50 p-4">
              <p className="text-sm font-medium text-brand-dark">What changed since then:</p>
              <ul className="mt-2 space-y-1">
                {detail.diff.changed_fields.map((field) => (
                  <li key={field} className="flex items-center gap-2 text-sm text-brand-dark">
                    <HiMiniCheckCircle className="h-3.5 w-3.5 shrink-0 text-brand-blue" aria-hidden="true" />
                    {field}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {pendingAction !== null && props.approvalGate !== null && (
        <ApprovalPasswordModal
          gate={props.approvalGate}
          approvalPassword={approvalPassword}
          approvalTotpCode={approvalTotpCode}
          useCooldown={useCooldown}
          onApprovalPasswordChange={handleApprovalPasswordChange}
          onApprovalTotpCodeChange={handleApprovalTotpCodeChange}
          onUseCooldownChange={handleUseCooldownChange}
          onSubmit={handleModalSubmit}
          onCancel={handleModalCancel}
          submitLabel={pendingAction === "allow" ? allowButtonLabel(scope) : "Keep blocked"}
        />
      )}
    </div>
  );
}

function ScopeChoiceButton(props: {
  choice: (typeof scopeChoices)[number];
  checked: boolean;
  onScopeChange: (scope: DecisionScope) => void;
}) {
  const handleClick = useCallback(() => {
    props.onScopeChange(props.choice.value);
  }, [props.onScopeChange, props.choice.value]);

  return (
    <button
      type="button"
      onClick={handleClick}
      role="radio"
      aria-checked={props.checked}
      className={`rounded-xl border px-4 py-3 text-left transition-all focus:outline-none focus:ring-2 focus:ring-brand-blue/20 ${
        props.checked ? "border-brand-blue bg-brand-blue/[0.06]" : "border-slate-200/70 bg-white hover:bg-slate-50"
      }`}
    >
      <p className="text-sm font-medium text-brand-dark">{props.choice.label}</p>
      <p className="mt-0.5 text-xs text-muted-foreground">{props.choice.description}</p>
    </button>
  );
}

function allowButtonLabel(scope: DecisionScope): string {
  if (scope === "artifact") {
    return "Approve once";
  }
  if (scope === "workspace") {
    return "Remember for project";
  }
  return "Approve and remember";
}

type ReviewCodexResumePanelProps = {
  resume: GuardCodexResumeResult;
  onRetry?: () => void;
};

function ReviewCodexResumePanel({ resume, onRetry }: ReviewCodexResumePanelProps) {
  const ux = buildCodexResumeUx(resume);
  const isPending = resume.status === "pending" || resume.status === "in_progress";
  const isSuccess = resume.status === "sent" || resume.status === "already_sent";
  const isFailed = resume.status === "failed";

  const borderClass = isFailed
    ? "border-brand-purple/25 bg-brand-purple/[0.05]"
    : isSuccess
    ? "border-brand-green/25 bg-brand-green-bg/30"
    : isPending
    ? "border-brand-blue/25 bg-brand-blue/[0.04]"
    : "border-slate-200/60 bg-slate-50/40";

  const iconClass = isFailed
    ? "text-brand-purple"
    : isSuccess
    ? "text-brand-green"
    : "text-brand-blue";

  return (
    <div className={`flex items-start gap-3 rounded-2xl border px-4 py-3 ${borderClass}`}>
      {isPending && (
        <HiMiniArrowPath className={`mt-0.5 h-4 w-4 shrink-0 animate-spin ${iconClass}`} aria-hidden="true" />
      )}
      {isSuccess && (
        <HiMiniCheckCircle className={`mt-0.5 h-4 w-4 shrink-0 ${iconClass}`} aria-hidden="true" />
      )}
      {isFailed && (
        <HiMiniExclamationTriangle className={`mt-0.5 h-4 w-4 shrink-0 ${iconClass}`} aria-hidden="true" />
      )}
      {!isPending && !isSuccess && !isFailed && (
        <HiMiniInformationCircle className="mt-0.5 h-4 w-4 shrink-0 text-slate-500" aria-hidden="true" />
      )}
      <div className="flex-1 space-y-1">
        <p className="text-sm font-medium text-brand-dark">{ux.headline}</p>
        {ux.body !== null && (
          <p className="text-xs text-muted-foreground">{ux.body}</p>
        )}
        {isFailed && onRetry !== undefined && (
          <div className="mt-2">
            <ActionButton variant="outline" onClick={onRetry}>
              Retry resume
            </ActionButton>
          </div>
        )}
      </div>
    </div>
  );
}

function ReviewEmptyState({ runtime, resolutionMessage, codexResume, onRetryResume }: { runtime: GuardRuntimeSnapshot | null; resolutionMessage: string | null; codexResume: GuardCodexResumeResult | null; onRetryResume?: () => void }) {
  const appsCount = runtime?.managed_installs?.filter((i) => i.active).length ?? 0;

  return (
    <div className="space-y-6">
      <GuardHero
        status="clear"
        headline="Nothing to review"
        subheadline="Guard is watching your AI work. No actions need your decision right now."
      />

      <ProofStrip
        items={[
          { label: "Status", value: "All clear", tone: "green" },
          { label: "Apps protected", value: appsCount, tone: appsCount > 0 ? "green" : "slate" },
        ]}
      />

      {codexResume !== null && (
        <ReviewCodexResumePanel resume={codexResume} onRetry={onRetryResume} />
      )}

      {codexResume === null && resolutionMessage && (
        <div className="flex items-start gap-3 rounded-2xl border border-brand-green/25 bg-brand-green-bg/30 px-4 py-3">
          <HiMiniCheckCircle className="mt-0.5 h-4 w-4 shrink-0 text-brand-green" aria-hidden="true" />
          <p className="text-sm font-medium text-brand-green-text">{resolutionMessage}</p>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <div className="rounded-xl border border-emerald-200/60 bg-emerald-50/30 p-4 sm:p-5">
          <div className="flex items-start gap-3">
            <span className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-brand-green/10">
              <HiMiniShieldCheck className="h-5 w-5 text-brand-green" aria-hidden="true" />
            </span>
            <div>
              <SectionLabel>Protection active</SectionLabel>
              <p className="mt-2 text-sm text-muted-foreground">
                Guard is running and will pause any risky actions from your AI apps. When something needs review, it will appear here.
              </p>
            </div>
          </div>
        </div>

        <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
          <SectionLabel>What Guard does</SectionLabel>
          <ul className="mt-3 space-y-2">
            {[
              "Pauses risky file reads and writes",
              "Blocks commands that could delete data",
              "Warns about new network connections",
              "Stops credential sharing",
            ].map((item) => (
              <li key={item} className="flex items-start gap-2 text-sm text-brand-dark">
                <HiMiniCheckCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-brand-green" aria-hidden="true" />
                {item}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}

function PrimaryActionCard({ item }: { item: GuardApprovalRequest }) {
  const action = buildPrimaryReviewAction(item);

  return (
    <div className="mt-5 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <SectionLabel>What was stopped</SectionLabel>
          {action.detail !== null && (
            <p className="mt-1 text-sm text-brand-dark/70">
              {action.detail}
            </p>
          )}
        </div>
        <span className="rounded-full border border-brand-blue/15 bg-brand-blue/[0.04] px-3 py-1 font-mono text-[11px] font-semibold uppercase tracking-[0.16em] text-brand-blue">
          {action.label}
        </span>
      </div>
      <div className="mt-3">
        <LoggedActionPanel
          key={item.request_id}
          label={action.label}
          text={action.text}
          copyAriaLabel="Copy full stopped action to clipboard"
          expandAriaLabel="Expand full stopped action"
          collapseAriaLabel="Collapse full stopped action"
        />
      </div>
    </div>
  );
}

function buildWhatWouldHappen(item: GuardApprovalRequest): string | null {
  const type = item.artifact_type;
  if (type?.includes("file_write") || type?.includes("file_read")) {
    return `Without Guard, ${harnessDisplayName(item.harness)} would access "${item.artifact_name ?? item.artifact_id}" immediately. Guard paused it so you can review first.`;
  }
  if (type?.includes("shell") || type?.includes("command")) {
    return `Without Guard, this shell command would run immediately. Guard paused it so you can review what it does first.`;
  }
  if (type?.includes("network") || type?.includes("request")) {
    return `Without Guard, this request would go to the network immediately. Guard paused it so you can review the destination first.`;
  }
  if (type?.includes("mcp") || type?.includes("tool")) {
    return `Without Guard, this tool would execute immediately. Guard paused it so you can review what data it accesses.`;
  }
  return `Without Guard, this action would run immediately. Guard paused it so you can review and decide.`;
}

function pastDecisionVerb(decision: string): string {
  if (decision === "allow") {
    return "allowed";
  }
  if (decision === "block") {
    return "blocked";
  }
  return "reviewed";
}
