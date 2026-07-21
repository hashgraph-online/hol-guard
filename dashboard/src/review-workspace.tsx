import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { HiMiniChevronDown } from "react-icons/hi2";
import { useRequestReadState } from "./request-read-state";
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
  riskScore,
  searchQueue,
  sortQueue,
  REVIEW_SEMANTIC_GROUPS,
  type QueueCategory,
  type QueueCategoryId,
  type QueueSortDirection,
  type SemanticGroupId,
} from "./queue-state";
import type { BulkGateCredentials } from "./approval-gate-utils";
import { guardAwareHref } from "./guard-api";
import {
  QueueBulkDrawer,
  QueueBulkGatePrompt,
  QueueBulkStickyBar,
  QueueBulkStatusBanner,
} from "./queue-bulk-approve-flow";
import { useQueueBulkApprove } from "./use-queue-bulk-approve";
import { ReviewDecisionCard } from "./review-decision-card";
import { ReviewHeader, ReviewQueueList } from "./review-queue-list";
import { ReviewEmptyState } from "./review-states";

export type ReviewViewModel = {
  item: GuardApprovalRequest;
  diff: GuardArtifactDiff | null;
  receipt: GuardReceipt | null;
  policy: GuardPolicyDecision[];
};

export type ReviewWorkspaceProps = {
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
    scope_contract_version?: string;
    scope_contract_digest?: string;
  }) => Promise<void> | void;
  onGoHome: () => void;
  onBulkApprove?: (ids: string[], gateCredentials?: BulkGateCredentials) => void | Promise<void>;
};

const QUEUE_PAGE_SIZE = 10;
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
