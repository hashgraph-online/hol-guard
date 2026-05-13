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
  HiMiniClipboard,
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
  harnessDisplayName,
  resolveStoppedCommandText,
  resolveTerminalLabel,
  resolveDecisionV2Detail,
  resolveDecisionV2Title,
  displayArtifactName,
  buildPauseLine,
  resolveEnvelopeDisplayText,
  formatRelativeTime,
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
import type {
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardPolicyDecision,
  GuardReceipt,
  GuardRuntimeSnapshot,
  DecisionScope,
} from "./guard-types";
import {
  filterQueueByCategory,
  queueCategoriesForItems,
  resolveQueueCategory,
  searchQueue,
  sortQueue,
  type QueueCategory,
  type QueueCategoryId,
  type QueueSortDirection,
} from "./queue-state";
import { plainEnglishRequestTitle, whyPaused } from "./evidence/plain-english";

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
  onOpenRequest: (requestId: string) => void;
  onResolve: (payload: {
    requestId: string;
    action: "allow" | "block";
    scope: DecisionScope;
    workspace?: string;
    reason: string;
  }) => Promise<void> | void;
  onGoHome: () => void;
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
const commonScopeValues = new Set<DecisionScope>(["artifact", "workspace"]);

export function ReviewWorkspace(props: ReviewWorkspaceProps) {
  const { requests, activeRequestId, detail } = props;
  const queueRef = useRef<HTMLDivElement>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<QueueCategoryId | "all">("all");
  const [sortDirection, setSortDirection] = useState<QueueSortDirection>("newest");
  const [semanticFilter, setSemanticFilter] = useState<SemanticGroupId>("all");
  const [mobileQueueOpen, setMobileQueueOpen] = useState(false);
  const [page, setPage] = useState(1);

  const handleOpenRequest = useCallback((id: string) => {
    props.onOpenRequest(id);
    setMobileQueueOpen(false);
  }, [props.onOpenRequest]);

  const handleToggleMobileQueue = useCallback(() => {
    setMobileQueueOpen((v) => !v);
  }, []);

  const filteredRequests = useMemo(() => {
    let items = requests;
    if (semanticFilter !== "all") {
      const group = SEMANTIC_GROUPS.find((g) => g.id === semanticFilter);
      if (group && group.matches.length > 0) {
        items = items.filter((item) => group.matches.includes(resolveQueueCategory(item).id));
      }
    } else if (categoryFilter !== "all") {
      items = filterQueueByCategory(items, categoryFilter);
    }
    const searched = searchQueue(items, searchTerm);
    return sortQueue(searched, sortDirection);
  }, [categoryFilter, requests, searchTerm, sortDirection, semanticFilter]);

  // Reset page when filters change
  useEffect(() => {
    setPage(1);
  }, [searchTerm, categoryFilter, sortDirection, semanticFilter]);

  const totalPages = Math.max(1, Math.ceil(filteredRequests.length / QUEUE_PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const pageStart = (currentPage - 1) * QUEUE_PAGE_SIZE;
  const pagedRequests = filteredRequests.slice(pageStart, pageStart + QUEUE_PAGE_SIZE);

  const categoryOptions = useMemo(() => queueCategoriesForItems(requests), [requests]);

  const activeRequest =
    activeRequestId !== null
      ? requests.find((r) => r.request_id === activeRequestId) ?? null
      : null;

  // Keyboard navigation for queue (scoped to visible page)
  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if (pagedRequests.length === 0) return;
      const activeIdx = pagedRequests.findIndex((r) => r.request_id === activeRequestId);
      if (event.key === "ArrowDown") {
        event.preventDefault();
        const nextIdx = Math.min(activeIdx + 1, pagedRequests.length - 1);
        if (nextIdx !== activeIdx) props.onOpenRequest(pagedRequests[nextIdx].request_id);
      }
      if (event.key === "ArrowUp") {
        event.preventDefault();
        const prevIdx = Math.max(activeIdx - 1, 0);
        if (prevIdx !== activeIdx) props.onOpenRequest(pagedRequests[prevIdx].request_id);
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [pagedRequests, activeRequestId, props.onOpenRequest]);

  useEffect(() => {
    if (filteredRequests.length === 0) {
      return;
    }
    if (activeRequestId === null || !filteredRequests.some((item) => item.request_id === activeRequestId)) {
      props.onOpenRequest(filteredRequests[0].request_id);
    }
  }, [activeRequestId, filteredRequests, props.onOpenRequest]);

  // When page changes, ensure active item is on the current page
  useEffect(() => {
    if (pagedRequests.length === 0) return;
    const activeOnPage = pagedRequests.some((item) => item.request_id === activeRequestId);
    if (!activeOnPage) {
      props.onOpenRequest(pagedRequests[0].request_id);
    }
  }, [currentPage, pagedRequests, activeRequestId, props.onOpenRequest]);

  if (requests.length === 0) {
    return <ReviewEmptyState runtime={props.runtime} resolutionMessage={props.resolutionMessage} />;
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

      {/* Mobile queue toggle */}
      <div className="md:hidden">
        <button
          onClick={handleToggleMobileQueue}
          className="flex w-full items-center justify-between rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm font-medium text-brand-dark"
        >
          <span>Queue ({filteredRequests.length})</span>
          <HiMiniChevronDown className={`h-4 w-4 transition-transform ${mobileQueueOpen ? "rotate-180" : ""}`} />
        </button>
      </div>

      <div className="grid gap-4 md:grid-cols-[260px_minmax(0,1fr)] lg:grid-cols-[280px_minmax(0,1fr)] xl:grid-cols-[300px_minmax(0,1fr)] items-start">
        <div className={`${mobileQueueOpen ? "block" : "hidden"} md:block`}>
          <ReviewQueueList
            requests={pagedRequests}
            allFilteredRequests={filteredRequests}
            totalCount={requests.length}
            filteredCount={filteredRequests.length}
            activeRequestId={activeItem.request_id}
            categoryOptions={categoryOptions}
            categoryFilter={categoryFilter}
            searchTerm={searchTerm}
            sortDirection={sortDirection}
            semanticFilter={semanticFilter}
            page={currentPage}
            totalPages={totalPages}
            onCategoryFilterChange={setCategoryFilter}
            onSearchTermChange={setSearchTerm}
            onSortDirectionChange={setSortDirection}
            onSemanticFilterChange={setSemanticFilter}
            onPageChange={setPage}
            onOpenRequest={handleOpenRequest}
            ref={queueRef}
          />
        </div>
        <ReviewDecisionCard
          detail={detail}
          onResolve={props.onResolve}
          onGoHome={props.onGoHome}
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
        <h1 className="text-2xl font-semibold tracking-[-0.02em] text-brand-dark">Review</h1>
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

type SemanticGroupId = "all" | "files" | "shell" | "network" | "tools" | "other";

const SEMANTIC_GROUPS: { id: SemanticGroupId; label: string; matches: QueueCategoryId[] }[] = [
  { id: "all", label: "All", matches: [] },
  { id: "files", label: "Files", matches: ["file_read", "file_edit"] },
  { id: "shell", label: "Shell", matches: ["shell_command", "destructive_shell", "encoded_shell"] },
  { id: "network", label: "Network & Data", matches: ["network", "data_exfiltration", "secret_access"] },
  { id: "tools", label: "Tools & Apps", matches: ["mcp_tool", "package_script", "harness_start", "browser_action"] },
  { id: "other", label: "Other", matches: ["prompt_instruction", "config_change", "other"] },
];

function resolveSemanticGroup(categoryId: QueueCategoryId): SemanticGroupId {
  for (const group of SEMANTIC_GROUPS) {
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
  categoryOptions: QueueCategory[];
  categoryFilter: QueueCategoryId | "all";
  searchTerm: string;
  sortDirection: QueueSortDirection;
  semanticFilter: SemanticGroupId;
  page: number;
  totalPages: number;
  onCategoryFilterChange: (category: QueueCategoryId | "all") => void;
  onSearchTermChange: (term: string) => void;
  onSortDirectionChange: (direction: QueueSortDirection) => void;
  onSemanticFilterChange: (group: SemanticGroupId) => void;
  onPageChange: (page: number) => void;
  onOpenRequest: (requestId: string) => void;
}>(({
  requests,
  allFilteredRequests,
  totalCount,
  filteredCount,
  activeRequestId,
  categoryOptions,
  categoryFilter,
  searchTerm,
  sortDirection,
  semanticFilter,
  page,
  totalPages,
  onCategoryFilterChange,
  onSearchTermChange,
  onSortDirectionChange,
  onSemanticFilterChange,
  onPageChange,
  onOpenRequest,
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
  const handlePreviousPage = useCallback(() => {
    onPageChange(Math.max(1, page - 1));
  }, [page, onPageChange]);
  const handleNextPage = useCallback(() => {
    onPageChange(Math.min(totalPages, page + 1));
  }, [page, totalPages, onPageChange]);

  const activeSemanticGroup = semanticFilter;

  // Only show groups that have items (derive from full filtered set, not paged)
  const visibleGroups = useMemo(() => {
    const available = new Set<SemanticGroupId>();
    for (const item of allFilteredRequests) {
      available.add(resolveSemanticGroup(resolveQueueCategory(item).id));
    }
    return SEMANTIC_GROUPS.filter((g) => g.id === "all" || available.has(g.id));
  }, [allFilteredRequests]);

  const isFiltered = searchTerm || semanticFilter !== "all" || categoryFilter !== "all" || sortDirection !== "newest";
  const showPagination = filteredCount > QUEUE_PAGE_SIZE;

  return (
    <aside className="space-y-3" ref={ref}>
      <div className="flex items-center justify-between gap-3">
        <SectionLabel>Queue</SectionLabel>
        <span className="font-mono text-[11px] font-semibold text-muted-foreground">
          {filteredCount}/{totalCount}
        </span>
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
            placeholder="Search command, category, host..."
            className="min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          />
        </label>
        <button
          onClick={() => setShowFilters((v) => !v)}
          className="flex items-center gap-1 text-xs font-medium text-brand-blue hover:text-brand-dark transition-colors"
        >
          {showFilters ? "Hide filters" : "Show filters"}
          {isFiltered && !showFilters && <span className="ml-1 h-1.5 w-1.5 rounded-full bg-brand-attention" />}
        </button>
        {showFilters && (
          <div className="space-y-2">
            <div className="flex flex-wrap gap-1">
              {visibleGroups.map((group) => (
                <button
                  key={group.id}
                  onClick={() => onSemanticFilterChange(group.id)}
                  className={`rounded-full px-2.5 py-1 text-[11px] font-medium transition-all ${
                    activeSemanticGroup === group.id
                      ? "bg-brand-blue text-white"
                      : "border border-slate-200 bg-white text-brand-dark hover:bg-slate-50"
                  }`}
                >
                  {group.label}
                </button>
              ))}
            </div>
            <label className="block">
              <span className="sr-only">Sort review queue</span>
              <select
                value={sortDirection}
                onChange={handleSortChange}
                className="min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
              >
                <option value="newest">Newest first</option>
                <option value="oldest">Oldest first</option>
                <option value="category">Category</option>
              </select>
            </label>
            {isFiltered && (
              <button
                onClick={() => { onSearchTermChange(""); onCategoryFilterChange("all"); onSortDirectionChange("newest"); onSemanticFilterChange("all"); }}
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
        {requests.length > 0 ? (
          requests.map((item, index) => (
            <QueueItemRow
              key={item.request_id}
              item={item}
              active={item.request_id === activeRequestId}
              index={index}
              onOpenRequest={onOpenRequest}
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

function QueueItemRow({ item, active, index, onOpenRequest }: {
  item: GuardApprovalRequest;
  active: boolean;
  index: number;
  onOpenRequest: (requestId: string) => void;
}) {
  const isBlocked = item.policy_action === "block";
  const category = resolveQueueCategory(item);
  const CategoryIcon = iconForQueueCategory(category.id);
  const preview = queueItemPreview(item);
  const handleClick = useCallback(() => {
    onOpenRequest(item.request_id);
  }, [item.request_id, onOpenRequest]);
  return (
    <button
      onClick={handleClick}
      role="option"
      aria-selected={active}
      aria-posinset={index + 1}
      aria-setsize={/* parent will provide */ undefined}
      tabIndex={active ? 0 : -1}
      className={`w-full rounded-lg py-2.5 px-2 text-left transition-all ${
        active
          ? "border-brand-blue bg-brand-blue/[0.06]"
          : "border-transparent bg-white hover:bg-slate-50"
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <span
            className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${
              isBlocked ? "bg-brand-attention" : "bg-emerald-400"
            }`}
            aria-hidden="true"
          />
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-brand-dark">{preview}</p>
            <p className="truncate text-[11px] text-muted-foreground">
              {harnessDisplayName(item.harness)} · {category.shortLabel}
            </p>
          </div>
        </div>
        <span
          className={`inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg ${
            active ? "bg-brand-blue/10 text-brand-blue" : "bg-slate-50 text-slate-500"
          }`}
        >
          <CategoryIcon className="h-4 w-4" aria-hidden="true" />
        </span>
      </div>
    </button>
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
    envelope?.mcp_tool ??
    envelope?.prompt_excerpt ??
    envelope?.package_name ??
    displayArtifactName(item)
  );
}

function ReviewDecisionCard(props: {
  detail: ReviewViewModel | null;
  onResolve: ReviewWorkspaceProps["onResolve"];
  onGoHome: () => void;
}) {
  const detail = props.detail;
  const item = detail?.item ?? null;
  const [scope, setScope] = useState<DecisionScope>(item?.recommended_scope ?? "artifact");
  const [submitting, setSubmitting] = useState<"allow" | "block" | null>(null);
  const [resolved, setResolved] = useState<"allow" | "block" | null>(null);
  const [showConsequences, setShowConsequences] = useState(false);
  const [showEvidence, setShowEvidence] = useState(false);
  const [showTechnical, setShowTechnical] = useState(true);
  const [lastAction, setLastAction] = useState<"allow" | "block" | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
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

  useEffect(() => {
    if (item) {
      setScope(normalizeDecisionScope(item, item.recommended_scope));
      setResolved(null);
      setSubmitting(null);
      setLastAction(null);
      setErrorMessage(null);
    }
  }, [item?.request_id]);

  useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  // Keyboard shortcuts
  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if (submitting !== null) return;
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
  }, [submitting, scope, item?.request_id, availableScopeChoices]);

  const handleResolve = useCallback(
    async (action: "allow" | "block") => {
      if (!item) return;
      setSubmitting(action);
      setErrorMessage(null);
      try {
        await props.onResolve(buildDecisionPayload({
          item,
          action,
          scope,
          reason: action === "allow" ? "approved in review" : "blocked in review",
        }));
        setResolved(action);
        timerRef.current = setTimeout(() => setResolved(null), 2000);
      } catch (err) {
        setErrorMessage(err instanceof Error ? err.message : "Something went wrong. Try again.");
      } finally {
        setSubmitting(null);
      }
    },
    [item, scope, props.onResolve]
  );

  const handleRequestResolve = useCallback(
    (action: "allow" | "block") => {
      setLastAction(action);
      void handleResolve(action);
    },
    [handleResolve]
  );
  const handleAllow = useCallback(() => {
    handleRequestResolve("allow");
  }, [handleRequestResolve]);
  const handleBlock = useCallback(() => {
    handleRequestResolve("block");
  }, [handleRequestResolve]);

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
  const hasEvidence = (item.risk_signals?.length ?? 0) > 0 || item.risk_summary || item.why_now;
  const pauseReason = whyPaused(item);

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
            {resolved === "allow" ? "Approved: action can proceed" : "Blocked: action stopped"}
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

        <div className="mt-4 rounded-xl border border-brand-blue/10 bg-brand-blue/[0.04] p-4">
          <p className="text-sm text-brand-dark">{pauseReason}</p>
        </div>

        {item.risk_summary && (
          <div className="mt-4 rounded-xl border border-brand-attention/15 bg-brand-attention/[0.04] p-4">
            <div className="flex items-start gap-2.5">
              <HiMiniExclamationTriangle className="mt-0.5 h-4 w-4 shrink-0 text-brand-attention" aria-hidden="true" />
              <p className="text-sm text-brand-dark">{item.risk_summary}</p>
            </div>
          </div>
        )}

        <div className="mt-4">
          <button
            onClick={() => setShowTechnical(!showTechnical)}
            className="flex items-center gap-2 text-sm font-medium text-slate-500 hover:text-brand-dark transition-colors"
            aria-expanded={showTechnical}
          >
            {showTechnical ? (
              <HiMiniChevronUp className="h-3.5 w-3.5" aria-hidden="true" />
            ) : (
              <HiMiniChevronDown className="h-3.5 w-3.5" aria-hidden="true" />
            )}
            {showTechnical ? "Hide technical details" : "Show technical details"}
          </button>
          {showTechnical && <ActionContentCard item={item} />}
        </div>

        {whatWouldHappen && (
          <div className="mt-5">
            <button
              onClick={() => setShowConsequences(!showConsequences)}
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
                Additional approval scopes
              </summary>
              <p className="mt-2 text-xs text-brand-dark/70">
                These apply across more future sessions. Use them only when a project-level decision is too narrow.
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
                Advanced: applies everywhere
              </summary>
              <p className="mt-2 text-xs text-brand-dark/70">
                This affects every project on this machine. Prefer narrower scopes unless you are sure.
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
                  onClick={() => {
                    setErrorMessage(null);
                    if (lastAction) handleRequestResolve(lastAction);
                  }}
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
            disabled={submitting !== null}
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
            disabled={submitting !== null}
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

      {hasEvidence && (
        <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
          <button
            onClick={() => setShowEvidence(!showEvidence)}
            className="flex w-full items-center justify-between text-left focus:outline-none focus:ring-2 focus:ring-brand-blue/20 rounded-lg px-2 py-1 -ml-2"
            aria-expanded={showEvidence}
          >
            <SectionLabel>Why Guard paused this</SectionLabel>
            {showEvidence ? (
              <HiMiniChevronUp className="h-4 w-4 text-slate-400" aria-hidden="true" />
            ) : (
              <HiMiniChevronDown className="h-4 w-4 text-slate-400" aria-hidden="true" />
            )}
          </button>
          {showEvidence && (
            <div className="mt-4 space-y-3">
              <ScannerEvidenceSection signals={item.decision_v2_json?.signals ?? []} />
              {item.why_now && (
                <div className="rounded-xl border border-brand-purple/15 bg-brand-purple/[0.04] p-4">
                  <p className="text-sm text-brand-dark">{item.why_now}</p>
                </div>
              )}
              <DataFlowEvidenceCard item={item} />
              <SkillRiskCard item={item} />
              <SupplyChainRiskCard item={item} />
              <DecodedLayerCard item={item} />
            </div>
          )}
        </div>
      )}

      {/* Last time */}
      {detail.receipt && (
        <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
          <SectionLabel>Last time</SectionLabel>
          <p className="mt-2 text-sm text-muted-foreground">
            You previously {detail.receipt.policy_decision}d a similar action{" "}
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

function ReviewEmptyState({ runtime, resolutionMessage }: { runtime: GuardRuntimeSnapshot | null; resolutionMessage: string | null }) {
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

      {resolutionMessage && (
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

function ActionContentCard({ item }: { item: GuardApprovalRequest }) {
  const launchText = resolveStoppedCommandText(item);
  const detailText = resolveDecisionV2Detail(item);
  const pauseReason = buildPauseLine(item);
  const envelope = item.action_envelope_json;
  const isMcpTool = envelope?.action_type === "mcp_tool";
  const mcpServer = isMcpTool ? (envelope?.mcp_server ?? null) : null;
  const mcpTool = isMcpTool ? (envelope?.mcp_tool ?? null) : null;
  const mcpInputSummary =
    isMcpTool && envelope !== null && envelope.raw_payload_redacted
      ? (() => {
          const inputs = envelope.raw_payload_redacted.arguments ?? envelope.raw_payload_redacted.input ?? envelope.raw_payload_redacted.params ?? null;
          if (inputs === null) return null;
          try {
            const serialized = JSON.stringify(inputs);
            if (serialized.length <= 2) return null;
            return serialized.length > 140 ? `${serialized.slice(0, 140)}...` : serialized;
          } catch {
            return null;
          }
        })()
      : null;
  const terminalLabel = resolveTerminalLabel(item);

  return (
    <div className="mt-5 space-y-3">
      {/* MCP badge */}
      {isMcpTool && mcpServer !== null && mcpTool !== null && (
        <div className="rounded-xl border border-brand-blue/20 bg-brand-blue/[0.04] px-3 py-2.5">
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.15em] text-brand-blue">
              MCP
            </span>
            <span className="font-mono text-sm font-medium text-brand-dark">
              {mcpServer} → {mcpTool}
            </span>
          </div>
          {mcpInputSummary !== null && (
            <p className="mt-1 truncate font-mono text-xs text-brand-dark/60">
              {mcpInputSummary}
            </p>
          )}
        </div>
      )}

      {/* Why it was paused */}
      <p className="text-sm leading-relaxed text-brand-dark/80">
        {pauseReason}
      </p>
      {detailText && (
        <p className="text-sm leading-relaxed text-brand-dark/80">
          {detailText}
        </p>
      )}

      {/* Terminal display of actual content */}
      <div className="overflow-hidden rounded-xl bg-[#0f172a]">
        <div className="flex items-center gap-1.5 border-b border-white/10 px-3 py-2">
          <span className="h-2.5 w-2.5 rounded-full bg-brand-purple" />
          <span className="h-2.5 w-2.5 rounded-full bg-brand-blue" />
          <span className="h-2.5 w-2.5 rounded-full bg-brand-green" />
          <span className="ml-2 font-mono text-[10px] uppercase tracking-[0.22em] text-white/45">
            {terminalLabel}
          </span>
          <span className="ml-auto">
            <CopyButton text={launchText} />
          </span>
        </div>
        <pre className="max-h-[50vh] overflow-y-auto whitespace-pre-wrap break-words px-3 py-3 font-mono text-sm leading-6 text-white/90 [scrollbar-gutter:stable]">
          {launchText}
        </pre>
      </div>
    </div>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = useCallback(() => {
    void navigator.clipboard?.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, [text]);

  return (
    <button
      type="button"
      onClick={handleCopy}
      aria-label="Copy to clipboard"
      className="inline-flex items-center gap-1 rounded-full border border-white/20 bg-white/10 px-2 py-1 font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-white/70 transition-colors hover:bg-white/20 hover:text-white"
    >
      {copied ? (
        <HiMiniClipboardDocumentCheck className="h-3 w-3" aria-hidden="true" />
      ) : (
        <HiMiniClipboard className="h-3 w-3" aria-hidden="true" />
      )}
      {copied ? "Copied" : "Copy"}
    </button>
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
