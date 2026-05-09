import type { ReactNode } from "react";
import { useState, useEffect, useCallback, useMemo, useRef, type ChangeEvent } from "react";
import {
  HiMiniClipboard,
  HiMiniClipboardDocumentCheck,
  HiMiniExclamationTriangle,
  HiMiniNoSymbol,
  HiMiniArrowTopRightOnSquare,
  HiMiniChevronLeft,
  HiBars3,
  HiMiniXMark as HiMiniXMarkLayout,
  HiMiniCheckCircle,
  HiMiniInformationCircle,
} from "react-icons/hi2";
import {
  ShellHeader,
  ShellSidebar,
  Surface,
  Badge,
  Tag,
  ActionButton,
  KeyValueGrid,
  EmptyState,
  WelcomeState,
  SectionLabel,
  PaginationControls
} from "./approval-center-primitives";
import { DataFlowEvidenceCard } from "./data-flow-evidence-card";
import { SkillRiskCard, SupplyChainRiskCard, DecodedLayerCard } from "./risk-signal-cards";
import { ReceiptsWorkspace } from "./receipts-workspace";
import { QueueChipFilter } from "./queue-chip-filter";
import { ScannerEvidenceSection } from "./scanner-evidence-badge";
import {
  buildPauseLine,
  buildRecommendation,
  buildQueueSummary,
  buildMemorySummary,
  buildStoppedReason,
  policyActionLabel,
  artifactTypeLabel,
  shortConfigPath,
  buildTechnicalSummary,
  humanizeChangedFields,
  harnessDisplayName,
  resolveDecisionV2Title,
  resolveDecisionV2Detail,
  resolveStoppedCommandText,
  displayArtifactName,
  resolveTerminalLabel,
  scopeLabel,
  STALE_REQUEST_COPY,
} from "./approval-center-utils";
import {
  WhyThisPaused,
  ApproveConsequence,
  BlockConsequence,
  KeyboardHints,
  ConfirmModal
} from "./approval-center-review-cards";
import {
  buildProgressCopy,
  sortQueue,
  searchQueue,
  groupDuplicates,
  isReadOnlyQueueGroup,
  bulkApproveActionCount,
  bulkApprovePrimaryIds,
  type QueueSortDirection,
} from "./queue-state";
import type {
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardInventoryItem,
  GuardPolicyDecision,
  GuardReceipt,
  GuardRuntimeSnapshot,
  DecisionScope
} from "./guard-types";

type RequestState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardApprovalRequest[] };
type DetailState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "stale" }
  | {
      kind: "ready";
      item: GuardApprovalRequest;
      diff: GuardArtifactDiff | null;
      receipt: GuardReceipt | null;
      policy: GuardPolicyDecision[];
    };

type ReceiptsState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardReceipt[] };
type RuntimeState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; snapshot: GuardRuntimeSnapshot };
type LayoutProps = {
  view: "home" | "inbox" | "fleet" | "evidence" | "settings";
  requests: RequestState;
  detail: DetailState;
  receipts: ReceiptsState;
  runtime: RuntimeState;
  inventory: GuardInventoryItem[];
  activeRequestId: string | null;
  resolutionMessage: string | null;
  homeContent: ReactNode;
  fleetContent: ReactNode;
  settingsContent: ReactNode;
  onGoHome: () => void;
  onNavigate: (pathname: string) => void;
  onOpenRequest: (requestId: string) => void;
  onRetry?: () => void;
  onResolve: (payload: {
    requestId: string;
    action: "allow" | "block";
    scope: DecisionScope;
    workspace?: string;
    reason: string;
  }) => void;
  onBulkApprove?: (ids: string[]) => void;
  onRepair?: () => Promise<void>;
};

const scopeOptions: Array<{ value: DecisionScope; label: string; description: string }> = [
  { value: "artifact", label: "This exact action", description: "Ask again if the command or tool details change." },
  { value: "workspace", label: "This project folder", description: "Remember this choice only for this project." },
  { value: "publisher", label: "This source", description: "Trust future actions from the same source in this app." },
  { value: "harness", label: "This app", description: "Trust matching actions from this app." },
  { value: "global", label: "Every project", description: "Use this choice across this machine." }
];

const commonScopeValues = new Set<DecisionScope>(["artifact", "workspace"]);
const broadScopeValues = new Set<DecisionScope>(["publisher", "harness", "global"]);
const queuePageSize = 8;
export function ApprovalCenterLayout(props: LayoutProps) {
  const [mobileQueueOpen, setMobileQueueOpen] = useState(false);
  const queuedItems = props.requests.kind === "ready" ? props.requests.items : [];
  const activeHarness =
    props.detail.kind === "ready" ? props.detail.item.harness : queuedItems[0]?.harness ?? null;

  const handleOpenMobileQueue = useCallback(() => setMobileQueueOpen(true), []);
  const handleCloseMobileQueue = useCallback(() => setMobileQueueOpen(false), []);

  return (
    <div className="min-h-screen bg-white text-brand-dark">
      <ShellHeader
        queuedCount={queuedItems.length}
        activeHarness={activeHarness}
        view={props.view}
        onNavigate={props.onNavigate}
        onOpenMobileQueue={handleOpenMobileQueue}
      />
      <ShellSidebar queuedCount={queuedItems.length} activeHarness={activeHarness} view={props.view} />
      {mobileQueueOpen && props.view === "inbox" && props.requests.kind === "ready" && (
        <MobileQueueDrawer
          requests={props.requests.items}
          activeRequestId={props.activeRequestId}
          onClose={handleCloseMobileQueue}
          onOpenRequest={props.onOpenRequest}
          onBulkApprove={props.onBulkApprove}
        />
      )}
      <div className="flex flex-col lg:pl-64">
        <main className="flex-1 p-6 lg:p-10">
          <div className="mx-auto max-w-6xl">
            {props.view === "home" ? (
              props.homeContent
            ) : props.view === "evidence" ? (
              <ReceiptsWorkspace receipts={props.receipts} />
            ) : props.view === "fleet" ? (
              props.fleetContent
            ) : props.view === "settings" ? (
              props.settingsContent
            ) : (
              <QueueWorkspace
                requests={props.requests}
                detail={props.detail}
                runtime={props.runtime}
                activeRequestId={props.activeRequestId}
                resolutionMessage={props.resolutionMessage}
                onOpenRequest={props.onOpenRequest}
                onGoHome={props.onGoHome}
                onResolve={props.onResolve}
                onBulkApprove={props.onBulkApprove}
                onRetry={props.onRetry}
                onRepair={props.onRepair}
              />
            )}
          </div>
        </main>
      </div>
    </div>
  );
}

function MobileQueueDrawer(props: {
  requests: GuardApprovalRequest[];
  activeRequestId: string | null;
  onClose: () => void;
  onOpenRequest: (requestId: string) => void;
  onBulkApprove?: (ids: string[]) => void;
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex lg:hidden"
      role="dialog"
      aria-label="Review queue"
      aria-modal="true"
    >
      <div className="absolute inset-0 bg-black/30 backdrop-blur-sm" onClick={props.onClose} />
      <div className="relative ml-0 flex w-full max-w-sm flex-col overflow-hidden bg-white shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-slate-200 px-4 py-3">
          <span className="text-sm font-semibold text-brand-dark">
            Review Queue ({props.requests.length})
          </span>
          <button
            type="button"
            onClick={props.onClose}
            aria-label="Close queue"
            className="rounded-full p-1.5 text-slate-500 hover:bg-slate-100"
          >
            <HiMiniXMarkLayout className="h-5 w-5" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto">
          <QueueBrowser
            activeRequestId={props.activeRequestId}
            items={props.requests}
            onOpenRequest={props.onOpenRequest}
            onBulkApprove={props.onBulkApprove}
          />
        </div>
      </div>
    </div>
  );
}

function QueueWorkspace(props: {
  requests: RequestState;
  detail: DetailState;
  runtime: RuntimeState;
  activeRequestId: string | null;
  resolutionMessage: string | null;
  onOpenRequest: (requestId: string) => void;
  onGoHome: () => void;
  onResolve: LayoutProps["onResolve"];
  onBulkApprove?: (ids: string[]) => void;
  onRetry?: () => void;
  onRepair?: () => Promise<void>;
}) {
  const [repairing, setRepairing] = useState(false);

  const handleRepair = useCallback(async () => {
    if (props.onRepair === undefined) return;
    setRepairing(true);
    try {
      await props.onRepair();
    } finally {
      setRepairing(false);
    }
  }, [props.onRepair]);

  if (props.requests.kind === "loading") {
    return (
      <div className="space-y-4">
        <div className="guard-skeleton h-8 w-64" />
        <div className="guard-skeleton h-32 w-full" />
      </div>
    );
  }
  if (props.requests.kind === "error") {
    const approvalUrl =
      props.runtime.kind === "ready" ? props.runtime.snapshot.approval_center_url : null;
    return (
      <div className="space-y-4">
        <Surface tone="danger">
          <p className="text-sm font-semibold text-brand-purple">Guard connection lost. Check if the daemon is running.</p>
          <p className="mt-1 text-sm text-brand-purple/80">{props.requests.message}</p>
          <div className="mt-4 flex flex-wrap gap-3">
            {props.onRepair !== undefined && (
              <ActionButton onClick={handleRepair} disabled={repairing}>
                {repairing ? "Repairing…" : "Repair"}
              </ActionButton>
            )}
            <a
              href="x-terminal-emulator://"
              className="inline-flex min-h-10 items-center rounded-lg border border-brand-purple/30 bg-white px-3 py-2 text-sm font-medium text-brand-purple transition-colors hover:bg-brand-purple/5"
            >
              Open Terminal
            </a>
            {props.onRetry && (
              <ActionButton variant="outline" onClick={props.onRetry}>Retry</ActionButton>
            )}
            {approvalUrl && (
              <ActionButton href={approvalUrl} variant="outline" onClick={() => window.location.reload()}>
                Open dashboard
              </ActionButton>
            )}
          </div>
        </Surface>
      </div>
    );
  }
  if (props.requests.items.length === 0) {
    return (
      <WelcomeState
        connectUrl={props.runtime.kind === "ready" ? props.runtime.snapshot.connect_url : null}
        dashboardUrl={props.runtime.kind === "ready" ? props.runtime.snapshot.dashboard_url : null}
        fleetUrl={props.runtime.kind === "ready" ? props.runtime.snapshot.fleet_url : null}
        inboxUrl={props.runtime.kind === "ready" ? props.runtime.snapshot.inbox_url : null}
        resolutionMessage={props.resolutionMessage}
      />
    );
  }
  const showSideBySide = props.requests.items.length > 1;
  const activeIndex = props.requests.items.findIndex(
    (item) => item.request_id === props.activeRequestId
  );
  const progressCopy = buildProgressCopy(
    Math.max(0, activeIndex),
    props.requests.items.length
  );
  return (
    <div className="space-y-4">
      {props.resolutionMessage && props.requests.items.length > 0 && (
        <div className="flex items-start gap-3 rounded-2xl border border-brand-green/25 bg-brand-green-bg/30 px-4 py-3">
          <HiMiniCheckCircle className="mt-0.5 h-4 w-4 shrink-0 text-brand-green" aria-hidden="true" />
          <p className="text-sm font-medium text-brand-green-text">{props.resolutionMessage}</p>
        </div>
      )}
      <QueueHeader
        activeRequestId={props.activeRequestId}
        requests={props.requests.items}
        progressCopy={progressCopy}
        runtime={props.runtime}
      />
      {showSideBySide ? (
        <div className="grid gap-6 lg:grid-cols-[300px_1fr] lg:items-start">
          <aside className="lg:sticky lg:top-6">
            <QueueBrowser
              activeRequestId={props.activeRequestId}
              items={props.requests.items}
              onOpenRequest={props.onOpenRequest}
              onBulkApprove={props.onBulkApprove}
            />
          </aside>
          <div>
            <DecisionWorkspace
              detail={props.detail}
              onGoHome={props.onGoHome}
              onResolve={props.onResolve}
            />
          </div>
        </div>
      ) : (
        <div>
          <button
            type="button"
            onClick={props.onGoHome}
            className="mb-3 flex items-center gap-1 text-sm font-medium text-brand-blue transition-colors hover:text-brand-blue/70 lg:hidden"
          >
            <HiMiniChevronLeft className="h-4 w-4" />
            Back to queue
          </button>
          <DecisionWorkspace
            detail={props.detail}
            onGoHome={props.onGoHome}
            onResolve={props.onResolve}
          />
        </div>
      )}
    </div>
  );
}

function QueueHeader(props: {
  activeRequestId: string | null;
  requests: GuardApprovalRequest[];
  progressCopy: string;
  runtime: RuntimeState;
}) {
  const activeItem = props.requests.find((item) => item.request_id === props.activeRequestId) ?? props.requests[0] ?? null;
  const runtimeLabel = props.runtime.kind === "ready" ? props.runtime.snapshot.cloud_state_label : "Local runtime";
  return (
    <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-[-0.02em] text-brand-dark">
          Review Queue
        </h1>
        <p className="max-w-2xl text-sm leading-relaxed text-muted-foreground">
          HOL Guard paused this before it ran. Review what was stopped, then approve or block it.
        </p>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {props.progressCopy.length > 0 && (
          <span
            className="font-mono text-xs font-semibold text-muted-foreground"
            aria-label={`Queue position: ${props.progressCopy}`}
          >
            {props.progressCopy}
          </span>
        )}
        <Badge tone="default">{props.requests.length} waiting</Badge>
        {activeItem ? <Tag tone="blue">{harnessDisplayName(activeItem.harness)}</Tag> : null}
        <Tag tone="slate">{runtimeLabel}</Tag>
      </div>
    </div>
  );
}

function QueueBrowser(props: {
  activeRequestId: string | null;
  items: GuardApprovalRequest[];
  onOpenRequest: (requestId: string) => void;
  onBulkApprove?: (ids: string[]) => void;
}) {
  const [searchTerm, setSearchTerm] = useState("");
  const [harnessFilter, setHarnessFilter] = useState("all");
  const [sortDirection, setSortDirection] = useState<QueueSortDirection>("newest");
  const [page, setPage] = useState(1);
  const harnesses = Array.from(new Set(props.items.map((item) => item.harness))).sort();

  const filteredItems = useMemo(() => {
    const byHarness =
      harnessFilter === "all"
        ? props.items
        : props.items.filter((item) => item.harness === harnessFilter);
    const searched = searchQueue(byHarness, searchTerm);
    return sortQueue(searched, sortDirection);
  }, [harnessFilter, props.items, searchTerm, sortDirection]);

  const groups = useMemo(() => groupDuplicates(filteredItems), [filteredItems]);
  const totalPages = Math.max(1, Math.ceil(groups.length / queuePageSize));
  const currentPage = Math.min(page, totalPages);
  const pageStart = (currentPage - 1) * queuePageSize;
  const visibleGroups = groups.slice(pageStart, pageStart + queuePageSize);

  const allGroups = useMemo(() => groupDuplicates(props.items), [props.items]);
  const nextUpItem = useMemo(() => {
    if (allGroups.length < 2 || props.activeRequestId === null) return null;
    const activeIdx = allGroups.findIndex((g) => g.primary.request_id === props.activeRequestId);
    if (activeIdx < 0 || activeIdx >= allGroups.length - 1) return null;
    return allGroups[activeIdx + 1]?.primary ?? null;
  }, [allGroups, props.activeRequestId]);

  useEffect(() => {
    setPage(1);
  }, [harnessFilter, searchTerm, sortDirection, props.items.length]);

  const handleSearchChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setSearchTerm(event.target.value);
  }, []);

  const handleSortChange = useCallback((event: ChangeEvent<HTMLSelectElement>) => {
    setSortDirection(event.target.value as QueueSortDirection);
  }, []);

  const handlePreviousPage = useCallback(() => {
    setPage((value) => Math.max(1, value - 1));
  }, []);

  const handleNextPage = useCallback(() => {
    setPage((value) => Math.min(totalPages, value + 1));
  }, [totalPages]);

  const isReadOnlyGroup = useCallback(
    (group: ReturnType<typeof groupDuplicates>[number]) => isReadOnlyQueueGroup(group),
    []
  );

  const bulkEligibleGroups = useMemo(
    () => groups.filter(isReadOnlyGroup),
    [groups, isReadOnlyGroup]
  );

  const bulkEligibleActionCount = useMemo(
    () => bulkApproveActionCount(bulkEligibleGroups),
    [bulkEligibleGroups]
  );

  const showBulkApprove =
    props.onBulkApprove !== undefined &&
    bulkEligibleGroups.length > 0 &&
    bulkEligibleGroups.length === groups.length;

  const handleBulkApprove = useCallback(() => {
    const ids = bulkApprovePrimaryIds(bulkEligibleGroups);
    props.onBulkApprove?.(ids);
  }, [props.onBulkApprove, bulkEligibleGroups]);

  return (
    <section>
      {showBulkApprove && (
        <div className="mb-4">
          <button
            type="button"
            onClick={handleBulkApprove}
            className="rounded-full border border-brand-blue/30 bg-white px-4 py-2 text-sm font-medium text-brand-blue shadow-sm transition-colors hover:bg-brand-blue/5"
          >
            Approve all read-only actions ({bulkEligibleActionCount})
          </button>
        </div>
      )}
      <div className="mb-3 space-y-2">
        <label className="block">
          <span className="sr-only">Search waiting actions</span>
          <input
            type="search"
            value={searchTerm}
            onChange={handleSearchChange}
            placeholder="Command, file, MCP, host…"
            className="min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm text-brand-dark placeholder:text-slate-400 transition-colors duration-150 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          />
        </label>
        {harnesses.length > 0 && (
          <QueueChipFilter
            harnesses={harnesses}
            activeFilter={harnessFilter}
            onFilterChange={setHarnessFilter}
          />
        )}
        <label className="block">
          <span className="sr-only">Sort order</span>
          <select
            value={sortDirection}
            onChange={handleSortChange}
            className="min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors duration-150 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          >
            <option value="newest">Newest first</option>
            <option value="oldest">Oldest first</option>
          </select>
        </label>
      </div>
      <div className="divide-y divide-slate-200/70 overflow-hidden rounded-[1.5rem] border border-slate-200/70 bg-white/75 shadow-sm">
        {visibleGroups.length > 0 ? (
          visibleGroups.map((group) => (
            <QueueCardRow
              key={group.primary.request_id}
              group={group}
              activeRequestId={props.activeRequestId}
              nextUpItem={
                nextUpItem !== null && group.primary.request_id === props.activeRequestId
                  ? nextUpItem
                  : null
              }
              onOpenRequest={props.onOpenRequest}
            />
          ))
        ) : (
          <p className="px-4 py-5 text-sm text-muted-foreground">
            No waiting actions match those filters.
          </p>
        )}
      </div>
      <PaginationControls
        page={currentPage}
        totalPages={totalPages}
        totalItems={groups.length}
        pageSize={queuePageSize}
        onPrevious={handlePreviousPage}
        onNext={handleNextPage}
        className="mt-4"
      />
    </section>
  );
}

function QueueCardRow(props: {
  group: ReturnType<typeof groupDuplicates>[number];
  activeRequestId: string | null;
  nextUpItem: GuardApprovalRequest | null;
  onOpenRequest: (requestId: string) => void;
}) {
  const handleClick = useCallback(() => {
    props.onOpenRequest(props.group.primary.request_id);
  }, [props.onOpenRequest, props.group.primary.request_id]);

  return (
    <div>
      <QueueCard
        item={props.group.primary}
        duplicateCount={props.group.duplicateCount}
        active={props.group.primary.request_id === props.activeRequestId}
        onClick={handleClick}
      />
      {props.nextUpItem !== null && (
        <div className="border-t border-slate-100 bg-slate-50/60 px-4 py-2">
          <p className="truncate text-[11px] text-muted-foreground">
            <span className="font-semibold">Next up:</span>{" "}
            {displayArtifactName(props.nextUpItem)}
          </p>
        </div>
      )}
    </div>
  );
}

function QueueCard(props: { item: GuardApprovalRequest; duplicateCount: number; active: boolean; onClick: () => void }) {
  const summary = buildQueueSummary(props.item);
  const isBlocked = props.item.policy_action === "block";
  const statusDotClass = queueCardStatusDotClass(props.active, isBlocked);
  return (
    <button
      type="button"
      onClick={props.onClick}
      aria-pressed={props.active}
      className={`group/item w-full cursor-pointer border-l-4 px-4 py-3.5 text-left transition-all duration-150 hover:bg-brand-blue/[0.035] ${
        props.active
          ? "border-brand-blue bg-brand-blue/[0.06]"
          : "border-transparent bg-white/70"
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-start gap-3">
           <span
             className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full transition-colors ${
               statusDotClass
             }`}
           />
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold text-brand-dark">{actionDisplayTitle(props.item)}</p>
            <p className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">
              {displayArtifactName(props.item)}
            </p>
          </div>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-1">
          <PolicyBadge action={props.item.policy_action} />
          {props.duplicateCount > 0 && (
            <span className="rounded-full bg-slate-100 px-2 py-0.5 font-mono text-[10px] font-semibold text-muted-foreground">
              +{props.duplicateCount} repeat{props.duplicateCount !== 1 ? "s" : ""} collapsed
            </span>
          )}
        </div>
      </div>
      <p className="mt-2 line-clamp-2 text-xs leading-relaxed text-muted-foreground">
        {harnessDisplayName(props.item.harness)} · {summary}
      </p>
    </button>
  );
}

function queueCardStatusDotClass(active: boolean, blocked: boolean): string {
  if (active) {
    return "bg-brand-blue";
  }
  if (blocked) {
    return "bg-brand-purple";
  }
  return "bg-slate-200";
}

function StickyMobileActions(props: {
  allowLabel: string;
  submitting: "allow" | "block" | null;
  isBlocked: boolean;
  onAllow: () => void;
  onBlock: () => void;
}) {
  const allowText = resolveAllowButtonText(props.submitting, props.isBlocked, props.allowLabel);
  const blockText = resolveBlockButtonText(props.submitting, props.isBlocked);
  return (
    <div className="sticky bottom-0 z-20 -mx-6 border-t border-slate-200/70 bg-white/95 px-4 py-3 shadow-[0_-4px_16px_rgba(63,65,116,0.08)] backdrop-blur lg:hidden">
      <div className="grid grid-cols-2 gap-2">
        <ActionButton variant="success" onClick={props.onAllow} disabled={props.submitting !== null}>
          {allowText}
        </ActionButton>
        <ActionButton variant="danger" onClick={props.onBlock} disabled={props.submitting !== null}>
          {blockText}
        </ActionButton>
      </div>
    </div>
  );
}

function DecisionWorkspace(props: {
  detail: DetailState;
  onGoHome: () => void;
  onResolve: LayoutProps["onResolve"];
}) {
  const [scope, setScope] = useState<DecisionScope>("artifact");
  const [reason, setReason] = useState("approved in local approval center");
  const [submitting, setSubmitting] = useState<"allow" | "block" | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [confirmPending, setConfirmPending] = useState<"allow" | "block" | null>(null);
  const [resolvedBanner, setResolvedBanner] = useState<"allow" | "block" | null>(null);
  const bannerTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const prevRequestIdRef = useRef<string | null>(null);

  useEffect(() => {
    if (props.detail.kind === "ready") {
      const isNewItem = props.detail.item.request_id !== prevRequestIdRef.current;
      prevRequestIdRef.current = props.detail.item.request_id;
      if (isNewItem) {
        setResolvedBanner(null);
        if (bannerTimerRef.current !== null) {
          clearTimeout(bannerTimerRef.current);
          bannerTimerRef.current = null;
        }
      }
      setScope(props.detail.item.recommended_scope);
      setErrorMessage(null);
      setSubmitting(null);
    }
  }, [props.detail]);

  useEffect(() => {
    return () => {
      if (bannerTimerRef.current !== null) {
        clearTimeout(bannerTimerRef.current);
      }
    };
  }, []);

  const readyItem = props.detail.kind === "ready" ? props.detail.item : null;
  const readyRequestId = readyItem?.request_id ?? "";
  const readyWorkspace = readyItem?.workspace ?? undefined;

  const handleResolve = useCallback(
    async (action: "allow" | "block") => {
      setSubmitting(action);
      setErrorMessage(null);
      try {
        await props.onResolve({
          requestId: readyRequestId,
          action,
          scope,
          reason,
          workspace: scope === "workspace" ? readyWorkspace : undefined,
        });
        setResolvedBanner(action);
        bannerTimerRef.current = setTimeout(() => {
          setResolvedBanner(null);
        }, 1500);
      } catch (error) {
        setErrorMessage(error instanceof Error ? error.message : "Something went wrong.");
        setSubmitting(null);
      }
    },
    [props.onResolve, readyRequestId, readyWorkspace, reason, scope]
  );

  const handleRequestResolve = useCallback(
    (action: "allow" | "block") => {
      if (broadScopeValues.has(scope)) {
        setConfirmPending(action);
      } else {
        void handleResolve(action);
      }
    },
    [scope, handleResolve]
  );

  const handleConfirmResolve = useCallback(() => {
    if (confirmPending !== null) {
      void handleResolve(confirmPending);
      setConfirmPending(null);
    }
  }, [confirmPending, handleResolve]);

  const handleCancelConfirm = useCallback(() => {
    setConfirmPending(null);
  }, []);

  const handleAllowDirect = useCallback(() => handleRequestResolve("allow"), [handleRequestResolve]);
  const handleBlockDirect = useCallback(() => handleRequestResolve("block"), [handleRequestResolve]);

  useEffect(() => {
    if (props.detail.kind !== "ready") return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (submitting !== null) return;
      if (confirmPending !== null) {
        if (event.key === "Enter") {
          handleConfirmResolve();
          return;
        }
        if (event.key === "Escape") {
          handleCancelConfirm();
          return;
        }
        return;
      }
      const target = event.target as HTMLElement;
      if (
        target.tagName === "INPUT" ||
        target.tagName === "TEXTAREA" ||
        target.tagName === "SELECT" ||
        target.isContentEditable
      ) return;
      if (event.key === "a" || event.key === "A") handleRequestResolve("allow");
      else if (event.key === "b" || event.key === "B") handleRequestResolve("block");
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [props.detail.kind, submitting, handleRequestResolve, confirmPending, handleConfirmResolve, handleCancelConfirm]);

  if (props.detail.kind === "loading") {
    return (
      <div className="space-y-4">
        <div className="guard-skeleton h-8 w-48" />
        <div className="guard-skeleton h-40 w-full" />
        <div className="guard-skeleton h-56 w-full" />
      </div>
    );
  }
  if (props.detail.kind === "stale") {
    return (
      <Surface tone="default">
        <div className="flex items-start gap-3">
          <HiMiniInformationCircle className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />
          <div>
            <p className="text-sm font-medium text-brand-dark">{STALE_REQUEST_COPY}</p>
            <p className="mt-1 text-sm text-muted-foreground">
              Someone already reviewed this blocked action. No further action needed.
            </p>
          </div>
        </div>
        <div className="mt-4">
          <ActionButton variant="outline" onClick={props.onGoHome}>Back to queue</ActionButton>
        </div>
      </Surface>
    );
  }
  if (props.detail.kind === "error") {
    return (
      <Surface tone="danger">
        <p className="text-sm text-brand-purple">{props.detail.message}</p>
        <ActionButton variant="outline" onClick={props.onGoHome}>Back to queue</ActionButton>
      </Surface>
    );
  }
  if (props.detail.kind === "idle") {
    return <EmptyState title="Select an item" body="Choose a blocked item from the list to review the evidence and make a decision." />;
  }
  const { item, diff, receipt, policy } = props.detail;
  const commonScopeOpts = scopeOptions.filter((option) => commonScopeValues.has(option.value));
  const broadScopeOpts = scopeOptions.filter((option) => !commonScopeValues.has(option.value));
  const isAlreadyDecided = item.resolution_action !== null;
  const decidedLabel =
    item.resolution_action === "allow" ? "allow" : item.resolution_action === "block" ? "block" : item.resolution_action ?? "decided";
  const allowLabel = scope === "artifact" ? "Approve once" : "Approve and remember";
  return (
    <div className="guard-surface-in space-y-4">
      {resolvedBanner !== null && (
        <div
          className={`flex items-center gap-3 rounded-2xl border px-4 py-3 ${
            resolvedBanner === "allow"
              ? "border-brand-green/25 bg-brand-green-bg/30"
              : "border-brand-purple/25 bg-brand-purple/[0.06]"
          }`}
          role="status"
          aria-live="polite"
        >
          <HiMiniCheckCircle
            className={`h-4 w-4 shrink-0 ${resolvedBanner === "allow" ? "text-brand-green" : "text-brand-purple"}`}
            aria-hidden="true"
          />
          <p className={`text-sm font-medium ${resolvedBanner === "allow" ? "text-brand-green-text" : "text-brand-purple"}`}>
            {resolvedBanner === "allow" ? "✓ Approved" : "✗ Blocked"}
          </p>
        </div>
      )}
      {isAlreadyDecided && (
        <div className="flex items-start gap-3 rounded-2xl border border-slate-200/60 bg-slate-50 px-4 py-3">
          <HiMiniInformationCircle className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />
          <p className="text-sm text-muted-foreground">
            This action was already decided — {decidedLabel}. No further action needed.
          </p>
        </div>
      )}
      {confirmPending !== null && (
        <ConfirmModal
          action={confirmPending}
          scopeLabel={scopeLabel(scope)}
          onConfirm={handleConfirmResolve}
          onCancel={handleCancelConfirm}
        />
      )}
      <RuleBuilder
        item={item}
        scope={scope}
        reason={reason}
        submitting={submitting}
        errorMessage={errorMessage}
        commonScopeOptions={commonScopeOpts}
        broadScopeOptions={broadScopeOpts}
        onScopeChange={setScope}
        onReasonChange={setReason}
        onResolve={handleRequestResolve}
      />
      <StickyMobileActions
        allowLabel={allowLabel}
        submitting={submitting}
        isBlocked={item.policy_action === "block"}
        onAllow={handleAllowDirect}
        onBlock={handleBlockDirect}
      />
      <ScannerEvidenceSectionFull item={item} />
      <WhatChanged item={item} diff={diff} receipt={receipt} policy={policy} />
    </div>
  );
}

function InlineScannerSection(props: { item: GuardApprovalRequest }) {
  const allSignals = props.item.decision_v2_json?.signals ?? [];
  return <ScannerEvidenceSection signals={allSignals} />;
}

function ScannerEvidenceSectionFull(props: { item: GuardApprovalRequest }) {
  const hasSignals =
    (props.item.risk_signals ?? []).length > 0 ||
    !!props.item.risk_summary ||
    !!props.item.why_now;
  if (!hasSignals) return null;
  return (
    <div className="space-y-3">
      <InlineScannerSection item={props.item} />
      <WhyGuardCares item={props.item} />
      <DataFlowEvidenceCard item={props.item} />
      <SkillRiskCard item={props.item} />
      <SupplyChainRiskCard item={props.item} />
      <DecodedLayerCard item={props.item} />
    </div>
  );
}

function buildDecisionTitle(item: GuardApprovalRequest): string {
  if (item.risk_headline) {
    return simplifyRiskHeadline(item.risk_headline, item.harness);
  }
  if (item.policy_action === "block") {
    return "HOL Guard kept this action blocked.";
  }
  return `${harnessDisplayName(item.harness)} wants to run this action.`;
}

function WhyGuardCares(props: { item: GuardApprovalRequest }) {
  const { item } = props;
  const signals = item.risk_signals ?? [];
  if (signals.length === 0 && !item.risk_summary && !item.why_now) return null;
  return (
    <div className="rounded-xl border border-brand-purple/20 bg-brand-purple/[0.04] p-4">
      <SectionLabel>Why this was paused</SectionLabel>
      {item.why_now ? <p className="mt-1 text-sm leading-relaxed text-brand-dark/80">{item.why_now}</p> : null}
      {item.risk_summary ? <p className="mt-1 text-sm leading-relaxed text-brand-dark/80">{item.risk_summary}</p> : null}
      {signals.length > 0 ? (
        <ul className="mt-2 space-y-1">
          {signals.map((signal) => (
            <li key={signal} className="flex items-start gap-2 text-sm text-brand-purple">
              <span className="mt-1 block h-1.5 w-1.5 flex-shrink-0 rounded-full bg-brand-purple/70" />
              <span className="font-mono text-[13px]">{signal}</span>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function WhatChanged(props: { item: GuardApprovalRequest; diff: GuardArtifactDiff | null; receipt: GuardReceipt | null; policy: GuardPolicyDecision[]; }) {
  const { item, diff, receipt, policy } = props;
  const evidenceRows: Array<[string, string]> = [
    ["Action ID", item.artifact_id],
    ["Hash", item.artifact_hash],
    ["Config", shortConfigPath(item.config_path)],
    ["What changed", item.changed_fields.length > 0 ? humanizeChangedFields(item.changed_fields) : "Nothing"],
    ...(item.launch_target ? [["Launch target", item.launch_target] as [string, string]] : []),
    ...(item.transport ? [["Transport", item.transport] as [string, string]] : []),
    ...buildTechnicalSummary(diff, item)
  ];
  return (
    <details className="group rounded-2xl border border-slate-200/60 bg-card p-5 shadow-sm sm:p-6">
      <summary className="flex cursor-pointer select-none items-center justify-between gap-3 text-sm font-medium text-brand-dark [&::-webkit-details-marker]:hidden">
        <span className="flex items-center gap-2">
          <span className="text-brand-blue transition-transform duration-200 group-open:rotate-90">›</span>
          Technical details
        </span>
        <Badge tone="warning">{artifactTypeLabel(item.artifact_type)}</Badge>
      </summary>
      <div className="mt-4 space-y-3 border-l-2 border-brand-blue/10 pl-4">
        <p className="text-sm leading-relaxed text-brand-dark/70">{buildStoppedReason(item, receipt)}</p>
        {policy.length > 0 ? (
          <p className="text-sm leading-relaxed text-brand-dark/70">
            HOL Guard checked {policy.length} saved {policy.length === 1 ? "decision" : "decisions"} before asking you.
          </p>
        ) : null}
        <KeyValueGrid items={evidenceRows} columns={2} />
        {receipt ? (
          <Surface className="text-xs shadow-none">
            <SectionLabel>Previously trusted</SectionLabel>
            <p className="mt-2 text-brand-dark/70">{buildMemorySummary(item, receipt)}</p>
            <p className="mt-2 font-mono text-muted-foreground">
              {receipt.policy_decision} · {receipt.timestamp}
            </p>
          </Surface>
        ) : null}
      </div>
    </details>
  );
}

function RuleBuilder(props: {
  item: GuardApprovalRequest;
  scope: DecisionScope;
  reason: string;
  submitting: "allow" | "block" | null;
  errorMessage: string | null;
  commonScopeOptions: typeof scopeOptions;
  broadScopeOptions: typeof scopeOptions;
  onScopeChange: (scope: DecisionScope) => void;
  onReasonChange: (reason: string) => void;
  onResolve: (action: "allow" | "block") => void;
}) {
  const previewText = getRulePreviewText(props.item, props.scope);
  const allowLabel = props.scope === "artifact" ? "Approve once" : "Approve and remember";
  const retryInstruction = props.item.decision_v2_json?.retry_instruction ?? null;

  const handleAllow = useCallback(() => props.onResolve("allow"), [props.onResolve]);
  const handleBlock = useCallback(() => props.onResolve("block"), [props.onResolve]);
  const handleReasonChange = useCallback((e: ChangeEvent<HTMLInputElement>) => {
    props.onReasonChange(e.target.value);
  }, [props.onReasonChange]);

  return (
    <section className="guard-surface-in relative overflow-hidden rounded-[2rem] border border-brand-blue/15 bg-[radial-gradient(circle_at_top_left,rgba(85,153,254,0.12),transparent_32%),linear-gradient(135deg,#ffffff_0%,#ffffff_58%,rgba(85,153,254,0.08)_100%)] p-5 shadow-[0_20px_60px_rgba(63,65,116,0.08)] sm:p-6 lg:p-7">
      <div className="pointer-events-none absolute right-8 top-8 h-24 w-24 rounded-full bg-brand-green/20 blur-3xl" />
      <div className="relative">
        <div className="flex flex-wrap items-center gap-2">
          <Tag tone="blue">HOL Guard</Tag>
          <Tag tone="slate">{harnessDisplayName(props.item.harness)}</Tag>
          <PolicyBadge action={props.item.policy_action} />
        </div>
        <div className="mt-4 max-w-3xl">
          <SectionLabel>Needs your decision</SectionLabel>
          <h3 className="mt-2 text-2xl font-semibold tracking-tight text-brand-dark sm:text-3xl">
            {buildDecisionTitle(props.item)}
          </h3>
          <p className="mt-3 max-w-2xl text-sm leading-6 text-brand-dark/70">
            {buildPauseLine(props.item)}
          </p>
        </div>
      </div>

      <div className="relative mt-5 sticky top-4 z-10">
        <DecisionActionPanel
          allowLabel={allowLabel}
          previewText={previewText}
          submitting={props.submitting}
          isBlocked={props.item.policy_action === "block"}
          retryInstruction={retryInstruction}
          onAllow={handleAllow}
          onBlock={handleBlock}
        />
      </div>

      <DecisionSteps activeStep={props.submitting === null ? 1 : 3} />
      <KeyboardHints />

      <div className="relative mt-6 grid gap-6 xl:grid-cols-[minmax(0,1.08fr)_minmax(340px,0.92fr)] xl:items-start">
        <BlockedActionCard item={props.item} />
        <div className="space-y-4 xl:sticky xl:top-6">
          <div>
            <SectionLabel>Approval scope</SectionLabel>
            <p className="mt-2 text-sm leading-6 text-brand-dark/75">
              {buildRecommendation(props.item)}
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              Start with the narrowest scope. Broader trust is harder to undo.
            </p>
          </div>
          <fieldset className="space-y-3">
            <legend className="sr-only">Approval scope</legend>
            <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-1">
              {props.commonScopeOptions.map((option) => (
                <ScopeOptionRow
                  key={option.value}
                  option={option}
                  checked={props.scope === option.value}
                  onScopeChange={props.onScopeChange}
                />
              ))}
            </div>
            <details>
              <summary className="cursor-pointer select-none py-1 font-mono text-[11px] font-semibold uppercase tracking-[0.2em] text-muted-foreground transition-colors hover:text-brand-dark/70 [&::-webkit-details-marker]:hidden">
                › Broader approval scopes
              </summary>
              <div className="mt-2 rounded-[1rem] border border-amber-200/60 bg-amber-50/50 p-2 dark:border-amber-500/20 dark:bg-amber-900/10">
                <p className="mb-2 px-1 text-[11px] font-medium text-amber-700 dark:text-amber-400">
                  Broader scopes apply across more sessions. Use only when the narrower options are not enough.
                </p>
                <div className="grid gap-2 sm:grid-cols-3 xl:grid-cols-1">
                  {props.broadScopeOptions.map((option) => (
                    <ScopeOptionRow
                      key={option.value}
                      option={option}
                      checked={props.scope === option.value}
                      onScopeChange={props.onScopeChange}
                    />
                  ))}
                </div>
              </div>
            </details>
          </fieldset>
          <div>
            <label htmlFor="guard-reason" className="block font-mono text-[11px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
              Optional note
            </label>
            <input
              id="guard-reason"
              type="text"
              value={props.reason}
              onChange={handleReasonChange}
              className="mt-2 min-h-11 w-full rounded-full border border-border bg-white/90 px-4 py-2 text-sm text-brand-dark placeholder:text-muted-foreground transition-colors focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
              placeholder="Why are you allowing or blocking this?"
            />
          </div>
        </div>
      </div>
      {props.errorMessage ? (
        <p className="guard-fade-in mt-3 rounded-xl border border-brand-purple/25 bg-brand-purple/[0.05] px-3 py-2 text-sm text-brand-purple">{props.errorMessage}</p>
      ) : null}
    </section>
  );
}

function DecisionActionPanel(props: {
  allowLabel: string;
  previewText: string;
  submitting: "allow" | "block" | null;
  isBlocked: boolean;
  retryInstruction: string | null;
  onAllow: () => void;
  onBlock: () => void;
}) {
  const allowText = resolveAllowButtonText(props.submitting, props.isBlocked, props.allowLabel);
  const blockText = resolveBlockButtonText(props.submitting, props.isBlocked);

  return (
    <div className="rounded-[1.65rem] border border-white/80 bg-white/80 p-4 shadow-[0_16px_40px_rgba(63,65,116,0.10)] backdrop-blur">
      <SectionLabel>Decision</SectionLabel>
      <p className="mt-2 text-sm leading-6 text-brand-dark/70">
        {props.previewText}
      </p>
      <div className="mt-3 grid gap-1.5">
        <ApproveConsequence retryInstruction={props.retryInstruction} />
        <BlockConsequence />
      </div>
      <div className="mt-4 grid gap-2">
        <ActionButton variant="success" onClick={props.onAllow} disabled={props.submitting !== null}>
          {allowText}
        </ActionButton>
        <ActionButton variant="danger" onClick={props.onBlock} disabled={props.submitting !== null}>
          {blockText}
        </ActionButton>
      </div>
      <p className="mt-3 text-xs leading-5 text-muted-foreground">
        After saving, retry the same request in your chat.
      </p>
    </div>
  );
}

function resolveAllowButtonText(
  submitting: "allow" | "block" | null,
  blocked: boolean,
  allowLabel: string
): string {
  if (submitting === "allow") {
    return "Saving…";
  }
  if (blocked) {
    return "Allow — override block";
  }
  return allowLabel;
}

function resolveBlockButtonText(submitting: "allow" | "block" | null, blocked: boolean): string {
  if (submitting === "block") {
    return "Saving…";
  }
  if (blocked) {
    return "Keep blocked";
  }
  return "Block this action";
}

function DecisionSteps(props: { activeStep: number }) {
  const steps = [
    "Review the stopped action",
    "Choose the safest trust level",
    "Save and retry in your chat"
  ];
  return (
    <ol className="relative mt-6 grid gap-3 md:grid-cols-3" aria-label="Guard review steps">
      {steps.map((step, index) => {
        const stepNumber = index + 1;
        const active = stepNumber === props.activeStep;
        return (
          <li
            key={step}
            className={`relative flex items-center gap-3 rounded-full border px-3 py-2.5 ${
              active
                ? "border-brand-blue/25 bg-white text-brand-dark shadow-sm"
                : "border-transparent bg-white/50 text-muted-foreground"
            }`}
          >
            <span className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-full font-mono text-[11px] font-semibold ${
              active ? "bg-brand-blue text-white" : "bg-surface-2 text-brand-dark/60"
            }`}>
              {stepNumber}
            </span>
            <span className="text-sm font-semibold leading-5">{step}</span>
          </li>
        );
      })}
    </ol>
  );
}

function CopyCommandButton(props: { command: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(() => {
    void navigator.clipboard?.writeText(props.command)?.then(() => {
      setCopied(true);
      const timer = setTimeout(() => setCopied(false), 2000);
      return timer;
    });
  }, [props.command]);

  return (
    <button
      type="button"
      onClick={handleCopy}
      aria-label="Copy command to clipboard"
      className="inline-flex items-center gap-1.5 rounded-full border border-white/20 bg-white/10 px-2.5 py-1 font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-white/70 transition-colors hover:bg-white/20 hover:text-white"
    >
      {copied ? (
        <HiMiniClipboardDocumentCheck className="h-3.5 w-3.5" aria-hidden="true" />
      ) : (
        <HiMiniClipboard className="h-3.5 w-3.5" aria-hidden="true" />
      )}
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

function resolveMcpInputSummary(payload: Record<string, unknown>): string | null {
  const inputs = payload.arguments ?? payload.input ?? payload.params ?? null;
  if (inputs === null || inputs === undefined) return null;
  try {
    const serialized = JSON.stringify(inputs);
    if (serialized.length <= 2) return null;
    return serialized.length > 140 ? `${serialized.slice(0, 140)}…` : serialized;
  } catch {
    return null;
  }
}

function BlockedActionCard(props: { item: GuardApprovalRequest }) {
  const launchText = actionLaunchText(props.item);
  const decisionDetail = resolveDecisionV2Detail(props.item);
  const isBlocked = props.item.policy_action === "block";
  const bannerBg = isBlocked
    ? "bg-gradient-to-r from-brand-purple/90 to-brand-purple/75"
    : "bg-gradient-to-r from-brand-blue/85 to-brand-dark/80";
  const bannerLabel = isBlocked ? "Blocked" : "Paused for review";
  const bannerIcon = isBlocked ? HiMiniNoSymbol : HiMiniExclamationTriangle;
  const BannerIcon = bannerIcon;
  const envelope = props.item.action_envelope_json;
  const isMcpTool = envelope?.action_type === "mcp_tool";
  const mcpServer = isMcpTool ? (envelope?.mcp_server ?? null) : null;
  const mcpTool = isMcpTool ? (envelope?.mcp_tool ?? null) : null;
  const mcpInputSummary =
    isMcpTool && envelope !== null
      ? resolveMcpInputSummary(envelope.raw_payload_redacted)
      : null;

  return (
    <div className="overflow-hidden rounded-[1.65rem] border border-brand-blue/15 bg-white/70 shadow-[inset_0_1px_0_rgba(255,255,255,0.85)]">
      <div className={`flex items-center gap-2 px-4 py-2.5 ${bannerBg}`}>
        <BannerIcon className="h-3.5 w-3.5 shrink-0 text-white" aria-hidden="true" />
        <span className="font-mono text-[11px] font-semibold uppercase tracking-[0.2em] text-white">
          {bannerLabel}
        </span>
        {props.item.approval_url ? (
          <a
            href={props.item.approval_url}
            target="_blank"
            rel="noreferrer"
            className="ml-auto inline-flex items-center gap-1 font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-white/80 transition-colors hover:text-white"
          >
            Approval link
            <HiMiniArrowTopRightOnSquare className="h-3 w-3" aria-hidden="true" />
          </a>
        ) : null}
      </div>
      <div className="p-4">
        {isMcpTool && mcpServer !== null && mcpTool !== null && (
          <div className="mb-3 space-y-2 rounded-xl border border-brand-blue/20 bg-brand-blue/[0.04] px-3 py-2">
            <div className="flex items-center gap-2">
              <span className="font-mono text-[11px] font-semibold uppercase tracking-[0.15em] text-brand-blue">
                MCP
              </span>
              <span className="font-mono text-sm font-medium text-brand-dark">
                {mcpServer} → {mcpTool}
              </span>
            </div>
            {mcpInputSummary !== null && (
              <p className="truncate font-mono text-xs text-brand-dark/60">
                {mcpInputSummary}
              </p>
            )}
          </div>
        )}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <SectionLabel>What was stopped</SectionLabel>
        </div>
        <h4 className="mt-2 text-xl font-semibold tracking-tight text-brand-dark">
          {actionDisplayTitle(props.item)}
        </h4>
        <p className="mt-2 text-sm leading-6 text-brand-dark/70">
          {harnessDisplayName(props.item.harness)} paused this because {buildQueueSummary(props.item).toLowerCase()}.
        </p>
        {decisionDetail !== null ? (
          <p className="mt-2 text-sm leading-6 text-brand-dark/80">
            {decisionDetail}
          </p>
        ) : null}
        <div className="mt-4 rounded-[1.25rem] bg-[#090d1a] p-1 shadow-[0_14px_35px_rgba(9,13,26,0.18)]">
          <div className="flex items-center gap-1.5 border-b border-white/10 px-3 py-2">
            <span className="h-2.5 w-2.5 rounded-full bg-brand-purple" />
            <span className="h-2.5 w-2.5 rounded-full bg-brand-blue" />
            <span className="h-2.5 w-2.5 rounded-full bg-brand-green" />
            <span className="ml-2 font-mono text-[10px] uppercase tracking-[0.22em] text-white/45">
              {resolveTerminalLabel(props.item)}
            </span>
            <span className="ml-auto">
              <CopyCommandButton command={launchText} />
            </span>
          </div>
          <pre className="overflow-x-auto whitespace-pre-wrap break-words px-3 py-3 font-mono text-sm leading-6 text-white">
            {launchText}
          </pre>
        </div>
        <WhyThisPaused item={props.item} />
        {isBlocked && (
          <div className="mt-3 rounded-[1rem] border border-brand-purple/20 bg-brand-purple/[0.05] px-3 py-2.5">
            <p className="text-sm leading-6 text-brand-purple">
              HOL Guard blocked this based on a saved decision. If this is a false positive, choose <span className="font-semibold">Allow</span> below and pick how broadly to remember the override.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

function actionDisplayTitle(item: GuardApprovalRequest): string {
  const v2Title = resolveDecisionV2Title(item);
  if (v2Title !== null) {
    return v2Title;
  }
  const artifactName = displayArtifactName(item);
  if (item.artifact_type === "tool_action_request") {
    return `${harnessDisplayName(item.harness)} wants to run a tool`;
  }
  if (item.artifact_type === "file_read_request") {
    return `${harnessDisplayName(item.harness)} wants to read a protected file`;
  }
  if (item.artifact_type === "prompt_request") {
    return `${harnessDisplayName(item.harness)} received a sensitive prompt`;
  }
  if (artifactName.toLowerCase().includes("bash")) {
    return `${harnessDisplayName(item.harness)} wants to run a shell command`;
  }
  return artifactName;
}

function actionLaunchText(item: GuardApprovalRequest): string {
  return resolveStoppedCommandText(item);
}

function getRulePreviewText(
  item: GuardApprovalRequest,
  scope: DecisionScope,
): string {
  if (scope === "artifact") {
    return `Allow only this exact action. HOL Guard will ask again if it changes.`;
  }
  if (scope === "workspace") {
    return `Remember this choice for ${displayArtifactName(item)} in this project folder.`;
  }
  return "Remember this choice more broadly on this machine.";
}

function ScopeOptionRow(props: {
  option: { value: DecisionScope; label: string; description: string };
  checked: boolean;
  onScopeChange: (scope: DecisionScope) => void;
}) {
  const handleChange = useCallback(() => {
    props.onScopeChange(props.option.value);
  }, [props.onScopeChange, props.option.value]);

  return (
    <ScopeOption
      value={props.option.value}
      label={props.option.label}
      description={props.option.description}
      checked={props.checked}
      onChange={handleChange}
    />
  );
}

function ScopeOption(props: {
  value: string;
  label: string;
  description: string;
  checked: boolean;
  onChange: () => void;
}) {
  return (
    <label
      className={`flex cursor-pointer items-start gap-3 rounded-[1.15rem] border p-3 transition-all duration-150 ${
        props.checked
          ? "border-brand-blue/30 bg-white shadow-sm"
          : "border-transparent bg-white/55 hover:border-brand-dark/15 hover:bg-white"
      }`}
    >
      <input
        type="radio"
        name="guard-scope"
        value={props.value}
        checked={props.checked}
        onChange={props.onChange}
        className="mt-0.5 accent-brand-blue"
      />
      <div>
        <span className="text-sm font-medium text-brand-dark">{props.label}</span>
        {props.checked ? (
          <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{props.description}</p>
        ) : null}
      </div>
    </label>
  );
}

function PolicyBadge(props: { action: string }) {
  if (props.action === "block") {
    return <Badge tone="destructive">{policyActionLabel(props.action)}</Badge>;
  }
  if (props.action === "allow") {
    return <Badge tone="success">{policyActionLabel(props.action)}</Badge>;
  }
  return <Badge tone="warning">{policyActionLabel(props.action)}</Badge>;
}

function simplifyRiskHeadline(headline: string, harness: string): string {
  const lowerHeadline = headline.toLowerCase();
  if (lowerHeadline.includes("sensitive native tool action") || lowerHeadline.includes("destructive shell command")) {
    return `${harnessDisplayName(harness)} wants to run a sensitive shell command.`;
  }
  if (lowerHeadline.includes("credential") || lowerHeadline.includes("secret")) {
    return `${harnessDisplayName(harness)} wants to access something sensitive.`;
  }
  return headline;
}
