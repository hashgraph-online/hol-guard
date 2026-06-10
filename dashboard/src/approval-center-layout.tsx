import type { ReactNode, MouseEvent, KeyboardEvent } from "react";
import { useState, useEffect, useCallback, useMemo, useRef, type ChangeEvent } from "react";
import {
  HiMiniChevronDown,
  HiMiniChevronUp,
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
  HiMiniArrowPath,
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
import { ReviewWorkspace } from "./review-workspace";
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
  resolveSecondaryRiskSummary,
  hasReviewEvidence,
  resolveStoppedCommandText,
  displayArtifactName,
  resolveTerminalLabel,
  resolveFileReadPath,
  resolveApprovalShareUrl,
  scopeLabel,
  STALE_REQUEST_COPY,
  QUEUE_CONNECTION_ERROR_HEADLINE,
  QUEUE_CONNECTION_ERROR_INSTRUCTION,
  isDisplayableHarness,
  isCodexHarness,
  buildCodexResumeUx,
} from "./approval-center-utils";
import { requiresApprovalPasswordPrompt } from "./approval-gate-utils";
import {
  WhyThisPaused,
  ApproveConsequence,
  BlockConsequence,
  ApprovalPasswordModal,
} from "./approval-center-review-cards";
import {
  buildProgressCopy,
  buildNextUpChipText,
  sortQueue,
  searchQueue,
  groupDuplicates,
  isReadOnlyQueueGroup,
  isDuplicateGroup,
  bulkApproveActionCount,
  bulkApprovePrimaryIds,
  bulkBlockEligibleGroups,
  bulkBlockPrimaryIds,
  countSensitiveFileReadGroups,
  type QueueSortDirection,
} from "./queue-state";
import {
  buildDecisionPayload,
  filterScopeChoicesForRequest,
  normalizeDecisionScope,
} from "./approval-scopes";
import type {
  GuardApprovalGatePublicConfig,
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardCodexResumeResult,
  GuardInventoryItem,
  GuardPolicyDecision,
  GuardReceipt,
  GuardRuntimeSnapshot,
  DecisionScope
} from "./guard-types";
import { guardAwareHref } from "./guard-api";
import { useGuardUpdate } from "./guard-update-panel";

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
type AppView = "home" | "inbox" | "fleet" | "evidence" | "settings" | "app-detail" | "supply-chain" | "audit" | "policy" | "feed-health";

export type BulkGateCredentials = {
  approval_password?: string;
  approval_totp_code?: string;
  approval_gate_use_cooldown?: boolean;
};

type LayoutProps = {
  view: AppView;
  requests: RequestState;
  detail: DetailState;
  receipts: ReceiptsState;
  runtime: RuntimeState;
  inventory: GuardInventoryItem[];
  activeRequestId: string | null;
  resolutionMessage: string | null;
  codexResume: GuardCodexResumeResult | null;
  approvalGate?: GuardApprovalGatePublicConfig | null;
  homeContent: ReactNode;
  fleetContent: ReactNode;
  settingsContent: ReactNode;
  appDetailContent: ReactNode;
  supplyChainHubContent?: ReactNode;
  aboutContent?: ReactNode;
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
    approval_password?: string;
    approval_totp_code?: string;
    approval_gate_use_cooldown?: boolean;
  }) => void;
  onBulkApprove?: (ids: string[], gateCredentials?: BulkGateCredentials) => void;
  onBulkBlock?: (ids: string[], reason: string, gateCredentials?: BulkGateCredentials) => void;
  onRepair?: () => Promise<void>;
  onClearEvidence?: () => void;
  onRetryResume?: () => void;
  onGuardReconnected?: () => void;
};

const scopeOptions: Array<{ value: DecisionScope; label: string; description: string }> = [
  {
    value: "artifact",
    label: "Approve once",
    description: "Remember this exact prompt, command, tool, path, or host fingerprint."
  },
  {
    value: "workspace",
    label: "Remember for project",
    description: "Skip the next prompt for this same action here; different sensitive actions still ask."
  },
  { value: "publisher", label: "This source", description: "Trust future actions from the same source in this app." },
  { value: "harness", label: "This app", description: "Trust matching actions from this app." },
  { value: "global", label: "Every project", description: "Use this choice across every project on this machine. Cannot easily be undone." }
];

const commonScopeValues = new Set<DecisionScope>(["artifact", "workspace"]);
const advancedScopeValues = new Set<DecisionScope>(["global"]);
const queuePageSize = 8;

function renderInboxContent(props: LayoutProps): ReactNode {
  if (props.requests.kind === "loading") {
    return (
      <div className="space-y-4" aria-busy="true" aria-live="polite">
        <div className="guard-skeleton h-8 w-64" />
        <div className="guard-skeleton h-32 w-full" />
        <div className="guard-skeleton h-48 w-full" />
      </div>
    );
  }
  if (props.requests.kind === "error") {
    return (
      <QueueWorkspace
        requests={props.requests}
        detail={props.detail}
        runtime={props.runtime}
        activeRequestId={props.activeRequestId}
        resolutionMessage={props.resolutionMessage}
        codexResume={props.codexResume}
        approvalGate={props.approvalGate ?? null}
        onOpenRequest={props.onOpenRequest}
        onGoHome={props.onGoHome}
        onResolve={props.onResolve}
        onBulkApprove={props.onBulkApprove}
        onBulkBlock={props.onBulkBlock}
        onRetry={props.onRetry}
        onRepair={props.onRepair}
        onRetryResume={props.onRetryResume}
      />
    );
  }
  return (
    <ReviewWorkspace
      requests={props.requests.items}
      activeRequestId={props.activeRequestId}
      detail={props.detail.kind === "ready" ? {
        item: props.detail.item,
        diff: props.detail.diff,
        receipt: props.detail.receipt,
        policy: props.detail.policy,
      } : null}
      runtime={props.runtime.kind === "ready" ? props.runtime.snapshot : null}
      resolutionMessage={props.resolutionMessage}
      codexResume={props.codexResume}
      approvalGate={props.approvalGate ?? null}
      onOpenRequest={props.onOpenRequest}
      onResolve={props.onResolve}
      onGoHome={props.onGoHome}
      onRetryResume={props.onRetryResume}
    />
  );
}

export function ApprovalCenterLayout(props: LayoutProps) {
  const [mobileQueueOpen, setMobileQueueOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    try {
      return localStorage.getItem("guard-sidebar-collapsed") === "true";
    } catch {
      return false;
    }
  });
  const queuedItems = props.requests.kind === "ready" ? props.requests.items : [];

  const handleOpenMobileQueue = useCallback(() => setMobileQueueOpen(true), []);
  const handleCloseMobileQueue = useCallback(() => setMobileQueueOpen(false), []);
  const handleToggleSidebar = useCallback(() => {
    setSidebarCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem("guard-sidebar-collapsed", String(next));
      } catch {
        // ignore
      }
      return next;
    });
  }, []);

  const {
    guardVersion,
    updateStatus,
    updatePhase,
    onUpdateGuard,
  } = useGuardUpdate({ onReconnected: props.onGuardReconnected });

  return (
    <div className="min-h-screen bg-white text-brand-dark">
      <ShellHeader
        queuedCount={queuedItems.length}
        view={props.view}
        onNavigate={props.onNavigate}
        onOpenMobileQueue={handleOpenMobileQueue}
        guardVersion={guardVersion}
        updateStatus={updateStatus}
        updatePhase={updatePhase}
        onUpdateGuard={onUpdateGuard}
      />
      <ShellSidebar
        queuedCount={queuedItems.length}
        view={props.view}
        collapsed={sidebarCollapsed}
        onToggleCollapse={handleToggleSidebar}
        guardVersion={guardVersion}
        updateStatus={updateStatus}
        updatePhase={updatePhase}
        onUpdateGuard={onUpdateGuard}
      />
      {mobileQueueOpen && props.view === "inbox" && props.requests.kind === "ready" && (
        <MobileQueueDrawer
          requests={props.requests.items}
          activeRequestId={props.activeRequestId}
          approvalGate={props.approvalGate ?? null}
          onClose={handleCloseMobileQueue}
          onOpenRequest={props.onOpenRequest}
          onBulkApprove={props.onBulkApprove}
          onBulkBlock={props.onBulkBlock}
        />
      )}
      <div className={`flex flex-col transition-all duration-200 ${sidebarCollapsed ? "lg:pl-20" : "lg:pl-64"}`}>
        <main id="main-content" className="flex-1 p-4 sm:p-6 lg:p-8" tabIndex={-1}>
          <div className={props.view === "inbox" ? "mx-auto max-w-none" : "mx-auto max-w-6xl"}>
            {props.view === "home" ? (
              props.homeContent
            ) : props.view === "evidence" ? (
              <ReceiptsWorkspace
                receipts={props.receipts}
                runtime={props.runtime}
                onClearEvidence={props.onClearEvidence}
                onNavigate={props.onNavigate}
              />
            ) : props.view === "fleet" ? (
              props.fleetContent
            ) : props.view === "app-detail" ? (
              props.appDetailContent
            ) : props.view === "settings" ? (
              props.settingsContent
            ) : props.view === "about" ? (
              props.aboutContent ?? null
            ) : props.view === "supply-chain" || props.view === "audit" || props.view === "policy" || props.view === "feed-health" ? (
              props.supplyChainHubContent ?? null
            ) : props.view === "inbox" ? (
              renderInboxContent(props)
            ) : (
              <QueueWorkspace
                requests={props.requests}
                detail={props.detail}
                runtime={props.runtime}
                activeRequestId={props.activeRequestId}
                resolutionMessage={props.resolutionMessage}
                codexResume={props.codexResume}
                approvalGate={props.approvalGate ?? null}
                onOpenRequest={props.onOpenRequest}
                onGoHome={props.onGoHome}
                onResolve={props.onResolve}
                onBulkApprove={props.onBulkApprove}
                onBulkBlock={props.onBulkBlock}
                onRetry={props.onRetry}
                onRepair={props.onRepair}
                onRetryResume={props.onRetryResume}
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
  approvalGate?: GuardApprovalGatePublicConfig | null;
  onClose: () => void;
  onOpenRequest: (requestId: string) => void;
  onBulkApprove?: (ids: string[], gateCredentials?: BulkGateCredentials) => void;
  onBulkBlock?: (ids: string[], reason: string, gateCredentials?: BulkGateCredentials) => void;
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
            <HiMiniXMarkLayout className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto">
          <QueueBrowser
            activeRequestId={props.activeRequestId}
            items={props.requests}
            approvalGate={props.approvalGate ?? null}
            onOpenRequest={props.onOpenRequest}
            onBulkApprove={props.onBulkApprove}
            onBulkBlock={props.onBulkBlock}
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
  codexResume: GuardCodexResumeResult | null;
  approvalGate?: GuardApprovalGatePublicConfig | null;
  onOpenRequest: (requestId: string) => void;
  onGoHome: () => void;
  onResolve: LayoutProps["onResolve"];
  onBulkApprove?: (ids: string[], gateCredentials?: BulkGateCredentials) => void;
  onBulkBlock?: (ids: string[], reason: string, gateCredentials?: BulkGateCredentials) => void;
  onRetry?: () => void;
  onRepair?: () => Promise<void>;
  onRetryResume?: () => void;
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
    const handleOpenDaemon = () => {
      if (approvalUrl !== null) {
        window.open(approvalUrl, "_blank", "noopener,noreferrer");
      } else {
        void handleRepair();
      }
    };
    return (
      <div className="space-y-4">
        <Surface tone="danger">
          <p className="text-sm font-semibold text-brand-purple">{QUEUE_CONNECTION_ERROR_HEADLINE}</p>
          <p className="mt-1 text-sm text-brand-purple/80">{props.requests.message}</p>
          <p className="mt-2 text-sm text-brand-purple/70">{QUEUE_CONNECTION_ERROR_INSTRUCTION}</p>
          <div className="mt-4 flex flex-wrap gap-3">
            <ActionButton onClick={handleOpenDaemon}>
              Repair
            </ActionButton>
            {props.onRepair !== undefined && (
              <ActionButton onClick={handleRepair} disabled={repairing} variant="outline">
                {repairing ? "Repairing..." : "Reconnect"}
              </ActionButton>
            )}
            <code className="inline-flex min-h-10 items-center rounded-lg border border-brand-purple/30 bg-slate-50 px-3 py-2 font-mono text-sm text-brand-purple select-all">hol-guard start</code>
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
      <>
        {props.codexResume !== null && (
          <CodexResumePanel resume={props.codexResume} onRetry={props.onRetryResume} />
        )}
        <WelcomeState
          connectUrl={props.runtime.kind === "ready" ? props.runtime.snapshot.connect_url : null}
          dashboardUrl={props.runtime.kind === "ready" ? props.runtime.snapshot.dashboard_url : null}
          fleetUrl={props.runtime.kind === "ready" ? props.runtime.snapshot.fleet_url : null}
          inboxUrl={props.runtime.kind === "ready" ? props.runtime.snapshot.inbox_url : null}
          resolutionMessage={props.codexResume === null ? props.resolutionMessage : null}
        />
      </>
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
      {props.codexResume !== null && (
        <CodexResumePanel resume={props.codexResume} onRetry={props.onRetryResume} />
      )}
      {props.resolutionMessage && props.codexResume === null && props.requests.items.length > 0 && (
        <div className="flex items-start gap-3 rounded-2xl border border-brand-green/25 bg-brand-green-bg/30 px-4 py-3">
          <HiMiniCheckCircle className="mt-0.5 h-4 w-4 shrink-0 text-brand-green" aria-hidden="true" />
          <p className="text-sm font-medium text-brand-green-text">{props.resolutionMessage}</p>
        </div>
      )}
      <QueueHeader
        activeRequestId={props.activeRequestId}
        requests={props.requests.items}
        progressCopy={progressCopy}
      />
      {showSideBySide ? (
        <div className="grid gap-6 lg:grid-cols-[300px_1fr] lg:items-start">
          <aside className="lg:sticky lg:top-6">
            <QueueBrowser
              activeRequestId={props.activeRequestId}
              items={props.requests.items}
              approvalGate={props.approvalGate ?? null}
              onOpenRequest={props.onOpenRequest}
              onBulkApprove={props.onBulkApprove}
              onBulkBlock={props.onBulkBlock}
            />
          </aside>
          <div>
            <DecisionWorkspace
              detail={props.detail}
              onGoHome={props.onGoHome}
              onResolve={props.onResolve}
              approvalGate={props.approvalGate ?? null}
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
            <HiMiniChevronLeft className="h-4 w-4" aria-hidden="true" />
            Back to queue
          </button>
          <DecisionWorkspace
            detail={props.detail}
            onGoHome={props.onGoHome}
            onResolve={props.onResolve}
            approvalGate={props.approvalGate ?? null}
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
}) {
  const activeItem = props.requests.find((item) => item.request_id === props.activeRequestId) ?? props.requests[0] ?? null;
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
      <p className="text-sm text-muted-foreground">
        {props.progressCopy.length > 0 ? `${props.progressCopy} · ` : ""}
        {props.requests.length} waiting
        {activeItem ? ` · from ${harnessDisplayName(activeItem.harness)}` : ""}
      </p>
    </div>
  );
}

function QueueBrowser(props: {
  activeRequestId: string | null;
  items: GuardApprovalRequest[];
  approvalGate?: GuardApprovalGatePublicConfig | null;
  onOpenRequest: (requestId: string) => void;
  onBulkApprove?: (ids: string[], gateCredentials?: BulkGateCredentials) => void;
  onBulkBlock?: (ids: string[], reason: string, gateCredentials?: BulkGateCredentials) => void;
}) {
  const [searchTerm, setSearchTerm] = useState("");
  const [harnessFilter, setHarnessFilter] = useState("all");
  const [sortDirection, setSortDirection] = useState<QueueSortDirection>("newest");
  const [page, setPage] = useState(1);
  const [showFilters, setShowFilters] = useState(false);
  const [bulkApprovePassword, setBulkApprovePassword] = useState("");
  const [bulkApproveTotpCode, setBulkApproveTotpCode] = useState("");
  const [bulkApproveUseCooldown, setBulkApproveUseCooldown] = useState(false);
  const harnesses = Array.from(new Set(props.items.map((item) => item.harness).filter(isDisplayableHarness))).sort();

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

  useEffect(() => {
    setPage(1);
  }, [harnessFilter, searchTerm, sortDirection, props.items.length]);

  useEffect(() => {
    if (props.activeRequestId === null) return;
    const groupIndex = groups.findIndex(
      (g) => g.primary.request_id === props.activeRequestId
    );
    if (groupIndex < 0) return;
    const targetPage = Math.floor(groupIndex / queuePageSize) + 1;
    setPage((prev) => (prev === targetPage ? prev : targetPage));
  }, [props.activeRequestId, groups]);

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

  const handleToggleFilters = useCallback(() => setShowFilters((v) => !v), []);

  const handleClearFilters = useCallback(() => {
    setSearchTerm("");
    setHarnessFilter("all");
    setSortDirection("newest");
  }, []);

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

  const sensitiveFileReadCount = useMemo(
    () => countSensitiveFileReadGroups(groups),
    [groups]
  );

  const showBulkApprove =
    props.onBulkApprove !== undefined &&
    bulkEligibleGroups.length > 0;

  const showBulkGateFields =
    showBulkApprove &&
    props.approvalGate?.enabled === true &&
    props.approvalGate.configured === true;

  const handleBulkApprovePasswordChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setBulkApprovePassword(event.target.value);
  }, []);
  const handleBulkApproveTotpCodeChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setBulkApproveTotpCode(event.target.value);
  }, []);

  const handleBulkApproveUseCooldownChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setBulkApproveUseCooldown(event.target.checked);
  }, []);

  const handleBulkApprove = useCallback(() => {
    const ids = bulkApprovePrimaryIds(bulkEligibleGroups);
    const gateCredentials: BulkGateCredentials | undefined = showBulkGateFields
      ? {
          approval_password: bulkApprovePassword,
          approval_totp_code: bulkApproveTotpCode,
          approval_gate_use_cooldown: bulkApproveUseCooldown
        }
      : undefined;
    props.onBulkApprove?.(ids, gateCredentials);
  }, [props.onBulkApprove, bulkEligibleGroups, showBulkGateFields, bulkApprovePassword, bulkApproveTotpCode, bulkApproveUseCooldown]);

  const blockEligibleGroups = useMemo(() => bulkBlockEligibleGroups(groups), [groups]);
  const blockEligibleActionCount = useMemo(() => bulkApproveActionCount(blockEligibleGroups), [blockEligibleGroups]);
  const showBulkBlock = props.onBulkBlock !== undefined && blockEligibleGroups.length > 0;
  const showBulkBlockGateFields =
    showBulkBlock &&
    props.approvalGate?.enabled === true &&
    props.approvalGate.configured === true &&
    props.approvalGate.strict_all_decisions === true;

  const handleBulkBlockConfirm = useCallback((reason: string, gateCredentials?: BulkGateCredentials) => {
    const ids = bulkBlockPrimaryIds(blockEligibleGroups);
    props.onBulkBlock?.(ids, reason, gateCredentials);
  }, [props.onBulkBlock, blockEligibleGroups]);

  return (
    <section>
      {showBulkApprove && (
        <div className="mb-4 space-y-2">
          {showBulkGateFields && (
            <div className="space-y-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2">
              <label className="block">
                <span className="sr-only">Approval password</span>
                <input
                  type="password"
                  value={bulkApprovePassword}
                  onChange={handleBulkApprovePasswordChange}
                  placeholder="Approval password"
                  autoComplete="current-password"
                  className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                />
              </label>
              {props.approvalGate?.totp_enabled === true && (
                <label className="block">
                  <span className="sr-only">Authenticator code</span>
                  <input
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    value={bulkApproveTotpCode}
                    onChange={handleBulkApproveTotpCodeChange}
                    placeholder="Authenticator code"
                    className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                  />
                </label>
              )}
              {(props.approvalGate?.cooldown_seconds ?? 0) > 0 && props.approvalGate?.totp_enabled !== true && (
                <label className="flex items-center gap-2 text-xs text-slate-600">
                  <input
                    type="checkbox"
                    checked={bulkApproveUseCooldown}
                    onChange={handleBulkApproveUseCooldownChange}
                    className="rounded"
                  />
                  Skip password for next approvals (use cooldown)
                </label>
              )}
            </div>
          )}
          <button
            type="button"
            onClick={handleBulkApprove}
            className="rounded-full border border-brand-blue/30 bg-white px-4 py-2 text-sm font-medium text-brand-blue shadow-sm transition-colors hover:bg-brand-blue/5"
          >
            Approve all read-only actions ({bulkEligibleActionCount})
          </button>
          {sensitiveFileReadCount > 0 && (
            <p className="text-xs text-brand-attention">
              {sensitiveFileReadCount} sensitive file {sensitiveFileReadCount === 1 ? "read" : "reads"} excluded — review individually for informed consent.
            </p>
          )}
        </div>
      )}
      {!showBulkApprove && sensitiveFileReadCount > 0 && (
        <div className="mb-4 rounded-lg border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2">
          <p className="text-xs text-brand-attention">
            {sensitiveFileReadCount} sensitive file {sensitiveFileReadCount === 1 ? "read" : "reads"} in queue — review each path before approving.
          </p>
        </div>
      )}
      {showBulkBlock && (
        <QueueBulkBlockForm
          count={blockEligibleActionCount}
          showGateFields={showBulkBlockGateFields}
          cooldownSeconds={props.approvalGate?.cooldown_seconds ?? 0}
          totpEnabled={props.approvalGate?.totp_enabled === true}
          onBlock={handleBulkBlockConfirm}
        />
      )}
      <div className="mb-3 space-y-2">
        <label className="block">
          <span className="sr-only">Search waiting actions</span>
          <input
            type="search"
            value={searchTerm}
            onChange={handleSearchChange}
            placeholder="Command, file, MCP, host..."
            className="min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm text-brand-dark placeholder:text-slate-400 transition-colors duration-150 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          />
        </label>
        <button
          type="button"
          onClick={handleToggleFilters}
          className="flex items-center gap-1 text-xs font-medium text-brand-blue transition-colors hover:text-brand-dark"
        >
          {showFilters ? "Hide filters" : "Show filters"}
          {(searchTerm || harnessFilter !== "all" || sortDirection !== "newest") && !showFilters && (
            <span className="ml-1 h-1.5 w-1.5 rounded-full bg-brand-attention" />
          )}
        </button>
        {showFilters && (
          <div className="space-y-2">
            {harnesses.length >= 2 && (
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
            {(searchTerm || harnessFilter !== "all" || sortDirection !== "newest") && (
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
      <div className="divide-y divide-slate-200/70 overflow-hidden rounded-2xl border border-slate-200/70 bg-white/75 shadow-sm">
        {visibleGroups.length > 0 ? (
          visibleGroups.map((group) => (
            <QueueCardRow
              key={group.primary.request_id}
              group={group}
              activeRequestId={props.activeRequestId}
              onOpenRequest={props.onOpenRequest}
            />
          ))
        ) : (
          <div className="px-4 py-5">
            <EmptyState title="No matches" body="Try a different search or filter to find waiting actions." />
          </div>
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
  onOpenRequest: (requestId: string) => void;
}) {
  const handleClick = useCallback(() => {
    props.onOpenRequest(props.group.primary.request_id);
  }, [props.onOpenRequest, props.group.primary.request_id]);

  return (
    <QueueCard
      item={props.group.primary}
      duplicateCount={props.group.duplicateCount}
      active={props.group.primary.request_id === props.activeRequestId}
      onClick={handleClick}
    />
  );
}

function QueueApprovalShareButton(props: { item: GuardApprovalRequest }) {
  const [shareState, setShareState] = useState<"idle" | "copied" | "failed">("idle");
  const approvalUrl = resolveApprovalShareUrl(props.item);
  const timeoutRef = useRef<number | null>(null);
  const handleCopy = useCallback(
    async (event: MouseEvent<HTMLButtonElement>) => {
      event.stopPropagation();
      event.preventDefault();
      if (approvalUrl === null) {
        return;
      }
      if (timeoutRef.current !== null) {
        window.clearTimeout(timeoutRef.current);
      }
      try {
        await navigator.clipboard.writeText(approvalUrl);
        setShareState("copied");
        timeoutRef.current = window.setTimeout(() => setShareState("idle"), 1800);
      } catch {
        setShareState("failed");
        timeoutRef.current = window.setTimeout(() => setShareState("idle"), 2400);
      }
    },
    [approvalUrl]
  );

  useEffect(() => {
    return () => {
      if (timeoutRef.current !== null) {
        window.clearTimeout(timeoutRef.current);
      }
    };
  }, []);

  if (approvalUrl === null) {
    return null;
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      className="inline-flex shrink-0 items-center gap-1 rounded-md px-2 py-1 font-mono text-[10px] font-semibold uppercase tracking-[0.16em] text-brand-blue/80 transition-colors hover:bg-brand-blue/[0.06] hover:text-brand-blue"
      aria-label="Copy approval link"
      title={copyApprovalUrlLabel(shareState)}
    >
      <HiMiniClipboard className="h-3.5 w-3.5" aria-hidden="true" />
      <span className="hidden sm:inline">{copyApprovalUrlLabel(shareState)}</span>
    </button>
  );
}

function QueueCard(props: { item: GuardApprovalRequest; duplicateCount: number; active: boolean; onClick: () => void }) {
  const summary = buildQueueSummary(props.item);
  const fileReadPath = resolveFileReadPath(props.item);
  const isBlocked = props.item.policy_action === "block";
  const statusDotClass = queueCardStatusDotClass(props.active, isBlocked);
  const handleKeyDown = useCallback(
    (event: KeyboardEvent<HTMLDivElement>) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        props.onClick();
      }
    },
    [props.onClick]
  );
  return (
    <div
      className={`group/item w-full border-l-4 px-4 py-3.5 transition-all duration-150 hover:bg-brand-blue/[0.035] ${
        props.active
          ? "border-brand-blue bg-brand-blue/[0.06]"
          : "border-transparent bg-white/70"
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div
          role="button"
          tabIndex={0}
          onClick={props.onClick}
          onKeyDown={handleKeyDown}
          aria-pressed={props.active}
          className="flex min-w-0 flex-1 cursor-pointer items-start gap-3 text-left"
        >
           <span
             className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full transition-colors ${
               statusDotClass
             }`}
           />
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold text-brand-dark">{actionDisplayTitle(props.item)}</p>
            <p className="mt-0.5 truncate text-xs text-muted-foreground">
              {harnessDisplayName(props.item.harness)} · {summary}
            </p>
            {fileReadPath !== null && (
              <p className="mt-0.5 truncate font-mono text-[11px] text-brand-dark/50">
                {fileReadPath}
              </p>
            )}
          </div>
        </div>
        <div className="flex shrink-0 items-start gap-2">
          {props.duplicateCount > 0 && (
            <span className="rounded-full bg-slate-100 px-2 py-0.5 font-mono text-[10px] font-semibold text-muted-foreground">
              +{props.duplicateCount}
            </span>
          )}
          <QueueApprovalShareButton item={props.item} />
        </div>
      </div>
    </div>
  );
}

function QueueBulkBlockForm(props: {
  count: number;
  showGateFields: boolean;
  cooldownSeconds: number;
  totpEnabled: boolean;
  onBlock: (reason: string, gateCredentials?: BulkGateCredentials) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [reason, setReason] = useState("");
  const [gatePassword, setGatePassword] = useState("");
  const [gateTotpCode, setGateTotpCode] = useState("");
  const [gateUseCooldown, setGateUseCooldown] = useState(false);

  const handleExpand = useCallback(() => setExpanded(true), []);
  const handleCollapse = useCallback(() => {
    setExpanded(false);
    setReason("");
    setGatePassword("");
    setGateTotpCode("");
    setGateUseCooldown(false);
  }, []);
  const handleReasonChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setReason(event.target.value);
  }, []);
  const handleGatePasswordChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setGatePassword(event.target.value);
  }, []);
  const handleGateTotpCodeChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setGateTotpCode(event.target.value);
  }, []);
  const handleGateUseCooldownChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setGateUseCooldown(event.target.checked);
  }, []);
  const handleConfirm = useCallback(() => {
    const gateCredentials = props.showGateFields
      ? {
          approval_password: gatePassword,
          approval_totp_code: gateTotpCode,
          approval_gate_use_cooldown: gateUseCooldown
        }
      : undefined;
    props.onBlock(reason.trim().length > 0 ? reason.trim() : "blocked as part of duplicate group", gateCredentials);
    setExpanded(false);
    setReason("");
    setGatePassword("");
    setGateTotpCode("");
    setGateUseCooldown(false);
  }, [props.onBlock, props.showGateFields, reason, gatePassword, gateTotpCode, gateUseCooldown]);

  if (!expanded) {
    return (
      <div className="mb-4">
        <button
          type="button"
          onClick={handleExpand}
          className="rounded-full border border-slate-300 bg-white px-4 py-2 text-sm font-medium text-slate-600 shadow-sm transition-colors hover:bg-slate-50"
        >
          Keep blocked: all duplicates ({props.count})
        </button>
      </div>
    );
  }

  return (
    <div className="mb-4 rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <p className="text-sm font-medium text-brand-dark">
        Block {props.count} duplicate {props.count === 1 ? "action" : "actions"}
      </p>
      <p className="mt-1 text-xs text-muted-foreground">
        This saves a block decision for each duplicate group. Add an optional note.
      </p>
      <label className="mt-3 block">
        <span className="sr-only">Optional reason for blocking duplicates</span>
        <input
          type="text"
          value={reason}
          onChange={handleReasonChange}
          placeholder="Why are you blocking these? (optional)"
          className="min-h-10 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        />
      </label>
      {props.showGateFields && (
        <div className="mt-3 space-y-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2">
          <label className="block">
            <span className="sr-only">Approval password for bulk block</span>
            <input
              type="password"
              value={gatePassword}
              onChange={handleGatePasswordChange}
              placeholder="Approval password"
              autoComplete="current-password"
              className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
            />
          </label>
          {props.totpEnabled && (
            <label className="block">
              <span className="sr-only">Authenticator code for bulk block</span>
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                value={gateTotpCode}
                onChange={handleGateTotpCodeChange}
                placeholder="Authenticator code"
                className="w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
              />
            </label>
          )}
          {props.cooldownSeconds > 0 && !props.totpEnabled && (
            <label className="flex items-center gap-2 text-xs text-slate-600">
              <input
                type="checkbox"
                checked={gateUseCooldown}
                onChange={handleGateUseCooldownChange}
                className="rounded"
              />
              Skip password for next approvals (use cooldown)
            </label>
          )}
        </div>
      )}
      <div className="mt-3 flex gap-2">
        <button
          type="button"
          onClick={handleConfirm}
          className="rounded-full border border-slate-300 bg-white px-4 py-1.5 text-sm font-medium text-brand-dark shadow-sm transition-colors hover:bg-slate-50"
        >
          Keep blocked
        </button>
        <button
          type="button"
          onClick={handleCollapse}
          className="rounded-full px-4 py-1.5 text-sm font-medium text-muted-foreground transition-colors hover:text-brand-dark"
        >
          Cancel
        </button>
      </div>
    </div>
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

function CodexResumePanel(props: {
  resume: GuardCodexResumeResult;
  onRetry?: () => void;
}) {
  const ux = buildCodexResumeUx(props.resume);
  const isPending = props.resume.status === "pending" || props.resume.status === "in_progress";
  const isSuccess = props.resume.status === "sent" || props.resume.status === "already_sent";
  const isFailed = props.resume.status === "failed";

  if (isPending) {
    return (
      <div
        className="flex items-center gap-3 rounded-2xl border border-brand-blue/25 bg-brand-blue/[0.05] px-4 py-3"
        role="status"
        aria-live="polite"
      >
        <HiMiniArrowPath className="h-4 w-4 shrink-0 animate-spin text-brand-blue" aria-hidden="true" />
        <p className="text-sm font-medium text-brand-blue">{ux.headline}</p>
      </div>
    );
  }

  if (isSuccess) {
    return (
      <div
        className="flex items-start gap-3 rounded-2xl border border-brand-green/25 bg-brand-green-bg/30 px-4 py-3"
        role="status"
        aria-live="polite"
      >
        <HiMiniCheckCircle className="mt-0.5 h-4 w-4 shrink-0 text-brand-green" aria-hidden="true" />
        <div>
          <p className="text-sm font-medium text-brand-green-text">{ux.headline}</p>
          {ux.body !== null && (
            <p className="mt-0.5 text-sm text-brand-green-text/80">{ux.body}</p>
          )}
        </div>
      </div>
    );
  }

  if (isFailed) {
    return (
      <div
        className="rounded-2xl border border-brand-purple/25 bg-brand-purple/[0.05] px-4 py-3 space-y-2"
        role="alert"
      >
        <div className="flex items-start gap-3">
          <HiMiniExclamationTriangle className="mt-0.5 h-4 w-4 shrink-0 text-brand-purple" aria-hidden="true" />
          <p className="text-sm font-medium text-brand-purple">{ux.headline}</p>
        </div>
        {ux.body !== null && (
          <p className="ml-7 text-xs text-brand-purple/80">{ux.body}</p>
        )}
        {ux.showRetry && props.onRetry !== undefined && (
          <div className="ml-7">
            <ActionButton variant="outline" onClick={props.onRetry}>Try again</ActionButton>
          </div>
        )}
        <p className="ml-7 text-xs text-muted-foreground">
          You can also return to your terminal and retry manually.
        </p>
      </div>
    );
  }

  return (
    <div className="flex items-start gap-3 rounded-2xl border border-slate-200/60 bg-slate-50 px-4 py-3">
      <HiMiniInformationCircle className="mt-0.5 h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />
      <div>
        <p className="text-sm font-medium text-brand-dark">{ux.headline}</p>
        {ux.body !== null && (
          <p className="mt-0.5 text-sm text-muted-foreground">{ux.body}</p>
        )}
      </div>
    </div>
  );
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
    <div className="sticky bottom-0 z-20 -mx-4 border-t border-slate-200/70 bg-white/95 px-4 py-3 shadow-[0_-4px_16px_rgba(63,65,116,0.08)] backdrop-blur sm:-mx-6 sm:px-6 lg:hidden">
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
  approvalGate?: GuardApprovalGatePublicConfig | null;
}) {
  const [scope, setScope] = useState<DecisionScope>("artifact");
  const [reason, setReason] = useState("approved in local approval center");
  const [submitting, setSubmitting] = useState<"allow" | "block" | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [resolvedBanner, setResolvedBanner] = useState<"allow" | "block" | null>(null);
  const [resolvedState, setResolvedState] = useState<"idle" | "decided" | "loaded">("idle");
  const [approvalPassword, setApprovalPassword] = useState("");
  const [approvalTotpCode, setApprovalTotpCode] = useState("");
  const [useCooldown, setUseCooldown] = useState(false);
  const [pendingAction, setPendingAction] = useState<"allow" | "block" | null>(null);
  const bannerTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const prevRequestIdRef = useRef<string | null>(null);

  const gateRequiresPassword = useMemo(() => {
    const gate = props.approvalGate;
    return (
      gate?.enabled === true &&
      gate?.configured === true &&
      requiresApprovalPasswordPrompt(gate.cooldown_active, gate.strict_all_decisions, scope)
    );
  }, [props.approvalGate, scope]);

  useEffect(() => {
    if (props.detail.kind === "ready") {
      const isNewItem = props.detail.item.request_id !== prevRequestIdRef.current;
      prevRequestIdRef.current = props.detail.item.request_id;
      if (isNewItem) {
        setResolvedBanner(null);
        setResolvedState("loaded");
        setApprovalPassword("");
        setApprovalTotpCode("");
        setUseCooldown(false);
        setPendingAction(null);
        if (bannerTimerRef.current !== null) {
          clearTimeout(bannerTimerRef.current);
          bannerTimerRef.current = null;
        }
      }
      setScope(normalizeDecisionScope(props.detail.item, props.detail.item.recommended_scope));
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

  const handleResolve = useCallback(
    async (action: "allow" | "block") => {
      if (readyItem === null) return;
      setSubmitting(action);
      setErrorMessage(null);
      try {
        const gate = props.approvalGate;
        const includeGateFields =
          gate?.enabled === true &&
          gate?.configured === true &&
          requiresApprovalPasswordPrompt(gate.cooldown_active, gate.strict_all_decisions, scope);
        await props.onResolve({
          ...buildDecisionPayload({
            item: readyItem,
            action,
            scope,
            reason,
          }),
          ...(includeGateFields ? { approval_password: approvalPassword } : {}),
          ...(includeGateFields && gate?.totp_enabled === true
            ? { approval_totp_code: approvalTotpCode }
            : {}),
          ...(includeGateFields ? { approval_gate_use_cooldown: useCooldown } : {}),
        });
        setResolvedState("decided");
        setResolvedBanner(action);
        setApprovalPassword("");
        setApprovalTotpCode("");
        setUseCooldown(false);
        setPendingAction(null);
        bannerTimerRef.current = setTimeout(() => {
          setResolvedBanner(null);
        }, 1500);
      } catch (error) {
        setErrorMessage(error instanceof Error ? error.message : "Something went wrong.");
        setSubmitting(null);
      }
    },
    [props.onResolve, props.approvalGate, readyItem, reason, scope, approvalPassword, approvalTotpCode, useCooldown]
  );

  const handleRequestResolve = useCallback(
    (action: "allow" | "block") => {
      if (gateRequiresPassword) {
        setPendingAction(action);
        setErrorMessage(null);
        return;
      }
      void handleResolve(action);
    },
    [handleResolve, gateRequiresPassword]
  );

  const handleAllowDirect = useCallback(() => handleRequestResolve("allow"), [handleRequestResolve]);
  const handleBlockDirect = useCallback(() => handleRequestResolve("block"), [handleRequestResolve]);

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

  const handleApprovalPasswordChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setApprovalPassword(event.target.value);
  }, []);
  const handleApprovalTotpCodeChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setApprovalTotpCode(event.target.value);
  }, []);
  const handleUseCooldownChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setUseCooldown(event.target.checked);
  }, []);

  useEffect(() => {
    if (props.detail.kind !== "ready") return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (submitting !== null || pendingAction !== null) return;
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
  }, [props.detail.kind, submitting, pendingAction, handleRequestResolve]);

  if (props.detail.kind === "loading") {
    return (
      <div className="space-y-4">
        {resolvedState === "decided" && (
          <div
            className="flex items-center gap-3 rounded-2xl border border-brand-green/25 bg-brand-green-bg/30 px-4 py-3"
            role="status"
            aria-live="polite"
          >
            <HiMiniCheckCircle className="h-4 w-4 shrink-0 text-brand-green" aria-hidden="true" />
            <p className="text-sm font-medium text-brand-green-text">Decided: loading next...</p>
          </div>
        )}
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
    return <EmptyState title="Select an item" body="Choose a blocked item from the list to review the evidence and make a decision." tone="teach" />;
  }
  const { item, diff, receipt, policy } = props.detail;
  const availableScopeOptions = filterScopeChoicesForRequest(item, scopeOptions);
  const commonScopeOpts = availableScopeOptions.filter((option) => commonScopeValues.has(option.value));
  const broaderScopeOpts = availableScopeOptions.filter((option) => !commonScopeValues.has(option.value) && !advancedScopeValues.has(option.value));
  const advancedScopeOpts = availableScopeOptions.filter((option) => advancedScopeValues.has(option.value));
  const isAlreadyDecided = item.resolution_action !== null;
  const decidedLabel = resolveDecisionLabel(item.resolution_action);
  const allowLabel = resolveAllowScopeLabel(scope);
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
            This action was already decided: {decidedLabel}. No further action needed.
          </p>
        </div>
      )}
      <RuleBuilder
        item={item}
        scope={scope}
        reason={reason}
        submitting={submitting}
        errorMessage={errorMessage}
        commonScopeOptions={commonScopeOpts}
        broaderScopeOptions={broaderScopeOpts}
        advancedScopeOptions={advancedScopeOpts}
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
      {pendingAction !== null && props.approvalGate != null && (
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
          submitLabel={pendingAction === "allow" ? allowLabel : "Keep blocked"}
        />
      )}
    </div>
  );
}

function InlineScannerSection(props: { item: GuardApprovalRequest }) {
  const allSignals = props.item.decision_v2_json?.signals ?? [];
  return <ScannerEvidenceSection signals={allSignals} />;
}

function ScannerEvidenceSectionFull(props: { item: GuardApprovalRequest }) {
  if (!hasReviewEvidence(props.item)) return null;
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

function resolveDecisionLabel(action: GuardApprovalRequest["resolution_action"]): string {
  if (action === "allow") {
    return "allow";
  }
  if (action === "block") {
    return "block";
  }
  return action ?? "decided";
}

function resolveAllowScopeLabel(scope: DecisionScope): string {
  if (scope === "artifact") {
    return "Approve once";
  }
  if (scope === "workspace") {
    return "Remember for project";
  }
  return "Approve and remember";
}

function WhyGuardCares(props: { item: GuardApprovalRequest }) {
  const { item } = props;
  const signals = item.risk_signals ?? [];
  const secondaryRiskSummary = resolveSecondaryRiskSummary(item);
  if (signals.length === 0 && secondaryRiskSummary === null && !item.why_now) return null;
  return (
    <div className="rounded-xl border border-brand-purple/20 bg-brand-purple/[0.04] p-4">
      <SectionLabel>Why this was paused</SectionLabel>
      {item.why_now ? <p className="mt-1 text-sm leading-relaxed text-brand-dark/80">{item.why_now}</p> : null}
      {secondaryRiskSummary ? <p className="mt-1 text-sm leading-relaxed text-brand-dark/80">{secondaryRiskSummary}</p> : null}
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
        <Badge tone="attention">{artifactTypeLabel(item.artifact_type)}</Badge>
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
  broaderScopeOptions: typeof scopeOptions;
  advancedScopeOptions: typeof scopeOptions;
  onScopeChange: (scope: DecisionScope) => void;
  onReasonChange: (reason: string) => void;
  onResolve: (action: "allow" | "block") => void;
}) {
  const previewText = getRulePreviewText(props.item, props.scope);
  const allowLabel = resolveAllowScopeLabel(props.scope);
  const retryInstruction = props.item.decision_v2_json?.retry_instruction ?? null;
  const isCodex = isCodexHarness(props.item.harness);

  const handleAllow = useCallback(() => props.onResolve("allow"), [props.onResolve]);
  const handleBlock = useCallback(() => props.onResolve("block"), [props.onResolve]);
  const handleReasonChange = useCallback((e: ChangeEvent<HTMLInputElement>) => {
    props.onReasonChange(e.target.value);
  }, [props.onReasonChange]);

  return (
    <section className="guard-surface-in relative overflow-hidden rounded-2xl border border-brand-blue/15 bg-[radial-gradient(circle_at_top_left,rgba(85,153,254,0.12),transparent_32%),linear-gradient(135deg,#ffffff_0%,#ffffff_58%,rgba(85,153,254,0.08)_100%)] p-5 shadow-[0_20px_60px_rgba(63,65,116,0.08)] sm:p-6 lg:p-7">
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
          isCodex={isCodex}
          retryInstruction={retryInstruction}
          onAllow={handleAllow}
          onBlock={handleBlock}
        />
      </div>

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
            {props.broaderScopeOptions.length > 0 && (
              <details>
                <summary className="cursor-pointer select-none py-1 font-mono text-[11px] font-semibold uppercase tracking-[0.2em] text-muted-foreground transition-colors hover:text-brand-dark/70 [&::-webkit-details-marker]:hidden">
                  › Additional approval scopes
                </summary>
                <div className="mt-2 rounded-xl border border-brand-blue/20 bg-brand-blue/[0.04] p-2">
                  <p className="mb-2 px-1 text-[11px] font-medium text-brand-blue">
                    These scopes apply across more sessions. Use only when the narrower options are not enough.
                  </p>
                  <div className="grid gap-2 sm:grid-cols-3 xl:grid-cols-1">
                    {props.broaderScopeOptions.map((option) => (
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
            )}
            {props.advancedScopeOptions.length > 0 && (
              <details>
                <summary className="cursor-pointer select-none py-1 font-mono text-[11px] font-semibold uppercase tracking-[0.2em] text-brand-attention/80 transition-colors hover:text-brand-attention [&::-webkit-details-marker]:hidden">
                  Advanced: applies everywhere
                </summary>
                <div className="mt-2 rounded-xl border border-brand-attention/25 bg-brand-attention/[0.04] p-2">
                  <p className="mb-2 px-1 text-[11px] font-medium text-brand-attention">
                    This scope applies across every project on this machine. It cannot easily be undone. Only use when no narrower scope is appropriate.
                  </p>
                  <div className="grid gap-2 xl:grid-cols-1">
                    {props.advancedScopeOptions.map((option) => (
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
            )}
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
  isCodex: boolean;
  retryInstruction: string | null;
  onAllow: () => void;
  onBlock: () => void;
}) {
  const allowText = resolveAllowButtonText(props.submitting, props.isBlocked, props.allowLabel);
  const blockText = resolveBlockButtonText(props.submitting, props.isBlocked);
  const footerCopy = props.isCodex
    ? "Codex will continue automatically after you approve."
    : "After saving, retry the same request in your chat.";

  return (
    <div className="rounded-2xl border border-white/80 bg-white/80 p-4 shadow-[0_16px_40px_rgba(63,65,116,0.10)] backdrop-blur">
      <SectionLabel>Decision</SectionLabel>
      <p className="mt-2 text-sm leading-6 text-brand-dark/70">
        {props.previewText}
      </p>
      <div className="mt-3 grid gap-1.5">
        <ApproveConsequence retryInstruction={props.retryInstruction} isCodex={props.isCodex} />
        <BlockConsequence isCodex={props.isCodex} />
      </div>
      <div className="mt-4 grid gap-2">
        <ActionButton variant="success" onClick={props.onAllow} disabled={props.submitting !== null}>
          {allowText}
        </ActionButton>
        <ActionButton variant="outline" onClick={props.onBlock} disabled={props.submitting !== null}>
          {blockText}
        </ActionButton>
      </div>
      <p className="mt-3 text-xs leading-5 text-muted-foreground">
        {footerCopy}
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
    return "Saving...";
  }
  if (blocked) {
    return "Allow: override block";
  }
  return allowLabel;
}

function resolveBlockButtonText(submitting: "allow" | "block" | null, blocked: boolean): string {
  if (submitting === "block") {
    return "Saving...";
  }
  if (blocked) {
    return "Keep blocked";
  }
  return "Block this action";
}

function copyApprovalUrlLabel(shareState: "idle" | "copied" | "failed"): string {
  if (shareState === "copied") {
    return "Copied";
  }
  if (shareState === "failed") {
    return "Copy failed";
  }
  return "Copy link";
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

function CommandHeaderButton(props: {
  label: string;
  icon: ReactNode;
  onClick: () => void;
  ariaLabel: string;
  expanded?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={props.onClick}
      aria-label={props.ariaLabel}
      aria-expanded={props.expanded}
      className="inline-flex h-7 shrink-0 items-center gap-1 rounded-lg border border-white/15 bg-white/[0.08] px-2 font-mono text-[10px] font-semibold uppercase tracking-[0.12em] text-white/70 transition-colors hover:border-white/25 hover:bg-white/15 hover:text-white focus-visible:outline-white/50"
    >
      {props.icon}
      <span className="hidden sm:inline">{props.label}</span>
    </button>
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
    <CommandHeaderButton
      label={copied ? "Copied" : "Copy"}
      ariaLabel="Copy command to clipboard"
      onClick={handleCopy}
      icon={
        copied ? (
          <HiMiniClipboardDocumentCheck className="h-3.5 w-3.5" aria-hidden="true" />
        ) : (
          <HiMiniClipboard className="h-3.5 w-3.5" aria-hidden="true" />
        )
      }
    />
  );
}

function resolveMcpInputSummary(payload: Record<string, unknown>): string | null {
  const inputs = payload.arguments ?? payload.input ?? payload.params ?? null;
  if (inputs === null || inputs === undefined) return null;
  try {
    const serialized = JSON.stringify(inputs);
    if (serialized.length <= 2) return null;
    return serialized.length > 140 ? `${serialized.slice(0, 140)}...` : serialized;
  } catch {
    return null;
  }
}

function BlockedActionCard(props: { item: GuardApprovalRequest }) {
  const launchText = actionLaunchText(props.item);
  const decisionDetail = resolveDecisionV2Detail(props.item);
  const [showCommand, setShowCommand] = useState(true);
  const [shareState, setShareState] = useState<"idle" | "copied" | "failed">("idle");
  useEffect(() => {
    setShowCommand(true);
  }, [props.item.request_id]);
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
  const approvalUrl = resolveApprovalShareUrl(props.item);
  const toggleCommand = useCallback(() => {
    setShowCommand((visible) => !visible);
  }, []);

  const handleCopyApprovalUrl = useCallback(async () => {
    if (approvalUrl === null) return;
    try {
      await navigator.clipboard.writeText(approvalUrl);
      setShareState("copied");
      window.setTimeout(() => setShareState("idle"), 1800);
    } catch {
      setShareState("failed");
      window.setTimeout(() => setShareState("idle"), 2400);
    }
  }, [approvalUrl]);

  return (
    <div className="overflow-hidden rounded-2xl border border-brand-blue/15 bg-white/70 shadow-[inset_0_1px_0_rgba(255,255,255,0.85)]">
      <div className={`flex flex-wrap items-center gap-2 px-4 py-2.5 ${bannerBg}`}>
        <BannerIcon className="h-3.5 w-3.5 shrink-0 text-white" aria-hidden="true" />
        <span className="font-mono text-[11px] font-semibold uppercase tracking-[0.2em] text-white">
          {bannerLabel}
        </span>
        {approvalUrl ? (
          <div className="ml-auto flex items-center gap-2">
            <button
              type="button"
              onClick={handleCopyApprovalUrl}
              className="inline-flex items-center gap-1 font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-white/80 transition-colors hover:text-white"
              aria-label="Copy local review link"
            >
              <HiMiniClipboard className="h-3 w-3" aria-hidden="true" />
              {copyApprovalUrlLabel(shareState)}
            </button>
            <a
              href={approvalUrl}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-white/80 transition-colors hover:text-white"
            >
              Open
              <HiMiniArrowTopRightOnSquare className="h-3 w-3" aria-hidden="true" />
            </a>
          </div>
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
        <div className="mt-4 overflow-hidden rounded-xl bg-[#090d1a] shadow-[0_14px_35px_rgba(9,13,26,0.18)]">
          <div className="flex min-h-11 flex-wrap items-center gap-1.5 border-b border-white/10 px-3 py-2 sm:flex-nowrap">
            <span className="h-2.5 w-2.5 rounded-full bg-brand-purple" />
            <span className="h-2.5 w-2.5 rounded-full bg-brand-blue" />
            <span className="h-2.5 w-2.5 rounded-full bg-brand-green" />
            <span className="ml-2 min-w-0 flex-1 truncate font-mono text-[10px] uppercase tracking-[0.2em] text-white/45">
              {resolveTerminalLabel(props.item)}
            </span>
            <span className="ml-auto flex shrink-0 items-center gap-1.5">
              <CopyCommandButton command={launchText} />
              <CommandHeaderButton
                label={showCommand ? "Hide" : "Show"}
                ariaLabel={showCommand ? "Hide stopped command" : "Show stopped command"}
                expanded={showCommand}
                onClick={toggleCommand}
                icon={
                  showCommand ? (
                    <HiMiniChevronUp className="h-3.5 w-3.5" aria-hidden="true" />
                  ) : (
                    <HiMiniChevronDown className="h-3.5 w-3.5" aria-hidden="true" />
                  )
                }
              />
            </span>
          </div>
          {showCommand ? (
            <pre className="max-h-[min(34rem,48vh)] overflow-auto whitespace-pre-wrap break-words px-3 py-3 font-mono text-[13px] leading-6 text-white sm:text-sm">
              {launchText}
            </pre>
          ) : null}
        </div>
        <WhyThisPaused item={props.item} />
        {isBlocked && (
          <div className="mt-3 rounded-xl border border-brand-purple/20 bg-brand-purple/[0.05] px-3 py-2.5">
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
      className={`flex cursor-pointer items-start gap-3 rounded-xl border p-3 transition-all duration-150 ${
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
    return <Badge tone="attention">{policyActionLabel(props.action)}</Badge>;
  }
  if (props.action === "allow") {
    return <Badge tone="success">{policyActionLabel(props.action)}</Badge>;
  }
  return <Badge tone="attention">{policyActionLabel(props.action)}</Badge>;
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
