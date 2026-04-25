import type { ReactNode } from "react";
import { useState, useEffect, useCallback, useMemo, type ChangeEvent } from "react";
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
  ListControls,
  PaginationControls
} from "./approval-center-primitives";
import { ReceiptsWorkspace } from "./receipts-workspace";
import { RuntimeOverview } from "./runtime-overview";
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
  harnessDisplayName
} from "./approval-center-utils";
import type {
  GuardApprovalRequest,
  GuardArtifactDiff,
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
  activeRequestId: string | null;
  resolutionMessage: string | null;
  homeContent: ReactNode;
  fleetContent: ReactNode;
  settingsContent: ReactNode;
  onGoHome: () => void;
  onNavigate: (pathname: string) => void;
  onOpenRequest: (requestId: string) => void;
  onResolve: (payload: {
    requestId: string;
    action: "allow" | "block";
    scope: DecisionScope;
    workspace?: string;
    reason: string;
  }) => void;
};

const scopeOptions: Array<{ value: DecisionScope; label: string; description: string }> = [
  { value: "artifact", label: "This exact action", description: "Ask again if the command or tool details change." },
  { value: "workspace", label: "This project folder", description: "Remember this choice only for this project." },
  { value: "publisher", label: "This source", description: "Trust future actions from the same source in this app." },
  { value: "harness", label: "This app", description: "Trust matching actions from this app." },
  { value: "global", label: "Every project", description: "Use this choice across this machine." }
];

const commonScopeValues = new Set<DecisionScope>(["artifact", "workspace"]);
const queuePageSize = 8;
export function ApprovalCenterLayout(props: LayoutProps) {
  const queuedItems = props.requests.kind === "ready" ? props.requests.items : [];
  const activeHarness =
    props.detail.kind === "ready" ? props.detail.item.harness : queuedItems[0]?.harness ?? null;
  return (
    <div className="min-h-screen bg-white text-brand-dark">
      <ShellHeader
        queuedCount={queuedItems.length}
        activeHarness={activeHarness}
        view={props.view}
        onNavigate={props.onNavigate}
      />
      <ShellSidebar queuedCount={queuedItems.length} activeHarness={activeHarness} view={props.view} />
      <div className="flex flex-col lg:pl-64">
        <main className="flex-1 p-6 lg:p-10">
          <div className="mx-auto max-w-6xl">
            {props.view === "home" ? (
              <>
                <RuntimeBanner runtime={props.runtime} />
                {props.homeContent}
              </>
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
              />
            )}
          </div>
        </main>
      </div>
    </div>
  );
}

function RuntimeBanner(props: { runtime: RuntimeState }) {
  if (props.runtime.kind === "loading") {
    return <div className="mb-6 guard-skeleton h-20 w-full" />;
  }
  if (props.runtime.kind === "error") {
    return (
      <Surface className="mb-6" tone="warning">
        <SectionLabel>Runtime health</SectionLabel>
        <h2 className="mt-1 text-lg font-semibold tracking-tight text-brand-dark">
          Guard is not connected to the local runtime right now
        </h2>
        <p className="mt-2 text-sm text-brand-dark/80">{props.runtime.message}</p>
        <p className="mt-2 text-sm text-muted-foreground">
          Restart with hol-guard bootstrap if the local approval center stopped or if the daemon lost its session.
        </p>
      </Surface>
    );
  }
  return <RuntimeOverview snapshot={props.runtime.snapshot} />;
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
}) {
  if (props.requests.kind === "loading") {
    return (
      <div className="space-y-4">
        <div className="guard-skeleton h-8 w-64" />
        <div className="guard-skeleton h-32 w-full" />
      </div>
    );
  }
  if (props.requests.kind === "error") {
    return (
      <Surface tone="danger">
        <p className="text-sm text-brand-purple">{props.requests.message}</p>
      </Surface>
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
  return (
    <div className="space-y-6">
      <QueueHeader
        activeRequestId={props.activeRequestId}
        requests={props.requests.items}
        runtime={props.runtime}
      />
      <DecisionWorkspace
        detail={props.detail}
        onGoHome={props.onGoHome}
        onResolve={props.onResolve}
      />
      <QueueBrowser
        activeRequestId={props.activeRequestId}
        items={props.requests.items}
        onOpenRequest={props.onOpenRequest}
      />
    </div>
  );
}

function QueueHeader(props: {
  activeRequestId: string | null;
  requests: GuardApprovalRequest[];
  runtime: RuntimeState;
}) {
  const activeItem = props.requests.find((item) => item.request_id === props.activeRequestId) ?? props.requests[0] ?? null;
  const runtimeLabel = props.runtime.kind === "ready" ? props.runtime.snapshot.cloud_state_label : "Local runtime";
  return (
    <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-[-0.02em] text-brand-dark">
          Review Queue
        </h1>
        <p className="max-w-2xl text-sm leading-relaxed text-muted-foreground">
          HOL Guard paused the action below before it ran. Review the command or tool, then approve it once or keep it blocked.
        </p>
      </div>
      <div className="flex flex-wrap gap-2">
        <Badge tone="warning">{props.requests.length} waiting</Badge>
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
}) {
  const [searchTerm, setSearchTerm] = useState("");
  const [harnessFilter, setHarnessFilter] = useState("all");
  const [actionFilter, setActionFilter] = useState("all");
  const [page, setPage] = useState(1);
  const harnesses = Array.from(new Set(props.items.map((item) => item.harness))).sort();
  const actions = Array.from(new Set(props.items.map((item) => item.policy_action))).sort();
  const filteredItems = useMemo(() => {
    const normalizedSearchTerm = searchTerm.trim().toLowerCase();
    return props.items.filter((item) => {
      const matchesHarness = harnessFilter === "all" || item.harness === harnessFilter;
      const matchesAction = actionFilter === "all" || item.policy_action === actionFilter;
      if (!matchesHarness || !matchesAction) {
        return false;
      }
      if (normalizedSearchTerm.length === 0) {
        return true;
      }
      const searchable = `${displayArtifactName(item)} ${item.artifact_type} ${item.harness} ${item.policy_action} ${buildQueueSummary(item)}`.toLowerCase();
      return searchable.includes(normalizedSearchTerm);
    });
  }, [actionFilter, harnessFilter, props.items, searchTerm]);
  const totalPages = Math.max(1, Math.ceil(filteredItems.length / queuePageSize));
  const currentPage = Math.min(page, totalPages);
  const pageStart = (currentPage - 1) * queuePageSize;
  const visibleItems = filteredItems.slice(pageStart, pageStart + queuePageSize);

  useEffect(() => {
    setPage(1);
  }, [actionFilter, harnessFilter, searchTerm, props.items.length]);

  const handleSearchChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setSearchTerm(event.target.value);
  }, []);

  const handleHarnessFilterChange = useCallback((event: ChangeEvent<HTMLSelectElement>) => {
    setHarnessFilter(event.target.value);
  }, []);

  const handleActionFilterChange = useCallback((event: ChangeEvent<HTMLSelectElement>) => {
    setActionFilter(event.target.value);
  }, []);

  const handlePreviousPage = useCallback(() => {
    setPage((value) => Math.max(1, value - 1));
  }, []);

  const handleNextPage = useCallback(() => {
    setPage((value) => Math.min(totalPages, value + 1));
  }, [totalPages]);

  return (
    <section className="border-t border-slate-200/70 pt-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <SectionLabel>Other waiting actions</SectionLabel>
          <h2 className="mt-2 text-lg font-semibold tracking-tight text-brand-dark">
            Switch only if this is not the action you meant to review.
          </h2>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-muted-foreground">
            The current action stays above. Use this list when several apps are waiting for Guard decisions.
          </p>
        </div>
        <Badge tone="warning">{filteredItems.length} shown</Badge>
      </div>
      <div className="mt-5 grid gap-3 lg:grid-cols-[minmax(0,1fr)_180px]">
        <ListControls
          searchLabel="Search waiting actions"
          searchValue={searchTerm}
          searchPlaceholder="Search action, app, or reason"
          filterLabel="Filter by app"
          filterValue={harnessFilter}
          filterOptions={harnesses}
          allLabel="All apps"
          onSearchChange={handleSearchChange}
          onFilterChange={handleHarnessFilterChange}
        />
        <label className="block">
          <span className="sr-only">Filter by decision</span>
          <select
            value={actionFilter}
            onChange={handleActionFilterChange}
            className="min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors duration-150 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          >
            <option value="all">All decisions</option>
            {actions.map((action) => (
              <option key={action} value={action}>{policyActionLabel(action)}</option>
            ))}
          </select>
        </label>
      </div>
      <div className="mt-4 divide-y divide-slate-200/70 overflow-hidden rounded-[1.5rem] border border-slate-200/70 bg-white/75 shadow-sm">
        {visibleItems.length > 0 ? (
          visibleItems.map((item) => (
            <QueueCard
              key={item.request_id}
              item={item}
              active={item.request_id === props.activeRequestId}
              onClick={() => props.onOpenRequest(item.request_id)}
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
        totalItems={filteredItems.length}
        pageSize={queuePageSize}
        onPrevious={handlePreviousPage}
        onNext={handleNextPage}
        className="mt-4"
      />
    </section>
  );
}

function QueueCard(props: { item: GuardApprovalRequest; active: boolean; onClick: () => void }) {
  const summary = buildQueueSummary(props.item);
  const isBlocked = props.item.policy_action === "block";
  return (
    <button
      type="button"
      onClick={props.onClick}
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
              props.active ? "bg-brand-blue" : isBlocked ? "bg-brand-purple" : "bg-slate-200"
            }`}
          />
          <div className="min-w-0">
            <p className="truncate text-sm font-semibold text-brand-dark">{actionDisplayTitle(props.item)}</p>
            <p className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">
              {displayArtifactName(props.item)}
            </p>
          </div>
        </div>
        <PolicyBadge action={props.item.policy_action} />
      </div>
      <p className="mt-2 line-clamp-2 text-xs leading-relaxed text-muted-foreground">
        {harnessDisplayName(props.item.harness)} · {summary}
      </p>
    </button>
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

  useEffect(() => {
    if (props.detail.kind === "ready") {
      setScope(props.detail.item.recommended_scope);
      setErrorMessage(null);
      setSubmitting(null);
    }
  }, [props.detail]);
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
      } catch (error) {
        setErrorMessage(error instanceof Error ? error.message : "Something went wrong.");
        setSubmitting(null);
      }
    },
    [props.onResolve, readyRequestId, readyWorkspace, reason, scope]
  );

  if (props.detail.kind === "loading") {
    return (
      <div className="space-y-4">
        <div className="guard-skeleton h-8 w-48" />
        <div className="guard-skeleton h-40 w-full" />
        <div className="guard-skeleton h-56 w-full" />
      </div>
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
    return <EmptyState title="Select an item" body="Choose a blocked item from the sidebar to review the evidence and make a decision." />;
  }
  const { item, diff, receipt, policy } = props.detail;
  const commonScopeOpts = scopeOptions.filter((option) => commonScopeValues.has(option.value));
  const broadScopeOpts = scopeOptions.filter((option) => !commonScopeValues.has(option.value));
  return (
    <div className="guard-surface-in space-y-4">
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
        onResolve={handleResolve}
      />
      <WhatChanged item={item} diff={diff} receipt={receipt} policy={policy} />
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
          Review technical evidence
        </span>
        <span className="hidden rounded-full bg-surface-1 px-3 py-1 font-mono text-[11px] text-muted-foreground sm:inline">
            saved details
        </span>
      </summary>
      <div className="mt-4 space-y-3 border-l-2 border-brand-blue/10 pl-4">
        <p className="text-sm leading-relaxed text-brand-dark/70">{buildStoppedReason(item, receipt)}</p>
        <WhyGuardCares item={item} />
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
  return (
    <section className="guard-surface-in relative overflow-hidden rounded-[2rem] border border-brand-blue/15 bg-[radial-gradient(circle_at_top_left,rgba(85,153,254,0.12),transparent_32%),linear-gradient(135deg,#ffffff_0%,#ffffff_58%,rgba(85,153,254,0.08)_100%)] p-5 shadow-[0_20px_60px_rgba(63,65,116,0.08)] sm:p-6 lg:p-7">
      <div className="pointer-events-none absolute right-8 top-8 h-24 w-24 rounded-full bg-brand-green/20 blur-3xl" />
      <div className="relative grid gap-6 lg:grid-cols-[minmax(0,1fr)_330px] lg:items-start">
        <div>
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
        <DecisionActionPanel
          allowLabel={allowLabel}
          previewText={previewText}
          submitting={props.submitting}
          onAllow={() => props.onResolve("allow")}
          onBlock={() => props.onResolve("block")}
        />
      </div>

      <DecisionSteps activeStep={props.submitting === null ? 1 : 3} />

      <div className="relative mt-6 grid gap-6 xl:grid-cols-[minmax(0,1.08fr)_minmax(340px,0.92fr)] xl:items-start">
        <BlockedActionCard item={props.item} />
        <div className="space-y-4">
          <div>
            <SectionLabel>Trust level</SectionLabel>
            <p className="mt-2 text-sm leading-6 text-brand-dark/75">
              {buildRecommendation(props.item)}
            </p>
          </div>
          <fieldset className="space-y-3">
            <legend className="sr-only">Approval scope</legend>
            <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-1">
              {props.commonScopeOptions.map((option) => (
                <ScopeOption
                  key={option.value}
                  value={option.value}
                  label={option.label}
                  description={option.description}
                  checked={props.scope === option.value}
                  onChange={() => props.onScopeChange(option.value)}
                />
              ))}
            </div>
            <details>
              <summary className="cursor-pointer select-none py-1 font-mono text-[11px] font-semibold uppercase tracking-[0.2em] text-muted-foreground transition-colors hover:text-brand-dark/70 [&::-webkit-details-marker]:hidden">
                › Advanced trust levels
              </summary>
              <div className="mt-2 grid gap-2 sm:grid-cols-3 xl:grid-cols-1">
                {props.broadScopeOptions.map((option) => (
                  <ScopeOption
                    key={option.value}
                    value={option.value}
                    label={option.label}
                    description={option.description}
                    checked={props.scope === option.value}
                    onChange={() => props.onScopeChange(option.value)}
                  />
                ))}
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
              onChange={(e) => props.onReasonChange(e.target.value)}
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
  onAllow: () => void;
  onBlock: () => void;
}) {
  return (
    <div className="rounded-[1.65rem] border border-white/80 bg-white/80 p-4 shadow-[0_16px_40px_rgba(63,65,116,0.10)] backdrop-blur">
      <SectionLabel>Decision</SectionLabel>
      <p className="mt-2 text-sm leading-6 text-brand-dark/70">
        {props.previewText}
      </p>
      <div className="mt-4 grid gap-2">
        <ActionButton onClick={props.onAllow} disabled={props.submitting !== null}>
          {props.submitting === "allow" ? "Saving…" : props.allowLabel}
        </ActionButton>
        <ActionButton variant="danger" onClick={props.onBlock} disabled={props.submitting !== null}>
          {props.submitting === "block" ? "Saving…" : "Keep blocked"}
        </ActionButton>
      </div>
      <p className="mt-3 text-xs leading-5 text-muted-foreground">
        After saving, retry the same request in your chat.
      </p>
    </div>
  );
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

function BlockedActionCard(props: { item: GuardApprovalRequest }) {
  const launchText = actionLaunchText(props.item);
  return (
    <div className="rounded-[1.65rem] border border-brand-blue/15 bg-white/70 p-4 shadow-[inset_0_1px_0_rgba(255,255,255,0.85)]">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <SectionLabel>What was stopped</SectionLabel>
        <Badge tone="warning">{artifactTypeLabel(props.item.artifact_type)}</Badge>
      </div>
      <h4 className="mt-2 text-xl font-semibold tracking-tight text-brand-dark">
        {actionDisplayTitle(props.item)}
      </h4>
      <p className="mt-2 text-sm leading-6 text-brand-dark/70">
        {harnessDisplayName(props.item.harness)} paused this because {buildQueueSummary(props.item).toLowerCase()}.
      </p>
      <div className="mt-4 rounded-[1.25rem] bg-[#090d1a] p-1 shadow-[0_14px_35px_rgba(9,13,26,0.18)]">
        <div className="flex items-center gap-1.5 border-b border-white/10 px-3 py-2">
          <span className="h-2.5 w-2.5 rounded-full bg-brand-purple" />
          <span className="h-2.5 w-2.5 rounded-full bg-brand-blue" />
          <span className="h-2.5 w-2.5 rounded-full bg-brand-green" />
          <span className="ml-2 font-mono text-[10px] uppercase tracking-[0.22em] text-white/45">
            Command or tool details
          </span>
        </div>
        <pre className="overflow-x-auto whitespace-pre-wrap break-words px-3 py-3 font-mono text-sm leading-6 text-white">
          {launchText}
        </pre>
      </div>
    </div>
  );
}

function actionDisplayTitle(item: GuardApprovalRequest): string {
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
  if (item.launch_target?.trim()) {
    return item.launch_target;
  }
  if (item.launch_summary?.trim()) {
    const commandMatch = item.launch_summary.match(/`([^`]+)`/);
    if (commandMatch?.[1]) {
      return commandMatch[1];
    }
    return item.launch_summary;
  }
  return displayArtifactName(item);
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
  const tone =
    props.action === "block" ? "destructive" as const :
    props.action === "allow" ? "success" as const :
    "warning" as const;
  return <Badge tone={tone}>{policyActionLabel(props.action)}</Badge>;
}

function displayArtifactName(item: GuardApprovalRequest): string {
  return item.artifact_name || item.artifact_id || "this action";
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
