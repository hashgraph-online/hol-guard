import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  HiMiniArrowLeft,
  HiMiniHome,
  HiMiniBolt,
  HiMiniClipboardDocumentList,
  HiMiniAdjustmentsHorizontal,
  HiMiniChevronRight,
  HiMiniCheckCircle,
  HiMiniMinusCircle,
  HiMiniExclamationTriangle,
  HiMiniCloud,
  HiMiniChartBar,
  HiMiniXMark,
  HiMiniChevronDown,
} from "react-icons/hi2";
import {
  ActionButton,
  Badge,
  EmptyState,
  SectionLabel,
  Tag,
  GuardHero,
  ProofStrip,
} from "../approval-center-primitives";
import {
  fetchApprovalPage,
  fetchPolicy,
} from "../guard-api";
import { harnessDisplayName, formatRelativeTime } from "../approval-center-utils";
import { useFocusTrap } from "../use-focus-trap";
import type {
  GuardApprovalRequest,
  GuardInventoryItem,
  GuardPolicyDecision,
  GuardReceipt,
  GuardRuntimeSnapshot,
  GuardManagedInstall,
} from "../guard-types";

type TabKey = "overview" | "activity" | "settings";

const tabOrder: TabKey[] = ["overview", "activity", "settings"];

type AppDetailWorkspaceProps = {
  harness: string;
  runtime: GuardRuntimeSnapshot;
  receipts: GuardReceipt[];
  policies: GuardPolicyDecision[];
  inventory: GuardInventoryItem[];
  requests: GuardApprovalRequest[];
  onGoHome: () => void;
  onOpenRequest: (requestId: string) => void;
  onClearAppPolicies?: (harness: string) => Promise<void>;
};

function readTabFromUrl(): TabKey {
  const hash = window.location.hash.replace("#", "");
  if (hash === "activity" || hash === "settings") return hash;
  return "overview";
}

function writeTabToUrl(tab: TabKey) {
  const url = new URL(window.location.href);
  url.hash = tab;
  window.history.replaceState({}, "", url.toString());
}

export function AppDetailWorkspace(props: AppDetailWorkspaceProps) {
  const [activeTab, setActiveTab] = useState<TabKey>(readTabFromUrl);
  const [tabDirection, setTabDirection] = useState<"left" | "right">("right");
  const touchStartX = useRef<number | null>(null);

  useEffect(() => {
    function handleHashChange() {
      setActiveTab(readTabFromUrl());
    }
    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, []);
  const [harnessQueue, setHarnessQueue] = useState<
    | { kind: "loading" }
    | { kind: "error"; message: string }
    | { kind: "ready"; items: GuardApprovalRequest[] }
  >({ kind: "loading" });
  const [harnessPolicy, setHarnessPolicy] = useState<
    | { kind: "loading" }
    | { kind: "error"; message: string }
    | { kind: "ready"; items: GuardPolicyDecision[] }
  >({ kind: "loading" });

  const { harness, runtime, receipts, policies, inventory } = props;

  const loadTabData = useCallback(() => {
    let cancelled = false;
    setHarnessQueue({ kind: "loading" });
    setHarnessPolicy({ kind: "loading" });
    Promise.allSettled([
      fetchApprovalPage({ harness, status: "pending" }),
      fetchPolicy(harness),
    ]).then(([queueResult, policyResult]) => {
      if (cancelled) return;
      if (queueResult.status === "fulfilled") {
        setHarnessQueue({ kind: "ready", items: queueResult.value.items ?? [] });
      } else {
        setHarnessQueue({
          kind: "error",
          message: queueResult.reason instanceof Error ? queueResult.reason.message : "Unable to load queue.",
        });
      }
      if (policyResult.status === "fulfilled") {
        setHarnessPolicy({ kind: "ready", items: policyResult.value ?? [] });
      } else {
        setHarnessPolicy({
          kind: "error",
          message: policyResult.reason instanceof Error ? policyResult.reason.message : "Unable to load policy.",
        });
      }
    });
    return () => {
      cancelled = true;
    };
  }, [harness]);

  useEffect(() => {
    const cleanup = loadTabData();
    return cleanup;
  }, [loadTabData]);

  const install = runtime.managed_installs?.find((i) => i.harness === harness);
  const isActive = install?.active === true;
  const isObserved =
    runtime.items.some((i) => i.harness === harness) ||
    receipts.some((r) => r.harness === harness) ||
    policies.some((p) => p.harness === harness);
  const present = isActive || isObserved;

  const harnessReceipts = useMemo(
    () => receipts.filter((r) => r.harness === harness).sort((a, b) => +new Date(b.timestamp) - +new Date(a.timestamp)),
    [receipts, harness]
  );
  const harnessInventory = useMemo(
    () => inventory.filter((i) => i.harness === harness && i.present),
    [inventory, harness]
  );
  const harnessPolicies = useMemo(
    () => (harnessPolicy.kind === "ready" ? harnessPolicy.items : policies.filter((p) => p.harness === harness)),
    [harnessPolicy, policies, harness]
  );
  const pendingItems = useMemo(
    () => (harnessQueue.kind === "ready" ? harnessQueue.items : props.requests.filter((r) => r.harness === harness)),
    [harnessQueue, props.requests, harness]
  );

  const totalActions = harnessReceipts.length;
  const blockedCount = harnessReceipts.filter((r) => r.policy_decision === "block").length;
  const allowedCount = harnessReceipts.filter((r) => r.policy_decision === "allow").length;
  const blockRate = totalActions > 0 ? Math.round((blockedCount / totalActions) * 100) : 0;

  const lastActivity = harnessReceipts[0]?.timestamp ?? null;

  const isLoading = harnessQueue.kind === "loading" || harnessPolicy.kind === "loading";
  const queueError = harnessQueue.kind === "error" ? harnessQueue.message : null;
  const policyError = harnessPolicy.kind === "error" ? harnessPolicy.message : null;

  const status: "active" | "needs_setup" | "observed" | "unknown" = isActive
    ? "active"
    : install !== undefined
    ? "needs_setup"
    : isObserved
    ? "observed"
    : "unknown";

  const heroStatus = status === "active" ? "clear" : status === "needs_setup" ? "setup_gap" : "needs_review";
  const heroHeadline =
    status === "active"
      ? `${harnessDisplayName(harness)} is protected`
      : status === "needs_setup"
      ? `${harnessDisplayName(harness)} needs setup`
      : isObserved
      ? `${harnessDisplayName(harness)} is observed`
      : `${harnessDisplayName(harness)}`;
  const heroSub =
    status === "active"
      ? "Guard is watching this app. Review its activity and settings below."
      : status === "needs_setup"
      ? "Finish setup so Guard can protect this app."
      : isObserved
      ? "Guard has seen activity but install is not active."
      : "This app has not been seen yet.";

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <button
          onClick={props.onGoHome}
          className="inline-flex items-center gap-1 rounded-full px-3 py-1.5 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-100"
        >
          <HiMiniArrowLeft className="h-4 w-4" aria-hidden="true" />
          Home
        </button>
        <HiMiniChevronRight className="h-4 w-4 text-slate-300" aria-hidden="true" />
        <span className="text-sm text-muted-foreground">Apps</span>
        <HiMiniChevronRight className="h-4 w-4 text-slate-300" aria-hidden="true" />
        <span className="text-sm font-medium text-brand-dark">{harnessDisplayName(harness)}</span>
      </div>

      <GuardHero
        status={heroStatus}
        headline={heroHeadline}
        subheadline={heroSub}
        cta={
          pendingItems.length > 0 ? (
            <ActionButton
              onClick={() => setActiveTab("activity")}
              data-primary="true"
            >
              Review {pendingItems.length} pending
            </ActionButton>
          ) : status === "needs_setup" ? (
            <ActionButton onClick={() => setActiveTab("settings")} data-primary="true">
              Open Settings
            </ActionButton>
          ) : (
            <ActionButton onClick={() => setActiveTab("activity")} data-primary="true">
              View Activity
            </ActionButton>
          )
        }
      />

      <ProofStrip
        items={[
          { label: "Pending", value: pendingItems.length, tone: pendingItems.length > 0 ? "blue" : "slate" },
          { label: "Total actions", value: totalActions, tone: totalActions > 0 ? "purple" : "slate" },
          { label: "Blocked", value: `${blockRate}%`, tone: blockRate > 0 ? "blue" : "slate" },
          { label: "Status", value: isActive ? "active" : "inactive", tone: isActive ? "green" : "slate" },
        ]}
      />

      <div className="space-y-2">
        <div className="flex gap-1 rounded-xl border border-slate-200/70 bg-white/80 p-1 shadow-sm">
          {(
            [
              { key: "overview" as TabKey, label: "Overview", icon: HiMiniHome },
              { key: "activity" as TabKey, label: "Activity", icon: HiMiniBolt },
              { key: "settings" as TabKey, label: "Settings", icon: HiMiniAdjustmentsHorizontal },
            ] as const
          ).map((t) => {
            const Icon = t.icon;
            const isActive = activeTab === t.key;
            return (
              <button
                key={t.key}
                onClick={() => handleTabChange(t.key)}
                className={`flex flex-1 items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-medium transition-all ${
                  isActive
                    ? "bg-brand-blue text-white shadow-sm"
                    : "text-brand-dark hover:bg-slate-50"
                }`}
              >
                <Icon className="h-4 w-4" />
                {t.label}
              </button>
            );
          })}
        </div>
        <p className="px-1 text-[11px] text-muted-foreground lg:hidden">
          Swipe or tap tabs to switch views
        </p>
      </div>

      <div
        className="min-h-[300px]"
        onTouchStart={handleTouchStart}
        onTouchEnd={handleTouchEnd}
      >
        {isLoading && (
          <div className="space-y-4">
            <div className="guard-skeleton h-36 w-full" />
            <div className="guard-skeleton h-8 w-1/2" />
            <div className="guard-skeleton h-48 w-full" />
          </div>
        )}
        {!isLoading && (
          <TabContent activeTab={activeTab} direction={tabDirection}>
            {activeTab === "overview" && (
              <AppOverviewTab
                harness={harness}
                status={status}
                install={install}
                totalActions={totalActions}
                allowedCount={allowedCount}
                blockedCount={blockedCount}
                blockRate={blockRate}
                lastActivity={lastActivity}
                harnessReceipts={harnessReceipts}
                harnessInventory={harnessInventory}
                pendingItems={pendingItems}
                onOpenRequest={props.onOpenRequest}
              />
            )}
            {activeTab === "activity" && (
              <AppActivityTab
                harness={harness}
                pendingItems={pendingItems}
                harnessReceipts={harnessReceipts}
                onOpenRequest={props.onOpenRequest}
                queueError={queueError}
                onRetry={loadTabData}
              />
            )}
            {activeTab === "settings" && (
              <AppSettingsTab
                harness={harness}
                status={status}
                harnessPolicies={harnessPolicies}
                onClearAppPolicies={props.onClearAppPolicies}
                policyError={policyError}
                onRetry={loadTabData}
              />
            )}
          </TabContent>
        )}
      </div>
    </div>
  );

  function handleTabChange(next: TabKey) {
    const currentIndex = tabOrder.indexOf(activeTab);
    const nextIndex = tabOrder.indexOf(next);
    setTabDirection(nextIndex > currentIndex ? "right" : "left");
    setActiveTab(next);
    writeTabToUrl(next);
  }

  function handleTouchStart(e: React.TouchEvent) {
    touchStartX.current = e.changedTouches[0].screenX;
  }

  function handleTouchEnd(e: React.TouchEvent) {
    if (touchStartX.current === null) return;
    const endX = e.changedTouches[0].screenX;
    const diff = touchStartX.current - endX;
    const threshold = 50;
    const currentIndex = tabOrder.indexOf(activeTab);
    if (diff > threshold && currentIndex < tabOrder.length - 1) {
      handleTabChange(tabOrder[currentIndex + 1]);
    } else if (diff < -threshold && currentIndex > 0) {
      handleTabChange(tabOrder[currentIndex - 1]);
    }
    touchStartX.current = null;
  }
}

function AppStatusBadge({ status }: { status: "active" | "needs_setup" | "observed" | "unknown" }) {
  if (status === "active") return <Badge tone="success">Active</Badge>;
  if (status === "needs_setup") return <Badge tone="attention">Needs setup</Badge>;
  if (status === "observed") return <Badge tone="default">Observed</Badge>;
  return <Badge tone="default">Unknown</Badge>;
}

function AppOverviewTab(props: {
  harness: string;
  status: "active" | "needs_setup" | "observed" | "unknown";
  install: GuardManagedInstall | undefined;
  totalActions: number;
  allowedCount: number;
  blockedCount: number;
  blockRate: number;
  lastActivity: string | null;
  harnessReceipts: GuardReceipt[];
  harnessInventory: GuardInventoryItem[];
  pendingItems: GuardApprovalRequest[];
  onOpenRequest: (requestId: string) => void;
}) {
  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,0.9fr)]">
      <section className="space-y-6">
        <div className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm sm:p-6">
          <div className="flex items-center justify-between gap-3">
            <div>
              <SectionLabel>Status</SectionLabel>
              <p className="mt-1 text-sm text-muted-foreground">
                {props.status === "active"
                  ? "Guard is actively protecting this app."
                  : props.status === "needs_setup"
                  ? "Guard detected this app but it needs setup."
                  : props.status === "observed"
                  ? "Guard has seen activity from this app."
                  : "This app has not been seen yet."}
              </p>
            </div>
            <AppStatusBadge status={props.status} />
          </div>

          <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
            <StatCard label="Total actions" value={props.totalActions} />
            <StatCard label="Allowed" value={props.allowedCount} tone="green" />
            <StatCard label="Blocked" value={props.blockedCount} tone={props.blockedCount > 0 ? "attention" : "slate"} />
            <StatCard label="Block rate" value={`${props.blockRate}%`} tone={props.blockRate > 10 ? "attention" : "slate"} />
          </div>

          {/* Risk snapshot */}
          {props.harnessReceipts.length >= 5 && (
            <RiskSnapshot receipts={props.harnessReceipts} />
          )}

          {props.lastActivity && (
            <p className="mt-4 text-xs text-muted-foreground">
              Last activity: {formatRelativeTime(props.lastActivity)}
            </p>
          )}

          {/* Activity Sparkline */}
          {props.harnessReceipts.length >= 3 && (
            <ActivitySparkline receipts={props.harnessReceipts} />
          )}

          {props.blockedCount > 0 && (
            <CloudValueBanner
              icon={<HiMiniExclamationTriangle className="h-4 w-4 text-brand-attention" />}
              title="Team alerts available"
              body="Cloud would alert your team when Guard blocks actions like this."
              cta={{ label: "Learn more", href: "https://hol.org/guard/pricing" }}
            />
          )}
        </div>

        {props.pendingItems.length > 0 && (
          <div className="rounded-[1.75rem] border border-brand-blue/15 bg-brand-blue/[0.04] p-5 shadow-sm sm:p-6">
            <SectionLabel>Pending review</SectionLabel>
            <p className="mt-2 text-sm text-muted-foreground">
              These actions from {harnessDisplayName(props.harness)} need your decision.
            </p>
            <div className="mt-4 space-y-2">
              {props.pendingItems.slice(0, 5).map((item) => (
                <button
                  key={item.request_id}
                  onClick={() => props.onOpenRequest(item.request_id)}
                  className="flex w-full items-center justify-between rounded-xl border border-slate-200/70 bg-white px-4 py-3 text-left transition-shadow hover:shadow-sm"
                >
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-brand-dark">
                      {item.artifact_name ?? item.artifact_id}
                    </p>
                    <p className="mt-0.5 text-xs text-muted-foreground">
                      {item.artifact_type} · {formatRelativeTime(item.created_at)}
                    </p>
                  </div>
                  <HiMiniChevronRight className="h-4 w-4 shrink-0 text-slate-300" />
                </button>
              ))}
            </div>
          </div>
        )}
      </section>

      <section className="space-y-6">
        {props.harnessReceipts.length > 0 && (
          <div className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm sm:p-6">
            <SectionLabel>Recent events</SectionLabel>
            <p className="mt-2 text-sm text-muted-foreground">
              What Guard decided recently.
            </p>
            <div className="mt-4 space-y-3">
              {props.harnessReceipts.slice(0, 5).map((receipt) => (
                <div
                  key={receipt.receipt_id}
                  className="flex items-start justify-between gap-3 rounded-xl border border-slate-200/70 bg-white px-4 py-3"
                >
                  <div className="min-w-0">
                    <p className="text-sm text-brand-dark">
                      <span className="font-medium">
                        {receipt.policy_decision === "allow" ? "Allowed" : "Blocked"}
                      </span>{" "}
                      <span className="font-mono text-xs">{receipt.artifact_name ?? receipt.artifact_id}</span>
                    </p>
                    <p className="mt-1 text-xs text-muted-foreground">
                      {formatRelativeTime(receipt.timestamp)}
                    </p>
                  </div>
                  <Tag tone={receipt.policy_decision === "allow" ? "green" : "attention"}>
                    {receipt.policy_decision}
                  </Tag>
                </div>
              ))}
            </div>
          </div>
        )}

        {props.harnessInventory.length > 0 && (
          <div className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm sm:p-6">
            <SectionLabel>Discovered items</SectionLabel>
            <p className="mt-2 text-sm text-muted-foreground">
              Tools and plugins Guard found in this app.
            </p>
            <div className="mt-4 space-y-2">
              {props.harnessInventory.slice(0, 8).map((item) => (
                <div
                  key={item.artifact_id}
                  className="flex items-center justify-between rounded-lg border border-slate-200/70 px-3 py-2"
                >
                  <p className="truncate text-sm text-brand-dark">{item.artifact_name ?? item.artifact_id}</p>
                  <span className="shrink-0 text-[11px] text-muted-foreground">{item.artifact_type}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

function AppActivityTab(props: {
  harness: string;
  pendingItems: GuardApprovalRequest[];
  harnessReceipts: GuardReceipt[];
  onOpenRequest: (requestId: string) => void;
  queueError: string | null;
  onRetry: () => void;
}) {
  const [filter, setFilter] = useState<"all" | "pending" | "allowed" | "blocked">("all");
  const [timeFilter, setTimeFilter] = useState<"all" | "today" | "week">("all");
  const [search, setSearch] = useState("");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === " " && document.activeElement?.tagName !== "INPUT") {
        const focused = document.activeElement as HTMLElement | null;
        if (focused?.closest('[role="listitem"]')) {
          const checkbox = focused.querySelector('input[type="checkbox"]') as HTMLInputElement | null;
          if (checkbox) {
            event.preventDefault();
            checkbox.click();
          }
        }
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const filteredReceipts = useMemo(() => {
    let items = props.harnessReceipts;
    if (filter === "allowed") items = items.filter((r) => r.policy_decision === "allow");
    if (filter === "blocked") items = items.filter((r) => r.policy_decision === "block");
    if (timeFilter === "today") {
      const start = new Date();
      start.setHours(0, 0, 0, 0);
      items = items.filter((r) => new Date(r.timestamp) >= start);
    }
    if (timeFilter === "week") {
      const start = new Date();
      start.setDate(start.getDate() - 7);
      items = items.filter((r) => new Date(r.timestamp) >= start);
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      items = items.filter((r) =>
        (r.artifact_name ?? r.artifact_id).toLowerCase().includes(q)
      );
    }
    return items;
  }, [props.harnessReceipts, filter, timeFilter, search]);

  const groups = useMemo(() => {
    const today: GuardReceipt[] = [];
    const yesterday: GuardReceipt[] = [];
    const thisWeek: GuardReceipt[] = [];
    const earlier: GuardReceipt[] = [];
    const now = new Date();
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const startOfYesterday = new Date(startOfToday);
    startOfYesterday.setDate(startOfYesterday.getDate() - 1);
    const startOfWeek = new Date(startOfToday);
    startOfWeek.setDate(startOfWeek.getDate() - startOfWeek.getDay());

    filteredReceipts.forEach((r) => {
      const d = new Date(r.timestamp);
      if (d >= startOfToday) today.push(r);
      else if (d >= startOfYesterday) yesterday.push(r);
      else if (d >= startOfWeek) thisWeek.push(r);
      else earlier.push(r);
    });
    return { today, yesterday, thisWeek, earlier };
  }, [filteredReceipts]);

  const hasPending = props.pendingItems.length > 0;
  const allReceiptIds = useMemo(() => filteredReceipts.map((r) => r.receipt_id), [filteredReceipts]);
  const selectedCount = selectedIds.size;

  const toggleSelection = useCallback((id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const selectAll = useCallback(() => {
    setSelectedIds(new Set(allReceiptIds));
  }, [allReceiptIds]);

  const clearSelection = useCallback(() => {
    setSelectedIds(new Set());
  }, []);

  return (
    <div className="space-y-6">
      {props.queueError && (
        <div className="guard-fade-in rounded-[1.75rem] border border-brand-attention/20 bg-brand-attention/[0.04] p-5 shadow-sm sm:p-6">
          <div className="flex items-start gap-3">
            <HiMiniExclamationTriangle className="mt-0.5 h-5 w-5 shrink-0 text-brand-attention" aria-hidden="true" />
            <div className="flex-1">
              <p className="text-sm font-medium text-brand-dark">Unable to load activity</p>
              <p className="mt-1 text-sm text-muted-foreground">{props.queueError}</p>
              <button
                onClick={props.onRetry}
                className="mt-3 inline-flex min-h-9 items-center rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50"
              >
                Retry
              </button>
            </div>
          </div>
        </div>
      )}
      <div className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm sm:p-6">
        <div className="flex flex-wrap items-center gap-2">
          {(
            [
              { key: "all" as const, label: "All" },
              { key: "pending" as const, label: `Pending (${props.pendingItems.length})` },
              { key: "allowed" as const, label: "Allowed" },
              { key: "blocked" as const, label: "Blocked" },
            ] as const
          ).map((c) => (
            <button
              key={c.key}
              onClick={() => { setFilter(c.key); clearSelection(); }}
              className={`rounded-full px-3 py-1.5 text-xs font-medium transition-all ${
                filter === c.key
                  ? "bg-brand-blue text-white shadow-sm"
                  : "border border-slate-200 bg-white text-brand-dark hover:bg-slate-50"
              }`}
            >
              {c.label}
            </button>
          ))}
          <div className="ml-auto flex gap-2">
            {(
              [
                { key: "all" as const, label: "All time" },
                { key: "today" as const, label: "Today" },
                { key: "week" as const, label: "This week" },
              ] as const
            ).map((c) => (
              <button
                key={c.key}
                onClick={() => { setTimeFilter(c.key); clearSelection(); }}
                className={`rounded-full px-3 py-1.5 text-xs font-medium transition-all ${
                  timeFilter === c.key
                    ? "bg-brand-dark text-white shadow-sm"
                    : "border border-slate-200 bg-white text-brand-dark hover:bg-slate-50"
                }`}
              >
                {c.label}
              </button>
            ))}
          </div>
        </div>

        <input
          value={search}
          onChange={(e) => { setSearch(e.target.value); clearSelection(); }}
          placeholder="Search by name..."
          className="mt-3 w-full rounded-xl border border-slate-200/70 bg-white px-4 py-2.5 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        />
      </div>

      {/* Batch selection bar */}
      {filter !== "pending" && filteredReceipts.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={selectedCount === allReceiptIds.length ? clearSelection : selectAll}
            className="rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-brand-dark transition-colors hover:bg-slate-50"
          >
            {selectedCount === allReceiptIds.length ? "Deselect all" : "Select all"}
          </button>
          {selectedCount > 0 && (
            <span className="text-xs text-muted-foreground">
              {selectedCount} selected
            </span>
          )}
        </div>
      )}

      {filter === "pending" && hasPending && (
        <div className="space-y-3">
          {props.pendingItems.map((item) => (
            <button
              key={item.request_id}
              onClick={() => props.onOpenRequest(item.request_id)}
              className="flex w-full items-center justify-between rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-4 py-3 text-left transition-shadow hover:shadow-sm"
            >
              <div className="min-w-0">
                <p className="text-sm font-medium text-brand-dark">{item.artifact_name ?? item.artifact_id}</p>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  {item.artifact_type} · {formatRelativeTime(item.created_at)}
                </p>
              </div>
              <Badge tone="info">Pending</Badge>
            </button>
          ))}
        </div>
      )}

      {filter !== "pending" && (
        <div className="space-y-6">
          {filteredReceipts.length === 0 ? (
            <EmptyState
              title="No activity yet"
              body={
                filter === "all"
                  ? "Guard hasn't recorded any decisions for this app yet. Allow or block an action and it will appear here."
                  : `No ${filter} decisions match your filters.`
              }
              tone="teach"
            />
          ) : (
            <>
              <ReceiptGroup title="Today" items={groups.today} selectedIds={selectedIds} onToggle={toggleSelection} />
              <ReceiptGroup title="Yesterday" items={groups.yesterday} selectedIds={selectedIds} onToggle={toggleSelection} />
              <ReceiptGroup title="This week" items={groups.thisWeek} selectedIds={selectedIds} onToggle={toggleSelection} />
              <ReceiptGroup title="Earlier" items={groups.earlier} selectedIds={selectedIds} onToggle={toggleSelection} />
            </>
          )}
        </div>
      )}
    </div>
  );
}

function ReceiptGroup({ title, items, selectedIds, onToggle }: { title: string; items: GuardReceipt[]; selectedIds: Set<string>; onToggle: (id: string) => void }) {
  if (items.length === 0) return null;
  return (
    <div className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm sm:p-6">
      <div className="flex items-center justify-between">
        <SectionLabel>{title}</SectionLabel>
        <span className="text-xs text-muted-foreground">{items.length} events</span>
      </div>
      <div className="mt-4 space-y-3">
        {items.map((receipt) => (
          <ExpandableReceiptRow key={receipt.receipt_id} receipt={receipt} selected={selectedIds.has(receipt.receipt_id)} onToggle={onToggle} />
        ))}
      </div>
    </div>
  );
}

function ExpandableReceiptRow({ receipt, selected, onToggle }: { receipt: GuardReceipt; selected?: boolean; onToggle?: (id: string) => void }) {
  const [expanded, setExpanded] = useState(false);
  const decisionLabel = receipt.policy_decision === "allow" ? "Allowed" : "Blocked";
  const name = receipt.artifact_name ?? receipt.artifact_id;
  return (
    <div className="rounded-xl border border-slate-200/70 bg-white overflow-hidden">
      <div className="flex w-full items-start gap-2 px-4 py-3">
        {onToggle !== undefined && (
          <label className="flex items-center pt-0.5">
            <input
              type="checkbox"
              checked={selected ?? false}
              onChange={() => onToggle(receipt.receipt_id)}
              className="h-4 w-4 rounded border-slate-300 text-brand-blue focus:ring-brand-blue"
              aria-label={`Select ${name}`}
            />
          </label>
        )}
        <button
          onClick={() => setExpanded(!expanded)}
          className="flex flex-1 items-start justify-between gap-3 text-left transition-colors hover:bg-slate-50 rounded-lg -m-1 p-1"
          aria-expanded={expanded}
        >
          <div className="min-w-0">
            <p className="text-sm text-brand-dark">
              <span className="font-medium">{decisionLabel}</span>{" "}
              <span className="font-mono text-xs">{name}</span>
            </p>
            {receipt.capabilities_summary && (
              <p className="mt-1 text-xs text-muted-foreground">{receipt.capabilities_summary}</p>
            )}
            <p className="mt-1 text-[11px] text-muted-foreground">{formatRelativeTime(receipt.timestamp)}</p>
          </div>
          <div className="flex items-center gap-2">
            <Tag tone={receipt.policy_decision === "allow" ? "green" : "attention"}>
              {receipt.policy_decision}
            </Tag>
            <HiMiniChevronDown
              className={`h-4 w-4 text-slate-400 transition-transform ${expanded ? "rotate-180" : ""}`}
              aria-hidden="true"
            />
          </div>
        </button>
      </div>
      {expanded && (
        <div className="guard-fade-in border-t border-slate-200/70 bg-slate-50/60 px-4 py-3">
          <dl className="grid grid-cols-1 gap-2 text-xs">
            <div>
              <dt className="text-muted-foreground">Action ID</dt>
              <dd className="mt-0.5 font-mono text-brand-dark">{receipt.artifact_id}</dd>
            </div>
            {receipt.artifact_hash && (
              <div>
                <dt className="text-muted-foreground">Hash</dt>
                <dd className="mt-0.5 font-mono text-brand-dark">{receipt.artifact_hash}</dd>
              </div>
            )}
            {receipt.capabilities_summary && (
              <div>
                <dt className="text-muted-foreground">Capabilities</dt>
                <dd className="mt-0.5 text-brand-dark">{receipt.capabilities_summary}</dd>
              </div>
            )}
            {receipt.provenance_summary && (
              <div>
                <dt className="text-muted-foreground">Provenance</dt>
                <dd className="mt-0.5 text-brand-dark">{receipt.provenance_summary}</dd>
              </div>
            )}
            <div>
              <dt className="text-muted-foreground">Time</dt>
              <dd className="mt-0.5 font-mono text-brand-dark">{new Date(receipt.timestamp).toLocaleString()}</dd>
            </div>
          </dl>
        </div>
      )}
    </div>
  );
}

function AppSettingsTab(props: {
  harness: string;
  status: "active" | "needs_setup" | "observed" | "unknown";
  harnessPolicies: GuardPolicyDecision[];
  onClearAppPolicies?: (harness: string) => Promise<void>;
  policyError: string | null;
  onRetry: () => void;
}) {
  const [showClearConfirm, setShowClearConfirm] = useState(false);
  const [clearing, setClearing] = useState(false);
  const confirmRef = useRef<HTMLDivElement>(null);
  useFocusTrap(showClearConfirm, confirmRef);

  const handleClear = useCallback(async () => {
    if (!props.onClearAppPolicies) return;
    setClearing(true);
    await props.onClearAppPolicies(props.harness);
    setClearing(false);
    setShowClearConfirm(false);
  }, [props.onClearAppPolicies, props.harness]);

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,0.8fr)]">
      <div className="space-y-6">
        {props.policyError && (
          <div className="guard-fade-in rounded-[1.75rem] border border-brand-attention/20 bg-brand-attention/[0.04] p-5 shadow-sm sm:p-6">
            <div className="flex items-start gap-3">
              <HiMiniExclamationTriangle className="mt-0.5 h-5 w-5 shrink-0 text-brand-attention" aria-hidden="true" />
              <div className="flex-1">
                <p className="text-sm font-medium text-brand-dark">Unable to load decisions</p>
                <p className="mt-1 text-sm text-muted-foreground">{props.policyError}</p>
                <button
                  onClick={props.onRetry}
                  className="mt-3 inline-flex min-h-9 items-center rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50"
                >
                  Retry
                </button>
              </div>
            </div>
          </div>
        )}
        <div className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm sm:p-6">
          <div className="flex items-center justify-between gap-3">
            <SectionLabel>Remembered decisions</SectionLabel>
            {props.harnessPolicies.length > 0 && props.onClearAppPolicies && (
              <button
                onClick={() => setShowClearConfirm(true)}
                className="text-xs font-medium text-brand-attention hover:text-brand-dark transition-colors"
              >
                Clear all
              </button>
            )}
          </div>
          <p className="mt-2 text-sm text-muted-foreground">
            Guard remembers these choices for {harnessDisplayName(props.harness)}. Remove any to be asked again.
          </p>
          {props.harnessPolicies.length === 0 ? (
            <div className="mt-4">
              <EmptyState
                title="No remembered decisions"
                body="Guard will remember choices here after you allow or block actions for this app."
                tone="teach"
              />
            </div>
          ) : (
            <div className={`mt-4 space-y-2 ${clearing ? "guard-fade-out" : ""}`}>
              {props.harnessPolicies.map((policy) => (
                <div
                  key={`${policy.scope}-${policy.artifact_id ?? policy.workspace ?? "global"}`}
                  className="flex items-center justify-between rounded-lg border border-slate-200/70 px-4 py-3 transition-all duration-200 hover:border-brand-blue/30 hover:shadow-sm"
                >
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-brand-dark">
                      {policy.scope === "global"
                        ? "Every project"
                        : policy.scope === "harness"
                        ? "This app"
                        : policy.scope === "artifact" && policy.artifact_id
                        ? policy.artifact_id
                        : policy.scope}
                    </p>
                    <p className="mt-0.5 text-xs text-muted-foreground">
                      {policy.action} · {policy.reason || "No reason given"}
                    </p>
                  </div>
                  <Tag tone={policy.action === "allow" ? "green" : policy.action === "block" ? "attention" : "blue"}>
                    {policy.action}
                  </Tag>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Clear confirmation */}
        {showClearConfirm && (
          <div ref={confirmRef} className="guard-fade-in rounded-[1.75rem] border border-brand-attention/20 bg-brand-attention/[0.04] p-5 shadow-sm sm:p-6">
            <div className="flex items-start gap-3">
              <HiMiniExclamationTriangle className="mt-0.5 h-5 w-5 shrink-0 text-brand-attention" aria-hidden="true" />
              <div>
                <h3 className="text-sm font-semibold text-brand-dark">
                  Clear all remembered decisions for {harnessDisplayName(props.harness)}?
                </h3>
                <p className="mt-1 text-sm text-muted-foreground">
                  This will remove {props.harnessPolicies.length} remembered decision{props.harnessPolicies.length !== 1 ? "s" : ""}. Guard will ask again next time matching actions run.
                </p>
                <div className="mt-4 flex flex-wrap gap-2">
                  <button
                    onClick={handleClear}
                    disabled={clearing}
                    className="inline-flex min-h-9 items-center rounded-lg bg-brand-attention px-3 text-sm font-semibold text-white transition-colors hover:bg-brand-attention/90 disabled:opacity-50"
                  >
                    {clearing ? "Clearing…" : "Clear decisions"}
                  </button>
                  <button
                    onClick={() => setShowClearConfirm(false)}
                    className="inline-flex min-h-9 items-center rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50"
                  >
                    Keep decisions
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {props.harnessPolicies.length > 0 && !showClearConfirm && (
          <CloudValueBanner
            icon={<HiMiniCloud className="h-4 w-4 text-brand-blue" />}
            title="Team policy sync"
            body="Cloud keeps your team's rules consistent across all devices."
            cta={{ label: "Learn more", href: "https://hol.org/guard/pricing" }}
          />
        )}
      </div>

      <div className="space-y-6">
        {props.status === "needs_setup" && (
          <div className="rounded-[1.75rem] border border-brand-attention/15 bg-brand-attention/[0.04] p-5 shadow-sm sm:p-6">
            <div className="flex items-start gap-3">
              <HiMiniExclamationTriangle className="mt-0.5 h-5 w-5 shrink-0 text-brand-attention" />
              <div>
                <SectionLabel>Setup needed</SectionLabel>
                <p className="mt-2 text-sm text-muted-foreground">
                  This app is detected but not active. Run Guard with this app once to complete setup.
                </p>
                <div className="mt-4 rounded-xl bg-white/60 p-4">
                  <p className="font-mono text-xs text-brand-dark">{`npx @hol/guard install ${props.harness}`}</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function ActivitySparkline({ receipts }: { receipts: GuardReceipt[] }) {
  const days = 7;
  const data = useMemo(() => {
    const result: { date: string; allowed: number; blocked: number }[] = [];
    const now = new Date();
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      d.setHours(0, 0, 0, 0);
      const end = new Date(d);
      end.setDate(end.getDate() + 1);
      const dayReceipts = receipts.filter((r) => {
        const rt = new Date(r.timestamp);
        return rt >= d && rt < end;
      });
      result.push({
        date: d.toLocaleDateString("en-US", { weekday: "short" }),
        allowed: dayReceipts.filter((r) => r.policy_decision === "allow").length,
        blocked: dayReceipts.filter((r) => r.policy_decision === "block").length,
      });
    }
    return result;
  }, [receipts]);

  const maxVal = Math.max(...data.map((d) => d.allowed + d.blocked), 1);

  return (
    <div className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm sm:p-6">
      <div className="flex items-center justify-between">
        <SectionLabel>Last 7 days</SectionLabel>
        <HiMiniChartBar className="h-4 w-4 text-slate-400" aria-hidden="true" />
      </div>
      <div className="mt-4 flex items-end gap-2">
        {data.map((day) => {
          const total = day.allowed + day.blocked;
          const height = total > 0 ? Math.max(20, (total / maxVal) * 100) : 4;
          return (
            <div key={day.date} className="flex flex-1 flex-col items-center gap-1">
              <div className="flex w-full gap-0.5" style={{ height: `${height}px` }}>
                <div
                  className="flex-1 rounded-t bg-brand-green/60"
                  style={{ height: `${day.allowed > 0 ? (day.allowed / total) * 100 : 0}%` }}
                  title={`${day.allowed} allowed`}
                />
                <div
                  className="flex-1 rounded-t bg-brand-attention/60"
                  style={{ height: `${day.blocked > 0 ? (day.blocked / total) * 100 : 0}%` }}
                  title={`${day.blocked} blocked`}
                />
              </div>
              <span className="text-[10px] text-muted-foreground">{day.date}</span>
            </div>
          );
        })}
      </div>
      <div className="mt-2 flex items-center gap-4">
        <span className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
          <span className="h-2 w-2 rounded-sm bg-brand-green/60" />
          Allowed
        </span>
        <span className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
          <span className="h-2 w-2 rounded-sm bg-brand-attention/60" />
          Blocked
        </span>
      </div>
    </div>
  );
}

function RiskSnapshot({ receipts }: { receipts: GuardReceipt[] }) {
  const analysis = useMemo(() => {
    const blockedCount = receipts.filter((r) => r.policy_decision === "block").length;
    const allowedCount = receipts.filter((r) => r.policy_decision === "allow").length;
    return { blocked: blockedCount, allowed: allowedCount, total: receipts.length };
  }, [receipts]);

  if (analysis.total === 0) return null;

  return (
    <div className="mt-4 rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] p-4">
      <SectionLabel>Activity breakdown</SectionLabel>
      <div className="mt-2 space-y-1.5 text-sm text-brand-dark">
        <p>
          <span className="font-medium">{analysis.allowed}</span>{" "}
          <span className="text-muted-foreground">allowed</span>
        </p>
        {analysis.blocked > 0 && (
          <p>
            <span className="font-medium text-brand-attention">{analysis.blocked}</span>{" "}
            <span className="text-muted-foreground">blocked</span>
          </p>
        )}
      </div>
    </div>
  );
}

function TabContent({
  activeTab,
  direction,
  children,
}: {
  activeTab: TabKey;
  direction: "left" | "right";
  children: React.ReactNode;
}) {
  const animationClass = direction === "right" ? "guard-tab-enter" : "guard-tab-enter-reverse";
  return (
    <div key={activeTab} className={`${animationClass}`}>
      {children}
    </div>
  );
}

function CloudValueBanner({
  icon,
  title,
  body,
  cta,
}: {
  icon: React.ReactNode;
  title: string;
  body: string;
  cta: { label: string; href: string };
}) {
  return (
    <div className="rounded-[1.75rem] border border-brand-purple/15 bg-brand-purple/[0.04] p-5 shadow-sm sm:p-6">
      <div className="flex items-start gap-3">
        <div className="mt-0.5 shrink-0">{icon}</div>
        <div className="flex-1">
          <p className="text-sm font-semibold text-brand-dark">{title}</p>
          <p className="mt-1 text-sm text-muted-foreground">{body}</p>
          <a
            href={cta.href}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-3 inline-flex items-center gap-1 text-sm font-medium text-brand-blue hover:text-brand-dark transition-colors"
          >
            {cta.label}
            <HiMiniChevronRight className="h-3 w-3" aria-hidden="true" />
          </a>
        </div>
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  tone,
}: {
  label: string;
  value: number | string;
  tone?: "green" | "attention" | "blue" | "slate";
}) {
  const toneClass =
    tone === "green"
      ? "text-brand-green"
      : tone === "attention"
      ? "text-brand-attention"
      : tone === "blue"
      ? "text-brand-blue"
      : "text-brand-dark";
  return (
    <div className="rounded-xl border border-slate-200/70 bg-white p-3 text-center">
      <p className={`text-xl font-semibold ${toneClass}`}>{value}</p>
      <p className="mt-1 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{label}</p>
    </div>
  );
}


