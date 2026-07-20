import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { RefObject } from "react";
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
  HiMiniShieldCheck,
  HiMiniRocketLaunch,
  HiMiniArrowPath,
  HiMiniTrash,
  HiMiniXCircle,
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
  formatHarnessCommand,
  GuardHarnessActionError,
  runHarnessAction,
} from "../guard-api";
import { harnessDisplayName, formatRelativeTime } from "../approval-center-utils";
import { buildClearPayload, clearLabelForScope, policyIdentityKey } from "../clear-policy-payload";
import { useFocusTrap } from "../use-focus-trap";
import { EvidenceActionList } from "../evidence/evidence-action-list";
import { EvidenceActionDetail } from "../evidence/evidence-action-detail";
import { EvidenceFilterBar } from "../evidence/evidence-filter-bar";
import { EvidenceInsightStrip } from "../evidence/evidence-insight-strip";
import { filterEvidence } from "../evidence/evidence-filters";
import { sortEvidence } from "../evidence/evidence-sort";
import { computeMetrics } from "../evidence/evidence-metrics";
import { guardActionDisposition, guardActionPresentation } from "../guard-action";
import { DEFAULT_FILTER_STATE } from "../evidence/evidence-url-state";
import type { EvidenceFilterState, EvidenceSortKey } from "../evidence/evidence-types";
import type {
  GuardApprovalRequest,
  GuardInventoryItem,
  GuardPolicyDecision,
  GuardReceipt,
  GuardRuntimeSnapshot,
  GuardManagedInstall,
  GuardHarnessAction,
  GuardHarnessActionResult,
  GuardHarnessSetupStep,
  PackageManagerProtection,
} from "../guard-types";

type TabKey = "overview" | "activity" | "settings";

const tabOrder: TabKey[] = ["overview", "activity", "settings"];

const TAB_DEFINITIONS = [
  { key: "overview" as TabKey, label: "Overview", icon: HiMiniHome },
  { key: "activity" as TabKey, label: "Activity", icon: HiMiniBolt },
  { key: "settings" as TabKey, label: "Settings", icon: HiMiniAdjustmentsHorizontal },
] as const;

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
  onClearPolicy?: (policy: GuardPolicyDecision) => Promise<void>;
  onManagedInstallChanged?: () => Promise<void>;
};

function readTabFromUrl(): TabKey {
  const queryTab = new URLSearchParams(window.location.search).get("tab");
  if (queryTab === "overview" || queryTab === "activity" || queryTab === "settings") return queryTab;
  const hash = window.location.hash.replace("#", "");
  if (hash === "activity" || hash === "settings") return hash;
  return "overview";
}

function writeTabToUrl(tab: TabKey) {
  const url = new URL(window.location.href);
  if (tab === "overview") {
    url.searchParams.delete("tab");
    if (url.hash === "#activity" || url.hash === "#settings" || url.hash === "#overview") {
      url.hash = "";
    }
  } else {
    url.searchParams.set("tab", tab);
  }
  window.history.replaceState({}, "", url.toString());
}

function resolveHeroStatus(status: "active" | "needs_setup" | "observed" | "unknown"): "clear" | "setup_gap" | "needs_review" {
  if (status === "active") return "clear";
  if (status === "needs_setup") return "setup_gap";
  return "needs_review";
}

function resolveHeroHeadline(status: "active" | "needs_setup" | "observed" | "unknown", harness: string, isObserved: boolean): string {
  if (status === "active") return `${harnessDisplayName(harness)} is protected`;
  if (status === "needs_setup") return `${harnessDisplayName(harness)} needs setup`;
  if (isObserved) return `${harnessDisplayName(harness)} is observed`;
  return harnessDisplayName(harness);
}

function resolveHeroSubheadline(status: "active" | "needs_setup" | "observed" | "unknown", isObserved: boolean): string {
  if (status === "active") return "Guard is watching this app. Review its activity and settings below.";
  if (status === "needs_setup") return "Finish setup so Guard can protect this app.";
  if (isObserved) return "Guard has seen activity but install is not active.";
  return "This app has not been seen yet.";
}

function resolveHeroCta(opts: {
  pendingCount: number;
  status: "active" | "needs_setup" | "observed" | "unknown";
  onGoActivity: () => void;
  onGoSettings: () => void;
}): React.ReactNode {
  if (opts.pendingCount > 0) {
    return (
      <ActionButton onClick={opts.onGoActivity} data-primary="true">
        Review {opts.pendingCount} pending
      </ActionButton>
    );
  }
  if (opts.status === "needs_setup") {
    return (
      <ActionButton onClick={opts.onGoSettings} data-primary="true">
        Open Settings
      </ActionButton>
    );
  }
  return (
    <ActionButton onClick={opts.onGoActivity} data-primary="true">
      View Activity
    </ActionButton>
  );
}

type TabButtonProps = {
  tabKey: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string; "aria-hidden"?: true }>;
  isActive: boolean;
  tabRefs: React.MutableRefObject<Record<TabKey, HTMLButtonElement | null>>;
  onSelect: (key: TabKey) => void;
};

function TabButton({ tabKey, label, icon: Icon, isActive, tabRefs, onSelect }: TabButtonProps) {
  const handleClick = useCallback(() => onSelect(tabKey), [onSelect, tabKey]);
  const setRef = useCallback((el: HTMLButtonElement | null) => {
    if (el) tabRefs.current[tabKey] = el;
  }, [tabRefs, tabKey]);

  return (
    <button
      ref={setRef}
      role="tab"
      aria-selected={isActive}
      aria-label={label}
      aria-controls={`tabpanel-${tabKey}`}
      id={`tab-${tabKey}`}
      tabIndex={isActive ? 0 : -1}
      onClick={handleClick}
      className={`group relative flex min-w-[44px] items-center justify-center gap-2 px-4 py-2.5 text-sm font-medium transition-colors ${isActive ? "text-brand-blue" : "text-brand-dark hover:text-brand-blue"}`}
    >
      <Icon className="h-4 w-4" aria-hidden={true} />
      <span className="hidden sm:inline">{label}</span>
      {isActive && <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-brand-blue" />}
    </button>
  );
}

export function AppDetailWorkspace(props: AppDetailWorkspaceProps) {
  const [activeTab, setActiveTab] = useState<TabKey>(readTabFromUrl);
  const [tabDirection, setTabDirection] = useState<"left" | "right">("right");
  const tabRefs = useRef<Record<TabKey, HTMLButtonElement | null>>({ overview: null, activity: null, settings: null });

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
  const blockedCount = harnessReceipts.filter((r) => guardActionDisposition(r.policy_decision) === "blocked").length;
  const allowedCount = harnessReceipts.filter((r) => guardActionDisposition(r.policy_decision) === "allowed").length;
  const reviewedCount = harnessReceipts.filter((r) => guardActionDisposition(r.policy_decision) === "reviewed").length;
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

  const heroStatus = resolveHeroStatus(status);
  const heroHeadline = resolveHeroHeadline(status, harness, isObserved);
  const heroSub = resolveHeroSubheadline(status, isObserved);

  const handleTabChange = useCallback((next: TabKey) => {
    const currentIndex = tabOrder.indexOf(activeTab);
    const nextIndex = tabOrder.indexOf(next);
    setTabDirection(nextIndex > currentIndex ? "right" : "left");
    setActiveTab(next);
    writeTabToUrl(next);
  }, [activeTab]);

  const handleTabKeyDown = useCallback((e: React.KeyboardEvent) => {
    const focused = document.activeElement as HTMLElement | null;
    const focusedTab = focused?.getAttribute("role") === "tab" ? (focused.id.replace("tab-", "") as TabKey) : activeTab;
    const currentIndex = tabOrder.indexOf(focusedTab);
    let nextIndex = -1;

    if (e.key === "ArrowRight") nextIndex = Math.min(currentIndex + 1, tabOrder.length - 1);
    else if (e.key === "ArrowLeft") nextIndex = Math.max(currentIndex - 1, 0);
    else if (e.key === "Home") nextIndex = 0;
    else if (e.key === "End") nextIndex = tabOrder.length - 1;

    if (nextIndex >= 0 && nextIndex < tabOrder.length) {
      e.preventDefault();
      const nextTab = tabOrder[nextIndex];
      handleTabChange(nextTab);
      const nextEl = tabRefs.current[nextTab];
      if (nextEl) nextEl.focus();
    }
  }, [activeTab, handleTabChange]);

  const handleGoActivity = useCallback(() => handleTabChange("activity"), [handleTabChange]);
  const handleGoSettings = useCallback(() => handleTabChange("settings"), [handleTabChange]);

  const heroCta = resolveHeroCta({ pendingCount: pendingItems.length, status, onGoActivity: handleGoActivity, onGoSettings: handleGoSettings });

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
        cta={heroCta}
      />

      <ProofStrip
        items={[
          { label: "Pending", value: pendingItems.length, tone: pendingItems.length > 0 ? "blue" : "slate" },
          { label: "Total actions", value: totalActions, tone: totalActions > 0 ? "purple" : "slate" },
          { label: "Blocked", value: `${blockRate}%`, tone: blockRate > 0 ? "blue" : "slate" },
          { label: "Status", value: isActive ? "active" : "inactive", tone: isActive ? "green" : "slate" },
        ]}
      />

      <div
        className="relative"
        role="tablist"
        aria-label="App detail tabs"
        onKeyDown={handleTabKeyDown}
      >
        <div className="flex gap-1 border-b border-slate-200/70">
          {TAB_DEFINITIONS.map((t) => (
            <TabButton
              key={t.key}
              tabKey={t.key}
              label={t.label}
              icon={t.icon}
              isActive={activeTab === t.key}
              tabRefs={tabRefs}
              onSelect={handleTabChange}
            />
          ))}
        </div>
      </div>

      <div
        className="min-h-[300px]"
        role="tabpanel"
        id={`tabpanel-${activeTab}`}
        aria-labelledby={`tab-${activeTab}`}
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
                reviewedCount={reviewedCount}
                blockRate={blockRate}
                lastActivity={lastActivity}
                harnessReceipts={harnessReceipts}
                harnessInventory={harnessInventory}
                pendingItems={pendingItems}
                protection={runtime.supply_chain?.package_manager_protection}
                onOpenRequest={props.onOpenRequest}
                onManagedInstallChanged={props.onManagedInstallChanged}
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
                install={install}
                harnessPolicies={harnessPolicies}
                onClearAppPolicies={props.onClearAppPolicies}
                onClearPolicy={props.onClearPolicy}
                onManagedInstallChanged={props.onManagedInstallChanged}
                policyError={policyError}
                onRetry={loadTabData}
              />
            )}
          </TabContent>
        )}
      </div>
    </div>
  );
}

function AppStatusBadge({ status }: { status: "active" | "needs_setup" | "observed" | "unknown" }) {
  if (status === "active") return <Badge tone="success">Active</Badge>;
  if (status === "needs_setup") return <Badge tone="attention">Needs setup</Badge>;
  if (status === "observed") return <Badge tone="default">Observed</Badge>;
  return <Badge tone="default">Unknown</Badge>;
}

function firstRunSteps(harness: string): { index: number; title: string; body: string }[] {
  const displayName = harnessDisplayName(harness);
  return [
    {
      index: 1,
      title: `Connect ${displayName}`,
      body: "Use the dashboard action. Guard asks the local daemon to write only managed app configuration.",
    },
    {
      index: 2,
      title: `Restart ${displayName}`,
      body: "Restart the app once so the new hooks and wrappers load in the next session.",
    },
    {
      index: 3,
      title: "Run your agent flow",
      body: "When a risky command, prompt, or tool action appears, Guard pauses it and sends the decision to Review.",
    },
  ];
}

function AppOverviewTab(props: {
  harness: string;
  status: "active" | "needs_setup" | "observed" | "unknown";
  install: GuardManagedInstall | undefined;
  totalActions: number;
  allowedCount: number;
  blockedCount: number;
  reviewedCount: number;
  blockRate: number;
  lastActivity: string | null;
  harnessReceipts: GuardReceipt[];
  harnessInventory: GuardInventoryItem[];
  pendingItems: GuardApprovalRequest[];
  protection: PackageManagerProtection | undefined;
  onOpenRequest: (requestId: string) => void;
  onManagedInstallChanged?: () => Promise<void>;
}) {
  const showFirstRunGuide = shouldShowFirstRunGuide({
    status: props.status,
    totalActions: props.totalActions,
    inventoryCount: props.harnessInventory.length,
    pendingCount: props.pendingItems.length,
  });

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,0.9fr)]">
      <section className="space-y-6">
        {showFirstRunGuide && (
          <FirstRunGuide
            harness={props.harness}
            install={props.install}
            status={props.status}
            onManagedInstallChanged={props.onManagedInstallChanged}
          />
        )}

        <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
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

          <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-5">
            <StatCard label="Total actions" value={props.totalActions} />
            <StatCard label="Allowed" value={props.allowedCount} tone="green" />
            <StatCard label="Review" value={props.reviewedCount} tone={props.reviewedCount > 0 ? "blue" : "slate"} />
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
          <div className="rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] p-4 sm:p-5">
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
        {props.harnessReceipts.length > 0 ? (
          <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
            <SectionLabel>Recent events</SectionLabel>
            <p className="mt-2 text-sm text-muted-foreground">
              What Guard decided recently.
            </p>
            <div className="mt-4 space-y-3">
              {props.harnessReceipts.slice(0, 5).map((receipt) => {
                const presentation = guardActionPresentation(receipt.policy_decision);
                return (
                  <div
                    key={receipt.receipt_id}
                    className="flex items-start justify-between gap-3 rounded-xl border border-slate-200/70 bg-white px-4 py-3"
                  >
                    <div className="min-w-0">
                      <p className="text-sm text-brand-dark">
                        <span className="font-medium">{presentation.label}</span>{" "}
                        <span className="font-mono text-xs">{receipt.artifact_name ?? receipt.artifact_id}</span>
                      </p>
                      <p className="mt-1 text-xs text-muted-foreground">
                        {formatRelativeTime(receipt.timestamp)}
                      </p>
                    </div>
                    <Badge tone={presentation.tone}>{presentation.label}</Badge>
                  </div>
                );
              })}
            </div>
          </div>
        ) : showFirstRunGuide ? (
          <div className="rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] p-4 sm:p-5">
            <SectionLabel>What happens next</SectionLabel>
            <div className="mt-4 space-y-3">
              {firstRunSteps(props.harness).map((step) => (
                <div key={step.title} className="flex gap-3 rounded-xl border border-white/70 bg-white/80 p-3">
                  <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-brand-blue/10 text-xs font-semibold text-brand-blue">
                    {step.index}
                  </span>
                  <div>
                    <p className="text-sm font-semibold text-brand-dark">{step.title}</p>
                    <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{step.body}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : null}

        {props.harnessInventory.length > 0 && (
          <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
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

        <AppFirewallStatusCard protection={props.protection} />
      </section>
    </div>
  );
}

function AppFirewallStatusCard({ protection }: { protection: PackageManagerProtection | undefined }) {
  const protectedManagers = protection?.protected_managers ?? [];
  const unprotectedManagers = protection?.unprotected_managers ?? [];
  const total = protectedManagers.length + unprotectedManagers.length;

  return (
    <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
      <div className="flex items-center justify-between gap-2 mb-3">
        <SectionLabel>Package firewall</SectionLabel>
        {total === 0 ? (
          <Tag tone="slate">No data</Tag>
        ) : unprotectedManagers.length === 0 ? (
          <Tag tone="green">All covered</Tag>
        ) : (
          <Tag tone="attention">{unprotectedManagers.length} unprotected</Tag>
        )}
      </div>
      {total === 0 ? (
        <p className="text-sm text-slate-500">
          Package manager coverage data is not available. Run Guard to collect supply chain metrics.
        </p>
      ) : (
        <div className="space-y-1.5">
          {protectedManagers.map((mgr) => (
            <div key={mgr} className="flex items-center justify-between gap-2 py-1 border-b border-slate-100 last:border-b-0">
              <span className="text-sm font-mono text-brand-dark">{mgr}</span>
              <span className="inline-flex items-center gap-1 rounded-full border border-brand-green/25 bg-brand-green/[0.06] px-2.5 py-0.5 text-xs font-medium text-brand-green-text">
                <HiMiniCheckCircle className="h-3 w-3" aria-hidden="true" />
                Shim active
              </span>
            </div>
          ))}
          {unprotectedManagers.map((mgr) => (
            <div key={mgr} className="flex items-center justify-between gap-2 py-1 border-b border-slate-100 last:border-b-0">
              <span className="text-sm font-mono text-brand-dark">{mgr}</span>
              <span className="inline-flex items-center gap-1 rounded-full border border-amber-200 bg-amber-50/60 px-2.5 py-0.5 text-xs font-medium text-amber-700">
                <HiMiniXCircle className="h-3 w-3" aria-hidden="true" />
                No shim
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function shouldShowFirstRunGuide(input: {
  status: "active" | "needs_setup" | "observed" | "unknown";
  totalActions: number;
  inventoryCount: number;
  pendingCount: number;
}): boolean {
  return input.status !== "active" && input.totalActions === 0 && input.inventoryCount === 0 && input.pendingCount === 0;
}

function FirstRunGuide(props: {
  harness: string;
  install: GuardManagedInstall | undefined;
  status: "active" | "needs_setup" | "observed" | "unknown";
  onManagedInstallChanged?: () => Promise<void>;
}) {
  const displayName = harnessDisplayName(props.harness);
  return (
    <div className="overflow-hidden rounded-[1.35rem] border border-brand-blue/15 bg-gradient-to-br from-brand-blue/[0.10] via-white to-brand-green/[0.06] shadow-sm">
      <div className="grid gap-0 lg:grid-cols-[minmax(0,0.92fr)_minmax(0,1.08fr)]">
        <div className="flex flex-col justify-between gap-6 p-5 sm:p-6">
          <div>
            <SectionLabel>Start protecting {displayName}</SectionLabel>
            <h2 className="mt-3 max-w-xl text-2xl font-semibold leading-tight text-brand-dark">
              Connect {displayName}, restart it once, then let Guard pause risky actions before they run.
            </h2>
            <p className="mt-3 max-w-lg text-sm leading-relaxed text-muted-foreground">
              {firstRunIntro(props.harness)}
            </p>
          </div>
          <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-1">
            <GuidePill label="No terminal copy" value="Dashboard action" />
            <GuidePill label="Local only" value="Daemon managed" />
            <GuidePill label="First proof" value="Appears here" />
          </div>
        </div>
        <div className="border-t border-white/70 bg-white/72 p-4 sm:p-5 lg:border-l lg:border-t-0">
          <HarnessSetupPanel
            harness={props.harness}
            install={props.install}
            status={props.status}
            onManagedInstallChanged={props.onManagedInstallChanged}
          />
        </div>
      </div>
    </div>
  );
}

function GuidePill(props: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-white/80 bg-white/70 p-3 shadow-sm">
      <p className="text-[10px] font-semibold uppercase tracking-widest text-brand-blue">{props.label}</p>
      <p className="mt-1 text-sm font-semibold text-brand-dark">{props.value}</p>
    </div>
  );
}

function firstRunIntro(harness: string): string {
  if (harness === "cursor") {
    return "Guard writes the Cursor-specific local configuration through the daemon. After connecting, restart Cursor so the protected hooks load before your next agent run.";
  }
  return `Guard writes the ${harnessDisplayName(harness)} local configuration through the daemon. After connecting, restart the app so protected hooks load before your next agent run.`;
}

const ACTIVITY_PAGE_SIZE = 50;

function AppActivityTab(props: {
  harness: string;
  pendingItems: GuardApprovalRequest[];
  harnessReceipts: GuardReceipt[];
  onOpenRequest: (requestId: string) => void;
  queueError: string | null;
  onRetry: () => void;
}) {
  const [showPending, setShowPending] = useState(false);
  const [filters, setFilters] = useState<EvidenceFilterState>(() => ({
    ...DEFAULT_FILTER_STATE,
    view: "actions",
  }));
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [page, setPage] = useState(0);

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(filters.search), 300);
    return () => clearTimeout(timer);
  }, [filters.search]);

  useEffect(() => {
    setPage(0);
  }, [debouncedSearch, filters.time, filters.decision, filters.category, filters.sourceScope, filters.day]);

  const { view, time, decision, category, sourceScope, day, sort, selectedId } = filters;
  const effectiveFilters = useMemo(
    () => ({
      view,
      time,
      decision,
      category,
      sourceScope,
      day,
      sort,
      selectedId,
      search: debouncedSearch,
      harness: props.harness,
    }),
    [view, time, decision, category, sourceScope, day, sort, selectedId, debouncedSearch, props.harness]
  );

  const filtered = useMemo(
    () => filterEvidence(props.harnessReceipts, effectiveFilters),
    [props.harnessReceipts, effectiveFilters]
  );

  const sorted = useMemo(
    () => sortEvidence(filtered, filters.sort),
    [filtered, filters.sort]
  );

  const metrics = useMemo(() => computeMetrics(filtered), [filtered]);

  const selectedReceipt = useMemo(() => {
    if (!filters.selectedId) return null;
    return filtered.find((receipt) => receipt.receipt_id === filters.selectedId) ?? null;
  }, [filtered, filters.selectedId]);

  const handleFilterChange = useCallback((patch: Partial<EvidenceFilterState>) => {
    setFilters((prev) => ({ ...prev, ...patch }));
  }, []);

  const handleSelectId = useCallback((id: string) => {
    setFilters((prev) => ({
      ...prev,
      selectedId: prev.selectedId === id ? "" : id,
    }));
  }, []);

  const handleCloseDetail = useCallback(() => {
    setFilters((prev) => ({ ...prev, selectedId: "" }));
  }, []);

  const handleFilterCategory = useCallback((category: string) => {
    setFilters((prev) => ({ ...prev, category }));
  }, []);

  const handleSortChange = useCallback((sort: EvidenceSortKey) => {
    handleFilterChange({ sort });
  }, [handleFilterChange]);

  const handleLoadMore = useCallback(() => {
    setPage((prev) => prev + 1);
  }, []);

  const handleShowActions = useCallback(() => {
    setShowPending(false);
  }, []);

  const handleShowPending = useCallback(() => {
    setShowPending(true);
    setFilters((prev) => ({ ...prev, selectedId: "" }));
  }, []);

  const noopHarnessFilter = useCallback((_harness: string) => {}, []);

  const hasPending = props.pendingItems.length > 0;

  return (
    <div className="space-y-6">
      {props.queueError && (
        <div className="guard-fade-in rounded-xl border border-brand-attention/10 bg-brand-attention/[0.03] p-4 sm:p-5">
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

      {hasPending && (
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={handleShowActions}
            className={`rounded-full px-3 py-1.5 text-xs font-medium transition-all ${
              !showPending
                ? "bg-brand-blue text-white shadow-sm"
                : "border border-slate-200 bg-white text-brand-dark hover:bg-slate-50"
            }`}
          >
            Actions
          </button>
          <button
            type="button"
            onClick={handleShowPending}
            className={`rounded-full px-3 py-1.5 text-xs font-medium transition-all ${
              showPending
                ? "bg-brand-blue text-white shadow-sm"
                : "border border-slate-200 bg-white text-brand-dark hover:bg-slate-50"
            }`}
          >
            Pending ({props.pendingItems.length})
          </button>
        </div>
      )}

      {showPending ? (
        hasPending ? (
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
        ) : (
          <EmptyState
            title="No pending reviews"
            body="Guard will surface actions here when this app needs a decision."
            tone="teach"
          />
        )
      ) : props.harnessReceipts.length === 0 ? (
        <EmptyState
          title="No activity yet"
          body="Guard has not recorded any decisions for this app yet. Allow or block an action and it will appear here."
          tone="teach"
        />
      ) : (
        <div className={selectedReceipt ? "grid grid-cols-1 gap-3 lg:grid-cols-[1fr_340px]" : ""}>
          <div className="space-y-3">
            <EvidenceFilterBar
              filters={filters}
              onChange={handleFilterChange}
              totalCount={props.harnessReceipts.length}
              filteredCount={filtered.length}
              harnesses={[]}
              hideHarnessFilter={true}
            />
            <EvidenceInsightStrip metrics={metrics} />
            <EvidenceActionList
              receipts={sorted}
              selectedId={filters.selectedId}
              onSelectId={handleSelectId}
              onFilterHarness={noopHarnessFilter}
              onFilterCategory={handleFilterCategory}
              sort={filters.sort}
              onSortChange={handleSortChange}
              page={page}
              pageSize={ACTIVITY_PAGE_SIZE}
              onLoadMore={handleLoadMore}
              hideHarnessColumn={true}
              tableLabel={`${harnessDisplayName(props.harness)} actions`}
            />
          </div>
          {selectedReceipt && (
            <div className="overflow-hidden rounded-2xl border border-slate-100 bg-white shadow-sm">
              <EvidenceActionDetail receipt={selectedReceipt} onClose={handleCloseDetail} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function policyDecisionTitle(policy: GuardPolicyDecision): string {
  if (policy.scope === "global") {
    return "Every project";
  }
  if (policy.scope === "harness") {
    return "This app";
  }
  if (policy.scope === "artifact" && policy.artifact_id) {
    return policy.artifact_id;
  }
  return policy.scope;
}

function policyDecisionTone(action: string): "blue" | "green" | "attention" {
  if (action === "allow") {
    return "green";
  }
  if (action === "block") {
    return "attention";
  }
  return "blue";
}

function PolicyDecisionRow(props: {
  policy: GuardPolicyDecision;
  rowKey: string;
  isConfirming: boolean;
  inFlight: boolean;
  showClearButton: boolean;
  onRequestClear: (key: string) => void;
  onConfirmClear: () => void;
  onCancelClear: () => void;
  rowConfirmRef?: RefObject<HTMLDivElement | null>;
}) {
  const { policy, rowKey, isConfirming, inFlight, showClearButton } = props;
  const label = clearLabelForScope(policy.scope);
  const handleRequest = useCallback(() => props.onRequestClear(rowKey), [props.onRequestClear, rowKey]);
  const clearButtonLabel = inFlight ? "Clearing..." : label;

  return (
    <div className="rounded-lg border border-slate-200/70 transition-all duration-200 hover:border-brand-blue/30 hover:shadow-sm">
      <div className="flex items-center justify-between px-4 py-3">
        <div className="min-w-0">
          <p className="text-sm font-medium text-brand-dark">{policyDecisionTitle(policy)}</p>
          <p className="mt-0.5 text-xs text-muted-foreground">
            {policy.action} · {policy.reason || "No reason given"}
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Tag tone={policyDecisionTone(policy.action)}>{policy.action}</Tag>
          {showClearButton && !isConfirming && (
            <button
              onClick={handleRequest}
              className="text-xs font-medium text-muted-foreground hover:text-brand-attention transition-colors"
            >
              {label}
            </button>
          )}
        </div>
      </div>
      {isConfirming && (
        <div
          ref={props.rowConfirmRef}
          className="guard-fade-in border-t border-slate-200/70 bg-slate-50/60 px-4 py-3"
        >
          <p className="text-xs text-muted-foreground">
            Guard will ask again the next time this action runs.
          </p>
          <div className="mt-2 flex flex-wrap gap-2">
            <button
              onClick={props.onConfirmClear}
              disabled={inFlight}
              className="inline-flex min-h-8 items-center rounded-lg bg-brand-attention px-3 text-xs font-semibold text-white transition-colors hover:bg-brand-attention/90 disabled:opacity-50"
            >
              {clearButtonLabel}
            </button>
            <button
              onClick={props.onCancelClear}
              disabled={inFlight}
              className="inline-flex min-h-8 items-center rounded-lg border border-slate-200 bg-white px-3 text-xs font-medium text-brand-dark transition-colors hover:bg-slate-50 disabled:opacity-50"
            >
              Keep decision
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function AppSettingsTab(props: {
  harness: string;
  status: "active" | "needs_setup" | "observed" | "unknown";
  install: GuardManagedInstall | undefined;
  harnessPolicies: GuardPolicyDecision[];
  onClearAppPolicies?: (harness: string) => Promise<void>;
  onClearPolicy?: (policy: GuardPolicyDecision) => Promise<void>;
  onManagedInstallChanged?: () => Promise<void>;
  policyError: string | null;
  onRetry: () => void;
}) {
  const [showClearConfirm, setShowClearConfirm] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [clearingRowKey, setClearingRowKey] = useState<string | null>(null);
  const [clearingRowInFlight, setClearingRowInFlight] = useState(false);
  const confirmRef = useRef<HTMLDivElement>(null);
  const rowConfirmRef = useRef<HTMLDivElement>(null);
  useFocusTrap(showClearConfirm, confirmRef);
  useFocusTrap(clearingRowKey !== null, rowConfirmRef);

  const handleClear = useCallback(async () => {
    if (!props.onClearAppPolicies) return;
    setClearing(true);
    await props.onClearAppPolicies(props.harness);
    await props.onRetry();
    setClearing(false);
    setShowClearConfirm(false);
  }, [props.onClearAppPolicies, props.harness, props.onRetry]);

  const handleClearCancel = useCallback(() => {
    setShowClearConfirm(false);
  }, []);

  const handleClearRowConfirm = useCallback(async () => {
    if (!props.onClearPolicy || clearingRowKey === null) return;
    const policy = props.harnessPolicies.find(
      (item) => policyIdentityKey(item) === clearingRowKey
    );
    if (!policy) return;
    setClearingRowInFlight(true);
    try {
      await props.onClearPolicy(policy);
      await props.onRetry();
      setClearingRowKey(null);
    } finally {
      setClearingRowInFlight(false);
    }
  }, [props.onClearPolicy, props.harnessPolicies, props.onRetry, clearingRowKey]);

  const handleClearRowCancel = useCallback(() => {
    setClearingRowKey(null);
  }, []);
  const clearAllButtonLabel = clearing ? "Clearing..." : "Clear decisions";

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,0.8fr)]">
      <div className="space-y-6">
        <HarnessSetupPanel
          harness={props.harness}
          install={props.install}
          status={props.status}
          onManagedInstallChanged={props.onManagedInstallChanged}
        />

        {props.policyError && (
          <div className="guard-fade-in rounded-xl border border-brand-attention/10 bg-brand-attention/[0.03] p-4 sm:p-5">
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
        <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
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
              {props.harnessPolicies.map((policy) => {
                const rowKey = policyIdentityKey(policy);
                const isConfirmingThis = clearingRowKey === rowKey;
                return (
                  <PolicyDecisionRow
                    key={rowKey}
                    policy={policy}
                    rowKey={rowKey}
                    isConfirming={isConfirmingThis}
                    inFlight={isConfirmingThis && clearingRowInFlight}
                    showClearButton={!!props.onClearPolicy}
                    onRequestClear={setClearingRowKey}
                    onConfirmClear={handleClearRowConfirm}
                    onCancelClear={handleClearRowCancel}
                    rowConfirmRef={isConfirmingThis ? rowConfirmRef : undefined}
                  />
                );
              })}
            </div>
          )}
        </div>

        {/* Clear confirmation */}
        {showClearConfirm && (
          <div ref={confirmRef} className="guard-fade-in rounded-xl border border-brand-attention/10 bg-brand-attention/[0.03] p-4 sm:p-5">
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
                    {clearAllButtonLabel}
                  </button>
                  <button
                    onClick={handleClearCancel}
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

      <HarnessCoverageAside status={props.status} install={props.install} />
    </div>
  );
}

type HarnessSetupState =
  | { kind: "idle" }
  | { kind: "loading"; action: GuardHarnessAction }
  | { kind: "ready"; plan: GuardHarnessActionResult }
  | { kind: "success"; action: GuardHarnessAction; result: GuardHarnessActionResult }
  | { kind: "error"; action: GuardHarnessAction; message: string; confirmationPhrase?: string; confirmCommand?: string };

function HarnessSetupPanel(props: {
  harness: string;
  install: GuardManagedInstall | undefined;
  status: "active" | "needs_setup" | "observed" | "unknown";
  onManagedInstallChanged?: () => Promise<void>;
}) {
  const [setupState, setSetupState] = useState<HarnessSetupState>({ kind: "idle" });
  const [disconnectArmed, setDisconnectArmed] = useState(false);
  const active = props.install?.active === true;
  const displayName = harnessDisplayName(props.harness);

  const refreshAfterMutation = useCallback(async () => {
    await props.onManagedInstallChanged?.();
  }, [props.onManagedInstallChanged]);

  const loadPlan = useCallback(async () => {
    setSetupState({ kind: "loading", action: active ? "verify" : "install" });
    try {
      const result = active
        ? await runHarnessAction({ harness: props.harness, action: "verify" })
        : await runHarnessAction({ harness: props.harness, action: "install", dryRun: true });
      setSetupState({ kind: "ready", plan: result });
    } catch (error) {
      setSetupState({
        kind: "error",
        action: active ? "verify" : "install",
        message: error instanceof Error ? error.message : "Unable to load setup plan.",
      });
    }
  }, [active, props.harness]);

  useEffect(() => {
    void loadPlan();
  }, [loadPlan]);

  const runAction = useCallback(
    async (action: GuardHarnessAction, options: { dryRun?: boolean; confirmationPhrase?: string } = {}) => {
      setSetupState({ kind: "loading", action });
      try {
        const result = await runHarnessAction({
          harness: props.harness,
          action,
          dryRun: options.dryRun,
          confirmationPhrase: options.confirmationPhrase,
        });
        setDisconnectArmed(false);
        setSetupState({ kind: "success", action, result });
        if (action !== "verify" && options.dryRun !== true) {
          await refreshAfterMutation();
        }
      } catch (error) {
        if (error instanceof GuardHarnessActionError) {
          setSetupState({
            kind: "error",
            action,
            message: setupActionErrorMessage(error),
            confirmationPhrase: error.payload?.confirmation_phrase,
            confirmCommand: error.payload?.confirm_command,
          });
        } else {
          setSetupState({
            kind: "error",
            action,
            message: error instanceof Error ? error.message : "Harness action failed.",
          });
        }
      }
    },
    [props.harness, refreshAfterMutation]
  );

  const handleConnect = useCallback(() => {
    void runAction("install", { dryRun: false });
  }, [runAction]);

  const handleVerify = useCallback(() => {
    void runAction("verify");
  }, [runAction]);

  const handleRepair = useCallback(() => {
    void runAction("repair", { dryRun: false });
  }, [runAction]);

  const handleRequestDisconnect = useCallback(() => {
    setDisconnectArmed(true);
    void runAction("uninstall", { dryRun: true });
  }, [runAction]);

  const handleConfirmDisconnect = useCallback(() => {
    const phrase =
      setupState.kind === "error" && setupState.confirmationPhrase
        ? setupState.confirmationPhrase
        : setupState.kind === "success" && setupState.result.confirmation_phrase
        ? setupState.result.confirmation_phrase
        : `disconnect-${props.harness}`;
    void runAction("uninstall", { dryRun: false, confirmationPhrase: phrase });
  }, [props.harness, runAction, setupState]);

  const handleCancelDisconnect = useCallback(() => {
    setDisconnectArmed(false);
    void loadPlan();
  }, [loadPlan]);

  const busy = setupState.kind === "loading";
  const currentPlan =
    setupState.kind === "ready"
      ? setupState.plan
      : setupState.kind === "success"
      ? setupState.result
      : null;
  const steps = setupStepsFor(currentPlan, active);
  const notes = setupNotesFor(currentPlan);

  return (
    <div className="rounded-2xl border border-brand-blue/15 bg-gradient-to-br from-brand-blue/[0.055] via-white to-brand-dark/[0.025] p-4 shadow-sm sm:p-5">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <SectionLabel>Local harness install</SectionLabel>
          <h3 className="mt-2 text-lg font-semibold text-brand-dark">
            {active ? `${displayName} is managed by Guard` : `Connect ${displayName} from this dashboard`}
          </h3>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            {active
              ? "Run safe checks, repair managed hooks, or disconnect this app without leaving the dashboard."
              : "Guard will install the local managed hooks through the daemon. No copied shell command required."}
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">
          {!active && (
            <ActionButton onClick={handleConnect} disabled={busy} data-primary="true">
              <HiMiniRocketLaunch className="h-4 w-4" aria-hidden="true" />
              {busy && setupState.kind === "loading" && setupState.action === "install" ? "Connecting..." : "Connect app"}
            </ActionButton>
          )}
          {active && (
            <>
              <ActionButton onClick={handleVerify} disabled={busy} variant="outline">
                <HiMiniShieldCheck className="h-4 w-4" aria-hidden="true" />
                Test
              </ActionButton>
              <ActionButton onClick={handleRepair} disabled={busy} variant="outline">
                <HiMiniArrowPath className="h-4 w-4" aria-hidden="true" />
                Repair
              </ActionButton>
            </>
          )}
        </div>
      </div>

      <div className="mt-5 grid gap-3 md:grid-cols-3">
        <SetupMetric label="Install state" value={active ? "Protected" : props.status === "observed" ? "Observed" : "Not connected"} active={active} />
        <SetupMetric label="Config source" value={props.install?.workspace ?? "Local machine"} />
        <SetupMetric label="Last changed" value={props.install ? formatRelativeTime(props.install.updated_at) : "Not yet"} />
      </div>

      {setupState.kind === "error" && (
        <div className="mt-4 rounded-xl border border-brand-attention/15 bg-brand-attention/[0.04] p-4">
          <div className="flex items-start gap-3">
            <HiMiniExclamationTriangle className="mt-0.5 h-5 w-5 shrink-0 text-brand-attention" aria-hidden="true" />
            <div className="min-w-0 flex-1">
              <p className="text-sm font-semibold text-brand-dark">Could not finish {setupActionLabel(setupState.action)}</p>
              <p className="mt-1 break-words text-sm text-muted-foreground">{setupState.message}</p>
              {setupState.confirmCommand && (
                <code className="mt-3 block overflow-x-auto rounded-lg bg-white/80 px-3 py-2 font-mono text-xs text-brand-dark">
                  {setupState.confirmCommand}
                </code>
              )}
            </div>
          </div>
        </div>
      )}

      {setupState.kind === "success" && (
        <div className="mt-4 rounded-xl border border-brand-green/20 bg-brand-green/[0.045] p-4">
          <div className="flex items-start gap-3">
            <HiMiniCheckCircle className="mt-0.5 h-5 w-5 shrink-0 text-brand-green" aria-hidden="true" />
            <div className="min-w-0">
              <p className="text-sm font-semibold text-brand-dark">{setupSuccessTitle(setupState.action, displayName)}</p>
              <p className="mt-1 text-sm text-muted-foreground">
                {setupState.action === "verify"
                  ? "Safe local check completed. No app config was changed."
                  : "Dashboard action completed through the local Guard daemon."}
              </p>
            </div>
          </div>
        </div>
      )}

      {steps.length > 0 && (
        <div className="mt-5 space-y-2">
          {steps.map((step) => (
            <HarnessSetupStepRow key={step.step_id} step={step} />
          ))}
        </div>
      )}

      {notes.length > 0 && (
        <div className="mt-4 rounded-xl border border-slate-200/70 bg-white/80 p-4">
          <p className="text-xs font-semibold uppercase tracking-widest text-slate-400">What changed</p>
          <ul className="mt-2 space-y-1.5">
            {notes.slice(0, 4).map((note) => (
              <li key={note} className="break-words text-xs leading-relaxed text-muted-foreground">
                {note}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="mt-5 flex flex-wrap items-center gap-2 border-t border-slate-200/70 pt-4">
        <button
          onClick={() => void loadPlan()}
          disabled={busy}
          className="inline-flex min-h-10 items-center rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50 disabled:opacity-50"
        >
          Refresh setup
        </button>
        {active && !disconnectArmed && (
          <button
            onClick={handleRequestDisconnect}
            disabled={busy}
            className="inline-flex min-h-10 items-center gap-1.5 rounded-lg border border-brand-attention/20 bg-white px-3 text-sm font-medium text-brand-attention transition-colors hover:bg-brand-attention/[0.04] disabled:opacity-50"
          >
            <HiMiniTrash className="h-4 w-4" aria-hidden="true" />
            Disconnect
          </button>
        )}
        {active && disconnectArmed && (
          <>
            <button
              onClick={handleConfirmDisconnect}
              disabled={busy}
              className="inline-flex min-h-10 items-center rounded-lg bg-brand-attention px-3 text-sm font-semibold text-white transition-colors hover:bg-brand-attention/90 disabled:opacity-50"
            >
              {busy && setupState.kind === "loading" && setupState.action === "uninstall" ? "Disconnecting..." : "Confirm disconnect"}
            </button>
            <button
              onClick={handleCancelDisconnect}
              disabled={busy}
              className="inline-flex min-h-10 items-center rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50 disabled:opacity-50"
            >
              Keep connected
            </button>
          </>
        )}
      </div>
    </div>
  );
}

function HarnessSetupStepRow({ step }: { step: GuardHarnessSetupStep }) {
  const commandText = formatHarnessCommand(step.command);
  return (
    <div className="rounded-xl border border-slate-200/70 bg-white/80 p-3">
      <div className="flex items-start gap-3">
        <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-brand-blue/10 text-brand-blue">
          {step.writes_config ? <HiMiniAdjustmentsHorizontal className="h-3.5 w-3.5" aria-hidden="true" /> : <HiMiniCheckCircle className="h-3.5 w-3.5" aria-hidden="true" />}
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-brand-dark">{step.title}</p>
          <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{step.body}</p>
          {commandText && (
            <code className="mt-2 block overflow-x-auto rounded-lg bg-slate-50 px-3 py-2 font-mono text-xs text-brand-dark">
              {commandText}
            </code>
          )}
        </div>
      </div>
    </div>
  );
}

function HarnessCoverageAside(props: {
  status: "active" | "needs_setup" | "observed" | "unknown";
  install: GuardManagedInstall | undefined;
}) {
  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
        <SectionLabel>Protection model</SectionLabel>
        <p className="mt-2 text-sm text-muted-foreground">
          Dashboard actions call the local Guard daemon directly. CLI commands are shown only as fallback copy for terminals or automation.
        </p>
        <div className="mt-4 space-y-2 text-xs text-muted-foreground">
          <p>Runs locally on this machine.</p>
          <p>Requires the one-time Guard token in this dashboard session.</p>
          <p>Writes only the harness-managed Guard config for this app.</p>
        </div>
      </div>
      {props.install?.manifest ? (
        <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
          <SectionLabel>Managed files</SectionLabel>
          <ManifestPathList manifest={props.install.manifest} />
        </div>
      ) : props.status !== "active" ? (
        <div className="rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] p-4 sm:p-5">
          <SectionLabel>First run</SectionLabel>
          <p className="mt-2 text-sm text-muted-foreground">
            Connect this app here first. Then launch the app normally through the Guard wrapper so risky actions pause for review.
          </p>
        </div>
      ) : null}
    </div>
  );
}

function ManifestPathList({ manifest }: { manifest: Record<string, unknown> }) {
  const pathEntries = Object.entries(manifest).filter(
    ([key, value]) => key.endsWith("_path") && typeof value === "string" && value.length > 0
  );
  if (pathEntries.length === 0) {
    return <p className="mt-2 text-sm text-muted-foreground">Guard has no managed file paths to show for this app yet.</p>;
  }
  return (
    <dl className="mt-3 space-y-2">
      {pathEntries.slice(0, 5).map(([key, value]) => (
        <div key={key} className="min-w-0">
          <dt className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">{key.replace(/_/g, " ")}</dt>
          <dd className="mt-0.5 break-all font-mono text-xs text-brand-dark">{String(value)}</dd>
        </div>
      ))}
    </dl>
  );
}

function SetupMetric(props: { label: string; value: string; active?: boolean }) {
  return (
    <div className="min-w-0 rounded-xl border border-slate-200/70 bg-white/80 p-3">
      <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">{props.label}</p>
      <p className={`mt-1 truncate text-sm font-semibold ${props.active ? "text-brand-green" : "text-brand-dark"}`}>
        {props.value}
      </p>
    </div>
  );
}

function setupStepsFor(result: GuardHarnessActionResult | null, active: boolean): GuardHarnessSetupStep[] {
  if (!result) return [];
  if (Array.isArray(result.steps) && result.steps.length > 0) return result.steps;
  if (result.verification?.steps) return result.verification.steps;
  if (!active && result.contract?.setup_steps) return result.contract.setup_steps;
  if (active && result.contract?.verify_steps) return result.contract.verify_steps;
  return [];
}

function setupNotesFor(result: GuardHarnessActionResult | null): string[] {
  const manifest = result?.managed_install?.manifest;
  const notes = manifest?.["notes"];
  return Array.isArray(notes) ? notes.filter((note): note is string => typeof note === "string") : [];
}

function setupActionLabel(action: GuardHarnessAction): string {
  if (action === "install") return "connect";
  if (action === "verify") return "test";
  if (action === "repair") return "repair";
  return "disconnect";
}

function setupActionErrorMessage(error: GuardHarnessActionError): string {
  if (error.payload?.error === "confirmation_required") {
    return "Disconnect requires confirmation so accidental clicks cannot remove local protection.";
  }
  return error.payload?.error ?? error.message;
}

function setupSuccessTitle(action: GuardHarnessAction, displayName: string): string {
  if (action === "install") return `${displayName} connected`;
  if (action === "verify") return `${displayName} test complete`;
  if (action === "repair") return `${displayName} repaired`;
  return `${displayName} disconnected`;
}

function ActivitySparkline({ receipts }: { receipts: GuardReceipt[] }) {
  const days = 7;
  const data = useMemo(() => {
    const result: { date: string; allowed: number; reviewed: number; blocked: number }[] = [];
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
        allowed: dayReceipts.filter((r) => guardActionDisposition(r.policy_decision) === "allowed").length,
        reviewed: dayReceipts.filter((r) => guardActionDisposition(r.policy_decision) === "reviewed").length,
        blocked: dayReceipts.filter((r) => guardActionDisposition(r.policy_decision) === "blocked").length,
      });
    }
    return result;
  }, [receipts]);

  const maxVal = Math.max(...data.map((d) => d.allowed + d.reviewed + d.blocked), 1);

  return (
    <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
      <div className="flex items-center justify-between">
        <SectionLabel>Last 7 days</SectionLabel>
        <HiMiniChartBar className="h-4 w-4 text-slate-400" aria-hidden="true" />
      </div>
      <div className="mt-4 flex items-end gap-2">
        {data.map((day) => {
          const total = day.allowed + day.reviewed + day.blocked;
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
                  className="flex-1 rounded-t bg-brand-blue/50"
                  style={{ height: `${day.reviewed > 0 ? (day.reviewed / total) * 100 : 0}%` }}
                  title={`${day.reviewed} awaiting review`}
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
          <span className="h-2 w-2 rounded-sm bg-brand-blue/50" />
          Review
        </span>
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
    const blockedCount = receipts.filter((r) => guardActionDisposition(r.policy_decision) === "blocked").length;
    const allowedCount = receipts.filter((r) => guardActionDisposition(r.policy_decision) === "allowed").length;
    const reviewedCount = receipts.filter((r) => guardActionDisposition(r.policy_decision) === "reviewed").length;
    return { blocked: blockedCount, allowed: allowedCount, reviewed: reviewedCount, total: receipts.length };
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
        {analysis.reviewed > 0 && (
          <p>
            <span className="font-medium text-brand-blue">{analysis.reviewed}</span>{" "}
            <span className="text-muted-foreground">awaiting review</span>
          </p>
        )}
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
    <div className="rounded-xl border border-brand-purple/10 bg-brand-purple/[0.03] p-4 sm:p-5">
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
