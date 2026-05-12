import { useCallback, useEffect, useMemo, useState } from "react";
import {
  HiMiniArrowLeft,
  HiMiniHome,
  HiMiniBolt,
  HiMiniAdjustmentsHorizontal,
  HiMiniChevronRight,
} from "react-icons/hi2";
import {
  GuardHero,
  ProofStrip,
} from "../approval-center-primitives";
import { harnessDisplayName, formatRelativeTime } from "../approval-center-utils";
import { fetchApprovalPage, fetchPolicy } from "../guard-api";
import type {
  GuardApprovalRequest,
  GuardInventoryItem,
  GuardPolicyDecision,
  GuardReceipt,
  GuardRuntimeSnapshot,
  GuardManagedInstall,
} from "../guard-types";
import type { TabKey } from "./app-types";
import {
  TabContent,
} from "./app-detail-primitives";
import { AppOverviewTab } from "./app-overview-tab";
import { AppActivityTab } from "./app-activity-tab";
import { AppSettingsTab } from "./app-settings-tab";

const tabOrder: TabKey[] = ["overview", "activity", "settings"];

const tabDefs = [
  { key: "overview" as TabKey, label: "Overview", icon: HiMiniHome },
  { key: "activity" as TabKey, label: "Activity", icon: HiMiniBolt },
  { key: "settings" as TabKey, label: "Settings", icon: HiMiniAdjustmentsHorizontal },
] as const;

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

export function AppDetailWorkspace(props: AppDetailWorkspaceProps) {
  const [activeTab, setActiveTab] = useState<TabKey>(readTabFromUrl);
  const [tabDirection, setTabDirection] = useState<"left" | "right">("right");

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

  const handleViewActivityTab = useCallback(() => {
    handleTabChange("activity");
  }, []);

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
            <button
              onClick={() => handleTabChange("activity")}
              className="inline-flex min-h-9 items-center rounded-lg bg-brand-blue px-4 text-sm font-semibold text-white transition-colors hover:bg-brand-blue/90"
            >
              Review {pendingItems.length} pending
            </button>
          ) : status === "needs_setup" ? (
            <button
              onClick={() => handleTabChange("settings")}
              className="inline-flex min-h-9 items-center rounded-lg bg-brand-blue px-4 text-sm font-semibold text-white transition-colors hover:bg-brand-blue/90"
            >
              Open Settings
            </button>
          ) : (
            <button
              onClick={() => handleTabChange("activity")}
              className="inline-flex min-h-9 items-center rounded-lg bg-brand-blue px-4 text-sm font-semibold text-white transition-colors hover:bg-brand-blue/90"
            >
              View Activity
            </button>
          )
        }
      />

      <ProofStrip
        items={[
          { label: "Pending", value: pendingItems.length, tone: pendingItems.length > 0 ? "blue" : "slate" },
          { label: "Total actions", value: totalActions, tone: totalActions > 0 ? "purple" : "slate" },
          { label: "Stopped", value: `${blockRate}%`, tone: blockRate > 0 ? "blue" : "slate" },
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
          {tabDefs.map((t) => {
            const Icon = t.icon;
            const isActiveTab = activeTab === t.key;
            return (
              <button
                key={t.key}
                role="tab"
                aria-selected={isActiveTab}
                aria-controls={`tabpanel-${t.key}`}
                id={`tab-${t.key}`}
                onClick={() => handleTabChange(t.key)}
                className={`group relative flex min-w-[44px] items-center justify-center gap-2 px-4 py-2.5 text-sm font-medium transition-colors ${
                  isActiveTab
                    ? "text-brand-blue"
                    : "text-brand-dark hover:text-brand-blue"
                }`}
              >
                <Icon className="h-4 w-4" aria-hidden="true" />
                <span className="hidden sm:inline">{t.label}</span>
                {isActiveTab && (
                  <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-brand-blue" />
                )}
              </button>
            );
          })}
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
                blockRate={blockRate}
                lastActivity={lastActivity}
                harnessReceipts={harnessReceipts}
                harnessInventory={harnessInventory}
                pendingItems={pendingItems}
                onOpenRequest={props.onOpenRequest}
                onViewActivityTab={handleViewActivityTab}
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

  function handleTabKeyDown(e: React.KeyboardEvent) {
    const currentIndex = tabOrder.indexOf(activeTab);
    if (e.key === "ArrowRight" && currentIndex < tabOrder.length - 1) {
      e.preventDefault();
      handleTabChange(tabOrder[currentIndex + 1]);
    } else if (e.key === "ArrowLeft" && currentIndex > 0) {
      e.preventDefault();
      handleTabChange(tabOrder[currentIndex - 1]);
    }
  }
}
