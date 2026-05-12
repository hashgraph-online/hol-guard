import { useMemo, memo } from "react";
import {
  HiMiniExclamationTriangle,
  HiMiniCloud,
  HiMiniChevronRight,
} from "react-icons/hi2";
import {
  EmptyState,
  SectionLabel,
  Tag,
} from "../approval-center-primitives";
import { harnessDisplayName, formatRelativeTime } from "../approval-center-utils";
import type {
  GuardManagedInstall,
  GuardReceipt,
  GuardApprovalRequest,
  GuardInventoryItem,
} from "../guard-types";
import type { AppStatus } from "./app-types";
import {
  AppStatusBadge,
  StatCard,
  ActivitySparkline,
  RiskSnapshot,
  CloudValueBanner,
} from "./app-detail-primitives";

type AppOverviewTabProps = {
  harness: string;
  status: AppStatus;
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
  onViewActivityTab?: () => void;
};

export const AppOverviewTab = memo(function AppOverviewTab(props: AppOverviewTabProps) {
  const {
    harness,
    status,
    totalActions,
    allowedCount,
    blockedCount,
    blockRate,
    lastActivity,
    harnessReceipts,
    harnessInventory,
    pendingItems,
    onOpenRequest,
    onViewActivityTab,
  } = props;

  const recentEvents = useMemo(() => harnessReceipts.slice(0, 5), [harnessReceipts]);
  const discoveredItems = useMemo(() => harnessInventory.slice(0, 8), [harnessInventory]);
  const pendingPreview = useMemo(() => pendingItems.slice(0, 5), [pendingItems]);
  const hasMorePending = pendingItems.length > 5;
  const hasMoreEvents = harnessReceipts.length > 5;
  const hasMoreInventory = harnessInventory.length > 8;

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,0.9fr)]">
      <section className="space-y-6">
        <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
          <div className="flex items-center justify-between gap-3">
            <div>
              <SectionLabel>Status</SectionLabel>
              <p className="mt-1 text-sm text-muted-foreground">
                {status === "active"
                  ? "Guard is actively protecting this app."
                  : status === "needs_setup"
                  ? "Guard detected this app but it needs setup."
                  : status === "observed"
                  ? "Guard has seen activity from this app."
                  : "This app has not been seen yet."}
              </p>
            </div>
            <AppStatusBadge status={status} />
          </div>

          <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
            <StatCard label="Total actions" value={totalActions} />
            <StatCard label="Allowed" value={allowedCount} tone="green" />
            <StatCard label="Stopped" value={blockedCount} tone={blockedCount > 0 ? "blue" : "slate"} />
            <StatCard label="Stop rate" value={`${blockRate}%`} tone={blockRate > 10 ? "blue" : "slate"} />
          </div>

          {harnessReceipts.length >= 5 && (
            <RiskSnapshot receipts={harnessReceipts} />
          )}

          {lastActivity && (
            <p className="mt-4 text-xs text-muted-foreground">
              Last activity: {formatRelativeTime(lastActivity)}
            </p>
          )}

          {harnessReceipts.length >= 3 && (
            <ActivitySparkline receipts={harnessReceipts} />
          )}

          {blockedCount > 0 && (
            <CloudValueBanner
              icon={<HiMiniExclamationTriangle className="h-4 w-4 text-brand-blue" />}
              title="Team alerts available"
              body="Cloud would alert your team when Guard stops actions like this."
              cta={{ label: "Learn more", href: "https://hol.org/guard/pricing" }}
            />
          )}
        </div>

        {pendingPreview.length > 0 && (
          <div className="rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] p-4 sm:p-5">
            <SectionLabel>Pending review</SectionLabel>
            <p className="mt-2 text-sm text-muted-foreground">
              These actions from {harnessDisplayName(harness)} need your decision.
            </p>
            <div className="mt-4 space-y-2">
              {pendingPreview.map((item) => (
                <button
                  key={item.request_id}
                  onClick={() => onOpenRequest(item.request_id)}
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
            {hasMorePending && (
              <button
                onClick={onViewActivityTab}
                className="mt-3 text-sm font-medium text-brand-blue hover:text-brand-dark transition-colors"
              >
                Show all {pendingItems.length} pending
              </button>
            )}
          </div>
        )}

        {pendingPreview.length === 0 && (
          <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
            <EmptyState
              title="Nothing waiting for review"
              body="Guard has paused no actions from this app."
              tone="default"
            />
          </div>
        )}
      </section>

      <section className="space-y-6">
        {recentEvents.length > 0 && (
          <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
            <div className="flex items-center justify-between">
              <SectionLabel>Recent events</SectionLabel>
              {hasMoreEvents && (
                <button
                  onClick={onViewActivityTab}
                  className="text-xs font-medium text-brand-blue hover:text-brand-dark transition-colors"
                >
                  View all
                </button>
              )}
            </div>
            <p className="mt-2 text-sm text-muted-foreground">
              What Guard decided recently.
            </p>
            <div className="mt-4 space-y-3">
              {recentEvents.map((receipt) => (
                <div
                  key={receipt.receipt_id}
                  className="flex items-start justify-between gap-3 rounded-xl border border-slate-200/70 bg-white px-4 py-3"
                >
                  <div className="min-w-0">
                    <p className="text-sm text-brand-dark">
                      <span className="font-medium">
                        {receipt.policy_decision === "allow" ? "Allowed" : "Stopped"}
                      </span>{" "}
                      <span className="font-mono text-xs">{receipt.artifact_name ?? receipt.artifact_id}</span>
                    </p>
                    <p className="mt-1 text-xs text-muted-foreground">
                      {formatRelativeTime(receipt.timestamp)}
                    </p>
                  </div>
                  <Tag tone={receipt.policy_decision === "allow" ? "green" : "blue"}>
                    {receipt.policy_decision}
                  </Tag>
                </div>
              ))}
            </div>
          </div>
        )}

        {recentEvents.length === 0 && (
          <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
            <EmptyState
              title="No events yet"
              body="Guard hasn't recorded any decisions for this app yet."
              tone="teach"
            />
          </div>
        )}

        {discoveredItems.length > 0 && (
          <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
            <div className="flex items-center justify-between">
              <SectionLabel>Discovered items</SectionLabel>
              {hasMoreInventory && (
                <span className="text-xs text-muted-foreground">
                  +{harnessInventory.length - 8} more
                </span>
              )}
            </div>
            <p className="mt-2 text-sm text-muted-foreground">
              Tools and plugins Guard found in this app.
            </p>
            <div className="mt-4 space-y-2">
              {discoveredItems.map((item) => (
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
});
