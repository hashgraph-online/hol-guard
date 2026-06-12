import { lazy, Suspense, useCallback } from "react";
import type { GuardApprovalGatePublicConfig, GuardReceipt, GuardRuntimeSnapshot } from "./guard-types";
import { WorkspacePageHeader } from "./workspace-page-header";
import { SUPPLY_CHAIN_WORKSPACE_SHELL_CLASS } from "./supply-chain-workspace-layout";

const SupplyChainWorkspace = lazy(() =>
  import("./supply-chain-workspace").then((module) => ({ default: module.SupplyChainWorkspace })),
);
const AuditWorkspace = lazy(() =>
  import("./audit-workspace").then((module) => ({ default: module.AuditWorkspace })),
);
const FeedHealthWorkspace = lazy(() =>
  import("./feed-health-workspace").then((module) => ({ default: module.FeedHealthWorkspace })),
);

type HubTab = "supply-chain" | "audit" | "feed-health";

const hubTabs: Array<{ value: HubTab; label: string }> = [
  { value: "supply-chain", label: "Supply Chain" },
  { value: "audit", label: "Audit" },
  { value: "feed-health", label: "Feed Health" },
];

export function hubTitleForTab(tab: string): string {
  return hubTabs.find((item) => item.value === tab)?.label ?? "Supply Chain";
}

function viewToTab(view: string): HubTab {
  if (view === "supply-chain" || view === "audit" || view === "feed-health") {
    return view;
  }
  return "supply-chain";
}

export function SupplyChainHubWorkspace(props: {
  activeView: string;
  snapshot: GuardRuntimeSnapshot;
  receipts: GuardReceipt[];
  approvalGate: GuardApprovalGatePublicConfig | null;
  onOpenSettings: () => void;
  onGoHome: () => void;
  onNavigate: (pathname: string) => void;
  onRuntimeRefresh?: () => Promise<void> | void;
}) {
  const tab = viewToTab(props.activeView);

  const handleTabChange = useCallback(
    (value: HubTab) => {
      const path = value === "supply-chain" ? "/supply-chain" : `/${value}`;
      props.onNavigate(path);
    },
    [props.onNavigate],
  );

  return (
    <div className={SUPPLY_CHAIN_WORKSPACE_SHELL_CLASS}>
      <WorkspacePageHeader
        eyebrow="Supply chain"
        title={hubTitleForTab(tab)}
        tabs={hubTabs}
        activeTab={tab}
        onTabChange={handleTabChange}
      />
      <Suspense fallback={<LazyFallback />}>
        {tab === "supply-chain" ? (
          <SupplyChainWorkspace
            snapshot={props.snapshot}
            approvalGate={props.approvalGate}
            onGoHome={props.onGoHome}
            onRuntimeRefresh={props.onRuntimeRefresh}
          />
        ) : null}
        {tab === "audit" ? (
          <AuditWorkspace snapshot={props.snapshot} receipts={props.receipts} approvalGate={props.approvalGate} />
        ) : null}
        {tab === "feed-health" ? (
          <FeedHealthWorkspace snapshot={props.snapshot} onOpenSettings={props.onOpenSettings} />
        ) : null}
      </Suspense>
    </div>
  );
}

function LazyFallback() {
  return (
    <div className="flex min-h-[200px] items-center justify-center">
      <div className="guard-skeleton h-8 w-48" />
    </div>
  );
}
