import { lazy, Suspense, useCallback } from "react";
import { TabBar } from "./approval-center-primitives";
import type { GuardApprovalGatePublicConfig, GuardPolicyDecision, GuardReceipt, GuardRuntimeSnapshot } from "./guard-types";

const SupplyChainWorkspace = lazy(() =>
  import("./supply-chain-workspace").then((m) => ({ default: m.SupplyChainWorkspace }))
);
const AuditWorkspace = lazy(() =>
  import("./audit-workspace").then((m) => ({ default: m.AuditWorkspace }))
);
const PolicyWorkspace = lazy(() =>
  import("./policy-workspace").then((m) => ({ default: m.PolicyWorkspace }))
);
const FeedHealthWorkspace = lazy(() =>
  import("./feed-health-workspace").then((m) => ({ default: m.FeedHealthWorkspace }))
);

type HubTab = "supply-chain" | "audit" | "policy" | "feed-health";

const hubTabs: Array<{ value: HubTab; label: string }> = [
  { value: "supply-chain", label: "Supply Chain" },
  { value: "audit", label: "Audit" },
  { value: "policy", label: "Policy" },
  { value: "feed-health", label: "Feed Health" },
];

export function hubTitleForTab(tab: HubTab): string {
  return hubTabs.find((item) => item.value === tab)?.label ?? "Supply Chain";
}

function viewToTab(view: string): HubTab {
  if (view === "supply-chain" || view === "audit" || view === "policy" || view === "feed-health") {
    return view;
  }
  return "supply-chain";
}

export function SupplyChainHubWorkspace(props: {
  activeView: string;
	  snapshot: GuardRuntimeSnapshot;
	  receipts: GuardReceipt[];
	  policies: GuardPolicyDecision[];
	  approvalGate: GuardApprovalGatePublicConfig | null;
	  onClearPolicy: (policy: GuardPolicyDecision) => void;
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
    [props.onNavigate]
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="space-y-1">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Trust Center</p>
          <h1 className="text-2xl font-semibold tracking-tight text-brand-dark">{hubTitleForTab(tab)}</h1>
        </div>
        <TabBar tabs={hubTabs} active={tab} onChange={handleTabChange} />
      </div>
      <Suspense fallback={<LazyFallback />}>
        {tab === "supply-chain" && (
          <SupplyChainWorkspace
            snapshot={props.snapshot}
            approvalGate={props.approvalGate}
            onGoHome={props.onGoHome}
            onRuntimeRefresh={props.onRuntimeRefresh}
          />
	        )}
	        {tab === "audit" && (
	          <AuditWorkspace snapshot={props.snapshot} receipts={props.receipts} approvalGate={props.approvalGate} />
	        )}
        {tab === "policy" && (
          <PolicyWorkspace
            policies={props.policies}
            snapshot={props.snapshot}
            onClearPolicy={props.onClearPolicy}
            onOpenSettings={props.onOpenSettings}
          />
        )}
        {tab === "feed-health" && (
          <FeedHealthWorkspace snapshot={props.snapshot} onOpenSettings={props.onOpenSettings} />
        )}
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
