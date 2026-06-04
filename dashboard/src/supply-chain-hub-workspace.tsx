import { lazy, Suspense, useCallback, useEffect, useState } from "react";
import { TabBar } from "./approval-center-primitives";
import type { GuardPolicyDecision, GuardReceipt, GuardRuntimeSnapshot } from "./guard-types";

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
  onClearPolicy: (policy: GuardPolicyDecision) => void;
  onOpenSettings: () => void;
  onGoHome: () => void;
  onNavigate: (pathname: string) => void;
}) {
  const [tab, setTab] = useState<HubTab>(viewToTab(props.activeView));

  useEffect(() => {
    setTab(viewToTab(props.activeView));
  }, [props.activeView]);

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
        <h1 className="text-2xl font-semibold tracking-tight text-brand-dark">Trust Center</h1>
        <TabBar tabs={hubTabs} active={tab} onChange={handleTabChange} />
      </div>
      <Suspense fallback={<LazyFallback />}>
        {tab === "supply-chain" && (
          <SupplyChainWorkspace snapshot={props.snapshot} onGoHome={props.onGoHome} />
        )}
        {tab === "audit" && (
          <AuditWorkspace snapshot={props.snapshot} receipts={props.receipts} />
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
