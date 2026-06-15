import { lazy, Suspense, useCallback, useMemo, useRef } from "react";
import type { GuardApprovalGatePublicConfig, GuardPolicyDecision, GuardReceipt, GuardRuntimeSnapshot } from "./guard-types";
import { WorkspacePageHeader } from "./workspace-page-header";
import { SUPPLY_CHAIN_WORKSPACE_SHELL_CLASS } from "./supply-chain-workspace-layout";
import { PackageFirewallPanel, type PackageFirewallPanelHandle } from "./supply-chain-firewall-panel";
import { useSupplyChainAuditSession } from "./use-supply-chain-audit-session";
import { resolveSupplyChainAuditWorkspaceDir } from "./supply-chain-audit-workspace";

const SupplyChainWorkspace = lazy(() =>
  import("./supply-chain-workspace").then((m) => ({ default: m.SupplyChainWorkspace }))
);
const AuditWorkspace = lazy(() =>
  import("./audit-workspace").then((m) => ({ default: m.AuditWorkspace }))
);
const FeedHealthWorkspace = lazy(() =>
  import("./feed-health-workspace").then((m) => ({ default: m.FeedHealthWorkspace }))
);

type HubTab = "supply-chain" | "audit" | "feed-health";

const hubTabs: Array<{ value: HubTab; label: string }> = [
  { value: "supply-chain", label: "Supply Chain" },
  { value: "audit", label: "Audit" },
  { value: "feed-health", label: "Feed Health" },
];

export function hubTitleForTab(tab: HubTab): string {
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
  policies: GuardPolicyDecision[];
  approvalGate: GuardApprovalGatePublicConfig | null;
  onClearPolicy: (policy: GuardPolicyDecision) => void;
  onOpenSettings: () => void;
  onGoHome: () => void;
  onNavigate: (pathname: string) => void;
  onRuntimeRefresh?: () => Promise<void> | void;
}) {
  const tab = viewToTab(props.activeView);
  const firewallPanelRef = useRef<PackageFirewallPanelHandle>(null);
  const auditSession = useSupplyChainAuditSession({
    snapshot: props.snapshot,
    onNavigate: props.onNavigate,
  });

  const auditWorkspaceDir = useMemo(
    () => resolveSupplyChainAuditWorkspaceDir(props.snapshot.managed_installs ?? []),
    [props.snapshot.managed_installs],
  );

  const handleTabChange = useCallback(
    (value: HubTab) => {
      const path = value === "supply-chain" ? "/supply-chain" : `/${value}`;
      props.onNavigate(path);
    },
    [props.onNavigate]
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
        {tab === "supply-chain" && (
          <SupplyChainWorkspace
            snapshot={props.snapshot}
            onGoHome={props.onGoHome}
            onRuntimeRefresh={props.onRuntimeRefresh}
            firewallPanelRef={firewallPanelRef}
            onAuditNavigate={() => props.onNavigate("/audit")}
            auditSnapshot={auditSession.auditSnapshot}
            auditRunning={auditSession.auditRunning}
          />
        )}
        {tab === "audit" && (
          <AuditWorkspace
            snapshot={props.snapshot}
            receipts={props.receipts}
            approvalGate={props.approvalGate}
            auditSession={auditSession}
          />
        )}
        {tab === "feed-health" && (
          <FeedHealthWorkspace snapshot={props.snapshot} onOpenSettings={props.onOpenSettings} />
        )}
      </Suspense>
      <div className={tab === "supply-chain" ? undefined : "hidden"} aria-hidden={tab !== "supply-chain"}>
        <PackageFirewallPanel
          ref={firewallPanelRef}
          approvalGate={props.approvalGate}
          auditWorkspaceDir={auditWorkspaceDir}
          onAuditConnectGateChange={auditSession.setAuditConnectGate}
          onAuditErrorChange={auditSession.handleAuditErrorChange}
          onStateChanged={props.onRuntimeRefresh}
          onAuditStarted={auditSession.handleAuditStarted}
          onAuditCompleted={auditSession.handleAuditCompleted}
          onAuditRunningChange={auditSession.handleAuditRunningChange}
          runAuditRef={auditSession.runAuditRef}
        />
      </div>
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
