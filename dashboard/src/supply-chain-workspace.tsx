import { useMemo, useState, useCallback, useEffect, useRef } from "react";
import {
  HiMiniExclamationTriangle,
  HiMiniCheckCircle,
  HiMiniXCircle,
  HiMiniArrowPath,
  HiMiniChevronDown,
  HiMiniChevronUp,
} from "react-icons/hi2";
import { SectionLabel, Badge, Tag, ActionButton, EmptyState } from "./approval-center-primitives";
import { harnessDisplayName, formatRelativeTime } from "./approval-center-utils";
import type {
  GuardApprovalGatePublicConfig,
  GuardManagedInstall,
  GuardRuntimeSnapshot,
  PackageManagerProtection,
  SupplyChainAuditSnapshot,
} from "./guard-types";
import { derivePackageWorkbenchFromReceipts, fetchReceipts, normalizeSupplyChainAuditSnapshot } from "./guard-api";
import { PackageFirewallPanel, type PackageFirewallPanelHandle } from "./supply-chain-firewall-panel";
import { PackageWorkbenchPanel } from "./package-workbench-panel";
import { SupplyChainBundlePanel } from "./supply-chain-bundle-panel";
import {
  deriveSupplyChainEvidenceRail,
  type SupplyChainEvidenceRailSnapshot,
} from "./supply-chain-evidence-rail";
import {
  SupplyChainEvidenceRail,
} from "./supply-chain-evidence-rail-panel";
import { resolveSupplyChainCloudCapabilities } from "./supply-chain-cloud-capabilities";
import { SupplyChainCloudCapabilitiesPanel } from "./supply-chain-cloud-capabilities-panel";
import { SupplyChainAuditFindingsSummary } from "./supply-chain-audit-findings-summary";
import { resolveSupplyChainIssues, type SupplyChainIssueAction } from "./supply-chain-issues";
import { SupplyChainIssueFocus } from "./supply-chain-issue-focus";
import { resolveSupplyChainWorkspaceHero } from "./supply-chain-workspace-hero-state";
import { SupplyChainWorkspaceHero } from "./supply-chain-workspace-hero";
import { SUPPLY_CHAIN_WORKSPACE_SHELL_CLASS } from "./supply-chain-workspace-layout";

export { buildSupplyChainStats } from "./supply-chain-protection-stats";

type AppFirewallRowProps = {
  install: GuardManagedInstall;
  protection: PackageManagerProtection | undefined;
};

function AppFirewallRow({ install, protection }: AppFirewallRowProps) {
  const [open, setOpen] = useState(false);
  const toggle = useCallback(() => setOpen((p) => !p), []);
  const protectedManagers = protection?.protected_managers ?? [];

  return (
    <div className="border-b border-slate-100 last:border-b-0">
      <button
        type="button"
        onClick={toggle}
        aria-expanded={open}
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left hover:bg-slate-50/60 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-brand-blue/30"
      >
        <div className="flex min-w-0 items-center gap-2.5">
          {install.active ? (
            <HiMiniCheckCircle className="h-4 w-4 shrink-0 text-brand-green" aria-hidden="true" />
          ) : (
            <HiMiniXCircle className="h-4 w-4 shrink-0 text-brand-attention" aria-hidden="true" />
          )}
          <span className="text-sm font-medium text-brand-dark">
            {harnessDisplayName(install.harness)}
          </span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Badge tone={install.active ? "success" : "attention"}>
            {install.active ? "Active" : "Inactive"}
          </Badge>
          {open ? (
            <HiMiniChevronUp className="h-4 w-4 text-slate-400" aria-hidden="true" />
          ) : (
            <HiMiniChevronDown className="h-4 w-4 text-slate-400" aria-hidden="true" />
          )}
        </div>
      </button>
      {open && (
        <div className="px-4 pb-3 pt-1">
          <p className="text-xs font-semibold uppercase tracking-[0.15em] text-slate-400 mb-2">
            Shim coverage
          </p>
          {protectedManagers.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {protectedManagers.map((mgr) => (
                <span
                  key={mgr}
                  className="inline-flex items-center gap-1 rounded-full border border-brand-green/25 bg-brand-green/[0.06] px-2.5 py-0.5 text-xs font-medium text-brand-green-text"
                >
                  <HiMiniCheckCircle className="h-3 w-3" aria-hidden="true" />
                  {mgr}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-xs text-slate-500">No package manager shims active for this app.</p>
          )}
          {install.updated_at && (
            <p className="mt-2 text-xs text-slate-400">
              Updated {formatRelativeTime(install.updated_at)}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

type SupplyChainWorkspaceProps = {
  snapshot: GuardRuntimeSnapshot;
  approvalGate: GuardApprovalGatePublicConfig | null;
  onGoHome: () => void;
  onRuntimeRefresh?: () => Promise<void> | void;
};

export function SupplyChainWorkspace({
  snapshot,
  approvalGate,
  onGoHome,
  onRuntimeRefresh,
}: SupplyChainWorkspaceProps) {
  const protection = snapshot.supply_chain?.package_manager_protection;
  const managedInstalls = useMemo(
    () => snapshot.managed_installs ?? [],
    [snapshot.managed_installs],
  );
  const [auditSnapshot, setAuditSnapshot] = useState<SupplyChainAuditSnapshot | null>(null);
  const [evidenceRail, setEvidenceRail] = useState<SupplyChainEvidenceRailSnapshot | null>(null);
  const [auditRunning, setAuditRunning] = useState(false);
  const runAuditRef = useRef<(() => void) | null>(null);
  const firewallPanelRef = useRef<PackageFirewallPanelHandle>(null);
  const [issueActionPending, setIssueActionPending] = useState(false);

  const handleIssueAction = useCallback(
    async (action: SupplyChainIssueAction) => {
      const panel = firewallPanelRef.current;
      if (panel === null) {
        return;
      }
      if (action.kind === "firewall_unprotected") {
        panel.focusUnprotected();
        panel.scrollIntoView();
        return;
      }
      if (action.kind === "firewall_repair") {
        panel.focusActionable();
        panel.scrollIntoView();
        return;
      }
      if (action.kind === "firewall_audit") {
        panel.runAudit();
        panel.scrollIntoView();
        return;
      }

      setIssueActionPending(true);
      try {
        if (action.kind === "connect") {
          await panel.startConnect();
          await onRuntimeRefresh?.();
          return;
        }
        if (action.kind === "open_shell") {
          await panel.openShell();
        }
      } finally {
        setIssueActionPending(false);
      }
    },
    [onRuntimeRefresh],
  );


  const supplyChainIssues = useMemo(() => resolveSupplyChainIssues(snapshot), [snapshot]);
  const workspaceHero = useMemo(
    () => resolveSupplyChainWorkspaceHero(snapshot, { openIssueCount: supplyChainIssues.length }),
    [snapshot, supplyChainIssues.length],
  );
  const cloudCapabilities = useMemo(
    () => resolveSupplyChainCloudCapabilities(snapshot),
    [snapshot],
  );

  useEffect(() => {
    let cancelled = false;
    const loadReceiptEvidence = async () => {
      try {
        const receipts = await fetchReceipts();
        if (cancelled) {
          return;
        }
        setAuditSnapshot(derivePackageWorkbenchFromReceipts(receipts));
        setEvidenceRail(deriveSupplyChainEvidenceRail(receipts));
      } catch {
        if (!cancelled) {
          setAuditSnapshot(null);
          setEvidenceRail(null);
        }
      }
    };
    void loadReceiptEvidence();
    return () => {
      cancelled = true;
    };
  }, [snapshot.generated_at, snapshot.receipt_count]);

  const handleAuditCompleted = useCallback((resultDetail: Record<string, unknown>) => {
    const normalized = normalizeSupplyChainAuditSnapshot(resultDetail);
    setAuditSnapshot(normalized);
  }, []);

  const handleAuditRunningChange = useCallback((running: boolean) => {
    setAuditRunning(running);
  }, []);

  const handleRunAudit = useCallback(() => {
    runAuditRef.current?.();
  }, []);

  return (
    <div className={SUPPLY_CHAIN_WORKSPACE_SHELL_CLASS} data-testid="supply-chain-workspace">
      <div className="flex flex-wrap items-start justify-end gap-3">
        <ActionButton variant="ghost" onClick={onGoHome}>
          Back to Home
        </ActionButton>
      </div>

      <SupplyChainWorkspaceHero hero={workspaceHero} compact={supplyChainIssues.length > 0} />

      <SupplyChainIssueFocus
        issues={supplyChainIssues}
        onIssueAction={(action) => {
          void handleIssueAction(action);
        }}
        actionPending={issueActionPending}
      />

      {supplyChainIssues.length === 0 ? (
        <SupplyChainCloudCapabilitiesPanel state={cloudCapabilities} />
      ) : null}

      {evidenceRail !== null ? <SupplyChainEvidenceRail rail={evidenceRail} /> : null}

      <SupplyChainAuditFindingsSummary
        auditSnapshot={auditSnapshot}
        auditRunning={auditRunning}
        onRunAudit={handleRunAudit}
      />

      <SupplyChainBundlePanel />

      <PackageFirewallPanel
        ref={firewallPanelRef}
        approvalGate={approvalGate}
        onStateChanged={onRuntimeRefresh}
        onAuditCompleted={handleAuditCompleted}
        onAuditRunningChange={handleAuditRunningChange}
        runAuditRef={runAuditRef}
      />

      <PackageWorkbenchPanel
        auditSnapshot={auditSnapshot}
        onRunAudit={handleRunAudit}
        auditRunning={auditRunning}
      />

      <div className="rounded-2xl border border-slate-100 bg-white shadow-sm">
        <div className="border-b border-slate-100 px-4 py-3">
          <SectionLabel>Connected apps</SectionLabel>
          <p className="mt-1 text-sm leading-relaxed text-slate-500">
            Which package tools Guard is watching inside each connected app.
          </p>
        </div>
        {managedInstalls.length === 0 ? (
          <EmptyState
            title="No apps connected"
            body="Connect an AI app to see per-app package manager coverage here."
            tone="teach"
          />
        ) : (
          <div>
            {managedInstalls.map((install) => (
              <AppFirewallRow
                key={`${install.harness}-${install.workspace ?? "global"}`}
                install={install}
                protection={protection}
              />
            ))}
          </div>
        )}
      </div>

      <div className="rounded-2xl border border-slate-100 bg-white shadow-sm">
        <div className="border-b border-slate-100 px-4 py-3">
          <SectionLabel>Safety check source</SectionLabel>
          <p className="mt-1 text-sm leading-relaxed text-slate-500">
            Whether this device uses sample data or live Guard Cloud updates.
          </p>
        </div>
        <FeedHealthPanel snapshot={snapshot} hideLocalOnlyWarning={supplyChainIssues.some((issue) => issue.id === "cloud_connect")} />
      </div>
    </div>
  );
}

function FeedHealthPanel({ snapshot, hideLocalOnlyWarning = false }: { snapshot: GuardRuntimeSnapshot; hideLocalOnlyWarning?: boolean }) {
  const cloudState = snapshot.cloud_state;
  const isSample = cloudState === "local_only";
  const isStale =
    snapshot.latest_receipts.length > 0 &&
    Date.now() - new Date(snapshot.latest_receipts[0].timestamp).getTime() > 7 * 24 * 60 * 60 * 1000;

  return (
    <div className="px-4 py-4 space-y-3">
      <div className="flex flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-[0.15em]">
            Data source
          </span>
          <Tag tone={isSample ? "attention" : "green"}>
            {isSample ? "On this device only" : "Live from Guard Cloud"}
          </Tag>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-[0.15em]">
            Last update
          </span>
          <Tag tone={isStale ? "attention" : "green"}>
            {isStale ? "Older than 7 days" : "Recent"}
          </Tag>
        </div>
      </div>
      {isSample && !hideLocalOnlyWarning && (
        <div className="flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50/60 px-3 py-2.5">
          <HiMiniExclamationTriangle
            className="mt-0.5 h-4 w-4 shrink-0 text-amber-600"
            aria-hidden="true"
          />
          <p className="text-xs leading-relaxed text-amber-800">
            This device is using sample safety data. Connect Guard Cloud for live package warnings and
            protection across your machines.
          </p>
        </div>
      )}
      {isStale && !isSample && (
        <div className="flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50/60 px-3 py-2.5">
          <HiMiniArrowPath
            className="mt-0.5 h-4 w-4 shrink-0 text-amber-600"
            aria-hidden="true"
          />
          <p className="text-xs leading-relaxed text-amber-800">
            Safety checks have not refreshed recently. Make sure Guard is running, then sync policy or
            run an audit.
          </p>
        </div>
      )}
    </div>
  );
}
