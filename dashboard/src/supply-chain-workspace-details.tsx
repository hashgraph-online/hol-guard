import { useMemo, useState, useCallback, useEffect } from "react";
import {
  HiMiniExclamationTriangle,
  HiMiniCheckCircle,
  HiMiniXCircle,
  HiMiniArrowPath,
  HiMiniChevronDown,
  HiMiniChevronUp,
  HiMiniBugAnt,
} from "react-icons/hi2";
import { Badge, Tag, ActionButton } from "./approval-center-primitives";
import { harnessDisplayName, formatRelativeTime } from "./approval-center-utils";
import type {
  GuardManagedInstall,
  GuardRuntimeSnapshot,
  PackageManagerProtection,
  SupplyChainAuditSnapshot,
} from "./guard-types";
import { fetchReceipts } from "./guard-api";
import { SupplyChainBundlePanel } from "./supply-chain-bundle-panel";
import { bundleRefreshKey, resolveIntelFreshness } from "./supply-chain-intel-freshness";
import { useSupplyChainBundle } from "./use-supply-chain-bundle";
import {
  deriveSupplyChainEvidenceRail,
  type SupplyChainEvidenceRailSnapshot,
} from "./supply-chain-evidence-rail";
import { SupplyChainEvidenceRail, SupplyChainEvidenceRailPlaceholder } from "./supply-chain-evidence-rail-panel";
import { resolveSupplyChainCloudCapabilities } from "./supply-chain-cloud-capabilities";
import { SupplyChainCloudCapabilitiesPanel } from "./supply-chain-cloud-capabilities-panel";
import { resolveSupplyChainIssues } from "./supply-chain-issues";
import { SupplyChainDetailSection } from "./supply-chain-detail-section";

// The details below the roster live in their own module, so the status line
// above the roster loads without waiting for them. The page's design contract
// is in supply-chain-workspace.tsx.

type AppFirewallRowProps = {
  install: GuardManagedInstall;
  protection: PackageManagerProtection | undefined;
};

function AppFirewallRow({ install, protection }: AppFirewallRowProps) {
  const [open, setOpen] = useState(false);
  const toggle = useCallback(() => setOpen((p) => !p), []);
  const protectedManagers = protection?.protected_managers ?? [];

  return (
    <div>
      <button
        type="button"
        onClick={toggle}
        aria-expanded={open}
        className="flex w-full items-center justify-between gap-3 py-2.5 text-left hover:bg-slate-50/60 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-brand-blue/30"
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
        <div className="pb-3 pt-1">
          <p className="mb-2 text-xs font-medium text-slate-600">Shim coverage</p>
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

type SupplyChainAuditTeaserProps = {
  auditSnapshot: SupplyChainAuditSnapshot | null;
  auditRunning: boolean;
  onOpenAudit: () => void;
};

function auditTeaserBody(
  auditRunning: boolean,
  auditSnapshot: SupplyChainAuditSnapshot | null,
): string {
  if (auditRunning) {
    return "Audit is running on the Audit tab.";
  }
  if (auditSnapshot !== null) {
    const packageLabel = auditSnapshot.findings.length === 1 ? "package" : "packages";
    return `${auditSnapshot.findings.length} ${packageLabel} need review across ${auditSnapshot.inventory.totalPackages} indexed.`;
  }
  return "Run an audit to index dependencies and surface packages that need review.";
}

function SupplyChainAuditTeaser({ auditSnapshot, auditRunning, onOpenAudit }: SupplyChainAuditTeaserProps) {
  const handleOpenAudit = useCallback(() => {
    onOpenAudit();
  }, [onOpenAudit]);
  const teaserBody = auditTeaserBody(auditRunning, auditSnapshot);

  return (
    <SupplyChainDetailSection
      id="supply-chain-audit-heading"
      title="Workspace audit"
      lead="Index a project's dependencies and flag the packages that need review."
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-brand-dark">{teaserBody}</p>
        <ActionButton variant="outline" onClick={handleOpenAudit}>
          <HiMiniBugAnt className="mr-1.5 h-4 w-4" aria-hidden="true" />
          Open Audit tab
        </ActionButton>
      </div>
    </SupplyChainDetailSection>
  );
}

type SupplyChainWorkspaceDetailsProps = {
  snapshot: GuardRuntimeSnapshot;
  onGoHome: () => void;
  onAuditNavigate: () => void;
  auditSnapshot: SupplyChainAuditSnapshot | null;
  auditRunning: boolean;
};

/** The facts behind the roster, below it, as ruled sections. */
export function SupplyChainWorkspaceDetails({
  snapshot,
  onGoHome,
  onAuditNavigate,
  auditSnapshot,
  auditRunning,
}: SupplyChainWorkspaceDetailsProps) {
  const protection = snapshot.supply_chain?.package_manager_protection;
  const managedInstalls = useMemo(
    () => snapshot.managed_installs ?? [],
    [snapshot.managed_installs],
  );
  // undefined while receipts load, null when they could not be read.
  const [evidenceRail, setEvidenceRail] = useState<SupplyChainEvidenceRailSnapshot | null | undefined>(undefined);
  const supplyChainIssues = useMemo(() => resolveSupplyChainIssues(snapshot), [snapshot]);
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
        setEvidenceRail(deriveSupplyChainEvidenceRail(receipts));
      } catch {
        if (!cancelled) {
          setEvidenceRail(null);
        }
      }
    };
    void loadReceiptEvidence();
    return () => {
      cancelled = true;
    };
  }, [snapshot.generated_at, snapshot.receipt_count]);

  return (
    <div data-testid="supply-chain-workspace">
      <h2 className="text-lg font-semibold tracking-tight text-brand-dark">Activity and sources</h2>
      <div className="mt-2 divide-y divide-slate-200 border-y border-slate-200">
        {evidenceRail === undefined ? (
          <SupplyChainEvidenceRailPlaceholder />
        ) : evidenceRail !== null ? (
          <SupplyChainEvidenceRail rail={evidenceRail} />
        ) : null}

        <SupplyChainAuditTeaser
          auditSnapshot={auditSnapshot}
          auditRunning={auditRunning}
          onOpenAudit={onAuditNavigate}
        />

        <SupplyChainBundlePanel refreshKey={bundleRefreshKey(snapshot)} cloudState={snapshot.cloud_state} />

        <SupplyChainDetailSection
          id="supply-chain-apps-heading"
          title="Connected apps"
          lead="Which package tools Guard is watching inside each connected app."
        >
          {managedInstalls.length === 0 ? (
            <p className="text-sm text-slate-600">
              <span className="font-medium text-brand-dark">No apps connected.</span> Connect an AI app to see
              per-app package manager coverage here.
            </p>
          ) : (
            <div className="divide-y divide-slate-100">
              {managedInstalls.map((install) => (
                <AppFirewallRow
                  key={`${install.harness}-${install.workspace ?? "global"}`}
                  install={install}
                  protection={protection}
                />
              ))}
            </div>
          )}
        </SupplyChainDetailSection>

        <SupplyChainDetailSection
          id="supply-chain-source-heading"
          title="Safety check source"
          lead="Whether this device uses sample data or live Guard Cloud updates."
        >
          <FeedHealthPanel
            snapshot={snapshot}
            hideLocalOnlyWarning={supplyChainIssues.some((issue) => issue.id === "cloud_connect")}
          />
        </SupplyChainDetailSection>

        {supplyChainIssues.length === 0 ? (
          <SupplyChainCloudCapabilitiesPanel state={cloudCapabilities} />
        ) : null}
      </div>

      {/* Pulled left so the label lines up with the content edge. */}
      <div className="mt-4 -ml-3 sm:-ml-4">
        <ActionButton variant="ghost" onClick={onGoHome}>
          Back to Home
        </ActionButton>
      </div>
    </div>
  );
}

function FeedHealthPanel({ snapshot, hideLocalOnlyWarning = false }: { snapshot: GuardRuntimeSnapshot; hideLocalOnlyWarning?: boolean }) {
  const cloudState = snapshot.cloud_state;
  const isSample = cloudState === "local_only";
  const bundleLoad = useSupplyChainBundle(bundleRefreshKey(snapshot));
  const freshness = resolveIntelFreshness({ cloudState, load: bundleLoad, nowMs: Date.now() });
  const needsRefresh = freshness.kind === "none" || freshness.kind === "expired";
  const generatedAt =
    freshness.kind === "current" && bundleLoad.phase === "ready" ? bundleLoad.bundle?.generatedAt : undefined;
  const updateLabel = generatedAt ? `Updated ${formatRelativeTime(generatedAt)}` : freshness.label;
  const sourceLabel = isSample
    ? "On this device only"
    : cloudState === "paired_waiting"
      ? "Guard Cloud connected, syncing"
      : "Live from Guard Cloud";
  const sourceTone = isSample ? "attention" : cloudState === "paired_waiting" ? "blue" : "green";

  return (
    <div className="space-y-3">
      <dl className="flex flex-wrap gap-x-8 gap-y-2">
        <div className="flex items-center gap-2">
          <dt className="text-sm text-slate-600">Data source</dt>
          <dd>
            <Tag tone={sourceTone}>{sourceLabel}</Tag>
          </dd>
        </div>
        <div className="flex items-center gap-2">
          <dt className="text-sm text-slate-600">Last update</dt>
          <dd>
            <Tag tone={freshness.tone}>{updateLabel}</Tag>
          </dd>
        </div>
      </dl>
      {isSample && !hideLocalOnlyWarning && (
        <p className="flex items-start gap-2 text-sm leading-6 text-slate-600">
          <HiMiniExclamationTriangle
            className="mt-1 h-4 w-4 shrink-0 text-brand-attention"
            aria-hidden="true"
          />
          This device is using sample safety data. Connect Guard Cloud for live package warnings and
          protection across your machines.
        </p>
      )}
      {needsRefresh && !isSample && (
        <p className="flex items-start gap-2 text-sm leading-6 text-slate-600">
          <HiMiniArrowPath
            className="mt-1 h-4 w-4 shrink-0 text-brand-attention"
            aria-hidden="true"
          />
          {freshness.description}
        </p>
      )}
    </div>
  );
}
