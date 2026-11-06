import { useMemo, useCallback, type ReactNode } from "react";
import {
  HiMiniExclamationTriangle,
  HiMiniBugAnt,
  HiMiniArrowTopRightOnSquare,
} from "react-icons/hi2";
import { Badge } from "./approval-center-primitives";
import type { GuardRuntimeSnapshot, SupplyChainBundleAdvisory } from "./guard-types";
import { SupplyChainDetailSection } from "./supply-chain-detail-section";
import { formatBundleExpiry, isBundleExpired, missingBundleMessage } from "./supply-chain-intel-freshness";
import { useSupplyChainBundle } from "./use-supply-chain-bundle";

function SeverityBadge({ severity }: { severity: string }) {
  const tone =
    severity === "critical" || severity === "high"
      ? "destructive"
      : severity === "medium"
      ? "attention"
      : "default";
  return <Badge tone={tone}>{severity}</Badge>;
}

function AdvisoryRow({ advisory }: { advisory: SupplyChainBundleAdvisory }) {
  return (
    <li className="flex items-start gap-3 py-3">
      <div className="mt-0.5 shrink-0">
        {advisory.knownExploited ? (
          <HiMiniExclamationTriangle className="h-4 w-4 text-red-500" aria-hidden="true" />
        ) : (
          <HiMiniBugAnt className="h-4 w-4 text-slate-400" aria-hidden="true" />
        )}
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium text-brand-dark">{advisory.advisoryId}</span>
          <SeverityBadge severity={advisory.normalizedSeverity} />
          {advisory.knownExploited && (
            <Badge tone="destructive">Known exploited</Badge>
          )}
        </div>
        <p className="mt-0.5 text-sm text-slate-600">{advisory.title}</p>
        {advisory.summary && (
          <p className="mt-1 text-xs text-slate-500 line-clamp-2">{advisory.summary}</p>
        )}
        {advisory.recommendedFixVersion && (
          <p className="mt-1 text-xs text-brand-green">
            Fix: {advisory.recommendedFixVersion}
          </p>
        )}
      </div>
    </li>
  );
}

const SEVERITY_LEVELS = ["critical", "high", "medium", "low"] as const;

const SEVERITY_TEXT_CLASS: Record<(typeof SEVERITY_LEVELS)[number], string> = {
  critical: "text-brand-purple",
  high: "text-brand-purple",
  medium: "text-brand-attention-text",
  low: "text-brand-dark",
};

function IntelSection({ action, children }: { action?: ReactNode; children: ReactNode }) {
  return (
    <SupplyChainDetailSection
      id="supply-chain-intel-heading"
      title="Supply chain intel"
      lead="The signed advisory feed Guard checks each install against."
      action={action}
    >
      {children}
    </SupplyChainDetailSection>
  );
}

export function SupplyChainBundlePanel({
  refreshKey = "",
  cloudState,
}: {
  refreshKey?: string;
  cloudState: GuardRuntimeSnapshot["cloud_state"];
}) {
  const load = useSupplyChainBundle(refreshKey);
  const bundle = load.phase === "ready" ? load.bundle : null;
  const loading = load.phase === "loading";
  const error = load.phase === "error" ? load.message : null;

  const severityCounts = useMemo(() => {
    if (!bundle) return null;
    const counts: Record<string, number> = {};
    for (const a of bundle.advisories) {
      counts[a.normalizedSeverity] = (counts[a.normalizedSeverity] ?? 0) + 1;
    }
    return counts;
  }, [bundle]);

  const topAdvisories = useMemo(() => {
    if (!bundle) return [];
    const severityOrder: Record<string, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      unknown: 4,
    };
    return [...bundle.advisories]
      .sort((a, b) => {
        const sevA = severityOrder[a.normalizedSeverity] ?? 99;
        const sevB = severityOrder[b.normalizedSeverity] ?? 99;
        if (sevA !== sevB) return sevA - sevB;
        return b.confidence - a.confidence;
      })
      .slice(0, 10);
  }, [bundle]);

  const handleOpenCloud = useCallback(() => {
    window.open("https://hol.org/guard", "_blank", "noopener,noreferrer");
  }, []);

  if (loading) {
    return (
      <IntelSection>
        <div className="space-y-2 py-1" aria-hidden="true">
          <div className="guard-skeleton h-4 w-48" />
          <div className="guard-skeleton h-4 w-40" />
        </div>
      </IntelSection>
    );
  }

  if (error) {
    return (
      <IntelSection>
        <p className="text-sm text-slate-600">
          <span className="font-medium text-brand-dark">Could not load intel.</span> {error}
        </p>
      </IntelSection>
    );
  }

  if (!bundle) {
    return (
      <IntelSection>
        <p className="text-sm text-slate-600">
          <span className="font-medium text-brand-dark">No intel available.</span>{" "}
          {missingBundleMessage(cloudState)}
        </p>
      </IntelSection>
    );
  }

  const nowMs = Date.now();
  const expiry = bundle.expiresAt ? formatBundleExpiry(bundle.expiresAt, nowMs) : null;
  const expired = isBundleExpired(bundle, nowMs);

  return (
    <IntelSection
      action={
        <button
          type="button"
          onClick={handleOpenCloud}
          className="inline-flex items-center gap-1 rounded text-xs font-medium text-brand-blue hover:text-brand-blue-dark focus:outline-none focus:ring-2 focus:ring-brand-blue/30"
        >
          View in cloud
          <HiMiniArrowTopRightOnSquare className="h-3 w-3" aria-hidden="true" />
        </button>
      }
    >
      <dl className="flex flex-wrap gap-x-8 gap-y-2 text-sm">
        <div className="flex items-baseline gap-2">
          <dt className="text-slate-600">Bundle</dt>
          <dd className="font-mono font-medium text-brand-dark">{bundle.bundleVersion}</dd>
        </div>
        <div className="flex items-baseline gap-2">
          <dt className="text-slate-600">Advisories</dt>
          <dd className="font-medium tabular-nums text-brand-dark">{bundle.advisories.length}</dd>
        </div>
        <div className="flex items-baseline gap-2">
          <dt className="text-slate-600">Packages</dt>
          <dd className="font-medium tabular-nums text-brand-dark">{bundle.packages.length}</dd>
        </div>
        {expiry !== null && (
          <div className="flex items-baseline gap-2">
            <dt className="text-slate-600">{expired ? "Expired" : "Expires"}</dt>
            <dd className={`font-medium ${expired ? "text-brand-attention-text" : "text-brand-dark"}`}>{expiry}</dd>
          </div>
        )}
      </dl>

      {severityCounts && Object.keys(severityCounts).length > 0 && (
        <ul className="mt-3 flex flex-wrap gap-x-6 gap-y-1 text-sm" aria-label="Advisories by severity">
          {SEVERITY_LEVELS.map((sev) => (
            <li key={sev} className="flex items-baseline gap-1.5">
              <span className={`font-semibold tabular-nums ${SEVERITY_TEXT_CLASS[sev]}`}>
                {severityCounts[sev] ?? 0}
              </span>
              <span className="text-slate-600">{sev}</span>
            </li>
          ))}
        </ul>
      )}

      {topAdvisories.length > 0 && (
        <div className="mt-4">
          <h4 className="text-xs font-medium text-slate-600">Top advisories by severity and confidence</h4>
          <ul className="mt-1 divide-y divide-slate-100">
            {topAdvisories.map((advisory) => (
              <AdvisoryRow key={advisory.advisoryId} advisory={advisory} />
            ))}
          </ul>
          {bundle.advisories.length > 10 && (
            <button
              type="button"
              onClick={handleOpenCloud}
              className="mt-1 rounded text-xs font-medium text-brand-blue hover:text-brand-blue-dark focus:outline-none focus:ring-2 focus:ring-brand-blue/30"
            >
              View all {bundle.advisories.length} advisories in Guard Cloud
            </button>
          )}
        </div>
      )}
    </IntelSection>
  );
}
