import { useState, useEffect, useMemo, useCallback } from "react";
import {
  HiMiniExclamationTriangle,
  HiMiniBugAnt,
  HiMiniArrowTopRightOnSquare,
} from "react-icons/hi2";
import { SectionLabel, Badge, Tag, EmptyState } from "./approval-center-primitives";
import { formatRelativeTime } from "./approval-center-utils";
import { fetchSupplyChainBundle } from "./guard-api";
import type { SupplyChainBundle, SupplyChainBundleAdvisory } from "./guard-types";

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
    <div className="flex items-start gap-3 px-4 py-3 border-b border-slate-100 last:border-b-0 hover:bg-slate-50/40 transition-colors">
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
    </div>
  );
}

export function SupplyChainBundlePanel() {
  const [bundle, setBundle] = useState<SupplyChainBundle | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    fetchSupplyChainBundle()
      .then((data) => {
        if (cancelled) return;
        setBundle(data);
        setError(null);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "Failed to load");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

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
      <div className="rounded-2xl border border-slate-100 bg-white shadow-sm">
        <div className="border-b border-slate-100 px-4 py-3">
          <SectionLabel>Supply chain intel</SectionLabel>
        </div>
        <div className="px-4 py-8">
          <div className="guard-skeleton h-4 w-32 mb-3" />
          <div className="guard-skeleton h-4 w-48 mb-2" />
          <div className="guard-skeleton h-4 w-40" />
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-2xl border border-slate-100 bg-white shadow-sm">
        <div className="border-b border-slate-100 px-4 py-3">
          <SectionLabel>Supply chain intel</SectionLabel>
        </div>
        <div className="px-4 py-6">
          <EmptyState
            title="Could not load intel"
            body={error}
          />
        </div>
      </div>
    );
  }

  if (!bundle) {
    return (
      <div className="rounded-2xl border border-slate-100 bg-white shadow-sm">
        <div className="border-b border-slate-100 px-4 py-3">
          <SectionLabel>Supply chain intel</SectionLabel>
        </div>
        <div className="px-4 py-6">
          <EmptyState
            title="No intel available"
            body="Guard has not synced a supply chain bundle yet. Connect to Guard Cloud for live advisory data."
            tone="teach"
          />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Bundle metadata */}
      <div className="rounded-2xl border border-slate-100 bg-white shadow-sm">
        <div className="border-b border-slate-100 px-4 py-3">
          <div className="flex items-center justify-between">
            <SectionLabel>Supply chain bundle</SectionLabel>
            <button
              type="button"
              onClick={handleOpenCloud}
              className="inline-flex items-center gap-1 text-xs font-medium text-brand-blue hover:text-brand-blue-dark focus:outline-none focus:ring-2 focus:ring-brand-blue/30 rounded px-1.5 py-0.5"
            >
              View in cloud
              <HiMiniArrowTopRightOnSquare className="h-3 w-3" aria-hidden="true" />
            </button>
          </div>
          <p className="mt-1 text-sm text-slate-500">
            Signed advisory feed and package risk data.
          </p>
        </div>
        <div className="px-4 py-4 space-y-3">
          <div className="flex flex-wrap gap-3">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-slate-500 uppercase tracking-[0.15em]">Version:</span>
              <Tag tone="blue">{bundle.bundleVersion}</Tag>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-slate-500 uppercase tracking-[0.15em]">Advisories:</span>
              <Tag tone="slate">{bundle.advisories.length}</Tag>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-slate-500 uppercase tracking-[0.15em]">Packages:</span>
              <Tag tone="slate">{bundle.packages.length}</Tag>
            </div>
          </div>
          {bundle.expiresAt && (
            <p className="text-xs text-slate-400">
              Expires {formatRelativeTime(bundle.expiresAt)}
            </p>
          )}
        </div>
      </div>

      {/* Severity breakdown */}
      {severityCounts && Object.keys(severityCounts).length > 0 && (
        <div className="rounded-2xl border border-slate-100 bg-white shadow-sm">
          <div className="border-b border-slate-100 px-4 py-3">
            <SectionLabel>Severity breakdown</SectionLabel>
          </div>
          <div className="px-4 py-4">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {["critical", "high", "medium", "low"].map((sev) => {
                const count = severityCounts[sev] ?? 0;
                const tone =
                  sev === "critical" || sev === "high"
                    ? "destructive"
                    : sev === "medium"
                    ? "attention"
                    : "default";
                return (
                  <div key={sev} className="rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2.5">
                    <p className="text-xs font-semibold uppercase tracking-[0.15em] text-slate-400">{sev}</p>
                    <p className="mt-1 text-xl font-bold tabular-nums">
                      <Badge tone={tone}>{count}</Badge>
                    </p>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Top advisories */}
      {topAdvisories.length > 0 && (
        <div className="rounded-2xl border border-slate-100 bg-white shadow-sm">
          <div className="border-b border-slate-100 px-4 py-3">
            <SectionLabel>Top advisories</SectionLabel>
            <p className="mt-1 text-sm text-slate-500">
              Highest severity and confidence advisories in this bundle.
            </p>
          </div>
          <div>
            {topAdvisories.map((advisory) => (
              <AdvisoryRow key={advisory.advisoryId} advisory={advisory} />
            ))}
          </div>
          {bundle.advisories.length > 10 && (
            <div className="border-t border-slate-100 px-4 py-2.5">
              <button
                type="button"
                onClick={handleOpenCloud}
                className="text-xs font-medium text-brand-blue hover:text-brand-blue-dark focus:outline-none focus:ring-2 focus:ring-brand-blue/30 rounded px-1.5 py-0.5"
              >
                View all {bundle.advisories.length} advisories in Guard Cloud
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
