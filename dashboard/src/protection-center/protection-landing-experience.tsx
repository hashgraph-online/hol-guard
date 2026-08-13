import { useMemo, useState } from "react";

import {
  fetchEffectiveExtensionControls,
  fetchExtensionCatalog,
  type EffectiveExtensionControls,
  type ExtensionCatalogItem,
} from "../extension-controls-api";
import { ExtensionsFilterBar } from "../extensions-filter-bar";
import type { ExtensionFilterState } from "../extensions-filters";
import { fetchRuntimeSnapshot } from "../guard-api";
import {
  ProtectionHealthCheckPanel,
  ProtectionModuleExplorer,
  ProtectionWatchingMap,
  RecentProtectionDecisions,
} from "./components/protection-landing-panels";
import { CloudValueGate } from "./protection-cloud-value";
import {
  evaluateProtectionHealth,
  rankProtectionModules,
  recentProtectionDecisions,
  type ProtectionHealthCheck,
} from "./model/protection-landing";
import { useProtectionLandingData } from "./use-protection-landing-data";

export function ProtectionLandingExperience(props: {
  catalog: readonly ExtensionCatalogItem[];
  catalogDigest: string;
  effective: EffectiveExtensionControls;
  filters: ExtensionFilterState;
  onFilters: (patch: Partial<ExtensionFilterState>) => void;
  onClearFilters: () => void;
  onOpen: (extension: ExtensionCatalogItem) => void;
}) {
  const landing = useProtectionLandingData();
  const [healthBusy, setHealthBusy] = useState(false);
  const [healthResult, setHealthResult] = useState<ProtectionHealthCheck | null>(null);
  const [healthError, setHealthError] = useState<string | null>(null);
  const modules = useMemo(() => rankProtectionModules(props.catalog, landing.activity), [landing.activity, props.catalog]);
  const decisions = useMemo(() => recentProtectionDecisions(landing.activity, props.catalog, 3), [landing.activity, props.catalog]);

  async function runHealthCheck() {
    setHealthBusy(true);
    setHealthError(null);
    try {
      const [catalog, effective, runtime] = await Promise.all([
        fetchExtensionCatalog(),
        fetchEffectiveExtensionControls(),
        fetchRuntimeSnapshot({ includeItems: false, includeReceipts: false }),
      ]);
      const result = evaluateProtectionHealth(catalog.catalog_digest, effective, runtime);
      if (catalog.catalog_digest !== props.catalogDigest) {
        result.status = "needs-attention";
        result.summary = "Protection data changed since this page loaded. Refresh Extensions before making changes.";
        result.checks.push({ id: "view-freshness", label: "This page matches the latest protection catalog", passed: false });
      }
      setHealthResult(result);
    } catch (error) {
      setHealthResult(null);
      setHealthError(error instanceof Error ? error.message : "Guard could not complete the local protection health check.");
    } finally {
      setHealthBusy(false);
    }
  }

  return <>
    <ProtectionWatchingMap modules={modules} onOpen={props.onOpen} />
    <ProtectionModuleExplorer
      modules={modules}
      effective={props.effective}
      onOpen={props.onOpen}
      advancedFilters={<ExtensionsFilterBar filters={props.filters} onChange={props.onFilters} onClear={props.onClearFilters} extensions={props.catalog as ExtensionCatalogItem[]} effective={props.effective} />}
    />
    <RecentProtectionDecisions decisions={decisions} loading={landing.activityLoading} unavailable={landing.activityError} />
    <div className="mt-8"><CloudValueGate runtime={landing.runtime} loading={landing.runtimeLoading} loadFailed={landing.runtimeError} /></div>
    <details className="mt-8">
      <summary className="cursor-pointer text-sm font-semibold text-brand-dark">Check protection health</summary>
      <ProtectionHealthCheckPanel result={healthResult} busy={healthBusy} error={healthError} onRun={() => { void runHealthCheck(); }} />
    </details>
  </>;
}
