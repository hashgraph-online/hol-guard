import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ChangeEvent } from "react";
import { HiMiniAdjustmentsHorizontal, HiMiniArrowDownTray, HiMiniMagnifyingGlass } from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import { harnessDisplayName, policyActionLabel } from "./approval-center-utils";
import type { GuardPolicyDecision, GuardRuntimeSnapshot } from "./guard-types";
import { PolicyActiveModeCard } from "./policy-active-mode-card";
import { downloadPolicies } from "./policy-export";
import { PolicyGuardCloudBundleCard } from "./policy-guard-cloud-bundle-card";
import {
  isCloudManagedPolicy,
  resolvePolicyDisplay,
  resolvePolicyMatcherFamily,
  type PolicySortState,
} from "./policy-workspace-helpers";
import {
  groupPoliciesByFamily,
  resolveFamilyFilterLabel,
} from "./policy-workspace-views";
import { PolicyRememberedCloudRules } from "./policy-remembered-cloud-rules";
import { PolicyRememberedLocalRules } from "./policy-remembered-local-rules";
import { PolicyRememberedRulesRightRail } from "./policy-remembered-rules-right-rail";

type PolicyRememberedRulesTabProps = {
  policies: GuardPolicyDecision[];
  snapshot: GuardRuntimeSnapshot;
  cloudControlsUrl: string | null;
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
  onOpenCloudExceptions: () => void;
  onNavigate?: (pathname: string) => void;
};

export function PolicyRememberedRulesTab({
  policies,
  snapshot,
  cloudControlsUrl,
  onClearPolicy,
  onOpenCloudExceptions,
  onNavigate,
}: PolicyRememberedRulesTabProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [appFilter, setAppFilter] = useState("");
  const [familyFilter, setFamilyFilter] = useState("");
  const [showFilters, setShowFilters] = useState(false);
  const [sort, setSort] = useState<PolicySortState>({ key: "updated", direction: "desc" });
  const searchInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const handleSearchChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(event.target.value);
  }, []);

  const handleToggleFilters = useCallback(() => {
    setShowFilters((current) => !current);
  }, []);

  const filteredPolicies = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    return policies.filter((policy) => {
      if (appFilter && policy.harness !== appFilter) {
        return false;
      }
      if (familyFilter) {
        const family = resolvePolicyMatcherFamily(policy) ?? "other";
        if (family !== familyFilter) {
          return false;
        }
      }
      if (!query) {
        return true;
      }
      const display = resolvePolicyDisplay(policy);
      const displayHaystack = [
        policy.harness,
        policy.artifact_id,
        policy.workspace,
        policy.publisher,
        policy.scope,
        policy.action,
        policy.reason,
        policy.remembered_command,
        policy.remembered_context,
        policy.workspace_label,
        policy.source_scope_path,
        policy.source_receipt_id,
        display.headline,
        display.kindLine,
        display.pathLine,
        display.projectLabel,
        harnessDisplayName(policy.harness),
        policyActionLabel(policy.action),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return displayHaystack.includes(query);
    });
  }, [policies, searchQuery, appFilter, familyFilter]);

  const rememberedRules = useMemo(
    () =>
      filteredPolicies.filter((policy) => policy.action === "allow" || policy.action === "block"),
    [filteredPolicies],
  );

  const localRules = useMemo(
    () => rememberedRules.filter((policy) => !isCloudManagedPolicy(policy.source)),
    [rememberedRules],
  );
  const cloudRules = useMemo(
    () => rememberedRules.filter((policy) => isCloudManagedPolicy(policy.source)),
    [rememberedRules],
  );

  const appOptions = useMemo(
    () => [...new Set(policies.map((policy) => policy.harness).filter(Boolean))].sort(),
    [policies],
  );
  const familyCounts = useMemo(() => groupPoliciesByFamily(rememberedRules), [rememberedRules]);

  const handleExportCsv = useCallback(() => {
    downloadPolicies("csv", rememberedRules);
  }, [rememberedRules]);

  const handleExportJson = useCallback(() => {
    downloadPolicies("json", rememberedRules);
  }, [rememberedRules]);

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_280px] lg:items-start">
      <div className="space-y-4">
        <div className="grid gap-4 lg:grid-cols-2">
          <PolicyGuardCloudBundleCard snapshot={snapshot} />
          <PolicyActiveModeCard snapshot={snapshot} />
        </div>

        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
            <div className="flex flex-1 items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-3 py-2">
              <HiMiniMagnifyingGlass className="h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />
              <input
                ref={searchInputRef}
                type="search"
                placeholder="Search by app, action, or reason…"
                value={searchQuery}
                onChange={handleSearchChange}
                aria-label="Search policies"
                className="w-full bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none"
              />
              <kbd className="hidden shrink-0 rounded-md border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[10px] font-medium text-slate-500 sm:inline">
                ⌘K
              </kbd>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={handleToggleFilters}
                aria-expanded={showFilters}
                className={`inline-flex min-h-10 items-center gap-1.5 rounded-xl border px-3 py-2 text-sm font-medium transition-colors ${
                  showFilters
                    ? "border-brand-blue/30 bg-brand-blue/[0.04] text-brand-dark"
                    : "border-slate-200 bg-white text-brand-dark hover:border-brand-blue/20"
                }`}
              >
                <HiMiniAdjustmentsHorizontal className="h-4 w-4 text-slate-500" aria-hidden="true" />
                Filters
              </button>
              <ActionButton variant="secondary" onClick={handleExportCsv}>
                <HiMiniArrowDownTray className="mr-1.5 h-4 w-4" aria-hidden="true" />
                Export CSV
              </ActionButton>
              <ActionButton variant="secondary" onClick={handleExportJson}>
                <HiMiniArrowDownTray className="mr-1.5 h-4 w-4" aria-hidden="true" />
                Export JSON
              </ActionButton>
            </div>
          </div>

          {showFilters ? (
            <div className="flex flex-wrap gap-2">
              <select
                value={appFilter}
                onChange={(event) => setAppFilter(event.target.value)}
                aria-label="Filter by app"
                className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark"
              >
                <option value="">All assets</option>
                {appOptions.map((app) => (
                  <option key={app} value={app}>
                    {harnessDisplayName(app)}
                  </option>
                ))}
              </select>
              <select
                value={familyFilter}
                onChange={(event) => setFamilyFilter(event.target.value)}
                aria-label="Filter by action type"
                className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark"
              >
                <option value="">All action types</option>
                {[...familyCounts.entries()].map(([family, count]) => (
                  <option key={family} value={family}>
                    {resolveFamilyFilterLabel(family)} ({count})
                  </option>
                ))}
              </select>
            </div>
          ) : null}
        </div>

        <PolicyRememberedLocalRules
          policies={localRules}
          cloudControlsUrl={cloudControlsUrl}
          onClearPolicy={onClearPolicy}
          onNavigate={onNavigate}
          sort={sort}
          onSortChange={setSort}
        />
        <PolicyRememberedCloudRules
          policies={cloudRules}
          cloudControlsUrl={cloudControlsUrl}
          sort={sort}
          onSortChange={setSort}
        />
      </div>

      <PolicyRememberedRulesRightRail onOpenCloudExceptions={onOpenCloudExceptions} snapshot={snapshot} />
    </div>
  );
}
