import { useCallback, useMemo, useState } from "react";
import type { ChangeEvent } from "react";
import { HiMiniMagnifyingGlass } from "react-icons/hi2";
import { harnessDisplayName, policyActionLabel } from "./approval-center-utils";
import type { GuardPolicyDecision, GuardRuntimeSnapshot } from "./guard-types";
import { PolicyGuardCloudBundleCard } from "./policy-guard-cloud-bundle-card";
import {
  isCloudManagedPolicy,
  resolvePolicyDisplay,
  resolvePolicyMatcherFamily,
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
};

export function PolicyRememberedRulesTab({
  policies,
  snapshot,
  cloudControlsUrl,
  onClearPolicy,
  onOpenCloudExceptions,
}: PolicyRememberedRulesTabProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [appFilter, setAppFilter] = useState("");
  const [familyFilter, setFamilyFilter] = useState("");

  const handleSearchChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(event.target.value);
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
      filteredPolicies
        .filter((policy) => policy.action === "allow" || policy.action === "block")
        .sort((a, b) => new Date(b.updated_at || 0).getTime() - new Date(a.updated_at || 0).getTime()),
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

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_280px] lg:items-start">
      <div className="space-y-4">
        <PolicyGuardCloudBundleCard snapshot={snapshot} />

        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex flex-1 items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-3 py-2">
            <HiMiniMagnifyingGlass className="h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />
            <input
              type="search"
              placeholder="Search command, project, path, or app…"
              value={searchQuery}
              onChange={handleSearchChange}
              aria-label="Search policies"
              className="w-full bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none"
            />
          </div>
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
        </div>

        <PolicyRememberedLocalRules
          policies={localRules}
          cloudControlsUrl={cloudControlsUrl}
          onClearPolicy={onClearPolicy}
        />
        <PolicyRememberedCloudRules policies={cloudRules} cloudControlsUrl={cloudControlsUrl} />
      </div>

      <PolicyRememberedRulesRightRail snapshot={snapshot} onOpenCloudExceptions={onOpenCloudExceptions} />
    </div>
  );
}
