import { useCallback, useMemo, useState } from "react";
import type { ChangeEvent } from "react";
import { HiMiniMagnifyingGlass, HiMiniCloudArrowUp, HiMiniPlus } from "react-icons/hi2";
import { SectionLabel, Tag, ActionButton, EmptyState } from "./approval-center-primitives";
import { harnessDisplayName, policyActionLabel } from "./approval-center-utils";
import type { GuardPolicyDecision, GuardRuntimeSnapshot } from "./guard-types";
import { PolicyExceptionForm } from "./policy-exception-form";
import {
  isCloudManagedPolicy,
  resolveCloudPolicyBundleCopy,
  resolveCloudPolicyControlsUrl,
  resolvePolicyDisplay,
  resolvePolicyMatcherFamily,
  resolveSecurityModeCopy,
} from "./policy-workspace-helpers";
import {
  GroupedPolicySection,
  PolicyRuleList,
  resolveFamilyFilterLabel,
  groupPoliciesByFamily,
} from "./policy-workspace-views";

export type PolicyPageView = "rules" | "exceptions" | "strict";

export {
  groupPoliciesByHarness,
  resolveSecurityModeCopy,
  resolveCloudPolicyBundleCopy,
} from "./policy-workspace-helpers";

type PolicyWorkspaceProps = {
  policies: GuardPolicyDecision[];
  snapshot: GuardRuntimeSnapshot;
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
  onOpenSettings?: () => void;
  onOpenInbox?: () => void;
  onRefreshPolicies?: () => void;
};

export function PolicyWorkspace({
  policies,
  snapshot,
  onClearPolicy,
  onOpenSettings,
  onOpenInbox,
  onRefreshPolicies,
}: PolicyWorkspaceProps) {
  const [activeView, setActiveView] = useState<PolicyPageView>("rules");
  const [searchQuery, setSearchQuery] = useState("");
  const [appFilter, setAppFilter] = useState("");
  const [familyFilter, setFamilyFilter] = useState("");
  const [showExceptionForm, setShowExceptionForm] = useState(false);

  const handleSearchChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(event.target.value);
  }, []);

  const handleViewChange = useCallback((view: PolicyPageView) => {
    setActiveView(view);
    setShowExceptionForm(false);
  }, []);

  const handleOpenExceptionForm = useCallback(() => {
    setShowExceptionForm(true);
  }, []);

  const handleCloseExceptionForm = useCallback(() => {
    setShowExceptionForm(false);
  }, []);

  const handleExceptionSaved = useCallback(() => {
    setShowExceptionForm(false);
    onRefreshPolicies?.();
  }, [onRefreshPolicies]);

  const modeCopy = useMemo(() => resolveSecurityModeCopy(snapshot.security_level), [snapshot.security_level]);
  const cloudControlsUrl = useMemo(() => resolveCloudPolicyControlsUrl(snapshot), [snapshot]);
  const cloudBundleCopy = useMemo(() => resolveCloudPolicyBundleCopy(snapshot), [snapshot]);

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
        display.headline,
        display.subtitle,
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

  const exceptionPolicies = useMemo(
    () =>
      filteredPolicies
        .filter((policy) => policy.action !== "allow" && policy.action !== "block")
        .sort((a, b) => new Date(b.updated_at || 0).getTime() - new Date(a.updated_at || 0).getTime()),
    [filteredPolicies],
  );

  const appOptions = useMemo(
    () => [...new Set(policies.map((policy) => policy.harness).filter(Boolean))].sort(),
    [policies],
  );
  const familyCounts = useMemo(() => groupPoliciesByFamily(rememberedRules), [rememberedRules]);

  return (
    <div className="space-y-6">
      {cloudBundleCopy ? (
        <div className="rounded-2xl border border-emerald-200/70 bg-emerald-50/70 p-4 shadow-sm">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <SectionLabel>Guard Cloud bundle</SectionLabel>
            <Tag tone={cloudBundleCopy.tone}>{cloudBundleCopy.label}</Tag>
          </div>
          <p className="text-sm text-brand-dark/75">{cloudBundleCopy.detail}</p>
        </div>
      ) : null}

      <div className="rounded-2xl border border-brand-blue/10 bg-brand-blue/[0.03] p-5 shadow-sm">
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <SectionLabel>Active mode</SectionLabel>
          <Tag tone={modeCopy.tone}>{modeCopy.label}</Tag>
        </div>
        <p className="text-sm text-brand-dark/75">{modeCopy.description}</p>
        {onOpenSettings ? (
          <div className="mt-3">
            <ActionButton variant="secondary" onClick={onOpenSettings}>
              Open security settings
            </ActionButton>
          </div>
        ) : null}
      </div>

      <div className="flex flex-wrap gap-2 border-b border-slate-100 pb-3">
        {(["rules", "exceptions", "strict"] as const).map((view) => (
          <button
            key={view}
            type="button"
            onClick={() => handleViewChange(view)}
            aria-pressed={activeView === view}
            className={`rounded-full px-4 py-1.5 text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${
              activeView === view
                ? "bg-brand-blue text-white"
                : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
            }`}
          >
            {view === "rules" ? "Remembered rules" : view === "exceptions" ? "Exceptions" : "Strict config"}
          </button>
        ))}
      </div>

      {activeView === "rules" ? (
        <div className="space-y-4">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex flex-1 items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-3 py-2">
              <HiMiniMagnifyingGlass className="h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />
              <input
                type="search"
                placeholder="Search by app, action, or reason…"
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
                <option value="">All apps</option>
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

          <GroupedPolicySection
            title="Remembered on this device"
            description="Choices you saved from Inbox. Each card explains what Guard will do next time."
            policies={localRules}
            cloudControlsUrl={cloudControlsUrl}
            onClearPolicy={onClearPolicy}
            emptyTitle="No local remembered rules yet"
            emptyBody="Approve or block in Inbox and Guard remembers the decision here in plain language."
            defaultOpen
          />
          <GroupedPolicySection
            title="From Guard Cloud"
            description="Synced team rules are read-only here. Edit them in Guard Cloud Controls."
            policies={cloudRules}
            cloudControlsUrl={cloudControlsUrl}
            emptyTitle="No Guard Cloud rules synced"
            emptyBody="Connect Guard Cloud to sync shared policy bundles."
            defaultOpen={cloudRules.length > 0}
          />
        </div>
      ) : null}

      {activeView === "exceptions" ? (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-slate-600">
              Exceptions change how Guard responds (warn, require review, block, or allow) without waiting for Inbox.
            </p>
            {!showExceptionForm ? (
              <ActionButton variant="primary" onClick={handleOpenExceptionForm}>
                <HiMiniPlus className="mr-1.5 h-4 w-4" aria-hidden="true" />
                New exception
              </ActionButton>
            ) : null}
          </div>

          {showExceptionForm ? (
            <PolicyExceptionForm
              policies={policies}
              onSaved={handleExceptionSaved}
              onCancel={handleCloseExceptionForm}
            />
          ) : null}

          {exceptionPolicies.length === 0 && !showExceptionForm ? (
            <EmptyState
              title="No exceptions yet"
              body="Create one when you want Guard to warn, always review, block, or allow a whole class of actions."
              tone="teach"
            />
          ) : (
            <PolicyRuleList
              policies={exceptionPolicies}
              cloudControlsUrl={cloudControlsUrl}
              onClearPolicy={onClearPolicy}
              emptyTitle="No active exceptions"
              emptyBody="Saved warn, review, and custom rules appear here."
            />
          )}

          {cloudControlsUrl ? (
            <a
              href={cloudControlsUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-sm font-medium text-brand-blue hover:underline"
            >
              <HiMiniCloudArrowUp className="h-4 w-4" aria-hidden="true" />
              Manage team exceptions in Guard Cloud
            </a>
          ) : null}
        </div>
      ) : null}

      {activeView === "strict" ? (
        <StrictModeView snapshot={snapshot} onOpenSettings={onOpenSettings} onOpenInbox={onOpenInbox} />
      ) : null}
    </div>
  );
}

function StrictModeView({
  snapshot,
  onOpenSettings,
  onOpenInbox,
}: {
  snapshot: GuardRuntimeSnapshot;
  onOpenSettings?: () => void;
  onOpenInbox?: () => void;
}) {
  const isStrict = snapshot.security_level === "strict";
  return (
    <div className="space-y-4">
      <div className={`rounded-2xl border p-5 ${isStrict ? "border-brand-green/20 bg-brand-green/[0.04]" : "border-slate-200 bg-slate-50/40"}`}>
        <div className="mb-2 flex items-center gap-2">
          <SectionLabel>Strict mode</SectionLabel>
          <Tag tone={isStrict ? "green" : "slate"}>{isStrict ? "Enabled" : "Disabled"}</Tag>
        </div>
        <p className="mb-4 text-sm text-brand-dark/75">
          Strict mode asks before new network connections, subprocess launches, file writes, and harness starts.
        </p>
        {!isStrict && onOpenSettings ? (
          <ActionButton variant="secondary" onClick={onOpenSettings}>
            Enable strict mode
          </ActionButton>
        ) : null}
      </div>
      {onOpenInbox ? (
        <ActionButton variant="secondary" onClick={onOpenInbox}>
          Review pending Inbox items
        </ActionButton>
      ) : null}
    </div>
  );
}
