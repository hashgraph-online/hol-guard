import { useState, useCallback, useMemo } from "react";
import type { ChangeEvent } from "react";
import { HiMiniMagnifyingGlass, HiMiniCloudArrowUp } from "react-icons/hi2";
import { SectionLabel, Tag, ActionButton } from "./approval-center-primitives";
import type { GuardPolicyDecision, GuardRuntimeSnapshot } from "./guard-types";
import {
  isCloudManagedPolicy,
  policyTargetLabel,
  resolveCloudPolicyControlsUrl,
} from "./policy-workspace-helpers";
import {
  ExceptionsView,
  PolicyTableSection,
  StrictModeView,
  type PolicySortKey,
  type PolicySortState,
} from "./policy-workspace-views";

export type PolicyPageView = "rules" | "exceptions" | "strict";

export type PolicyFilterState = {
  searchQuery: string;
  harnessFilter: string;
  scopeFilter: string;
};

export { policyTargetLabel } from "./policy-workspace-helpers";

export function groupPoliciesByHarness(
  policies: GuardPolicyDecision[],
): Map<string, GuardPolicyDecision[]> {
  const map = new Map<string, GuardPolicyDecision[]>();
  for (const policy of policies) {
    const key = policy.harness || "global";
    const existing = map.get(key) ?? [];
    map.set(key, [...existing, policy]);
  }
  return map;
}

export function resolveSecurityModeCopy(
  level: string | undefined,
): { label: string; description: string; tone: "green" | "attention" | "slate" } {
  if (level === "strict") {
    return {
      label: "Strict mode",
      description:
        "Guard asks before most actions including new network connections and file writes. Higher noise, maximum protection.",
      tone: "attention",
    };
  }
  if (level === "balanced") {
    return {
      label: "Balanced (default)",
      description:
        "Guard asks for secrets, destructive commands, and new network destinations. Low noise, solid coverage.",
      tone: "green",
    };
  }
  if (level === "gentle" || level === "relaxed") {
    return {
      label: "Low noise",
      description: "Guard only asks for the highest-risk actions. Minimal interruptions.",
      tone: "slate",
    };
  }
  return {
    label: level ?? "Custom",
    description: "Custom policy rules apply. Review individual rules below.",
    tone: "slate",
  };
}

export function resolveCloudPolicyBundleCopy(snapshot: GuardRuntimeSnapshot): {
  label: string;
  detail: string;
  tone: "green" | "attention" | "slate";
} | null {
  const bundleVersion = snapshot.cloud_policy_bundle_version?.trim();
  if (!bundleVersion) {
    return null;
  }
  const rollout = snapshot.cloud_policy_rollout_state?.trim() || "unknown";
  const syncError = snapshot.cloud_policy_sync_error?.trim();
  if (syncError) {
    return {
      label: `Cloud bundle ${bundleVersion}`,
      detail: `Guard Cloud Controls owns rollout and authoring. Latest sync issue: ${syncError}.`,
      tone: "attention",
    };
  }
  return {
    label: `Cloud bundle ${bundleVersion}`,
    detail: `Guard Cloud Controls owns authoring and rollout. This local workspace reflects rollout state ${rollout}.`,
    tone: "green",
  };
}

function sortPolicies(policies: GuardPolicyDecision[], sort: PolicySortState): GuardPolicyDecision[] {
  if (sort === null) {
    return policies;
  }
  const sorted = [...policies];
  const dir = sort.direction === "asc" ? 1 : -1;
  sorted.sort((a, b) => {
    switch (sort.key) {
      case "app":
        return a.harness.localeCompare(b.harness) * dir;
      case "scope":
        return a.scope.localeCompare(b.scope) * dir;
      case "action":
        return a.action.localeCompare(b.action) * dir;
      case "target":
        return policyTargetLabel(a).localeCompare(policyTargetLabel(b)) * dir;
      case "updated":
        return (new Date(a.updated_at || 0).getTime() - new Date(b.updated_at || 0).getTime()) * dir;
      default:
        return 0;
    }
  });
  return sorted;
}

function resolveCloudBundleSurfaceClass(tone: "green" | "attention" | "slate"): string {
  if (tone === "attention") {
    return "border border-amber-200/70 bg-amber-50/70";
  }
  if (tone === "slate") {
    return "border border-slate-200/70 bg-slate-50/70";
  }
  return "border border-emerald-200/70 bg-emerald-50/70";
}

type PolicyWorkspaceProps = {
  policies: GuardPolicyDecision[];
  snapshot: GuardRuntimeSnapshot;
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
  onOpenSettings?: () => void;
  onOpenInbox?: () => void;
};

export function PolicyWorkspace({
  policies,
  snapshot,
  onClearPolicy,
  onOpenSettings,
  onOpenInbox,
}: PolicyWorkspaceProps) {
  const [activeView, setActiveView] = useState<PolicyPageView>("rules");
  const [filter, setFilter] = useState<PolicyFilterState>({
    searchQuery: "",
    harnessFilter: "",
    scopeFilter: "",
  });
  const [sort, setSort] = useState<PolicySortState>({ key: "updated", direction: "desc" });

  const handleSearchChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setFilter((current) => ({ ...current, searchQuery: event.target.value }));
  }, []);

  const handleViewChange = useCallback((view: PolicyPageView) => {
    setActiveView(view);
  }, []);

  const handleSort = useCallback((key: PolicySortKey) => {
    setSort((current) => {
      if (current?.key === key) {
        if (current.direction === "asc") {
          return { key, direction: "desc" };
        }
        return { key, direction: "asc" };
      }
      return { key, direction: "asc" };
    });
  }, []);

  const securityLevel = snapshot.security_level;
  const modeCopy = useMemo(() => resolveSecurityModeCopy(securityLevel), [securityLevel]);
  const cloudControlsUrl = useMemo(() => resolveCloudPolicyControlsUrl(snapshot), [snapshot]);

  const filteredPolicies = useMemo(() => {
    return policies.filter((policy) => {
      const query = filter.searchQuery.toLowerCase();
      if (query === "") {
        return true;
      }
      return (
        policy.harness.toLowerCase().includes(query) ||
        (policy.artifact_id ?? "").toLowerCase().includes(query) ||
        (policy.workspace ?? "").toLowerCase().includes(query) ||
        (policy.publisher ?? "").toLowerCase().includes(query) ||
        policy.scope.toLowerCase().includes(query) ||
        policy.action.toLowerCase().includes(query) ||
        (policy.reason ?? "").toLowerCase().includes(query)
      );
    });
  }, [policies, filter.searchQuery]);

  const sortedPolicies = useMemo(() => sortPolicies(filteredPolicies, sort), [filteredPolicies, sort]);

  const rememberedRules = useMemo(
    () => sortedPolicies.filter((policy) => policy.action === "allow" || policy.action === "block"),
    [sortedPolicies],
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
    () => sortedPolicies.filter((policy) => policy.action !== "allow" && policy.action !== "block"),
    [sortedPolicies],
  );

  const cloudBundleCopy = useMemo(() => resolveCloudPolicyBundleCopy(snapshot), [snapshot]);

  return (
    <div className="space-y-6">
      {cloudBundleCopy ? (
        <div className={`rounded-2xl p-4 shadow-sm ${resolveCloudBundleSurfaceClass(cloudBundleCopy.tone)}`}>
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <SectionLabel>Guard Cloud bundle</SectionLabel>
            <Tag tone={cloudBundleCopy.tone}>{cloudBundleCopy.label}</Tag>
          </div>
          <p className="text-sm text-brand-dark/75">{cloudBundleCopy.detail}</p>
          {cloudControlsUrl ? (
            <a
              href={cloudControlsUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-3 inline-flex items-center gap-1 text-sm font-medium text-brand-blue hover:underline"
            >
              <HiMiniCloudArrowUp className="h-4 w-4" aria-hidden="true" />
              View bundle in Guard Cloud Controls
            </a>
          ) : null}
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
        <div className="ml-auto flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5">
          <HiMiniMagnifyingGlass className="h-3.5 w-3.5 shrink-0 text-slate-400" aria-hidden="true" />
          <input
            type="search"
            placeholder="Search policies..."
            value={filter.searchQuery}
            onChange={handleSearchChange}
            aria-label="Search policies"
            className="w-36 bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none sm:w-48"
          />
        </div>
      </div>

      {activeView === "rules" ? (
        <div className="space-y-6">
          <PolicyTableSection
            title="Remembered on this device"
            description="Rules you created from Inbox approvals. You can clear them here or jump to the related evidence."
            policies={localRules}
            sort={sort}
            onSort={handleSort}
            cloudControlsUrl={cloudControlsUrl}
            onClearPolicy={onClearPolicy}
            emptyTitle="No local remembered rules yet"
            emptyBody="Approve or block actions in Inbox and Guard will remember your choice here."
          />
          <PolicyTableSection
            title="From Guard Cloud"
            description="Synced bundle rules are read-only on this device. Open Guard Cloud Controls to review or edit rollout."
            policies={cloudRules}
            sort={sort}
            onSort={handleSort}
            cloudControlsUrl={cloudControlsUrl}
            emptyTitle="No Guard Cloud rules synced yet"
            emptyBody="Connect Guard Cloud to sync shared bundle rules to this device."
          />
        </div>
      ) : null}
      {activeView === "exceptions" ? (
        <ExceptionsView
          policies={exceptionPolicies}
          cloudControlsUrl={cloudControlsUrl}
          onClearPolicy={onClearPolicy}
          onOpenInbox={onOpenInbox}
          onOpenSettings={onOpenSettings}
          sort={sort}
          onSort={handleSort}
        />
      ) : null}
      {activeView === "strict" ? (
        <StrictModeView snapshot={snapshot} onOpenSettings={onOpenSettings} />
      ) : null}
    </div>
  );
}
