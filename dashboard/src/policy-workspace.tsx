import { useState, useCallback, useMemo } from "react";
import type { ChangeEvent } from "react";
import {
  HiMiniCheckCircle,
  HiMiniTrash,
  HiMiniMagnifyingGlass,
  HiMiniBarsArrowUp,
  HiMiniBarsArrowDown,
  HiMiniDocumentText,
  HiMiniCloudArrowUp,
  HiMiniInbox,
  HiMiniCog6Tooth,
} from "react-icons/hi2";
import { SectionLabel, Badge, Tag, ActionButton, EmptyState } from "./approval-center-primitives";
import { harnessDisplayName, formatRelativeTime, policyActionLabel, scopeLabel } from "./approval-center-utils";
import { guardAwareHref } from "./guard-api";
import type { GuardPolicyDecision, GuardRuntimeSnapshot } from "./guard-types";
import {
  isCloudManagedPolicy,
  policyTargetLabel,
  resolveCloudPolicyControlsUrl,
  resolvePolicyEvidenceHref,
  resolvePolicyRuleSummary,
  resolvePolicySourceLabel,
} from "./policy-workspace-helpers";

export type PolicyPageView = "rules" | "exceptions" | "strict";

export type PolicyFilterState = {
  searchQuery: string;
  harnessFilter: string;
  scopeFilter: string;
};

type PolicySortKey = "app" | "scope" | "action" | "target" | "updated";
type PolicySortDirection = "asc" | "desc";
type PolicySortState = { key: PolicySortKey; direction: PolicySortDirection } | null;

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

function resolveActionTone(action: string): "success" | "destructive" | "warning" | "default" {
  if (action === "allow") {
    return "success";
  }
  if (action === "block") {
    return "destructive";
  }
  if (action === "warn" || action === "require-reapproval") {
    return "warning";
  }
  return "default";
}

type PolicyRowProps = {
  policy: GuardPolicyDecision;
  cloudControlsUrl: string | null;
  onClear?: (policy: GuardPolicyDecision) => void;
};

function PolicyRow({ policy, cloudControlsUrl, onClear }: PolicyRowProps) {
  const handleClear = useCallback(() => onClear?.(policy), [onClear, policy]);
  const cloudManaged = isCloudManagedPolicy(policy.source);
  const summary = resolvePolicyRuleSummary(policy, {
    appName: harnessDisplayName(policy.harness),
    scopeLabel: scopeLabel(policy.scope),
    actionLabel: policyActionLabel(policy.action),
  });
  const target = policyTargetLabel(policy);
  const canClear = onClear !== undefined && !cloudManaged;

  return (
    <tr className="border-b border-slate-100 last:border-b-0 align-top hover:bg-slate-50/40 transition-colors">
      <td className="px-4 py-3 text-sm text-brand-dark min-w-[120px]">
        <span className="font-medium">{harnessDisplayName(policy.harness)}</span>
        <p className="mt-1 text-xs text-slate-400">{policy.scope} scope</p>
      </td>
      <td className="px-4 py-3 min-w-[240px]">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone={resolveActionTone(policy.action)}>{policyActionLabel(policy.action)}</Badge>
          <Tag tone={cloudManaged ? "blue" : "green"}>{resolvePolicySourceLabel(policy.source)}</Tag>
        </div>
        <p className="mt-2 text-sm leading-relaxed text-brand-dark">{summary}</p>
        <details className="mt-2 text-xs text-slate-500">
          <summary className="cursor-pointer font-medium text-brand-blue hover:underline">Rule details</summary>
          <dl className="mt-2 space-y-1.5 rounded-lg border border-slate-100 bg-slate-50/70 px-3 py-2">
            <div>
              <dt className="font-semibold text-slate-600">Target</dt>
              <dd className="font-mono break-all text-slate-700">{target}</dd>
            </div>
            {policy.workspace ? (
              <div>
                <dt className="font-semibold text-slate-600">Project</dt>
                <dd className="break-all text-slate-700">{policy.workspace}</dd>
              </div>
            ) : null}
            {policy.publisher ? (
              <div>
                <dt className="font-semibold text-slate-600">Publisher</dt>
                <dd className="break-all text-slate-700">{policy.publisher}</dd>
              </div>
            ) : null}
            {policy.reason ? (
              <div>
                <dt className="font-semibold text-slate-600">Reason</dt>
                <dd className="text-slate-700">{policy.reason}</dd>
              </div>
            ) : null}
            {policy.artifact_hash ? (
              <div>
                <dt className="font-semibold text-slate-600">Artifact hash</dt>
                <dd className="font-mono break-all text-slate-700">{policy.artifact_hash}</dd>
              </div>
            ) : null}
          </dl>
        </details>
      </td>
      <td className="px-4 py-3 text-xs text-slate-400 whitespace-nowrap">
        {policy.updated_at ? formatRelativeTime(policy.updated_at) : null}
      </td>
      <td className="px-4 py-3">
        <div className="flex flex-wrap items-center gap-1">
          {!cloudManaged ? (
            <a
              href={guardAwareHref(resolvePolicyEvidenceHref(policy))}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-600 hover:border-brand-blue/30 hover:text-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/30 transition-colors"
            >
              <HiMiniDocumentText className="h-3.5 w-3.5" aria-hidden="true" />
              View evidence
            </a>
          ) : null}
          {cloudManaged && cloudControlsUrl ? (
            <a
              href={cloudControlsUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 rounded-lg border border-brand-blue/20 bg-brand-blue/[0.05] px-2.5 py-1.5 text-xs font-medium text-brand-blue hover:bg-brand-blue/[0.1] focus:outline-none focus:ring-2 focus:ring-brand-blue/30 transition-colors"
            >
              <HiMiniCloudArrowUp className="h-3.5 w-3.5" aria-hidden="true" />
              View on cloud
            </a>
          ) : null}
          {canClear ? (
            <button
              type="button"
              onClick={handleClear}
              aria-label={`Clear policy for ${harnessDisplayName(policy.harness)}`}
              className="inline-flex h-8 w-8 items-center justify-center rounded p-1.5 text-slate-400 hover:bg-red-50 hover:text-red-500 focus:outline-none focus:ring-2 focus:ring-red-300/50 transition-colors"
              title="Clear policy"
            >
              <HiMiniTrash className="h-4 w-4" aria-hidden="true" />
            </button>
          ) : null}
        </div>
      </td>
    </tr>
  );
}

type SortHeaderProps = {
  label: string;
  sortKey: PolicySortKey;
  activeSort: PolicySortState;
  onSort: (key: PolicySortKey) => void;
  className?: string;
};

function SortHeader({ label, sortKey, activeSort, onSort, className }: SortHeaderProps) {
  const isActive = activeSort?.key === sortKey;
  const ariaSort = isActive ? (activeSort.direction === "asc" ? "ascending" : "descending") : "none";
  return (
    <th scope="col" aria-sort={ariaSort} className={`px-4 py-2.5 text-left ${className ?? ""}`}>
      <button
        type="button"
        onClick={() => onSort(sortKey)}
        className="group inline-flex items-center gap-1 rounded px-1 -ml-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400 transition-colors hover:text-brand-dark focus:outline-none focus:ring-2 focus:ring-brand-blue/30"
        aria-label={`Sort by ${label}, ${isActive ? (activeSort.direction === "asc" ? "descending" : "ascending") : "ascending"}`}
      >
        {label}
        <span className="inline-flex h-3.5 w-3.5 items-center justify-center" aria-hidden="true">
          {isActive ? (
            activeSort.direction === "asc" ? (
              <HiMiniBarsArrowUp className="h-3 w-3 text-brand-blue" />
            ) : (
              <HiMiniBarsArrowDown className="h-3 w-3 text-brand-blue" />
            )
          ) : (
            <HiMiniBarsArrowUp className="h-3 w-3 text-slate-300 opacity-0 transition-opacity group-hover:opacity-100" />
          )}
        </span>
      </button>
    </th>
  );
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
        <div
          className={`rounded-2xl p-4 shadow-sm ${
            cloudBundleCopy.tone === "attention"
              ? "border border-amber-200/70 bg-amber-50/70"
              : cloudBundleCopy.tone === "slate"
                ? "border border-slate-200/70 bg-slate-50/70"
                : "border border-emerald-200/70 bg-emerald-50/70"
          }`}
        >
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
        />
      ) : null}
      {activeView === "strict" ? (
        <StrictModeView snapshot={snapshot} onOpenSettings={onOpenSettings} />
      ) : null}
    </div>
  );
}

type PolicyTableSectionProps = {
  title: string;
  description: string;
  policies: GuardPolicyDecision[];
  sort: PolicySortState;
  onSort: (key: PolicySortKey) => void;
  cloudControlsUrl: string | null;
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
  emptyTitle: string;
  emptyBody: string;
};

function PolicyTableSection({
  title,
  description,
  policies,
  sort,
  onSort,
  cloudControlsUrl,
  onClearPolicy,
  emptyTitle,
  emptyBody,
}: PolicyTableSectionProps) {
  if (policies.length === 0) {
    return (
      <section className="space-y-2">
        <div>
          <h2 className="text-base font-semibold text-brand-dark">{title}</h2>
          <p className="text-sm text-slate-500">{description}</p>
        </div>
        <EmptyState title={emptyTitle} body={emptyBody} tone="teach" />
      </section>
    );
  }

  return (
    <section className="space-y-3">
      <div>
        <h2 className="text-base font-semibold text-brand-dark">{title}</h2>
        <p className="text-sm text-slate-500">{description}</p>
      </div>
      <div className="overflow-hidden rounded-2xl border border-slate-100 bg-white shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[760px] text-sm" aria-label={title}>
            <thead>
              <tr className="border-b border-slate-100 bg-slate-50">
                <SortHeader label="App" sortKey="app" activeSort={sort} onSort={onSort} />
                <th scope="col" className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">
                  What this rule does
                </th>
                <SortHeader label="Updated" sortKey="updated" activeSort={sort} onSort={onSort} />
                <th scope="col" className="px-4 py-2.5">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {policies.map((policy) => (
                <PolicyRow
                  key={`${policy.harness}-${policy.scope}-${policyTargetLabel(policy)}-${policy.updated_at ?? ""}-${policy.source}`}
                  policy={policy}
                  cloudControlsUrl={cloudControlsUrl}
                  onClear={onClearPolicy}
                />
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

function ExceptionsView({
  policies,
  cloudControlsUrl,
  onClearPolicy,
  onOpenInbox,
  onOpenSettings,
}: {
  policies: GuardPolicyDecision[];
  cloudControlsUrl: string | null;
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
  onOpenInbox?: () => void;
  onOpenSettings?: () => void;
}) {
  if (policies.length === 0) {
    return (
      <div className="space-y-4">
        <EmptyState
          title="No exceptions yet"
          body="Exceptions are created when Inbox decisions use custom responses such as Warn or Require review, or when repo and environment overrides are configured."
          tone="teach"
        />
        <div className="flex flex-wrap gap-2">
          {onOpenInbox ? (
            <ActionButton variant="primary" onClick={onOpenInbox}>
              <HiMiniInbox className="mr-1.5 h-4 w-4" aria-hidden="true" />
              Review Inbox
            </ActionButton>
          ) : null}
          {onOpenSettings ? (
            <ActionButton variant="secondary" onClick={onOpenSettings}>
              <HiMiniCog6Tooth className="mr-1.5 h-4 w-4" aria-hidden="true" />
              Configure in Settings
            </ActionButton>
          ) : null}
          {cloudControlsUrl ? (
            <a
              href={cloudControlsUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 rounded-lg border border-brand-blue/20 bg-white px-4 py-2 text-sm font-medium text-brand-blue hover:bg-brand-blue/[0.05]"
            >
              <HiMiniCloudArrowUp className="h-4 w-4" aria-hidden="true" />
              View on cloud
            </a>
          ) : null}
        </div>
      </div>
    );
  }

  return (
    <PolicyTableSection
      title="Active exceptions"
      description="Custom responses and overrides that are not simple allow or block rules."
      policies={policies}
      sort={{ key: "updated", direction: "desc" }}
      onSort={() => undefined}
      cloudControlsUrl={cloudControlsUrl}
      onClearPolicy={onClearPolicy}
      emptyTitle="No exceptions configured"
      emptyBody="Exceptions appear after custom Inbox decisions or repo overrides."
    />
  );
}

function StrictModeView({
  snapshot,
  onOpenSettings,
}: {
  snapshot: GuardRuntimeSnapshot;
  onOpenSettings?: () => void;
}) {
  const securityLevel = snapshot.security_level;
  const isStrict = securityLevel === "strict";
  return (
    <div className="space-y-4">
      <div
        className={`rounded-2xl border p-5 ${isStrict ? "border-brand-green/20 bg-brand-green/[0.04]" : "border-slate-200 bg-slate-50/40"}`}
      >
        <div className="mb-2 flex items-center gap-2">
          <SectionLabel>Strict mode</SectionLabel>
          <Tag tone={isStrict ? "green" : "slate"}>{isStrict ? "Enabled" : "Disabled"}</Tag>
        </div>
        <p className="mb-4 text-sm text-brand-dark/75">
          Strict mode enables maximum coverage. Guard asks before new network connections, subprocess launches, file writes, and all harness starts.
        </p>
        {!isStrict && onOpenSettings ? (
          <ActionButton variant="secondary" onClick={onOpenSettings}>
            Enable strict mode
          </ActionButton>
        ) : null}
        {isStrict ? (
          <div className="flex items-center gap-2 text-sm text-brand-green">
            <HiMiniCheckCircle className="h-4 w-4" aria-hidden="true" />
            Strict mode is active
          </div>
        ) : null}
      </div>

      <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-sm">
        <SectionLabel>Repo and environment rules</SectionLabel>
        <p className="mt-1 mb-3 text-sm text-slate-500">
          Per-repo and per-environment policy overrides can be set in your Guard config file or Guard Cloud Controls.
        </p>
        <div className="rounded-lg border border-slate-100 bg-slate-50/60 px-4 py-3">
          <p className="font-mono text-xs text-slate-600">~/.config/hol-guard/guard.yaml</p>
          <p className="mt-1 text-xs text-slate-400">See repo_rules and env_rules in the Guard docs.</p>
        </div>
      </div>
    </div>
  );
}
