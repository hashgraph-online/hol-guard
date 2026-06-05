import { useState, useCallback, useMemo } from "react";
import type { ChangeEvent } from "react";
import {
  HiMiniShieldCheck,
  HiMiniExclamationTriangle,
  HiMiniCheckCircle,
  HiMiniXCircle,
  HiMiniTrash,
  HiMiniMagnifyingGlass,
  HiMiniPlus,
  HiMiniChevronRight,
} from "react-icons/hi2";
import { SectionLabel, Badge, Tag, ActionButton, EmptyState } from "./approval-center-primitives";
import { harnessDisplayName, formatRelativeTime } from "./approval-center-utils";
import type { GuardPolicyDecision, GuardRuntimeSnapshot } from "./guard-types";

export type PolicyPageView = "rules" | "exceptions" | "strict";

export type PolicyFilterState = {
  searchQuery: string;
  harnessFilter: string;
  scopeFilter: string;
};

export function groupPoliciesByHarness(
  policies: GuardPolicyDecision[],
): Map<string, GuardPolicyDecision[]> {
  const map = new Map<string, GuardPolicyDecision[]>();
  for (const p of policies) {
    const key = p.harness || "global";
    const existing = map.get(key) ?? [];
    map.set(key, [...existing, p]);
  }
  return map;
}

export function resolveSecurityModeCopy(
  level: string | undefined,
): { label: string; description: string; tone: "green" | "attention" | "slate" } {
  if (level === "strict") {
    return {
      label: "Strict mode",
      description: "Guard asks before most actions including new network connections and file writes. Higher noise, maximum protection.",
      tone: "attention",
    };
  }
  if (level === "balanced") {
    return {
      label: "Balanced (default)",
      description: "Guard asks for secrets, destructive commands, and new network destinations. Low noise, solid coverage.",
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

type PolicyRowProps = {
  policy: GuardPolicyDecision;
  onClear?: (policy: GuardPolicyDecision) => void;
};

function PolicyRow({ policy, onClear }: PolicyRowProps) {
  const handleClear = useCallback(() => onClear?.(policy), [onClear, policy]);

  const actionTone =
    policy.action === "allow"
      ? "success"
      : policy.action === "block"
      ? "destructive"
      : policy.action === "warn"
      ? "warning"
      : "default";

  return (
    <tr className="border-b border-slate-100 last:border-b-0 hover:bg-slate-50/40 transition-colors">
      <td className="px-4 py-2.5 text-sm text-brand-dark min-w-0">
        <span className="font-medium">{harnessDisplayName(policy.harness)}</span>
      </td>
      <td className="px-4 py-2.5 text-sm text-slate-500">
        {policy.scope}
      </td>
      <td className="px-4 py-2.5">
        <Badge tone={actionTone}>{policy.action}</Badge>
      </td>
      <td className="px-4 py-2.5 text-xs text-slate-500 max-w-[200px]">
        <span className="truncate block" title={policy.artifact_id ?? undefined}>
          {policy.artifact_id ?? policy.publisher ?? policy.workspace ?? "Global"}
        </span>
      </td>
      <td className="px-4 py-2.5 text-xs text-slate-400 whitespace-nowrap">
        {policy.updated_at ? formatRelativeTime(policy.updated_at) : null}
      </td>
      <td className="px-4 py-2.5">
        {onClear && (
          <button
            type="button"
            onClick={handleClear}
            aria-label={`Clear policy for ${harnessDisplayName(policy.harness)}`}
            className="inline-flex items-center justify-center rounded p-1 text-slate-400 hover:bg-red-50 hover:text-red-500 focus:outline-none focus:ring-2 focus:ring-red-300/50 transition-colors"
          >
            <HiMiniTrash className="h-3.5 w-3.5" aria-hidden="true" />
          </button>
        )}
      </td>
    </tr>
  );
}

type PolicyWorkspaceProps = {
  policies: GuardPolicyDecision[];
  snapshot: GuardRuntimeSnapshot;
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
  onOpenSettings?: () => void;
};

export function PolicyWorkspace({
  policies,
  snapshot,
  onClearPolicy,
  onOpenSettings,
}: PolicyWorkspaceProps) {
  const [activeView, setActiveView] = useState<PolicyPageView>("rules");
  const [filter, setFilter] = useState<PolicyFilterState>({
    searchQuery: "",
    harnessFilter: "",
    scopeFilter: "",
  });

  const handleSearchChange = useCallback((e: ChangeEvent<HTMLInputElement>) => {
    setFilter((f) => ({ ...f, searchQuery: e.target.value }));
  }, []);

  const handleViewChange = useCallback((v: PolicyPageView) => {
    setActiveView(v);
  }, []);

  const securityLevel = snapshot.security_level;
  const modeCopy = useMemo(() => resolveSecurityModeCopy(securityLevel), [securityLevel]);

  const filteredPolicies = useMemo(() => {
    return policies.filter((p) => {
      const q = filter.searchQuery.toLowerCase();
      if (q === "") return true;
      return (
        p.harness.toLowerCase().includes(q) ||
        (p.artifact_id ?? "").toLowerCase().includes(q) ||
        (p.workspace ?? "").toLowerCase().includes(q) ||
        (p.publisher ?? "").toLowerCase().includes(q)
      );
    });
  }, [policies, filter.searchQuery]);

  const allowPolicies = useMemo(
    () => filteredPolicies.filter((p) => p.action === "allow"),
    [filteredPolicies],
  );
  const blockPolicies = useMemo(
    () => filteredPolicies.filter((p) => p.action === "block"),
    [filteredPolicies],
  );
  const exceptionPolicies = useMemo(
    () => filteredPolicies.filter((p) => p.action !== "allow" && p.action !== "block"),
    [filteredPolicies],
  );

  const policyByHarness = useMemo(() => groupPoliciesByHarness(policies), [policies]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-sm text-slate-500">
            Guard rules, exceptions, and remembered decisions.
          </p>
        </div>
        {onOpenSettings && (
          <ActionButton variant="outline" onClick={onOpenSettings}>
            Open Settings
          </ActionButton>
        )}
      </div>

      <div className="rounded-2xl border border-brand-blue/10 bg-brand-blue/[0.03] p-5 shadow-sm">
        <div className="flex flex-wrap items-center gap-2 mb-2">
          <SectionLabel>Active mode</SectionLabel>
          <Tag tone={modeCopy.tone}>{modeCopy.label}</Tag>
        </div>
        <p className="text-sm text-brand-dark/75">{modeCopy.description}</p>
        {onOpenSettings && (
          <div className="mt-3">
            <ActionButton variant="ghost" onClick={onOpenSettings}>
              Change mode in Settings
            </ActionButton>
          </div>
        )}
      </div>

      <div className="flex flex-wrap gap-2 border-b border-slate-100 pb-3">
        {(["rules", "exceptions", "strict"] as const).map((v) => (
          <button
            key={v}
            type="button"
            onClick={() => handleViewChange(v)}
            aria-pressed={activeView === v}
            className={`rounded-full px-4 py-1.5 text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${
              activeView === v
                ? "bg-brand-blue text-white"
                : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
            }`}
          >
            {v === "rules" ? "Remembered rules" : v === "exceptions" ? "Exceptions" : "Strict config"}
          </button>
        ))}
        <div className="ml-auto flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5">
          <HiMiniMagnifyingGlass className="h-3.5 w-3.5 text-slate-400 shrink-0" aria-hidden="true" />
          <input
            type="search"
            placeholder="Search policies..."
            value={filter.searchQuery}
            onChange={handleSearchChange}
            aria-label="Search policies"
            className="bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none w-36"
          />
        </div>
      </div>

      {activeView === "rules" && (
        <PolicyTable
          allowPolicies={allowPolicies}
          blockPolicies={blockPolicies}
          onClearPolicy={onClearPolicy}
        />
      )}
      {activeView === "exceptions" && (
        <ExceptionsView policies={exceptionPolicies} onClearPolicy={onClearPolicy} />
      )}
      {activeView === "strict" && (
        <StrictModeView snapshot={snapshot} onOpenSettings={onOpenSettings} />
      )}
    </div>
  );
}

type PolicyTableProps = {
  allowPolicies: GuardPolicyDecision[];
  blockPolicies: GuardPolicyDecision[];
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
};

function PolicyTable({ allowPolicies, blockPolicies, onClearPolicy }: PolicyTableProps) {
  const allPolicies = [...allowPolicies, ...blockPolicies];

  if (allPolicies.length === 0) {
    return (
      <EmptyState
        title="No remembered rules yet"
        body="Guard will remember your decisions as you approve or block actions. They appear here so you can review and remove them."
        tone="teach"
      />
    );
  }

  return (
    <div className="rounded-2xl border border-slate-100 bg-white shadow-sm overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[600px] text-sm" aria-label="Policy rules">
          <thead>
            <tr className="border-b border-slate-100 bg-slate-50">
              <th scope="col" className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">
                App
              </th>
              <th scope="col" className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">
                Scope
              </th>
              <th scope="col" className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">
                Action
              </th>
              <th scope="col" className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">
                Target
              </th>
              <th scope="col" className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">
                Updated
              </th>
              <th scope="col" className="px-4 py-2.5">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {allPolicies.map((p) => (
              <PolicyRow
                key={`${p.harness}-${p.scope}-${p.artifact_id ?? p.publisher ?? p.workspace ?? "global"}`}
                policy={p}
                onClear={onClearPolicy}
              />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ExceptionsView({
  policies,
  onClearPolicy,
}: {
  policies: GuardPolicyDecision[];
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
}) {
  if (policies.length === 0) {
    return (
      <EmptyState
        title="No exceptions configured"
        body="Exceptions are non-allow/block rules that customize Guard behavior for specific repos, harnesses, or environments."
        tone="teach"
      />
    );
  }
  return (
    <div className="rounded-2xl border border-slate-100 bg-white shadow-sm overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[500px] text-sm" aria-label="Exception rules">
          <thead>
            <tr className="border-b border-slate-100 bg-slate-50">
              <th scope="col" className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">App</th>
              <th scope="col" className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">Action</th>
              <th scope="col" className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">Reason</th>
              <th scope="col" className="px-4 py-2.5"><span className="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody>
            {policies.map((p) => (
              <tr
                key={`${p.harness}-${p.scope}-${p.artifact_id ?? "global"}`}
                className="border-b border-slate-100 last:border-b-0 hover:bg-slate-50/40 transition-colors"
              >
                <td className="px-4 py-2.5 text-sm font-medium text-brand-dark">{harnessDisplayName(p.harness)}</td>
                <td className="px-4 py-2.5"><Badge tone="default">{p.action}</Badge></td>
                <td className="px-4 py-2.5 text-sm text-slate-500 max-w-[240px]">
                  <span className="truncate block">{p.reason ?? "No reason recorded"}</span>
                </td>
                <td className="px-4 py-2.5">
                  {onClearPolicy && (
                    <button
                      type="button"
                      onClick={() => onClearPolicy(p)}
                      aria-label={`Remove exception for ${harnessDisplayName(p.harness)}`}
                      className="inline-flex items-center justify-center rounded p-1 text-slate-400 hover:bg-red-50 hover:text-red-500 transition-colors"
                    >
                      <HiMiniTrash className="h-3.5 w-3.5" aria-hidden="true" />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
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
      <div className={`rounded-2xl border p-5 ${isStrict ? "border-brand-green/20 bg-brand-green/[0.04]" : "border-slate-200 bg-slate-50/40"}`}>
        <div className="flex items-center gap-2 mb-2">
          <SectionLabel>Strict mode</SectionLabel>
          <Tag tone={isStrict ? "green" : "slate"}>
            {isStrict ? "Enabled" : "Disabled"}
          </Tag>
        </div>
        <p className="text-sm text-brand-dark/75 mb-4">
          Strict mode enables maximum coverage. Guard asks before new network connections, subprocess launches, file writes, and all harness starts. Expect more interruptions.
        </p>
        {!isStrict && onOpenSettings && (
          <ActionButton variant="secondary" onClick={onOpenSettings}>
            Enable strict mode
          </ActionButton>
        )}
        {isStrict && (
          <div className="flex items-center gap-2 text-sm text-brand-green">
            <HiMiniCheckCircle className="h-4 w-4" aria-hidden="true" />
            Strict mode is active
          </div>
        )}
      </div>

      <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-sm">
        <SectionLabel>Repo and environment rules</SectionLabel>
        <p className="mt-1 mb-3 text-sm text-slate-500">
          Per-repo and per-environment policy overrides can be set in your Guard config file.
        </p>
        <div className="rounded-lg border border-slate-100 bg-slate-50/60 px-4 py-3">
          <p className="font-mono text-xs text-slate-600">~/.config/hol-guard/guard.yaml</p>
          <p className="mt-1 text-xs text-slate-400">
            See the docs for repo_rules and env_rules configuration options.
          </p>
        </div>
      </div>
    </div>
  );
}
