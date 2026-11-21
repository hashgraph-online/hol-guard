import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ChangeEvent } from "react";
import { HiMiniAdjustmentsHorizontal, HiMiniArrowDownTray, HiMiniInbox, HiMiniMagnifyingGlass, HiMiniXMark } from "react-icons/hi2";
import { ActionButton, EmptyState } from "./approval-center-primitives";
import { harnessDisplayName, policyActionLabel } from "./approval-center-utils";
import type { GuardPolicyDecision, GuardRuntimeSnapshot } from "./guard-types";
import { downloadPolicies } from "./policy-export";
import {
  isCloudManagedPolicy,
  resolveCloudExceptionsConnected,
  resolvePolicyDisplay,
  resolvePolicyMatcherFamily,
  resolveSecurityModeCopy,
  type PolicySortState,
} from "./policy-workspace-helpers";
import { resolvePolicyGoverningExtensionId, resolvePolicyRowSourceLabel } from "./policy-managed-authority";
import { groupPoliciesByFamily, PolicyRuleTable, resolveFamilyFilterLabel } from "./policy-workspace-views";
import { StyledSelect } from "./styled-select";
import { PolicyRulesHero } from "./policy-rules-hero";
import { PolicyRulesListSwitch } from "./policy-rules-list-switch";
import { PolicyRulesAttentionStrip } from "./policy-rules-attention-strip";
import { PolicyRulesAbout } from "./policy-rules-about";
import { PolicyRuleInspector } from "./policy-rule-inspector";
import { buildRuleAttention, buildRulesHeroModel, heroCountsFrom } from "./policy-rules-hero-model";
import {
  countPolicyRules,
  filterPoliciesByAction,
  isBulkRemovablePolicy,
  policySelectionKey,
  prunePolicySelection,
  resolveRulesResultSummary,
  togglePolicySelection,
  type PolicyActionFilter,
} from "./policy-rules-overview-model";
import { buildRulesExceptionsView } from "./managed-controls/rules-exceptions-model";

type PolicyRememberedRulesTabProps = {
  policies: GuardPolicyDecision[];
  snapshot: GuardRuntimeSnapshot;
  cloudControlsUrl: string | null;
  onClearPolicy?: (policy: GuardPolicyDecision) => void | Promise<void>;
  onOpenCloudExceptions: () => void;
  onOpenInbox?: () => void;
  onNavigate?: (pathname: string) => void;
};

const SORT_OPTIONS = ["updated:desc", "updated:asc", "rule:asc", "action:asc", "app:asc"];

export function PolicyRememberedRulesTab({
  policies,
  snapshot,
  cloudControlsUrl,
  onClearPolicy,
  onOpenCloudExceptions,
  onOpenInbox,
  onNavigate,
}: PolicyRememberedRulesTabProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [appFilter, setAppFilter] = useState("");
  const [familyFilter, setFamilyFilter] = useState("");
  const [actionFilter, setActionFilter] = useState<PolicyActionFilter>("all");
  const [showMore, setShowMore] = useState(false);
  const [sort, setSort] = useState<PolicySortState>({ key: "updated", direction: "desc" });
  const [selectedKeys, setSelectedKeys] = useState<ReadonlySet<string>>(new Set());
  const [removingSelected, setRemovingSelected] = useState(false);
  const [removeError, setRemoveError] = useState<string | null>(null);
  const [inspectedKey, setInspectedKey] = useState<string | null>(null);
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

  const handleSearchChange = useCallback((event: ChangeEvent<HTMLInputElement>) => setSearchQuery(event.target.value), []);
  const handleClearSearch = useCallback(() => setSearchQuery(""), []);
  const handleToggleMore = useCallback(() => setShowMore((current) => !current), []);
  const handleClearFilters = useCallback(() => {
    setSearchQuery("");
    setAppFilter("");
    setFamilyFilter("");
    setActionFilter("all");
  }, []);

  const filteredPolicies = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    const byAction = filterPoliciesByAction(policies, actionFilter);
    return byAction.filter((policy) => {
      if (appFilter && policy.harness !== appFilter) return false;
      if (familyFilter) {
        const family = resolvePolicyMatcherFamily(policy) ?? "other";
        if (family !== familyFilter) return false;
      }
      if (!query) return true;
      const display = resolvePolicyDisplay(policy);
      const displayHaystack = [
        policy.harness, policy.artifact_id, policy.workspace, policy.publisher, policy.scope,
        policy.action, policy.reason, policy.remembered_command, policy.remembered_context,
        policy.workspace_label, policy.source_scope_path, policy.source_receipt_id,
        display.headline, display.kindLine, display.pathLine, display.projectLabel,
        display.rememberSentence, harnessDisplayName(policy.harness), policyActionLabel(policy.action),
      ].filter(Boolean).join(" ").toLowerCase();
      return displayHaystack.includes(query);
    });
  }, [policies, searchQuery, appFilter, familyFilter, actionFilter]);

  const rememberedRules = useMemo(
    () => filteredPolicies.filter((policy) => policy.action === "allow" || policy.action === "block"),
    [filteredPolicies],
  );
  const allRemembered = useMemo(
    () => policies.filter((policy) => policy.action === "allow" || policy.action === "block"),
    [policies],
  );
  const counts = useMemo(() => countPolicyRules(allRemembered), [allRemembered]);
  const appOptions = useMemo(
    () => [...new Set(policies.map((policy) => policy.harness).filter(Boolean))].sort(),
    [policies],
  );
  const familyCounts = useMemo(() => groupPoliciesByFamily(rememberedRules), [rememberedRules]);
  const rulesView = useMemo(() => buildRulesExceptionsView(rememberedRules.map((policy, index) => {
    const resolvedAuthority = resolvePolicyRowSourceLabel(policy);
    const authority = resolvedAuthority === "Trusted local tool" ? "Remembered on this device" : resolvedAuthority;
    return {
      id: String(policy.decision_id ?? `${policy.source}-${index}`),
      title: resolvePolicyDisplay(policy).headline,
      authority,
      extensionId: resolvePolicyGoverningExtensionId(policy) ?? undefined,
    };
  })), [rememberedRules]);

  const resultSummary = resolveRulesResultSummary({
    visible: rememberedRules.length,
    total: allRemembered.length,
    searchQuery, actionFilter, appFilter, familyFilter,
  });
  const hasActiveFilters = searchQuery.trim() !== "" || actionFilter !== "all" || appFilter !== "" || familyFilter !== "";

  const bulkRemovableRules = useMemo(
    () => rememberedRules.filter((policy) => isBulkRemovablePolicy(policy)),
    [rememberedRules],
  );
  useEffect(() => {
    setSelectedKeys((current) => prunePolicySelection(current, bulkRemovableRules));
  }, [bulkRemovableRules]);

  const handleToggleSelect = useCallback((policy: GuardPolicyDecision) => {
    setSelectedKeys((current) => togglePolicySelection(current, policySelectionKey(policy)));
  }, []);
  const handleClearSelection = useCallback(() => {
    setSelectedKeys(new Set());
    setRemoveError(null);
  }, []);
  const handleRemoveSelected = useCallback(async () => {
    if (!onClearPolicy || removingSelected) return;
    const targets = bulkRemovableRules.filter((policy) => selectedKeys.has(policySelectionKey(policy)));
    if (targets.length === 0) return;
    setRemovingSelected(true);
    setRemoveError(null);
    const failed = new Set<string>();
    // Sequential: each clear refetches the policy list, so parallel clears can
    // resolve out of order and resurrect rules that were already removed.
    for (const policy of targets) {
      try {
        await onClearPolicy(policy);
      } catch {
        failed.add(policySelectionKey(policy));
      }
    }
    setSelectedKeys(failed);
    if (failed.size > 0) {
      setRemoveError(
        failed.size === 1
          ? "1 rule could not be removed. It is still selected — try again."
          : `${failed.size} rules could not be removed. They are still selected — try again.`,
      );
    }
    setRemovingSelected(false);
  }, [bulkRemovableRules, onClearPolicy, removingSelected, selectedKeys]);

  const handleExportCsv = useCallback(() => downloadPolicies("csv", rememberedRules), [rememberedRules]);
  const handleExportJson = useCallback(() => downloadPolicies("json", rememberedRules), [rememberedRules]);

  const modeCopy = resolveSecurityModeCopy(snapshot.protection_posture ?? snapshot.security_level);
  const cloudConnected = resolveCloudExceptionsConnected(snapshot);
  const attention = useMemo(() => buildRuleAttention(allRemembered, new Date()), [allRemembered]);
  const heroModel = useMemo(
    () =>
      buildRulesHeroModel({
        counts: heroCountsFrom(allRemembered),
        attention,
        protectionLabel: modeCopy.label,
        cloudConnected,
        pendingCount: snapshot.queue_summary?.remaining_pending_count ?? snapshot.pending_count ?? 0,
      }),
    [allRemembered, attention, cloudConnected, modeCopy.label, snapshot.pending_count, snapshot.queue_summary],
  );

  const inspectedPolicy = useMemo(
    () => allRemembered.find((policy) => policySelectionKey(policy) === inspectedKey) ?? null,
    [allRemembered, inspectedKey],
  );
  const handleInspect = useCallback((policy: GuardPolicyDecision) => setInspectedKey(policySelectionKey(policy)), []);
  const handleCloseInspector = useCallback(() => setInspectedKey(null), []);

  const sortValue = sort ? `${sort.key}:${sort.direction}` : "updated:desc";
  const sortIsCustom = !SORT_OPTIONS.includes(sortValue);

  return (
    <div className="space-y-4">
      <PolicyRulesHero model={heroModel} />

      <PolicyRulesAttentionStrip broadAllows={attention.broadAllows} onInspect={handleInspect} />

      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex min-w-0 flex-1 items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-3 py-2 focus-within:border-brand-blue/40 focus-within:ring-2 focus-within:ring-brand-blue/20 sm:max-w-md">
            <HiMiniMagnifyingGlass className="h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />
            <input
              ref={searchInputRef}
              type="search"
              placeholder="Search remembered rules…"
              value={searchQuery}
              onChange={handleSearchChange}
              aria-label="Search remembered rules"
              className="w-full min-w-0 bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none"
            />
            {searchQuery ? (
              <button type="button" onClick={handleClearSearch} aria-label="Clear search" className="shrink-0 rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-brand-dark">
                <HiMiniXMark className="h-4 w-4" aria-hidden="true" />
              </button>
            ) : (
              <kbd className="hidden shrink-0 rounded-md border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[10px] font-medium text-slate-500 sm:inline">⌘K</kbd>
            )}
          </div>
          <PolicyRulesListSwitch
            value={actionFilter}
            counts={{ all: counts.total, allow: counts.allow, block: counts.block }}
            onChange={setActionFilter}
          />
          <button
            type="button"
            onClick={handleToggleMore}
            aria-expanded={showMore}
            className={`inline-flex min-h-10 items-center gap-1.5 rounded-xl border px-3 py-2 text-sm font-medium transition-colors ${
              showMore || appFilter || familyFilter
                ? "border-brand-blue/30 bg-brand-blue/[0.04] text-brand-dark"
                : "border-slate-200 bg-white text-brand-dark hover:border-brand-blue/20"
            }`}
          >
            <HiMiniAdjustmentsHorizontal className="h-4 w-4 text-slate-500" aria-hidden="true" />
            More{(appFilter || familyFilter) ? " (active)" : ""}
          </button>
          {hasActiveFilters ? (
            <button type="button" onClick={handleClearFilters} className="min-h-9 px-1 text-sm font-medium text-brand-blue hover:underline">
              Clear
            </button>
          ) : null}
        </div>

        {resultSummary && rememberedRules.length > 0 ? (
          <p className="text-sm text-slate-600" role="status">{resultSummary}</p>
        ) : null}

        {showMore ? (
          <div className="flex flex-wrap items-center gap-2 rounded-xl bg-slate-50/70 p-2">
            <StyledSelect value={appFilter} onChange={(event) => setAppFilter(event.target.value)} aria-label="Filter by app" className="min-h-9 text-xs font-medium">
              <option value="">All assets</option>
              {appOptions.map((app) => (
                <option key={app} value={app}>{harnessDisplayName(app)}</option>
              ))}
            </StyledSelect>
            <StyledSelect value={familyFilter} onChange={(event) => setFamilyFilter(event.target.value)} aria-label="Filter by action type" className="min-h-9 text-xs font-medium">
              <option value="">All action types</option>
              {[...familyCounts.entries()].map(([family, count]) => (
                <option key={family} value={family}>{resolveFamilyFilterLabel(family)} ({count})</option>
              ))}
            </StyledSelect>
            <StyledSelect
              value={sortValue}
              onChange={(event) => {
                const [key, direction] = event.target.value.split(":");
                setSort({ key: key as "updated" | "rule" | "action" | "app" | "source", direction: direction as "asc" | "desc" });
              }}
              aria-label="Sort rules"
              className="min-h-9 text-xs font-medium"
            >
              {sortIsCustom ? <option value={sortValue}>Custom (column sort)</option> : null}
              <option value="updated:desc">Newest first</option>
              <option value="updated:asc">Oldest first</option>
              <option value="rule:asc">Rule A–Z</option>
              <option value="action:asc">Action A–Z</option>
              <option value="app:asc">App A–Z</option>
            </StyledSelect>
            <span className="mx-1 hidden h-5 w-px bg-slate-200 sm:block" aria-hidden="true" />
            <ActionButton variant="secondary" onClick={handleExportCsv}>
              <HiMiniArrowDownTray className="mr-1.5 h-4 w-4" aria-hidden="true" />
              Export CSV
            </ActionButton>
            <ActionButton variant="secondary" onClick={handleExportJson}>
              <HiMiniArrowDownTray className="mr-1.5 h-4 w-4" aria-hidden="true" />
              Export JSON
            </ActionButton>
          </div>
        ) : null}
      </div>

      <div id="remembered-rules-list" className="scroll-mt-4">
        {/* Mounted whatever the result count is: a live region that appears
            with its text already in it is not announced. */}
        <p role="status" className="sr-only">
          {rememberedRules.length === 0 && allRemembered.length > 0 ? "No rules match the current search and filters." : ""}
        </p>
        {rememberedRules.length === 0 && allRemembered.length > 0 ? (
          <div>
            <EmptyState
              title="No rules match"
              body="Nothing here matches the current search and filters. Clear them to see every remembered rule."
              tone="teach"
              action={
                <ActionButton variant="secondary" onClick={handleClearFilters}>Clear search and filters</ActionButton>
              }
            />
          </div>
        ) : (
          <PolicyRuleTable
            policies={rememberedRules}
            cloudControlsUrl={cloudControlsUrl}
            onClearPolicy={onClearPolicy}
            onNavigate={onNavigate}
            emptyTitle="No remembered rules yet"
            emptyBody="Approve or block in Inbox and Guard remembers the decision here in plain language."
            emptyAction={
              hasActiveFilters ? undefined : onOpenInbox ? (
                <ActionButton variant="primary" onClick={onOpenInbox}>
                  <HiMiniInbox className="mr-1.5 h-4 w-4" aria-hidden="true" />
                  Review pending requests
                </ActionButton>
              ) : undefined
            }
            sort={sort}
            onSortChange={setSort}
            selectedKeys={selectedKeys}
            onToggleSelect={onClearPolicy ? handleToggleSelect : undefined}
            onClearSelection={handleClearSelection}
            onRemoveSelected={onClearPolicy ? handleRemoveSelected : undefined}
            removingSelected={removingSelected}
            removeError={removeError}
            onInspect={handleInspect}
          />
        )}
      </div>

      <PolicyRulesAbout
        snapshot={snapshot}
        decisionOrder={rulesView.decisionOrder}
        onOpenCloudExceptions={onOpenCloudExceptions}
        onNavigate={onNavigate}
      />

      {inspectedPolicy ? (
        <PolicyRuleInspector
          policy={inspectedPolicy}
          cloudControlsUrl={cloudControlsUrl}
          onClose={handleCloseInspector}
          onClear={onClearPolicy}
          onNavigate={onNavigate}
        />
      ) : null}
    </div>
  );
}
