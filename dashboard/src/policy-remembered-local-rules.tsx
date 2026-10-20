import type { GuardPolicyDecision } from "./guard-types";
import type { PolicySortState } from "./policy-workspace-helpers";
import { GroupedPolicySection } from "./policy-workspace-views";

type PolicyRememberedLocalRulesProps = {
  policies: GuardPolicyDecision[];
  cloudControlsUrl: string | null;
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
  onNavigate?: (pathname: string) => void;
  sort: PolicySortState;
  onSortChange: (sort: PolicySortState) => void;
  emptyAction?: React.ReactNode;
  selectedKeys?: ReadonlySet<string>;
  onToggleSelect?: (policy: GuardPolicyDecision) => void;
  onClearSelection?: () => void;
  onRemoveSelected?: () => void;
  removingSelected?: boolean;
  removeError?: string | null;
  onInspect?: (policy: GuardPolicyDecision) => void;
};

export function PolicyRememberedLocalRules({
  policies,
  cloudControlsUrl,
  onClearPolicy,
  onNavigate,
  sort,
  onSortChange,
  emptyAction,
  selectedKeys,
  onToggleSelect,
  onClearSelection,
  onRemoveSelected,
  removingSelected,
  removeError,
  onInspect,
}: PolicyRememberedLocalRulesProps) {
  return (
    <GroupedPolicySection
      title="Remembered on this device"
      badge="Local rules"
      description="Decisions you've remembered on this machine. Remove one and Guard asks again next time."
      policies={policies}
      cloudControlsUrl={cloudControlsUrl}
      onClearPolicy={onClearPolicy}
      onNavigate={onNavigate}
      emptyTitle="No local remembered rules yet"
      emptyBody="Approve or block in Inbox and Guard remembers the decision here in plain language."
      emptyAction={emptyAction}
      defaultOpen
      sort={sort}
      onSortChange={onSortChange}
      selectedKeys={selectedKeys}
      onToggleSelect={onToggleSelect}
      onClearSelection={onClearSelection}
      onRemoveSelected={onRemoveSelected}
      removingSelected={removingSelected}
      removeError={removeError}
      onInspect={onInspect}
    />
  );
}
