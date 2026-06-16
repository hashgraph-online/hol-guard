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
};

export function PolicyRememberedLocalRules({
  policies,
  cloudControlsUrl,
  onClearPolicy,
  onNavigate,
  sort,
  onSortChange,
}: PolicyRememberedLocalRulesProps) {
  return (
    <GroupedPolicySection
      title="Remembered on this device"
      badge="Local rules"
      description="Decisions you've remembered on this machine."
      policies={policies}
      cloudControlsUrl={cloudControlsUrl}
      onClearPolicy={onClearPolicy}
      onNavigate={onNavigate}
      emptyTitle="No local remembered rules yet"
      emptyBody="Approve or block in Inbox and Guard remembers the decision here in plain language."
      defaultOpen
      sort={sort}
      onSortChange={onSortChange}
    />
  );
}
