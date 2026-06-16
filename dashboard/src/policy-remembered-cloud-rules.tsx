import type { GuardPolicyDecision } from "./guard-types";
import type { PolicySortState } from "./policy-workspace-helpers";
import { GroupedPolicySection } from "./policy-workspace-views";

type PolicyRememberedCloudRulesProps = {
  policies: GuardPolicyDecision[];
  cloudControlsUrl: string | null;
  sort: PolicySortState;
  onSortChange: (sort: PolicySortState) => void;
};

export function PolicyRememberedCloudRules({
  policies,
  cloudControlsUrl,
  sort,
  onSortChange,
}: PolicyRememberedCloudRulesProps) {
  return (
    <GroupedPolicySection
      title="From Guard Cloud"
      badge="Team policy rules"
      description="Managed by your team in Guard Cloud. These rules are read-only locally."
      policies={policies}
      cloudControlsUrl={cloudControlsUrl}
      emptyTitle="No Guard Cloud rules synced"
      emptyBody="Connect Guard Cloud to sync shared policy bundles."
      defaultOpen={policies.length > 0}
      cloudVariant
      sort={sort}
      onSortChange={onSortChange}
    />
  );
}
