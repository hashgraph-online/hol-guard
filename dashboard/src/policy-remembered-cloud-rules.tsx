import type { GuardPolicyDecision } from "./guard-types";
import { GroupedPolicySection } from "./policy-workspace-views";

type PolicyRememberedCloudRulesProps = {
  policies: GuardPolicyDecision[];
  cloudControlsUrl: string | null;
};

export function PolicyRememberedCloudRules({
  policies,
  cloudControlsUrl,
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
      viewAllLabel="View all cloud rules ({count}) →"
    />
  );
}
