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
      description="Synced team rules are read-only here. Edit them in Guard Cloud Controls."
      policies={policies}
      cloudControlsUrl={cloudControlsUrl}
      emptyTitle="No Guard Cloud rules synced"
      emptyBody="Connect Guard Cloud to sync shared policy bundles."
      defaultOpen={policies.length > 0}
    />
  );
}
