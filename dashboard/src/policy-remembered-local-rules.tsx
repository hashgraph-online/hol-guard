import type { GuardPolicyDecision } from "./guard-types";
import { GroupedPolicySection } from "./policy-workspace-views";

type PolicyRememberedLocalRulesProps = {
  policies: GuardPolicyDecision[];
  cloudControlsUrl: string | null;
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
};

export function PolicyRememberedLocalRules({
  policies,
  cloudControlsUrl,
  onClearPolicy,
}: PolicyRememberedLocalRulesProps) {
  return (
    <GroupedPolicySection
      title="Remembered on this device"
      description="Choices you saved from Inbox. Each row shows the exact command or action Guard will remember, and where it applies."
      policies={policies}
      cloudControlsUrl={cloudControlsUrl}
      onClearPolicy={onClearPolicy}
      emptyTitle="No local remembered rules yet"
      emptyBody="Approve or block in Inbox and Guard remembers the decision here in plain language."
      defaultOpen
    />
  );
}
