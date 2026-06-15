import type { GuardPolicyDecision } from "./guard-types";
import { GroupedPolicySection } from "./policy-workspace-views";

type PolicyRememberedLocalRulesProps = {
  policies: GuardPolicyDecision[];
  cloudControlsUrl: string | null;
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
  onNavigate?: (pathname: string) => void;
};

export function PolicyRememberedLocalRules({
  policies,
  cloudControlsUrl,
  onClearPolicy,
  onNavigate,
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
      viewAllLabel="View all local rules ({count}) →"
    />
  );
}
