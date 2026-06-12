import { Suspense, lazy, useCallback } from "react";
import type { GuardPolicyDecision, GuardRuntimeSnapshot } from "./guard-types";
import { WorkspacePageHeader } from "./workspace-page-header";

const PolicyWorkspace = lazy(() =>
  import("./policy-workspace").then((module) => ({ default: module.PolicyWorkspace })),
);

function PolicyFallback() {
  return <div className="guard-skeleton h-40 w-full rounded-2xl" aria-busy="true" aria-live="polite" />;
}

export function PolicyWorkspacePage(props: {
  snapshot: GuardRuntimeSnapshot;
  policies: GuardPolicyDecision[];
  onClearPolicy: (policy: GuardPolicyDecision) => void;
  onOpenSettings: () => void;
  onOpenInbox: () => void;
  onRefreshPolicies: () => void;
}) {
  const handleOpenSettings = useCallback(() => props.onOpenSettings(), [props]);
  const handleOpenInbox = useCallback(() => props.onOpenInbox(), [props]);
  const handleRefresh = useCallback(() => props.onRefreshPolicies(), [props]);

  return (
    <div className="space-y-6">
      <WorkspacePageHeader
        eyebrow="Policy"
        title="Remembered rules and exceptions"
        description="See what Guard will do next time, in plain language. Remove local rules or add custom exceptions here."
      />
      <Suspense fallback={<PolicyFallback />}>
        <PolicyWorkspace
          policies={props.policies}
          snapshot={props.snapshot}
          onClearPolicy={props.onClearPolicy}
          onOpenSettings={handleOpenSettings}
          onOpenInbox={handleOpenInbox}
          onRefreshPolicies={handleRefresh}
        />
      </Suspense>
    </div>
  );
}
