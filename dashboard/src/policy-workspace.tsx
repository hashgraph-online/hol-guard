import type { GuardPolicyDecision, GuardRuntimeSnapshot } from "./guard-types";
import { PolicyCloudExceptionsTab } from "./policy-cloud-exceptions-tab";
import { PolicyRememberedRulesTab } from "./policy-remembered-rules-tab";
import { PolicyStrictConfigTab } from "./policy-strict-config-tab";
import { resolveCloudPolicyControlsUrl } from "./policy-workspace-helpers";

export type PolicyPageView = "rules" | "exceptions" | "strict";

export function resolvePolicyViewLabel(view: PolicyPageView): string {
  if (view === "rules") {
    return "Remembered rules";
  }
  if (view === "exceptions") {
    return "Cloud exceptions";
  }
  return "Strict config";
}

export {
  groupPoliciesByHarness,
  resolveSecurityModeCopy,
  resolveCloudPolicyBundleCopy,
} from "./policy-workspace-helpers";

type PolicyWorkspaceProps = {
  activeView: PolicyPageView;
  policies: GuardPolicyDecision[];
  snapshot: GuardRuntimeSnapshot;
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
  onOpenSettings?: () => void;
  onOpenInbox?: () => void;
  onOpenCloudExceptions?: () => void;
  exceptionRequestOpen?: boolean;
  onExceptionRequestOpenChange?: (open: boolean) => void;
  onReloadPolicy?: () => void;
  reloadingPolicy?: boolean;
};

export function PolicyWorkspace({
  activeView,
  policies,
  snapshot,
  onClearPolicy,
  onOpenSettings,
  onOpenInbox,
  onOpenCloudExceptions,
  exceptionRequestOpen = false,
  onExceptionRequestOpenChange,
  onReloadPolicy,
  reloadingPolicy = false,
}: PolicyWorkspaceProps) {
  if (activeView === "rules") {
    return (
      <div id="policy-panel-rules" role="tabpanel" aria-labelledby="policy-tab-rules">
        <PolicyRememberedRulesTab
          policies={policies}
          snapshot={snapshot}
          cloudControlsUrl={resolveCloudPolicyControlsUrl(snapshot)}
          onClearPolicy={onClearPolicy}
          onOpenCloudExceptions={onOpenCloudExceptions ?? (() => undefined)}
        />
      </div>
    );
  }

  if (activeView === "exceptions") {
    return (
      <div id="policy-panel-exceptions" role="tabpanel" aria-labelledby="policy-tab-exceptions">
        <PolicyCloudExceptionsTab
          snapshot={snapshot}
          requestOpen={exceptionRequestOpen}
          onRequestOpenChange={onExceptionRequestOpenChange}
        />
      </div>
    );
  }

  return (
    <div id="policy-panel-strict" role="tabpanel" aria-labelledby="policy-tab-strict">
      <PolicyStrictConfigTab
        snapshot={snapshot}
        onOpenSettings={onOpenSettings}
        onOpenInbox={onOpenInbox}
        onReloadPolicy={onReloadPolicy}
        reloadingPolicy={reloadingPolicy}
      />
    </div>
  );
}
