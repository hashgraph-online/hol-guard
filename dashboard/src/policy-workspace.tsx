import { useCallback, useMemo, useState, type KeyboardEvent } from "react";
import { SectionLabel, Tag, ActionButton } from "./approval-center-primitives";
import type { GuardPolicyDecision, GuardRuntimeSnapshot } from "./guard-types";
import { PolicyCloudExceptionsTab } from "./policy-cloud-exceptions-tab";
import { PolicyRememberedRulesTab } from "./policy-remembered-rules-tab";
import { PolicyStrictConfigTab } from "./policy-strict-config-tab";
import {
  resolveCloudBundleSurfaceClass,
  resolveCloudPolicyBundleCopy,
  resolveCloudPolicyControlsUrl,
  resolveSecurityModeCopy,
} from "./policy-workspace-helpers";

export type PolicyPageView = "rules" | "exceptions" | "strict";

const POLICY_VIEWS: PolicyPageView[] = ["rules", "exceptions", "strict"];

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
  policies: GuardPolicyDecision[];
  snapshot: GuardRuntimeSnapshot;
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
  onOpenSettings?: () => void;
  onOpenInbox?: () => void;
  onRefreshPolicies?: () => void;
};

export function PolicyWorkspace({
  policies,
  snapshot,
  onClearPolicy,
  onOpenSettings,
  onOpenInbox,
}: PolicyWorkspaceProps) {
  const [activeView, setActiveView] = useState<PolicyPageView>("rules");

  const handleViewChange = useCallback((view: PolicyPageView) => {
    setActiveView(view);
  }, []);

  const handleOpenCloudExceptions = useCallback(() => {
    setActiveView("exceptions");
  }, []);

  const handleTabKeyDown = useCallback(
    (event: KeyboardEvent<HTMLButtonElement>, view: PolicyPageView) => {
      const index = POLICY_VIEWS.indexOf(view);
      if (index < 0) {
        return;
      }
      let nextView: PolicyPageView | undefined;
      if (event.key === "ArrowRight") {
        nextView = POLICY_VIEWS[(index + 1) % POLICY_VIEWS.length];
      } else if (event.key === "ArrowLeft") {
        nextView = POLICY_VIEWS[(index - 1 + POLICY_VIEWS.length) % POLICY_VIEWS.length];
      }
      if (nextView) {
        event.preventDefault();
        setActiveView(nextView);
        document.getElementById(`policy-tab-${nextView}`)?.focus();
      }
    },
    [],
  );

  const modeCopy = useMemo(() => resolveSecurityModeCopy(snapshot.security_level), [snapshot.security_level]);
  const cloudBundleCopy = useMemo(() => resolveCloudPolicyBundleCopy(snapshot), [snapshot]);

  return (
    <div className="space-y-6">
      {cloudBundleCopy ? (
        <div className={resolveCloudBundleSurfaceClass(cloudBundleCopy.tone)}>
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <SectionLabel>Guard Cloud bundle</SectionLabel>
            <Tag tone={cloudBundleCopy.tone}>{cloudBundleCopy.label}</Tag>
          </div>
          <p className="text-sm text-brand-dark/75">{cloudBundleCopy.detail}</p>
        </div>
      ) : null}

      <div className="rounded-2xl border border-brand-blue/10 bg-brand-blue/[0.03] p-5 shadow-sm">
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <SectionLabel>Active mode</SectionLabel>
          <Tag tone={modeCopy.tone}>{modeCopy.label}</Tag>
        </div>
        <p className="text-sm text-brand-dark/75">{modeCopy.description}</p>
        {onOpenSettings ? (
          <div className="mt-3">
            <ActionButton variant="secondary" onClick={onOpenSettings}>
              Open security settings
            </ActionButton>
          </div>
        ) : null}
      </div>

      <div
        className="flex flex-wrap gap-2 border-b border-slate-100 pb-3"
        role="tablist"
        aria-label="Policy sections"
      >
        {POLICY_VIEWS.map((view) => (
          <button
            key={view}
            type="button"
            role="tab"
            id={`policy-tab-${view}`}
            aria-controls={`policy-panel-${view}`}
            aria-selected={activeView === view}
            tabIndex={activeView === view ? 0 : -1}
            onClick={() => handleViewChange(view)}
            onKeyDown={(event) => handleTabKeyDown(event, view)}
            className={`rounded-full px-4 py-1.5 text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${
              activeView === view
                ? "bg-brand-blue text-white"
                : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
            }`}
          >
            {resolvePolicyViewLabel(view)}
          </button>
        ))}
      </div>

      {activeView === "rules" ? (
        <div id="policy-panel-rules" role="tabpanel" aria-labelledby="policy-tab-rules">
          <PolicyRememberedRulesTab
            policies={policies}
            cloudControlsUrl={resolveCloudPolicyControlsUrl(snapshot)}
            onClearPolicy={onClearPolicy}
            onOpenCloudExceptions={handleOpenCloudExceptions}
          />
        </div>
      ) : null}

      {activeView === "exceptions" ? (
        <div id="policy-panel-exceptions" role="tabpanel" aria-labelledby="policy-tab-exceptions">
          <PolicyCloudExceptionsTab snapshot={snapshot} />
        </div>
      ) : null}

      {activeView === "strict" ? (
        <div id="policy-panel-strict" role="tabpanel" aria-labelledby="policy-tab-strict">
          <PolicyStrictConfigTab snapshot={snapshot} onOpenSettings={onOpenSettings} onOpenInbox={onOpenInbox} />
        </div>
      ) : null}
    </div>
  );
}
