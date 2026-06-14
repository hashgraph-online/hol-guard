import { useCallback, useMemo, useState } from "react";
import { SectionLabel, Tag, ActionButton } from "./approval-center-primitives";
import type { GuardPolicyDecision, GuardRuntimeSnapshot } from "./guard-types";
import { PolicyCloudExceptionsTab } from "./policy-cloud-exceptions-tab";
import { PolicyRememberedRulesTab } from "./policy-remembered-rules-tab";
import {
  resolveCloudBundleSurfaceClass,
  resolveCloudPolicyBundleCopy,
  resolveCloudPolicyControlsUrl,
  resolveSecurityModeCopy,
} from "./policy-workspace-helpers";

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

      <div className="flex flex-wrap gap-2 border-b border-slate-100 pb-3">
        {(["rules", "exceptions", "strict"] as const).map((view) => (
          <button
            key={view}
            type="button"
            onClick={() => handleViewChange(view)}
            aria-pressed={activeView === view}
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
        <PolicyRememberedRulesTab
          policies={policies}
          cloudControlsUrl={resolveCloudPolicyControlsUrl(snapshot)}
          onClearPolicy={onClearPolicy}
          onOpenCloudExceptions={handleOpenCloudExceptions}
        />
      ) : null}

      {activeView === "exceptions" ? <PolicyCloudExceptionsTab snapshot={snapshot} /> : null}

      {activeView === "strict" ? (
        <StrictModeView snapshot={snapshot} onOpenSettings={onOpenSettings} onOpenInbox={onOpenInbox} />
      ) : null}
    </div>
  );
}

function StrictModeView({
  snapshot,
  onOpenSettings,
  onOpenInbox,
}: {
  snapshot: GuardRuntimeSnapshot;
  onOpenSettings?: () => void;
  onOpenInbox?: () => void;
}) {
  const isStrict = snapshot.security_level === "strict";
  return (
    <div className="space-y-4">
      <div className={`rounded-2xl border p-5 ${isStrict ? "border-brand-green/20 bg-brand-green/[0.04]" : "border-slate-200 bg-slate-50/40"}`}>
        <div className="mb-2 flex items-center gap-2">
          <SectionLabel>Strict mode</SectionLabel>
          <Tag tone={isStrict ? "green" : "slate"}>{isStrict ? "Enabled" : "Disabled"}</Tag>
        </div>
        <p className="mb-4 text-sm text-brand-dark/75">
          Strict mode asks before new network connections, subprocess launches, file writes, and harness starts.
        </p>
        {!isStrict && onOpenSettings ? (
          <ActionButton variant="secondary" onClick={onOpenSettings}>
            Enable strict mode
          </ActionButton>
        ) : null}
      </div>
      {onOpenInbox ? (
        <ActionButton variant="secondary" onClick={onOpenInbox}>
          Review pending Inbox items
        </ActionButton>
      ) : null}
    </div>
  );
}
