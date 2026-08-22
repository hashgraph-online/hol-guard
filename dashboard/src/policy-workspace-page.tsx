import { useCallback, useState, Suspense } from "react";
import type { GuardPolicyDecision, GuardRuntimeSnapshot } from "./guard-types";
import { WorkspacePageHeader } from "./workspace-page-header";
import { PolicyExceptionsToolbar, PolicyPageToolbar, PolicyUnderlineTabBar } from "./policy-page-chrome";
import type { PolicyPageView } from "./policy-workspace";
import { resolveCloudPolicyControlsUrl, resolveCloudExceptionsConnected } from "./policy-workspace-helpers";
import { lazyWorkspace } from "./lazy-workspace";

const PolicyWorkspace = lazyWorkspace(() =>
  import("./policy-workspace").then((module) => ({ default: module.PolicyWorkspace })),
);

function PolicyFallback() {
  return <div className="guard-skeleton h-40 w-full rounded-2xl" aria-busy="true" aria-live="polite" />;
}

export function resolveProtectionRulesPath(search: string): string {
  const params = new URLSearchParams({ section: "rules" });
  if (new URLSearchParams(search).get("demo") === "1") {
    params.set("demo", "1");
  }
  return `/settings?${params.toString()}`;
}

export function PolicyWorkspacePage(props: {
  snapshot: GuardRuntimeSnapshot;
  policies: GuardPolicyDecision[];
  onClearPolicy: (policy: GuardPolicyDecision) => void;
  onOpenSettings: (pathname?: string) => void;
  onOpenInbox: () => void;
  onRefreshPolicies: () => void;
  onNavigate?: (pathname: string) => void;
}) {
  const [activeView, setActiveView] = useState<PolicyPageView>("rules");
  const [reloading, setReloading] = useState(false);
  const [exceptionRequestOpen, setExceptionRequestOpen] = useState(false);
  const cloudControlsUrl = resolveCloudPolicyControlsUrl(props.snapshot);
  const cloudConnected = resolveCloudExceptionsConnected(props.snapshot);

  const handleOpenSettings = useCallback(() => {
    const settingsPath = resolveProtectionRulesPath(window.location.search);
    if (props.onNavigate) {
      props.onNavigate(settingsPath);
      return;
    }
    props.onOpenSettings(settingsPath);
  }, [props]);
  const handleOpenInbox = useCallback(() => props.onOpenInbox(), [props]);
  const handleViewChange = useCallback((view: PolicyPageView) => setActiveView(view), []);

  const handleReloadPolicy = useCallback(() => {
    setReloading(true);
    try {
      props.onRefreshPolicies();
    } finally {
      window.setTimeout(() => setReloading(false), 600);
    }
  }, [props]);

  return (
    <div className="space-y-6">
      <WorkspacePageHeader
        eyebrow="Rules & exceptions"
        title="Remembered decisions and exceptions"
        description="Review decisions remembered on this device, contextual rules synced from Guard Cloud, exceptions, and the order Guard uses to decide. Configure tools and capability posture in Extensions."
        actions={
          activeView === "exceptions" ? (
            <PolicyExceptionsToolbar
              cloudConnected={cloudConnected}
              cloudControlsUrl={cloudControlsUrl}
              connectUrl={props.snapshot.connect_url?.trim() || null}
              onRequestException={() => setExceptionRequestOpen(true)}
            />
          ) : (
            <PolicyPageToolbar
              snapshot={props.snapshot}
              onReloadPolicy={handleReloadPolicy}
              reloading={reloading}
            />
          )
        }
      />
      <PolicyUnderlineTabBar activeView={activeView} onViewChange={handleViewChange} />
      <Suspense fallback={<PolicyFallback />}>
        <PolicyWorkspace
          activeView={activeView}
          policies={props.policies}
          snapshot={props.snapshot}
          onClearPolicy={props.onClearPolicy}
          onOpenSettings={handleOpenSettings}
          onOpenInbox={handleOpenInbox}
          onOpenCloudExceptions={() => setActiveView("exceptions")}
          exceptionRequestOpen={exceptionRequestOpen}
          onExceptionRequestOpenChange={setExceptionRequestOpen}
          onReloadPolicy={handleReloadPolicy}
          reloadingPolicy={reloading}
          onNavigate={props.onNavigate}
        />
      </Suspense>
    </div>
  );
}
