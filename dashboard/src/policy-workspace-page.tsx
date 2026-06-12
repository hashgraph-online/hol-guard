import { lazy, Suspense } from "react";
import type { GuardPolicyDecision, GuardRuntimeSnapshot } from "./guard-types";
import { SUPPLY_CHAIN_WORKSPACE_SHELL_CLASS } from "./supply-chain-workspace-layout";

const PolicyWorkspace = lazy(() =>
  import("./policy-workspace").then((module) => ({ default: module.PolicyWorkspace })),
);

type PolicyWorkspacePageProps = {
  policies: GuardPolicyDecision[];
  snapshot: GuardRuntimeSnapshot;
  onClearPolicy: (policy: GuardPolicyDecision) => void;
  onOpenSettings: () => void;
  onOpenInbox: () => void;
};

function LazyFallback() {
  return (
    <div className="flex min-h-[200px] items-center justify-center">
      <div className="guard-skeleton h-8 w-48" />
    </div>
  );
}

export function PolicyWorkspacePage(props: PolicyWorkspacePageProps) {
  return (
    <div className={`${SUPPLY_CHAIN_WORKSPACE_SHELL_CLASS} space-y-6`} data-testid="policy-workspace-page">
      <header className="space-y-1">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Guard</p>
        <h1 className="text-2xl font-semibold tracking-tight text-brand-dark">Policy</h1>
        <p className="max-w-2xl text-sm text-slate-500">
          Remembered decisions, Guard Cloud bundle rules, and strict-mode posture for this device.
        </p>
      </header>
      <Suspense fallback={<LazyFallback />}>
        <PolicyWorkspace
          policies={props.policies}
          snapshot={props.snapshot}
          onClearPolicy={props.onClearPolicy}
          onOpenSettings={props.onOpenSettings}
          onOpenInbox={props.onOpenInbox}
        />
      </Suspense>
    </div>
  );
}
