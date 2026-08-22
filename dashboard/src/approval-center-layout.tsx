import { Suspense, useCallback, useState } from "react";
import type { ReactNode } from "react";

import type { AppView } from "./approval-center-primitives";
import { ShellFooter } from "./shell-footer";
import { ShellNavigation } from "./shell-navigation";
import { ReceiptsWorkspace } from "./receipts-workspace";
import { ReviewWorkspace } from "./review-workspace";
import { QueueConnectionError } from "./queue-connection-error";
import { ErrorBoundary } from "./error-boundary";
import { lazyWorkspace } from "./lazy-workspace";
import type { BulkGateCredentials } from "./approval-gate-utils";
import type {
  GuardApprovalGatePublicConfig,
  GuardApprovalRequest,
  GuardArtifactDiff,
  GuardCodexResumeResult,
  GuardInventoryItem,
  GuardPolicyDecision,
  GuardReceipt,
  GuardRuntimeSnapshot,
  DecisionScope,
} from "./guard-types";
import { useGuardUpdate } from "./guard-update-panel";
import { updateSettings } from "./guard-api";
import { WatchProtectionBanner } from "./watch-protection-banner";

const McpPolicyRequestPanel = lazyWorkspace(() =>
  import("./mcp-policy-request-panel").then((m) => ({ default: m.McpPolicyRequestPanel })),
);

type RequestState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardApprovalRequest[] };

type DetailState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "stale" }
  | {
      kind: "ready";
      item: GuardApprovalRequest;
      diff: GuardArtifactDiff | null;
      receipt: GuardReceipt | null;
      policy: GuardPolicyDecision[];
    }
  | { kind: "mcp-policy"; requestId: string };

type ReceiptsState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardReceipt[] };

type RuntimeState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; snapshot: GuardRuntimeSnapshot };

export type { BulkGateCredentials } from "./approval-gate-utils";

type LayoutProps = {
  view: AppView;
  requests: RequestState;
  detail: DetailState;
  receipts: ReceiptsState;
  runtime: RuntimeState;
  inventory: GuardInventoryItem[];
  activeRequestId: string | null;
  resolutionMessage: string | null;
  codexResume: GuardCodexResumeResult | null;
  approvalGate?: GuardApprovalGatePublicConfig | null;
  homeContent: ReactNode;
  fleetContent: ReactNode;
  settingsContent: ReactNode;
  extensionsContent: ReactNode;
  appDetailContent: ReactNode;
  supplyChainHubContent?: ReactNode;
  policyContent?: ReactNode;
  aboutContent?: ReactNode;
  onGoHome: () => void;
  onNavigate: (pathname: string) => void;
  onOpenRequest: (requestId: string) => void;
  onRetry?: () => void;
  onResolve: (payload: {
    requestId: string;
    action: "allow" | "block";
    scope: DecisionScope;
    workspace?: string;
    reason: string;
    approval_password?: string;
    approval_totp_code?: string;
    approval_gate_use_cooldown?: boolean;
    scope_contract_version?: string;
    scope_contract_digest?: string;
  }) => void;
  onBulkApprove?: (ids: string[], gateCredentials?: BulkGateCredentials) => void | Promise<void>;
  onRepair?: () => Promise<void>;
  onClearEvidence?: () => void;
  onRetryResume?: () => void;
  onGuardReconnected?: () => void;
  enableUpdateStatus?: boolean;
};

function InboxWatchBanner(props: { onRestored?: () => void; onOpenSettings: () => void }) {
  const handleTurnOn = useCallback(() => {
    void updateSettings({ protection_posture: "protected" })
      .then(() => {
        props.onRestored?.();
      })
      .catch(() => {
        props.onOpenSettings();
      });
  }, [props.onOpenSettings, props.onRestored]);
  return <WatchProtectionBanner onTurnProtectionOn={handleTurnOn} />;
}

function renderInboxContent(props: LayoutProps): ReactNode {
  if (props.requests.kind === "loading") {
    return (
      <div className="space-y-4" aria-busy="true" aria-live="polite">
        <div className="guard-skeleton h-8 w-64" />
        <div className="guard-skeleton h-32 w-full" />
        <div className="guard-skeleton h-48 w-full" />
      </div>
    );
  }
  if (props.requests.kind === "error") {
    return (
      <QueueConnectionError
        message={props.requests.message}
        approvalUrl={props.runtime.kind === "ready" ? props.runtime.snapshot.approval_center_url : null}
        onRetry={props.onRetry}
        onRepair={props.onRepair}
      />
    );
  }
  if (props.detail.kind === "mcp-policy") {
    return (
      <Suspense
        fallback={
          <div className="space-y-4" aria-busy="true" aria-live="polite">
            <div className="guard-skeleton h-8 w-72" />
            <div className="guard-skeleton h-24 w-full" />
            <div className="guard-skeleton h-40 w-full" />
          </div>
        }
      >
        <McpPolicyRequestPanel
          requestId={props.detail.requestId}
          approvalGate={props.approvalGate ?? null}
        />
      </Suspense>
    );
  }
  return (
    <ReviewWorkspace
      requests={props.requests.items}
      activeRequestId={props.activeRequestId}
      detail={
        props.detail.kind === "ready"
          ? {
              item: props.detail.item,
              diff: props.detail.diff,
              receipt: props.detail.receipt,
              policy: props.detail.policy,
            }
          : null
      }
      runtime={props.runtime.kind === "ready" ? props.runtime.snapshot : null}
      resolutionMessage={props.resolutionMessage}
      codexResume={props.codexResume}
      approvalGate={props.approvalGate ?? null}
      onOpenRequest={props.onOpenRequest}
      onResolve={props.onResolve}
      onGoHome={props.onGoHome}
      onRetryResume={props.onRetryResume}
      onBulkApprove={props.onBulkApprove}
    />
  );
}

function renderViewContent(props: LayoutProps): ReactNode {
  if (props.view === "home") {
    return props.homeContent;
  }
  if (props.view === "evidence") {
    return (
      <ReceiptsWorkspace
        receipts={props.receipts}
        runtime={props.runtime}
        onClearEvidence={props.onClearEvidence}
        onNavigate={props.onNavigate}
      />
    );
  }
  if (props.view === "fleet") {
    return props.fleetContent;
  }
  if (props.view === "app-detail") {
    return props.appDetailContent;
  }
  if (props.view === "extensions") {
    return props.extensionsContent;
  }
  if (props.view === "settings") {
    return props.settingsContent;
  }
  if (props.view === "about") {
    return props.aboutContent ?? null;
  }
  if (props.view === "policy") {
    return props.policyContent ?? null;
  }
  if (
    props.view === "supply-chain" ||
    props.view === "audit" ||
    props.view === "feed-health"
  ) {
    return props.supplyChainHubContent ?? null;
  }
  if (props.view === "inbox") {
    return renderInboxContent(props);
  }
  return null;
}

export function ApprovalCenterLayout(props: LayoutProps) {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    try {
      return localStorage.getItem("guard-sidebar-collapsed") === "true";
    } catch {
      return false;
    }
  });
  const queuedItems = props.requests.kind === "ready" ? props.requests.items : [];
  const needsFullQueue = props.view === "inbox";
  let queuedCount = 0;
  if (needsFullQueue && props.requests.kind === "ready") {
    queuedCount = queuedItems.length;
  } else if (props.runtime.kind === "ready") {
    queuedCount = props.runtime.snapshot.pending_count;
  } else {
    queuedCount = queuedItems.length;
  }

  const handleOpenSettings = useCallback(() => {
    props.onNavigate("/settings");
  }, [props.onNavigate]);

  const handleToggleSidebar = useCallback(() => {
    setSidebarCollapsed((previous) => {
      const next = !previous;
      try {
        localStorage.setItem("guard-sidebar-collapsed", String(next));
      } catch {
        // Local storage is optional in hardened browser contexts.
      }
      return next;
    });
  }, []);

  const {
    guardVersion,
    updateStatus,
    updatePhase,
    onUpdateGuard,
    onReinstallGuard,
  } = useGuardUpdate({ onReconnected: props.onGuardReconnected, enabled: props.enableUpdateStatus });

  return (
    <div className="min-h-screen bg-white text-brand-dark">
      <ShellNavigation
        queuedCount={queuedCount}
        view={props.view}
        collapsed={sidebarCollapsed}
        onToggleCollapse={handleToggleSidebar}
        onNavigate={props.onNavigate}
        guardVersion={guardVersion}
        updateStatus={updateStatus}
        updatePhase={updatePhase}
        onUpdateGuard={onUpdateGuard}
        onReinstallGuard={onReinstallGuard}
        approvalGate={props.approvalGate ?? null}
        cloudUserProfile={
          props.runtime.kind === "ready"
            ? props.runtime.snapshot.cloud_user_profile
            : null
        }
        workspaceId={
          props.runtime.kind === "ready"
            ? props.runtime.snapshot.cloud_pairing_state.workspace_id ?? null
            : null
        }
        planId={
          props.runtime.kind === "ready"
            ? props.runtime.snapshot.cloud_pairing_state.plan_id ?? null
            : null
        }
      />
      <div
        className="guard-shell-content flex flex-col"
        data-sidebar-collapsed={sidebarCollapsed ? "true" : "false"}
      >
        <main id="main-content" className="guard-shell-main flex-1" tabIndex={-1}>
          <div className="guard-shell-workspace" data-view={props.view}>
            {props.view === "inbox"
              && props.runtime.kind === "ready"
              && props.runtime.snapshot.protection_posture === "watch" ? (
              <div className="mb-4">
                <InboxWatchBanner
                  onRestored={props.onGuardReconnected}
                  onOpenSettings={handleOpenSettings}
                />
              </div>
            ) : null}
            <ErrorBoundary key={props.view} onReset={props.onGoHome}>
              {renderViewContent(props)}
            </ErrorBoundary>
          </div>
        </main>
        <ShellFooter />
      </div>
    </div>
  );
}
