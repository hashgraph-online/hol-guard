import { useCallback } from "react";

import {
  HiMiniCheckCircle,
  HiMiniExclamationCircle,
  HiMiniMinusCircle,
} from "react-icons/hi2";
import {
  ActionButton,
  Badge,
  EmptyState,
  SectionLabel,
  Tag,
} from "./approval-center-primitives";
import {
  buildHomePrimaryState,
  type HomeProtectionStatus,
} from "./queue-state";
import { harnessDisplayName } from "./approval-center-utils";
import type {
  GuardApprovalRequest,
  GuardManagedInstall,
  GuardPolicyDecision,
  GuardReceipt,
  GuardRuntimeSnapshot,
} from "./guard-types";

type HomeRequestState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardApprovalRequest[] };

type HomeRuntimeState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; snapshot: GuardRuntimeSnapshot };

type HomePolicyState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardPolicyDecision[] };

function heroBackgroundClass(status: HomeProtectionStatus): string {
  if (status === "needs_decision") {
    return "bg-[radial-gradient(circle_at_top_left,rgba(85,153,254,0.12),transparent_32%),linear-gradient(135deg,#ffffff_0%,#ffffff_58%,rgba(245,158,11,0.08)_100%)]";
  }
  if (status === "setup_needed") {
    return "bg-[radial-gradient(circle_at_top_left,rgba(85,153,254,0.12),transparent_32%),linear-gradient(135deg,#ffffff_0%,#ffffff_58%,rgba(85,153,254,0.06)_100%)]";
  }
  return "bg-[radial-gradient(circle_at_top_left,rgba(85,153,254,0.12),transparent_32%),linear-gradient(135deg,#ffffff_0%,#ffffff_58%,rgba(72,223,123,0.10)_100%)]";
}

function ClearHarnessButton(props: {
  harness: string;
  onClearPolicies: (scope: { harness?: string; all?: boolean }) => Promise<void>;
}) {
  const handleClick = useCallback(() => {
    void props.onClearPolicies({ harness: props.harness });
  }, [props.onClearPolicies, props.harness]);

  return (
    <ActionButton variant="ghost" onClick={handleClick}>
      Clear {props.harness}
    </ActionButton>
  );
}

export function HomeWorkspace(props: {
  requests: HomeRequestState;
  runtime: HomeRuntimeState;
  policies: HomePolicyState;
  onOpenInbox: () => void;
  onOpenFleet: () => void;
  onOpenEvidence: () => void;
  onOpenSettings: () => void;
  onClearPolicies: (scope: { harness?: string; all?: boolean }) => Promise<void>;
}) {
  const handleClearAll = useCallback(() => {
    void props.onClearPolicies({ all: true });
  }, [props.onClearPolicies]);

  if (props.runtime.kind === "loading" || props.requests.kind === "loading") {
    return (
      <div className="space-y-4">
        <div className="guard-skeleton h-36 w-full" />
        <div className="guard-skeleton h-16 w-full" />
      </div>
    );
  }

  if (props.runtime.kind === "error") {
    return (
      <EmptyState
        title="Guard is not connected"
        body={props.runtime.message}
        action={<ActionButton onClick={props.onOpenInbox}>Open review queue</ActionButton>}
      />
    );
  }

  const snapshot = props.runtime.snapshot;
  const queuedCount = props.requests.kind === "ready" ? props.requests.items.length : 0;
  const policyItems = props.policies.kind === "ready" ? props.policies.items : [];
  const managedInstalls = snapshot.managed_installs ?? [];
  const activeInstalls = managedInstalls.filter((item) => item.active);
  const observedHarnesses = Array.from(
    new Set([
      ...snapshot.items.map((item) => item.harness),
      ...snapshot.latest_receipts.map((receipt) => receipt.harness),
      ...policyItems.map((policy) => policy.harness),
    ])
  ).sort();
  const clearHarnesses =
    activeInstalls.length > 0 ? activeInstalls.map((install) => install.harness) : observedHarnesses;
  const watchedAppsCount = activeInstalls.length > 0 ? activeInstalls.length : observedHarnesses.length;
  const primaryState = buildHomePrimaryState(queuedCount, watchedAppsCount);

  return (
    <div className="space-y-6">
      <ProtectionHero
        status={primaryState.status}
        copy={primaryState.copy}
        ctaLabel={primaryState.ctaLabel}
        queuedCount={queuedCount}
        syncConfigured={snapshot.sync_configured}
        cloudState={snapshot.cloud_state}
        connectUrl={snapshot.connect_url}
        fleetUrl={snapshot.fleet_url}
        activeInstallsCount={activeInstalls.length}
        latestReceiptsCount={snapshot.latest_receipts.length}
        onOpenInbox={props.onOpenInbox}
        onOpenFleet={props.onOpenFleet}
      />

      <HomeStatusStrip
        queuedCount={queuedCount}
        watchedAppsCount={watchedAppsCount}
        savedChoicesCount={policyItems.length}
        onOpenEvidence={props.onOpenEvidence}
        onOpenSettings={props.onOpenSettings}
      />

      <AppsProtectedSection
        managedInstalls={managedInstalls}
        observedHarnesses={observedHarnesses}
      />

      {snapshot.latest_receipts.length > 0 && (
        <RecentProtectionSection receipts={snapshot.latest_receipts} />
      )}

      <section className="rounded-[1.75rem] border border-brand-blue/15 bg-brand-blue/[0.04] p-5 sm:p-6">
        <details className="group">
          <summary className="flex cursor-pointer select-none items-center justify-between gap-3 text-sm font-semibold text-brand-dark [&::-webkit-details-marker]:hidden">
            <span>Reset remembered decisions</span>
            <span className="text-brand-blue transition-transform group-open:rotate-90">›</span>
          </summary>
          <p className="mt-3 text-sm leading-relaxed text-muted-foreground">
            Clear remembered decisions when you want Guard to ask again next time. This does not remove your review history.
          </p>
          <div className="mt-4 flex flex-wrap gap-3">
            <ActionButton variant="outline" onClick={handleClearAll}>
              Clear all remembered decisions
            </ActionButton>
            {clearHarnesses.slice(0, 3).map((harness) => (
              <ClearHarnessButton
                key={harness}
                harness={harness}
                onClearPolicies={props.onClearPolicies}
              />
            ))}
          </div>
        </details>
      </section>
    </div>
  );
}

function ProtectionHero(props: {
  status: HomeProtectionStatus;
  copy: string;
  ctaLabel: string;
  queuedCount: number;
  syncConfigured: boolean;
  cloudState: "local_only" | "paired_waiting" | "paired_active";
  connectUrl: string;
  fleetUrl: string;
  activeInstallsCount: number;
  latestReceiptsCount: number;
  onOpenInbox: () => void;
  onOpenFleet: () => void;
}) {
  const handlePrimaryCta = useCallback(() => {
    if (props.status === "setup_needed") {
      props.onOpenFleet();
    } else {
      props.onOpenInbox();
    }
  }, [props.status, props.onOpenInbox, props.onOpenFleet]);

  const heroBg = heroBackgroundClass(props.status);
  const statusBadge =
    props.status === "needs_decision" ? (
      <Badge tone="default">{props.queuedCount} waiting</Badge>
    ) : props.status === "setup_needed" ? (
      <Badge tone="default">Setup needed</Badge>
    ) : (
      <Badge tone="success">Protected</Badge>
    );

  const showConnectCta =
    props.cloudState === "local_only" && !props.syncConfigured;

  const showTestProtection =
    props.activeInstallsCount > 0 && props.latestReceiptsCount === 0;

  return (
    <section
      className={`guard-surface-in relative overflow-hidden rounded-[2rem] border border-brand-blue/15 ${heroBg} p-5 shadow-[0_20px_60px_rgba(63,65,116,0.08)] sm:p-6 lg:p-7`}
    >
      <div className="pointer-events-none absolute right-10 top-8 h-24 w-24 rounded-full bg-brand-blue/20 blur-3xl" />
      <div className="relative space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <SectionLabel>Protection status</SectionLabel>
          {statusBadge}
          {props.cloudState !== "local_only" && <Tag tone="blue">Cloud synced</Tag>}
        </div>
        <h2 className="text-xl font-semibold tracking-tight text-brand-dark">{props.copy}</h2>
        <div className="flex flex-wrap gap-3">
          <ActionButton onClick={handlePrimaryCta}>{props.ctaLabel}</ActionButton>
          {showTestProtection && (
            <ActionButton href={props.fleetUrl} variant="secondary">
              Test protection
            </ActionButton>
          )}
          {showConnectCta && props.status !== "needs_decision" && (
            <ActionButton href={props.connectUrl} variant="secondary">
              Connect this machine
            </ActionButton>
          )}
        </div>
      </div>
    </section>
  );
}

function HomeStatusStrip(props: {
  queuedCount: number;
  watchedAppsCount: number;
  savedChoicesCount: number;
  onOpenEvidence: () => void;
  onOpenSettings: () => void;
}) {
  return (
    <div className="grid gap-3 sm:grid-cols-3">
      <HomeStatChip label="Needs your choice" value={props.queuedCount.toString()} />
      <HomeStatChip label="Apps watched" value={props.watchedAppsCount.toString()} />
      <details className="group rounded-[1.25rem] border border-white/80 bg-white/80 px-4 py-3 shadow-sm">
        <summary className="flex cursor-pointer select-none items-center justify-between [&::-webkit-details-marker]:hidden">
          <div>
            <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
              Remembered decisions
            </p>
            <p className="mt-1 text-2xl font-semibold tracking-tight text-brand-dark">
              {props.savedChoicesCount}
            </p>
          </div>
          <span className="text-brand-blue transition-transform group-open:rotate-90">›</span>
        </summary>
        <div className="mt-3 flex flex-wrap gap-2">
          <ActionButton variant="ghost" onClick={props.onOpenEvidence}>
            History
          </ActionButton>
          <ActionButton variant="ghost" onClick={props.onOpenSettings}>
            Settings
          </ActionButton>
        </div>
      </details>
    </div>
  );
}

function HomeStatChip(props: { label: string; value: string }) {
  return (
    <div className="rounded-[1.25rem] border border-white/80 bg-white/80 px-4 py-3 shadow-sm">
      <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
        {props.label}
      </p>
      <p className="mt-1 text-2xl font-semibold tracking-tight text-brand-dark">{props.value}</p>
    </div>
  );
}

type AppRowProps = {
  harness: string;
  install: GuardManagedInstall | undefined;
  isObserved: boolean;
};

function AppStatusIcon(props: { install: GuardManagedInstall | undefined; isObserved: boolean }) {
  if (props.install?.active === true) {
    return <HiMiniCheckCircle className="h-4 w-4 shrink-0 text-brand-green" aria-hidden="true" />;
  }
  if (props.install !== undefined && !props.install.active) {
    return <HiMiniExclamationCircle className="h-4 w-4 shrink-0 text-amber-500" aria-hidden="true" />;
  }
  if (props.isObserved) {
    return <HiMiniMinusCircle className="h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />;
  }
  return <HiMiniMinusCircle className="h-4 w-4 shrink-0 text-slate-300" aria-hidden="true" />;
}

function AppStatusBadge(props: { install: GuardManagedInstall | undefined; isObserved: boolean }) {
  if (props.install?.active === true) {
    return <Badge tone="success">Active</Badge>;
  }
  if (props.install !== undefined && !props.install.active) {
    return <Badge tone="default">Needs setup</Badge>;
  }
  if (props.isObserved) {
    return <Badge tone="default">Observed</Badge>;
  }
  return <Badge tone="default">Unknown</Badge>;
}

function AppRow(props: AppRowProps) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-slate-200/70 px-4 py-3 last:border-b-0">
      <div className="flex min-w-0 items-center gap-2.5">
        <AppStatusIcon install={props.install} isObserved={props.isObserved} />
        <p className="truncate text-sm font-medium text-brand-dark">
          {harnessDisplayName(props.harness)}
        </p>
      </div>
      <AppStatusBadge install={props.install} isObserved={props.isObserved} />
    </div>
  );
}

type AppsProtectedSectionProps = {
  managedInstalls: GuardManagedInstall[];
  observedHarnesses: string[];
};

function AppsProtectedSection(props: AppsProtectedSectionProps) {
  const allHarnesses = Array.from(
    new Set([
      ...props.managedInstalls.map((i) => i.harness),
      ...props.observedHarnesses,
    ])
  ).sort();

  if (allHarnesses.length === 0) {
    return (
      <section className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm sm:p-6">
        <SectionLabel>Apps protected</SectionLabel>
        <p className="mt-3 text-sm text-muted-foreground">
          None yet. Connect an AI harness to start.
        </p>
      </section>
    );
  }

  return (
    <section className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm sm:p-6">
      <SectionLabel>Apps protected</SectionLabel>
      <div className="mt-3 overflow-hidden rounded-[1.25rem] border border-slate-200/70">
        {allHarnesses.map((harness) => {
          const install = props.managedInstalls.find((i) => i.harness === harness);
          const isObserved = props.observedHarnesses.includes(harness);
          return (
            <AppRow
              key={harness}
              harness={harness}
              install={install}
              isObserved={isObserved}
            />
          );
        })}
      </div>
    </section>
  );
}

function formatReceiptTimestamp(timestamp: string): string {
  try {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    if (diffMins < 60) return `${diffMins}m ago`;
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${Math.floor(diffHours / 24)}d ago`;
  } catch {
    return timestamp;
  }
}

type RecentReceiptRowProps = {
  receipt: GuardReceipt;
};

function RecentReceiptRow(props: RecentReceiptRowProps) {
  const { receipt } = props;
  const decisionLabel = receipt.policy_decision === "allow" ? "allowed" : "blocked";
  const name = receipt.artifact_name ?? receipt.artifact_id;
  return (
    <div className="flex items-start justify-between gap-3 border-b border-slate-200/70 px-4 py-3 last:border-b-0">
      <div className="min-w-0">
        <p className="text-sm text-brand-dark">
          <span className="font-medium">{harnessDisplayName(receipt.harness)}</span>{" "}
          {decisionLabel}{" "}
          <span className="font-mono text-xs">{name}</span>
        </p>
      </div>
      <span className="shrink-0 text-[11px] text-muted-foreground">
        {formatReceiptTimestamp(receipt.timestamp)}
      </span>
    </div>
  );
}

type RecentProtectionSectionProps = {
  receipts: GuardReceipt[];
};

function RecentProtectionSection(props: RecentProtectionSectionProps) {
  const recent = props.receipts.slice(0, 3);
  return (
    <section className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm sm:p-6">
      <SectionLabel>Recent protection</SectionLabel>
      <div className="mt-3 overflow-hidden rounded-[1.25rem] border border-slate-200/70">
        {recent.map((receipt) => (
          <RecentReceiptRow key={receipt.receipt_id} receipt={receipt} />
        ))}
      </div>
    </section>
  );
}
