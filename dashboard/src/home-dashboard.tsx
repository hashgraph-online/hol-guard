import { useCallback } from "react";

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
import type {
  GuardApprovalRequest,
  GuardPolicyDecision,
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
      <Badge tone="warning">{props.queuedCount} waiting</Badge>
    ) : props.status === "setup_needed" ? (
      <Badge tone="default">Setup needed</Badge>
    ) : (
      <Badge tone="success">Protected</Badge>
    );

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
          {props.cloudState === "local_only" && (
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
