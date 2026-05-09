import { ActionButton, Badge, KeyValueGrid, SectionLabel, Surface, Tag } from "./approval-center-primitives";
import { harnessDisplayName } from "./approval-center-utils";
import type { GuardCloudSyncHealth, GuardInventoryItem, GuardReceipt, GuardRuntimeSnapshot } from "./guard-types";

const WATCHED_HARNESSES = ["codex", "claude-code", "opencode", "copilot", "gemini", "cursor", "hermes", "openclaw"] as const;

type WatchedHarnessName = (typeof WATCHED_HARNESSES)[number];

type RuntimeOverviewProps = {
  snapshot: GuardRuntimeSnapshot;
  inventory?: GuardInventoryItem[];
};

function headlineTone(state: GuardRuntimeSnapshot["headline_state"]): "info" | "success" | "warning" | "destructive" {
  if (state === "blocked") {
    return "destructive";
  }
  if (state === "connected" || state === "local_only") {
    return "info";
  }
  if (state === "protected") {
    return "success";
  }
  return "warning";
}

function remediationLine(snapshot: GuardRuntimeSnapshot): string {
  if (snapshot.runtime_state === null) {
    return "Start Guard with hol-guard bootstrap so the approval center can receive live requests again.";
  }
  if (snapshot.pending_count > 0) {
    return "Open the review queue, choose what to do with the blocked action, then retry in the same chat.";
  }
  if (snapshot.cloud_state === "paired_waiting") {
    return "Open Guard Cloud while the first protected session lands and this machine finishes syncing.";
  }
  if (snapshot.cloud_state === "local_only") {
    return "Stay local for now or connect this machine when you want shared queue memory and cross-device proof.";
  }
  return "Open Guard Cloud for shared decisions, Watched Apps for local coverage, or the review queue when something needs your choice.";
}

export type ApprovalCenterHealthState = "ready" | "starting" | "stale" | "repair_needed";

export type ApprovalCenterHealthCopy = {
  state: ApprovalCenterHealthState;
  label: string;
  detail: string;
};

export function resolveApprovalCenterHealth(snapshot: GuardRuntimeSnapshot): ApprovalCenterHealthCopy {
  if (snapshot.runtime_state === null) {
    if (snapshot.headline_state === "setup") {
      return {
        state: "starting",
        label: "Approval center starting",
        detail: "Guard is setting up the local approval center. This takes a few seconds.",
      };
    }
    return {
      state: "stale",
      label: "Approval center offline",
      detail: "The local approval center is not running. Start Guard to restore the approval link.",
    };
  }
  if (snapshot.approval_center_url === null) {
    return {
      state: "repair_needed",
      label: "Approval center unreachable",
      detail: "The approval center URL is missing. Use the repair action in Settings to restore it.",
    };
  }
  return {
    state: "ready",
    label: "Approval center ready",
    detail: `The approval center is running and accepting requests at ${snapshot.approval_center_url}.`,
  };
}


export function resolveCloudSyncHealthCopy(health: GuardCloudSyncHealth): { label: string; detail: string } {
  return {
    label: health.label,
    detail: health.detail
  };
}

export function resolveProtectionLevelCopy(level: "balanced" | "strict" | "custom" | "gentle" | "paranoid"): string {
  if (level === "gentle") {
    return "Monitors quietly, asks only for high-risk actions";
  }
  if (level === "balanced") {
    return "Asks before secrets and destructive commands";
  }
  if (level === "strict") {
    return "Asks more often, including new network";
  }
  if (level === "paranoid") {
    return "Asks before nearly every action";
  }
  return "Custom rules active";
}

export function resolveCloudIntelCopy(state: "local_only" | "paired_waiting" | "paired_active"): { label: string; detail: string } {
  if (state === "local_only") {
    return { label: "Offline, free", detail: "Running locally with no cloud sync. Your choices stay on this machine." };
  }
  if (state === "paired_waiting") {
    return { label: "Pairing…", detail: "Connected to Guard Cloud, waiting for sync to start." };
  }
  return { label: "Synced, pro", detail: "Guard Cloud is active and syncing choices across your devices." };
}

function cloudSyncHealthTone(state: GuardCloudSyncHealth["state"]): "blue" | "slate" {
  if (state === "disabled" || state === "failed" || state === "stale") {
    return "slate";
  }
  return "blue";
}

function humanizeCloudSyncHealthLabel(label: string): string {
  const labels: Record<string, string> = {
    "Cloud sync stale": "Your protection history hasn't synced recently",
  };
  return labels[label] ?? label;
}

function CloudSyncHealthCard(props: { health: GuardCloudSyncHealth }) {
  const copy = resolveCloudSyncHealthCopy(props.health);
  return (
    <div className="rounded-xl border border-border bg-white px-5 py-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-brand-blue">
          Cloud sync health
        </p>
        <Tag tone={cloudSyncHealthTone(props.health.state)}>{humanizeCloudSyncHealthLabel(copy.label)}</Tag>
      </div>
      <p className="mt-2 text-sm leading-relaxed text-brand-dark/80">{copy.detail}</p>
    </div>
  );
}

function approvalHealthTone(state: ApprovalCenterHealthState): "green" | "blue" | "slate" | "red" {
  if (state === "ready") return "green";
  if (state === "starting") return "blue";
  if (state === "repair_needed") return "red";
  return "slate";
}

function ApprovalCenterHealthCard(props: { snapshot: GuardRuntimeSnapshot }) {
  const copy = resolveApprovalCenterHealth(props.snapshot);
  return (
    <div className="rounded-xl border border-border bg-white px-5 py-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-brand-blue">
          Approval center health
        </p>
        <Tag tone={approvalHealthTone(copy.state)}>{copy.label}</Tag>
      </div>
      <p className="mt-2 text-sm leading-relaxed text-brand-dark/80">{copy.detail}</p>
    </div>
  );
}

function WatchedAppsCard(props: { inventory: GuardInventoryItem[] | undefined }) {
  const inventory = props.inventory ?? [];
  return (
    <div className="rounded-xl border border-border bg-white px-5 py-4">
      <p className="text-xs font-semibold uppercase tracking-[0.18em] text-brand-blue">Watched apps</p>
      <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
        {WATCHED_HARNESSES.map((harness) => {
          const found = inventory.some((item) => item.harness === harness);
          return (
            <WatchedHarnessChip key={harness} harness={harness} installed={found} />
          );
        })}
      </div>
    </div>
  );
}

function WatchedHarnessChip(props: { harness: WatchedHarnessName; installed: boolean }) {
  return (
    <div className={"flex items-center justify-between gap-2 rounded-lg border px-3 py-2 " + (props.installed ? "border-green-200 bg-green-50" : "border-slate-200 bg-slate-50")}>
      <span className="text-xs font-semibold text-brand-dark">{harnessDisplayName(props.harness)}</span>
      <Tag tone={props.installed ? "green" : "slate"}>{props.installed ? "seen" : "—"}</Tag>
    </div>
  );
}

function ProtectionLevelCard(props: { securityLevel: "balanced" | "strict" | "custom" | "gentle" | "paranoid" | undefined }) {
  const level = props.securityLevel ?? "balanced";
  const copy = resolveProtectionLevelCopy(level);
  const toneClass = level === "strict" ? "text-brand-purple" : level === "balanced" ? "text-brand-blue" : "text-slate-500";
  return (
    <div className="rounded-xl border border-border bg-white px-5 py-4">
      <p className="text-xs font-semibold uppercase tracking-[0.18em] text-brand-blue">Protection level</p>
      <p className={"mt-2 text-base font-semibold capitalize " + toneClass}>{level}</p>
      <p className="mt-1 text-sm leading-relaxed text-brand-dark/80">{copy}</p>
    </div>
  );
}

function RecentProtectionCard(props: { receipt: GuardReceipt | undefined }) {
  if (!props.receipt) {
    return (
      <div className="rounded-xl border border-border bg-white px-5 py-4">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-brand-blue">Recent protection</p>
        <p className="mt-2 text-sm leading-relaxed text-brand-dark/60">No recent activity yet.</p>
      </div>
    );
  }
  const { receipt } = props;
  const name = receipt.artifact_name ?? receipt.artifact_id;
  const decisionTone = receipt.policy_decision === "allow" ? "green" : receipt.policy_decision === "block" ? "purple" : "blue";
  const relativeTime = formatRelativeTime(receipt.timestamp);
  return (
    <div className="rounded-xl border border-border bg-white px-5 py-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-brand-blue">Recent protection</p>
        <Tag tone={decisionTone}>{receipt.policy_decision}</Tag>
      </div>
      <p className="mt-2 truncate text-sm font-semibold text-brand-dark">{name}</p>
      <p className="mt-1 text-xs text-muted-foreground">{relativeTime}</p>
    </div>
  );
}

function CloudIntelCard(props: { cloudState: "local_only" | "paired_waiting" | "paired_active"; connectUrl: string }) {
  const copy = resolveCloudIntelCopy(props.cloudState);
  const tone = props.cloudState === "paired_active" ? "green" : props.cloudState === "paired_waiting" ? "blue" : "slate";
  return (
    <div className="rounded-xl border border-border bg-white px-5 py-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-brand-blue">Cloud intel</p>
        <Tag tone={tone}>{copy.label}</Tag>
      </div>
      <p className="mt-2 text-sm leading-relaxed text-brand-dark/80">{copy.detail}</p>
      {props.cloudState === "local_only" ? (
        <div className="mt-3">
          <ActionButton href={props.connectUrl} variant="secondary">Connect this machine</ActionButton>
        </div>
      ) : null}
    </div>
  );
}

function formatRelativeTime(timestamp: string): string {
  const diffMs = Date.now() - new Date(timestamp).getTime();
  const diffMin = Math.floor(diffMs / 60000);
  if (diffMin < 1) {
    return "just now";
  }
  if (diffMin < 60) {
    return diffMin + "m ago";
  }
  const diffH = Math.floor(diffMin / 60);
  if (diffH < 24) {
    return diffH + "h ago";
  }
  return Math.floor(diffH / 24) + "d ago";
}

export function RuntimeOverview(props: RuntimeOverviewProps) {
  const { snapshot, inventory } = props;
  const securityLevel = snapshot.security_level;
  const latestReceipt = snapshot.latest_receipts[0];
  const daemonHealthLabel = snapshot.runtime_state !== null ? "running" : "offline";
  const resolvedInventory = inventory ?? snapshot.inventory ?? [];

  return (
    <Surface className="mb-6" tone="accent">
      <div className="flex flex-col gap-5">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <SectionLabel>Local status</SectionLabel>
              <Badge tone={headlineTone(snapshot.headline_state)}>{snapshot.headline_label}</Badge>
              <Tag tone={snapshot.cloud_state === "local_only" ? "slate" : "blue"}>
                {snapshot.cloud_state_label}
              </Tag>
              <Tag tone={snapshot.runtime_state !== null ? "green" : "slate"}>
                daemon {daemonHealthLabel}
              </Tag>
            </div>
            <div className="space-y-2">
              <h2 className="text-lg font-semibold tracking-tight text-brand-dark">
                HOL Guard is running locally.
              </h2>
              <p className="max-w-3xl text-sm leading-relaxed text-brand-dark/75">
                {snapshot.headline_detail}
              </p>
              <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">
                {snapshot.cloud_state_detail}
              </p>
            </div>
          </div>
          <KeyValueGrid
            columns={2}
            items={[
              ["Review queue", snapshot.pending_count + " waiting"],
              ["Saved choices", snapshot.receipt_count + " stored"],
              ["Watched apps", resolvedInventory.length + " seen"],
              ["Session", snapshot.runtime_state?.session_id.slice(0, 8) ?? "offline"],
            ]}
          />
        </div>

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <WatchedAppsCard inventory={resolvedInventory} />
          <ProtectionLevelCard securityLevel={securityLevel} />
          <RecentProtectionCard receipt={latestReceipt} />
          <CloudIntelCard cloudState={snapshot.cloud_state} connectUrl={snapshot.connect_url} />
        </div>

        <CloudSyncHealthCard health={snapshot.cloud_sync_health} />
        <ApprovalCenterHealthCard snapshot={snapshot} />

        <div className="rounded-xl border border-border bg-white px-5 py-4">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-brand-blue">
            Recommended next step
          </p>
          <p className="mt-2 text-sm leading-relaxed text-brand-dark/80">{remediationLine(snapshot)}</p>
          <div className="mt-4 flex flex-wrap gap-3">
            <ActionButton href={snapshot.dashboard_url}>Open Home</ActionButton>
            <ActionButton href={snapshot.inbox_url} variant="outline">
              Review Queue
            </ActionButton>
            <ActionButton href={snapshot.fleet_url} variant="outline">
              Watched Apps
            </ActionButton>
            {snapshot.cloud_state === "local_only" ? (
              <ActionButton href={snapshot.connect_url} variant="secondary">
                Connect this machine
              </ActionButton>
            ) : null}
          </div>
        </div>
      </div>
    </Surface>
  );
}
