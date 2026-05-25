import { ActionButton, Badge, KeyValueGrid, SectionLabel, Surface, Tag, ProofStrip } from "./approval-center-primitives";
import { harnessDisplayName, formatRelativeTime } from "./approval-center-utils";
import type { GuardCloudSyncHealth, GuardInventoryItem, GuardProofStatus, GuardReceipt, GuardRuntimeDevice, GuardRuntimeSnapshot, PackageManagerProtection } from "./guard-types";

const WATCHED_HARNESSES = ["codex", "claude-code", "opencode", "copilot", "gemini", "cursor", "hermes", "openclaw"] as const;

type WatchedHarnessName = (typeof WATCHED_HARNESSES)[number];

type RuntimeOverviewProps = {
  snapshot: GuardRuntimeSnapshot;
  inventory?: GuardInventoryItem[];
};

function headlineTone(state: GuardRuntimeSnapshot["headline_state"]): "info" | "success" | "attention" {
  if (state === "blocked") {
    return "attention";
  }
  if (state === "connected" || state === "local_only") {
    return "info";
  }
  if (state === "protected") {
    return "success";
  }
  return "info";
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
  return "Open Guard Cloud for shared decisions, Apps for local coverage, or the review queue when something needs your choice.";
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

export type ProofStatusCopy = {
  label: string;
  detail: string;
  tone: "green" | "blue" | "slate" | "attention";
};

export function resolveProofStatusCopy(proofStatus: GuardProofStatus): ProofStatusCopy {
  if (proofStatus.state === "synced") {
    return { label: proofStatus.label, detail: proofStatus.detail, tone: "green" };
  }
  if (proofStatus.state === "pending" || proofStatus.state === "waiting") {
    return { label: proofStatus.label, detail: proofStatus.detail, tone: "blue" };
  }
  if (proofStatus.state === "sync_unavailable") {
    return {
      label: "Cloud proof not available",
      detail: "Connect to Guard Cloud to unlock cross-device proof and shared history.",
      tone: "slate",
    };
  }
  if (proofStatus.state === "failed" || proofStatus.state === "expired") {
    return { label: proofStatus.label, detail: proofStatus.detail, tone: "attention" };
  }
  return {
    label: "Local only",
    detail: "Local protection is active. Cloud proof is optional.",
    tone: "slate",
  };
}

function cloudSyncHealthTone(state: GuardCloudSyncHealth["state"]): "blue" | "slate" {
  if (state === "disabled" || state === "failed" || state === "stale") {
    return "slate";
  }
  return "blue";
}

function humanizeCloudSyncHealthLabel(label: string): string {
  const labels: Record<string, string> = {
    "Cloud sync stale": "Cloud backup is out of date",
    "Cloud sync healthy": "Cloud backup up to date",
    "First shared proof": "First cloud backup",
  };
  return labels[label] ?? label;
}

function CloudSyncHealthCard(props: { health: GuardCloudSyncHealth }) {
  const copy = resolveCloudSyncHealthCopy(props.health);
  return (
    <div className="rounded-xl border border-border bg-white px-5 py-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-brand-blue">
          Guard cloud backup
        </p>
        <Tag tone={cloudSyncHealthTone(props.health.state)}>{humanizeCloudSyncHealthLabel(copy.label)}</Tag>
      </div>
      <p className="mt-2 text-sm leading-relaxed text-brand-dark/80">{copy.detail}</p>
    </div>
  );
}

function approvalHealthTone(state: ApprovalCenterHealthState): "green" | "blue" | "slate" | "attention" {
  if (state === "ready") return "green";
  if (state === "starting") return "blue";
  if (state === "repair_needed") return "attention";
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

function WatchedAppsList(props: { inventory: GuardInventoryItem[] | undefined }) {
  const inventory = props.inventory ?? [];
  const foundHarnesses = WATCHED_HARNESSES.filter((h) => inventory.some((item) => item.harness === h));
  return (
    <div className="flex flex-wrap gap-2">
      {WATCHED_HARNESSES.map((harness) => {
        const found = inventory.some((item) => item.harness === harness);
        return (
          <span
            key={harness}
            className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium ${
              found ? "border-brand-green/25 bg-brand-green-bg/50 text-brand-green-text" : "border-slate-200 bg-slate-50 text-slate-400"
            }`}
          >
            {harnessDisplayName(harness)}
            {found && <span className="h-1.5 w-1.5 rounded-full bg-brand-green" />}
          </span>
        );
      })}
    </div>
  );
}

type DeviceProofCardProps = {
  device: GuardRuntimeDevice;
  proofStatus: GuardProofStatus;
};

function formatDeviceInstallationId(installationId: string | null | undefined): string {
  const trimmed = installationId?.trim() ?? "";
  if (trimmed.length === 0) {
    return "local";
  }
  return trimmed.slice(0, 8);
}

export function DeviceProofCard(props: DeviceProofCardProps) {
  const copy = resolveProofStatusCopy(props.proofStatus);
  const shortId = formatDeviceInstallationId(props.device.installation_id);
  const timeValue = props.proofStatus.first_synced_at ?? props.proofStatus.runtime_session_synced_at;
  return (
    <div className="rounded-xl border border-border bg-white px-5 py-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-brand-blue">
          Device &amp; proof
        </p>
        <Tag tone={copy.tone}>{copy.label}</Tag>
      </div>
      <div className="mt-2 min-w-0 space-y-0.5">
        <p className="truncate text-sm font-medium text-brand-dark" title={props.device.device_label}>
          {props.device.device_label}
        </p>
        <p className="font-mono text-xs text-slate-400">{shortId}…</p>
      </div>
      <p className="mt-2 text-sm leading-relaxed text-brand-dark/80">{copy.detail}</p>
      {timeValue !== null ? (
        <p className="mt-1 text-xs text-slate-400">{formatRelativeTime(timeValue)}</p>
      ) : null}
    </div>
  );
}



export type PackageManagerProtectionCopy = {
  pathLabel: string;
  pathDetail: string;
  pathTone: "green" | "attention" | "slate";
  protectedList: string[];
  unprotectedList: string[];
};

export function resolvePackageManagerProtectionCopy(
  protection: PackageManagerProtection | undefined,
): PackageManagerProtectionCopy {
  if (protection === undefined) {
    return {
      pathLabel: "Status unknown",
      pathDetail: "Supply-chain protection data is not available for this session.",
      pathTone: "slate",
      protectedList: [],
      unprotectedList: [],
    };
  }
  const pathInPath = protection.path_status === "in_path";
  return {
    pathLabel: pathInPath ? "Guard shim directory is in PATH" : "Guard shim directory missing from PATH",
    pathDetail: pathInPath
      ? `Package manager commands are intercepted via ${protection.shim_dir}.`
      : `The shim directory (${protection.shim_dir}) is not on PATH. Install bypass is possible for package managers that are not otherwise protected.`,
    pathTone: pathInPath ? "green" : "attention",
    protectedList: protection.protected_managers,
    unprotectedList: protection.unprotected_managers,
  };
}

function PackageManagerProtectionCard(props: { snapshot: GuardRuntimeSnapshot }) {
  const protection = props.snapshot.supply_chain?.package_manager_protection;
  const copy = resolvePackageManagerProtectionCopy(protection);
  return (
    <div className="rounded-xl border border-border bg-white px-5 py-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-brand-blue">
          Package manager protection
        </p>
        <Tag tone={copy.pathTone}>{copy.pathLabel}</Tag>
      </div>
      <p className="mt-2 text-sm leading-relaxed text-brand-dark/80">{copy.pathDetail}</p>
      {copy.protectedList.length > 0 || copy.unprotectedList.length > 0 ? (
        <div className="mt-3 space-y-2">
          {copy.protectedList.length > 0 ? (
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-xs font-medium text-slate-500">Protected:</span>
              {copy.protectedList.map((mgr) => (
                <span
                  key={mgr}
                  className="inline-flex items-center rounded-full border border-brand-green/25 bg-brand-green-bg/50 px-2.5 py-0.5 text-xs font-medium text-brand-green-text"
                >
                  {mgr}
                </span>
              ))}
            </div>
          ) : null}
          {copy.unprotectedList.length > 0 ? (
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-xs font-medium text-slate-500">Unprotected:</span>
              {copy.unprotectedList.map((mgr) => (
                <span
                  key={mgr}
                  className="inline-flex items-center rounded-full border border-amber-200 bg-amber-50 px-2.5 py-0.5 text-xs font-medium text-amber-700"
                >
                  {mgr}
                </span>
              ))}
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

export function RuntimeOverview(props: RuntimeOverviewProps) {
  const { snapshot, inventory } = props;
  const securityLevel = snapshot.security_level;
  const latestReceipt = snapshot.latest_receipts[0];
  const daemonHealthLabel = snapshot.runtime_state !== null ? "running" : "offline";
  const resolvedInventory = inventory ?? snapshot.inventory ?? [];

  return (
    <Surface className="mb-6" tone="accent">
      <div className="flex flex-col gap-6">
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

        <ProofStrip
          items={[
            { label: "Protection level", value: securityLevel ?? "balanced", tone: securityLevel === "strict" ? "purple" : "blue" },
            { label: "Recent decision", value: latestReceipt ? (latestReceipt.policy_decision) : "None", tone: latestReceipt ? (latestReceipt.policy_decision === "allow" ? "green" : "purple") : "slate" },
            { label: "Cloud state", value: snapshot.cloud_state === "local_only" ? "Local only" : "Syncing", tone: snapshot.cloud_state === "local_only" ? "slate" : "green" },
            { label: "Apps seen", value: resolvedInventory.length, tone: resolvedInventory.length > 0 ? "green" : "slate" },
          ]}
        />

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-2 xl:grid-cols-4">
          <CloudSyncHealthCard health={snapshot.cloud_sync_health} />
          <ApprovalCenterHealthCard snapshot={snapshot} />
          <DeviceProofCard device={snapshot.device} proofStatus={snapshot.proof_status} />
          <PackageManagerProtectionCard snapshot={snapshot} />
        </div>

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
              Apps
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
