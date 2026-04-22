import { ActionButton, Badge, KeyValueGrid, SectionLabel, Surface, Tag } from "./approval-center-primitives";
import type { GuardRuntimeSnapshot } from "./guard-types";

type RuntimeOverviewProps = {
  snapshot: GuardRuntimeSnapshot;
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
    return "Open the current request lane, resolve the blocked launch, and rerun the same command in your harness.";
  }
  if (snapshot.cloud_state === "paired_waiting") {
    return "Open Fleet in Guard Cloud while the first shared proof lands and the connected machine finishes syncing.";
  }
  if (snapshot.cloud_state === "local_only") {
    return "Stay local for now or connect this machine when you want shared queue memory and cross-device proof.";
  }
  return "Open Guard Cloud Home for shared proof, Fleet for machine coverage, or Inbox when the next review item appears.";
}

export function RuntimeOverview(props: RuntimeOverviewProps) {
  const { snapshot } = props;

  return (
    <Surface className="mb-6" tone="accent">
      <div className="flex flex-col gap-5">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <SectionLabel>Runtime health</SectionLabel>
              <Badge tone={headlineTone(snapshot.headline_state)}>{snapshot.headline_label}</Badge>
              <Tag tone={snapshot.cloud_state === "local_only" ? "slate" : "blue"}>
                {snapshot.cloud_state_label}
              </Tag>
            </div>
            <div className="space-y-2">
              <h2 className="text-lg font-semibold tracking-tight text-brand-dark">
                One Guard runtime for the local queue, evidence, and cloud handoff
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
              ["Queue", `${snapshot.pending_count} pending`],
              ["Decisions", `${snapshot.receipt_count} stored`],
              ["Session", snapshot.runtime_state?.session_id.slice(0, 8) ?? "offline"],
              ["Approval center", snapshot.approval_center_url ?? "offline"],
            ]}
          />
        </div>

        <div className="rounded-xl border border-border bg-white px-5 py-4">
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-brand-blue">
            Recommended next step
          </p>
          <p className="mt-2 text-sm leading-relaxed text-brand-dark/80">{remediationLine(snapshot)}</p>
          <div className="mt-4 flex flex-wrap gap-3">
            <ActionButton href={snapshot.dashboard_url}>Open Home</ActionButton>
            <ActionButton href={snapshot.inbox_url} variant="outline">
              Open Inbox
            </ActionButton>
            <ActionButton href={snapshot.fleet_url} variant="outline">
              Open Fleet
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
