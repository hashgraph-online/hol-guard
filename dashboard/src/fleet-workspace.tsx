import {
  ActionButton,
  Badge,
  EmptyState,
  KeyValueGrid,
  SectionLabel,
  Tag
} from "./approval-center-primitives";
import { harnessDisplayName } from "./approval-center-utils";
import type { GuardInventoryItem, GuardPolicyDecision, GuardReceipt, GuardRuntimeSnapshot } from "./guard-types";

type FleetWorkspaceProps = {
  runtime: GuardRuntimeSnapshot;
  policies: GuardPolicyDecision[];
  inventory:
    | { kind: "idle" }
    | { kind: "loading" }
    | { kind: "error"; message: string }
    | { kind: "ready"; items: GuardInventoryItem[] };
};

function collectHarnesses(snapshot: GuardRuntimeSnapshot): string[] {
  const harnesses = new Set<string>();
  for (const item of snapshot.items) {
    harnesses.add(item.harness);
  }
  for (const receipt of snapshot.latest_receipts) {
    harnesses.add(receipt.harness);
  }
  return Array.from(harnesses).sort((left, right) => left.localeCompare(right));
}

function renderReceiptContext(receipt: GuardReceipt): string {
  const decision = receipt.policy_decision.replace(/-/g, " ");
  return `${harnessDisplayName(receipt.harness)} · ${decision}`;
}

export function FleetWorkspace(props: FleetWorkspaceProps) {
  const harnesses = collectHarnesses(props.runtime);
  const managedInstalls = props.runtime.managed_installs ?? [];
  const activeInstalls = managedInstalls.filter((install) => install.active);
  const visibleHarnesses = Array.from(
    new Set([...managedInstalls.map((install) => install.harness), ...harnesses])
  ).sort((left, right) => left.localeCompare(right));
  const inventory = props.inventory.kind === "ready" ? props.inventory.items : [];
  const runtimeState = props.runtime.runtime_state;

  return (
    <div className="space-y-6">
      <section className="guard-surface-in relative overflow-hidden rounded-[2rem] border border-brand-blue/15 bg-[radial-gradient(circle_at_top_left,rgba(85,153,254,0.12),transparent_32%),linear-gradient(135deg,#ffffff_0%,#ffffff_62%,rgba(72,223,123,0.10)_100%)] p-5 shadow-[0_20px_60px_rgba(63,65,116,0.08)] sm:p-6 lg:p-7">
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_420px] lg:items-start">
          <div className="space-y-2">
            <SectionLabel>Watched Apps</SectionLabel>
            <h2 className="text-xl font-semibold tracking-tight text-brand-dark">
              One machine, all connected apps
            </h2>
            <p className="max-w-2xl text-sm leading-relaxed text-brand-dark/75">
              Confirm that HOL Guard is running, see which local apps it is protecting, and review
              recent choices before you rely on team-wide Cloud sync.
            </p>
            <div className="flex flex-wrap gap-3 pt-1">
              <ActionButton href={props.runtime.fleet_url}>Open Cloud Devices</ActionButton>
              <ActionButton href={props.runtime.dashboard_url} variant="outline">
                Open Home
              </ActionButton>
              <ActionButton href={props.runtime.inbox_url} variant="outline">
                Review Queue
              </ActionButton>
            </div>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <FleetMetric label="Needs review" value={`${props.runtime.pending_count}`} />
            <FleetMetric label="History" value={`${props.runtime.receipt_count}`} />
            <FleetMetric label="Watched apps" value={`${activeInstalls.length > 0 ? activeInstalls.length : visibleHarnesses.length}`} />
            <FleetMetric label="Runtime" value={runtimeState ? "active" : "offline"} />
          </div>
        </div>
      </section>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,0.9fr)]">
        <section className="rounded-[1.75rem] border border-slate-200/70 bg-white/80 p-5 shadow-sm sm:p-6">
          <SectionLabel>App coverage</SectionLabel>
          {visibleHarnesses.length > 0 ? (
            <div className="mt-4 overflow-hidden rounded-[1.5rem] border border-slate-200/70 bg-white/75">
              {visibleHarnesses.map((harness) => {
                const install = managedInstalls.find((item) => item.harness === harness);
                const harnessInventory = inventory.filter((item) => item.harness === harness && item.present);
                const harnessPolicies = props.policies.filter((item) => item.harness === harness);
                const statusLabel = install === undefined ? "Observed" : install.active ? "Protected" : "Disabled";
                return (
                  <div key={harness} className="border-b border-slate-200/70 px-4 py-3 last:border-b-0">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className="text-sm font-semibold text-brand-dark">{harnessDisplayName(harness)}</p>
                        <p className="mt-1 text-xs text-muted-foreground">
                          {harnessInventory.length} actions seen · {harnessPolicies.length} saved approvals
                        </p>
                      </div>
                      <Badge tone={install === undefined || install.active ? "success" : "destructive"}>
                        {statusLabel}
                      </Badge>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="mt-3">
              <EmptyState
                title="No watched apps yet"
                body="Run HOL Guard once with Codex, Claude Code, Cursor, Hermes, or another supported app and this machine will show coverage here."
              />
            </div>
          )}
          <div className="mt-4">
            <KeyValueGrid
              columns={2}
              items={[
                ["Approval center", props.runtime.approval_center_url ?? "offline"],
                ["Session", runtimeState?.session_id.slice(0, 8) ?? "offline"],
                ["Started", runtimeState?.started_at ?? "offline"],
                ["Heartbeat", runtimeState?.last_heartbeat_at ?? "offline"],
                ["Detected", `${harnesses.length} apps`],
                ["Actions seen", props.inventory.kind === "loading" ? "loading" : `${inventory.length}`]
              ]}
            />
            {props.inventory.kind === "error" ? (
              <p className="mt-3 text-xs leading-relaxed text-muted-foreground">{props.inventory.message}</p>
            ) : null}
          </div>
        </section>

        <section className="rounded-[1.75rem] border border-brand-blue/15 bg-brand-blue/[0.04] p-5 sm:p-6">
          <SectionLabel>Recent choices</SectionLabel>
          {props.runtime.latest_receipts.length > 0 ? (
            <div className="mt-3 space-y-3">
              {props.runtime.latest_receipts.slice(0, 6).map((receipt) => (
                <div
                  key={receipt.receipt_id}
                  className="rounded-lg border border-border bg-white px-4 py-3"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-semibold text-brand-dark">
                        {receipt.artifact_name ?? receipt.artifact_id}
                      </p>
                      <p className="mt-1 text-xs text-muted-foreground">{renderReceiptContext(receipt)}</p>
                    </div>
                    <Tag tone="green">{receipt.policy_decision}</Tag>
                  </div>
                  <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
                    {receipt.capabilities_summary || receipt.provenance_summary}
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <div className="mt-3">
              <EmptyState
                title="No choices yet"
                body="Allow or block an action once and HOL Guard will start building local history for this machine."
              />
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

function FleetMetric(props: { label: string; value: string }) {
  return (
    <div className="rounded-[1.25rem] border border-white/80 bg-white/80 px-4 py-3 shadow-sm">
      <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">{props.label}</p>
      <p className="mt-1 text-xl font-semibold tracking-tight text-brand-dark">{props.value}</p>
    </div>
  );
}
