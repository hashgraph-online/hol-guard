import {
  ActionButton,
  EmptyState,
  KeyValueGrid,
  SectionLabel,
  Surface,
  Tag
} from "./approval-center-primitives";
import type { GuardReceipt, GuardRuntimeSnapshot } from "./guard-types";

type FleetWorkspaceProps = {
  runtime: GuardRuntimeSnapshot;
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
  return `${receipt.harness} · ${decision}`;
}

export function FleetWorkspace(props: FleetWorkspaceProps) {
  const harnesses = collectHarnesses(props.runtime);
  const runtimeState = props.runtime.runtime_state;

  return (
    <div className="space-y-6">
      <Surface tone="accent">
        <SectionLabel>Fleet</SectionLabel>
        <div className="mt-2 flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="space-y-2">
            <h2 className="text-xl font-semibold tracking-tight text-brand-dark">
              One protected machine, one local command center
            </h2>
            <p className="max-w-2xl text-sm leading-relaxed text-brand-dark/75">
              Use Fleet to confirm that the local Guard runtime is healthy, see which harnesses are
              active on this machine, and verify that your recent evidence is still flowing before
              you depend on cloud continuity.
            </p>
            <div className="flex flex-wrap gap-3 pt-1">
              <ActionButton href={props.runtime.fleet_url}>Open Cloud Fleet</ActionButton>
              <ActionButton href={props.runtime.dashboard_url} variant="outline">
                Open Home
              </ActionButton>
              <ActionButton href={props.runtime.inbox_url} variant="outline">
                Open Inbox
              </ActionButton>
            </div>
          </div>
          <KeyValueGrid
            columns={2}
            items={[
              ["Pending queue", `${props.runtime.pending_count}`],
              ["Evidence", `${props.runtime.receipt_count}`],
              ["Harnesses", `${harnesses.length}`],
              ["Runtime", runtimeState ? "active" : "offline"]
            ]}
          />
        </div>
      </Surface>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,0.9fr)]">
        <Surface>
          <SectionLabel>Harness coverage</SectionLabel>
          {harnesses.length > 0 ? (
            <div className="mt-3 flex flex-wrap gap-2">
              {harnesses.map((harness) => (
                <Tag key={harness} tone="blue">
                  {harness}
                </Tag>
              ))}
            </div>
          ) : (
            <div className="mt-3">
              <EmptyState
                title="No active harnesses yet"
                body="Run Guard once against Codex, Claude Code, Cursor, Hermes, or another supported harness and this machine will start building its local fleet picture."
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
                ["Heartbeat", runtimeState?.last_heartbeat_at ?? "offline"]
              ]}
            />
          </div>
        </Surface>

        <Surface>
          <SectionLabel>Recent evidence</SectionLabel>
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
                title="No evidence yet"
                body="Allow or block a launch once and Guard will start building reusable local evidence for this machine."
              />
            </div>
          )}
        </Surface>
      </div>
    </div>
  );
}
