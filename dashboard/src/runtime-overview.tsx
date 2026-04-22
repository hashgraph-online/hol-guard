import { Badge, EmptyState, KeyValueGrid, SectionLabel, Surface } from "./approval-center-primitives";
import type { GuardRuntimeSummary } from "./guard-types";

type RuntimeState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; item: GuardRuntimeSummary };

function formatValue(value: string | null | undefined): string {
  if (value === null || value === undefined || value.trim() === "") {
    return "Not available";
  }
  return value;
}

function formatCount(value: number): string {
  return value === 1 ? "1 item" : `${value} items`;
}

export function RuntimeOverview(props: { runtime: RuntimeState }) {
  if (props.runtime.kind === "loading") {
    return (
      <Surface tone="accent">
        <div className="space-y-3">
          <div className="guard-skeleton h-4 w-40" />
          <div className="guard-skeleton h-20 w-full" />
        </div>
      </Surface>
    );
  }
  if (props.runtime.kind === "error") {
    return (
      <Surface tone="warning">
        <SectionLabel>Runtime health</SectionLabel>
        <p className="mt-2 text-sm text-brand-dark/70">{props.runtime.message}</p>
      </Surface>
    );
  }

  const { session, attachments, operations, activeOperation } = props.runtime.item;
  if (session === null) {
    return (
      <Surface tone="accent">
        <EmptyState
          title="No active runtime session"
          body="The approval center is attached and waiting. When Guard pauses a harness action, Runtime health will show the live session and operation here."
        />
      </Surface>
    );
  }

  return (
    <Surface tone="accent">
      <div className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <SectionLabel>Runtime health</SectionLabel>
            <p className="mt-1 text-lg font-semibold text-brand-dark">
              {session.harness} session via {session.surface}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone="info">{session.status}</Badge>
            {activeOperation ? <Badge tone="warning">{activeOperation.status}</Badge> : null}
          </div>
        </div>
        <KeyValueGrid
          columns={2}
          items={[
            ["Session", session.session_id],
            ["Workspace", formatValue(session.workspace)],
            ["Client", formatValue(session.client_title ?? session.client_name)],
            ["Capabilities", session.capabilities.length > 0 ? session.capabilities.join(", ") : "Not available"],
            ["Attachments", formatCount(attachments.length)],
            ["Operations", formatCount(operations.length)],
          ]}
        />
        {activeOperation ? (
          <KeyValueGrid
            columns={2}
            items={[
              ["Active operation", activeOperation.operation_id],
              ["Type", activeOperation.operation_type],
              ["Approval requests", formatCount(activeOperation.approval_request_ids.length)],
              ["Resume token", formatValue(activeOperation.resume_token)],
            ]}
          />
        ) : (
          <p className="text-sm text-brand-dark/70">
            This session is attached, but Guard has not started an operation yet.
          </p>
        )}
      </div>
    </Surface>
  );
}
