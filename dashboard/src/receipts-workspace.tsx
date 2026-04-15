import { EmptyState, KeyValueGrid, SectionLabel, Surface } from "./approval-center-primitives";
import type { GuardReceipt } from "./guard-types";

type ReceiptsState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardReceipt[] };

export function ReceiptsWorkspace(props: { receipts: ReceiptsState }) {
  if (props.receipts.kind === "loading") {
    return (
      <div className="space-y-4">
        <div className="guard-skeleton h-8 w-64" />
        <div className="guard-skeleton h-32 w-full" />
      </div>
    );
  }
  if (props.receipts.kind === "error") {
    return (
      <Surface tone="danger">
        <p className="text-sm text-red-700">{props.receipts.message}</p>
      </Surface>
    );
  }
  if (props.receipts.items.length === 0) {
    return (
      <EmptyState
        title="No receipts yet"
        body="Receipts appear here after Guard evaluates a harness launch or approval decision."
      />
    );
  }
  return (
    <div className="space-y-4">
      <div>
        <SectionLabel>Recent receipts</SectionLabel>
        <h2 className="mt-1 text-lg font-semibold tracking-tight text-brand-dark">
          Local Guard history from this shared runtime
        </h2>
      </div>
      <div className="space-y-3">
        {props.receipts.items.map((receipt) => (
          <Surface key={receipt.receipt_id}>
            <div className="space-y-3">
              <div>
                <p className="text-sm font-semibold text-brand-dark">
                  {receipt.artifact_name ?? receipt.artifact_id}
                </p>
                <p className="mt-1 text-xs text-muted-foreground">
                  {receipt.harness} · {receipt.policy_decision} · {receipt.timestamp}
                </p>
              </div>
              <KeyValueGrid
                columns={2}
                items={[
                  ["Artifact ID", receipt.artifact_id],
                  ["Hash", receipt.artifact_hash],
                  ["Source", receipt.source_scope ?? "unknown"],
                  ["Capabilities", receipt.capabilities_summary],
                  ["Changed", receipt.changed_capabilities.join(", ") || "none"],
                  ["Provenance", receipt.provenance_summary]
                ]}
              />
            </div>
          </Surface>
        ))}
      </div>
    </div>
  );
}
