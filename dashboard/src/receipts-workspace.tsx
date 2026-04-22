import {
  EmptyState,
  KeyValueGrid,
  SectionLabel,
  Surface,
  Tag
} from "./approval-center-primitives";
import type { GuardReceipt } from "./guard-types";

type ReceiptsState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardReceipt[] };

export function ReceiptsWorkspace(props: { receipts: ReceiptsState }) {
  const items = props.receipts.kind === "ready" ? props.receipts.items : [];

  return (
    <div className="space-y-5">
      <Surface>
        <SectionLabel>Recent decisions</SectionLabel>
        <h1 className="mt-1 text-xl font-semibold tracking-tight text-brand-dark">Local evidence and proof</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-gray-500">
          Each decision records the artifact fingerprint, observed capabilities, and provenance Guard used when it paused or allowed a launch.
        </p>
      </Surface>

      {props.receipts.kind === "loading" ? (
        <div className="space-y-3">
          <div className="guard-skeleton h-20 w-full" />
          <div className="guard-skeleton h-20 w-full" />
        </div>
      ) : null}

      {props.receipts.kind === "error" ? (
        <Surface tone="danger">
          <EmptyState title="Evidence unavailable" body={props.receipts.message} />
        </Surface>
      ) : null}

      {props.receipts.kind === "ready" && items.length === 0 ? (
        <Surface>
          <EmptyState
            title="No decisions saved yet"
            body="When you allow or block a tool, Guard saves the evidence here so you can review, revoke, or reuse that decision later."
          />
        </Surface>
      ) : null}

      {props.receipts.kind === "ready" && items.length > 0 ? (
        <div className="space-y-2">
          {items.map((receipt) => (
            <ReceiptCard key={receipt.receipt_id} receipt={receipt} />
          ))}
        </div>
      ) : null}
    </div>
  );
}

function ReceiptCard(props: { receipt: GuardReceipt }) {
  const policyTone =
    props.receipt.policy_decision === "block"
      ? "red"
      : props.receipt.policy_decision === "allow"
        ? "green"
        : "blue";

  return (
    <Surface>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 space-y-2">
          <div className="flex flex-wrap items-center gap-1.5">
            <Tag tone={policyTone}>{props.receipt.policy_decision}</Tag>
            <Tag tone="blue">{props.receipt.harness}</Tag>
            {props.receipt.source_scope ? <Tag tone="slate">{props.receipt.source_scope}</Tag> : null}
          </div>
          <h2 className="font-mono text-base font-medium text-brand-dark">
            {props.receipt.artifact_name ?? props.receipt.artifact_id}
          </h2>
          <p className="text-xs text-gray-400">{props.receipt.timestamp}</p>
        </div>
        <div className="w-full shrink-0 lg:w-64">
          <KeyValueGrid
            columns={1}
            items={[
              ["Fingerprint", props.receipt.artifact_hash],
              ["Capabilities", props.receipt.capabilities_summary || "None saved"],
              ["Provenance", props.receipt.provenance_summary || "None saved"]
            ]}
          />
        </div>
      </div>
    </Surface>
  );
}
