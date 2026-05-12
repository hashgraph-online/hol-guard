import { useState, memo } from "react";
import {
  HiMiniChevronDown,
} from "react-icons/hi2";
import { SectionLabel, Tag } from "../approval-center-primitives";
import { formatRelativeTime } from "../approval-center-utils";
import type { GuardReceipt } from "../guard-types";

export const ReceiptGroup = memo(function ReceiptGroup({
  title,
  items,
}: {
  title: string;
  items: GuardReceipt[];
}) {
  if (items.length === 0) return null;
  return (
    <div>
      <div className="flex items-center justify-between px-1">
        <SectionLabel>{title}</SectionLabel>
        <span className="text-xs text-muted-foreground">{items.length} events</span>
      </div>
      <div className="mt-3 space-y-2">
        {items.map((receipt) => (
          <ExpandableReceiptRow key={receipt.receipt_id} receipt={receipt} />
        ))}
      </div>
    </div>
  );
});

export const ExpandableReceiptRow = memo(function ExpandableReceiptRow({
  receipt,
}: {
  receipt: GuardReceipt;
}) {
  const [expanded, setExpanded] = useState(false);
  const decisionLabel = receipt.policy_decision === "allow" ? "Allowed" : "Stopped";
  const name = receipt.artifact_name ?? receipt.artifact_id;

  return (
    <button
      onClick={() => setExpanded((prev) => !prev)}
      className="flex w-full items-start justify-between gap-3 rounded-xl border border-slate-200/70 bg-white px-4 py-3 text-left transition-colors hover:bg-slate-50"
      aria-expanded={expanded}
    >
      <div className="min-w-0 flex-1">
        <p className="text-sm text-brand-dark">
          <span className="font-medium">{decisionLabel}</span>{" "}
          <span className="font-mono text-xs">{name}</span>
        </p>
        {receipt.capabilities_summary && (
          <p className="mt-1 text-xs text-muted-foreground">{receipt.capabilities_summary}</p>
        )}
        <p className="mt-1 text-[11px] text-muted-foreground">{formatRelativeTime(receipt.timestamp)}</p>
        {expanded && (
          <div className="guard-fade-in mt-3 grid grid-cols-1 gap-2 border-t border-slate-200/70 pt-3 text-xs">
            <div>
              <span className="text-muted-foreground">Action ID</span>
              <p className="mt-0.5 font-mono text-brand-dark">{receipt.artifact_id}</p>
            </div>
            {receipt.artifact_hash && (
              <div>
                <span className="text-muted-foreground">Hash</span>
                <p className="mt-0.5 font-mono text-brand-dark">{receipt.artifact_hash}</p>
              </div>
            )}
            {receipt.capabilities_summary && (
              <div>
                <span className="text-muted-foreground">Capabilities</span>
                <p className="mt-0.5 text-brand-dark">{receipt.capabilities_summary}</p>
              </div>
            )}
            {receipt.provenance_summary && (
              <div>
                <span className="text-muted-foreground">Provenance</span>
                <p className="mt-0.5 text-brand-dark">{receipt.provenance_summary}</p>
              </div>
            )}
            <div>
              <span className="text-muted-foreground">Time</span>
              <p className="mt-0.5 font-mono text-brand-dark">{new Date(receipt.timestamp).toLocaleString()}</p>
            </div>
          </div>
        )}
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <Tag tone={receipt.policy_decision === "allow" ? "green" : "blue"}>
          {receipt.policy_decision}
        </Tag>
        <HiMiniChevronDown
          className={`h-4 w-4 text-slate-400 transition-transform ${expanded ? "rotate-180" : ""}`}
          aria-hidden="true"
        />
      </div>
    </button>
  );
});
