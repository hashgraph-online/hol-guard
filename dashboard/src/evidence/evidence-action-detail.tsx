import { useCallback } from "react";
import {
  HiMiniXMark,
  HiMiniClipboardDocument,
  HiMiniShieldCheck,
  HiMiniNoSymbol,
  HiMiniQuestionMarkCircle,
  HiMiniChevronDown,
  HiMiniChevronUp,
} from "react-icons/hi2";
import { useState } from "react";
import type { GuardReceipt } from "../guard-types";
import { harnessDisplayName, formatRelativeTime } from "../approval-center-utils";
import { plainEnglishDescription, humanFileName } from "./plain-english";
import { detectCategory, getCategoryInfo } from "./categories";

interface EvidenceActionDetailProps {
  receipt: GuardReceipt | null;
  onClose: () => void;
}

interface DecisionBadgeProps {
  decision: string;
}

function DecisionBadge({ decision }: DecisionBadgeProps) {
  if (decision === "allow") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-green-50 px-2.5 py-1 text-xs font-semibold text-green-700 ring-1 ring-green-200">
        <HiMiniShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
        Allowed
      </span>
    );
  }
  if (decision === "block") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-amber-50 px-2.5 py-1 text-xs font-semibold text-brand-attention ring-1 ring-amber-200">
        <HiMiniNoSymbol className="h-3.5 w-3.5" aria-hidden="true" />
        Stopped
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-blue-50 px-2.5 py-1 text-xs font-semibold text-brand-blue ring-1 ring-blue-200">
      <HiMiniQuestionMarkCircle className="h-3.5 w-3.5" aria-hidden="true" />
      Reviewed
    </span>
  );
}

interface TechnicalSectionProps {
  receipt: GuardReceipt;
}

function TechnicalSection({ receipt }: TechnicalSectionProps) {
  const [open, setOpen] = useState(false);

  const handleToggle = useCallback(() => {
    setOpen((prev) => !prev);
  }, []);

  return (
    <div className="rounded-lg border border-slate-200">
      <button
        type="button"
        onClick={handleToggle}
        aria-expanded={open}
        className="flex w-full items-center justify-between px-4 py-3 text-sm font-medium text-brand-dark hover:bg-slate-50 rounded-lg transition-colors"
      >
        Technical details
        {open ? (
          <HiMiniChevronUp className="h-4 w-4 text-slate-400" aria-hidden="true" />
        ) : (
          <HiMiniChevronDown className="h-4 w-4 text-slate-400" aria-hidden="true" />
        )}
      </button>
      {open && (
        <div className="border-t border-slate-100 px-4 py-3 space-y-2">
          <DetailRow label="Receipt ID" value={receipt.receipt_id} mono />
          <DetailRow label="Artifact ID" value={receipt.artifact_id} mono />
          <DetailRow
            label="Hash"
            value={receipt.artifact_hash.slice(0, 16) + "…"}
            mono
          />
          {receipt.source_scope && (
            <DetailRow label="Source scope" value={receipt.source_scope} />
          )}
          {receipt.provenance_summary && (
            <DetailRow label="Provenance" value={receipt.provenance_summary} />
          )}
          {receipt.changed_capabilities.length > 0 && (
            <DetailRow
              label="Changed capabilities"
              value={receipt.changed_capabilities.join(", ")}
            />
          )}
          {receipt.capabilities_summary && (
            <DetailRow label="Capabilities" value={receipt.capabilities_summary} />
          )}
        </div>
      )}
    </div>
  );
}

interface DetailRowProps {
  label: string;
  value: string;
  mono?: boolean;
}

function DetailRow({ label, value, mono }: DetailRowProps) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[11px] font-medium uppercase tracking-wide text-slate-400">
        {label}
      </span>
      <span
        className={`text-sm text-brand-dark break-all ${mono ? "font-mono text-xs" : ""}`}
      >
        {value}
      </span>
    </div>
  );
}

export function EvidenceActionDetail({
  receipt,
  onClose,
}: EvidenceActionDetailProps) {
  const [copied, setCopied] = useState(false);

  const handleCopyId = useCallback(async () => {
    if (!receipt) return;
    try {
      await navigator.clipboard.writeText(receipt.receipt_id);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // clipboard not available
    }
  }, [receipt]);

  if (!receipt) {
    return (
      <div
        className="flex h-full items-center justify-center p-8 text-sm text-slate-400"
        aria-label="No action selected"
      >
        Select an action to see details.
      </div>
    );
  }

  const category = detectCategory(receipt);
  const catInfo = getCategoryInfo(category);
  const description = plainEnglishDescription(receipt);
  const artifactLabel = humanFileName(receipt.artifact_name ?? receipt.artifact_id);

  return (
    <div
      role="dialog"
      aria-label="Evidence action detail"
      className="flex h-full flex-col overflow-hidden bg-white"
    >
      <div className="flex items-start justify-between gap-2 border-b border-slate-100 px-5 py-4">
        <div className="flex items-center gap-2 min-w-0">
          <span
            className={`shrink-0 ${catInfo.color}`}
            aria-hidden="true"
          >
            {catInfo.icon}
          </span>
          <span className="font-semibold text-brand-dark truncate text-sm">
            {artifactLabel}
          </span>
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close detail panel"
          className="shrink-0 flex h-8 w-8 items-center justify-center rounded-full text-slate-400 hover:bg-slate-100 hover:text-slate-600 transition-colors"
        >
          <HiMiniXMark className="h-5 w-5" aria-hidden="true" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <DecisionBadge decision={receipt.policy_decision} />
          <span className="text-xs text-slate-500">
            {harnessDisplayName(receipt.harness)}
          </span>
          <span className="text-xs text-slate-400">·</span>
          <span className="text-xs text-slate-500">
            {formatRelativeTime(receipt.timestamp)}
          </span>
        </div>

        <p className="text-sm text-brand-dark leading-relaxed">{description}</p>

        {receipt.capabilities_summary && (
          <p className="text-xs text-slate-500 italic leading-relaxed">
            {receipt.capabilities_summary}
          </p>
        )}

        <TechnicalSection receipt={receipt} />

        <button
          type="button"
          onClick={handleCopyId}
          aria-label="Copy receipt ID to clipboard"
          className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-600 hover:bg-slate-50 transition-colors"
        >
          <HiMiniClipboardDocument className="h-3.5 w-3.5" aria-hidden="true" />
          {copied ? "Copied!" : "Copy receipt ID"}
        </button>
      </div>
    </div>
  );
}
