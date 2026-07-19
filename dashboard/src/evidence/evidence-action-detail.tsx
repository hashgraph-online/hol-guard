import { useCallback } from "react";
import {
  HiMiniXMark,
  HiMiniClipboardDocument,
  HiMiniShieldCheck,
  HiMiniNoSymbol,
  HiMiniQuestionMarkCircle,
  HiMiniChevronDown,
  HiMiniChevronUp,
  HiMiniExclamationTriangle,
  HiMiniInformationCircle,
  HiMiniBolt,
  HiMiniDocumentText,
} from "react-icons/hi2";
import { useState } from "react";
import type { GuardReceipt, RiskSignalV2 } from "../guard-types";
import { isRiskSignalEvidence } from "../guard-types";
import { harnessDisplayName, formatRelativeTime } from "../approval-center-utils";
import { plainEnglishDescription, resolveActionTitle, resolveActionType, resolveActionDetail } from "./plain-english";
import { detectCategory, getCategoryInfo } from "./categories";
import { SectionLabel } from "../approval-center-primitives";
import { DecisionBadge } from "./decision-badge";
import { LoggedActionPanel } from "../logged-action-panel";
import { guardActionPresentation } from "../guard-action";

interface EvidenceActionDetailProps {
  receipt: GuardReceipt | null;
  onClose: () => void;
}

function SeverityIcon({ severity }: { severity: string }) {
  if (severity === "critical" || severity === "high") {
    return <HiMiniExclamationTriangle className="h-4 w-4 text-amber-500" aria-hidden="true" />;
  }
  if (severity === "medium") {
    return <HiMiniBolt className="h-4 w-4 text-orange-400" aria-hidden="true" />;
  }
  return <HiMiniInformationCircle className="h-4 w-4 text-brand-blue" aria-hidden="true" />;
}

function SeverityBadge({ severity }: { severity: string }) {
  const styles: Record<string, string> = {
    critical: "bg-amber-100 text-amber-800 ring-amber-200",
    high: "bg-amber-50 text-amber-700 ring-amber-200",
    medium: "bg-orange-50 text-orange-700 ring-orange-200",
    low: "bg-blue-50 text-brand-blue ring-blue-200",
    info: "bg-slate-100 text-slate-600 ring-slate-200",
  };
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ring-1 ${styles[severity] ?? styles.info}`}
    >
      {severity}
    </span>
  );
}

function ScannerEvidenceSection({ signals }: { signals: RiskSignalV2[] }) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const toggle = useCallback((id: string) => {
    setExpanded((prev) => ({ ...prev, [id]: !prev[id] }));
  }, []);

  if (signals.length === 0) return null;

  return (
    <div className="space-y-2">
      <SectionLabel>Scanner findings ({signals.length})</SectionLabel>
      <div className="space-y-2">
        {signals.map((signal) => {
          const isOpen = expanded[signal.signal_id] ?? false;
          return (
            <div
              key={signal.signal_id}
              className="rounded-lg border border-slate-200 bg-white overflow-hidden"
            >
              <button
                type="button"
                onClick={() => toggle(signal.signal_id)}
                aria-expanded={isOpen}
                className="flex w-full items-center gap-2 px-3 py-2.5 text-left hover:bg-slate-50 transition-colors"
              >
                <SeverityIcon severity={signal.severity} />
                <span className="flex-1 text-xs font-medium text-brand-dark truncate">
                  {signal.title}
                </span>
                <SeverityBadge severity={signal.severity} />
                {isOpen ? (
                  <HiMiniChevronUp className="h-3.5 w-3.5 text-slate-400 shrink-0" aria-hidden="true" />
                ) : (
                  <HiMiniChevronDown className="h-3.5 w-3.5 text-slate-400 shrink-0" aria-hidden="true" />
                )}
              </button>
              {isOpen && (
                <div className="border-t border-slate-100 px-3 py-2.5 space-y-2">
                  <p className="text-xs text-brand-dark/80 leading-relaxed">
                    {signal.plain_reason}
                  </p>
                  {signal.technical_detail && (
                    <div className="rounded-md bg-slate-50 px-2.5 py-2">
                      <SectionLabel>Technical detail</SectionLabel>
                      <p className="text-xs font-mono text-brand-dark/70 break-all leading-relaxed">
                        {signal.technical_detail}
                      </p>
                    </div>
                  )}
                  {signal.false_positive_hint && (
                    <p className="text-[11px] text-slate-500 italic">
                      {signal.false_positive_hint}
                    </p>
                  )}
                  <div className="flex items-center gap-2 text-[10px] text-slate-400">
                    <span>Detector: {signal.detector}</span>
                    {signal.advisory_id && (
                      <span>· Advisory: {signal.advisory_id}</span>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
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
          <DetailRow label="Action ID" value={receipt.artifact_id} mono />
          <DetailRow
            label="Hash"
            value={(receipt.artifact_hash ?? "").slice(0, 16) + "…"}
            mono
          />
          {receipt.source_scope && (
            <DetailRow label="Source scope" value={receipt.source_scope} />
          )}
          {receipt.provenance_summary && (
            <DetailRow label="Provenance" value={receipt.provenance_summary} />
          )}
          {(receipt.changed_capabilities ?? []).length > 0 && (
            <DetailRow
              label="Changed capabilities"
              value={(receipt.changed_capabilities ?? []).join(", ")}
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

export function nextSafeStep(receipt: GuardReceipt): string | null {
  const action = guardActionPresentation(receipt.policy_decision).action;
  if (action === "block") {
    return "This action is blocked. Review the governing policy or choose a safer alternative; it cannot be approved from the review queue.";
  }
  if (action === "sandbox-required") {
    return "Run this action through an approved sandbox, then retry only after the sandbox requirement is satisfied.";
  }
  if (action === "allow" || action === "warn") {
    return null;
  }
  const category = detectCategory(receipt);
  const approvalCopy = action === "require-reapproval" ? "grant fresh approval" : "approve it";
  if (category === "supply-chain") {
    return `Review the package source and version, then ${approvalCopy} from the review queue if it is safe.`;
  }
  if (category === "tool-call" || category === "mcp") {
    return `Review the tool call in Evidence, then ${approvalCopy} in the review queue if it is safe.`;
  }
  if (category === "file-write" || category === "destructive") {
    return `Check whether the file operation is expected, then ${approvalCopy} from the review queue.`;
  }
  if (category === "secret" || category === "network") {
    return "Inspect the access pattern, then make the required review decision before retrying.";
  }
  return null;
}

function NextSafeCommandHint({ receipt }: { receipt: GuardReceipt }) {
  const hint = nextSafeStep(receipt);
  if (!hint) return null;
  return (
    <div className="rounded-lg border border-brand-blue/15 bg-brand-blue/[0.04] px-3 py-2.5">
      <SectionLabel>Next safe step</SectionLabel>
      <p className="text-xs text-brand-dark/80">{hint}</p>
    </div>
  );
}

function EvidenceTimeline({ receipt }: { receipt: GuardReceipt }) {
  const action = guardActionPresentation(receipt.policy_decision);
  const events = [
    {
      label: "Action received",
      time: receipt.timestamp,
      icon: "start",
    },
    {
      label: action.label,
      time: receipt.timestamp,
      icon: action.disposition,
    },
  ];
  return (
    <div>
      <SectionLabel>Timeline</SectionLabel>
      <ol className="relative border-l border-slate-200 ml-2" aria-label="Evidence timeline">
        {events.map((event, i) => (
          <li key={i} className="mb-2 ml-4 last:mb-0">
            <span
              className={`absolute -left-1.5 flex h-3 w-3 items-center justify-center rounded-full border ${
                event.icon === "allowed"
                  ? "border-brand-green bg-brand-green/20"
                  : event.icon === "blocked"
                  ? "border-brand-attention bg-brand-attention/20"
                  : "border-slate-300 bg-slate-100"
              }`}
              aria-hidden="true"
            />
            <p className="text-xs font-medium text-brand-dark">{event.label}</p>
            <time className="text-[11px] text-slate-400">{formatRelativeTime(event.time)}</time>
          </li>
        ))}
      </ol>
    </div>
  );
}

export function EvidenceActionDetail({
  receipt,
  onClose,
}: EvidenceActionDetailProps) {
  const [copied, setCopied] = useState(false);
  const [copyUnavailable, setCopyUnavailable] = useState(false);

  const handleCopyId = useCallback(async () => {
    if (!receipt) return;
    try {
      await navigator.clipboard.writeText(receipt.receipt_id);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopyUnavailable(true);
      setTimeout(() => setCopyUnavailable(false), 2000);
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
  const actionTitle = resolveActionTitle(receipt);
  const actionType = resolveActionType(receipt);
  const actionDetail = resolveActionDetail(receipt);
  const signals = (receipt.scanner_evidence ?? []).filter(isRiskSignalEvidence);
  const primarySignal = signals[0];
  let copyLabel = "Copy receipt ID";
  if (copied) {
    copyLabel = "Copied!";
  } else if (copyUnavailable) {
    copyLabel = "Unavailable";
  }

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
          <div className="flex flex-col min-w-0">
            <span className="font-semibold text-brand-dark truncate text-sm">
              {actionTitle}
            </span>
            <span className="text-[11px] text-slate-400 truncate">
              {actionType}
            </span>
          </div>
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

        {actionDetail && (
          <div className="space-y-2">
            <SectionLabel>{actionType}</SectionLabel>
            <LoggedActionPanel
              key={receipt.receipt_id}
              label={actionType}
              text={actionDetail}
              copyAriaLabel={`Copy full ${actionType.toLowerCase()} to clipboard`}
              expandAriaLabel={`Expand full ${actionType.toLowerCase()}`}
              collapseAriaLabel={`Collapse full ${actionType.toLowerCase()}`}
            />
          </div>
        )}

        {primarySignal && (
          <div className="rounded-xl border border-brand-blue/20 bg-brand-blue/[0.04] px-3 py-3">
            <div className="flex items-center gap-2">
              <SeverityIcon severity={primarySignal.severity} />
              <SectionLabel>Scanner finding</SectionLabel>
              <SeverityBadge severity={primarySignal.severity} />
            </div>
            <p className="mt-1 text-sm font-medium text-brand-dark">{primarySignal.title}</p>
            <p className="mt-1 text-xs text-brand-dark/80 leading-relaxed">
              {primarySignal.plain_reason}
            </p>
            {primarySignal.false_positive_hint && (
              <p className="mt-2 text-[11px] text-slate-500 italic">
                Might be safe if: {primarySignal.false_positive_hint}
              </p>
            )}
          </div>
        )}

        {receipt.provenance_summary && (
          <div className="rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2.5">
            <SectionLabel>Provenance</SectionLabel>
            <p className="text-xs text-slate-700">{receipt.provenance_summary}</p>
          </div>
        )}

        {receipt.diff_summary && (
          <div className="rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2.5">
            <div className="flex items-center gap-1.5 mb-1">
              <HiMiniDocumentText className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
              <SectionLabel>What changed</SectionLabel>
            </div>
            <p className="text-xs text-slate-700">{receipt.diff_summary}</p>
          </div>
        )}

        {guardActionPresentation(receipt.policy_decision).disposition !== "allowed" && (
          <NextSafeCommandHint receipt={receipt} />
        )}

        <ScannerEvidenceSection signals={signals} />

        <EvidenceTimeline receipt={receipt} />

        <TechnicalSection receipt={receipt} />

        <button
          type="button"
          onClick={handleCopyId}
          aria-label="Copy receipt ID to clipboard"
          className="inline-flex items-center gap-1.5 rounded-md border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-600 hover:bg-slate-50 transition-colors"
        >
          <HiMiniClipboardDocument className="h-3.5 w-3.5" aria-hidden="true" />
          {copyLabel}
        </button>
      </div>
    </div>
  );
}
