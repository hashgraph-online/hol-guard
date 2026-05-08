import type { RiskSignalV2 } from "./guard-types";
import { SectionLabel } from "./approval-center-primitives";

type ScannerEvidenceBadgeProps = {
  signal: RiskSignalV2;
};

export function ScannerEvidenceBadge(props: ScannerEvidenceBadgeProps) {
  const isScannerCategory =
    props.signal.category === "skill" || props.signal.category === "mcp";
  if (!isScannerCategory) return null;
  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-amber-300/50 bg-amber-50 px-2 py-0.5 text-[10px] font-semibold text-amber-700">
      🔍 Scanner
    </span>
  );
}

type ScannerSignalRowProps = {
  signal: RiskSignalV2;
};

function ScannerSignalRow(props: ScannerSignalRowProps) {
  const { signal } = props;
  return (
    <li className="space-y-1">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-sm font-semibold text-brand-dark">{signal.title}</p>
        <ScannerEvidenceBadge signal={signal} />
      </div>
      <p className="text-sm leading-relaxed text-brand-dark/70">{signal.plain_reason}</p>
      {signal.technical_detail !== null ? (
        <p className="font-mono text-[11px] text-muted-foreground break-all">
          {signal.technical_detail}
        </p>
      ) : null}
      {signal.false_positive_hint !== null ? (
        <p className="text-xs leading-5 text-amber-700/80">
          <span className="font-semibold">Might be safe if: </span>
          {signal.false_positive_hint}
        </p>
      ) : null}
    </li>
  );
}

type ScannerEvidenceSectionProps = {
  signals: RiskSignalV2[];
};

export function ScannerEvidenceSection(props: ScannerEvidenceSectionProps) {
  const scannerSignals = props.signals.filter(
    (s) => s.category === "skill" || s.category === "mcp"
  );
  if (scannerSignals.length === 0) return null;
  return (
    <div className="rounded-xl border border-amber-200/60 bg-amber-50/60 p-4" aria-label="Scanner evidence">
      <SectionLabel>Scanner evidence</SectionLabel>
      <ul className="mt-3 space-y-3">
        {scannerSignals.map((signal) => (
          <ScannerSignalRow key={signal.signal_id} signal={signal} />
        ))}
      </ul>
    </div>
  );
}
