import { useEffect, useId, useState } from "react";
import type { GuardBrowserProviderFindingV1 } from "../guard-types";
import { checkedAgo, providerCapabilityText, STATE_TEXT, VERDICT_TEXT } from "./browser-provider-finding-model";

const CHIP = "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium text-brand-dark";

const VERDICT_TONE: Record<GuardBrowserProviderFindingV1["verdict"], string> = {
  danger: "border-brand-danger/30 bg-brand-danger/[0.08]",
  caution: "border-brand-attention/30 bg-brand-attention/[0.08]",
  ok: "border-brand-green/30 bg-brand-green/[0.08]",
  unknown: "border-slate-200 bg-slate-50",
};

function VerdictChip({ row }: { row: GuardBrowserProviderFindingV1 }) {
  if (row.state !== "fresh") {
    return <span className={`${CHIP} ${VERDICT_TONE.unknown}`}>{STATE_TEXT[row.state]}</span>;
  }
  return (
    <span data-provider-verdict={row.verdict} className={`${CHIP} ${VERDICT_TONE[row.verdict]}`}>
      {VERDICT_TEXT[row.verdict]}
    </span>
  );
}

/** One provider's row: name, what it checked, its verdict, up to three reasons and the answer's age. */
export function ProviderFindingRow({ row, nowMs }: { row: GuardBrowserProviderFindingV1; nowMs: number }) {
  return (
    <li data-provider-finding={row.provider_id} className="py-2 first:pt-0 last:pb-0">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="text-sm font-semibold text-brand-dark">{row.provider_name}</span>
        {row.sponsored && <span className="text-xs font-medium text-brand-dark/60">Sponsor</span>}
        <span className="text-xs text-brand-dark/60">{providerCapabilityText(row.capability)}</span>
        <VerdictChip row={row} />
      </div>
      {row.state === "fresh" && row.reason_labels.length > 0 && (
        <ul className="mt-1 flex flex-wrap gap-1.5" aria-label="Reasons">
          {row.reason_labels.map((label) => (
            <li key={label} className="text-xs text-brand-dark/80">
              {label}
            </li>
          ))}
        </ul>
      )}
      <p className="mt-0.5 text-xs text-brand-dark/50">{checkedAgo(row.observed_at_ms, nowMs)}</p>
    </li>
  );
}

function useNow(intervalMs: number, enabled: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!enabled) return undefined;
    const id = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(id);
  }, [intervalMs, enabled]);
  return now;
}

/**
 * Provider findings, after Guard's own facts. The rows come with each queue refresh, so an answer
 * that arrives while the card is open appears on the next poll without changing Guard's findings.
 */
export function BrowserProviderFindings(props: { findings: GuardBrowserProviderFindingV1[]; nowMs?: number }) {
  const labelId = useId();
  const ticking = useNow(10_000, props.nowMs === undefined && props.findings.length > 0);
  if (props.findings.length === 0) return null;
  const nowMs = props.nowMs ?? ticking;
  return (
    <div className="border-t border-slate-100 px-4 py-2.5 sm:px-5">
      <p id={labelId} className="text-xs font-medium text-brand-dark/60">
        Provider findings
      </p>
      <ul aria-labelledby={labelId} className="mt-1.5 divide-y divide-slate-100">
        {props.findings.map((row) => (
          <ProviderFindingRow key={`${row.provider_id}:${row.capability}`} row={row} nowMs={nowMs} />
        ))}
      </ul>
    </div>
  );
}
