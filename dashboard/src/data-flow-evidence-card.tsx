import { SectionLabel } from "./approval-center-primitives";
import { deriveDataFlowEvidence } from "./approval-center-utils";
import type { GuardApprovalRequest } from "./guard-types";

export function DataFlowEvidenceCard(props: { item: GuardApprovalRequest }) {
  const evidence = deriveDataFlowEvidence(props.item);
  if (evidence === null) return null;
  const extraCount = evidence.count - 1;
  return (
    <div
      className="rounded-xl border border-brand-blue/20 bg-brand-blue/[0.04] p-4"
      aria-label="Data flow evidence"
    >
      <SectionLabel>Data flow detected</SectionLabel>
      <div
        className="mt-3 flex flex-wrap items-center gap-2"
        role="group"
        aria-label="Source to sink route"
      >
        <span className="rounded-full bg-brand-purple/10 px-2.5 py-1 text-xs font-medium text-brand-purple">
          {evidence.sourceLabel}
        </span>
        <span className="select-none text-muted-foreground" aria-hidden="true">-&gt;</span>
        <span className="rounded-full bg-brand-blue/10 px-2.5 py-1 text-xs font-medium text-brand-blue">
          {evidence.sinkLabel}
        </span>
      </div>
      <p className="mt-2 text-sm leading-relaxed text-brand-dark/80">{evidence.signalTitle}</p>
      <p className="mt-1 font-mono text-[11px] text-muted-foreground">{evidence.signalId}</p>
      {extraCount > 0 ? (
        <p className="mt-1 text-xs text-muted-foreground">
          {`and ${extraCount} more data-flow ${extraCount === 1 ? "signal" : "signals"}`}
        </p>
      ) : null}
    </div>
  );
}
