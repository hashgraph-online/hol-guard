import { deriveSkillRiskSignals, deriveSupplyChainRiskSignals, deriveEncodedLayerSignals } from "./approval-center-utils";
import { SectionLabel } from "./approval-center-primitives";
import type { GuardApprovalRequest, RiskSignalV2 } from "./guard-types";

type SkillRiskCardProps = {
  item: GuardApprovalRequest;
};

export function SkillRiskCard(props: SkillRiskCardProps) {
  const skillSignals = deriveSkillRiskSignals(props.item);
  if (skillSignals.length === 0) return null;
  return (
    <div
      className="rounded-xl border border-amber-200/60 bg-amber-50/60 p-4"
      aria-label="Skill risk details"
    >
      <SectionLabel>Skill risk</SectionLabel>
      <ul className="mt-3 space-y-3">
        {skillSignals.map((signal) => (
          <SkillSignalRow key={signal.signal_id} signal={signal} />
        ))}
      </ul>
    </div>
  );
}

type SkillSignalRowProps = {
  signal: RiskSignalV2;
};

function SkillSignalRow(props: SkillSignalRowProps) {
  const { signal } = props;
  return (
    <li className="space-y-1">
      <p className="text-sm font-semibold text-brand-dark">{signal.title}</p>
      <p className="text-sm leading-relaxed text-brand-dark/70">{signal.plain_reason}</p>
      {signal.technical_detail !== null ? (
        <p className="font-mono text-[11px] text-muted-foreground">{signal.technical_detail}</p>
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

type SupplyChainRiskCardProps = {
  item: GuardApprovalRequest;
};

export function SupplyChainRiskCard(props: SupplyChainRiskCardProps) {
  const scSignals = deriveSupplyChainRiskSignals(props.item);
  const isSupplyChainArtifact =
    props.item.artifact_type === "supply_chain" ||
    props.item.artifact_type === "package_request" ||
    props.item.artifact_type.endsWith("_package");
  if (scSignals.length === 0 && !isSupplyChainArtifact) return null;
  return (
    <div
      className="rounded-xl border border-orange-200/60 bg-orange-50/60 p-4"
      aria-label="Supply-chain risk"
    >
      <SectionLabel>Supply-chain risk</SectionLabel>
      {scSignals.length > 0 ? (
        <ul className="mt-3 space-y-3">
          {scSignals.map((signal) => (
            <SupplyChainSignalRow key={signal.signal_id} signal={signal} />
          ))}
        </ul>
      ) : (
        <p className="mt-2 text-sm leading-relaxed text-brand-dark/70">
          This action originates from a supply-chain artifact. Verify the publisher and version before approving.
        </p>
      )}
    </div>
  );
}

type SupplyChainSignalRowProps = {
  signal: RiskSignalV2;
};

function SupplyChainSignalRow(props: SupplyChainSignalRowProps) {
  const { signal } = props;
  return (
    <li className="space-y-1">
      <p className="text-sm font-semibold text-brand-dark">{signal.title}</p>
      <p className="text-sm leading-relaxed text-brand-dark/70">{signal.plain_reason}</p>
      {signal.advisory_id !== null ? (
        <p className="font-mono text-[11px] text-brand-purple">{signal.advisory_id}</p>
      ) : null}
      {signal.false_positive_hint !== null ? (
        <p className="text-xs leading-5 text-orange-700/80">
          <span className="font-semibold">Might be safe if: </span>
          {signal.false_positive_hint}
        </p>
      ) : null}
    </li>
  );
}

type DecodedLayerCardProps = {
  item: GuardApprovalRequest;
};

export function DecodedLayerCard(props: DecodedLayerCardProps) {
  const encodedSignals = deriveEncodedLayerSignals(props.item);
  if (encodedSignals.length === 0) return null;
  const primary = encodedSignals[0];
  const layerCount = _parseLayerCountFromReason(primary.plain_reason);
  const extraCount = layerCount !== null ? Math.max(0, layerCount - 1) : encodedSignals.length - 1;
  return (
    <div
      className="rounded-xl border border-rose-200/60 bg-rose-50/60 p-4"
      aria-label="Decoded-layer evidence"
    >
      <SectionLabel>Encoded payload detected</SectionLabel>
      <p className="mt-2 text-sm leading-relaxed text-brand-dark/80">{primary.plain_reason}</p>
      {primary.technical_detail !== null ? (
        <p className="mt-1 font-mono text-[11px] text-muted-foreground break-all">
          {primary.technical_detail}
        </p>
      ) : null}
      {primary.evidence_ref !== null ? (
        <p className="mt-2 font-mono text-[11px] text-rose-700/70">{primary.evidence_ref}</p>
      ) : null}
      {extraCount > 0 ? (
        <p className="mt-1 text-xs text-muted-foreground">
          {`and ${extraCount} more encoded ${extraCount === 1 ? "layer" : "layers"}`}
        </p>
      ) : null}
    </div>
  );
}

function _parseLayerCountFromReason(reason: string): number | null {
  const match = /(\d+)\s+encoding\s+layer/i.exec(reason);
  if (match === null) return null;
  const count = parseInt(match[1], 10);
  return Number.isFinite(count) && count > 0 ? count : null;
}
