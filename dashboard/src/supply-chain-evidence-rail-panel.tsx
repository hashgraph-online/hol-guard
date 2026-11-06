import { HiMiniArrowTopRightOnSquare } from "react-icons/hi2";
import { Tag } from "./approval-center-primitives";
import { formatRelativeTime } from "./approval-center-utils";
import type {
  SupplyChainCloudDegradedState,
  SupplyChainEvidenceRailItem,
  SupplyChainEvidenceRailSnapshot,
} from "./supply-chain-evidence-rail";
import { supplyChainEvidenceHref } from "./supply-chain-evidence-rail";
import { SupplyChainDetailSection } from "./supply-chain-detail-section";

type SupplyChainEvidenceRailProps = {
  rail: SupplyChainEvidenceRailSnapshot;
};

const kindLabels: Record<SupplyChainEvidenceRailItem["kind"], string> = {
  block: "Last block",
  audit: "Last audit",
  sync: "Last sync",
};

type EvidenceRailRowProps = {
  item: SupplyChainEvidenceRailItem;
};

function EvidenceRailRow({ item }: EvidenceRailRowProps) {
  const href = supplyChainEvidenceHref(item.receiptId, item.harness);
  const tagTone = item.tone === "green" ? "green" : item.tone === "attention" ? "attention" : "slate";

  return (
    <li className="min-w-0 space-y-1 py-3 sm:py-0">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs font-medium text-slate-600">{kindLabels[item.kind]}</p>
        {item.timestamp !== null ? <Tag tone={tagTone}>{formatRelativeTime(item.timestamp)}</Tag> : null}
      </div>
      {/* Nothing recorded yet is one plain line, not a pill and a paragraph. */}
      <p className={`text-sm ${item.timestamp !== null ? "font-medium text-brand-dark" : "text-slate-500"}`}>
        {item.title}
      </p>
      {item.timestamp !== null ? <p className="text-xs leading-relaxed text-slate-500">{item.detail}</p> : null}
      {href !== null ? (
        <a
          href={href}
          className="inline-flex items-center gap-1 rounded text-xs font-medium text-brand-blue hover:underline focus:outline-none focus:ring-2 focus:ring-brand-blue/30"
        >
          Open evidence
          <HiMiniArrowTopRightOnSquare className="h-3.5 w-3.5" aria-hidden="true" />
        </a>
      ) : null}
    </li>
  );
}

/** Holds the section's place while receipts load, so the page below it does not jump. */
export function SupplyChainEvidenceRailPlaceholder() {
  return (
    <SupplyChainDetailSection
      id="supply-chain-evidence-heading"
      title="Recent activity"
      lead="The latest blocked install, project audit, and policy sync on this device."
    >
      <div className="grid gap-6 sm:grid-cols-3" aria-hidden="true">
        <div className="guard-skeleton h-10" />
        <div className="guard-skeleton h-10" />
        <div className="guard-skeleton h-10" />
      </div>
    </SupplyChainDetailSection>
  );
}

export function SupplyChainEvidenceRail({ rail }: SupplyChainEvidenceRailProps) {
  // Three facts of the same kind read across on wide screens, so they sit
  // in one row instead of three stacked blocks.
  return (
    <SupplyChainDetailSection
      id="supply-chain-evidence-heading"
      title="Recent activity"
      lead="The latest blocked install, project audit, and policy sync on this device."
      aria-label="Recent supply chain evidence"
      data-testid="supply-chain-evidence-rail"
    >
      <ul className="grid min-w-0 divide-y divide-slate-100 sm:grid-cols-3 sm:gap-6 sm:divide-y-0">
        <EvidenceRailRow item={rail.block} />
        <EvidenceRailRow item={rail.audit} />
        <EvidenceRailRow item={rail.sync} />
      </ul>
    </SupplyChainDetailSection>
  );
}

type SupplyChainCloudDegradedBannerProps = {
  state: SupplyChainCloudDegradedState;
};

export function SupplyChainCloudDegradedBanner({ state }: SupplyChainCloudDegradedBannerProps) {
  if (!state.active) {
    return null;
  }

  return (
    <div
      className="rounded-2xl border border-brand-attention/20 bg-brand-attention/[0.04] px-4 py-3"
      role="status"
      data-testid="supply-chain-cloud-degraded"
    >
      <p className="text-sm font-medium text-brand-dark">{state.title}</p>
      <p className="mt-1 text-xs leading-relaxed text-slate-600">{state.detail}</p>
    </div>
  );
}
