import {
  HiMiniArrowTopRightOnSquare,
  HiMiniArrowPath,
  HiMiniDocumentMagnifyingGlass,
  HiMiniShieldExclamation,
} from "react-icons/hi2";
import { SectionLabel, Tag } from "./approval-center-primitives";
import { formatRelativeTime } from "./approval-center-utils";
import type {
  SupplyChainCloudDegradedState,
  SupplyChainEvidenceRailItem,
  SupplyChainEvidenceRailSnapshot,
} from "./supply-chain-evidence-rail";
import { supplyChainEvidenceHref } from "./supply-chain-evidence-rail";

type SupplyChainEvidenceRailProps = {
  rail: SupplyChainEvidenceRailSnapshot;
};

const kindLabels: Record<SupplyChainEvidenceRailItem["kind"], string> = {
  block: "Last block",
  audit: "Last audit",
  sync: "Last sync",
};

const kindIcons: Record<SupplyChainEvidenceRailItem["kind"], typeof HiMiniShieldExclamation> = {
  block: HiMiniShieldExclamation,
  audit: HiMiniDocumentMagnifyingGlass,
  sync: HiMiniArrowPath,
};

type EvidenceRailRowProps = {
  item: SupplyChainEvidenceRailItem;
};

function EvidenceRailRow({ item }: EvidenceRailRowProps) {
  const Icon = kindIcons[item.kind];
  const href = supplyChainEvidenceHref(item.receiptId);
  const tagTone = item.tone === "green" ? "green" : item.tone === "attention" ? "attention" : "slate";

  return (
    <div className="px-4 py-3">
      <div className="flex items-start gap-3">
        <span
          className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-slate-50 text-slate-500"
          aria-hidden="true"
        >
          <Icon className="h-4 w-4" />
        </span>
        <div className="min-w-0 flex-1 space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-400">
              {kindLabels[item.kind]}
            </p>
            {item.timestamp !== null ? (
              <Tag tone={tagTone}>{formatRelativeTime(item.timestamp)}</Tag>
            ) : (
              <Tag tone="slate">Waiting</Tag>
            )}
          </div>
          <p className="text-sm font-medium text-brand-dark">{item.title}</p>
          <p className="text-xs leading-relaxed text-slate-500">{item.detail}</p>
          {href !== null ? (
            <a
              href={href}
              className="inline-flex items-center gap-1 text-xs font-medium text-brand-blue hover:underline focus:outline-none focus:ring-2 focus:ring-brand-blue/30 rounded"
            >
              Open evidence
              <HiMiniArrowTopRightOnSquare className="h-3.5 w-3.5" aria-hidden="true" />
            </a>
          ) : null}
        </div>
      </div>
    </div>
  );
}

export function SupplyChainEvidenceRail({ rail }: SupplyChainEvidenceRailProps) {
  return (
    <section
      className="overflow-hidden rounded-2xl border border-slate-100 bg-white shadow-sm"
      aria-label="Recent supply chain evidence"
      data-testid="supply-chain-evidence-rail"
    >
      <div className="border-b border-slate-100 px-4 py-3">
        <SectionLabel>Recent evidence</SectionLabel>
        <p className="mt-1 text-sm text-slate-500">
          Latest block, audit, and policy sync recorded on this machine.
        </p>
      </div>
      <div className="divide-y divide-slate-100">
        <EvidenceRailRow item={rail.block} />
        <EvidenceRailRow item={rail.audit} />
        <EvidenceRailRow item={rail.sync} />
      </div>
    </section>
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
      className="rounded-2xl border border-amber-200 bg-amber-50/70 px-4 py-3"
      role="status"
      data-testid="supply-chain-cloud-degraded"
    >
      <p className="text-sm font-medium text-amber-950">{state.title}</p>
      <p className="mt-1 text-xs leading-relaxed text-amber-900/90">{state.detail}</p>
    </div>
  );
}
