import { useCallback, useState, type ReactNode } from "react";
import { HiMiniCloud, HiMiniQuestionMarkCircle, HiMiniChevronDown, HiMiniChevronUp } from "react-icons/hi2";
import { ActionButton, SectionLabel } from "./approval-center-primitives";
import { formatRelativeTime } from "./approval-center-utils";
import { resolveCloudIntelCopy } from "./runtime-overview";
import { buildRecentProtectionCopy, safeLocalStorage } from "./home-dashboard-model";
import type { GuardRuntimeSnapshot, GuardReceipt } from "./guard-types";

export function ClearHarnessButton(props: {
  harness: string;
  onClearPolicies: (scope: { harness?: string; all?: boolean }) => void;
}) {
  const handleClick = useCallback(() => {
    void props.onClearPolicies({ harness: props.harness });
  }, [props.onClearPolicies, props.harness]);

  return (
    <ActionButton variant="outline" onClick={handleClick}>
      Clear {props.harness}
    </ActionButton>
  );
}

export function CloudStatusCard(props: {
  snapshot: GuardRuntimeSnapshot;
  showUpsell: boolean;
  onOpenSettings: () => void;
}) {
  const copy = resolveCloudIntelCopy(props.snapshot.cloud_state);
  return (
    <section className="rounded-2xl border border-brand-blue/15 bg-brand-blue/[0.04] p-5 shadow-sm sm:p-6">
      <div className="flex items-start gap-3">
        <span className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-white/80 text-brand-blue">
          <HiMiniCloud className="h-5 w-5" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1">
          <SectionLabel>Cloud sync</SectionLabel>
          <p className="mt-2 text-sm font-medium text-brand-dark">{copy.label}</p>
          <p className="mt-1 text-sm text-muted-foreground">{copy.detail}</p>
          {props.showUpsell && (
            <div className="mt-4">
              <ActionButton variant="outline" onClick={props.onOpenSettings}>
                Open sync settings
              </ActionButton>
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

export function KeyboardHelpCard(props: { onOpenHelp?: () => void }) {
  if (!props.onOpenHelp) {
    return null;
  }
  return (
    <section className="rounded-2xl border border-slate-200/70 bg-white/80 p-5 shadow-sm sm:p-6">
      <div className="flex items-start gap-3">
        <span className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-slate-100 text-brand-dark">
          <HiMiniQuestionMarkCircle className="h-5 w-5" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1">
          <SectionLabel>Shortcuts</SectionLabel>
          <p className="mt-2 text-sm text-muted-foreground">
            Press ? for help or / to jump to pending review. Every Home action also works with Tab and Enter.
          </p>
          <div className="mt-4">
            <ActionButton variant="ghost" onClick={props.onOpenHelp}>
              Show shortcuts
            </ActionButton>
          </div>
        </div>
      </div>
    </section>
  );
}


type RecentReceiptRowProps = {
  receipt: GuardReceipt;
};

function RecentReceiptRow(props: RecentReceiptRowProps) {
  const { receipt } = props;
  const copy = buildRecentProtectionCopy(receipt);
  return (
    <div className="flex items-start justify-between gap-3 border-b border-slate-200/70 px-4 py-3 last:border-b-0">
      <div className="min-w-0">
        <p className="text-sm text-brand-dark">
          {copy}
        </p>
      </div>
      <span className="shrink-0 text-[11px] text-muted-foreground">
        {formatRelativeTime(receipt.timestamp)}
      </span>
    </div>
  );
}

type RecentProtectionSectionProps = {
  receipts: GuardReceipt[];
};

export function RecentProtectionSection(props: RecentProtectionSectionProps) {
  const recent = props.receipts.slice(0, 3);
  return (
    <section className="rounded-2xl border border-slate-200/70 bg-white/80 p-5 shadow-sm sm:p-6">
      <SectionLabel>Recent protection</SectionLabel>
      <p className="mt-2 text-sm text-muted-foreground">
        What Guard stopped or allowed recently.
      </p>
      <div className="mt-4 overflow-hidden rounded-xl border border-slate-200/70">
        {recent.map((receipt) => (
          <RecentReceiptRow key={receipt.receipt_id} receipt={receipt} />
        ))}
      </div>
    </section>
  );
}

export function CollapsibleCard(props: {
  id: string;
  icon: ReactNode;
  label: string;
  defaultOpen?: boolean;
  children: ReactNode;
}) {
  const storageKey = `guard-collapsed-${props.id}`;
  const [isOpen, setIsOpen] = useState(() => {
    const saved = safeLocalStorage.getItem(storageKey);
    return saved === null ? (props.defaultOpen ?? true) : saved === "1";
  });

  const toggle = useCallback(() => {
    setIsOpen((prev) => {
      const next = !prev;
      safeLocalStorage.setItem(storageKey, next ? "1" : "0");
      return next;
    });
  }, [storageKey]);

  const borderClass =
    props.id === "daily-brief"
      ? "border-brand-green/15 bg-brand-green/[0.04]"
      : "border-brand-purple/15 bg-brand-purple/[0.04]";

  return (
    <div className={`rounded-2xl border ${borderClass} p-5 shadow-sm sm:p-6`}>
      <button
        onClick={toggle}
        className="flex w-full items-center gap-3 text-left"
        aria-expanded={isOpen}
        aria-controls={`collapsible-content-${props.id}`}
      >
        {props.icon}
        <div className="flex-1">
          <SectionLabel>{props.label}</SectionLabel>
        </div>
        {isOpen ? (
          <HiMiniChevronUp className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        ) : (
          <HiMiniChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" aria-hidden="true" />
        )}
      </button>
      {isOpen && (
        <div id={`collapsible-content-${props.id}`} className="mt-3 guard-fade-in">
          {props.children}
        </div>
      )}
    </div>
  );
}
