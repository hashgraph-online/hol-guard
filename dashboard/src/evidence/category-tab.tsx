import { useMemo, useState } from "react";
import { HiMiniChevronRight, HiMiniLockClosed, HiMiniGlobeAlt, HiMiniExclamationTriangle, HiMiniEyeSlash, HiMiniDocumentText, HiMiniWrenchScrewdriver, HiMiniCircleStack } from "react-icons/hi2";
import type { GuardReceipt } from "../guard-types";
import { groupByCategory, getCategoryInfo, type ReceiptCategory, CATEGORIES } from "./categories";
import { plainEnglishDescription } from "./plain-english";
import { formatRelativeTime, harnessDisplayName } from "../approval-center-utils";

interface CategoryTabProps {
  receipts: GuardReceipt[];
  onFilterCategory?: (category: ReceiptCategory) => void;
}

const ICON_MAP: Record<ReceiptCategory, React.ReactNode> = {
  secret: <HiMiniLockClosed className="h-5 w-5" aria-hidden="true" />,
  network: <HiMiniGlobeAlt className="h-5 w-5" aria-hidden="true" />,
  destructive: <HiMiniExclamationTriangle className="h-5 w-5" aria-hidden="true" />,
  hidden: <HiMiniEyeSlash className="h-5 w-5" aria-hidden="true" />,
  "file-write": <HiMiniDocumentText className="h-5 w-5" aria-hidden="true" />,
  "tool-call": <HiMiniWrenchScrewdriver className="h-5 w-5" aria-hidden="true" />,
  other: <HiMiniCircleStack className="h-5 w-5" aria-hidden="true" />,
};

export function CategoryTab({ receipts, onFilterCategory }: CategoryTabProps) {
  const [selectedCategory, setSelectedCategory] = useState<ReceiptCategory | null>(null);

  const groups = useMemo(() => groupByCategory(receipts), [receipts]);

  if (selectedCategory) {
    const items = groups.get(selectedCategory) ?? [];
    const info = getCategoryInfo(selectedCategory);
    return (
      <div className="space-y-6">
        <button
          onClick={() => setSelectedCategory(null)}
          className="inline-flex items-center gap-1 rounded-lg px-3 py-1.5 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-100"
        >
          ← Back to categories
        </button>

        <div className="rounded-2xl border border-slate-100 bg-white/60 p-5">
          <div className="flex items-center gap-3">
            <span className={`inline-flex h-10 w-10 items-center justify-center rounded-full bg-slate-50 ${info.color}`}>
              {ICON_MAP[selectedCategory]}
            </span>
            <div>
              <h2 className="text-lg font-semibold text-brand-dark">{info.label}</h2>
              <p className="text-sm text-slate-500">{info.description}</p>
            </div>
          </div>
          <p className="mt-4 text-sm text-brand-dark">
            {items.length} action{items.length !== 1 ? "s" : ""} in this category
          </p>
        </div>

        <div className="space-y-3">
          {items.map((receipt) => (
            <div
              key={receipt.receipt_id}
              className="rounded-2xl border border-slate-100 bg-white p-4 shadow-sm"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <p className="text-sm text-brand-dark">{plainEnglishDescription(receipt)}</p>
                  <p className="mt-1 text-xs text-slate-400">
                    {harnessDisplayName(receipt.harness)} · {formatRelativeTime(receipt.timestamp)}
                  </p>
                </div>
                <span className={`shrink-0 text-xs font-medium ${receipt.policy_decision === "allow" ? "text-emerald-600" : "text-brand-attention"}`}>
                  {receipt.policy_decision === "allow" ? "Allowed" : "Stopped"}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {CATEGORIES.map((cat) => {
        const items = groups.get(cat.key) ?? [];
        if (items.length === 0) return null;
        return (
          <button
            key={cat.key}
            onClick={() => {
              setSelectedCategory(cat.key);
              onFilterCategory?.(cat.key);
            }}
            className="flex w-full items-center justify-between gap-3 rounded-2xl border border-slate-100 bg-white p-4 text-left shadow-sm transition-all hover:shadow-md"
          >
            <div className="flex items-center gap-3">
              <span className={`inline-flex h-10 w-10 items-center justify-center rounded-full bg-slate-50 ${cat.color}`}>
                {ICON_MAP[cat.key]}
              </span>
              <div>
                <p className="text-sm font-medium text-brand-dark">{cat.label}</p>
                <p className="text-xs text-slate-500">{items.length} action{items.length !== 1 ? "s" : ""}</p>
              </div>
            </div>
            <HiMiniChevronRight className="h-4 w-4 text-slate-300" aria-hidden="true" />
          </button>
        );
      })}

      {Array.from(groups.values()).every((items) => items.length === 0) && (
        <div className="rounded-2xl border border-slate-100 bg-white/60 p-8 text-center">
          <p className="text-sm text-slate-500">No activity yet.</p>
        </div>
      )}
    </div>
  );
}
