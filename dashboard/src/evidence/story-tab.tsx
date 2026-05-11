import { useMemo } from "react";
import { HiMiniChevronLeft, HiMiniChevronRight, HiMiniCheckCircle, HiMiniNoSymbol, HiMiniQuestionMarkCircle } from "react-icons/hi2";
import type { GuardReceipt } from "../guard-types";
import { harnessDisplayName, formatRelativeTime } from "../approval-center-utils";
import { detectCategory, getCategoryInfo } from "./categories";
import { plainEnglishDescription } from "./plain-english";

interface StoryTabProps {
  receipts: GuardReceipt[];
  selectedDay: string;
  onSelectDay: (day: string) => void;
}

export function StoryTab({ receipts, selectedDay, onSelectDay }: StoryTabProps) {
  const dayReceipts = useMemo(() => {
    if (!selectedDay) return receipts.slice(0, 20);
    const start = new Date(selectedDay);
    start.setHours(0, 0, 0, 0);
    const end = new Date(start);
    end.setDate(end.getDate() + 1);
    return receipts.filter((r) => {
      const d = new Date(r.timestamp);
      return d >= start && d < end;
    });
  }, [receipts, selectedDay]);

  const summary = useMemo(() => {
    const allowed = dayReceipts.filter((r) => r.policy_decision === "allow").length;
    const blocked = dayReceipts.filter((r) => r.policy_decision === "block").length;
    return { allowed, blocked, total: dayReceipts.length };
  }, [dayReceipts]);

  const dayLabel = useMemo(() => {
    if (!selectedDay) return "Recently";
    const d = new Date(selectedDay);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const diff = Math.floor((today.getTime() - d.getTime()) / (1000 * 60 * 60 * 24));
    if (diff === 0) return "Today";
    if (diff === 1) return "Yesterday";
    return d.toLocaleDateString("en-US", { weekday: "long", month: "short", day: "numeric" });
  }, [selectedDay]);

  const handlePrevDay = () => {
    if (!selectedDay) return;
    const d = new Date(selectedDay);
    d.setDate(d.getDate() - 1);
    onSelectDay(d.toISOString().split("T")[0]);
  };

  const handleNextDay = () => {
    if (!selectedDay) return;
    const d = new Date(selectedDay);
    d.setDate(d.getDate() + 1);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    if (d > today) return;
    onSelectDay(d.toISOString().split("T")[0]);
  };

  // Calculate navigation bounds across all receipt dates
  const { hasPrev, hasNext } = useMemo(() => {
    if (!selectedDay) {
      // "Recently" view - check if there are receipts beyond the first 20
      return { hasPrev: receipts.length > 20, hasNext: false };
    }
    const current = new Date(selectedDay);
    current.setHours(0, 0, 0, 0);
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    // Allow prev if there are any receipts older than current day
    const oldestReceipt = receipts.length > 0
      ? new Date(receipts[receipts.length - 1].timestamp)
      : null;
    const hasPrevDay = oldestReceipt !== null && oldestReceipt < current;

    // Allow next if current day is before today
    const hasNextDay = current < today;

    return { hasPrev: hasPrevDay, hasNext: hasNextDay };
  }, [receipts, selectedDay]);

  if (dayReceipts.length === 0) {
    return (
      <div className="space-y-6">
        <DayHeader dayLabel={dayLabel} onPrev={handlePrevDay} onNext={handleNextDay} hasPrev={hasPrev} hasNext={hasNext} />
        <div className="rounded-2xl border border-slate-100 bg-white/60 p-8 text-center">
          <p className="text-sm text-slate-500">All quiet. Guard is watching.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <DayHeader dayLabel={dayLabel} onPrev={handlePrevDay} onNext={handleNextDay} hasPrev={hasPrev} hasNext={hasNext} />

      <div className="rounded-2xl border border-slate-100 bg-white/60 p-4">
        <p className="text-sm text-brand-dark">
          Guard reviewed {summary.total} action{summary.total !== 1 ? "s" : ""}.{" "}
          {summary.allowed > 0 && (
            <span className="text-emerald-600">Allowed {summary.allowed}.</span>
          )}{" "}
          {summary.blocked > 0 && (
            <span className="text-brand-attention">Stopped {summary.blocked}.</span>
          )}
        </p>
      </div>

      <div className="space-y-4">
        {dayReceipts.map((receipt) => (
          <StoryCard key={receipt.receipt_id} receipt={receipt} />
        ))}
      </div>
    </div>
  );
}

function DayHeader({
  dayLabel,
  onPrev,
  onNext,
  hasPrev,
  hasNext,
}: {
  dayLabel: string;
  onPrev: () => void;
  onNext: () => void;
  hasPrev: boolean;
  hasNext: boolean;
}) {
  return (
    <div className="flex items-center justify-between">
      <button
        onClick={onPrev}
        disabled={!hasPrev}
        className="inline-flex items-center gap-1 rounded-lg px-3 py-1.5 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-100 disabled:opacity-30 disabled:hover:bg-transparent"
      >
        <HiMiniChevronLeft className="h-4 w-4" aria-hidden="true" />
        Previous
      </button>
      <h2 className="text-lg font-semibold text-brand-dark">{dayLabel}</h2>
      <button
        onClick={onNext}
        disabled={!hasNext}
        className="inline-flex items-center gap-1 rounded-lg px-3 py-1.5 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-100 disabled:opacity-30 disabled:hover:bg-transparent"
      >
        Next
        <HiMiniChevronRight className="h-4 w-4" aria-hidden="true" />
      </button>
    </div>
  );
}

function StoryCard({ receipt }: { receipt: GuardReceipt }) {
  const category = detectCategory(receipt);
  const catInfo = getCategoryInfo(category);
  const description = plainEnglishDescription(receipt);
  const isAllowed = receipt.policy_decision === "allow";

  return (
    <div className="rounded-2xl border border-slate-100 bg-white p-4 shadow-sm transition-all hover:shadow-md">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className={`inline-flex h-6 w-6 items-center justify-center rounded-full bg-slate-50 text-xs ${catInfo.color}`}>
              {catInfo.label[0]}
            </span>
            <span className="text-xs font-medium text-slate-500">{harnessDisplayName(receipt.harness)}</span>
            <span className="text-xs text-slate-400">·</span>
            <span className="text-xs text-slate-400">{formatRelativeTime(receipt.timestamp)}</span>
          </div>
          <p className="mt-2 text-sm text-brand-dark">{description}</p>
        </div>
        <DecisionBadge allowed={isAllowed} />
      </div>
      <div className="mt-3 flex items-center gap-2">
        <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-[10px] font-medium uppercase tracking-wider ${catInfo.color} bg-slate-50`}>
          {catInfo.label}
        </span>
      </div>
    </div>
  );
}

function DecisionBadge({ allowed }: { allowed: boolean }) {
  if (allowed) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2.5 py-1 text-xs font-medium text-emerald-700">
        <HiMiniCheckCircle className="h-3.5 w-3.5" aria-hidden="true" />
        Allowed
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-brand-dark">
      <HiMiniNoSymbol className="h-3.5 w-3.5" aria-hidden="true" />
      Stopped
    </span>
  );
}
