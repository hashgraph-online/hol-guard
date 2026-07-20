import { useMemo, memo } from "react";
import {
  HiMiniChevronLeft,
  HiMiniChevronRight,
} from "react-icons/hi2";
import type { GuardReceipt } from "../guard-types";
import { harnessDisplayName, formatRelativeTime } from "../approval-center-utils";
import { detectCategory, getCategoryInfo } from "./categories";
import { plainEnglishDescription } from "./plain-english";
import { guardActionDisposition } from "../guard-action";
import { DecisionBadge } from "./decision-badge";

interface StoryTabProps {
  receipts: GuardReceipt[];
  selectedDay: string;
  onSelectDay: (day: string) => void;
}

function StoryTabRaw({ receipts, selectedDay, onSelectDay }: StoryTabProps) {
  const daysWithData = useMemo(() => {
    const set = new Set<string>();
    for (const r of receipts) {
      const d = new Date(r.timestamp);
      const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
      set.add(key);
    }
    return set;
  }, [receipts]);

  const effectiveDay = useMemo(() => {
    if (selectedDay) return selectedDay;
    if (daysWithData.size === 0) return "";
    const sorted = Array.from(daysWithData).sort();
    return sorted[sorted.length - 1];
  }, [selectedDay, daysWithData]);

  const dayReceipts = useMemo(() => {
    if (!effectiveDay) return [];
    const start = new Date(effectiveDay);
    start.setHours(0, 0, 0, 0);
    const end = new Date(start);
    end.setDate(end.getDate() + 1);
    return receipts.filter((r) => {
      const d = new Date(r.timestamp);
      return d >= start && d < end;
    });
  }, [receipts, effectiveDay]);

  const summary = useMemo(() => {
    const allowed = dayReceipts.filter((r) => guardActionDisposition(r.policy_decision) === "allowed").length;
    const blocked = dayReceipts.filter((r) => guardActionDisposition(r.policy_decision) === "blocked").length;
    const reviewed = dayReceipts.filter((r) => guardActionDisposition(r.policy_decision) === "reviewed").length;
    return { allowed, blocked, reviewed, total: dayReceipts.length };
  }, [dayReceipts]);

  const dayLabel = useMemo(() => {
    if (!effectiveDay) return "No data";
    const d = new Date(effectiveDay);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const diff = Math.floor((today.getTime() - d.getTime()) / (1000 * 60 * 60 * 24));
    if (diff === 0) return "Today";
    if (diff === 1) return "Yesterday";
    return d.toLocaleDateString("en-US", { weekday: "long", month: "short", day: "numeric" });
  }, [effectiveDay]);

  const sortedDays = useMemo(() => Array.from(daysWithData).sort(), [daysWithData]);

  const currentIndex = useMemo(() => sortedDays.indexOf(effectiveDay), [sortedDays, effectiveDay]);

  const handlePrevDay = () => {
    if (currentIndex <= 0) return;
    onSelectDay(sortedDays[currentIndex - 1]);
  };

  const handleNextDay = () => {
    if (currentIndex < 0 || currentIndex >= sortedDays.length - 1) return;
    onSelectDay(sortedDays[currentIndex + 1]);
  };

  const hasPrev = currentIndex > 0;
  const hasNext = currentIndex >= 0 && currentIndex < sortedDays.length - 1;

  if (receipts.length === 0) {
    return (
      <div className="rounded-2xl border border-slate-100 bg-white/60 p-8 text-center">
        <p className="text-sm text-slate-500">All quiet. Guard is watching.</p>
        <p className="mt-1 text-xs text-slate-400">Saved decisions will appear here.</p>
      </div>
    );
  }

  if (dayReceipts.length === 0) {
    return (
      <div className="space-y-6">
        <DayHeader dayLabel={dayLabel} onPrev={handlePrevDay} onNext={handleNextDay} hasPrev={hasPrev} hasNext={hasNext} />
        <div className="rounded-2xl border border-slate-100 bg-white/60 p-8 text-center">
          <p className="text-sm text-slate-500">No decisions on this day.</p>
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
            <span className="text-brand-green">Allowed {summary.allowed}.</span>
          )}{" "}
          {summary.blocked > 0 && (
            <span className="text-brand-attention">Stopped {summary.blocked}.</span>
          )}
          {summary.reviewed > 0 && (
            <span className="text-brand-blue">Review required {summary.reviewed}.</span>
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

  return (
    <div className="rounded-2xl border border-slate-100 bg-white p-4 shadow-sm transition-all hover:shadow-md">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className={`inline-flex h-6 w-6 items-center justify-center rounded-full bg-slate-50 ${catInfo.color}`}>
              {catInfo.icon}
            </span>
            <span className="text-xs font-medium text-slate-500">{harnessDisplayName(receipt.harness)}</span>
            <span className="text-xs text-slate-400">·</span>
            <span className="text-xs text-slate-400">{formatRelativeTime(receipt.timestamp)}</span>
          </div>
          <p className="mt-2 text-sm text-brand-dark">{description}</p>
        </div>
        <DecisionBadge decision={receipt.policy_decision} />
      </div>
      <div className="mt-3 flex items-center gap-2">
        <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-[10px] font-medium uppercase tracking-wider ${catInfo.color} bg-slate-50`}>
          {catInfo.label}
        </span>
      </div>
    </div>
  );
}

export const StoryTab = memo(StoryTabRaw);
