import {
  HiMiniClock,
  HiMiniExclamationTriangle,
  HiMiniShieldCheck,
} from "react-icons/hi2";
import type { ReactNode } from "react";

type PolicyCloudExceptionsSummaryProps = {
  activeCount: number;
  pendingCount: number;
  expiringSoonCount: number;
  ackFailureCount: number;
  loading?: boolean;
};

type SummaryTone = "green" | "purple" | "amber" | "red";

const SUMMARY_VALUE_CLASSES: Record<SummaryTone, string> = {
  green: "text-emerald-700",
  purple: "text-violet-700",
  amber: "text-amber-700",
  red: "text-rose-700",
};

const SUMMARY_ICON_CLASSES: Record<SummaryTone, string> = {
  green: "bg-emerald-50 text-emerald-600",
  purple: "bg-violet-50 text-violet-600",
  amber: "bg-amber-50 text-amber-600",
  red: "bg-rose-50 text-rose-600",
};

function SummaryCard({
  label,
  value,
  detail,
  tone,
  icon,
}: {
  label: string;
  value: number;
  detail: string;
  tone: SummaryTone;
  icon: ReactNode;
}) {
  return (
    <div className="rounded-xl border border-slate-200/70 bg-white p-4 shadow-sm">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{label}</p>
          <p className={`mt-2 text-3xl font-semibold tabular-nums ${SUMMARY_VALUE_CLASSES[tone]}`}>{value}</p>
          <p className="mt-1 text-xs text-slate-500">{detail}</p>
        </div>
        <span
          className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-xl ${SUMMARY_ICON_CLASSES[tone]}`}
          aria-hidden="true"
        >
          {icon}
        </span>
      </div>
    </div>
  );
}

function SummarySkeleton() {
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
      {[0, 1, 2, 3].map((index) => (
        <div
          key={index}
          className="h-[96px] animate-pulse rounded-xl border border-slate-200/70 bg-slate-100"
          aria-hidden="true"
        />
      ))}
    </div>
  );
}

export function PolicyCloudExceptionsSummary({
  activeCount,
  pendingCount,
  expiringSoonCount,
  ackFailureCount,
  loading = false,
}: PolicyCloudExceptionsSummaryProps) {
  if (loading) {
    return <SummarySkeleton />;
  }

  return (
    <div
      className="grid grid-cols-2 gap-3 md:grid-cols-4"
      aria-label="Cloud exception summary"
    >
      <SummaryCard
        label="Active synced"
        value={activeCount}
        detail="Enforced locally"
        tone="green"
        icon={<HiMiniShieldCheck className="h-5 w-5" />}
      />
      <SummaryCard
        label="Pending approval"
        value={pendingCount}
        detail="Awaiting decision"
        tone="purple"
        icon={<HiMiniClock className="h-5 w-5" />}
      />
      <SummaryCard
        label="Expiring soon"
        value={expiringSoonCount}
        detail="Within 7 days"
        tone="amber"
        icon={<HiMiniClock className="h-5 w-5" />}
      />
      <SummaryCard
        label="Local ack failures"
        value={ackFailureCount}
        detail="Needs attention"
        tone="red"
        icon={<HiMiniExclamationTriangle className="h-5 w-5" />}
      />
    </div>
  );
}
