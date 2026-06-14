type PolicyCloudExceptionsSummaryProps = {
  activeCount: number;
  pendingCount: number;
  expiringSoonCount: number;
  ackFailureCount: number;
  loading?: boolean;
};

type SummaryTone = "blue" | "amber" | "attention" | "slate" | "green";

const SUMMARY_TONE_CLASSES: Record<SummaryTone, string> = {
  blue: "text-brand-blue",
  green: "text-emerald-700",
  amber: "text-amber-700",
  attention: "text-brand-attention",
  slate: "text-brand-dark",
};

function SummaryCard({
  label,
  value,
  detail,
  tone = "slate",
}: {
  label: string;
  value: number;
  detail: string;
  tone?: SummaryTone;
}) {
  const toneClass = SUMMARY_TONE_CLASSES[tone];
  return (
    <div className="rounded-xl border border-slate-200/70 bg-white p-4 shadow-sm">
      <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{label}</p>
      <p className={`mt-2 text-3xl font-semibold tabular-nums ${toneClass}`}>{value}</p>
      <p className="mt-1 text-xs text-slate-500">{detail}</p>
    </div>
  );
}

function SummarySkeleton() {
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
      {[0, 1, 2, 3].map((index) => (
        <div
          key={index}
          className="h-[88px] animate-pulse rounded-xl border border-slate-200/70 bg-slate-100"
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
      <SummaryCard label="Active synced" value={activeCount} detail="Enforced locally" tone="green" />
      <SummaryCard label="Pending approval" value={pendingCount} detail="Awaiting decision" tone="blue" />
      <SummaryCard label="Expiring soon" value={expiringSoonCount} detail="Within 7 days" tone="amber" />
      <SummaryCard label="Local ack failures" value={ackFailureCount} detail="Needs attention" tone="attention" />
    </div>
  );
}
