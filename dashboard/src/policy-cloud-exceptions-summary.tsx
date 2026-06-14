type PolicyCloudExceptionsSummaryProps = {
  activeCount: number;
  pendingCount: number;
  expiringSoonCount: number;
  ackFailureCount: number;
  loading?: boolean;
};

function SummaryCard({
  label,
  value,
  tone = "slate",
}: {
  label: string;
  value: number;
  tone?: "blue" | "amber" | "attention" | "slate";
}) {
  const toneClass =
    tone === "blue"
      ? "text-brand-blue"
      : tone === "amber"
        ? "text-amber-700"
        : tone === "attention"
          ? "text-brand-attention"
          : "text-brand-dark";
  return (
    <div className="rounded-xl border border-slate-200/70 bg-white p-3 text-center shadow-sm">
      <p className={`text-2xl font-semibold tabular-nums ${toneClass}`}>{value}</p>
      <p className="mt-1 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">{label}</p>
    </div>
  );
}

function SummarySkeleton() {
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
      {[0, 1, 2, 3].map((index) => (
        <div
          key={index}
          className="h-[72px] animate-pulse rounded-xl border border-slate-200/70 bg-slate-100"
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
      <SummaryCard label="Active synced" value={activeCount} tone="blue" />
      <SummaryCard label="Pending approval" value={pendingCount} tone="amber" />
      <SummaryCard label="Expiring soon" value={expiringSoonCount} tone="attention" />
      <SummaryCard label="Local ack failures" value={ackFailureCount} tone="attention" />
    </div>
  );
}
