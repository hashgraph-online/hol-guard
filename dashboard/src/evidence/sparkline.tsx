import { useMemo } from "react";
import type { GuardReceipt } from "../guard-types";

interface SparklineProps {
  items: GuardReceipt[];
  days?: number;
}

export function Sparkline({ items, days = 7 }: SparklineProps) {
  const buckets = useMemo(() => {
    const now = new Date();
    const counts: number[] = new Array(days).fill(0);
    for (const item of items) {
      const d = new Date(item.timestamp);
      const diff = Math.floor((now.getTime() - d.getTime()) / (1000 * 60 * 60 * 24));
      if (diff >= 0 && diff < days) {
        counts[days - 1 - diff] += 1;
      }
    }
    return counts;
  }, [items, days]);

  const max = Math.max(...buckets, 1);

  return (
    <div className="mt-4 pt-4 border-t border-slate-100">
      <p className="text-[11px] font-medium text-slate-400 mb-2">Last {days} days</p>
      <div className="flex h-10 w-full items-end gap-1">
        {buckets.map((count, i) => (
          <div
            key={i}
            className="flex-1 rounded-sm bg-brand-blue/20 transition-all hover:bg-brand-blue/30"
            style={{ height: `${Math.max((count / max) * 100, count > 0 ? 8 : 4)}%` }}
            title={`${count} action${count !== 1 ? "s" : ""}`}
          />
        ))}
      </div>
    </div>
  );
}
