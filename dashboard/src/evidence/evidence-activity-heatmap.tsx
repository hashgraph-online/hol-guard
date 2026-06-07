import { useMemo } from "react";
import type { GuardReceiptDailyActivity } from "../guard-types";

type HeatmapCell = {
  date_key: string;
  total: number;
};

function intensityClass(total: number, peak: number): string {
  if (total <= 0) return "bg-slate-100/80";
  const ratio = peak > 0 ? total / peak : 0;
  if (ratio >= 0.75) return "bg-amber-600 hover:bg-amber-700";
  if (ratio >= 0.4) return "bg-amber-400 hover:bg-amber-500";
  if (ratio >= 0.15) return "bg-amber-200 hover:bg-amber-300";
  return "bg-amber-100 hover:bg-amber-200";
}

function buildWeekColumns(days: GuardReceiptDailyActivity[]): Array<Array<HeatmapCell | null>> {
  if (days.length === 0) return [];

  const first = new Date(`${days[0].date_key}T12:00:00`);
  const startPad = first.getDay();
  const cells: Array<HeatmapCell | null> = [
    ...Array.from({ length: startPad }, () => null),
    ...days.map((day) => ({ date_key: day.date_key, total: day.total })),
  ];

  const weeks: Array<Array<HeatmapCell | null>> = [];
  for (let index = 0; index < cells.length; index += 7) {
    const column: Array<HeatmapCell | null> = cells.slice(index, index + 7);
    while (column.length < 7) {
      column.push(null);
    }
    weeks.push(column);
  }
  return weeks;
}

function monthLabels(weeks: Array<Array<HeatmapCell | null>>): string[] {
  const labels: string[] = [];
  let lastMonth = -1;
  for (const week of weeks) {
    const firstDay = week.find((cell) => cell !== null);
    if (!firstDay) {
      labels.push("");
      continue;
    }
    const month = new Date(`${firstDay.date_key}T12:00:00`).getMonth();
    if (month !== lastMonth) {
      labels.push(new Date(`${firstDay.date_key}T12:00:00`).toLocaleDateString(undefined, { month: "short" }));
      lastMonth = month;
    } else {
      labels.push("");
    }
  }
  return labels;
}

export function EvidenceActivityHeatmap({
  days,
  onSelectDay,
}: {
  days: GuardReceiptDailyActivity[];
  onSelectDay?: (dateKey: string) => void;
}) {
  const peak = useMemo(() => Math.max(...days.map((day) => day.total), 0), [days]);
  const weeks = useMemo(() => buildWeekColumns(days), [days]);
  const labels = useMemo(() => monthLabels(weeks), [weeks]);
  const weekDays = ["S", "M", "T", "W", "T", "F", "S"];

  if (days.length === 0) {
    return (
      <p className="text-sm text-slate-400 py-8 text-center">No activity in this period.</p>
    );
  }

  return (
    <div className="space-y-3">
      <div className="overflow-x-auto pb-1">
        <div className="inline-flex min-w-full flex-col gap-1">
          <div className="flex gap-1 pl-7">
            {labels.map((label, index) => (
              <div key={`label-${index}`} className="w-3 text-[10px] font-medium text-slate-400">
                {label}
              </div>
            ))}
          </div>
          <div className="flex gap-2">
            <div className="flex flex-col gap-1 pt-0.5">
              {weekDays.map((day, index) => (
                <div
                  key={day + index}
                  className="flex h-3 w-4 items-center justify-end text-[10px] text-slate-400"
                  aria-hidden={index % 2 === 1}
                >
                  {index % 2 === 0 ? day : ""}
                </div>
              ))}
            </div>
            <div className="flex gap-1">
              {weeks.map((week, weekIndex) => (
                <div key={`week-${weekIndex}`} className="flex flex-col gap-1">
                  {week.map((cell, dayIndex) => {
                    if (!cell) {
                      return <div key={`empty-${weekIndex}-${dayIndex}`} className="h-3 w-3 rounded-sm" />;
                    }
                    const label = new Date(`${cell.date_key}T12:00:00`).toLocaleDateString(undefined, {
                      month: "short",
                      day: "numeric",
                    });
                    return (
                      <button
                        key={cell.date_key}
                        type="button"
                        disabled={cell.total <= 0}
                        onClick={() => cell.total > 0 && onSelectDay?.(cell.date_key)}
                        className={`h-3 w-3 rounded-sm transition-colors ${intensityClass(cell.total, peak)} ${
                          cell.total > 0 ? "cursor-pointer focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-brand-blue" : "cursor-default"
                        }`}
                        aria-label={`${label}: ${cell.total} actions`}
                        title={`${label}: ${cell.total} actions`}
                      />
                    );
                  })}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-3 text-[10px] text-slate-500">
        <span>Less</span>
        <span className="h-3 w-3 rounded-sm bg-slate-100/80" />
        <span className="h-3 w-3 rounded-sm bg-amber-100" />
        <span className="h-3 w-3 rounded-sm bg-amber-200" />
        <span className="h-3 w-3 rounded-sm bg-amber-400" />
        <span className="h-3 w-3 rounded-sm bg-amber-600" />
        <span>More</span>
      </div>
    </div>
  );
}
