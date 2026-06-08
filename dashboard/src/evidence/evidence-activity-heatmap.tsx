import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { createPortal } from "react-dom";
import type { GuardReceiptDailyActivity } from "../guard-types";
import { formatDayLabel, formatEvidenceCount } from "./evidence-format";

type HeatmapCell = {
  date_key: string;
  total: number;
  flatIndex: number;
};

function intensityClass(total: number, peak: number): string {
  if (total <= 0) return "evidence-heatmap-0";
  const ratio = peak > 0 ? total / peak : 0;
  if (ratio >= 0.75) return "evidence-heatmap-4";
  if (ratio >= 0.4) return "evidence-heatmap-3";
  if (ratio >= 0.15) return "evidence-heatmap-2";
  return "evidence-heatmap-1";
}

function buildWeekColumns(days: GuardReceiptDailyActivity[]): Array<Array<HeatmapCell | null>> {
  if (days.length === 0) return [];

  const flatCells: HeatmapCell[] = days.map((day, index) => ({
    date_key: day.date_key,
    total: day.total,
    flatIndex: index,
  }));

  const first = new Date(`${days[0].date_key}T12:00:00`);
  const startPad = first.getDay();
  const cells: Array<HeatmapCell | null> = [
    ...Array.from({ length: startPad }, () => null),
    ...flatCells,
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

function isGuardModalOpen(): boolean {
  return typeof document !== "undefined" && document.documentElement.dataset.guardModalOpen === "true";
}

function flatCellsFromWeeks(weeks: Array<Array<HeatmapCell | null>>): HeatmapCell[] {
  const result: HeatmapCell[] = [];
  for (const week of weeks) {
    for (const cell of week) {
      if (cell) result.push(cell);
    }
  }
  return result;
}

interface TooltipState {
  dateKey: string;
  total: number;
  top: number;
  left: number;
  placement: "above" | "below";
}

export function EvidenceActivityHeatmap({
  days,
  onSelectDay,
}: {
  days: GuardReceiptDailyActivity[];
  onSelectDay?: (dateKey: string) => void;
}) {
  const gridRef = useRef<HTMLDivElement>(null);
  const cellRefs = useRef<Map<string, HTMLButtonElement>>(new Map());
  const [activeIndex, setActiveIndex] = useState(0);
  const [hoveredKey, setHoveredKey] = useState<string | null>(null);
  const [tooltip, setTooltip] = useState<TooltipState | null>(null);
  const [reduceMotion, setReduceMotion] = useState(false);

  const peak = useMemo(() => Math.max(...days.map((day) => day.total), 0), [days]);
  const weeks = useMemo(() => buildWeekColumns(days), [days]);
  const labels = useMemo(() => monthLabels(weeks), [weeks]);
  const flatCells = useMemo(() => flatCellsFromWeeks(weeks), [weeks]);
  const weekDays = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

  const activeCell = flatCells[activeIndex] ?? null;
  const displayKey = hoveredKey ?? activeCell?.date_key ?? null;
  const displayCell = displayKey ? flatCells.find((c) => c.date_key === displayKey) ?? null : null;

  useEffect(() => {
    setReduceMotion(window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  }, []);

  const updateTooltipForKey = useCallback((dateKey: string | null) => {
    if (!dateKey || isGuardModalOpen()) {
      setTooltip(null);
      return;
    }
    const cell = flatCells.find((entry) => entry.date_key === dateKey);
    const element = cellRefs.current.get(dateKey);
    if (!cell || !element) {
      setTooltip(null);
      return;
    }
    const rect = element.getBoundingClientRect();
    const aboveTop = rect.top - 8;
    const belowTop = rect.bottom + 8;
    const placement = aboveTop > 72 ? "above" : "below";
    setTooltip({
      dateKey: cell.date_key,
      total: cell.total,
      left: rect.left + rect.width / 2,
      top: placement === "above" ? aboveTop : belowTop,
      placement,
    });
  }, [flatCells]);

  useLayoutEffect(() => {
    updateTooltipForKey(displayKey);
  }, [displayKey, updateTooltipForKey, weeks]);

  useEffect(() => {
    const onScrollOrResize = () => updateTooltipForKey(displayKey);
    window.addEventListener("scroll", onScrollOrResize, true);
    window.addEventListener("resize", onScrollOrResize);
    return () => {
      window.removeEventListener("scroll", onScrollOrResize, true);
      window.removeEventListener("resize", onScrollOrResize);
    };
  }, [displayKey, updateTooltipForKey]);

  useEffect(() => {
    if (!tooltip) return;
    const dismissWhenModalOpens = () => {
      if (isGuardModalOpen()) {
        setTooltip(null);
        setHoveredKey(null);
      }
    };
    dismissWhenModalOpens();
    const observer = new MutationObserver(dismissWhenModalOpens);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-guard-modal-open"] });
    return () => observer.disconnect();
  }, [tooltip]);

  const moveActive = useCallback(
    (delta: number) => {
      if (flatCells.length === 0) return;
      setActiveIndex((prev) => Math.max(0, Math.min(flatCells.length - 1, prev + delta)));
    },
    [flatCells],
  );

  const handleGridKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (flatCells.length === 0) return;
    if (event.key === "ArrowRight") {
      event.preventDefault();
      moveActive(7);
    } else if (event.key === "ArrowLeft") {
      event.preventDefault();
      moveActive(-7);
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      moveActive(1);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      moveActive(-1);
    } else if (event.key === "Enter" || event.key === " ") {
      const cell = flatCells[activeIndex];
      if (cell && cell.total > 0 && onSelectDay) {
        event.preventDefault();
        onSelectDay(cell.date_key);
      }
    }
  };

  const handleCellActivate = (dateKey: string, total: number) => {
    if (total > 0 && onSelectDay) {
      onSelectDay(dateKey);
    }
  };

  if (days.length === 0) {
    return <p className="py-8 text-center text-sm text-slate-400">No activity in this period.</p>;
  }

  const tooltipNode =
    tooltip && !isGuardModalOpen() && typeof document !== "undefined"
      ? createPortal(
          <div
            className="pointer-events-none fixed z-40 -translate-x-1/2 rounded-lg bg-brand-dark px-3 py-2 text-xs text-white shadow-lg"
            style={{
              left: tooltip.left,
              top: tooltip.top,
              transform: `translate(-50%, ${tooltip.placement === "above" ? "-100%" : "0"})`,
            }}
            role="tooltip"
            id="evidence-heatmap-tooltip"
          >
            <div className="font-semibold">{formatDayLabel(tooltip.dateKey)}</div>
            <div className="mt-0.5 text-slate-200">
              {tooltip.total > 0
                ? `${formatEvidenceCount(tooltip.total)} action${tooltip.total === 1 ? "" : "s"}`
                : "No activity"}
            </div>
            {tooltip.total > 0 && onSelectDay && (
              <div className="mt-1 text-[10px] text-slate-300">Enter to view actions</div>
            )}
          </div>,
          document.body,
        )
      : null;

  return (
    <div className="space-y-3">
      {tooltipNode}
      <div
        ref={gridRef}
        className="flex w-full min-w-0 gap-2 outline-none"
        role="grid"
        aria-label="90 day activity heatmap"
        aria-describedby={displayCell ? "evidence-heatmap-tooltip" : undefined}
        aria-activedescendant={activeCell ? `heatmap-cell-${activeCell.date_key}` : undefined}
        tabIndex={0}
        onKeyDown={handleGridKeyDown}
        onFocus={() => {
          if (!displayKey && flatCells[0]) {
            setActiveIndex(0);
          }
        }}
        onBlur={() => {
          setHoveredKey(null);
        }}
      >
        <div className="flex w-8 shrink-0 flex-col justify-between py-[1.125rem] text-[10px] font-medium text-slate-400">
          {weekDays.map((day, index) => (
            <span key={day} className="leading-none" aria-hidden={index % 2 === 1}>
              {index % 2 === 0 ? day.slice(0, 3) : ""}
            </span>
          ))}
        </div>

        <div className="min-w-0 flex-1">
          <div
            className="mb-1 grid gap-1"
            style={{ gridTemplateColumns: `repeat(${weeks.length}, minmax(0, 1fr))` }}
            role="presentation"
          >
            {labels.map((label, index) => (
              <div key={`label-${index}`} className="truncate text-[10px] font-medium text-slate-400">
                {label}
              </div>
            ))}
          </div>

          <div
            className="grid gap-1"
            style={{ gridTemplateColumns: `repeat(${weeks.length}, minmax(0, 1fr))` }}
          >
            {weeks.map((week, weekIndex) => (
              <div key={`week-${weekIndex}`} className="grid grid-rows-7 gap-1" role="row">
                {week.map((cell, dayIndex) => {
                  if (!cell) {
                    return (
                      <div
                        key={`empty-${weekIndex}-${dayIndex}`}
                        className="flex min-h-11 items-center justify-center"
                        role="gridcell"
                        aria-hidden="true"
                      />
                    );
                  }
                  const isActive = activeCell?.date_key === cell.date_key;
                  const isHovered = hoveredKey === cell.date_key;
                  return (
                    <div
                      key={cell.date_key}
                      className="flex min-h-11 min-w-0 items-center justify-center"
                      role="gridcell"
                    >
                      <button
                        type="button"
                        ref={(node) => {
                          if (node) cellRefs.current.set(cell.date_key, node);
                          else cellRefs.current.delete(cell.date_key);
                        }}
                        id={`heatmap-cell-${cell.date_key}`}
                        tabIndex={-1}
                        aria-label={`${formatDayLabel(cell.date_key)}: ${cell.total} actions`}
                        className={`aspect-square w-full max-h-4 max-w-4 rounded-[3px] transition-[transform,opacity] duration-150 ${intensityClass(cell.total, peak)} ${
                          cell.total > 0 ? "cursor-pointer hover:opacity-90" : "cursor-default opacity-80"
                        } ${isActive || isHovered ? "evidence-heatmap-active" : ""} ${reduceMotion ? "" : "evidence-heatmap-motion"}`}
                        onMouseEnter={() => {
                          setHoveredKey(cell.date_key);
                          setActiveIndex(cell.flatIndex);
                        }}
                        onMouseLeave={() => setHoveredKey(null)}
                        onFocus={() => {
                          setActiveIndex(cell.flatIndex);
                          setHoveredKey(cell.date_key);
                        }}
                        onBlur={() => setHoveredKey(null)}
                        onClick={() => handleCellActivate(cell.date_key, cell.total)}
                      />
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2 text-[10px] text-slate-500">
        <span>Less</span>
        <span className="h-3 w-3 rounded-[2px] evidence-heatmap-0" />
        <span className="h-3 w-3 rounded-[2px] evidence-heatmap-1" />
        <span className="h-3 w-3 rounded-[2px] evidence-heatmap-2" />
        <span className="h-3 w-3 rounded-[2px] evidence-heatmap-3" />
        <span className="h-3 w-3 rounded-[2px] evidence-heatmap-4" />
        <span>More</span>
      </div>
    </div>
  );
}
