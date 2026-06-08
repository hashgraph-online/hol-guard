import type { GuardInsightsShareHeatmapCell } from "../guard-types";

export function getHeatmapLevel(total: number, peak: number): 0 | 1 | 2 | 3 | 4 {
  if (total <= 0 || peak <= 0) return 0;
  const ratio = total / peak;
  if (ratio >= 0.85) return 4;
  if (ratio >= 0.6) return 3;
  if (ratio >= 0.35) return 2;
  return 1;
}

interface EvidenceActivityHeatmapMiniProps {
  cells: GuardInsightsShareHeatmapCell[];
}

export function EvidenceActivityHeatmapMini({ cells }: EvidenceActivityHeatmapMiniProps) {
  const filled = cells.length < 5
    ? [
        ...Array.from({ length: 5 - cells.length }, () => null as GuardInsightsShareHeatmapCell | null),
        ...cells,
      ]
    : cells.slice(-5);

  return (
    <div className="flex items-center gap-1.5">
      {filled.map((cell, index) => {
        if (!cell) {
          return (
            <div
              key={`empty-${index}`}
              className="h-4 w-4 rounded-[3px] evidence-heatmap-0"
              aria-hidden="true"
            />
          );
        }
        return (
          <div
            key={cell.date}
            className={`h-4 w-4 rounded-[3px] evidence-heatmap-${cell.level}`}
            aria-label={`${cell.date}: level ${cell.level}`}
            title={`${cell.date}: level ${cell.level}`}
          />
        );
      })}
    </div>
  );
}
