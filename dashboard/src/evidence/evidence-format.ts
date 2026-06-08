export function formatBlockedShare(blocked: number, total: number): string | null {
  if (total <= 0 || blocked <= 0) {
    return null;
  }
  const percent = (blocked / total) * 100;
  if (percent < 1) {
    return "<1% of recorded actions";
  }
  if (percent < 10) {
    return `${percent.toFixed(1).replace(/\.0$/, "")}% of recorded actions`;
  }
  return `${Math.round(percent)}% of recorded actions`;
}

export function formatEvidenceCount(value: number): string {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1).replace(/\.0$/, "")}M`;
  if (value >= 10_000) return `${Math.round(value / 1_000)}K`;
  if (value >= 1_000) return value.toLocaleString();
  return String(value);
}

export function formatDurationSince(iso: string | null): string {
  if (!iso) return "No activity yet";
  const ts = new Date(iso).getTime();
  if (Number.isNaN(ts)) return "Recently";
  const days = Math.max(0, Math.floor((Date.now() - ts) / (24 * 60 * 60 * 1000)));
  if (days === 0) return "Today";
  if (days === 1) return "1 day ago";
  if (days < 30) return `${days} days ago`;
  const months = Math.floor(days / 30);
  return months === 1 ? "1 month ago" : `${months} months ago`;
}

export function formatDayLabel(dateKey: string): string {
  return new Date(`${dateKey}T12:00:00`).toLocaleDateString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}
