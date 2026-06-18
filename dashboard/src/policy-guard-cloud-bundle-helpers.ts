export function formatCloudBundleHashDisplay(hash: string | null | undefined): string {
  if (!hash?.trim()) {
    return "Unavailable";
  }
  const value = hash.trim();
  const isSha256 = value.toLowerCase().startsWith("sha256:");
  const normalized = isSha256 ? value.slice(7) : value;

  if (isSha256) {
    if (normalized.length <= 12) {
      return value;
    }
    return `sha256:${normalized.slice(0, 6)}…${normalized.slice(-4)}`;
  }
  if (normalized.length <= 16) {
    return normalized;
  }
  return `${normalized.slice(0, 8)}…${normalized.slice(-4)}`;
}

export function resolveCloudBundleStatusSubtitle(copy: {
  label: string;
  detail: string;
  tone: "green" | "attention" | "slate";
}): string {
  if (copy.tone === "green") {
    return "All policies up to date";
  }
  if (copy.tone === "attention") {
    return "Sync needs attention";
  }
  return copy.label;
}
