export function formatCloudBundleHashDisplay(hash: string | null | undefined): string {
  if (!hash?.trim()) {
    return "Unavailable";
  }
  const value = hash.trim();
  const isSha256 = value.toLowerCase().startsWith("sha256:");
  const normalized = isSha256 ? value.slice(7) : value;

  if (isSha256) {
    return normalized.length <= 4 ? value : `sha256:${normalized.slice(0, 4)}…`;
  }
  return normalized.length <= 8 ? normalized : `${normalized.slice(0, 8)}…`;
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
    return "Latest sync needs attention";
  }
  return copy.label;
}
