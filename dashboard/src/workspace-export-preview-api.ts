import { fetchGuardApi } from "./guard-api";
import type { WorktreeKeys } from "./workspace-findings-api";

const EXPORT_PREVIEW_PATH = "/v1/supply-chain/workspace-export-preview";
export const MAX_EXPORT_PREVIEW_PATHS = 200;
// The daemon refuses a path longer than this, so the browser says why first.
export const MAX_EXPORT_PREVIEW_PATH_LENGTH = 4096;

/**
 * `blocked` means a secret survived its redaction in at least one file, so no
 * export of this selection may leave the machine.
 */
export type ExportPreviewStatus = "ready" | "empty" | "blocked";

export type ExportPreviewFile = {
  path: string;
  /** Size on disk before redaction. */
  bytes: number;
  /** Size of the redacted text an export would carry. */
  exportBytes: number;
  redactions: number;
};

export type ExportPreviewExclusion = { path: string; reason: string };

/** What exporting the chosen files would carry. Never file content or matched text. */
export type ExportPreview = {
  status: ExportPreviewStatus;
  files: ExportPreviewFile[];
  excluded: ExportPreviewExclusion[];
  exportBytes: number;
  redactions: number;
  bundleDigest: string;
  maxFileBytes: number | null;
  maxTotalBytes: number | null;
};

export class ExportPreviewError extends Error {
  readonly code: string;

  constructor(code: string) {
    super(exportPreviewErrorMessage(code));
    this.name = "ExportPreviewError";
    this.code = code;
  }
}

const STATUSES = new Set<string>(["ready", "empty", "blocked"]);

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function count(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function normalizeFile(value: unknown): ExportPreviewFile | null {
  const item = record(value);
  const path = text(item.path);
  const bytes = count(item.bytes);
  const exportBytes = count(item.export_bytes);
  const redactions = count(item.redactions);
  return path && bytes !== null && exportBytes !== null && redactions !== null ? { path, bytes, exportBytes, redactions } : null;
}

export function normalizeExportPreview(value: unknown): ExportPreview | null {
  const item = record(value);
  const status = text(item.status);
  const bundleDigest = text(item.bundle_digest);
  if (!status || !STATUSES.has(status) || !bundleDigest || !Array.isArray(item.files) || !Array.isArray(item.excluded)) {
    return null;
  }
  const files = item.files.map(normalizeFile).filter((entry): entry is ExportPreviewFile => entry !== null);
  const excluded = item.excluded.flatMap((entry) => {
    const exclusion = record(entry);
    const path = typeof exclusion.path === "string" ? exclusion.path : null;
    const reason = text(exclusion.reason);
    return path !== null && reason ? [{ path, reason }] : [];
  });
  const limits = record(item.limits);
  return {
    status: status as ExportPreviewStatus,
    files,
    excluded,
    // Totals come from the files kept here, so a dropped malformed entry can
    // never leave the summary larger than the list it sits above.
    exportBytes: files.reduce((total, file) => total + file.exportBytes, 0),
    redactions: files.reduce((total, file) => total + file.redactions, 0),
    bundleDigest,
    maxFileBytes: count(limits.max_file_bytes),
    maxTotalBytes: count(limits.max_total_bytes),
  };
}

/** Root-relative, `/`-separated paths, one per line; blanks and repeats dropped. */
export function parseExportPaths(input: string): string[] {
  const seen = new Set<string>();
  for (const line of input.split(/\r?\n/)) {
    const path = line.trim();
    if (path) seen.add(path);
  }
  return [...seen];
}

export async function previewWorkspaceExport(worktree: WorktreeKeys, paths: string[]): Promise<ExportPreview> {
  if (paths.length === 0) throw new ExportPreviewError("no_paths");
  if (paths.length > MAX_EXPORT_PREVIEW_PATHS) throw new ExportPreviewError("invalid_paths");
  if (paths.some((path) => path.length > MAX_EXPORT_PREVIEW_PATH_LENGTH)) throw new ExportPreviewError("path_too_long");
  const response = await fetchGuardApi(EXPORT_PREVIEW_PATH, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ codebase_key: worktree.codebaseKey, worktree_key: worktree.worktreeKey, paths }),
  });
  const body = (await response.json().catch(() => null)) as unknown;
  if (!response.ok) throw new ExportPreviewError(text(record(body).error) ?? "workspace_export_preview_failed");
  const preview = normalizeExportPreview(body);
  if (preview === null) throw new ExportPreviewError("workspace_export_preview_failed");
  return preview;
}

const EXCLUSION_REASONS: Record<string, string> = {
  invalid_path: "Not a path inside this workspace.",
  sensitive: "Credential or key file. Guard never exports these.",
  policy_directory: "Inside a folder Guard never exports, such as .git or node_modules.",
  oversize: "Larger than one file may be.",
  byte_budget: "Past the total size Guard reads for one preview. List fewer files.",
  not_text: "Not a text file.",
  not_found: "No file at this path.",
  not_a_file: "A folder or other entry, not a file.",
  symlink: "Reached through a symbolic link, which Guard does not follow.",
  special: "A device, pipe or socket, not a file.",
  unreadable: "Could not be read.",
  unstable: "Changed while Guard was reading it.",
  redaction_failed: "Guard could not confirm this file is free of secrets after redaction, so it blocks the export.",
};

export function exclusionMessage(reason: string): string {
  return EXCLUSION_REASONS[reason] ?? "Left out of the export.";
}

const ERROR_MESSAGES: Record<string, string> = {
  no_paths: "Add at least one file path, one per line.",
  invalid_paths: `List up to ${MAX_EXPORT_PREVIEW_PATHS} file paths, one per line.`,
  path_too_long: `Each file path must be at most ${MAX_EXPORT_PREVIEW_PATH_LENGTH} characters.`,
  worktree_not_found: "This workspace is no longer tracked. Refresh the list.",
  worktree_moved: "This folder now belongs to a different workspace. Refresh the list, then preview again.",
  workspace_export_preview_root_missing: "Guard cannot find this workspace folder. Check that it still exists.",
  workspace_export_preview_root_unreadable: "Guard cannot read this workspace folder.",
  workspace_export_preview_too_many_paths: `List up to ${MAX_EXPORT_PREVIEW_PATHS} file paths, one per line.`,
  workspace_export_preview_native_unavailable:
    "The Guard runtime needed to read files is unavailable. Repair Guard, then try again.",
};

export function exportPreviewErrorMessage(code: string): string {
  return ERROR_MESSAGES[code] ?? "Guard could not build the preview. Check that Guard is running, then retry.";
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
