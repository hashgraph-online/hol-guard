import { fetchWithGuardAuth } from "../guard-api";
import { isGuardDemoMode } from "../guard-demo";
import { ContextAssistanceApiError } from "./api";

export type FolderPlace = { label: string; path: string; kind?: string };
export type FolderEntry = { name: string; path: string; project: boolean };
export type FolderListing = {
  path: string; name: string; parent: string | null; project: boolean; home: string; separator: string;
  places: FolderPlace[]; roots: FolderPlace[]; entries: FolderEntry[]; truncated: boolean;
};
export type ProjectFileReason = "too_large" | "not_text" | "empty" | null;
export type ProjectFile = { name: string; relative: string; size: number; available: boolean; reason: ProjectFileReason };
export type ProjectFileListing = {
  workspace: string; path: string; entries: { name: string; relative: string }[]; files: ProjectFile[];
  suggested: { relative: string; size: number }[]; maxFileBytes: number; truncated: boolean;
};

const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const text = (value: unknown): value is string => typeof value === "string";
const list = <T,>(value: unknown, max: number, item: (row: unknown) => row is T): T[] => {
  if (!Array.isArray(value) || value.length > max || !value.every(item)) invalid();
  return value as T[];
};
const place = (row: unknown): row is FolderPlace => object(row) && text(row.label) && text(row.path);
const size = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;
function invalid(): never { throw new ContextAssistanceApiError("folder_payload_invalid", "Guard returned an unexpected folder list. Try again."); }

const MESSAGES: Record<string, string> = {
  folder_not_found: "That folder does not exist or was moved.",
  folder_not_absolute: "Type a full path, starting from the top of your drive.",
  folder_not_directory: "That is a file, not a folder.",
  folder_denied: "Your computer does not let Guard open that folder.",
  folder_unreadable: "Guard could not open that folder.",
};

async function browse(input: Record<string, unknown>, signal?: AbortSignal): Promise<Record<string, unknown>> {
  if (isGuardDemoMode()) throw new ContextAssistanceApiError("demo_unavailable", "Browsing folders needs Guard running on this computer.");
  const timeout = AbortSignal.timeout(10_000);
  const response = await fetchWithGuardAuth("/v1/context-assistance/folders", {
    method: "POST", headers: { "Content-Type": "application/json" }, cache: "no-store",
    signal: signal ? AbortSignal.any([signal, timeout]) : timeout, body: JSON.stringify(input),
  });
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const code = object(body) && text(body.code) && /^[a-z0-9_]{1,80}$/.test(body.code) ? body.code : "folder_unavailable";
    throw new ContextAssistanceApiError(code, MESSAGES[code] ?? (response.status === 404
      ? "This Guard version cannot browse folders yet. Update Guard, then try again."
      : "Guard could not open that folder."));
  }
  if (!object(body) || body.schema !== "guard-context-folders.v1") invalid();
  return body;
}

export async function listFolders(path: string | null, hidden: boolean, signal?: AbortSignal): Promise<FolderListing> {
  const body = await browse({ mode: "folders", ...(path ? { path } : {}), hidden }, signal);
  if (!text(body.path) || !text(body.name) || !(body.parent === null || text(body.parent)) || typeof body.project !== "boolean"
      || !text(body.home) || !text(body.separator) || typeof body.truncated !== "boolean") invalid();
  return {
    path: body.path, name: body.name, parent: body.parent, project: body.project, home: body.home, separator: body.separator,
    truncated: body.truncated, places: list(body.places, 32, place), roots: list(body.roots, 26, place),
    entries: list(body.entries, 400, (row): row is FolderEntry => object(row) && text(row.name) && text(row.path) && typeof row.project === "boolean"),
  };
}

export async function listProjectFiles(workspace: string, path: string, signal?: AbortSignal): Promise<ProjectFileListing> {
  const body = await browse({ mode: "files", workspace, path }, signal);
  if (!text(body.workspace) || !text(body.path) || !size(body.max_file_bytes) || typeof body.truncated !== "boolean") invalid();
  return {
    workspace: body.workspace, path: body.path, maxFileBytes: body.max_file_bytes, truncated: body.truncated,
    entries: list(body.entries, 400, (row): row is { name: string; relative: string } => object(row) && text(row.name) && text(row.relative)),
    files: list(body.files, 400, (row): row is ProjectFile => object(row) && text(row.name) && text(row.relative) && size(row.size)
      && typeof row.available === "boolean" && (row.reason === null || ["too_large", "not_text", "empty"].includes(String(row.reason)))),
    suggested: list(body.suggested, 8, (row): row is { relative: string; size: number } => object(row) && text(row.relative) && size(row.size)),
  };
}

/** Segments for a breadcrumb: each one carries the full path to jump back to. */
export function folderCrumbs(path: string, separator: string): { label: string; path: string }[] {
  const windows = separator === "\\";
  const parts = path.split(windows ? /[\\/]/ : "/").filter(Boolean);
  const crumbs: { label: string; path: string }[] = [];
  let current = windows ? "" : "/";
  if (!windows) crumbs.push({ label: "/", path: "/" });
  parts.forEach((part, index) => {
    if (windows && index === 0) current = part + "\\";
    else current = current.endsWith(separator) ? current + part : current + separator + part;
    crumbs.push({ label: part, path: current });
  });
  return crumbs;
}

export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  return `${Math.max(1, Math.round(bytes / 1024))} KB`;
}
