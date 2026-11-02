import type { ProjectFileListing } from "./folders-api";

/**
 * Project access lives only in the running Guard, so a restart clears it on
 * purpose. This browser remembers the last few choices so adding one back is a
 * single click; access is still confirmed again every time.
 */
export type RecentProject = { workspace: string; files: string[]; app: string };
type Store = Pick<Storage, "getItem" | "setItem">;

export const RECENT_PROJECTS_KEY = "guard.cigar.recent-projects.v1";
export const MAX_RECENT_PROJECTS = 4;
const MAX_FILES = 32;

function browserStore(): Store | null {
  try {
    return typeof window === "undefined" ? null : window.localStorage;
  } catch {
    return null;
  }
}

function valid(value: unknown): value is RecentProject {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const row = value as Record<string, unknown>;
  return typeof row.workspace === "string" && row.workspace.length > 0 && typeof row.app === "string" && row.app.length > 0
    && Array.isArray(row.files) && row.files.length <= MAX_FILES && row.files.every((file) => typeof file === "string" && file.length > 0);
}

export function readRecentProjects(store: Store | null = browserStore()): RecentProject[] {
  try {
    const parsed: unknown = JSON.parse(store?.getItem(RECENT_PROJECTS_KEY) ?? "[]");
    if (!Array.isArray(parsed)) return [];
    const seen = new Set<string>();
    return parsed.filter(valid).filter((row) => !seen.has(row.workspace) && Boolean(seen.add(row.workspace)))
      .slice(0, MAX_RECENT_PROJECTS).map((row) => ({ workspace: row.workspace, files: [...row.files], app: row.app }));
  } catch {
    return [];
  }
}

function write(rows: RecentProject[], store: Store | null): RecentProject[] {
  try {
    store?.setItem(RECENT_PROJECTS_KEY, JSON.stringify(rows));
  } catch {
    // Remembering is a convenience; a blocked store just means no shortcut.
  }
  return rows;
}

export function rememberProject(project: RecentProject, store: Store | null = browserStore()): RecentProject[] {
  const row = { workspace: project.workspace, files: project.files.slice(0, MAX_FILES), app: project.app };
  return write([row, ...readRecentProjects(store).filter((item) => item.workspace !== row.workspace)].slice(0, MAX_RECENT_PROJECTS), store);
}

/** Forgets every remembered project, as part of deleting what CIGAR knows. */
export function clearRecentProjects(store: Store | null = browserStore()): RecentProject[] {
  return write([], store);
}

export function forgetProject(workspace: string, store: Store | null = browserStore()): RecentProject[] {
  return write(readRecentProjects(store).filter((item) => item.workspace !== workspace), store);
}

/** Folders holding remembered files below the top folder, to check they are still there. */
export function presetFolders(preset: string[]): string[] {
  const folders = preset.filter((relative) => relative.includes("/")).map((relative) => relative.slice(0, relative.lastIndexOf("/")));
  return [...new Set(folders)].slice(0, MAX_FILES);
}

/**
 * Keeps the remembered files that are still there and readable, so one that
 * was deleted never makes the whole grant fail.
 */
export function keptFiles(preset: string[], listing: Pick<ProjectFileListing, "files" | "suggested">): string[] {
  const present = new Set([
    ...listing.files.filter((file) => file.available).map((file) => file.relative),
    ...listing.suggested.map((item) => item.relative),
  ]);
  return preset.filter((relative) => present.has(relative)).slice(0, MAX_FILES);
}
