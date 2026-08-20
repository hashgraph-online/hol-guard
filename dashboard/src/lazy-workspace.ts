import { lazy, type ComponentType, type LazyExoticComponent } from "react";

export const CHUNK_RELOAD_STORAGE_KEY = "hol-guard-dashboard-chunk-reload";
export const CHUNK_RELOAD_DELAY_MS = 400;

export type WorkspaceModuleLoader<T> = () => Promise<T>;

export type LoadWorkspaceModuleOptions = {
  delayMs?: number;
  reload?: () => void;
  storage?: Pick<Storage, "getItem" | "setItem" | "removeItem">;
  wait?: (ms: number) => Promise<void>;
};

export function isChunkLoadError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  const normalized = message.toLowerCase();
  return (
    normalized.includes("failed to fetch dynamically imported module") ||
    normalized.includes("error loading dynamically imported module") ||
    normalized.includes("importing a module script failed") ||
    normalized.includes("loading chunk")
  );
}

function defaultWait(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function reloadDocument(reload: (() => void) | undefined): boolean {
  if (reload) {
    reload();
    return true;
  }
  if (typeof window !== "undefined") {
    window.location.reload();
    return true;
  }
  return false;
}

export async function loadWorkspaceModule<T>(
  loader: WorkspaceModuleLoader<T>,
  options: LoadWorkspaceModuleOptions = {},
): Promise<T> {
  try {
    return await loader();
  } catch (error) {
    if (!isChunkLoadError(error)) {
      throw error;
    }
    const storage = options.storage;
    if (!storage || storage.getItem(CHUNK_RELOAD_STORAGE_KEY) === "1") {
      throw error;
    }
    // Keep this flag for the tab so a nested child chunk cannot reload forever after a parent load succeeds.
    storage.setItem(CHUNK_RELOAD_STORAGE_KEY, "1");
    const wait = options.wait ?? defaultWait;
    await wait(options.delayMs ?? CHUNK_RELOAD_DELAY_MS);
    if (!reloadDocument(options.reload)) {
      throw error;
    }
    return new Promise<T>(() => {
      // The document unloads on reload; keep React.lazy pending until then.
    });
  }
}

export function lazyWorkspace<T extends ComponentType<unknown>>(
  loader: WorkspaceModuleLoader<{ default: T }>,
): LazyExoticComponent<T> {
  return lazy(() =>
    loadWorkspaceModule(loader, {
      storage: typeof sessionStorage === "undefined" ? undefined : sessionStorage,
    }),
  );
}
