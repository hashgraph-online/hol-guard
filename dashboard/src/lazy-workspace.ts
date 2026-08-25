import { lazy, type FunctionComponent, type LazyExoticComponent } from "react";

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

function storageGet(storage: Pick<Storage, "getItem">, key: string): string | null {
  try {
    return storage.getItem(key);
  } catch {
    return null;
  }
}

function storageSet(storage: Pick<Storage, "setItem">, key: string, value: string): boolean {
  try {
    storage.setItem(key, value);
    return true;
  } catch {
    return false;
  }
}

export function browserSessionStorage(): Pick<Storage, "getItem" | "setItem" | "removeItem"> | undefined {
  try {
    if (typeof sessionStorage === "undefined") {
      return undefined;
    }
    return sessionStorage;
  } catch {
    return undefined;
  }
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
    if (!storage || storageGet(storage, CHUNK_RELOAD_STORAGE_KEY) === "1") {
      throw error;
    }
    // Keep this flag for the tab so a nested child chunk cannot reload forever after a parent load succeeds.
    if (!storageSet(storage, CHUNK_RELOAD_STORAGE_KEY, "1")) {
      throw error;
    }
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

export function lazyWorkspace<T extends FunctionComponent<never>>(
  loader: WorkspaceModuleLoader<{ default: T }>,
): LazyExoticComponent<FunctionComponent<Parameters<T>[0]>> {
  const load = async (): Promise<{ default: FunctionComponent<Parameters<T>[0]> }> => {
    const module = await loadWorkspaceModule(loader, { storage: browserSessionStorage() });
    return { default: module.default };
  };
  return lazy(load);
}
