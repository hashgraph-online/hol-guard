import {
  CHUNK_RELOAD_DELAY_MS,
  CHUNK_RELOAD_STORAGE_KEY,
  isChunkLoadError,
  loadWorkspaceModule,
} from "./lazy-workspace";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

assert(
  isChunkLoadError(
    new TypeError(
      "Failed to fetch dynamically imported module: http://127.0.0.1:5474/assets/chunks/extensions-workspace.js",
    ),
  ),
  "Chrome chunk fetch failures are chunk-load errors",
);
assert(
  isChunkLoadError(new TypeError("error loading dynamically imported module")),
  "Firefox module load failures are chunk-load errors",
);
assert(
  isChunkLoadError(new Error("Importing a module script failed.")),
  "Safari module script failures are chunk-load errors",
);
assert(!isChunkLoadError(new Error("policy save failed")), "unrelated errors are not chunk-load errors");

const memoryStorage = (): Pick<Storage, "getItem" | "setItem" | "removeItem"> => {
  const values = new Map<string, string>();
  return {
    getItem(key) {
      return values.get(key) ?? null;
    },
    setItem(key, value) {
      values.set(key, value);
    },
    removeItem(key) {
      values.delete(key);
    },
  };
};

const ok = { default: "workspace" };

{
  const storage = memoryStorage();
  storage.setItem(CHUNK_RELOAD_STORAGE_KEY, "1");
  const loaded = await loadWorkspaceModule(async () => ok, { storage });
  assert(loaded === ok, "successful loads return the module");
  assert(
    storage.getItem(CHUNK_RELOAD_STORAGE_KEY) === "1",
    "successful parent loads keep the one-shot flag so a nested child failure cannot reload forever",
  );
}

{
  const storage = memoryStorage();
  let reloads = 0;
  let waited = 0;
  try {
    await loadWorkspaceModule(
      async () => {
        throw new TypeError(
          "Failed to fetch dynamically imported module: http://127.0.0.1:5474/assets/chunks/extensions-workspace.js",
        );
      },
      {
        storage,
        delayMs: CHUNK_RELOAD_DELAY_MS,
        wait: async (ms) => {
          waited = ms;
        },
        reload: () => {
          reloads += 1;
          throw new Error("dashboard-reload");
        },
      },
    );
    throw new Error("chunk recovery must not resolve a module while reloading");
  } catch (error) {
    assert(
      error instanceof Error && error.message === "dashboard-reload",
      "chunk recovery reloads instead of returning a cached failed module",
    );
  }
  assert(waited === CHUNK_RELOAD_DELAY_MS, "chunk recovery waits before reload so the daemon can return");
  assert(reloads === 1, "first chunk failure reloads the dashboard once");
  assert(storage.getItem(CHUNK_RELOAD_STORAGE_KEY) === "1", "first chunk failure records the reload flag");
}

{
  const storage = memoryStorage();
  storage.setItem(CHUNK_RELOAD_STORAGE_KEY, "1");
  let reloads = 0;
  try {
    await loadWorkspaceModule(
      async () => {
        throw new TypeError(
          "Failed to fetch dynamically imported module: http://127.0.0.1:5474/assets/chunks/extensions-workspace.js",
        );
      },
      {
        storage,
        reload: () => {
          reloads += 1;
        },
      },
    );
    throw new Error("second chunk failure must surface to the error boundary");
  } catch (error) {
    assert(isChunkLoadError(error), "second chunk failure rethrows the module load error");
  }
  assert(reloads === 0, "a second chunk failure does not loop reloads");
}

{
  let reloads = 0;
  try {
    await loadWorkspaceModule(
      async () => {
        throw new TypeError(
          "Failed to fetch dynamically imported module: http://127.0.0.1:5474/assets/chunks/extensions-workspace.js",
        );
      },
      {
        reload: () => {
          reloads += 1;
        },
      },
    );
    throw new Error("missing storage must not auto-reload");
  } catch (error) {
    assert(isChunkLoadError(error), "missing storage surfaces the module load error");
  }
  assert(reloads === 0, "privacy-mode sessions do not auto-reload without a one-shot flag");
}

{
  try {
    await loadWorkspaceModule(async () => {
      throw new Error("policy save failed");
    });
    throw new Error("non-chunk errors must propagate");
  } catch (error) {
    assert(error instanceof Error && error.message === "policy save failed", "non-chunk errors stay unchanged");
  }
}

{
  let reloads = 0;
  const blockedStorage: Pick<Storage, "getItem" | "setItem" | "removeItem"> = {
    getItem() {
      throw new Error("blocked");
    },
    setItem() {
      throw new Error("blocked");
    },
    removeItem() {
      throw new Error("blocked");
    },
  };
  try {
    await loadWorkspaceModule(
      async () => {
        throw new TypeError(
          "Failed to fetch dynamically imported module: http://127.0.0.1:5474/assets/chunks/extensions-workspace.js",
        );
      },
      {
        storage: blockedStorage,
        reload: () => {
          reloads += 1;
        },
      },
    );
    throw new Error("blocked storage must not swallow the chunk-load error");
  } catch (error) {
    assert(isChunkLoadError(error), "blocked storage keeps the original chunk-load error");
  }
  assert(reloads === 0, "blocked storage disables automatic reload");
}

{
  const storage = memoryStorage();
  let reloads = 0;
  const failingChild = async () => {
    throw new TypeError(
      "Failed to fetch dynamically imported module: http://127.0.0.1:5474/assets/chunks/audit-workspace.js",
    );
  };
  await loadWorkspaceModule(async () => ok, { storage });
  try {
    await loadWorkspaceModule(failingChild, {
      storage,
      wait: async () => undefined,
      reload: () => {
        reloads += 1;
        throw new Error("dashboard-reload");
      },
    });
  } catch (error) {
    assert(error instanceof Error && error.message === "dashboard-reload", "nested child failure still reloads once");
  }
  await loadWorkspaceModule(async () => ok, { storage });
  try {
    await loadWorkspaceModule(failingChild, {
      storage,
      reload: () => {
        reloads += 1;
      },
    });
    throw new Error("nested child failure must stop after the one-shot reload");
  } catch (error) {
    assert(isChunkLoadError(error), "nested child failure surfaces after the one-shot reload");
  }
  assert(reloads === 1, "parent success must not reset the nested child reload budget");
}

console.log("lazy-workspace.test.ts: all assertions passed");
