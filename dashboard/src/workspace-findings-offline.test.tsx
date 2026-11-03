import assert from "node:assert/strict";
import { fetchWorkspaceFindings, workspaceErrorMessage } from "./workspace-findings-api";

async function checkUnreachableDaemon() {
  const realFetch = globalThis.fetch;
  const realWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const storage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      location: { origin: "http://127.0.0.1:4174", pathname: "/", search: "", hash: "" },
      sessionStorage: storage,
      localStorage: storage,
    },
  });
  let attempts = 0;
  globalThis.fetch = (async () => {
    attempts += 1;
    throw new TypeError("Failed to fetch");
  }) as typeof fetch;
  try {
    await assert.rejects(fetchWorkspaceFindings(), (error: Error) => {
      assert.equal(error.message, workspaceErrorMessage(null), "a daemon that cannot be reached shows Guard's own advice");
      return true;
    });
    assert.ok(attempts > 0, "the request reached fetch");

    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      fetchWorkspaceFindings({ signal: controller.signal }),
      (error: Error) => error.message === "Failed to fetch",
      "a cancelled load keeps its own error so callers can ignore it",
    );
  } finally {
    globalThis.fetch = realFetch;
    if (realWindow) Object.defineProperty(globalThis, "window", realWindow);
    else Reflect.deleteProperty(globalThis, "window");
  }
}

await checkUnreachableDaemon();

console.log("workspace findings offline tests passed");
