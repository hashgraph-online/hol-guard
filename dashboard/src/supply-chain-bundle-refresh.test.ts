import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import type { SupplyChainBundle } from "./guard-types";
import {
  BUNDLE_REREAD_INTERVAL_MS,
  createBundleRefreshBus,
  createSharedBundleReader,
  readBundleLoad,
} from "./supply-chain-bundle-refresh";

const bundle = {
  bundleVersion: "2026.10.1",
  generatedAt: "2026-10-01T00:00:00Z",
  expiresAt: "2026-11-01T00:00:00Z",
  advisories: [],
} as unknown as SupplyChainBundle;

// Overlapping reads share one request; a read after it settles starts a new one.
{
  let calls = 0;
  let release: (value: SupplyChainBundle | null) => void = () => undefined;
  const read = createSharedBundleReader(() => {
    calls += 1;
    return new Promise<SupplyChainBundle | null>((resolve) => {
      release = resolve;
    });
  });
  const first = read();
  const second = read();
  assert.equal(calls, 1, "two panels reading at once make one request");
  assert.equal(first, second, "both readers get the same promise");
  release(bundle);
  assert.equal(await first, bundle);
  await Promise.resolve();
  const third = read();
  assert.equal(calls, 2, "a read after the first settled makes a new request");
  release(null);
  assert.equal(await third, null);
}

// A failed shared read does not stick: the next read tries again.
{
  let calls = 0;
  const read = createSharedBundleReader(async () => {
    calls += 1;
    if (calls === 1) throw new Error("daemon unreachable");
    return bundle;
  });
  await assert.rejects(read(), /daemon unreachable/);
  await Promise.resolve();
  assert.equal(await read(), bundle, "the read after a failure goes through");
  assert.equal(calls, 2);
}

// A failed read becomes an error state instead of keeping old intel.
{
  const failed = await readBundleLoad(async () => {
    throw new Error("daemon unreachable");
  });
  assert.deepEqual(failed, { phase: "error", message: "daemon unreachable" });
  const unnamed = await readBundleLoad(async () => {
    throw "nope";
  });
  assert.deepEqual(unnamed, { phase: "error", message: "Failed to load" });
  assert.deepEqual(await readBundleLoad(async () => bundle), { phase: "ready", bundle });
  assert.deepEqual(await readBundleLoad(async () => null), { phase: "ready", bundle: null });
}

// The bus: refresh notifies every subscriber; one timer runs while anyone listens.
{
  const started: Array<{ tick: () => void; intervalMs: number }> = [];
  const stopped: unknown[] = [];
  let visible = true;
  const bus = createBundleRefreshBus(
    {
      start: (tick, intervalMs) => {
        started.push({ tick, intervalMs });
        return started.length;
      },
      stop: (handle) => stopped.push(handle),
    },
    () => visible,
  );
  let a = 0;
  let b = 0;
  const offA = bus.subscribe(() => {
    a += 1;
  });
  const offB = bus.subscribe(() => {
    b += 1;
  });
  assert.equal(started.length, 1, "two subscribers share one timer");
  assert.equal(started[0]?.intervalMs, BUNDLE_REREAD_INTERVAL_MS);

  bus.refresh();
  assert.deepEqual([a, b], [1, 1], "refresh reaches every subscriber");

  started[0]?.tick();
  assert.deepEqual([a, b], [2, 2], "the interval tick refreshes when the page is visible");
  visible = false;
  started[0]?.tick();
  assert.deepEqual([a, b], [2, 2], "a hidden page skips the tick");
  visible = true;

  offA();
  bus.refresh();
  assert.deepEqual([a, b], [2, 3], "an unsubscribed listener is not notified");
  assert.equal(stopped.length, 0, "the timer keeps running while a subscriber remains");
  offB();
  assert.deepEqual(stopped, [1], "the timer stops with the last subscriber");
  const offC = bus.subscribe(() => undefined);
  assert.equal(started.length, 2, "a later subscriber starts a fresh timer");
  offC();
}

// Wiring: a finished Sync refreshes the readers, and the hook goes through the shared reader.
const here = fileURLToPath(new URL(".", import.meta.url));
const panelSource = readFileSync(`${here}supply-chain-firewall-panel.tsx`, "utf8");
const syncCalls = panelSource.match(/await runPackageSync\([^)]*\);\s*refreshSupplyChainBundle\(\);/g) ?? [];
assert.equal(syncCalls.length, 2, "both Sync call sites refresh the bundle readers after the request");
const hookSource = readFileSync(`${here}use-supply-chain-bundle.ts`, "utf8");
assert.ok(hookSource.includes("createSharedBundleReader(fetchSupplyChainBundle)"), "the hook shares one request");
assert.ok(hookSource.includes("readBundleLoad(readBundle)"), "a failed read is recorded as an error");

console.log("supply-chain-bundle-refresh tests passed");
