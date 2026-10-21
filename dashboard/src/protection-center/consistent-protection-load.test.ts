import assert from "node:assert/strict";
import {
  CONSISTENT_LOAD_RETRY_DELAYS_MS,
  loadConsistentProtectionData,
  PROTECTION_DATA_CHANGED_MESSAGE,
} from "./consistent-protection-load";

const sequence = (...digests: string[]) => {
  let index = 0;
  return async () => ({ catalog_digest: digests[Math.min(index++, digests.length - 1)] as string });
};

// Matching digests load on the first attempt without waiting.
{
  const waits: number[] = [];
  const result = await loadConsistentProtectionData(sequence("a"), sequence("a"), {
    sleep: async (ms) => { waits.push(ms); },
  });
  assert.equal(result.catalog.catalog_digest, "a");
  assert.deepEqual(waits, []);
}

// A daemon still settling a new catalog converges after a retry instead of
// failing the page (the 3.50.0 -> 3.51.0 upgrade left them split until restart).
{
  const waits: number[] = [];
  const result = await loadConsistentProtectionData(sequence("old", "old", "new"), sequence("new"), {
    sleep: async (ms) => { waits.push(ms); },
  });
  assert.equal(result.catalog.catalog_digest, "new");
  assert.equal(result.effective.catalog_digest, "new");
  assert.deepEqual(waits, CONSISTENT_LOAD_RETRY_DELAYS_MS.slice(0, 2));
}

// A pair that never agrees is still refused after the retry window.
{
  const waits: number[] = [];
  await assert.rejects(
    loadConsistentProtectionData(sequence("a"), sequence("b"), { sleep: async (ms) => { waits.push(ms); } }),
    { message: PROTECTION_DATA_CHANGED_MESSAGE },
  );
  assert.deepEqual(waits, [...CONSISTENT_LOAD_RETRY_DELAYS_MS]);
}

// The retry window spans at least one daemon control refresh (5 s).
assert.ok(CONSISTENT_LOAD_RETRY_DELAYS_MS.reduce((total, ms) => total + ms, 0) >= 5000);
