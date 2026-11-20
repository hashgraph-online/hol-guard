import assert from "node:assert/strict";

import { createListingSequence } from "./listing-sequence";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

const settledYet = async (promise: Promise<unknown>) => {
  let settled = false;
  void promise.then(() => { settled = true; });
  await new Promise((done) => setTimeout(done, 0));
  return settled;
};

// A load a newer one replaced waits for that one and reports its outcome.
{
  const sequence = createListingSequence();
  const first = deferred<boolean>();
  const second = deferred<boolean>();
  const older = sequence.start(async (isCurrent) => (await first.promise) && isCurrent(), (applied) => applied);
  const newer = sequence.start(async (isCurrent) => (await second.promise) && isCurrent(), (applied) => applied);
  first.resolve(true);
  assert.equal(await settledYet(older.listed), false, "the older load must not report success while the newer one is pending");
  second.resolve(false);
  assert.equal(await older.listed, false, "the newer load failed, so the older one's change is not on screen");
  assert.equal(await newer.listed, false);
}

{
  const sequence = createListingSequence();
  const first = deferred<boolean>();
  const older = sequence.start(() => first.promise, (applied) => applied);
  const newer = sequence.start(async () => true, (applied) => applied);
  assert.equal(await newer.listed, true);
  first.resolve(false);
  assert.equal(await older.listed, true, "a newer listing that applied counts for the older load");
  assert.equal(older.isCurrent(), false);
}

// A load nothing replaced reports its own outcome, and its raw result stays available.
{
  const sequence = createListingSequence();
  const only = sequence.start(async () => ({ outcome: "partial", applied: false }), ({ applied }) => applied);
  assert.equal(await only.listed, false);
  assert.deepEqual(await only.result, { outcome: "partial", applied: false });
  assert.equal(only.isCurrent(), true);
}
