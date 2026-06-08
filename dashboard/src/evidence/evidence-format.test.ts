import assert from "node:assert/strict";
import { formatBlockedShare } from "./evidence-format";

assert.equal(formatBlockedShare(0, 100), null);
assert.equal(formatBlockedShare(10, 0), null);
assert.equal(formatBlockedShare(2020, 746_300), "<1% of recorded actions");
assert.equal(formatBlockedShare(50_000, 746_300), "6.7% of recorded actions");
assert.equal(formatBlockedShare(5_000, 100_000), "5% of recorded actions");
assert.equal(formatBlockedShare(8_500, 100_000), "8.5% of recorded actions");

console.log("evidence-format.test.ts: all tests passed");
