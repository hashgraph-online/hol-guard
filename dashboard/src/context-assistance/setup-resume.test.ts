import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import type { CigarSetupRun } from "./one-click";
import { forgetTurnOn, forgetTurnOnClick, rememberTurnOn, rememberTurnOnJob, shouldResumeTurnOn, turnOnJob, turnOnRequestedAt } from "./setup-resume";
import { parseContextAssistanceStatus } from "./status";
import type { ContextAssistanceStatus } from "./types";

const fixture = JSON.parse(readFileSync(new URL("./fixtures/intent-state.json", import.meta.url), "utf8"));
const ready = parseContextAssistanceStatus(fixture.native_test.ready_observation);
const off: ContextAssistanceStatus = { ...ready, effective_enabled: false, requested_enabled: false };
const run = (approval: boolean): CigarSetupRun => ({ kind: "run", stages: ["start"], approval } as CigarSetupRun);

const memory = new Map<string, string>();
const storage = {
  getItem: (key: string) => memory.get(key) ?? null,
  setItem: (key: string, value: string) => void memory.set(key, value),
  removeItem: (key: string) => void memory.delete(key),
};

// A click is remembered for this tab and forgotten once setup ends.
assert.equal(turnOnRequestedAt(storage), null);
rememberTurnOn(1_000, storage);
assert.equal(turnOnRequestedAt(storage), 1_000);
forgetTurnOn(storage);
assert.equal(turnOnRequestedAt(storage), null);

// The prepared safety check outlives an approval prompt but not a finished or cancelled setup.
rememberTurnOn(2_000, storage);
rememberTurnOnJob("dashboard:mine", storage);
forgetTurnOnClick(storage);
assert.deepEqual([turnOnRequestedAt(storage), turnOnJob(storage)], [null, "dashboard:mine"]);
forgetTurnOn(storage);
assert.equal(turnOnJob(storage), null);

// Storage that throws (private windows, blocked site data) never breaks setup.
const broken = { getItem: () => { throw new Error("blocked"); }, setItem: () => { throw new Error("blocked"); }, removeItem: () => { throw new Error("blocked"); } };
rememberTurnOn(1_000, broken);
forgetTurnOn(broken);
assert.equal(turnOnRequestedAt(broken), null);

// Coming back to the page finishes a recent, unfinished click.
assert.equal(shouldResumeTurnOn(1_000, 61_000, off, run(false), false), true);
// Approval-gated steps resume only when the gate is off; otherwise the user starts again.
assert.equal(shouldResumeTurnOn(1_000, 61_000, off, run(true), true), false);
assert.equal(shouldResumeTurnOn(1_000, 61_000, off, run(true), false), true);
// Nothing to resume: no click, an old click, CIGAR already on, or nothing left to run.
assert.equal(shouldResumeTurnOn(null, 61_000, off, run(false), false), false);
assert.equal(shouldResumeTurnOn(1_000, 1_000 + 31 * 60_000, off, run(false), false), false);
assert.equal(shouldResumeTurnOn(61_000, 1_000, off, run(false), false), false);
assert.equal(shouldResumeTurnOn(1_000, 61_000, ready, run(false), false), false);
assert.equal(shouldResumeTurnOn(1_000, 61_000, null, run(false), false), false);
assert.equal(shouldResumeTurnOn(1_000, 61_000, off, { kind: "ready" }, false), false);
assert.equal(shouldResumeTurnOn(1_000, 61_000, off, null, false), false);

console.log("setup-resume tests passed");
