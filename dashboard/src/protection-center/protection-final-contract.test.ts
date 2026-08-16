import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const telemetry = readFileSync(new URL("./protection-telemetry.ts", import.meta.url), "utf8");
const lab = readFileSync(new URL("./protection-test-lab.tsx", import.meta.url), "utf8");
const guardApi = readFileSync(new URL("../guard-api.ts", import.meta.url), "utf8");
const docs = readFileSync(new URL("../../../docs/guard/protection-center.md", import.meta.url), "utf8");

assert.match(telemetry, /ALLOWED_FIELDS/);
const allowedFields = telemetry.match(/const ALLOWED_FIELDS = new Set\(\[([\s\S]*?)\]\);/)?.[1] ?? "";
for (const forbidden of ["command", "path", "proof_id", "rule_id", "extension_id", "token"]) {
  assert.equal(allowedFields.includes(`"${forbidden}"`), false);
}
assert.match(lab, /Nothing is executed/);
assert.match(lab, /not saved/);
assert.doesNotMatch(lab, /4\.99|15\.00|1073741824|30-day|deviceLimit/);
assert.match(guardApi, /catalog\|effective\|history\|preview\|test\|apply\|refresh\|recover-authority\|acknowledge-degraded/);
assert.match(docs, /must never disable or hide local protection controls/);
assert.match(docs, /client must not invent device, retention, or storage quotas/);

console.log("protection-final-contract.test.ts: all assertions passed");
