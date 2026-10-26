import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { inspectBusinessPolicy, recoverBusinessPolicy } from "./business-policy-recovery-api";
import { BusinessPolicyRecoveryPanel } from "./business-policy-recovery-panel";

const storage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
Object.defineProperty(globalThis, "window", { configurable: true, value: {
  location: { origin: "http://127.0.0.1:4174", pathname: "/", search: "", hash: "" },
  sessionStorage: storage, localStorage: storage,
} });
const markup = renderToStaticMarkup(<BusinessPolicyRecoveryPanel
  recoverPolicy={recoverBusinessPolicy}
  requestId="synthetic-request" candidateDigest="synthetic-digest" approvalGate={null} onRecovered={() => {}} policy={{ spec: { rules: [] } }}
/>);
assert.match(markup, /Checking local approval settings/);
assert.match(markup, /disabled=""/);
assert.match(markup, /does not resume an app task or resolve the original request/);
const unconfiguredMarkup = renderToStaticMarkup(<BusinessPolicyRecoveryPanel
  recoverPolicy={recoverBusinessPolicy}
  requestId="synthetic-request" candidateDigest="synthetic-digest" onRecovered={() => {}} policy={{ spec: { rules: [] } }}
  approvalGate={{ enabled: false, configured: false, cooldown_seconds: 0, cooldown_active: false,
    cooldown_expires_at: null, locked_until: null, fail_closed: true, strict_all_decisions: true }}
/>);
assert.match(unconfiguredMarkup, /Set up approval/);
assert.match(unconfiguredMarkup, /disabled=""/);
const recoveredMarkup = renderToStaticMarkup(<BusinessPolicyRecoveryPanel
  recoverPolicy={recoverBusinessPolicy}
  requestId="synthetic-request" candidateDigest="complete-original-digest" onRecovered={() => {}}
  requestRecovered installed policy={{ spec: { rules: [{ effect: "deny" }] } }}
/>);
assert.match(recoveredMarkup, /complete-original-digest/);
assert.match(recoveredMarkup, /already installed/);
assert.doesNotMatch(recoveredMarkup, /Approve and recover policy/);

const previousFetch = globalThis.fetch;
try {
  let submitted: Record<string, unknown> | null = null;
  globalThis.fetch = async (_url, init) => {
    submitted = JSON.parse(String(init?.body));
    return new Response(JSON.stringify({ installationRecovered: true, sourceDigest: "synthetic-digest" }), { status: 200 });
  };
  await recoverBusinessPolicy({ requestId: "synthetic-request", candidateDigest: "synthetic-digest", approval_password: "synthetic-proof" });
  assert.equal(submitted?.["action"], "recover");
  assert.equal(submitted?.["candidateDigest"], "synthetic-digest");
  for (const payload of [
    { resolved: true, status: "applied" },
    { installationRecovered: true, sourceDigest: "different-digest" },
    { installationRecovered: false, sourceDigest: "synthetic-digest" },
  ]) {
    globalThis.fetch = async () => new Response(JSON.stringify(payload), { status: 200 });
    await assert.rejects(recoverBusinessPolicy({ requestId: "synthetic-request", candidateDigest: "synthetic-digest" }), /not confirmed/);
  }
  globalThis.fetch = async () => new Response(JSON.stringify({ message: "private-server-marker" }), { status: 503 });
  await assert.rejects(recoverBusinessPolicy({ requestId: "synthetic-request", candidateDigest: "synthetic-digest" }),
    (error: Error) => !error.message.includes("private-server-marker"));
  const inspection = { state: "interrupted", candidateDigest: "synthetic-digest", requestRecovered: true,
    policy: { spec: { rules: [{ effect: "deny" }] } }, provenanceRedacted: true };
  globalThis.fetch = async () => new Response(JSON.stringify(inspection), { status: 200 });
  assert.equal((await inspectBusinessPolicy("synthetic-request", "synthetic-digest")).requestRecovered, true);
  globalThis.fetch = async () => new Response(JSON.stringify({ ...inspection, state: ["interrupted"] }), { status: 200 });
  await assert.rejects(inspectBusinessPolicy("synthetic-request", "synthetic-digest"), /not confirmed/);
  for (const policy of [null, [], "unverified policy"]) {
    globalThis.fetch = async () => new Response(JSON.stringify({ ...inspection, policy }), { status: 200 });
    await assert.rejects(inspectBusinessPolicy("synthetic-request", "synthetic-digest"), /not confirmed/);
  }
  globalThis.fetch = async () => new Response(JSON.stringify({ error: "approval_gate_totp_required" }), { status: 403 });
  await assert.rejects(recoverBusinessPolicy({ requestId: "synthetic-request", candidateDigest: "synthetic-digest" }), /fresh authenticator code/);
} finally {
  globalThis.fetch = previousFetch;
}
console.log("business-policy-recovery: missing proof and exact recovery response checks passed");
