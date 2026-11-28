import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ConnectReview } from "./provider-connect-dialog";
import { connectOutcome, getKeyHref, runProviderConnect, sameDisclosure } from "./provider-connect-flow";
import {
  normalizeConnectPreview,
  normalizeProviderDetail,
  ProviderIntegrationApiError,
  type ProviderConnectPreview,
} from "./provider-integrations-api";

const SHIELD = "provider.exampleshield";
const rawPreview = {
  provider_id: SHIELD,
  shares: ["target.origin"],
  opt_in_facts: ["target.path_prefix"],
  hosts: ["api.exampleshield.example"],
  challenge: "fixture-proof-1",
  expires_at_ms: 120_000,
};
const preview: ProviderConnectPreview = normalizeConnectPreview(rawPreview);
const detail = normalizeProviderDetail({
  summary: { id: SHIELD, name: "ExampleShield", summary: "Fixture", verified: false, state: "connected",
    capabilities: ["browser.origin-reputation"] },
  publisher_name: "Example Publisher", publisher_url: null, surfaces: ["browser"],
  hosts: ["api.exampleshield.example"], privacy_url: "https://publisher.example/privacy",
  terms_url: "https://publisher.example/terms", obtain_url: "https://publisher.example/keys",
  auth_kind: "api-key", shares: ["target.origin"], enabled_opt_in_facts: [], settings: [],
  last_verified_at_ms: 1, cache_counts: {},
});

assert.throws(() => normalizeConnectPreview({ ...rawPreview, challenge: "" }));

// Codes map to the five states the PRD allows, plus "start again" for a spent proof.
assert.equal(connectOutcome("provider_key_invalid"), "key_invalid");
assert.equal(connectOutcome("provider_rate_limited"), "rate_limited");
assert.equal(connectOutcome("provider_host_refused"), "unreachable");
assert.equal(connectOutcome("provider_integration_unavailable"), "unreachable");
assert.equal(connectOutcome("provider_capability_unavailable"), "disabled");
assert.equal(connectOutcome("provider_proof_invalid"), "start_again");

// "Get a key" carries one static referral parameter and nothing else; a non-https link is dropped.
assert.equal(getKeyHref("https://publisher.example/keys"), "https://publisher.example/keys?referrer_id=holguard");
assert.equal(getKeyHref("http://publisher.example/keys"), null);
assert.equal(getKeyHref(null), null);

type Call = string;
function steps(calls: Call[], now: number, next: ProviderConnectPreview, connect: () => Promise<typeof detail>) {
  return {
    now: () => now,
    preview: async () => {
      calls.push("preview");
      return next;
    },
    connect: async (proof: string) => {
      calls.push(`connect:${proof}`);
      return connect();
    },
  };
}

// A live proof is spent directly.
let calls: Call[] = [];
let result = await runProviderConnect(preview, steps(calls, 1_000, preview, async () => detail));
assert.deepEqual(calls, ["connect:fixture-proof-1"]);
assert.equal(result.kind === "done" && result.outcome, "connected");

// A proof near expiry is replaced before the key is sent.
const fresh: ProviderConnectPreview = { ...preview, challenge: "fixture-proof-2", expiresAtMs: 999_999 };
calls = [];
result = await runProviderConnect(preview, steps(calls, 115_000, fresh, async () => detail));
assert.deepEqual(calls, ["preview", "connect:fixture-proof-2"]);

// A replacement that would share more is never sent; the person reviews it first.
const wider = { ...fresh, shares: ["target.origin", "action.intent"] };
assert.equal(sameDisclosure(preview, wider), false);
calls = [];
result = await runProviderConnect(preview, steps(calls, 115_000, wider, async () => detail));
assert.deepEqual(calls, ["preview"]);
assert.equal(result.kind, "changed");

// A refused key comes back as a state, never as provider text.
calls = [];
result = await runProviderConnect(preview, steps(calls, 1_000, preview, async () => {
  throw new ProviderIntegrationApiError("provider_key_invalid", 400);
}));
assert.deepEqual(result, { kind: "done", outcome: "key_invalid" });

const review = (keyValue: string, outcome: Parameters<typeof ConnectReview>[0]["outcome"]) =>
  renderToStaticMarkup(createElement(ConnectReview, {
    name: "ExampleShield", preview, obtainUrl: detail.obtainUrl, optIn: [], onOptInChange: () => undefined,
    keyValue, onKeyChange: () => undefined, outcome, changed: false, pending: false, onSubmit: () => undefined,
  }));
const page = review("", null);
assert.match(page, /What leaves this device/);
assert.match(page, /The website&#x27;s address without a path/);
assert.match(page, /api\.exampleshield\.example/);
assert.match(page, /type="checkbox"/);
assert.doesNotMatch(page, /checked=""/, "optional facts start off");
assert.match(page, /type="password"[^>]*autoComplete="off"|autoComplete="off"[^>]*type="password"/i);
assert.match(page, /href="https:\/\/publisher\.example\/keys\?referrer_id=holguard"/);
assert.match(page, /<button[^>]*disabled=""[^>]*>Connect and verify<\/button>/);
assert.match(review("fixture", "key_invalid"), /The provider rejected this key/);

console.log("provider connect tests passed");
