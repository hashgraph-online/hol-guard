import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { fetchProviderIntegrationApi } from "../guard-api";
import { followExtensionsLink, parseIntegrationsRoute } from "./integrations-route";
import { ProviderDetailView, ProviderListView } from "./integrations-workspace";
import { normalizeProviderDetail, normalizeProviderList, safeHttpsUrl } from "./provider-integrations-api";

const SHIELD = "provider.exampleshield";
const summary = {
  id: SHIELD,
  name: "ExampleShield",
  summary: "Fixture origin reputation",
  verified: false,
  state: "not_connected",
  capabilities: ["browser.origin-reputation"],
};
const rawDetail = {
  summary,
  publisher_name: "Example Publisher",
  publisher_url: "https://publisher.example",
  surfaces: ["browser"],
  hosts: ["api.exampleshield.example"],
  privacy_url: "https://publisher.example/privacy",
  terms_url: "javascript:alert(1)",
  obtain_url: null,
  auth_kind: "api-key",
  shares: ["target.origin", "target.path_prefix"],
  enabled_opt_in_facts: ["target.path_prefix"],
  settings: [
    { capability: "browser.origin-reputation", effect: "tighten", require_fresh_check: false, quieted_reason_codes: [] },
  ],
  last_verified_at_ms: null,
  cache_counts: {},
};

// Routes: only the two Integrations shapes are claimed; every other Extensions path is left alone.
assert.deepEqual(parseIntegrationsRoute("/extensions/integrations"), { kind: "integrations" });
assert.deepEqual(parseIntegrationsRoute("/extensions/integrations/"), { kind: "integrations" });
assert.deepEqual(parseIntegrationsRoute(`/extensions/${SHIELD}`), { kind: "provider", providerId: SHIELD });
for (const other of ["/extensions", "/extensions/command.git", "/extensions/provider.", "/extensions/provider.-x",
  "/extensions/provider.a/b", "/extensions/provider.%E0%A4%A", "/extensions/add"]) {
  assert.equal(parseIntegrationsRoute(other), null, other);
}

// A modified or non-primary click keeps the browser's default (new tab, new window).
for (const modifier of [{ metaKey: true }, { ctrlKey: true }, { shiftKey: true }, { altKey: true }, { button: 1 }]) {
  let prevented = false;
  followExtensionsLink(
    { button: 0, metaKey: false, ctrlKey: false, shiftKey: false, altKey: false, ...modifier, preventDefault: () => { prevented = true; } },
    "/extensions/integrations",
  );
  assert.equal(prevented, false, JSON.stringify(modifier));
}

// The fetch allowlist refuses any path outside the provider routes before a request is made.
for (const path of ["/v1/integrations/providers/../settings", "/v1/integrations/providers/provider.x/other",
  "/v1/integrations/providers/command.git", "/v1/integrations/providers?x=1"]) {
  await assert.rejects(fetchProviderIntegrationApi(path), /Invalid provider integration API path/, path);
}

// Normalizers refuse a malformed answer instead of rendering it.
assert.equal(normalizeProviderList({ providers: [summary] })[0].name, "ExampleShield");
assert.throws(() => normalizeProviderList({ providers: [{ ...summary, state: "online" }] }));
assert.throws(() => normalizeProviderList({ providers: [{ ...summary, id: "command.git" }] }));
const detail = normalizeProviderDetail(rawDetail);
assert.equal(detail.publisherUrl, "https://publisher.example/");
assert.equal(safeHttpsUrl("http://publisher.example"), null);
assert.equal(safeHttpsUrl("https://user:pw@publisher.example"), null);

const list = renderToStaticMarkup(createElement(ProviderListView, { providers: normalizeProviderList({ providers: [summary] }) }));
assert.match(list, /<h1[^>]*>Integrations<\/h1>/);
assert.match(list, /href="\/extensions\/provider\.exampleshield"/);
assert.match(list, /Site reputation/);
assert.match(list, /Not connected/);
assert.match(renderToStaticMarkup(createElement(ProviderListView, { providers: [] })), /No provider integrations ship/);

const page = renderToStaticMarkup(createElement(ProviderDetailView, { detail }));
assert.match(page, /What it checks/);
assert.match(page, /known for phishing, malware or scams/);
assert.match(page, /What leaves this device/);
assert.match(page, /The website&#x27;s address without a path/);
assert.match(page, /The first part of the page path \(you turned this on\)/);
assert.equal(page.match(/The first part of the page path/g)?.length, 1, "a declared opt-in fact is listed once");
assert.doesNotMatch(page, /keys stay here/, "the key goes to the provider, so the page never says it stays");
const notEnabled = renderToStaticMarkup(createElement(ProviderDetailView, {
  detail: normalizeProviderDetail({ ...rawDetail, enabled_opt_in_facts: [] }),
}));
assert.match(notEnabled, /The first part of the page path \(only if you turn it on\)/);
assert.match(page, /api\.exampleshield\.example/);
assert.match(page, /HOL has not verified this publisher/);
assert.match(page, /href="https:\/\/publisher\.example\/privacy"[^>]*rel="noopener noreferrer"/);
assert.doesNotMatch(page, /javascript:/, "a non-https terms link is never rendered");
assert.match(page, />Connect</);

const connected = normalizeProviderDetail({ ...rawDetail, summary: { ...summary, state: "connected", verified: true } });
const connectedPage = renderToStaticMarkup(createElement(ProviderDetailView, { detail: connected }));
assert.match(connectedPage, /Verified publisher: Example Publisher/);
assert.match(connectedPage, /Ask before risky actions/);
assert.match(connectedPage, />Replace key</);

console.log("integrations tests passed");
