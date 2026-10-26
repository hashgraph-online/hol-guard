import assert from "node:assert/strict";

import {
  CODEX_HOST_FALLBACK,
  CONFIGURED_CONNECTIONS_FALLBACK,
  DiscoveryFailure,
  discoveryFailureMessage,
} from "./discovery-failure";
import { LocalCliApiError } from "./local-cli-api";
import { waitForDiscoveryJob } from "./discovery-job-wait";

// Every authored message names something the reader can do next, not just
// what went wrong; a banner that only restates the failure leaves them stuck.
const ACTION = /Check for connectors again|Reload this page|Restart Guard|Reopen Guard|host app|restart Guard|try again|Try again/;

{
  // A failed stage reaches the banner with its own guidance, not one sentence
  // that fits every failure. This is the regression the Extensions page hit.
  const failure = new DiscoveryFailure(
    "configured_host_scan_failed",
    "Guard could not read this device's configured connections. Check that your agent apps' MCP settings are valid, then choose Check for connectors again. Known connections were kept.",
  );
  const message = discoveryFailureMessage(failure, CONFIGURED_CONNECTIONS_FALLBACK);
  assert.equal(message, failure.message);
  assert.notEqual(message, CONFIGURED_CONNECTIONS_FALLBACK);
  assert.match(message, ACTION);
}

// Codes the daemon answers before a job exists each get their own guidance.
for (const [code, guidance] of [
  ["discovery_busy", "already refreshing other connections"],
  ["discovery_retry_backoff", "Wait ten seconds"],
  ["discovery_unavailable", "Reopen Guard"],
  ["discovery_job_unavailable", "expired"],
  ["local_cli_unavailable", "Restart Guard"],
  ["local_cli_request_failed", "Reload this page"],
] as const) {
  // The daemon's own fallback wording names the wrong surface for a host scan.
  const error = new LocalCliApiError(code, "Guard could not update this custom extension.");
  const message = discoveryFailureMessage(error, CONFIGURED_CONNECTIONS_FALLBACK);
  assert.ok(message.includes(guidance), `${code} must explain itself: ${message}`);
  assert.match(message, ACTION);
}

{
  // A reply Guard authored for an unlisted code is kept; its generic fallback
  // for custom extensions is not, because this surface is host discovery.
  const authored = new LocalCliApiError("session_expired", "Guard could not confirm this dashboard session. Reload this page, then try again.");
  assert.equal(discoveryFailureMessage(authored, CONFIGURED_CONNECTIONS_FALLBACK), authored.message);
  const generic = new LocalCliApiError("session_expired", "Guard could not load custom extensions.");
  assert.equal(discoveryFailureMessage(generic, CONFIGURED_CONNECTIONS_FALLBACK), CONFIGURED_CONNECTIONS_FALLBACK);
}

{
  // Foreign errors never render as guidance: a dropped connection carries no
  // code, so the banner falls back instead of showing transport text.
  assert.equal(discoveryFailureMessage(new TypeError("Failed to fetch"), CONFIGURED_CONNECTIONS_FALLBACK), CONFIGURED_CONNECTIONS_FALLBACK);
  assert.equal(discoveryFailureMessage(null, CONFIGURED_CONNECTIONS_FALLBACK), CONFIGURED_CONNECTIONS_FALLBACK);
  assert.equal(discoveryFailureMessage(undefined, CODEX_HOST_FALLBACK), CODEX_HOST_FALLBACK);
  assert.equal(discoveryFailureMessage("boom", CONFIGURED_CONNECTIONS_FALLBACK), CONFIGURED_CONNECTIONS_FALLBACK);
}

// Both fallbacks still name a next action, so even an unknown failure moves.
for (const fallback of [CONFIGURED_CONNECTIONS_FALLBACK, CODEX_HOST_FALLBACK]) assert.match(fallback, ACTION);

// Each configured-connections stage code carries its own code to the caller.
for (const [error, code, guidance] of [
  ["configured_host_scan_failed", "configured_host_scan_failed", "MCP settings are valid"],
  ["observed_provider_scan_failed", "observed_provider_scan_failed", "Check for connectors again"],
  ["catalog_limit_reached", "catalog_limit_reached", "remove tools you do not use"],
  ["discovery_failed", "discovery_failed", "Check for connectors again"],
  ["configured_host_persist_failed", "configured_host_persist_failed", "could not save them"],
  ["codex_host_changed", "codex_host_changed", "restarted while Guard was reading it"],
  ["codex_host_untrusted", "codex_host_untrusted", "control socket"],
  ["codex_host_invalid", "codex_host_invalid", "Update or reopen the Codex app"],
  ["codex_host_limit", "codex_host_limit", "Remove connections you do not use"],
  ["codex_host_timeout", "codex_host_timeout", "did not answer in time"],
  ["codex_host_unavailable", "codex_host_unavailable", "could not reach the Codex app"],
] as const) {
  await assert.rejects(
    waitForDiscoveryJob(
      "inventory:configured",
      { job_id: "a".repeat(32), cli_id: "inventory:configured", state: "failed", error },
      new AbortController().signal,
      async () => ({}),
    ),
    (caught: unknown) => caught instanceof DiscoveryFailure
      && caught.code === code
      && caught.message.includes(guidance),
  );
}

{
  // A code is attacker-shaped input: it arrives in a daemon reply and is used
  // as a lookup key. An inherited key such as `__proto__` names no message
  // Guard wrote, so the banner must fall back rather than render a function.
  for (const code of ["__proto__", "constructor", "toString", "hasOwnProperty"]) {
    const message = discoveryFailureMessage(new LocalCliApiError(code, "Guard could not update this custom extension."), CONFIGURED_CONNECTIONS_FALLBACK);
    assert.equal(message, CONFIGURED_CONNECTIONS_FALLBACK, `${code} must not reach the banner`);
  }
  // Only codes Guard authors a reply for may pass the daemon's text through;
  // an unknown code carrying arbitrary text falls back instead.
  const unknown = new LocalCliApiError("surprise_code", "Raw daemon text that names no next step.");
  assert.equal(discoveryFailureMessage(unknown, CONFIGURED_CONNECTIONS_FALLBACK), CONFIGURED_CONNECTIONS_FALLBACK);
}

console.log("discovery-failure ok");
