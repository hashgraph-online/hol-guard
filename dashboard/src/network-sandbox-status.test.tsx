import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import {
  INITIAL_NETWORK_SANDBOX_STATUS,
  beginNetworkSandboxRefresh,
  containmentPresentationState,
  loadNetworkSandboxStatus,
  networkPresentationState,
  normalizeGuardContainmentHealth,
  normalizeGuardNetworkStatus,
  settleNetworkSandboxStatus,
  type GuardContainmentHealth,
  type GuardNetworkStatus,
  type GuardStatusResource,
} from "./network-sandbox-status";
import {
  containmentStatusCopy,
  NetworkSandboxStatusPanel,
  NetworkSandboxStatusPanelView,
  networkStatusCopy,
  qualifyLastKnownUnsupported,
} from "./network-sandbox-status-panel";

const now = Date.parse("2026-08-30T16:00:00Z");
const networkPayload = {
  schema: "guard.network-status.v1",
  host_platform: "linux",
  effective_grade: "destination-enforced",
  independently_observed_grade: "destination-enforced",
  protection_active: true,
  independently_observed: true,
  reason_code: "verified-active",
  supervisor: {
    phase: "healthy",
    effective_grade: "destination-enforced",
    healthy_until_epoch_ms: now + 60_000,
    permits_enforcement: true,
    independently_observed: true,
    backend_id: "private-value-is-discarded",
    backend_digest: "c".repeat(64),
    retry_attempt: 0,
    next_retry_seconds: 0,
  },
  backends: [
    {
      backend_id: "private-value-is-discarded",
      platform: "linux",
      supported: true,
      installed: true,
      verified: true,
      active: true,
      observed: true,
      advertised_maximum_grade: "destination-enforced",
      effective_grade: "destination-enforced",
      production_ready: true,
      requires_privilege: true,
      reason_code: "verified-active",
      reference_reason_code: "provider-verified",
    },
  ],
};
const containmentPayload = {
  containment_health: {
    schema_version: "guard.containment-health.v1",
    containment_schema_version: "guard.containment.v1",
    policy_version: "guard.containment-policy.v1",
    effect_contract_schema_version: "1.0.0",
    effect_decision_schema_version: "1.1.0",
    backend: "linux-bwrap",
    probe_at: "2026-08-30T15:59:00Z",
    probe_enforced: true,
    backend_digest: "a".repeat(64),
    policy_contract_digest: "8861db0285235c9f06ca2c8443b0899928890cd63ba5d0f9873c9514e4614ee4",
    daemon_fingerprint: "b".repeat(64),
    runtime_fingerprint: "b".repeat(64),
    ignored_private_value: "private-value-is-discarded",
  },
};

const network = normalizeGuardNetworkStatus(networkPayload);
assert(network !== null);
assert.equal(JSON.stringify(network).includes("private-value"), false, "network normalizer drops provider identity and digests");
assert.equal(normalizeGuardNetworkStatus({ ...networkPayload, protection_active: 1 }), null);
assert.equal(normalizeGuardNetworkStatus({ ...networkPayload, schema: "guard.network-status.v2" }), null);
assert.equal(
  normalizeGuardNetworkStatus({
    ...networkPayload,
    supervisor: { ...networkPayload.supervisor, healthy_until_epoch_ms: null },
  }),
  null,
  "active network protection requires an expiry-bound proof",
);
assert.equal(normalizeGuardNetworkStatus({ ...networkPayload, independently_observed_grade: undefined }), null);
assert.equal(normalizeGuardNetworkStatus({ ...networkPayload, backends: [] }), null);
assert.equal(
  normalizeGuardNetworkStatus({
    ...networkPayload,
    backends: [{ ...networkPayload.backends[0], observed: false }],
  }),
  null,
);
assert.equal(
  normalizeGuardNetworkStatus({
    ...networkPayload,
    supervisor: { ...networkPayload.supervisor, backend_id: "different-backend" },
  }),
  null,
);
assert.equal(
  normalizeGuardNetworkStatus({
    ...networkPayload,
    supervisor: { ...networkPayload.supervisor, backend_digest: "not-a-digest" },
  }),
  null,
);
assert.equal(
  normalizeGuardNetworkStatus({
    ...networkPayload,
    backends: [{ ...networkPayload.backends[0], effective_grade: "deny-all" }],
  }),
  null,
);
assert.equal(
  normalizeGuardNetworkStatus({
    ...networkPayload,
    backends: [{ ...networkPayload.backends[0], production_ready: false }],
  }),
  null,
);
assert.equal(
  normalizeGuardNetworkStatus({
    ...networkPayload,
    backends: [networkPayload.backends[0], { ...networkPayload.backends[0], backend_id: "second-backend" }],
  }),
  null,
);

const containment = normalizeGuardContainmentHealth(containmentPayload);
assert(containment !== null);
assert.equal(JSON.stringify(containment).includes("private-value"), false, "containment normalizer drops fingerprints and digests");
assert.equal(
  normalizeGuardContainmentHealth({
    containment_health: { ...containmentPayload.containment_health, effect_decision_schema_version: "2.0.0" },
  }),
  null,
);
assert.equal(
  normalizeGuardContainmentHealth({
    containment_health: { ...containmentPayload.containment_health, policy_contract_digest: "c".repeat(64) },
  }),
  null,
  "containment proof binds to the current policy contract",
);

const networkResource: GuardStatusResource<GuardNetworkStatus> = {
  value: network,
  loadState: "ready",
  refreshing: false,
};
const containmentResource: GuardStatusResource<GuardContainmentHealth> = {
  value: containment,
  loadState: "ready",
  refreshing: false,
};
assert.equal(networkPresentationState(networkResource, now), "ready");
assert.equal(containmentPresentationState(containmentResource, now), "ready");
assert.equal(
  networkPresentationState({ ...networkResource, value: { ...network, independentlyObserved: false } }, now),
  "unavailable",
  "network protection needs independent observation",
);
assert.equal(
  containmentPresentationState({ ...containmentResource, value: { ...containment, probeAtEpochMs: now - 300_001 } }, now),
  "stale",
);

const unsupportedNetwork = normalizeGuardNetworkStatus({
  ...networkPayload,
  host_platform: "unsupported",
  effective_grade: "unavailable",
  independently_observed_grade: "unavailable",
  protection_active: false,
  independently_observed: false,
  backends: [
    {
      ...networkPayload.backends[0],
      active: false,
      observed: false,
      effective_grade: "unavailable",
    },
  ],
  supervisor: {
    ...networkPayload.supervisor,
    phase: "unavailable",
    effective_grade: "unavailable",
    healthy_until_epoch_ms: null,
    permits_enforcement: false,
    independently_observed: false,
    backend_id: null,
    backend_digest: null,
  },
});
assert(unsupportedNetwork !== null);
assert(
  normalizeGuardNetworkStatus({
    ...networkPayload,
    effective_grade: "unavailable",
    independently_observed_grade: "unavailable",
    protection_active: false,
    independently_observed: false,
    supervisor: undefined,
    backends: [
      {
        ...networkPayload.backends[0],
        active: false,
        observed: false,
        effective_grade: "unavailable",
      },
    ],
  }) !== null,
  "inactive status does not require supervisor proof",
);
assert.equal(
  networkPresentationState({ value: unsupportedNetwork, loadState: "stale", refreshing: false }, now),
  "unsupported",
  "a failed refresh does not replace a known unsupported platform with a generic stale state",
);
const unsupportedContainment = normalizeGuardContainmentHealth({
  containment_health: {
    ...containmentPayload.containment_health,
    backend: "unsupported",
    probe_enforced: false,
  },
});
assert(unsupportedContainment !== null);
assert.equal(
  containmentPresentationState({ value: unsupportedContainment, loadState: "stale", refreshing: false }, now),
  "unsupported",
  "a failed refresh preserves known unsupported containment",
);
assert.match(
  qualifyLastKnownUnsupported(networkStatusCopy("unsupported"), "stale").label,
  /last checked/,
  "known unsupported state discloses that the newest check failed",
);

const refreshing = beginNetworkSandboxRefresh({ network: networkResource, containment: containmentResource });
assert.equal(refreshing.network.value, network, "refresh retains prior network proof");
assert.equal(refreshing.containment.value, containment, "refresh retains prior containment proof");
const partlyFailed = settleNetworkSandboxStatus(
  refreshing,
  { status: "rejected", reason: new Error("offline") },
  { status: "fulfilled", value: containmentPayload },
);
assert.equal(partlyFailed.network.loadState, "stale", "failed network refresh retains stale proof independently");
assert.equal(partlyFailed.containment.loadState, "ready", "containment can refresh when network fails");
assert.equal(settleNetworkSandboxStatus(
  INITIAL_NETWORK_SANDBOX_STATUS,
  { status: "rejected", reason: new Error("offline") },
  { status: "rejected", reason: new Error("offline") },
).network.loadState, "error");

let timedOutSignal: AbortSignal | null = null;
const [timedOutNetwork, completedContainment] = await loadNetworkSandboxStatus(
  new AbortController().signal,
  5,
  {
    network: (signal) => {
      timedOutSignal = signal;
      return new Promise<unknown>(() => undefined);
    },
    containment: async () => containmentPayload,
  },
);
assert.equal(timedOutNetwork.status, "rejected", "a never-resolving endpoint settles at the hook timeout boundary");
assert.equal(completedContainment.status, "fulfilled", "the other endpoint settles independently");
assert.equal(timedOutSignal?.aborted, true, "the timed-out request receives an abort signal");
const recoveredAfterTimeout = settleNetworkSandboxStatus(
  beginNetworkSandboxRefresh(INITIAL_NETWORK_SANDBOX_STATUS),
  timedOutNetwork,
  completedContainment,
);
assert.equal(recoveredAfterTimeout.network.refreshing, false);
assert.equal(recoveredAfterTimeout.containment.refreshing, false);
const noOpRefresh = () => undefined;
const recoveredMarkup = renderToStaticMarkup(
  <NetworkSandboxStatusPanelView
    state={recoveredAfterTimeout}
    onRefresh={noOpRefresh}
    nowEpochMs={now}
  />,
);
assert.match(recoveredMarkup, /Refresh status/);
assert.equal(recoveredMarkup.includes(' disabled=""'), false, "timeout recovery re-enables Refresh");

assert.match(networkStatusCopy("unavailable").detail, /not active|No independently verified/i);
assert.match(networkStatusCopy("stale").detail, /not treating selective network isolation as active/i);
assert.match(containmentStatusCopy("ready").detail, /supported actions/i);
assert.doesNotMatch(containmentStatusCopy("ready").detail, /all actions/i);

const panelMarkup = renderToStaticMarkup(<NetworkSandboxStatusPanel />);
assert.match(panelMarkup, /Network &amp; sandboxing/);
assert.match(panelMarkup, /Selective network isolation/);
assert.match(panelMarkup, /Contained-action sandboxing/);
assert.match(panelMarkup, /Refresh status/);
assert.equal((panelMarkup.match(/Refresh status/g) ?? []).length, 1, "panel exposes one read-only refresh action");

const apiSource = readFileSync(new URL("./network-sandbox-api.ts", import.meta.url), "utf8");
assert.match(apiSource, /readJson<unknown>\(path, \{ cache: "no-store", method: "GET", signal \}\)/);
assert.match(apiSource, /fetchProof\("\/v1\/network\/status", signal\)/);
assert.match(apiSource, /fetchProof\("\/v1\/runtime\/containment-health", signal\)/);

console.log("network-sandbox-status.test.tsx: all tests passed");
