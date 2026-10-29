import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { isCigarCoreLabel, isCigarProducerVersion, isCigarReleaseBinding } from "./release-version";
import { parseContextHistoryEntry } from "./history-api";
import { parseContextAssistanceStatus } from "./status";

const history = JSON.parse(readFileSync(new URL("../../../docs/guard/cigar-integration/evidence/history-development-verification.json", import.meta.url), "utf8")).native_test.observation.history_observation.entries[0];
for (const version of ["0.14.0", "0.14.1", "0.15.2", "0.15.0rc1", "1!0.14.1.post2", "0.15.0.dev1+build.2"]) {
  assert.ok(isCigarProducerVersion(version));
  assert.equal(parseContextHistoryEntry({ ...history, sdk_version: version }).sdk_version, version,
    "compatible history retains its actual producer; it is not relabeled as the current SDK");
}
for (const version of ["", "latest", "../0.14.1", "0.14.1\n", "0".repeat(129), 0.14, null]) {
  assert.equal(isCigarProducerVersion(version), false);
  assert.throws(() => parseContextHistoryEntry({ ...history, sdk_version: version }));
}
assert.throws(() => parseContextHistoryEntry({ ...history, sdk_version: "0.15.2", historical: false }));
const binding = { identity: { build_id: "synthetic-build", sdk_version: "0.15.2", core_version: "0.15.1",
  source_revision: "a".repeat(40), manifest_sha256: "b".repeat(64) }, profile_id: "cigar-sdk-v1",
  adapter_id: "guard-cigar-python-sdk-v1", adapter_revision: 1, profile_sha256: "c".repeat(64), platform: "darwin-arm64" };
assert.ok(isCigarReleaseBinding(binding));
const ready = JSON.parse(readFileSync(new URL("../../../docs/guard/cigar-integration/evidence/intent-state-verification.json", import.meta.url), "utf8")).native_test.ready_observation;
const upgraded = { ...ready, qualification: "guard_qualified", runtime: { ...ready.runtime, package_version: "0.15.2", core_version: "0.15.1",
  adapter_id: binding.adapter_id, adapter_revision: 1, release: binding } };
assert.equal(parseContextAssistanceStatus(upgraded).runtime!.package_version, "0.15.2");
for (const change of [
  { core_version: "0.15.2" }, { package_version: "0.14.1" }, { adapter_revision: 2 },
  { release: { ...binding, profile_sha256: "tampered" } },
]) assert.throws(() => parseContextAssistanceStatus({ ...upgraded, runtime: { ...upgraded.runtime, ...change } }));
const managed = { runtime_id: "managed-build", qualification: "guard_qualified", python_version: [3, 14, 7],
  platform: "darwin-arm64", worker_fingerprint: "d".repeat(64), sdk_version: "0.15.2", core_version: "0.15.1",
  build_id: "synthetic-build", adapter_id: binding.adapter_id, adapter_revision: 1, managed: true };
assert.equal(parseContextAssistanceStatus({ ...upgraded, installation_options: [managed] }).installation_options![0].sdk_version, "0.15.2");
for (const change of [{ build_id: null }, { managed: false }, { sdk_version: undefined }, { core_version: "" }]) {
  assert.throws(() => parseContextAssistanceStatus({ ...upgraded, installation_options: [{ ...managed, ...change }] }));
}
assert.throws(() => parseContextAssistanceStatus({ ...ready, qualification: "guard_qualified" }));
const expanded = [...upgraded.runtime.features, ...Array.from({ length: 64 - upgraded.runtime.features.length }, (_, i) => "future_feature_" + i)];
assert.equal(parseContextAssistanceStatus({ ...upgraded, runtime: { ...upgraded.runtime, features: expanded } }).runtime!.features.length, 64);
assert.throws(() => parseContextAssistanceStatus({ ...upgraded, runtime: { ...upgraded.runtime, features: [...expanded, "one_too_many"] } }));
for (const core of ["native-0.15.0-rc.1+arm64.7", "0.15.0-rc.1", "native-next+build.2"]) {
  assert.ok(isCigarCoreLabel(core));
  const release = { ...binding, identity: { ...binding.identity, core_version: core } };
  assert.ok(isCigarReleaseBinding(release));
  assert.equal(parseContextAssistanceStatus({ ...upgraded, runtime: { ...upgraded.runtime, core_version: core, release } }).runtime!.core_version, core);
}
for (const core of ["", "../core", "core/next", "core?x=1", "core\n", "λ", "a".repeat(129)]) {
  assert.equal(isCigarCoreLabel(core), false);
}
console.log("Cross-version history, qualified installations, exact release projections and native feature bounds passed.");
