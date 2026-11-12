import assert from "node:assert/strict";
import { isCigarGeneration, parseCigarVersionJob, parseCigarVersionJobs } from "./versions-jobs";
const common = { job_id: "ui:one", phase: "queued", code: "queued", created_at_ms: 1000,
  updated_at_ms: 1000, deadline_at_ms: 121000, worker_live: true, cancel_requested: false, recovery_available: false };
const select = { ...common, schema: "guard-cigar-switch-job.v1", operation: "select", phase: "ready",
  target_runtime_id: "cigar:target", source_runtime_id: null, expected_generation: "9007199254740993",
  can_commit: true, keeps_disabled: true, reconnect_required: false, initial_selection: true,
  cleanup_pending: false, authority_restored: false, recovery_attempt: null };
const initial = parseCigarVersionJob(select);
assert.equal(initial.family, "selection");
if (initial.family === "selection") {
  assert.equal(initial.expected_generation, "9007199254740993");
  assert.equal(initial.keeps_disabled, true);
  assert.equal(initial.reconnect_required, false);
}
const active = { ...select, operation: "switch", source_runtime_id: "cigar:source",
  initial_selection: false, keeps_disabled: false, reconnect_required: true };
assert.equal(parseCigarVersionJob(active).can_commit, true);
const attempt = { id: "a".repeat(32), expected_generation: "18446744073709551615", started_at_ms: 2000, deadline_at_ms: 122000 };
const recover = { ...select, operation: "recover", phase: "preparing_recovery", expected_generation: attempt.expected_generation,
  can_commit: false, recovery_attempt: attempt };
assert.equal(parseCigarVersionJob(recover).operation, "recover");
for (const value of ["9007199254740993", "18446744073709551615", "1"]) assert.equal(isCigarGeneration(value), true);
for (const value of [9007199254740992, "0", "01", "-1", "1.0", "18446744073709551616"]) assert.equal(isCigarGeneration(value), false);
for (const bad of [
  { ...select, expected_generation: 9007199254740992 }, { ...select, authority_restored: true },
  { ...select, reconnect_required: true }, { ...select, source_runtime_id: "invented" },
  { ...select, worker_live: false }, { ...select, phase: "verifying" }, { ...select, cancel_requested: true },
  { ...recover, can_commit: true }, { ...recover, recovery_attempt: { ...attempt, expected_generation: "1" } },
  { ...recover, recovery_attempt: { ...attempt, expected_generation: 9007199254740992 } },
]) assert.throws(() => parseCigarVersionJob(bad), /incompatible CIGAR job data/);
const preparation = { ...common, schema: "guard-cigar-install-job.v1", operation: "install", activation_granted: false,
  build_id: "cigar-build:final", interpreter_id: "python:chosen", runtime_id: "cigar:prepared", sdk_version: "0.99.1", core_version: "0.99.0" };
assert.equal(parseCigarVersionJob(preparation).can_commit, false, "preparation alone does not permit selection");
assert.equal(parseCigarVersionJob({ ...preparation, operation: "verify" }).operation, "verify");
const setup = { ...common, schema: "guard-cigar-python-setup-job.v1", operation: "setup_interpreter",
  activation_granted: false, build_id: "cpython:chosen", interpreter_id: null };
assert.equal(parseCigarVersionJob(setup).operation, "setup_interpreter");
assert.throws(() => parseCigarVersionJob({ ...setup, phase: "ready" }), /incompatible CIGAR job data/);
const refresh = { ...common, schema: "guard-cigar-catalog-refresh-job.v1", operation: "refresh_catalog", activation_granted: false };
assert.equal(parseCigarVersionJob(refresh).operation, "refresh_catalog");
assert.throws(() => parseCigarVersionJob({ ...preparation, activation_granted: true }), /incompatible CIGAR job data/);
assert.equal(parseCigarVersionJobs({ jobs: [select, { ...preparation, job_id: "ui:two" }, { ...refresh, job_id: "ui:three" }] }).length, 3);
assert.throws(() => parseCigarVersionJobs({ jobs: [select, select] }), /incompatible CIGAR job data/);
assert.throws(() => parseCigarVersionJobs({ jobs: Array(33).fill(select) }), /incompatible CIGAR job data/);
console.log("CIGAR job families, native readiness separation, full generation precision and malformed projection checks passed.");
