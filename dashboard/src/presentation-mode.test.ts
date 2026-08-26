import { strict as assert } from "node:assert";
import { defaultTechnicalDisclosure, resolvePresentationMode } from "./presentation-mode";

assert.equal(resolvePresentationMode({}).value, "everyday");
assert.equal(resolvePresentationMode({ value: "simple", explicit: true }).value, "everyday");
assert.equal(resolvePresentationMode({ value: "advanced", explicit: true }).value, "technical");
assert.equal(resolvePresentationMode({ value: "developer", explicit: true }).value, "technical");
assert.equal(resolvePresentationMode({ value: "technical", explicit: true, cloudProfile: "everyday" }).source, "local-explicit");
assert.equal(resolvePresentationMode({ value: "everyday", sessionPreview: "technical" }).source, "session-preview");
assert.deepEqual(resolvePresentationMode({ value: "everyday", explicit: false }), {
  value: "everyday",
  source: "default",
  explicit: false,
  writable: true,
  schemaVersion: 1,
  revision: 0,
  diagnostic: null,
});
assert.deepEqual(resolvePresentationMode({ value: "technical" }), {
  value: "technical",
  source: "default",
  explicit: false,
  writable: true,
  schemaVersion: 1,
  revision: 0,
  diagnostic: null,
});
assert.deepEqual(resolvePresentationMode({ value: "technical", explicit: false, cloudProfile: "everyday" }), {
  value: "everyday",
  source: "cloud-profile",
  explicit: false,
  writable: true,
  schemaVersion: 1,
  revision: 0,
  diagnostic: null,
});
assert.equal(
  resolvePresentationMode({ value: "future" }).diagnostic,
  "unknown_presentation_mode_fell_back_to_everyday",
);
assert.equal(resolvePresentationMode({ value: "future", schemaVersion: 99 }).value, "everyday");
assert.equal(resolvePresentationMode({ readError: true }).source, "read-error");
assert.equal(defaultTechnicalDisclosure("everyday").open, false);
assert.equal(defaultTechnicalDisclosure("technical").open, true);
assert.equal(defaultTechnicalDisclosure("everyday", true).source, "required");
