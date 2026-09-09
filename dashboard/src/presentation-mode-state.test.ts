import { strict as assert } from "node:assert";
import { confirmsPresentationWrite, presentationWritePayload, readPresentationSettings, unavailablePresentation, withoutPresentationSettings } from "./presentation-mode-state";
import type { GuardSettings } from "./guard-types";

const initial = { value: "everyday", source: "default", explicit: false, writable: true, schema_version: 1, revision: 0, diagnostic: null } as const;
assert.deepEqual(readPresentationSettings({ presentation: initial }), initial);
for (const invalid of [undefined, null, {}, { presentation_mode: "technical" }, { presentation: { ...initial, schema_version: 2 } },
  { presentation: { ...initial, revision: -1 } }, { presentation: { ...initial, revision: 0.5 } },
  { presentation: { ...initial, revision: Number.MAX_SAFE_INTEGER + 1 } }, { presentation: { ...initial, mode: "technical" } },
  { presentation: { ...initial, diagnostic: "raw secret-bearing server error" } }]) {
  assert.equal(readPresentationSettings(invalid).writable, false);
  assert.equal(readPresentationSettings(invalid).value, "everyday");
}
const unsupported = readPresentationSettings({ presentation: { ...initial, diagnostic: "unsupported_presentation_schema_fell_back_to_everyday" } });
assert.equal(unsupported.writable, false);
assert.throws(() => presentationWritePayload(unsupported, "technical"));
assert.deepEqual(presentationWritePayload(initial, "technical"), {
  presentation_mode: "technical", presentation_schema_version: 1, presentation_revision: 0,
});
const saved = { ...initial, value: "technical", source: "local-explicit", explicit: true, revision: 1 } as const;
assert.equal(confirmsPresentationWrite(initial, saved, "technical"), true);
assert.equal(confirmsPresentationWrite(initial, { ...saved, revision: 0 }, "technical"), false);
assert.equal(confirmsPresentationWrite(initial, { ...saved, explicit: false }, "technical"), false);
assert.equal(confirmsPresentationWrite(initial, { ...saved, writable: false }, "technical"), false);
assert.equal(confirmsPresentationWrite(saved, saved, "technical"), true);
assert.throws(() => presentationWritePayload({ ...saved, revision: Number.MAX_SAFE_INTEGER }, "everyday"));
assert.throws(() => presentationWritePayload(unavailablePresentation(), "technical"));
const mixed = { mode: "enforce", security_level: "strict", sync: false, presentation_mode: "technical",
  presentation_revision: 3, presentation_schema_version: 1, presentation_mode_explicit: true,
  presentation: saved, presentation_diagnostic: null } as Partial<GuardSettings>;
assert.deepEqual(withoutPresentationSettings(mixed), { mode: "enforce", security_level: "strict", sync: false });
assert.equal(mixed.presentation_revision, 3, "stripping metadata must not mutate the security draft");
console.log("presentation-mode-state.test.ts: all tests passed");
