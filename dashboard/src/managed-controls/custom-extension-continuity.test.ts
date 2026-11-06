import assert from 'node:assert/strict';
import { customExtensionContinuityView } from './custom-extension-continuity';

const localOnly = customExtensionContinuityView('local-only');
assert.equal(localOnly.canApplyAcrossDevices, false);
assert.match(localOnly.description, /remains local/);
assert.doesNotMatch(localOnly.privacyDisclosure, /path is|source path:/i);

const portable = customExtensionContinuityView('portable');
assert.equal(portable.canApplyAcrossDevices, true);

for (const state of ['pending-observation', 'changed-identity', 'locally-overridden', 'removed', 'stale'] as const) {
  const view = customExtensionContinuityView(state);
  assert.equal(view.canApplyAcrossDevices, false);
  assert.doesNotMatch(view.description, /download|execute|source path/i);
}
assert.match(customExtensionContinuityView('pending-observation').description, /same extension identity locally/i);
assert.match(customExtensionContinuityView('changed-identity').description, /refused/i);
assert.match(customExtensionContinuityView('locally-overridden').description, /local setting/i);
assert.match(customExtensionContinuityView('removed').description, /did not delete/i);
assert.match(customExtensionContinuityView('stale').description, /last-known-good/i);
