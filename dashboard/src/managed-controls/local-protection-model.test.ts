import assert from 'node:assert/strict';
import { buildLocalProtectionView } from './local-protection-model';

const local = buildLocalProtectionView({
  extensionName: 'Git',
  effectiveState: 'allowed',
  source: 'This device',
  cloudControlsUrl: 'https://cloud.example.test/dashboard',
  extensionId: 'command.git',
});
assert.equal(local.primaryAction?.label, 'Apply across my devices');
assert.equal(
  local.primaryAction?.href,
  'https://cloud.example.test/guard/controls?extensionId=command.git',
);
assert.equal(local.status, 'protected');

const managed = buildLocalProtectionView({
  extensionName: 'Git',
  effectiveState: 'blocked',
  source: 'Organization Control Set',
  cloudControlsUrl: 'https://cloud.example.test',
  extensionId: 'command.git',
  permissionId: 'command.git.permission.push',
});
assert.equal(managed.status, 'managed');
assert.equal(managed.primaryAction?.label, 'Manage in Guard Cloud');
assert.equal(
  managed.primaryAction?.href,
  'https://cloud.example.test/guard/controls?extensionId=command.git&permissionId=command.git.permission.push',
);

const stale = buildLocalProtectionView({
  extensionName: 'Git',
  effectiveState: 'blocked',
  source: 'Organization Control Set',
  recovery: 'stale',
  controlSetName: 'Managed Git safety',
});
assert.equal(stale.primaryAction?.label, 'Check again');
assert.equal(stale.status, 'needs-attention');
assert(stale.technicalDetails.some((detail) => detail.value === 'Managed Git safety'));

const unsupported = buildLocalProtectionView({
  extensionName: 'Git',
  effectiveState: 'blocked',
  source: 'Organization Control Set',
  recovery: 'unsupported-version',
  catalogDigest: 'a'.repeat(64),
});
assert.equal(unsupported.status, 'unsupported');
assert.equal(unsupported.primaryAction?.label, 'Check for updates');
assert(unsupported.technicalDetails.some((detail) => detail.label === 'Catalog digest'));

const mixed = buildLocalProtectionView({
  extensionName: 'Git',
  effectiveState: 'blocked',
  source: 'Set on this device',
  sources: ['Managed by Engineering', 'Set on this device'],
  cloudControlsUrl: 'https://cloud.example.test',
});
assert.equal(mixed.effectiveState, 'blocked');
assert.equal(mixed.technicalDetails[0]?.value, 'Managed by Engineering · Set on this device');
assert.equal(mixed.primaryAction?.label, 'Manage in Guard Cloud');
