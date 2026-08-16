import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ProtectionModuleDetail } from "./protection-module-detail";
import {
  FIXED_PROTECTION_MODULE,
  FIXED_PROTECTION_PERMISSION,
  PROTECTION_AUTHORITY_FIXTURES,
  largeDeveloperModuleFixture,
  protectionModuleFixture,
} from "./fixtures/protection-fixtures";

const git = protectionModuleFixture({
  extension_id: "command.git",
  name: "Git",
  description: "Protects repository history and destructive source-control actions.",
  required: true,
  ecosystem_ids: ["git"],
  executables: ["git"],
  safer_alternatives: ["Create a checkpoint before rewriting history."],
  permission_count: 2,
  permissions: [{
    ...FIXED_PROTECTION_PERMISSION,
    permission_id: "command.git.permission.force-push",
    label: "Forced Git push",
    example_command: "git push --force",
    description: "Identifies remote history replacement through a forced push.",
    configurable: true,
    fixed_reason: null,
  }, {
    ...FIXED_PROTECTION_PERMISSION,
    permission_id: "command.git.permission.hard-reset",
    label: "Destructive Git reset",
    example_command: "git reset --hard",
    description: "Identifies hard resets that discard tracked working-tree and index changes.",
    configurable: true,
    fixed_reason: null,
  }],
});

const simple = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: git,
  effective: PROTECTION_AUTHORITY_FIXTURES.protected,
  catalogDigest: "a".repeat(64),
  onBack: () => undefined,
  onRefresh: () => undefined,
}));
assert.match(simple, />Git</);
assert.match(simple, /font-mono[^"]*">git</);
assert.match(simple, /Protection settings/);
assert.match(simple, /Forced Git push/);
assert.match(simple, /git push --force/);
assert.match(simple, /Recommended/);
assert.match(simple, />Allow</);
assert.match(simple, />Block</);
assert.match(simple, /cannot be turned off/);
assert.match(simple, /Test Lab/);
assert.match(simple, /Developer details/);
assert.doesNotMatch(simple, /data-testid="protection-more-detail"[^>]* open/, "developer details stay collapsed by default");
assert.doesNotMatch(simple, /What this protects/);
assert.doesNotMatch(simple, /Change settings/);
assert.doesNotMatch(simple, />Extension</);

const requiredExtension = { ...FIXED_PROTECTION_MODULE, required: true };
const required = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: requiredExtension,
  effective: PROTECTION_AUTHORITY_FIXTURES.protected,
  catalogDigest: "a".repeat(64),
  onBack: () => undefined,
  onRefresh: () => undefined,
}));
assert.match(required, /cannot be turned off/);
assert.doesNotMatch(required, />Change settings</);

const fixedSettingSimple = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: FIXED_PROTECTION_MODULE,
  effective: PROTECTION_AUTHORITY_FIXTURES.protected,
  catalogDigest: "a".repeat(64),
  onBack: () => undefined,
  onRefresh: () => undefined,
}));
assert.match(fixedSettingSimple, /Why this cannot be changed/);
assert.doesNotMatch(fixedSettingSimple, /0 changeable settings/);

const managed = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: git,
  effective: PROTECTION_AUTHORITY_FIXTURES.managedBlock,
  catalogDigest: "a".repeat(64),
  onBack: () => undefined,
  onRefresh: () => undefined,
}));
assert.match(managed, /Your organization controls part of this protection/);
assert.match(managed, /Recommended/);

const lockdown = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: git,
  effective: PROTECTION_AUTHORITY_FIXTURES.lockdown,
  catalogDigest: "a".repeat(64),
  onBack: () => undefined,
  onRefresh: () => undefined,
}));
assert.match(lockdown, /Emergency Lockdown currently controls this module/);

const large = largeDeveloperModuleFixture(500);
assert.equal(large.rules.length, 500);
const started = performance.now();
renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: large,
  effective: PROTECTION_AUTHORITY_FIXTURES.protected,
  catalogDigest: "a".repeat(64),
  onBack: () => undefined,
  onRefresh: () => undefined,
}));
assert.ok(performance.now() - started < 500, "Simple module detail should not expand 500 Developer detections by default");

console.log("protection-module-detail.test.tsx: all assertions passed");
