import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ProtectionModuleDetail } from "./protection-module-detail";
import { DEFAULT_EXTENSION_DETAIL_URL_STATE } from "../extension-control-center-model";
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
assert.match(simple, /data-extension-brand="git"/);
assert.match(simple, />Overview</);
assert.match(simple, />Permissions</);
assert.match(simple, />Managed controls</);
assert.match(simple, />Activity</);
assert.match(simple, />Technical details</);
assert.match(simple, /What this Extension protects/);
assert.doesNotMatch(simple, /Protection settings/);

const permissions = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: git,
  effective: PROTECTION_AUTHORITY_FIXTURES.protected,
  catalogDigest: "a".repeat(64),
  urlState: { ...DEFAULT_EXTENSION_DETAIL_URL_STATE, tab: "permissions" },
  onBack: () => undefined,
  onRefresh: () => undefined,
}));
assert.match(permissions, /Protection settings/);
assert.match(permissions, /Forced Git push/);
assert.match(permissions, /git push --force/);
assert.match(permissions, /Recommended/);
assert.match(permissions, />Allow</);
assert.match(permissions, />Block</);
assert.match(simple, /Required by Guard/);
const activity = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: git,
  effective: PROTECTION_AUTHORITY_FIXTURES.protected,
  catalogDigest: "a".repeat(64),
  urlState: { ...DEFAULT_EXTENSION_DETAIL_URL_STATE, tab: "activity" },
  onBack: () => undefined,
  onRefresh: () => undefined,
}));
assert.match(activity, /Test Lab/);
assert.match(activity, /View matching Evidence/);
const technical = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: git,
  effective: PROTECTION_AUTHORITY_FIXTURES.protected,
  catalogDigest: "a".repeat(64),
  urlState: { ...DEFAULT_EXTENSION_DETAIL_URL_STATE, tab: "technical" },
  onBack: () => undefined,
  onRefresh: () => undefined,
}));
assert.match(technical, /Developer details/);
assert.doesNotMatch(technical, /data-testid="protection-more-detail"[^>]* open/, "developer details stay collapsed by default");
assert.doesNotMatch(simple, /Change settings/);
assert.doesNotMatch(simple, />Extension</);
assert.doesNotMatch(simple, /MCP server defaults/);

const filesystem = protectionModuleFixture({
  extension_id: "command.mcp-filesystem",
  name: "Filesystem MCP",
  description: "Reviews official filesystem MCP tools. Off until you turn it on.",
  enabled: false,
  trust_class: "external",
  activation: "opt-in",
  executables: ["npx"],
  surface: "mcp",
  mcp_launch: { kind: "package-launcher", command: "npx", package: "@modelcontextprotocol/server-filesystem" },
  mcp_tools: [
    { name: "read_file", state: "inherit" },
    { name: "write_file", state: "block" },
    { name: "other", state: "inherit" },
  ],
});
const mcpDetail = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: filesystem,
  effective: PROTECTION_AUTHORITY_FIXTURES.protected,
  catalogDigest: "a".repeat(64),
  onBack: () => undefined,
  onRefresh: () => undefined,
  onRequestExtensionChange: () => undefined,
}));
assert.match(mcpDetail, /MCP server defaults/);
assert.match(mcpDetail, /@modelcontextprotocol\/server-filesystem/);
assert.match(mcpDetail, /write_file/);
assert.match(mcpDetail, />Block</);
assert.match(mcpDetail, /This community MCP server stays off until you turn it on/);
assert.match(mcpDetail, /MCP tools available/);

const partial = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: git,
  effective: {
    ...PROTECTION_AUTHORITY_FIXTURES.protected,
    layers: [{
      schema_version: "1.0.0",
      kind: "local-admin",
      catalog_digest: "a".repeat(64),
      global_lockdown: false,
      controls: [{
        target_kind: "permission",
        target_id: "command.git.permission.force-push",
        state: "disabled",
      }],
    }],
    projection: {
      schema_version: "guard.daemon.extension-control-projection.v1",
      revision: 1,
      catalog_digest: "a".repeat(64),
      health: "protected",
      extensions: [{
        extension_id: "command.git",
        effective_state: "allowed",
        local_state: "inherited",
        managed_state: "inherited",
        required: false,
        reason_codes: [],
      }],
      permissions: [{
        permission_id: "command.git.permission.force-push",
        extension_id: "command.git",
        effective_state: "blocked",
        local_state: "disabled",
        managed_state: "inherited",
        configurable: true,
        fixed_reason: null,
        reason_codes: ["control.disabled-permission"],
      }, {
        permission_id: "command.git.permission.hard-reset",
        extension_id: "command.git",
        effective_state: "allowed",
        local_state: "inherited",
        managed_state: "inherited",
        configurable: true,
        fixed_reason: null,
        reason_codes: [],
      }],
    },
  },
  catalogDigest: "a".repeat(64),
  onBack: () => undefined,
  onRefresh: () => undefined,
}));
assert.match(partial, />Partial</);
assert.doesNotMatch(partial, />Blocked<\/dd>/, "one blocked permission does not label the entire Extension blocked");

const requiredExtension = { ...FIXED_PROTECTION_MODULE, required: true };
const required = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: requiredExtension,
  effective: PROTECTION_AUTHORITY_FIXTURES.protected,
  catalogDigest: "a".repeat(64),
  onBack: () => undefined,
  onRefresh: () => undefined,
}));
assert.match(required, /Required by Guard/);
assert.match(required, />Required</);
assert.doesNotMatch(required, />Change settings</);

const fixedSettingSimple = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: FIXED_PROTECTION_MODULE,
  effective: PROTECTION_AUTHORITY_FIXTURES.protected,
  catalogDigest: "a".repeat(64),
  urlState: { ...DEFAULT_EXTENSION_DETAIL_URL_STATE, tab: "permissions" },
  onBack: () => undefined,
  onRefresh: () => undefined,
}));
assert.match(fixedSettingSimple, /Why this cannot be changed/);
assert.doesNotMatch(fixedSettingSimple, /0 changeable settings/);

const managed = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: git,
  effective: PROTECTION_AUTHORITY_FIXTURES.managedBlock,
  catalogDigest: "a".repeat(64),
  urlState: { ...DEFAULT_EXTENSION_DETAIL_URL_STATE, tab: "permissions" },
  onBack: () => undefined,
  onRefresh: () => undefined,
}));
assert.match(managed, /Your organization controls part of this protection/);
assert.match(managed, /Recommended/);

const managedOverview = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: git,
  effective: PROTECTION_AUTHORITY_FIXTURES.managedBlock,
  catalogDigest: "a".repeat(64),
  onBack: () => undefined,
  onRefresh: () => undefined,
}));
assert.match(managedOverview, />Blocked</);
assert.doesNotMatch(managedOverview, />Managed<\/dd>/, "state reports the effective behavior, not authority presentation");

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
