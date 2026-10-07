import { ba as fetchExtensionControlApi } from "../guard-dashboard.js";
const DIGEST$2 = /^[a-f0-9]{64}$/;
const EXTENSION_ID$1 = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const PERMISSION_ID$1 = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*\.permission\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const MAX_EXTENSIONS = 512;
const MAX_PERMISSIONS = 4096;
const MAX_REASONS = 64;
function record$2(value, label) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`Invalid ${label}`);
  return value;
}
function text(value, label, max = 256) {
  if (typeof value !== "string" || value.length === 0 || value.length > max) throw new Error(`Invalid ${label}`);
  return value;
}
function integer$2(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`Invalid ${label}`);
  return value;
}
function boolean(value, label) {
  if (typeof value !== "boolean") throw new Error(`Invalid ${label}`);
  return value;
}
function enumValue$1(value, label, values) {
  const candidate = text(value, label, 64);
  if (!values.includes(candidate)) throw new Error(`Invalid ${label}`);
  return candidate;
}
function id$1(value, label, pattern) {
  const candidate = text(value, label).toLowerCase();
  if (!pattern.test(candidate)) throw new Error(`Invalid ${label}`);
  return candidate;
}
function reasons(value, label) {
  if (!Array.isArray(value) || value.length > MAX_REASONS) throw new Error(`Invalid ${label}`);
  return value.map((item, index) => text(item, `${label}[${index}]`, 128));
}
function extensionItem(value, label) {
  const item = record$2(value, label);
  return {
    extension_id: id$1(item.extension_id, `${label}.extension_id`, EXTENSION_ID$1),
    effective_state: enumValue$1(item.effective_state, `${label}.effective_state`, ["allowed", "blocked"]),
    local_state: enumValue$1(item.local_state, `${label}.local_state`, ["inherited", "enabled", "disabled"]),
    managed_state: enumValue$1(item.managed_state, `${label}.managed_state`, ["inherited", "enabled", "disabled"]),
    required: boolean(item.required, `${label}.required`),
    reason_codes: reasons(item.reason_codes, `${label}.reason_codes`)
  };
}
function permissionItem(value, label) {
  const item = record$2(value, label);
  return {
    permission_id: id$1(item.permission_id, `${label}.permission_id`, PERMISSION_ID$1),
    extension_id: id$1(item.extension_id, `${label}.extension_id`, EXTENSION_ID$1),
    effective_state: enumValue$1(item.effective_state, `${label}.effective_state`, ["allowed", "blocked"]),
    local_state: enumValue$1(item.local_state, `${label}.local_state`, ["inherited", "enabled", "disabled"]),
    managed_state: enumValue$1(item.managed_state, `${label}.managed_state`, ["inherited", "enabled", "disabled"]),
    configurable: boolean(item.configurable, `${label}.configurable`),
    fixed_reason: item.fixed_reason === null ? null : text(item.fixed_reason, `${label}.fixed_reason`, 2048),
    reason_codes: reasons(item.reason_codes, `${label}.reason_codes`)
  };
}
function normalizeEffectiveExtensionControlProjection(value) {
  const root = record$2(value, "extension projection");
  const schemaVersion = text(root.schema_version, "projection.schema_version", 128);
  if (schemaVersion !== "guard.daemon.extension-control-projection.v1") throw new Error("Invalid extension projection schema");
  const digest2 = text(root.catalog_digest, "projection.catalog_digest", 64);
  if (!DIGEST$2.test(digest2)) throw new Error("Invalid projection.catalog_digest");
  if (!Array.isArray(root.extensions) || root.extensions.length > MAX_EXTENSIONS) throw new Error("Invalid projection.extensions");
  if (!Array.isArray(root.permissions) || root.permissions.length > MAX_PERMISSIONS) throw new Error("Invalid projection.permissions");
  const extensions = root.extensions.map((item, index) => extensionItem(item, `projection.extensions[${index}]`));
  const permissions = root.permissions.map((item, index) => permissionItem(item, `projection.permissions[${index}]`));
  if (new Set(extensions.map((item) => item.extension_id)).size !== extensions.length) throw new Error("Duplicate projection extension ID");
  if (new Set(permissions.map((item) => item.permission_id)).size !== permissions.length) throw new Error("Duplicate projection permission ID");
  return {
    schema_version: "guard.daemon.extension-control-projection.v1",
    revision: integer$2(root.revision, "projection.revision"),
    catalog_digest: digest2,
    health: enumValue$1(root.health, "projection.health", ["unenrolled", "protected", "tampered", "degraded-unacknowledged", "degraded-acknowledged", "recovery-required"]),
    extensions,
    permissions
  };
}
const EXTENSION_ID = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const PERMISSION_ID = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*\.permission\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const RULE_ID = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const DIGEST$1 = /^[a-f0-9]{64}$/;
const VERSION = /^[1-9][0-9]*\.[0-9]+\.[0-9]+$/;
const EXTENSION_CLIENT_LIMITS = Object.freeze({
  extensions: 512,
  rulesPerExtension: 1024,
  permissionsPerExtension: 512,
  relationshipIds: 1024,
  controls: 1024,
  layers: 2,
  failures: 256,
  stringLength: 8192
});
class ExtensionControlProtocolError extends Error {
  constructor(message) {
    super(`Invalid extension-control response: ${message}`);
  }
}
function record$1(value, label) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ExtensionControlProtocolError(`${label} must be an object`);
  }
  return value;
}
function array(value, label, max) {
  if (!Array.isArray(value)) throw new ExtensionControlProtocolError(`${label} must be an array`);
  if (value.length > max) throw new ExtensionControlProtocolError(`${label} exceeds ${max} items`);
  return value;
}
function string$1(value, label, allowEmpty = false) {
  if (typeof value !== "string") throw new ExtensionControlProtocolError(`${label} must be a string`);
  if (value.length > EXTENSION_CLIENT_LIMITS.stringLength) throw new ExtensionControlProtocolError(`${label} is too long`);
  if (!allowEmpty && value.trim().length === 0) throw new ExtensionControlProtocolError(`${label} is required`);
  return value;
}
function optionalString(value, label) {
  if (value === null) return null;
  return string$1(value, label);
}
function catalogText(value) {
  return typeof value === "string" && value.trim() ? value : null;
}
function publisher(value, label) {
  const item = record$1(value, label);
  const url = item.url;
  return {
    id: string$1(item.id, `${label}.id`),
    displayName: string$1(item.displayName, `${label}.displayName`),
    ...url === void 0 ? {} : { url: string$1(url, `${label}.url`) }
  };
}
function icon(value, label) {
  if (value === void 0 || value === null) return { kind: "none" };
  const item = record$1(value, label);
  const kind = enumValue(item.kind, `${label}.kind`, ["react-icon", "svg-ref", "none"]);
  const name = item.name === void 0 ? void 0 : string$1(item.name, `${label}.name`);
  const background = item.background === void 0 ? void 0 : string$1(item.background, `${label}.background`);
  return { kind, ...name ? { name } : {}, ...background ? { background } : {} };
}
function bool$1(value, label) {
  if (typeof value !== "boolean") throw new ExtensionControlProtocolError(`${label} must be boolean`);
  return value;
}
function integer$1(value, label, min = 0) {
  if (!Number.isSafeInteger(value) || value < min) {
    throw new ExtensionControlProtocolError(`${label} must be an integer >= ${min}`);
  }
  return value;
}
function enumValue(value, label, values) {
  const candidate = string$1(value, label);
  if (!values.includes(candidate)) throw new ExtensionControlProtocolError(`${label} has unsupported value`);
  return candidate;
}
function id(value, label, pattern) {
  const candidate = string$1(value, label).trim().toLowerCase();
  if (!pattern.test(candidate)) throw new ExtensionControlProtocolError(`${label} is not canonical`);
  return candidate;
}
function digest$1(value, label) {
  const candidate = string$1(value, label).trim().toLowerCase();
  if (!DIGEST$1.test(candidate)) throw new ExtensionControlProtocolError(`${label} must be a SHA-256 digest`);
  return candidate;
}
function version(value, label) {
  const candidate = string$1(value, label);
  if (!VERSION.test(candidate)) throw new ExtensionControlProtocolError(`${label} is not a semantic implementation version`);
  return candidate;
}
function terminalCommands(value) {
  if (value === void 0) return void 0;
  const item = record$1(value, "effective.terminal_commands");
  return {
    ...item.shell === void 0 ? {} : { shell: enumValue(item.shell, "effective.terminal_commands.shell", ["powershell"]) },
    enroll: string$1(item.enroll, "effective.terminal_commands.enroll"),
    recover_authority: string$1(item.recover_authority, "effective.terminal_commands.recover_authority")
  };
}
function stringList(value, label, max = EXTENSION_CLIENT_LIMITS.relationshipIds) {
  return array(value, label, max).map((item, index) => string$1(item, `${label}[${index}]`));
}
function idList$1(value, label, pattern, max = EXTENSION_CLIENT_LIMITS.relationshipIds) {
  const items = array(value, label, max).map((item, index) => id(item, `${label}[${index}]`, pattern));
  if (new Set(items).size !== items.length) throw new ExtensionControlProtocolError(`${label} contains duplicates`);
  return items;
}
function safeVariant(value, label) {
  const item = record$1(value, label);
  return {
    variant_id: string$1(item.variant_id, `${label}.variant_id`),
    title: string$1(item.title, `${label}.title`),
    matcher_kind: string$1(item.matcher_kind, `${label}.matcher_kind`)
  };
}
function rule(value, extensionId, label) {
  const item = record$1(value, label);
  const ruleId = id(item.rule_id, `${label}.rule_id`, RULE_ID);
  if (!ruleId.startsWith(`${extensionId}.`)) throw new ExtensionControlProtocolError(`${label}.rule_id belongs to another extension`);
  const rawVersion = item.rule_version;
  if (!(typeof rawVersion === "string" || Number.isSafeInteger(rawVersion))) {
    throw new ExtensionControlProtocolError(`${label}.rule_version must be string or integer`);
  }
  return {
    rule_id: ruleId,
    rule_version: rawVersion,
    title: string$1(item.title, `${label}.title`),
    description: string$1(item.description, `${label}.description`),
    severity: enumValue(item.severity, `${label}.severity`, ["low", "medium", "high", "critical"]),
    risk_classes: stringList(item.risk_classes, `${label}.risk_classes`),
    action_classes: stringList(item.action_classes, `${label}.action_classes`),
    safer_alternatives: stringList(item.safer_alternatives, `${label}.safer_alternatives`),
    default_mode: enumValue(item.default_mode, `${label}.default_mode`, ["required", "enforce", "review", "monitor", "disabled"]),
    matcher_kind: string$1(item.matcher_kind, `${label}.matcher_kind`),
    safe_variants: array(item.safe_variants, `${label}.safe_variants`, EXTENSION_CLIENT_LIMITS.relationshipIds).map((entry, index) => safeVariant(entry, `${label}.safe_variants[${index}]`)),
    compatibility_fallback: bool$1(item.compatibility_fallback, `${label}.compatibility_fallback`)
  };
}
function permission(value, extensionId, label) {
  const item = record$1(value, label);
  const permissionId = id(item.permission_id, `${label}.permission_id`, PERMISSION_ID);
  const owner = id(item.extension_id, `${label}.extension_id`, EXTENSION_ID);
  if (owner !== extensionId || !permissionId.startsWith(`${extensionId}.permission.`)) {
    throw new ExtensionControlProtocolError(`${label} belongs to another extension`);
  }
  const replacement = item.replacement_permission_id === null ? null : id(item.replacement_permission_id, `${label}.replacement_permission_id`, PERMISSION_ID);
  return {
    permission_id: permissionId,
    schema_version: integer$1(item.schema_version, `${label}.schema_version`, 1),
    extension_id: owner,
    implementation_version: version(item.implementation_version, `${label}.implementation_version`),
    label: string$1(item.label, `${label}.label`),
    description: string$1(item.description, `${label}.description`),
    risk_tier: enumValue(item.risk_tier, `${label}.risk_tier`, ["low", "medium", "high", "critical"]),
    baseline_floor: enumValue(item.baseline_floor, `${label}.baseline_floor`, ["allow", "warn", "review", "require-reapproval", "sandbox-required", "block"]),
    default_enabled: bool$1(item.default_enabled, `${label}.default_enabled`),
    configurable: bool$1(item.configurable, `${label}.configurable`),
    fixed_reason: optionalString(item.fixed_reason, `${label}.fixed_reason`),
    typed_capabilities: stringList(item.typed_capabilities, `${label}.typed_capabilities`),
    action_classes: stringList(item.action_classes, `${label}.action_classes`),
    rule_ids: idList$1(item.rule_ids, `${label}.rule_ids`, RULE_ID),
    dependencies: idList$1(item.dependencies, `${label}.dependencies`, PERMISSION_ID),
    conflicts: idList$1(item.conflicts, `${label}.conflicts`, PERMISSION_ID),
    implied_permissions: idList$1(item.implied_permissions, `${label}.implied_permissions`, PERMISSION_ID),
    introduced_version: version(item.introduced_version, `${label}.introduced_version`),
    deprecated: bool$1(item.deprecated, `${label}.deprecated`),
    replacement_permission_id: replacement,
    safer_guidance: stringList(item.safer_guidance, `${label}.safer_guidance`),
    example_command: catalogText(item.example_command),
    family: catalogText(item.family)
  };
}
function mcpLaunch(value, label) {
  const item = record$1(value, label);
  const kind = enumValue(item.kind, `${label}.kind`, ["package-launcher", "direct-command", "remote-http"]);
  if (kind === "direct-command") {
    return { kind, command: string$1(item.command, `${label}.command`) };
  }
  if (kind === "package-launcher") {
    return {
      kind,
      command: string$1(item.command, `${label}.command`),
      package: string$1(item.package, `${label}.package`)
    };
  }
  return {
    kind,
    url: string$1(item.url, `${label}.url`),
    serverNames: stringList(item.serverNames, `${label}.serverNames`, 8)
  };
}
function mcpTool(value, label) {
  const item = record$1(value, label);
  return {
    name: string$1(item.name, `${label}.name`),
    state: enumValue(item.state, `${label}.state`, ["inherit", "allow", "review", "block"])
  };
}
function mcpCatalogFields(item, label) {
  if (item.surface === void 0) return {};
  const surface = enumValue(item.surface, `${label}.surface`, ["mcp"]);
  const launch = item.mcp_launch === void 0 ? void 0 : mcpLaunch(item.mcp_launch, `${label}.mcp_launch`);
  const tools = item.mcp_tools === void 0 ? void 0 : array(item.mcp_tools, `${label}.mcp_tools`, 80).map((entry, index) => mcpTool(entry, `${label}.mcp_tools[${index}]`));
  return {
    surface,
    ...launch ? { mcp_launch: launch } : {},
    ...tools ? { mcp_tools: tools } : {}
  };
}
function extension(value, label) {
  const item = record$1(value, label);
  const extensionId = id(item.extension_id, `${label}.extension_id`, EXTENSION_ID);
  const rules = array(item.rules, `${label}.rules`, EXTENSION_CLIENT_LIMITS.rulesPerExtension).map((entry, index) => rule(entry, extensionId, `${label}.rules[${index}]`));
  const permissions = array(item.permissions, `${label}.permissions`, EXTENSION_CLIENT_LIMITS.permissionsPerExtension).map((entry, index) => permission(entry, extensionId, `${label}.permissions[${index}]`));
  const ruleIds = rules.map((entry) => entry.rule_id);
  const permissionIds = permissions.map((entry) => entry.permission_id);
  if (new Set(ruleIds).size !== ruleIds.length) throw new ExtensionControlProtocolError(`${label}.rules contains duplicate rule IDs`);
  if (new Set(permissionIds).size !== permissionIds.length) throw new ExtensionControlProtocolError(`${label}.permissions contains duplicate permission IDs`);
  const knownRules = new Set(ruleIds);
  for (const spec of permissions) {
    for (const ruleId of spec.rule_ids) {
      if (!knownRules.has(ruleId)) throw new ExtensionControlProtocolError(`${label} permission references unknown rule ${ruleId}`);
    }
  }
  const ruleCount = integer$1(item.rule_count, `${label}.rule_count`);
  const permissionCount = integer$1(item.permission_count, `${label}.permission_count`);
  if (ruleCount !== rules.length || permissionCount !== permissions.length) {
    throw new ExtensionControlProtocolError(`${label} count metadata does not match payload`);
  }
  return {
    schema_version: integer$1(item.schema_version, `${label}.schema_version`, 1),
    extension_id: extensionId,
    name: string$1(item.name, `${label}.name`),
    description: string$1(item.description, `${label}.description`),
    enabled: bool$1(item.enabled, `${label}.enabled`),
    required: bool$1(item.required, `${label}.required`),
    trust_class: item.trust_class === void 0 ? "first-party" : enumValue(item.trust_class, `${label}.trust_class`, ["first-party", "trusted-library", "external"]),
    activation: item.activation === void 0 ? "default-on" : enumValue(item.activation, `${label}.activation`, ["default-on", "opt-in"]),
    publisher: item.publisher === void 0 ? { id: "hol", displayName: "Hashgraph Online" } : publisher(item.publisher, `${label}.publisher`),
    icon: icon(item.icon, `${label}.icon`),
    source: enumValue(item.source, `${label}.source`, ["built-in", "local-admin", "signed-cloud"]),
    version: version(item.version, `${label}.version`),
    aliases: idList$1(item.aliases, `${label}.aliases`, EXTENSION_ID),
    dependencies: idList$1(item.dependencies, `${label}.dependencies`, EXTENSION_ID),
    conflicts: idList$1(item.conflicts, `${label}.conflicts`, EXTENSION_ID),
    delegated_protection: optionalString(item.delegated_protection, `${label}.delegated_protection`),
    ecosystem_ids: stringList(item.ecosystem_ids, `${label}.ecosystem_ids`),
    executables: stringList(item.executables, `${label}.executables`),
    project_markers: stringList(item.project_markers, `${label}.project_markers`),
    reference_urls: stringList(item.reference_urls, `${label}.reference_urls`),
    action_classes: stringList(item.action_classes, `${label}.action_classes`),
    risk_classes: stringList(item.risk_classes, `${label}.risk_classes`),
    safer_alternatives: stringList(item.safer_alternatives, `${label}.safer_alternatives`),
    rule_count: ruleCount,
    rules,
    permission_count: permissionCount,
    permissions,
    ...mcpCatalogFields(item, label)
  };
}
function normalizeExtensionControlLayer(value, label = "layer") {
  const item = record$1(value, label);
  const controls = array(item.controls, `${label}.controls`, EXTENSION_CLIENT_LIMITS.controls).map((entry, index) => {
    const raw = record$1(entry, `${label}.controls[${index}]`);
    const kind = enumValue(raw.target_kind, `${label}.controls[${index}].target_kind`, ["extension", "permission"]);
    return {
      target_kind: kind,
      target_id: id(raw.target_id, `${label}.controls[${index}].target_id`, kind === "extension" ? EXTENSION_ID : PERMISSION_ID),
      state: enumValue(raw.state, `${label}.controls[${index}].state`, ["enabled", "disabled"])
    };
  });
  const keys = controls.map((control) => `${control.target_kind}:${control.target_id}`);
  if (new Set(keys).size !== keys.length) throw new ExtensionControlProtocolError(`${label}.controls contains duplicate targets`);
  return {
    schema_version: string$1(item.schema_version, `${label}.schema_version`),
    kind: enumValue(item.kind, `${label}.kind`, ["local-admin", "signed-cloud"]),
    catalog_digest: digest$1(item.catalog_digest, `${label}.catalog_digest`),
    global_lockdown: bool$1(item.global_lockdown, `${label}.global_lockdown`),
    controls
  };
}
function normalizeExtensionCatalog(value) {
  const root = record$1(value, "catalog");
  const extensions = array(root.extensions, "catalog.extensions", EXTENSION_CLIENT_LIMITS.extensions).map((entry, index) => extension(entry, `catalog.extensions[${index}]`));
  const ids = extensions.map((entry) => entry.extension_id);
  if (new Set(ids).size !== ids.length) throw new ExtensionControlProtocolError("catalog.extensions contains duplicate extension IDs");
  const limits = root.limits === void 0 ? void 0 : record$1(root.limits, "catalog.limits");
  return {
    schema_version: string$1(root.schema_version, "catalog.schema_version"),
    control_schema_version: root.control_schema_version === void 0 ? void 0 : string$1(root.control_schema_version, "catalog.control_schema_version"),
    catalog_digest: digest$1(root.catalog_digest, "catalog.catalog_digest"),
    extensions,
    limits: limits === void 0 ? void 0 : {
      max_body_bytes: limits.max_body_bytes === void 0 ? void 0 : integer$1(limits.max_body_bytes, "catalog.limits.max_body_bytes", 1),
      max_controls: limits.max_controls === void 0 ? void 0 : integer$1(limits.max_controls, "catalog.limits.max_controls", 1),
      max_observations: limits.max_observations === void 0 ? void 0 : integer$1(limits.max_observations, "catalog.limits.max_observations", 1)
    }
  };
}
function normalizeEffectiveExtensionControls(value) {
  const root = record$1(value, "effective");
  const controls = array(root.controls, "effective.controls", EXTENSION_CLIENT_LIMITS.controls).map((entry, index) => {
    const raw = record$1(entry, `effective.controls[${index}]`);
    const target2 = record$1(raw.target, `effective.controls[${index}].target`);
    const kind = enumValue(target2.kind, `effective.controls[${index}].target.kind`, ["extension", "permission"]);
    return {
      target: {
        kind,
        target_id: id(target2.target_id, `effective.controls[${index}].target.target_id`, kind === "extension" ? EXTENSION_ID : PERMISSION_ID)
      },
      state: enumValue(raw.state, `effective.controls[${index}].state`, ["enabled", "disabled"])
    };
  });
  const keys = controls.map((control) => `${control.target.kind}:${control.target.target_id}`);
  if (new Set(keys).size !== keys.length) throw new ExtensionControlProtocolError("effective.controls contains duplicate targets");
  const layers = array(root.layers, "effective.layers", EXTENSION_CLIENT_LIMITS.layers).map((entry, index) => normalizeExtensionControlLayer(entry, `effective.layers[${index}]`));
  const failures = array(root.failures, "effective.failures", EXTENSION_CLIENT_LIMITS.failures).map((entry, index) => {
    const raw = record$1(entry, `effective.failures[${index}]`);
    return {
      code: string$1(raw.code, `effective.failures[${index}].code`),
      detail: raw.detail === void 0 ? void 0 : string$1(raw.detail, `effective.failures[${index}].detail`, true),
      layer_kind: raw.layer_kind === void 0 ? void 0 : string$1(raw.layer_kind, `effective.failures[${index}].layer_kind`)
    };
  });
  const managedControls = root.managed_controls === void 0 ? void 0 : (() => {
    const managed = record$1(root.managed_controls, "effective.managed_controls");
    const acknowledgement = record$1(
      managed.acknowledgement,
      "effective.managed_controls.acknowledgement"
    );
    const bundleVersion = managed.bundle_version;
    if (!(typeof bundleVersion === "string" && bundleVersion.length > 0 && bundleVersion.length <= 160) && !(typeof bundleVersion === "number" && Number.isSafeInteger(bundleVersion) && bundleVersion >= 0)) {
      throw new ExtensionControlProtocolError("effective.managed_controls.bundle_version is invalid");
    }
    const policyRevision = acknowledgement.policy_revision;
    if (policyRevision !== void 0 && !(typeof policyRevision === "string" && policyRevision.length > 0 && policyRevision.length <= 160) && !(typeof policyRevision === "number" && Number.isSafeInteger(policyRevision) && policyRevision >= 0)) {
      throw new ExtensionControlProtocolError("effective.managed_controls.acknowledgement.policy_revision is invalid");
    }
    return {
      control_set_id: managed.control_set_id === void 0 ? void 0 : string$1(managed.control_set_id, "effective.managed_controls.control_set_id"),
      control_set_name: managed.control_set_name === void 0 ? void 0 : string$1(managed.control_set_name, "effective.managed_controls.control_set_name"),
      bundle_version: bundleVersion,
      workspace_id: string$1(managed.workspace_id, "effective.managed_controls.workspace_id"),
      authority_mode: managed.authority_mode === void 0 ? void 0 : enumValue(
        managed.authority_mode,
        "effective.managed_controls.authority_mode",
        ["personal-shared", "workspace-shared", "managed-restrictive"]
      ),
      catalog_digest: digest$1(managed.catalog_digest, "effective.managed_controls.catalog_digest"),
      issued_at: managed.issued_at === void 0 ? void 0 : string$1(managed.issued_at, "effective.managed_controls.issued_at"),
      expires_at: managed.expires_at === void 0 ? void 0 : string$1(managed.expires_at, "effective.managed_controls.expires_at"),
      acknowledgement: {
        extension_authority_revision: integer$1(
          acknowledgement.extension_authority_revision,
          "effective.managed_controls.acknowledgement.extension_authority_revision"
        ),
        policy_revision: policyRevision,
        effective_projection_digest: acknowledgement.effective_projection_digest === void 0 ? void 0 : digest$1(
          acknowledgement.effective_projection_digest,
          "effective.managed_controls.acknowledgement.effective_projection_digest"
        ),
        status: string$1(acknowledgement.status, "effective.managed_controls.acknowledgement.status")
      }
    };
  })();
  return {
    schema_version: string$1(root.schema_version, "effective.schema_version"),
    health: enumValue(root.health, "effective.health", ["unenrolled", "protected", "tampered", "degraded-unacknowledged", "degraded-acknowledged", "recovery-required"]),
    revision: integer$1(root.revision, "effective.revision"),
    catalog_digest: digest$1(root.catalog_digest, "effective.catalog_digest"),
    global_lockdown: bool$1(root.global_lockdown, "effective.global_lockdown"),
    controls,
    layers,
    failures,
    terminal_commands: terminalCommands(root.terminal_commands),
    projection: root.projection === void 0 ? void 0 : normalizeEffectiveExtensionControlProjection(root.projection),
    managed_controls: managedControls
  };
}
const DIGEST = /^[a-f0-9]{64}$/;
const TARGET_ID = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const MAX_CHANGED_TARGETS = 4096;
const MAX_AFFECTED_IDS = 4096;
const MAX_WARNINGS = 64;
const MAX_TEXT = 8192;
function record(value, label) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`Invalid extension-control ${label}: expected object`);
  return value;
}
function string(value, label, max = MAX_TEXT) {
  if (typeof value !== "string" || value.length === 0 || value.length > max) throw new Error(`Invalid extension-control ${label}`);
  return value;
}
function integer(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`Invalid extension-control ${label}`);
  return value;
}
function bool(value, label) {
  if (typeof value !== "boolean") throw new Error(`Invalid extension-control ${label}`);
  return value;
}
function digest(value, label) {
  const candidate = string(value, label, 64);
  if (!DIGEST.test(candidate)) throw new Error(`Invalid extension-control ${label}`);
  return candidate;
}
function targetId(value, label) {
  const candidate = string(value, label, 256);
  if (!TARGET_ID.test(candidate)) throw new Error(`Invalid extension-control ${label}`);
  return candidate;
}
function boundedArray(value, label, max) {
  if (!Array.isArray(value) || value.length > max) throw new Error(`Invalid extension-control ${label}`);
  return value;
}
function idList(value, label) {
  const items = boundedArray(value, label, MAX_AFFECTED_IDS).map((item, index) => targetId(item, `${label}[${index}]`));
  if (new Set(items).size !== items.length) throw new Error(`Invalid extension-control ${label}: duplicate IDs`);
  return items;
}
function optionalIdList(value, label) {
  return value === void 0 ? void 0 : idList(value, label);
}
function optionalStringList(value, label) {
  if (value === void 0) return void 0;
  const items = boundedArray(value, label, MAX_AFFECTED_IDS).map((item, index) => string(item, `${label}[${index}]`, 128));
  if (new Set(items).size !== items.length) throw new Error(`Invalid extension-control ${label}: duplicate values`);
  return items;
}
function warning(value, label) {
  const item = record(value, label);
  return {
    code: string(item.code, `${label}.code`, 128),
    message: string(item.message, `${label}.message`, 1024),
    ...item.target_id === void 0 ? {} : { target_id: targetId(item.target_id, `${label}.target_id`) },
    ...item.count === void 0 ? {} : { count: integer(item.count, `${label}.count`) }
  };
}
function target(value, label) {
  const item = record(value, label);
  const rawTarget = record(item.target, `${label}.target`);
  const kind = string(rawTarget.kind, `${label}.target.kind`, 32);
  if (kind !== "extension" && kind !== "permission") throw new Error(`Invalid extension-control ${label}.target.kind`);
  const beforeExplicit = string(item.before_explicit, `${label}.before_explicit`, 32);
  const afterExplicit = string(item.after_explicit, `${label}.after_explicit`, 32);
  if (!["inherited", "enabled", "disabled"].includes(beforeExplicit) || !["inherited", "enabled", "disabled"].includes(afterExplicit)) throw new Error(`Invalid extension-control ${label} explicit state`);
  const beforeEffective = string(item.before_effective, `${label}.before_effective`, 32);
  const afterEffective = string(item.after_effective, `${label}.after_effective`, 32);
  if (!["allowed", "blocked"].includes(beforeEffective) || !["allowed", "blocked"].includes(afterEffective)) throw new Error(`Invalid extension-control ${label} effective state`);
  const affectedExtensionIds = optionalIdList(item.affected_extension_ids, `${label}.affected_extension_ids`);
  const dependencyPermissionIds = optionalIdList(item.dependency_permission_ids, `${label}.dependency_permission_ids`);
  const impliedPermissionIds = optionalIdList(item.implied_permission_ids, `${label}.implied_permission_ids`);
  const conflictPermissionIds = optionalIdList(item.conflict_permission_ids, `${label}.conflict_permission_ids`);
  const provenance = optionalStringList(item.provenance, `${label}.provenance`);
  return {
    target: { kind, target_id: targetId(rawTarget.target_id, `${label}.target.target_id`) },
    extension_id: targetId(item.extension_id, `${label}.extension_id`),
    label: string(item.label, `${label}.label`, 512),
    before_explicit: beforeExplicit,
    after_explicit: afterExplicit,
    before_effective: beforeEffective,
    after_effective: afterEffective,
    affected_permission_ids: idList(item.affected_permission_ids, `${label}.affected_permission_ids`),
    affected_rule_ids: idList(item.affected_rule_ids, `${label}.affected_rule_ids`),
    ...affectedExtensionIds === void 0 ? {} : { affected_extension_ids: affectedExtensionIds },
    ...dependencyPermissionIds === void 0 ? {} : { dependency_permission_ids: dependencyPermissionIds },
    ...impliedPermissionIds === void 0 ? {} : { implied_permission_ids: impliedPermissionIds },
    ...conflictPermissionIds === void 0 ? {} : { conflict_permission_ids: conflictPermissionIds },
    ...provenance === void 0 ? {} : { provenance },
    warnings: boundedArray(item.warnings, `${label}.warnings`, MAX_WARNINGS).map((entry, index) => warning(entry, `${label}.warnings[${index}]`)),
    ...item.extension_name === void 0 ? {} : { extension_name: string(item.extension_name, `${label}.extension_name`, 512) },
    ...item.baseline_risk === void 0 ? {} : { baseline_risk: string(item.baseline_risk, `${label}.baseline_risk`, 32) },
    ...item.baseline_floor === void 0 ? {} : { baseline_floor: string(item.baseline_floor, `${label}.baseline_floor`, 32) }
  };
}
function normalizeExtensionSemanticPreview(value) {
  const root = record(value, "semantic preview");
  if (string(root.schema_version, "semantic_preview.schema_version", 128) !== "guard.daemon.extension-control-semantic-preview.v1") throw new Error("Invalid extension-control semantic preview schema");
  const lockdown = record(root.global_lockdown, "semantic_preview.global_lockdown");
  const summary = record(root.summary, "semantic_preview.summary");
  const changedTargets = boundedArray(root.changed_targets, "semantic_preview.changed_targets", MAX_CHANGED_TARGETS).map((entry, index) => target(entry, `semantic_preview.changed_targets[${index}]`));
  const changedTargetCount = integer(root.changed_target_count, "semantic_preview.changed_target_count");
  if (changedTargetCount !== changedTargets.length) throw new Error("Invalid extension-control semantic preview target count");
  return {
    schema_version: "guard.daemon.extension-control-semantic-preview.v1",
    global_lockdown: {
      before: bool(lockdown.before, "semantic_preview.global_lockdown.before"),
      after: bool(lockdown.after, "semantic_preview.global_lockdown.after"),
      changed: bool(lockdown.changed, "semantic_preview.global_lockdown.changed")
    },
    changed_target_count: changedTargetCount,
    affected_permission_count: integer(root.affected_permission_count, "semantic_preview.affected_permission_count"),
    affected_rule_count: integer(root.affected_rule_count, "semantic_preview.affected_rule_count"),
    changed_targets: changedTargets,
    ...root.approval_required === void 0 ? {} : { approval_required: bool(root.approval_required, "semantic_preview.approval_required") },
    summary: {
      newly_blocked_permissions: integer(summary.newly_blocked_permissions, "semantic_preview.summary.newly_blocked_permissions"),
      newly_allowed_permissions: integer(summary.newly_allowed_permissions, "semantic_preview.summary.newly_allowed_permissions"),
      effective_change_count: integer(summary.effective_change_count, "semantic_preview.summary.effective_change_count")
    }
  };
}
function normalizeExtensionMutationPreview(value) {
  const root = record(value, "mutation preview");
  return {
    schema_version: string(root.schema_version, "preview.schema_version", 128),
    previous_revision: integer(root.previous_revision, "preview.previous_revision"),
    next_revision: integer(root.next_revision, "preview.next_revision"),
    catalog_digest: digest(root.catalog_digest, "preview.catalog_digest"),
    canonical_diff_digest: digest(root.canonical_diff_digest, "preview.canonical_diff_digest"),
    global_lockdown: bool(root.global_lockdown, "preview.global_lockdown"),
    controls: integer(root.controls, "preview.controls"),
    semantic_preview: normalizeExtensionSemanticPreview(root.semantic_preview),
    ...root.proof_id === void 0 ? {} : { proof_id: string(root.proof_id, "preview.proof_id", 256) }
  };
}
function normalizeExtensionMutationApply(value) {
  const root = record(value, "mutation apply");
  if (string(root.status, "apply.status", 32) !== "applied") throw new Error("Invalid extension-control apply status");
  return {
    schema_version: string(root.schema_version, "apply.schema_version", 128),
    status: "applied",
    revision: integer(root.revision, "apply.revision"),
    catalog_digest: digest(root.catalog_digest, "apply.catalog_digest")
  };
}
class ExtensionControlApiError extends Error {
  constructor(message, status, code, recoveryAction) {
    super(message);
    this.status = status;
    this.code = code;
    this.recoveryAction = recoveryAction;
  }
  status;
  code;
  recoveryAction;
}
async function request(path, init) {
  const response = await fetchExtensionControlApi(path, init);
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new ExtensionControlApiError(`Guard returned invalid JSON (${response.status})`, response.status);
  }
  if (!response.ok) {
    const error = typeof payload === "object" && payload !== null ? payload : {};
    throw new ExtensionControlApiError(
      typeof error.error === "string" ? error.error : `Request failed (${response.status})`,
      response.status,
      typeof error.error === "string" ? error.error : void 0,
      typeof error.recovery === "object" && error.recovery !== null && typeof error.recovery.action === "string" ? error.recovery.action : void 0
    );
  }
  return payload;
}
async function fetchExtensionCatalog() {
  return normalizeExtensionCatalog(await request("/v1/extension-controls/catalog"));
}
async function fetchEffectiveExtensionControls() {
  const raw = await request("/v1/extension-controls/effective");
  const normalized = normalizeEffectiveExtensionControls(raw);
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return normalized;
  const projectionValue = raw.projection;
  if (projectionValue === void 0) return normalized;
  const projection = normalizeEffectiveExtensionControlProjection(projectionValue);
  if (projection.revision !== normalized.revision || projection.catalog_digest !== normalized.catalog_digest || projection.health !== normalized.health) {
    throw new ExtensionControlApiError("Guard returned an inconsistent extension-control projection", 502);
  }
  return { ...normalized, projection };
}
async function fetchExtensionControlHistory() {
  const raw = await request("/v1/extension-controls/history");
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new ExtensionControlApiError("Guard returned invalid settings history", 502);
  const root = raw;
  if (root.schema_version !== "guard.daemon.extension-control-history.v1") throw new ExtensionControlApiError("Guard returned unsupported settings history", 502);
  if (!Number.isSafeInteger(root.revision) || root.revision < 0 || typeof root.catalog_digest !== "string") throw new ExtensionControlApiError("Guard returned invalid settings history metadata", 502);
  if (!Array.isArray(root.items) || root.items.length > 50) throw new ExtensionControlApiError("Guard returned too much settings history", 502);
  const items = root.items.map((value, index) => {
    if (typeof value !== "object" || value === null || Array.isArray(value)) throw new ExtensionControlApiError("Guard returned invalid settings history item", 502);
    const item = value;
    if (!Number.isSafeInteger(item.revision) || !Number.isSafeInteger(item.previous_revision) || typeof item.occurred_at !== "string" || typeof item.catalog_digest !== "string" || !Array.isArray(item.layers)) throw new ExtensionControlApiError("Guard returned invalid settings history item", 502);
    const layers = item.layers.map((layer, layerIndex) => normalizeExtensionControlLayer(layer, `history.items[${index}].layers[${layerIndex}]`));
    return {
      revision: item.revision,
      previous_revision: item.previous_revision,
      occurred_at: item.occurred_at,
      catalog_digest: item.catalog_digest,
      layers
    };
  });
  return {
    schema_version: "guard.daemon.extension-control-history.v1",
    revision: root.revision,
    catalog_digest: root.catalog_digest,
    items
  };
}
async function recoverExtensionControlAuthority(credentials) {
  const raw = await request("/v1/extension-controls/recover-authority", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_nonce: crypto.randomUUID().replaceAll("-", ""),
      ...credentials
    })
  });
  const normalized = normalizeEffectiveExtensionControls(raw);
  if (typeof raw === "object" && raw !== null && !Array.isArray(raw) && raw.projection !== void 0) {
    return { ...normalized, projection: normalizeEffectiveExtensionControlProjection(raw.projection) };
  }
  return normalized;
}
async function acknowledgeDegradedExtensionControlAuthority(credentials) {
  const raw = await request("/v1/extension-controls/acknowledge-degraded", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_nonce: crypto.randomUUID().replaceAll("-", ""),
      ...credentials
    })
  });
  const normalized = normalizeEffectiveExtensionControls(raw);
  if (typeof raw === "object" && raw !== null && !Array.isArray(raw) && raw.projection !== void 0) {
    return { ...normalized, projection: normalizeEffectiveExtensionControlProjection(raw.projection) };
  }
  return normalized;
}
async function previewExtensionMutation(payload) {
  try {
    return normalizeExtensionMutationPreview(await request("/v1/extension-controls/preview", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }));
  } catch (error) {
    if (error instanceof ExtensionControlApiError) throw error;
    throw new ExtensionControlApiError(error instanceof Error ? error.message : "Guard returned an invalid preview response", 502);
  }
}
async function applyExtensionMutation(payload) {
  try {
    return normalizeExtensionMutationApply(await request("/v1/extension-controls/apply", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }));
  } catch (error) {
    if (error instanceof ExtensionControlApiError) throw error;
    throw new ExtensionControlApiError(error instanceof Error ? error.message : "Guard returned an invalid apply response", 502);
  }
}
export {
  ExtensionControlApiError as E,
  applyExtensionMutation as a,
  fetchEffectiveExtensionControls as b,
  fetchExtensionControlHistory as c,
  acknowledgeDegradedExtensionControlAuthority as d,
  fetchExtensionCatalog as f,
  previewExtensionMutation as p,
  recoverExtensionControlAuthority as r
};
