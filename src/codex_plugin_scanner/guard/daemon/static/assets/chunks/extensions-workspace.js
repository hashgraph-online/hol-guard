import { aB as fetchLocalCliApi, r as reactExports, aC as fetchExtensionControlApi, j as jsxRuntimeExports, aD as useResolvedApprovalGate, aa as HiMiniLockClosed, M as HiMiniExclamationTriangle, aE as HiMiniArrowPath, t as HiMiniShieldCheck, aF as HiMiniInformationCircle, aG as isApprovalProofSubmitDisabled, z as HiMiniXMark, aH as ApprovalProofFieldInputs, aI as buildApprovalProofCredentials, aJ as GenIcon, N as HiMiniBolt, aK as HiMiniGlobeAlt, aL as HiMiniCube, I as HiMiniCloud, aM as HiMiniServerStack, b as HiMiniCommandLine, aN as HiMiniFolder, aO as FaWindows, aP as FaAws, o as HiMiniCheckCircle, c as HiMiniChevronRight, C as HiMiniChevronDown, aQ as approvalProofRecentlySatisfied, aR as HiMiniArrowLeft, aS as HiMiniPlus, a3 as HiMiniClipboardDocumentCheck, a4 as HiMiniClipboard, aw as HiMiniMagnifyingGlass, y as HiMiniSparkles, aT as HiMiniNoSymbol, aU as startGuardCloudConnect, aV as HiMiniArrowTopRightOnSquare, av as WorkspacePageHeader, aW as guardAwareHref } from "../guard-dashboard.js";
import { A as ApprovalProofModal } from "./approval-proof-modal.js";
const EXTENSION_ID_PATTERN = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const RULE_ID_PATTERN = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const DEFAULT_EXTENSION_DETAIL_URL_STATE = {
  tab: "overview",
  query: "",
  risk: "all",
  state: "all",
  configurable: "all",
  source: "all",
  deprecated: "all",
  type: "all",
  sort: "name",
  ruleId: null
};
function oneOf(value, allowed, fallback) {
  return value !== null && allowed.includes(value) ? value : fallback;
}
function parseExtensionRoute(pathname) {
  if (pathname === "/extensions" || pathname === "/extensions/") return { kind: "overview" };
  if (!pathname.startsWith("/extensions/")) return { kind: "invalid" };
  const encoded = pathname.slice("/extensions/".length);
  if (!encoded || encoded.includes("/")) return { kind: "invalid" };
  try {
    const decoded = decodeURIComponent(encoded).trim().toLowerCase();
    if (!EXTENSION_ID_PATTERN.test(decoded)) return { kind: "invalid" };
    return { kind: "detail", extensionId: decoded };
  } catch {
    return { kind: "invalid" };
  }
}
function readExtensionDetailUrlState(search) {
  const params = new URLSearchParams(search);
  const rawQuery = params.get("q") ?? "";
  const query = rawQuery.slice(0, 160);
  const rawRule = params.get("rule")?.trim().toLowerCase() ?? null;
  const ruleId = rawRule && RULE_ID_PATTERN.test(rawRule) ? rawRule : null;
  return {
    tab: oneOf(params.get("tab"), ["overview", "permissions", "managed-controls", "activity", "technical", "commands", "policy", "test-lab"], "overview"),
    query,
    risk: oneOf(params.get("risk"), ["all", "low", "medium", "high", "critical"], "all"),
    state: oneOf(params.get("state"), ["all", "allowed", "blocked"], "all"),
    configurable: oneOf(params.get("configurable"), ["all", "yes", "no"], "all"),
    source: oneOf(params.get("source"), ["all", "built-in", "local-admin", "signed-cloud"], "all"),
    deprecated: oneOf(params.get("deprecated"), ["all", "yes", "no"], "all"),
    type: oneOf(params.get("type"), ["all", "permission", "rule"], "all"),
    sort: oneOf(params.get("sort"), ["name", "risk", "id"], "name"),
    ruleId
  };
}
function extensionDetailSearch(state) {
  const params = new URLSearchParams();
  if (state.tab !== "overview") params.set("tab", state.tab);
  if (state.query.trim()) params.set("q", state.query.trim().slice(0, 160));
  if (state.risk !== "all") params.set("risk", state.risk);
  if (state.state !== "all") params.set("state", state.state);
  if (state.configurable !== "all") params.set("configurable", state.configurable);
  if (state.source !== "all") params.set("source", state.source);
  if (state.deprecated !== "all") params.set("deprecated", state.deprecated);
  if (state.type !== "all") params.set("type", state.type);
  if (state.sort !== "name") params.set("sort", state.sort);
  if (state.ruleId && RULE_ID_PATTERN.test(state.ruleId)) params.set("rule", state.ruleId);
  const encoded = params.toString();
  return encoded ? `?${encoded}` : "";
}
function extensionDetailHref(extensionId, state = DEFAULT_EXTENSION_DETAIL_URL_STATE) {
  const canonical = extensionId.trim().toLowerCase();
  if (!EXTENSION_ID_PATTERN.test(canonical)) return "/extensions";
  return `/extensions/${encodeURIComponent(canonical)}${extensionDetailSearch(state)}`;
}
function canonicalExtensionId(catalog, candidate) {
  if (!candidate) return null;
  const normalized = candidate.trim().toLowerCase();
  const direct = catalog.find((extension2) => extension2.extension_id === normalized);
  if (direct) return direct.extension_id;
  return catalog.find((extension2) => extension2.aliases.includes(normalized))?.extension_id ?? null;
}
function explicitControlState(effective, kind, targetId2) {
  const projected = kind === "extension" ? effective.projection?.extensions.find((item) => item.extension_id === targetId2)?.local_state : effective.projection?.permissions.find((item) => item.permission_id === targetId2)?.local_state;
  if (projected) return projected === "inherited" ? null : projected;
  return effective.controls.find(
    (control) => control.target.kind === kind && control.target.target_id === targetId2
  )?.state ?? null;
}
function managedExplicitControlState(effective, kind, targetId2) {
  const projected = effective.projection?.extensions.find((item) => item.extension_id === targetId2)?.managed_state;
  if (projected) return projected === "inherited" ? null : projected;
  for (const layer of effective.layers) {
    if (layer.kind !== "signed-cloud") continue;
    const control = layer.controls.find((item) => item.target_kind === kind && item.target_id === targetId2);
    if (control) return control.state;
  }
  return null;
}
function extensionEffectiveState(effective, extension2) {
  const projected = effective.projection?.extensions.find((item) => item.extension_id === extension2.extension_id);
  if (projected) return projected.effective_state === "allowed" ? "enabled" : "disabled";
  if (effective.health !== "protected") return "disabled";
  if (effective.global_lockdown) return "disabled";
  if (extension2.required) return "enabled";
  return explicitControlState(effective, "extension", extension2.extension_id) ?? "enabled";
}
function permissionEffectiveState(effective, extension2, permission2) {
  const projected = effective.projection?.permissions.find((item) => item.permission_id === permission2.permission_id);
  if (projected) return projected.effective_state === "allowed" ? "enabled" : "disabled";
  if (extensionEffectiveState(effective, extension2) === "disabled") return "disabled";
  if (!permission2.configurable) return permission2.default_enabled ? "enabled" : "disabled";
  return explicitControlState(effective, "permission", permission2.permission_id) ?? (permission2.default_enabled ? "enabled" : "disabled");
}
function extensionDisplayName(name) {
  for (const suffix of [" command protection", " protection"]) {
    if (!name.toLowerCase().endsWith(suffix)) continue;
    const shortened = name.slice(0, name.length - suffix.length);
    if (shortened.length < 3 || /[-\s,.]$/.test(shortened)) break;
    return shortened;
  }
  return name;
}
function extensionStateLabel(effective, extension2) {
  if (effective.health !== "protected") return "Unavailable";
  if (effective.global_lockdown) return "Lockdown";
  if (managedExplicitControlState(effective, "extension", extension2.extension_id) !== null) return "Managed";
  if (extension2.required) return "Required";
  return extensionEffectiveState(effective, extension2) === "enabled" ? "Allowed" : "Blocked";
}
function controlProvenance(effective, kind, targetId2) {
  const managedSource2 = effective.managed_controls?.authority_mode === "managed-restrictive" ? `Managed by ${effective.managed_controls.workspace_id}` : "Synced from Guard Cloud";
  const projected = kind === "extension" ? effective.projection?.extensions.find((item) => item.extension_id === targetId2) : effective.projection?.permissions.find((item) => item.permission_id === targetId2);
  if (projected) {
    const sources2 = [];
    if (effective.global_lockdown) sources2.push("Emergency Lockdown");
    if (projected.managed_state !== "inherited") sources2.push(managedSource2);
    if (projected.local_state !== "inherited") sources2.push("Set on this device");
    if (sources2.length === 0) sources2.push("Recommended by Guard");
    return sources2;
  }
  const sources = [];
  if (effective.global_lockdown) sources.push("Emergency Lockdown");
  for (const layer of effective.layers) {
    if (layer.controls.some((control) => control.target_kind === kind && control.target_id === targetId2)) {
      sources.push(layer.kind === "signed-cloud" ? managedSource2 : "Set on this device");
    }
  }
  if (sources.length === 0) sources.push("Recommended by Guard");
  return sources;
}
function permissionForRule(extension2, rule2) {
  return extension2.permissions.find((permission2) => permission2.rule_ids.includes(rule2.rule_id)) ?? null;
}
function treatmentLabel(value) {
  const labels = {
    allow: "Allow",
    warn: "Warn",
    review: "Review",
    "require-reapproval": "Require reapproval",
    "sandbox-required": "Require sandbox",
    block: "Block",
    required: "Required",
    enforce: "Enforce",
    monitor: "Monitor",
    disabled: "Disabled"
  };
  return labels[value] ?? value.replaceAll("-", " ");
}
function familyHeading(permissions) {
  const examples = permissions.map((permission2) => permission2.example_command).filter((example) => Boolean(example)).map((example) => example.split(/\s+/));
  if (!examples.length) return permissions[0]?.label ?? "";
  const first = examples[0];
  const shared = [];
  for (let index = 0; index < first.length; index += 1) {
    const token = first[index];
    if (examples.every((parts) => parts[index] === token)) shared.push(token);
    else break;
  }
  return shared.length ? shared.join(" ") : permissions[0]?.label ?? "";
}
function groupPermissionsByFamily(permissions) {
  const byFamily = /* @__PURE__ */ new Map();
  const ungrouped = [];
  for (const permission2 of permissions) {
    if (!permission2.family) ungrouped.push(permission2);
    else {
      const members = byFamily.get(permission2.family) ?? [];
      members.push(permission2);
      byFamily.set(permission2.family, members);
    }
  }
  const families = [...byFamily.entries()].map(([family, members]) => ({ family, heading: familyHeading(members), permissions: members })).sort((left, right) => left.family.localeCompare(right.family));
  return { ungrouped, families };
}
const LOCAL_CLI_ID_PATTERN = /^local-cli\.[a-z0-9]+(?:-[a-z0-9]+){0,8}$/;
function addCustomExtensionHref() {
  return "/extensions/add";
}
function parseProtectionRoute(pathname) {
  if (pathname === "/extensions/add" || pathname === "/extensions/add/") {
    return { kind: "add-custom" };
  }
  if (pathname.startsWith("/extensions/local-cli/")) {
    try {
      const cliId = decodeURIComponent(pathname.slice("/extensions/local-cli/".length)).trim().toLowerCase();
      if (cliId && !cliId.includes("/") && LOCAL_CLI_ID_PATTERN.test(cliId)) {
        return { kind: "local-cli", cliId };
      }
    } catch {
      return { kind: "invalid" };
    }
    return { kind: "invalid" };
  }
  return parseExtensionRoute(pathname);
}
function localCliHref(cliId) {
  return `/extensions/local-cli/${encodeURIComponent(cliId)}`;
}
class LocalCliApiError extends Error {
  code;
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}
const CLI_ID_PATTERN = /^local-cli\.[a-z0-9]+(?:-[a-z0-9]+){0,8}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
function isRecord(value) {
  return typeof value === "object" && value !== null;
}
function requiredString(value, field) {
  if (typeof value !== "string" || !value.trim()) throw new Error(`Invalid local CLI ${field}`);
  return value.trim();
}
function requiredInt(value, field) {
  if (typeof value !== "number" || !Number.isInteger(value)) throw new Error(`Invalid local CLI ${field}`);
  return value;
}
function optionalString$1(value) {
  if (value === null || value === void 0) return null;
  if (typeof value !== "string") throw new Error("Invalid local CLI string");
  return value;
}
function isLocalCliId(value) {
  return CLI_ID_PATTERN.test(value);
}
function addedCustomExtensions(items) {
  return items.filter((item) => item.state !== "unset");
}
function suggestedCustomExtensions(items) {
  return items.filter((item) => item.state === "unset" && item.suggestable);
}
function suggestedHarnessExtensions(items) {
  return suggestedCustomExtensions(items).filter((item) => item.source_label !== null);
}
function suggestedSeenExtensions(items) {
  return suggestedCustomExtensions(items).filter((item) => item.source_label === null && item.surface !== "package-scripts").slice().sort(compareSeenSuggestions);
}
function suggestedPackageScriptExtensions(items) {
  return suggestedCustomExtensions(items).filter((item) => item.surface === "package-scripts").slice().sort(compareSeenSuggestions);
}
function looksLikePackageScriptPaste(value) {
  const trimmed = value.trim();
  if (!trimmed) return false;
  if (/(^|\/)package\.json$/i.test(trimmed)) return true;
  if (!trimmed.includes(" ") && (trimmed.includes("/") || trimmed.includes("\\") || trimmed === ".")) {
    return true;
  }
  const manager = /^(npm|pnpm|yarn|bun)(?:\.cmd)?\b/i.exec(trimmed);
  if (manager === null) return false;
  if (/\b(run|run-script|start|test|stop|restart)\b/i.test(trimmed)) return true;
  return /^yarn\s+\S+/i.test(trimmed);
}
function filterExtensionSuggestions(items, query) {
  const needle = query.trim().toLowerCase();
  if (!needle) return [...items];
  return items.filter((item) => suggestionMatchesQuery(item, needle));
}
function preferredPackageScriptExtension(items) {
  return suggestedPackageScriptExtensions(items).find((item) => item.commands.length > 0) ?? null;
}
function looksLikeProjectRelocatePaste(value) {
  const trimmed = unwrapPathPaste(value);
  if (!trimmed) return false;
  if (/(^|[\\/])package\.json$/i.test(trimmed)) return true;
  if (/\s(--prefix|-C|--dir|--cwd|--workspace-dir)(=|\s)/i.test(trimmed)) return true;
  if (/^[A-Za-z]:[\\/]/.test(trimmed) || trimmed.startsWith("/") || trimmed.startsWith("~/") || trimmed === ".") {
    return true;
  }
  return !trimmed.includes(" ") && (trimmed.includes("/") || trimmed.includes("\\"));
}
function keepsPackageScriptCatalog(query, commands) {
  const trimmed = query.trim();
  if (!trimmed) return true;
  if (looksLikeProjectRelocatePaste(trimmed)) return false;
  if (looksLikePackageScriptPaste(trimmed)) return true;
  const needle = packageScriptFilterNeedle(trimmed) || trimmed.toLowerCase();
  return commands.some((command) => commandMatchesQuery(command, needle));
}
function filterPackageScriptCommands(commands, query) {
  const needle = packageScriptFilterNeedle(query);
  if (!needle) return [...commands];
  return commands.filter((command) => commandMatchesQuery(command, needle));
}
function commandMatchesQuery(command, needle) {
  const haystacks = [command.name, command.usage, command.description];
  if (haystacks.some((value) => value.toLowerCase().includes(needle))) return true;
  return colonPartsMatch(command.name, needle);
}
function enrollablePackageScriptCommands(commands) {
  return commands.filter((command) => command.command_id !== "root" && command.command_id !== "other");
}
function enrollmentCommandStates(commands, pending, surface) {
  if (surface !== "package-scripts") return commandStatesFrom(commands);
  return commands.map((command) => ({
    command_id: command.command_id,
    state: packageScriptEnrollmentState(command, pending)
  }));
}
function applyBulkCommandState(commands, state, skipIds = /* @__PURE__ */ new Set()) {
  return commands.map((command) => skipIds.has(command.command_id) ? command : { ...command, state });
}
function bulkCommandState(commands) {
  if (commands.length === 0) return "inherit";
  const first = commands[0].state;
  return commands.every((command) => command.state === first) ? first : "mixed";
}
function commandStatesFrom(commands) {
  return commands.map((command) => ({ command_id: command.command_id, state: command.state }));
}
function packageScriptEnrollmentState(command, pending) {
  if (command.command_id === "root" || command.command_id === "other") return command.state;
  if (pending === "blocked") return "block";
  if (command.state === "block") return "block";
  if (pending === "allowed") return "allow";
  return command.state;
}
function colonPartsMatch(name, needle) {
  const queryParts = needle.split(":").map((part) => part.trim()).filter(Boolean);
  if (queryParts.length < 2) return false;
  const nameParts = name.toLowerCase().split(":");
  let index = 0;
  for (const part of nameParts) {
    if (index < queryParts.length && part.includes(queryParts[index])) index += 1;
  }
  return index === queryParts.length;
}
function packageScriptFilterNeedle(query) {
  const trimmed = query.trim().toLowerCase();
  if (!trimmed) return "";
  return trimmed.replace(/^(npm|pnpm|yarn|bun)(?:\.cmd)?(?:\s+run(?:-script)?)?\s*/, "").trim();
}
function unwrapPathPaste(value) {
  const trimmed = value.trim();
  if (trimmed.startsWith("'") && trimmed.endsWith("'") || trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1).trim();
  }
  return trimmed;
}
function seenSuggestionMeta(item) {
  if (item.observed_count <= 0) {
    return item.kind === "script" ? "Script" : "Tool";
  }
  if (item.observed_count === 1) return "Seen once";
  return `Seen ${item.observed_count} times`;
}
function compareSeenSuggestions(left, right) {
  if (right.suggestion_score !== left.suggestion_score) {
    return right.suggestion_score - left.suggestion_score;
  }
  if (right.observed_count !== left.observed_count) {
    return right.observed_count - left.observed_count;
  }
  const recency = (right.last_seen_at ?? "").localeCompare(left.last_seen_at ?? "");
  if (recency !== 0) return recency;
  return left.name.localeCompare(right.name);
}
function suggestionMatchesQuery(item, needle) {
  const compact = packageScriptFilterNeedle(needle) || needle;
  const haystacks = [item.name, item.example_label, item.source_label ?? ""];
  if (haystacks.some((value) => value.toLowerCase().includes(needle) || value.toLowerCase().includes(compact))) {
    return true;
  }
  if (item.surface !== "package-scripts") return false;
  return item.commands.some((command) => commandMatchesQuery(command, compact));
}
function normalizeLocalCliItem(value) {
  if (!isRecord(value)) throw new Error("Invalid local CLI item");
  const cliId = requiredString(value.cli_id, "id");
  if (!isLocalCliId(cliId)) throw new Error("Invalid local CLI id");
  const identityHash = requiredString(value.identity_hash, "identity");
  if (!SHA256_PATTERN.test(identityHash)) throw new Error("Invalid local CLI identity");
  const kind = value.kind;
  if (kind !== "executable" && kind !== "script") throw new Error("Invalid local CLI kind");
  const state = value.state;
  if (state !== "unset" && state !== "allowed" && state !== "blocked") throw new Error("Invalid local CLI state");
  return {
    cli_id: cliId,
    name: requiredString(value.name, "name").slice(0, 120),
    kind,
    identity_hash: identityHash,
    example_label: requiredString(value.example_label, "example").slice(0, 160),
    interpreter_name: optionalString$1(value.interpreter_name),
    observed_count: requiredInt(value.observed_count, "count"),
    last_seen_at: optionalString$1(value.last_seen_at),
    source_path: optionalString$1(value.source_path),
    help_status: normalizeHelpStatus(value.help_status),
    surface: normalizeSurface(value.surface),
    server_identity_hash: normalizeIdentityHash(value.server_identity_hash),
    source_label: optionalSourceLabel(value.source_label),
    state,
    stale: value.stale === true,
    grant_revision: value.grant_revision === null || value.grant_revision === void 0 ? null : requiredInt(value.grant_revision, "grant revision"),
    authority_revision: requiredInt(value.authority_revision, "revision"),
    suggestable: value.suggestable === true,
    suggestion_score: optionalScore(value.suggestion_score),
    commands: Array.isArray(value.commands) ? value.commands.map(normalizeLocalCliCommand) : [],
    continuity: normalizeContinuity(value.continuity)
  };
}
function normalizeContinuity(value) {
  if (!isRecord(value)) return null;
  const status = value.status;
  if (status !== "applied" && status !== "pending_observation" && status !== "changed_identity" && status !== "locally_overridden" && status !== "removed" && status !== "stale") return null;
  return {
    status,
    reason: typeof value.reason === "string" ? value.reason : "",
    cloud_revision: typeof value.cloud_revision === "number" && Number.isInteger(value.cloud_revision) ? value.cloud_revision : null,
    surface: value.surface === "cli" || value.surface === "mcp" || value.surface === "package-scripts" ? value.surface : null
  };
}
function normalizeSurface(value) {
  if (value === "mcp") return "mcp";
  if (value === "package-scripts") return "package-scripts";
  return "cli";
}
function normalizeHelpStatus(value) {
  if (value === "ok" || value === "empty" || value === "failed") return value;
  return null;
}
function normalizeIdentityHash(value) {
  if (value === null || value === void 0 || value === "") return null;
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) return null;
  return value;
}
function optionalScore(value) {
  if (value === null || value === void 0) return 0;
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new Error("Invalid local CLI suggestion score");
  }
  return value;
}
function optionalSourceLabel(value) {
  if (value === null || value === void 0 || value === "") return null;
  if (typeof value !== "string") return null;
  return value.trim().slice(0, 120) || null;
}
function normalizeLocalCliCommand(value) {
  if (!isRecord(value)) throw new Error("Invalid local CLI command");
  const state = value.state;
  if (state !== "inherit" && state !== "allow" && state !== "block") {
    throw new Error("Invalid local CLI command state");
  }
  const parent = value.parent_id;
  if (parent !== null && parent !== void 0 && typeof parent !== "string") {
    throw new Error("Invalid local CLI command parent");
  }
  return {
    command_id: requiredString(value.command_id, "command").slice(0, 80),
    name: requiredString(value.name, "command name").slice(0, 120),
    usage: requiredString(value.usage, "command usage").slice(0, 160),
    description: typeof value.description === "string" ? value.description.slice(0, 240) : "",
    parent_id: typeof parent === "string" && parent.trim() ? parent : null,
    state
  };
}
function normalizeLocalCliList(value) {
  if (!isRecord(value)) throw new Error("Invalid local CLI list");
  const cloud = isRecord(value.cloud) ? value.cloud : {};
  const items = Array.isArray(value.items) ? value.items.flatMap((entry) => {
    try {
      return [normalizeLocalCliItem(entry)];
    } catch {
      return [];
    }
  }) : [];
  return {
    schema_version: requiredString(value.schema_version, "schema"),
    revision: requiredInt(value.revision, "revision"),
    items,
    cloud: {
      sync_local_only: cloud.sync_local_only !== false,
      continuity_enabled: cloud.continuity_enabled === true,
      summary: typeof cloud.summary === "string" ? cloud.summary : "Custom Extensions remain local to this device until portable continuity is enabled."
    }
  };
}
async function readJson(response) {
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const record2 = isRecord(payload) ? payload : {};
    const code = typeof record2.error === "string" ? record2.error : "local_cli_request_failed";
    const message = typeof record2.message === "string" ? record2.message : "Guard could not update this custom extension.";
    throw new LocalCliApiError(code, message);
  }
  if (payload === null) {
    throw new LocalCliApiError("local_cli_request_failed", "Guard could not update this custom extension.");
  }
  return payload;
}
async function fetchLocalCliList() {
  return normalizeLocalCliList(await readJson(await fetchLocalCliApi("/v1/local-clis")));
}
async function previewLocalCliMutation(payload) {
  const body = await readJson(await fetchLocalCliApi("/v1/local-clis/preview", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  }));
  if (!isRecord(body)) throw new Error("Invalid local CLI preview");
  return { summary: requiredString(body.summary, "summary") };
}
async function recognizeLocalCli(command, options) {
  const body = await readJson(await fetchLocalCliApi("/v1/local-clis/recognize", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      command,
      ...options?.cliId ? { cli_id: options.cliId } : {}
    })
  }));
  if (!isRecord(body)) throw new Error("Invalid local CLI recognition");
  const item = normalizeLocalCliItem(body.item);
  return {
    item,
    summary: requiredString(body.summary, "summary"),
    revision: requiredInt(body.revision, "revision"),
    help_status: normalizeHelpStatus(body.help_status) ?? item.help_status
  };
}
async function applyLocalCliMutation(payload) {
  await readJson(await fetchLocalCliApi("/v1/local-clis/apply", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  }));
}
const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "[tabindex]:not([tabindex='-1'])"
].join(",");
function focusableElements(root) {
  return Array.from(root.querySelectorAll(FOCUSABLE_SELECTOR)).filter(
    (element) => !element.hasAttribute("hidden") && element.getAttribute("aria-hidden") !== "true"
  );
}
function useModalDialog(onClose, canClose = true) {
  const dialogRef = reactExports.useRef(null);
  const closeRef = reactExports.useRef(onClose);
  const canCloseRef = reactExports.useRef(canClose);
  closeRef.current = onClose;
  canCloseRef.current = canClose;
  reactExports.useEffect(() => {
    const root = dialogRef.current;
    if (!root) return;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const initial = focusableElements(root)[0] ?? root;
    initial.focus();
    const handleKeyDown = (event) => {
      if (event.key === "Escape" && canCloseRef.current) {
        event.preventDefault();
        closeRef.current();
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = focusableElements(root);
      if (focusable.length === 0) {
        event.preventDefault();
        root.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      if (previous?.isConnected) previous.focus();
    };
  }, []);
  return dialogRef;
}
function cloneLayers$1(layers) {
  return layers.map((layer) => ({
    ...layer,
    controls: layer.controls.map((control) => ({ ...control }))
  }));
}
function sortedControls(layer) {
  return {
    ...layer,
    controls: [...layer.controls].sort(
      (left, right) => `${left.target_kind}:${left.target_id}`.localeCompare(`${right.target_kind}:${right.target_id}`)
    )
  };
}
function localPermissionDraftState(layers, permissionId) {
  const local = layers.find((layer) => layer.kind === "local-admin");
  const control = local?.controls.find(
    (item) => item.target_kind === "permission" && item.target_id === permissionId
  );
  if (!control) return "inherit";
  return control.state === "enabled" ? "allow" : "block";
}
function setLocalPermissionDraftState(layers, catalogDigest, permissionId, state) {
  const next = cloneLayers$1(layers);
  let local = next.find((layer) => layer.kind === "local-admin");
  if (!local && state === "inherit") return next;
  if (!local) {
    local = {
      schema_version: "1.0.0",
      kind: "local-admin",
      catalog_digest: catalogDigest,
      global_lockdown: false,
      controls: []
    };
    next.push(local);
  }
  const hadPermissionControl = local.controls.some(
    (control) => control.target_kind === "permission" && control.target_id === permissionId
  );
  local.controls = local.controls.filter(
    (control) => control.target_kind !== "permission" || control.target_id !== permissionId
  );
  if (state !== "inherit") {
    local.controls.push({
      target_kind: "permission",
      target_id: permissionId,
      state: state === "allow" ? "enabled" : "disabled"
    });
  }
  if (state === "inherit" && hadPermissionControl && !local.global_lockdown && local.controls.length === 0) {
    const localIndex = next.indexOf(local);
    next.splice(localIndex, 1);
  }
  const normalized = next.map((layer) => sortedControls(layer));
  normalized.sort((left, right) => left.kind.localeCompare(right.kind));
  return normalized;
}
function setLocalPermissionDraftStates(layers, catalogDigest, permissionIds, state) {
  return permissionIds.reduce(
    (next, permissionId) => setLocalPermissionDraftState(next, catalogDigest, permissionId, state),
    layers
  );
}
function canonicalLayerValue(layers) {
  return JSON.stringify(
    [...layers].map((layer) => sortedControls(layer)).sort((left, right) => left.kind.localeCompare(right.kind))
  );
}
function extensionPolicyDraftIsDirty(effective, draftLayers) {
  return canonicalLayerValue(effective.layers) !== canonicalLayerValue(draftLayers);
}
function buildExtensionPolicyDraftMutation(effective, catalogDigest, draftLayers, identity) {
  return {
    previous_revision: effective.revision,
    catalog_digest: catalogDigest,
    layers: cloneLayers$1(draftLayers),
    actor_id: "dashboard-admin",
    idempotency_key: identity.idempotencyKey,
    nonce: identity.nonce
  };
}
function newExtensionPolicyDraftIdentity() {
  return {
    idempotencyKey: crypto.randomUUID().replaceAll("-", ""),
    nonce: crypto.randomUUID().replaceAll("-", "")
  };
}
function isCurrentExtensionPolicyDraft(generation, current) {
  return generation === current;
}
const DIGEST$2 = /^[a-f0-9]{64}$/;
const EXTENSION_ID$1 = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const PERMISSION_ID$1 = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*\.permission\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const MAX_EXTENSIONS = 512;
const MAX_PERMISSIONS = 4096;
const MAX_REASONS = 64;
function record$3(value, label) {
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
  const item = record$3(value, label);
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
  const item = record$3(value, label);
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
  const root = record$3(value, "extension projection");
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
function record$2(value, label) {
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
function stringList$1(value, label, max = EXTENSION_CLIENT_LIMITS.relationshipIds) {
  return array(value, label, max).map((item, index) => string$1(item, `${label}[${index}]`));
}
function idList$1(value, label, pattern, max = EXTENSION_CLIENT_LIMITS.relationshipIds) {
  const items = array(value, label, max).map((item, index) => id(item, `${label}[${index}]`, pattern));
  if (new Set(items).size !== items.length) throw new ExtensionControlProtocolError(`${label} contains duplicates`);
  return items;
}
function safeVariant(value, label) {
  const item = record$2(value, label);
  return {
    variant_id: string$1(item.variant_id, `${label}.variant_id`),
    title: string$1(item.title, `${label}.title`),
    matcher_kind: string$1(item.matcher_kind, `${label}.matcher_kind`)
  };
}
function rule(value, extensionId, label) {
  const item = record$2(value, label);
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
    risk_classes: stringList$1(item.risk_classes, `${label}.risk_classes`),
    action_classes: stringList$1(item.action_classes, `${label}.action_classes`),
    safer_alternatives: stringList$1(item.safer_alternatives, `${label}.safer_alternatives`),
    default_mode: enumValue(item.default_mode, `${label}.default_mode`, ["required", "enforce", "review", "monitor", "disabled"]),
    matcher_kind: string$1(item.matcher_kind, `${label}.matcher_kind`),
    safe_variants: array(item.safe_variants, `${label}.safe_variants`, EXTENSION_CLIENT_LIMITS.relationshipIds).map((entry, index) => safeVariant(entry, `${label}.safe_variants[${index}]`)),
    compatibility_fallback: bool$1(item.compatibility_fallback, `${label}.compatibility_fallback`)
  };
}
function permission(value, extensionId, label) {
  const item = record$2(value, label);
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
    typed_capabilities: stringList$1(item.typed_capabilities, `${label}.typed_capabilities`),
    action_classes: stringList$1(item.action_classes, `${label}.action_classes`),
    rule_ids: idList$1(item.rule_ids, `${label}.rule_ids`, RULE_ID),
    dependencies: idList$1(item.dependencies, `${label}.dependencies`, PERMISSION_ID),
    conflicts: idList$1(item.conflicts, `${label}.conflicts`, PERMISSION_ID),
    implied_permissions: idList$1(item.implied_permissions, `${label}.implied_permissions`, PERMISSION_ID),
    introduced_version: version(item.introduced_version, `${label}.introduced_version`),
    deprecated: bool$1(item.deprecated, `${label}.deprecated`),
    replacement_permission_id: replacement,
    safer_guidance: stringList$1(item.safer_guidance, `${label}.safer_guidance`),
    example_command: catalogText(item.example_command),
    family: catalogText(item.family)
  };
}
function extension(value, label) {
  const item = record$2(value, label);
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
    source: enumValue(item.source, `${label}.source`, ["built-in", "local-admin", "signed-cloud"]),
    version: version(item.version, `${label}.version`),
    aliases: idList$1(item.aliases, `${label}.aliases`, EXTENSION_ID),
    dependencies: idList$1(item.dependencies, `${label}.dependencies`, EXTENSION_ID),
    conflicts: idList$1(item.conflicts, `${label}.conflicts`, EXTENSION_ID),
    delegated_protection: optionalString(item.delegated_protection, `${label}.delegated_protection`),
    ecosystem_ids: stringList$1(item.ecosystem_ids, `${label}.ecosystem_ids`),
    executables: stringList$1(item.executables, `${label}.executables`),
    project_markers: stringList$1(item.project_markers, `${label}.project_markers`),
    reference_urls: stringList$1(item.reference_urls, `${label}.reference_urls`),
    action_classes: stringList$1(item.action_classes, `${label}.action_classes`),
    risk_classes: stringList$1(item.risk_classes, `${label}.risk_classes`),
    safer_alternatives: stringList$1(item.safer_alternatives, `${label}.safer_alternatives`),
    rule_count: ruleCount,
    rules,
    permission_count: permissionCount,
    permissions
  };
}
function normalizeExtensionControlLayer(value, label = "layer") {
  const item = record$2(value, label);
  const controls = array(item.controls, `${label}.controls`, EXTENSION_CLIENT_LIMITS.controls).map((entry, index) => {
    const raw = record$2(entry, `${label}.controls[${index}]`);
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
  const root = record$2(value, "catalog");
  const extensions = array(root.extensions, "catalog.extensions", EXTENSION_CLIENT_LIMITS.extensions).map((entry, index) => extension(entry, `catalog.extensions[${index}]`));
  const ids = extensions.map((entry) => entry.extension_id);
  if (new Set(ids).size !== ids.length) throw new ExtensionControlProtocolError("catalog.extensions contains duplicate extension IDs");
  const limits = root.limits === void 0 ? void 0 : record$2(root.limits, "catalog.limits");
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
  const root = record$2(value, "effective");
  const controls = array(root.controls, "effective.controls", EXTENSION_CLIENT_LIMITS.controls).map((entry, index) => {
    const raw = record$2(entry, `effective.controls[${index}]`);
    const target2 = record$2(raw.target, `effective.controls[${index}].target`);
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
    const raw = record$2(entry, `effective.failures[${index}]`);
    return {
      code: string$1(raw.code, `effective.failures[${index}].code`),
      detail: raw.detail === void 0 ? void 0 : string$1(raw.detail, `effective.failures[${index}].detail`, true),
      layer_kind: raw.layer_kind === void 0 ? void 0 : string$1(raw.layer_kind, `effective.failures[${index}].layer_kind`)
    };
  });
  const managedControls = root.managed_controls === void 0 ? void 0 : (() => {
    const managed = record$2(root.managed_controls, "effective.managed_controls");
    const acknowledgement = record$2(
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
function record$1(value, label) {
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
  const item = record$1(value, label);
  return {
    code: string(item.code, `${label}.code`, 128),
    message: string(item.message, `${label}.message`, 1024),
    ...item.target_id === void 0 ? {} : { target_id: targetId(item.target_id, `${label}.target_id`) },
    ...item.count === void 0 ? {} : { count: integer(item.count, `${label}.count`) }
  };
}
function target(value, label) {
  const item = record$1(value, label);
  const rawTarget = record$1(item.target, `${label}.target`);
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
  const root = record$1(value, "semantic preview");
  if (string(root.schema_version, "semantic_preview.schema_version", 128) !== "guard.daemon.extension-control-semantic-preview.v1") throw new Error("Invalid extension-control semantic preview schema");
  const lockdown = record$1(root.global_lockdown, "semantic_preview.global_lockdown");
  const summary = record$1(root.summary, "semantic_preview.summary");
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
  const root = record$1(value, "mutation preview");
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
  const root = record$1(value, "mutation apply");
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
function permissionSuffix(permissionId) {
  const marker = ".permission.";
  const index = permissionId.indexOf(marker);
  return index < 0 ? null : permissionId.slice(index + marker.length);
}
function latestPermissionId(original, oldExtension, latestExtension) {
  if (latestExtension.permissions.some((permission2) => permission2.permission_id === original)) return original;
  if (latestExtension.extension_id !== oldExtension.extension_id && latestExtension.aliases.includes(oldExtension.extension_id)) {
    const suffix = permissionSuffix(original);
    if (!suffix) return null;
    const candidate = `${latestExtension.extension_id}.permission.${suffix}`;
    if (latestExtension.permissions.some((permission2) => permission2.permission_id === candidate)) return candidate;
  }
  return null;
}
function rebaseExtensionPolicyDraft(oldEffective, latestEffective, oldExtension, latestExtension, draftLayers) {
  let rebased = latestEffective.layers.map((layer) => ({ ...layer, controls: layer.controls.map((control) => ({ ...control })) }));
  const conflicts = [];
  const remapped = {};
  for (const permission2 of oldExtension.permissions) {
    const baseState = localPermissionDraftState(oldEffective.layers, permission2.permission_id);
    const requestedState = localPermissionDraftState(draftLayers, permission2.permission_id);
    if (baseState === requestedState) continue;
    const mapped = latestPermissionId(permission2.permission_id, oldExtension, latestExtension);
    if (!mapped) {
      conflicts.push({
        original_permission_id: permission2.permission_id,
        latest_permission_id: null,
        kind: "removed",
        base_state: baseState,
        latest_state: "inherit",
        requested_state: requestedState
      });
      continue;
    }
    remapped[permission2.permission_id] = mapped;
    const latestState = localPermissionDraftState(latestEffective.layers, mapped);
    if (latestState !== baseState && latestState !== requestedState) {
      conflicts.push({
        original_permission_id: permission2.permission_id,
        latest_permission_id: mapped,
        kind: "overlap",
        base_state: baseState,
        latest_state: latestState,
        requested_state: requestedState
      });
      continue;
    }
    rebased = setLocalPermissionDraftState(rebased, latestEffective.catalog_digest, mapped, requestedState);
  }
  return { draft_layers: rebased, conflicts, remapped_permission_ids: remapped };
}
function keepExtensionPolicyRebaseConflicts(result, latestEffective) {
  let layers = result.draft_layers;
  for (const conflict of result.conflicts) {
    if (conflict.kind !== "overlap" || !conflict.latest_permission_id) continue;
    layers = setLocalPermissionDraftState(
      layers,
      latestEffective.catalog_digest,
      conflict.latest_permission_id,
      conflict.requested_state
    );
  }
  return layers;
}
function cloneLayers(effective) {
  return effective.layers.map((layer) => ({ ...layer, controls: layer.controls.map((control) => ({ ...control })) }));
}
function useExtensionPolicyDraft(props) {
  const [baseEffective, setBaseEffective] = reactExports.useState(props.effective);
  const [draftLayers, setDraftLayers] = reactExports.useState(() => cloneLayers(props.effective));
  const [identity, setIdentity] = reactExports.useState(() => newExtensionPolicyDraftIdentity());
  const [preview, setPreview] = reactExports.useState(null);
  const [previewBusy, setPreviewBusy] = reactExports.useState(false);
  const [applyBusy, setApplyBusy] = reactExports.useState(false);
  const [approvalOpen, setApprovalOpen] = reactExports.useState(false);
  const [reviewOpen, setReviewOpen] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [stale, setStale] = reactExports.useState(false);
  const [pendingRebase, setPendingRebase] = reactExports.useState(null);
  const [refreshRequired, setRefreshRequired] = reactExports.useState(false);
  const [lastApplied, setLastApplied] = reactExports.useState(null);
  const draftGeneration = reactExports.useRef(0);
  const { onRefresh } = props;
  const dirty = reactExports.useMemo(() => extensionPolicyDraftIsDirty(baseEffective, draftLayers), [baseEffective, draftLayers]);
  reactExports.useEffect(() => {
    draftGeneration.current += 1;
    setBaseEffective(props.effective);
    setDraftLayers(cloneLayers(props.effective));
    setIdentity(newExtensionPolicyDraftIdentity());
    setRefreshRequired(false);
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
  }, [props.effective.revision, props.effective.catalog_digest]);
  const changeCountFor = reactExports.useCallback((permissionIds) => {
    return permissionIds.filter(
      (permissionId) => localPermissionDraftState(baseEffective.layers, permissionId) !== localPermissionDraftState(draftLayers, permissionId)
    ).length;
  }, [baseEffective, draftLayers]);
  const changedPermissionCount = reactExports.useMemo(
    () => changeCountFor([...new Set(
      baseEffective.layers.concat(draftLayers).flatMap((layer) => layer.controls).map((control) => control.target_kind === "permission" ? control.target_id : null).filter((id2) => Boolean(id2))
    )]),
    [baseEffective.layers, changeCountFor, draftLayers]
  );
  const resetDraft = reactExports.useCallback(() => {
    draftGeneration.current += 1;
    setDraftLayers(cloneLayers(baseEffective));
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
  }, [baseEffective]);
  const setPermissionState = reactExports.useCallback((permissionId, state) => {
    draftGeneration.current += 1;
    setDraftLayers((current) => setLocalPermissionDraftState(current, baseEffective.catalog_digest, permissionId, state));
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
    setLastApplied(null);
  }, [baseEffective.catalog_digest]);
  const setPermissionStates = reactExports.useCallback((permissionIds, state) => {
    if (!permissionIds.length) return;
    draftGeneration.current += 1;
    setDraftLayers((current) => setLocalPermissionDraftStates(
      current,
      baseEffective.catalog_digest,
      permissionIds,
      state
    ));
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
    setLastApplied(null);
  }, [baseEffective.catalog_digest]);
  const mutation = reactExports.useCallback(
    () => buildExtensionPolicyDraftMutation(baseEffective, baseEffective.catalog_digest, draftLayers, identity),
    [baseEffective, draftLayers, identity]
  );
  const handleApiError = reactExports.useCallback((caught, fallback) => {
    if (caught instanceof ExtensionControlApiError && ["revision_conflict", "catalog_conflict", "authority_conflict"].includes(caught.code ?? "")) {
      setStale(true);
      setError("The authoritative extension policy changed while this draft was open. Rebase the draft before applying; Guard will not silently overwrite security policy.");
      return;
    }
    setError(caught instanceof Error ? caught.message : fallback);
  }, []);
  const runPreview = reactExports.useCallback(async () => {
    if (!dirty) return;
    const generation = draftGeneration.current;
    setPreviewBusy(true);
    setError(null);
    setStale(false);
    try {
      const next = await previewExtensionMutation(mutation());
      if (!isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) return;
      setPreview(next);
      setReviewOpen(true);
    } catch (caught) {
      if (isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) handleApiError(caught, "Guard could not preview this draft.");
    } finally {
      setPreviewBusy(false);
    }
  }, [dirty, handleApiError, mutation]);
  const apply = reactExports.useCallback(async (credentials) => {
    if (!preview || !dirty || stale) return;
    setApplyBusy(true);
    setError(null);
    try {
      const base = mutation();
      const appliedLayersBefore = cloneLayers(baseEffective);
      const proofPreview = await previewExtensionMutation({ ...base, ...credentials, session_nonce: crypto.randomUUID().replaceAll("-", "") });
      if (!proofPreview.proof_id) throw new Error("Guard did not issue an approval proof for this exact draft.");
      if (proofPreview.canonical_diff_digest !== preview.canonical_diff_digest) throw new Error("The policy draft changed after preview. Preview it again before applying.");
      const applied = await applyExtensionMutation({ ...base, proof_id: proofPreview.proof_id });
      setApprovalOpen(false);
      setPreview(null);
      setReviewOpen(false);
      setError(null);
      setStale(false);
      if (applied.revision <= baseEffective.revision) throw new Error("Guard did not advance the committed extension-control revision.");
      const changedPermissionIds = baseEffective.layers.flatMap((layer) => layer.controls).concat(draftLayers.flatMap((layer) => layer.controls)).map((control) => control.target_kind === "permission" ? control.target_id : null).filter((id2) => Boolean(id2));
      const previouslyRequested = new Set(
        draftLayers.flatMap((layer) => layer.controls).map((control) => control.target_kind === "permission" ? control.target_id : null).filter((id2) => Boolean(id2))
      );
      setLastApplied({
        revision: applied.revision,
        previousLayers: appliedLayersBefore,
        changedPermissionIds: [...new Set(changedPermissionIds)].filter((id2) => previouslyRequested.has(id2) || localPermissionDraftState(baseEffective.layers, id2) !== localPermissionDraftState(draftLayers, id2))
      });
      draftGeneration.current += 1;
      setDraftLayers(cloneLayers(baseEffective));
      setIdentity(newExtensionPolicyDraftIdentity());
      setRefreshRequired(true);
      try {
        await onRefresh();
      } catch {
        setError("The policy was applied, but Guard could not refresh the latest state. Refresh this page to confirm the committed policy.");
      }
    } catch (caught) {
      handleApiError(caught, "Guard could not apply this draft.");
    } finally {
      setApplyBusy(false);
    }
  }, [baseEffective.revision, dirty, handleApiError, mutation, onRefresh, preview, stale]);
  const rebaseDraft = reactExports.useCallback(async (oldExtensions) => {
    const generation = draftGeneration.current;
    setPreviewBusy(true);
    setError(null);
    try {
      const [latestCatalog, latestEffective] = await Promise.all([fetchExtensionCatalog(), fetchEffectiveExtensionControls()]);
      const pairs = oldExtensions.map((oldExtension) => {
        const exact = latestCatalog.extensions.find((item) => item.extension_id === oldExtension.extension_id);
        if (exact) return { oldExtension, latestExtension: exact };
        const aliasMatches = latestCatalog.extensions.filter((item) => item.aliases.includes(oldExtension.extension_id));
        return aliasMatches.length === 1 ? { oldExtension, latestExtension: aliasMatches[0] } : null;
      }).filter((pair) => Boolean(pair));
      if (!pairs.length) {
        setError("These extensions no longer exist in the authoritative catalog. Discard the draft and refresh before continuing.");
        return;
      }
      if (!isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) {
        setError("The draft changed while Guard was loading current policy. Rebase again to preserve the latest edits.");
        return;
      }
      const chained = pairs.reduce((result2, { oldExtension, latestExtension }) => {
        const next = rebaseExtensionPolicyDraft(
          baseEffective,
          latestEffective,
          oldExtension,
          latestExtension,
          result2 ? result2.draft_layers : draftLayers
        );
        return {
          draft_layers: next.draft_layers,
          conflicts: [...result2?.conflicts ?? [], ...next.conflicts],
          remapped_permission_ids: { ...result2?.remapped_permission_ids ?? {}, ...next.remapped_permission_ids }
        };
      }, null);
      if (!chained) {
        setError("Guard could not rebase this draft against the current catalog.");
        return;
      }
      const result = chained;
      setBaseEffective(latestEffective);
      setIdentity(newExtensionPolicyDraftIdentity());
      setPreview(null);
      setReviewOpen(false);
      if (result.conflicts.length) {
        setPendingRebase({ result, latestEffective, latestExtensions: pairs.map((pair) => pair.latestExtension) });
        setDraftLayers(result.draft_layers);
        setStale(true);
        setError("The latest policy overlaps this draft. Choose whether to keep your overlapping changes or use current authoritative values. Removed permissions cannot be restored.");
      } else {
        setDraftLayers(result.draft_layers);
        setPendingRebase(null);
        setStale(false);
        setError(null);
      }
    } catch (caught) {
      if (isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) handleApiError(caught, "Guard could not rebase this draft.");
    } finally {
      setPreviewBusy(false);
    }
  }, [baseEffective, draftLayers]);
  const keepConflicts = reactExports.useCallback(() => {
    if (!pendingRebase) return;
    setDraftLayers(keepExtensionPolicyRebaseConflicts(pendingRebase.result, pendingRebase.latestEffective));
    setPendingRebase(null);
    setStale(false);
    setError(null);
    setIdentity(newExtensionPolicyDraftIdentity());
  }, [pendingRebase]);
  const useCurrent = reactExports.useCallback(() => {
    if (!pendingRebase) return;
    setDraftLayers(cloneLayers(pendingRebase.latestEffective));
    setPendingRebase(null);
    setStale(false);
    setError(null);
    setPreview(null);
    setIdentity(newExtensionPolicyDraftIdentity());
  }, [pendingRebase]);
  const applyProfile = reactExports.useCallback((permissions, profile) => {
    if (profile === "custom") return;
    draftGeneration.current += 1;
    let next = cloneLayers(baseEffective);
    for (const permission2 of permissions) {
      if (!permission2.configurable) continue;
      const state = profile === "recommended" ? "inherit" : "block";
      next = setLocalPermissionDraftState(next, baseEffective.catalog_digest, permission2.permission_id, state);
    }
    setDraftLayers(next);
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
    setLastApplied(null);
  }, [baseEffective]);
  const useHistoricalDraft = reactExports.useCallback((historicalLayers) => {
    draftGeneration.current += 1;
    const historicalLocal = historicalLayers.find((layer) => layer.kind === "local-admin");
    const next = baseEffective.layers.flatMap((layer) => layer.kind === "local-admin" ? historicalLocal ? [historicalLocal] : [] : [layer]);
    if (historicalLocal && !baseEffective.layers.some((layer) => layer.kind === "local-admin")) next.push(historicalLocal);
    setDraftLayers(next);
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
  }, [baseEffective.layers]);
  const undoLastApplied = reactExports.useCallback(() => {
    if (!lastApplied) return false;
    draftGeneration.current += 1;
    setDraftLayers(cloneLayers({ ...baseEffective, layers: lastApplied.previousLayers }));
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
    setLastApplied(null);
    return true;
  }, [baseEffective, lastApplied]);
  return {
    baseEffective,
    draftLayers,
    dirty,
    preview,
    previewBusy,
    applyBusy,
    reviewOpen,
    approvalOpen,
    error,
    stale,
    pendingRebase,
    refreshRequired,
    lastApplied,
    undoLastApplied,
    changedPermissionCount,
    setReviewOpen,
    setApprovalOpen,
    permissionState: reactExports.useCallback((permissionId) => localPermissionDraftState(draftLayers, permissionId), [draftLayers]),
    changeCountFor,
    setPermissionState,
    setPermissionStates,
    resetDraft,
    runPreview,
    apply,
    rebaseDraft,
    keepConflicts,
    useCurrent,
    applyProfile,
    useHistoricalDraft
  };
}
function ProtectionSettingsHistory(props) {
  const [items, setItems] = reactExports.useState([]);
  const [loading, setLoading] = reactExports.useState(true);
  const [error, setError] = reactExports.useState(null);
  reactExports.useEffect(() => {
    let active = true;
    setLoading(true);
    fetchExtensionControlHistory().then((history) => {
      if (!active) return;
      setItems(history.items.filter((item) => item.catalog_digest === props.catalogDigest));
      setError(null);
    }).catch(() => {
      if (active) setError("Local settings history is unavailable until Guard verifies settings integrity.");
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => {
      active = false;
    };
  }, [props.catalogDigest]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer text-sm font-semibold text-brand-dark", children: "Settings history" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs leading-5 text-brand-dark/80", children: "Guard verifies the authenticated local history before showing it. Restoring a version only prepares the device layer as a draft. Current organization policy stays in force, and nothing changes until you review and approve it." }),
    loading ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs text-brand-dark/70", children: "Loading verified history…" }) : error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs text-amber-950", children: error }) : items.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 space-y-2", children: items.slice(0, 10).map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-2 py-2 sm:flex-row sm:items-center sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-sm font-medium text-brand-dark", children: [
          "Device settings revision ",
          item.revision
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("time", { className: "text-xs text-brand-dark/70", dateTime: item.occurred_at, children: new Date(item.occurred_at).toLocaleString() })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.disabled, onClick: () => props.onUse(item.layers, item.revision), className: "min-h-10 px-1 text-xs font-semibold text-brand-blue disabled:opacity-40", children: "Use this version as draft" })
    ] }, item.revision)) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs text-brand-dark/70", children: "No earlier authenticated device settings are available yet." })
  ] });
}
function managedControlsHref(input) {
  if (!input.cloudControlsUrl) {
    return null;
  }
  let target2;
  try {
    target2 = new URL("/guard/controls", input.cloudControlsUrl);
  } catch {
    return null;
  }
  if (input.extensionId) {
    target2.searchParams.set("extensionId", input.extensionId);
  }
  if (input.permissionId) {
    target2.searchParams.set("permissionId", input.permissionId);
  }
  return target2.toString();
}
function buildLocalProtectionView(input) {
  const sources = input.sources?.length ? input.sources : [input.source];
  const technicalDetails = [
    ...sources.length > 1 ? [{ label: "Contributors", value: sources.join(" · ") }] : [],
    ...input.catalogDigest ? [{ label: "Catalog digest", value: input.catalogDigest }] : [],
    ...input.acknowledgementRevision !== void 0 ? [{ label: "Acknowledgement revision", value: String(input.acknowledgementRevision) }] : [],
    ...input.controlSetName ? [{ label: "Control Set", value: input.controlSetName }] : [],
    ...input.controlSetVersion !== void 0 ? [{ label: "Control Set version", value: String(input.controlSetVersion) }] : [],
    ...input.workspace ? [{ label: "Workspace", value: input.workspace }] : [],
    ...input.authorityMode ? [{ label: "Authority mode", value: input.authorityMode }] : [],
    ...input.acknowledgementStatus ? [{ label: "Acknowledgement", value: input.acknowledgementStatus }] : [],
    ...input.lastAcknowledgedAt ? [{ label: "Last acknowledged", value: input.lastAcknowledgedAt }] : [],
    ...input.effectiveProjectionDigest ? [{ label: "Effective projection digest", value: input.effectiveProjectionDigest }] : []
  ];
  if (input.recovery === "unsupported-version") {
    return {
      title: input.extensionName,
      summary: "Update Guard before this managed setting can be applied.",
      source: input.source,
      sources,
      effectiveState: input.effectiveState,
      status: "unsupported",
      primaryAction: { label: "Check for updates", action: "refresh" },
      technicalDetails
    };
  }
  if (input.recovery) {
    let recoverySummary = "Guard is using the last verified setting while it checks for an update.";
    if (input.recovery === "catalog-mismatch") {
      recoverySummary = "Guard is using the last verified setting because this Control Set and the local Extension catalog do not match.";
    } else if (input.recovery === "degraded") {
      recoverySummary = "Guard is preserving the last verified authority while local control recovery is required.";
    }
    return {
      title: input.extensionName,
      summary: recoverySummary,
      source: input.source,
      sources,
      effectiveState: input.effectiveState,
      status: "needs-attention",
      primaryAction: { label: "Check again", action: "refresh" },
      technicalDetails
    };
  }
  let status = "protected";
  if (input.effectiveState === "lockdown") {
    status = "lockdown";
  } else if (input.source === "Organization Control Set" || input.source.startsWith("Managed by ")) {
    status = "managed";
  }
  let summary = "Guard checks matching actions before they run.";
  if (input.effectiveState === "blocked") {
    summary = "Matching actions are blocked.";
  } else if (input.effectiveState === "partial") {
    summary = "Some matching actions are blocked while the remaining actions stay available.";
  } else if (input.effectiveState === "required") {
    summary = "This protection stays on.";
  } else if (input.effectiveState === "lockdown") {
    summary = "Emergency Lockdown blocks governed actions.";
  }
  const controlsHref = managedControlsHref(input);
  const hasManagedContributor = sources.some(
    (source) => source === "Organization Control Set" || source === "Synced from Guard Cloud" || source.startsWith("Managed by ")
  );
  const primaryAction = controlsHref ? {
    label: hasManagedContributor ? "Manage in Guard Cloud" : "Apply across my devices",
    href: controlsHref
  } : { label: "Connect Guard Cloud", action: "connect-cloud" };
  return {
    title: input.extensionName,
    summary,
    source: input.source,
    sources,
    effectiveState: input.effectiveState,
    status,
    primaryAction,
    technicalDetails
  };
}
function AppliedPolicyToast(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "status", "data-testid": "extension-policy-applied-toast", className: "mt-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm font-medium text-emerald-950", children: [
      "Applied · revision ",
      props.revision
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
      props.applyAcrossHref ? /* @__PURE__ */ jsxRuntimeExports.jsx("a", { href: props.applyAcrossHref, target: "_blank", rel: "noopener noreferrer", className: "inline-flex min-h-11 items-center rounded-xl border border-emerald-300 bg-white/70 px-3 text-sm font-semibold text-emerald-950", children: "Apply across my devices" }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: props.onViewHistory, className: "min-h-11 rounded-xl border border-emerald-300 bg-white/70 px-3 text-sm font-semibold text-emerald-950", children: "View history" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: props.onUndo, className: "min-h-11 rounded-xl bg-emerald-800 px-3 text-sm font-semibold text-white", children: "Undo" })
    ] })
  ] });
}
function appliedPolicyCloudHref(input) {
  return managedControlsHref({
    extensionName: input.extensionName,
    extensionId: input.extensionId,
    permissionId: input.changedPermissionIds.length === 1 ? input.changedPermissionIds[0] : void 0,
    effectiveState: "allowed",
    source: "Set on this device",
    cloudControlsUrl: input.cloudControlsUrl
  });
}
const RISK_TONE = {
  critical: "border-red-200 bg-red-50 text-red-950",
  high: "border-orange-200 bg-orange-50 text-orange-950",
  medium: "border-amber-200 bg-amber-50 text-amber-950",
  low: "border-[rgba(63,65,116,0.16)] text-brand-dark"
};
function Pill(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${props.tone ?? "border-[rgba(63,65,116,0.16)] text-brand-dark"}`, children: props.children });
}
function managedPermissionState(effective, permissionId) {
  const projected = effective.projection?.permissions.find((item) => item.permission_id === permissionId)?.managed_state;
  if (projected && projected !== "inherited") return projected;
  for (const layer of effective.layers) {
    if (layer.kind !== "signed-cloud") continue;
    const control = layer.controls.find((item) => item.target_kind === "permission" && item.target_id === permissionId);
    if (control) return control.state;
  }
  return null;
}
function extensionPolicyRadioTabStop(choices, state, groupDisabled) {
  if (groupDisabled) return -1;
  const selected = choices.findIndex((choice) => choice.value === state && !choice.disabled);
  return selected >= 0 ? selected : choices.findIndex((choice) => !choice.disabled);
}
function nextExtensionPolicyRadioIndex(choices, index, key, groupDisabled) {
  if (groupDisabled || !["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(key)) return -1;
  const direction = key === "ArrowLeft" || key === "ArrowUp" ? -1 : 1;
  for (let offset = 1; offset <= choices.length; offset += 1) {
    const next = (index + direction * offset + choices.length) % choices.length;
    if (!choices[next]?.disabled) return next;
  }
  return -1;
}
function DraftControl(props) {
  const managed = managedPermissionState(props.effective, props.permission.permission_id);
  const choices = [
    { value: "inherit", label: "Recommended" },
    { value: "allow", label: "Allow", disabled: managed === "disabled" },
    { value: "block", label: "Block" }
  ];
  const tabStopIndex = extensionPolicyRadioTabStop(choices, props.state, props.disabled);
  const chooseAdjacent = (event, index) => {
    const next = nextExtensionPolicyRadioIndex(choices, index, event.key, props.disabled);
    if (next < 0) return;
    event.preventDefault();
    props.onChange(choices[next].value);
    event.currentTarget.parentElement?.querySelectorAll('[role="radio"]')[next]?.focus();
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "radiogroup", "aria-label": `${props.permission.label} protection setting`, className: "guard-segmented", children: choices.map((choice, index) => /* @__PURE__ */ jsxRuntimeExports.jsx(
    "button",
    {
      type: "button",
      role: "radio",
      "aria-checked": props.state === choice.value,
      tabIndex: !props.disabled && index === tabStopIndex ? 0 : -1,
      disabled: props.disabled || choice.disabled,
      title: choice.disabled ? "Your organization already blocks this capability; this device cannot weaken it." : void 0,
      onKeyDown: (event) => chooseAdjacent(event, index),
      onClick: () => props.onChange(choice.value),
      className: "disabled:cursor-not-allowed disabled:opacity-45",
      children: choice.label
    },
    choice.value
  )) });
}
function PermissionPolicyRow(props) {
  const managed = managedPermissionState(props.effective, props.permission.permission_id);
  const provenance = controlProvenance(props.effective, "permission", props.permission.permission_id);
  const example = props.permission.example_command ?? (props.extension.executables[0]?.trim() || props.permission.label);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { id: `pattern-${props.permission.permission_id}`, className: "guard-pattern-row", "data-permission-id": props.permission.permission_id, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-brand-dark", children: props.permission.label }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "guard-pattern-example mt-1", children: example }),
      !props.permission.configurable ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-xs leading-5 text-brand-dark", children: [
        "Why this cannot be changed: ",
        props.permission.fixed_reason ?? "Guard marks this safety permission as immutable."
      ] }) : null,
      managed === "disabled" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 flex items-start gap-2 text-xs leading-5 text-indigo-950", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "mt-0.5 size-4 shrink-0" }),
        "Your organization blocks this capability. You can keep the organization setting or add a local block, but this device cannot weaken it."
      ] }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-2 text-xs text-brand-dark", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer font-semibold", children: "Technical setting details" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex flex-wrap gap-x-4 gap-y-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
            "Minimum protection: ",
            /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: treatmentLabel(props.permission.baseline_floor) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
            props.permission.rule_ids.length,
            " governed rule",
            props.permission.rule_ids.length === 1 ? "" : "s"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
            "Managed by: ",
            provenance.join(" · ")
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-2 block break-all text-[11px] text-brand-dark/80", children: props.permission.permission_id })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      DraftControl,
      {
        permission: props.permission,
        effective: props.effective,
        state: props.draftState,
        disabled: props.disabled || !props.permission.configurable || props.effective.health !== "protected",
        onChange: props.onChange
      }
    )
  ] });
}
function PreviewPanel(props) {
  const semantic = props.preview.semantic_preview;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Protection review" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "mt-1 text-lg font-semibold text-brand-dark", children: "What will change" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
          semantic.changed_target_count,
          " target",
          semantic.changed_target_count === 1 ? "" : "s"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
          semantic.affected_permission_count,
          " permissions"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
          semantic.affected_rule_count,
          " rules"
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-4 grid gap-3 sm:grid-cols-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/80", children: "Newly blocked settings" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-2xl font-semibold text-brand-dark", children: semantic.summary.newly_blocked_permissions })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/80", children: "Newly allowed settings" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-2xl font-semibold text-brand-dark", children: semantic.summary.newly_allowed_permissions })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/80", children: "Settings changing" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-2xl font-semibold text-brand-dark", children: semantic.summary.effective_change_count })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 space-y-3", children: semantic.changed_targets.map((target2) => /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "border-b border-[rgba(63,65,116,0.12)] py-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-sm text-brand-dark", children: target2.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
          target2.before_explicit,
          " → ",
          target2.after_explicit
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { children: [
          target2.before_effective,
          " → ",
          target2.after_effective
        ] }),
        target2.baseline_risk ? /* @__PURE__ */ jsxRuntimeExports.jsxs(Pill, { tone: RISK_TONE[target2.baseline_risk], children: [
          target2.baseline_risk,
          " baseline"
        ] }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 text-xs text-brand-dark/80", children: [
        "Affects ",
        target2.affected_permission_ids.length,
        " permission",
        target2.affected_permission_ids.length === 1 ? "" : "s",
        " and ",
        target2.affected_rule_ids.length,
        " rule",
        target2.affected_rule_ids.length === 1 ? "" : "s",
        "."
      ] }),
      target2.affected_rule_ids.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer text-xs font-semibold text-brand-blue", children: "Developer details" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 max-h-40 overflow-auto", children: target2.affected_rule_ids.map((id2) => /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "block break-all text-[11px] text-brand-dark/80", children: id2 }, id2)) })
      ] }) : null,
      target2.warnings.map((warning2, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-3 flex items-start gap-2 text-xs leading-5 text-amber-950", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-4 shrink-0" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("strong", { children: [
            warning2.code,
            ":"
          ] }),
          " ",
          warning2.message
        ] })
      ] }, `${warning2.code}-${index}`))
    ] }, `${target2.target.kind}:${target2.target.target_id}`)) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer text-xs font-semibold text-brand-dark/80", children: "Developer change identity" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-2 block break-all text-[11px] text-brand-dark/80", children: props.preview.canonical_diff_digest })
    ] })
  ] });
}
function PolicyReviewSheet(props) {
  const ref = useModalDialog(props.onClose, !props.busy);
  const [password, setPassword] = reactExports.useState("");
  const [totpCode, setTotpCode] = reactExports.useState("");
  const count = props.preview.semantic_preview.changed_target_count;
  const submitDisabled = isApprovalProofSubmitDisabled(props.approvalGate, { approvalPassword: password, approvalTotpCode: totpCode }, props.busy);
  const handleSubmit = (event) => {
    event.preventDefault();
    if (submitDisabled) return;
    props.onApply(buildApprovalProofCredentials(props.approvalGate, { approvalPassword: password, approvalTotpCode: totpCode }));
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "fixed inset-0 z-50 bg-brand-dark/40", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "form",
    {
      ref,
      tabIndex: -1,
      role: "dialog",
      "aria-modal": "true",
      "aria-labelledby": "extension-policy-review-title",
      onSubmit: handleSubmit,
      className: "absolute inset-y-0 right-0 flex w-full max-w-2xl flex-col overflow-y-auto bg-[var(--surface-1)] p-5 focus:outline-none sm:p-6",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Protection review" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("h2", { id: "extension-policy-review-title", className: "mt-1 text-xl font-semibold text-brand-dark", children: [
              "Review and apply ",
              count,
              " protection setting change",
              count === 1 ? "" : "s"
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.busy, "aria-label": "Close protection review", onClick: props.onClose, className: "grid size-11 place-items-center rounded-full text-brand-dark disabled:opacity-50", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-5" }) })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5 flex-1", children: /* @__PURE__ */ jsxRuntimeExports.jsx(PreviewPanel, { preview: props.preview }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 border-t border-[rgba(63,65,116,0.12)] pt-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Authenticate this exact change" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-5 text-brand-dark/75", children: "Guard uses a one-time local proof and rejects the apply if the reviewed settings changed." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
            ApprovalProofFieldInputs,
            {
              approvalGate: props.approvalGate,
              approvalPassword: password,
              approvalTotpCode: totpCode,
              onApprovalPasswordChange: (event) => setPassword(event.target.value),
              onApprovalTotpCodeChange: (event) => setTotpCode(event.target.value)
            }
          ) }),
          props.error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-3 text-sm text-red-950", children: props.error }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "sticky bottom-0 mt-4 flex flex-wrap justify-end gap-2 bg-[var(--surface-1)] pb-1 pt-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.busy, onClick: props.onClose, className: "min-h-11 rounded-xl border border-[rgba(63,65,116,0.2)] px-4 text-sm font-semibold text-brand-dark", children: "Continue editing" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "submit", disabled: submitDisabled, className: "min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-[#f4f7fb] disabled:opacity-40", children: props.busy ? "Applying…" : `Apply ${count} reviewed change${count === 1 ? "" : "s"}` })
          ] })
        ] })
      ]
    }
  ) });
}
function ExtensionPolicyPanel(props) {
  const [policyExtension, setPolicyExtension] = reactExports.useState(props.extension);
  const draft = useExtensionPolicyDraft({ effective: props.effective, onRefresh: props.onRefresh });
  const {
    baseEffective,
    dirty,
    preview,
    previewBusy,
    applyBusy,
    reviewOpen,
    error,
    stale,
    pendingRebase,
    refreshRequired,
    lastApplied,
    undoLastApplied,
    setReviewOpen,
    setPermissionState,
    resetDraft,
    runPreview,
    apply,
    rebaseDraft,
    keepConflicts,
    useCurrent,
    applyProfile,
    useHistoricalDraft,
    permissionState
  } = draft;
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  reactExports.useEffect(() => {
    props.onDirtyChange?.(dirty);
  }, [dirty, props.onDirtyChange]);
  reactExports.useEffect(() => {
    const beforeUnload = (event) => {
      if (!dirty) return;
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", beforeUnload);
    return () => window.removeEventListener("beforeunload", beforeUnload);
  }, [dirty]);
  reactExports.useEffect(() => {
    setPolicyExtension(props.extension);
    resetDraft();
  }, [props.extension.extension_id]);
  reactExports.useEffect(() => {
    if (!reviewOpen) return;
    void resolveApprovalGate({ failClosed: true }).catch(() => {
    });
  }, [reviewOpen, resolveApprovalGate]);
  const managedCount = policyExtension.permissions.filter((permission2) => managedPermissionState(baseEffective, permission2.permission_id) !== null).length;
  const changeCount = draft.changeCountFor(policyExtension.permissions.map((permission2) => permission2.permission_id));
  const applyAcrossHref = appliedPolicyCloudHref({
    extensionName: policyExtension.name,
    extensionId: policyExtension.extension_id,
    changedPermissionIds: lastApplied?.changedPermissionIds ?? [],
    cloudControlsUrl: props.cloudControlsUrl
  });
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { id: "extension-policy-editor", "aria-labelledby": "extension-policy-heading", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "extension-policy-heading", className: "text-lg font-semibold text-brand-dark", children: "Protection settings" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-sm leading-6 text-brand-dark/80", children: "Recommended follows Guard defaults. Allow is available only where built-in safety and organization policy still permit it. Block is a stricter local floor." }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-wrap items-center gap-x-3 gap-y-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold text-brand-dark/60", children: "Apply to every pattern you can change:" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: baseEffective.health !== "protected" || refreshRequired, onClick: () => applyProfile(policyExtension.permissions, "recommended"), className: "min-h-10 px-1 text-xs font-semibold text-brand-blue disabled:opacity-40", children: "Reset to Recommended" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: baseEffective.health !== "protected" || refreshRequired, onClick: () => applyProfile(policyExtension.permissions, "stricter"), className: "min-h-10 px-1 text-xs font-semibold text-brand-dark disabled:opacity-40", children: "Block all changeable variants" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { id: "extension-settings-history", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ProtectionSettingsHistory, { catalogDigest: baseEffective.catalog_digest, disabled: baseEffective.health !== "protected" || refreshRequired, onUse: (layers) => useHistoricalDraft(layers) }) }),
    baseEffective.global_lockdown ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { role: "status", className: "mt-4 flex gap-2 text-sm text-brand-dark", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "mt-0.5 size-4 shrink-0" }),
      "Emergency Lockdown remains dominant. You can prepare a local draft, but matching commands stay blocked while lockdown is active."
    ] }) : null,
    baseEffective.health !== "protected" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { role: "alert", className: "mt-4 flex gap-2 text-sm text-amber-950", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-4 shrink-0" }),
      "Settings cannot be changed until Guard verifies local settings integrity."
    ] }) : null,
    managedCount ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-4 text-sm text-indigo-950", children: [
      managedCount,
      " setting",
      managedCount === 1 ? " is" : "s are",
      " managed by your organization. This device can add stricter blocks but cannot weaken an organization block."
    ] }) : null,
    lastApplied ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      AppliedPolicyToast,
      {
        revision: lastApplied.revision,
        applyAcrossHref,
        onUndo: () => {
          undoLastApplied();
        },
        onViewHistory: () => {
          document.getElementById("extension-settings-history")?.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      }
    ) : refreshRequired ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "status", className: "mt-4 text-sm text-blue-950", children: "Settings applied. Editing stays locked until Guard reloads the current protected state." }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: (() => {
      const { ungrouped, families } = groupPermissionsByFamily(policyExtension.permissions);
      const renderRow = (permission2) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        PermissionPolicyRow,
        {
          permission: permission2,
          extension: policyExtension,
          effective: baseEffective,
          draftState: permissionState(permission2.permission_id),
          disabled: refreshRequired,
          onChange: (state) => setPermissionState(permission2.permission_id, state)
        },
        permission2.permission_id
      );
      return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        ungrouped.map(renderRow),
        families.map((group) => /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": `${group.heading} variants`, className: "guard-pattern-family", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("h3", { className: "guard-pattern-family-heading", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("code", { children: group.heading }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
              group.permissions.length,
              " variant",
              group.permissions.length === 1 ? "" : "s"
            ] })
          ] }),
          group.permissions.map(renderRow)
        ] }, group.family))
      ] });
    })() }),
    dirty ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-review-bar", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-sm text-brand-dark", children: [
        changeCount,
        " unsaved setting change",
        changeCount === 1 ? "" : "s",
        "."
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: previewBusy || applyBusy, onClick: resetDraft, className: "min-h-11 rounded-xl border border-[rgba(63,65,116,0.2)] px-4 text-sm font-semibold text-brand-dark", children: "Reset changes" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", disabled: previewBusy || applyBusy || baseEffective.health !== "protected" || stale, onClick: () => {
          void runPreview();
        }, className: "inline-flex min-h-11 items-center gap-2 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-[#f4f7fb] disabled:opacity-40", children: [
          previewBusy ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-4 animate-spin motion-reduce:animate-none" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-4" }),
          "Review ",
          changeCount,
          " change",
          changeCount === 1 ? "" : "s"
        ] })
      ] })
    ] }) }) : null,
    error ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "alert", className: "mt-4 text-sm text-red-950", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-5 shrink-0" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: error })
      ] }),
      stale && !pendingRebase ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: previewBusy, onClick: () => {
        void rebaseDraft([policyExtension]);
      }, className: "mt-3 min-h-11 rounded-xl bg-red-800 px-4 text-sm font-semibold text-[#f4f7fb]", children: "Update draft with latest protection" }) : null,
      pendingRebase ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "space-y-2", children: pendingRebase.result.conflicts.map((conflict) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "text-xs text-brand-dark", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "break-all", children: conflict.original_permission_id }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-1", children: conflict.kind === "removed" ? "Target removed from the current catalog." : `Current ${conflict.latest_state}; your draft requests ${conflict.requested_state}.` })
        ] }, conflict.original_permission_id)) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex flex-wrap gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: keepConflicts, className: "min-h-11 rounded-xl bg-red-800 px-4 text-sm font-semibold text-[#f4f7fb]", children: "Keep my compatible changes" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: useCurrent, className: "min-h-11 rounded-xl border border-red-300 px-4 text-sm font-semibold text-red-950", children: "Use current protection" })
        ] })
      ] }) : null
    ] }) : dirty && !preview ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex items-start gap-3 text-sm text-brand-dark", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniInformationCircle, { className: "mt-0.5 size-5 shrink-0" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Review is required before approval. Guard calculates the real outcome from current protections, dependencies, organization settings, and Emergency Lockdown before anything can change." })
    ] }) : null,
    reviewOpen && preview ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyReviewSheet,
      {
        preview,
        approvalGate: resolvedApprovalGate,
        busy: applyBusy,
        error,
        onClose: () => {
          if (!applyBusy) setReviewOpen(false);
        },
        onApply: (credentials) => {
          void apply(credentials);
        }
      }
    ) : null
  ] });
}
function enrollableCount(item) {
  return Math.max(enrollablePackageScriptCommands(item.commands).length, 0);
}
function addDialogSubmitLabel(input) {
  if (input.recognized === null) {
    return input.busy ? "Looking…" : "Find this tool";
  }
  if (input.step !== "confirm") {
    return "Continue";
  }
  if (input.busy) {
    return "Saving…";
  }
  if (input.pending === "blocked") {
    return blockActionLabel(input.recognized.surface);
  }
  return allowActionLabel(input.recognized.surface);
}
function enrollConfirmCopy(surface, recentlySatisfied, totpEnabled) {
  if (recentlySatisfied) {
    return "Recently confirmed with your authenticator. Save these settings.";
  }
  if (!totpEnabled) {
    return "Enter your approval password to save these settings.";
  }
  if (surface === "mcp") {
    return "Enter the current authenticator code to save this server.";
  }
  if (surface === "package-scripts") {
    return "Enter the current authenticator code to save these scripts.";
  }
  return "Enter the current authenticator code to save this tool.";
}
function enrollSubmitDisabled(input) {
  if (input.recognized === null) return input.command.trim() === "" || input.busy;
  if (!input.confirming) return input.busy;
  return !input.proofReady || input.proofBlocked;
}
function commandFieldLabel(surface) {
  if (surface === "package-scripts") return "Find a script";
  if (surface === "mcp") return "Launch command";
  return "Command";
}
function allowActionLabel(surface) {
  if (surface === "mcp") return "Allow this server";
  if (surface === "package-scripts") return "Allow these scripts";
  return "Allow this tool";
}
function blockActionLabel(surface) {
  if (surface === "mcp") return "Block this server";
  if (surface === "package-scripts") return "Block these scripts";
  return "Block this tool";
}
function dialogIntro(hasProjects, surface) {
  if (surface === "package-scripts") {
    return "Allow these scripts so Protect can stop asking about them. Type a nested name such as guard:audit to inspect one.";
  }
  if (surface === "mcp") {
    return "Choose Recommended, Allow all, or Block all, then confirm this server.";
  }
  if (hasProjects) {
    return "Guard already found project scripts on this device. Pick a project, or paste another folder.";
  }
  return "Paste a script, binary, MCP launch, or package scripts such as npm run. Everyday commands such as rg, grep, and whoami are not custom extensions.";
}
function filterCountCopy(visible, total) {
  if (visible === 0) return "No scripts match that name. Try another nested name, or pick a different project.";
  if (visible === total) return `${visible} scripts in this project.`;
  return `${visible} of ${total} scripts match. Allow still enrolls the whole project.`;
}
function suggestionSummary(item) {
  if (item.surface === "package-scripts" && item.commands.length > 0) {
    const count = enrollableCount(item);
    const unit = count === 1 ? "script" : "scripts";
    return `${count} ${unit} from ${item.source_label ?? item.name}. Allow lets this project's scripts run. Nested names stay grouped.`;
  }
  if (item.surface === "package-scripts") {
    return `Find this tool to list npm scripts from ${item.name}.`;
  }
  if (item.surface === "mcp" && item.commands.length > 0) {
    return `${item.commands.length} tools from this server. Recommended keeps the usual review. Allow all lets them run.`;
  }
  if (item.surface === "mcp") {
    return `Find this tool to list MCP tools from ${item.name}.`;
  }
  if (item.commands.length > 0) {
    return `Guard loaded ${item.commands.length} commands. Recommended keeps the usual review. Allow or block each one.`;
  }
  return `Find this tool to read ${item.name} --help and load its commands.`;
}
function SuggestionPanel(props) {
  if (!props.hasSuggestions) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-5 text-sm leading-6 text-brand-dark/70", children: suggestionEmptyCopy(props.query) });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      SuggestionGroup,
      {
        heading: "From this device",
        helper: "Projects Guard has already seen, including nested names such as guard:audit.",
        items: props.packageScriptSuggestions,
        onSelect: props.onSelect
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      SuggestionGroup,
      {
        heading: "From your apps",
        helper: "MCP servers already configured in apps on this device.",
        items: props.harnessSuggestions,
        onSelect: props.onSelect
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      SuggestionGroup,
      {
        heading: "Seen on this device",
        helper: "Your own tools that agents have run. Common commands stay hidden.",
        items: props.seenSuggestions,
        onSelect: props.onSelect
      }
    )
  ] });
}
function ProjectSwitcher(props) {
  if (props.items.length < 2) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 flex flex-wrap gap-2", role: "group", "aria-label": "Remembered projects", children: props.items.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx(
    ProjectChip,
    {
      item,
      selected: item.cli_id === props.currentId,
      onSelect: props.onSelect
    },
    item.cli_id
  )) });
}
function suggestionEmptyCopy(query) {
  if (query.trim() !== "") {
    return "No matching tools. Try npm run, a project folder, or a nested script name. Everyday commands such as rg stay hidden.";
  }
  return "No extra tools yet. Paste npm run, a project folder, a script, or an MCP launch.";
}
function SuggestionGroup(props) {
  if (props.items.length === 0) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: props.heading }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-5 text-brand-dark/60", children: props.helper }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 divide-y divide-slate-200", children: props.items.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: /* @__PURE__ */ jsxRuntimeExports.jsx(SuggestionButton, { item, onSelect: props.onSelect }) }, item.cli_id)) })
  ] });
}
function ProjectChip(props) {
  const handleSelect = reactExports.useCallback(() => {
    props.onSelect(props.item);
  }, [props]);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "button",
    {
      type: "button",
      onClick: handleSelect,
      "aria-pressed": props.selected,
      className: `min-h-11 rounded-full px-3 text-xs font-semibold ${props.selected ? "bg-brand-blue text-white" : "border border-slate-300 text-brand-dark"}`,
      children: props.item.source_label ?? props.item.name
    }
  );
}
function SuggestionButton(props) {
  const handleSelect = reactExports.useCallback(() => {
    props.onSelect(props.item);
  }, [props]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: handleSelect, className: "flex min-h-11 w-full items-baseline justify-between gap-3 py-2 text-left", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "min-w-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block truncate text-sm font-semibold text-brand-dark", children: props.item.name }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block truncate text-xs text-brand-dark/60", children: props.item.source_label ?? seenSuggestionMeta(props.item) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "truncate font-mono text-xs text-brand-dark/60", children: props.item.example_label })
  ] });
}
function CatalogPreview(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5", children: [
    props.showFilterCount && props.query.trim() !== "" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-5 text-brand-dark/60", children: filterCountCopy(props.visibleCount, props.totalCount) }) : null,
    props.previewNames.length > 0 && !props.reviewing ? /* @__PURE__ */ jsxRuntimeExports.jsxs("ul", { className: "mt-3 flex flex-wrap gap-2", children: [
      props.previewNames.map((name) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { className: "rounded-full bg-slate-100 px-3 py-1.5 font-mono text-xs text-brand-dark", children: name }, name)),
      props.visibleCount > props.previewNames.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "rounded-full px-3 py-1.5 text-xs font-semibold text-brand-dark/60", children: [
        "+",
        props.visibleCount - props.previewNames.length,
        " more"
      ] }) : null
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        onClick: props.reviewing ? props.onCloseReview : props.onOpenReview,
        className: "mt-4 min-h-11 text-sm font-semibold text-brand-blue",
        children: props.reviewing ? props.hideLabel : props.adjustLabel
      }
    ),
    props.reviewing ? props.children : null
  ] });
}
function BulkPolicyPicker(props) {
  const choices = [
    { value: "inherit", label: "Recommended" },
    { value: "allow", label: "Allow all" },
    { value: "block", label: "Block all" }
  ];
  const mixed = props.value === "mixed";
  const selected = mixed ? "inherit" : props.value;
  const groupLabel = props.groupLabel ?? "All tools protection setting";
  const tabStopIndex = extensionPolicyRadioTabStop(choices, selected, props.disabled);
  const chooseAdjacent = (event, index) => {
    const next = nextExtensionPolicyRadioIndex(choices, index, event.key, props.disabled);
    if (next < 0) return;
    event.preventDefault();
    props.onChange(choices[next].value);
    event.currentTarget.parentElement?.querySelectorAll('[role="radio"]')[next]?.focus();
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4", "data-testid": "custom-extension-bulk-policy", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "div",
      {
        role: "radiogroup",
        "aria-label": mixed ? `${groupLabel}. Custom mix` : groupLabel,
        "aria-describedby": mixed ? "bulk-policy-mixed" : void 0,
        className: "guard-segmented w-fit",
        children: choices.map((choice, index) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          BulkPolicyChoice,
          {
            choice,
            checked: props.value === choice.value,
            tabIndex: !props.disabled && index === tabStopIndex ? 0 : -1,
            disabled: props.disabled,
            index,
            onChoose: props.onChange,
            onAdjacent: chooseAdjacent
          },
          choice.value
        ))
      }
    ),
    props.value === "mixed" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { id: "bulk-policy-mixed", className: "mt-2 text-xs leading-5 text-brand-dark/70", children: props.mixedCopy ?? "Custom mix. Pick Recommended, Allow all, or Block all to reset every tool." }) : null
  ] });
}
function BulkPolicyChoice(props) {
  const handleClick = reactExports.useCallback(() => {
    props.onChoose(props.choice.value);
  }, [props]);
  const handleKeyDown = reactExports.useCallback((event) => {
    props.onAdjacent(event, props.index);
  }, [props]);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "button",
    {
      type: "button",
      role: "radio",
      "aria-checked": props.checked,
      tabIndex: props.tabIndex,
      disabled: props.disabled,
      onKeyDown: handleKeyDown,
      onClick: handleClick,
      className: "min-h-11 px-4 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-45",
      children: props.choice.label
    }
  );
}
function commandStatesPayload(commands) {
  return commands.map((command) => ({ command_id: command.command_id, state: command.state }));
}
function withCommandState(commands, commandId, state) {
  return commands.map((command) => command.command_id === commandId ? { ...command, state } : command);
}
function commandNestingDepth(command) {
  if (command.parent_id) return command.parent_id.split(".").filter(Boolean).length;
  const colons = command.name.split(":").length - 1;
  return colons > 0 ? colons : 0;
}
function commandRowUsage(name, usage) {
  const trimmed = usage.trim();
  if (trimmed === "" || trimmed === name) return null;
  return trimmed;
}
function CustomExtensionCommandList(props) {
  if (props.commands.length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm leading-6 text-brand-dark/75", children: emptyCommandCopy(props.surface) });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "divide-y divide-slate-200", children: props.commands.map((command) => /* @__PURE__ */ jsxRuntimeExports.jsx(
    CustomExtensionCommandRow,
    {
      command,
      disabled: props.disabled,
      onChange: props.onChange
    },
    command.command_id
  )) });
}
function emptyCommandCopy(surface) {
  if (surface === "mcp") {
    return "Guard has not loaded tools for this MCP server yet. Find the server again to list its tools.";
  }
  if (surface === "package-scripts") {
    return "Guard has not loaded scripts from package.json yet. Paste npm run, a project folder, or package.json.";
  }
  return "Guard has not loaded commands for this tool yet. Find the tool again to read its --help output.";
}
function CustomExtensionCommandRow(props) {
  const handleChange = reactExports.useCallback((state) => {
    props.onChange(props.command.command_id, state);
  }, [props]);
  const depth = commandNestingDepth(props.command);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "article",
    {
      className: "guard-pattern-row px-4 py-3.5",
      "data-command-id": props.command.command_id,
      style: depth > 0 ? { paddingLeft: `${1.25 + depth * 1.1}rem` } : void 0,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 pr-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-brand-dark", children: props.command.name }),
          commandRowUsage(props.command.name, props.command.usage) ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "guard-pattern-example mt-1", title: props.command.usage, children: props.command.usage }) : null,
          props.command.description ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs leading-5 text-brand-dark/70", children: props.command.description }) : null
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          CommandDraftControl,
          {
            label: props.command.name,
            state: props.command.state,
            disabled: props.disabled,
            onChange: handleChange
          }
        )
      ]
    }
  );
}
function CommandDraftControl(props) {
  const choices = [
    { value: "inherit", label: "Recommended" },
    { value: "allow", label: "Allow" },
    { value: "block", label: "Block" }
  ];
  const tabStopIndex = extensionPolicyRadioTabStop(choices, props.state, props.disabled);
  const chooseAdjacent = (event, index) => {
    const next = nextExtensionPolicyRadioIndex(choices, index, event.key, props.disabled);
    if (next < 0) return;
    event.preventDefault();
    props.onChange(choices[next].value);
    event.currentTarget.parentElement?.querySelectorAll('[role="radio"]')[next]?.focus();
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "radiogroup", "aria-label": `${props.label} protection setting`, className: "guard-segmented", children: choices.map((choice, index) => /* @__PURE__ */ jsxRuntimeExports.jsx(
    CommandChoiceButton,
    {
      choice,
      checked: props.state === choice.value,
      tabIndex: !props.disabled && index === tabStopIndex ? 0 : -1,
      disabled: props.disabled,
      index,
      onChoose: props.onChange,
      onAdjacent: chooseAdjacent
    },
    choice.value
  )) });
}
function CommandChoiceButton(props) {
  const handleClick = reactExports.useCallback(() => {
    props.onChoose(props.choice.value);
  }, [props]);
  const handleKeyDown = reactExports.useCallback((event) => {
    props.onAdjacent(event, props.index);
  }, [props]);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "button",
    {
      type: "button",
      role: "radio",
      "aria-checked": props.checked,
      tabIndex: props.tabIndex,
      disabled: props.disabled,
      onKeyDown: handleKeyDown,
      onClick: handleClick,
      className: "disabled:cursor-not-allowed disabled:opacity-45",
      children: props.choice.label
    }
  );
}
const EXTENSION_PANEL_CLASS = "guard-extensions-panel p-5 sm:p-6";
const EXTENSION_CHIP_CLASS = "guard-extensions-chip";
const EXTENSION_ROW_CLASS = "guard-extensions-row";
function SiVercel(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "m12 1.608 12 20.784H0Z" }, "child": [] }] })(props);
}
function SiTerraform(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M1.44 0v7.575l6.561 3.79V3.787zm21.12 4.227l-6.561 3.791v7.574l6.56-3.787zM8.72 4.23v7.575l6.561 3.787V8.018zm0 8.405v7.575L15.28 24v-7.578z" }, "child": [] }] })(props);
}
function SiSupabase(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M11.9 1.036c-.015-.986-1.26-1.41-1.874-.637L.764 12.05C-.33 13.427.65 15.455 2.409 15.455h9.579l.113 7.51c.014.985 1.259 1.408 1.873.636l9.262-11.653c1.093-1.375.113-3.403-1.645-3.403h-9.642z" }, "child": [] }] })(props);
}
function SiStripe(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M13.976 9.15c-2.172-.806-3.356-1.426-3.356-2.409 0-.831.683-1.305 1.901-1.305 2.227 0 4.515.858 6.09 1.631l.89-5.494C18.252.975 15.697 0 12.165 0 9.667 0 7.589.654 6.104 1.872 4.56 3.147 3.757 4.992 3.757 7.218c0 4.039 2.467 5.76 6.476 7.219 2.585.92 3.445 1.574 3.445 2.583 0 .98-.84 1.545-2.354 1.545-1.875 0-4.965-.921-6.99-2.109l-.9 5.555C5.175 22.99 8.385 24 11.714 24c2.641 0 4.843-.624 6.328-1.813 1.664-1.305 2.525-3.236 2.525-5.732 0-4.128-2.524-5.851-6.594-7.305h.003z" }, "child": [] }] })(props);
}
function SiSqlite(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M21.678.521c-1.032-.92-2.28-.55-3.513.544a8.71 8.71 0 0 0-.547.535c-2.109 2.237-4.066 6.38-4.674 9.544.237.48.422 1.093.544 1.561a13.044 13.044 0 0 1 .164.703s-.019-.071-.096-.296l-.05-.146a1.689 1.689 0 0 0-.033-.08c-.138-.32-.518-.995-.686-1.289-.143.423-.27.818-.376 1.176.484.884.778 2.4.778 2.4s-.025-.099-.147-.442c-.107-.303-.644-1.244-.772-1.464-.217.804-.304 1.346-.226 1.478.152.256.296.698.422 1.186.286 1.1.485 2.44.485 2.44l.017.224a22.41 22.41 0 0 0 .056 2.748c.095 1.146.273 2.13.5 2.657l.155-.084c-.334-1.038-.47-2.399-.41-3.967.09-2.398.642-5.29 1.661-8.304 1.723-4.55 4.113-8.201 6.3-9.945-1.993 1.8-4.692 7.63-5.5 9.788-.904 2.416-1.545 4.684-1.931 6.857.666-2.037 2.821-2.912 2.821-2.912s1.057-1.304 2.292-3.166c-.74.169-1.955.458-2.362.629-.6.251-.762.337-.762.337s1.945-1.184 3.613-1.72C21.695 7.9 24.195 2.767 21.678.521m-18.573.543A1.842 1.842 0 0 0 1.27 2.9v16.608a1.84 1.84 0 0 0 1.835 1.834h9.418a22.953 22.953 0 0 1-.052-2.707c-.006-.062-.011-.141-.016-.2a27.01 27.01 0 0 0-.473-2.378c-.121-.47-.275-.898-.369-1.057-.116-.197-.098-.31-.097-.432 0-.12.015-.245.037-.386a9.98 9.98 0 0 1 .234-1.045l.217-.028c-.017-.035-.014-.065-.031-.097l-.041-.381a32.8 32.8 0 0 1 .382-1.194l.2-.019c-.008-.016-.01-.038-.018-.053l-.043-.316c.63-3.28 2.587-7.443 4.8-9.791.066-.069.133-.128.198-.194Z" }, "child": [] }] })(props);
}
function SiRust(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M23.8346 11.7033l-1.0073-.6236a13.7268 13.7268 0 00-.0283-.2936l.8656-.8069a.3483.3483 0 00-.1154-.578l-1.1066-.414a8.4958 8.4958 0 00-.087-.2856l.6904-.9587a.3462.3462 0 00-.2257-.5446l-1.1663-.1894a9.3574 9.3574 0 00-.1407-.2622l.49-1.0761a.3437.3437 0 00-.0274-.3361.3486.3486 0 00-.3006-.154l-1.1845.0416a6.7444 6.7444 0 00-.1873-.2268l.2723-1.153a.3472.3472 0 00-.417-.4172l-1.1532.2724a14.0183 14.0183 0 00-.2278-.1873l.0415-1.1845a.3442.3442 0 00-.49-.328l-1.076.491c-.0872-.0476-.1742-.0952-.2623-.1407l-.1903-1.1673A.3483.3483 0 0016.256.955l-.9597.6905a8.4867 8.4867 0 00-.2855-.086l-.414-1.1066a.3483.3483 0 00-.5781-.1154l-.8069.8666a9.2936 9.2936 0 00-.2936-.0284L12.2946.1683a.3462.3462 0 00-.5892 0l-.6236 1.0073a13.7383 13.7383 0 00-.2936.0284L9.9803.3374a.3462.3462 0 00-.578.1154l-.4141 1.1065c-.0962.0274-.1903.0567-.2855.086L7.744.955a.3483.3483 0 00-.5447.2258L7.009 2.348a9.3574 9.3574 0 00-.2622.1407l-1.0762-.491a.3462.3462 0 00-.49.328l.0416 1.1845a7.9826 7.9826 0 00-.2278.1873L3.8413 3.425a.3472.3472 0 00-.4171.4171l.2713 1.1531c-.0628.075-.1255.1509-.1863.2268l-1.1845-.0415a.3462.3462 0 00-.328.49l.491 1.0761a9.167 9.167 0 00-.1407.2622l-1.1662.1894a.3483.3483 0 00-.2258.5446l.6904.9587a13.303 13.303 0 00-.087.2855l-1.1065.414a.3483.3483 0 00-.1155.5781l.8656.807a9.2936 9.2936 0 00-.0283.2935l-1.0073.6236a.3442.3442 0 000 .5892l1.0073.6236c.008.0982.0182.1964.0283.2936l-.8656.8079a.3462.3462 0 00.1155.578l1.1065.4141c.0273.0962.0567.1914.087.2855l-.6904.9587a.3452.3452 0 00.2268.5447l1.1662.1893c.0456.088.0922.1751.1408.2622l-.491 1.0762a.3462.3462 0 00.328.49l1.1834-.0415c.0618.0769.1235.1528.1873.2277l-.2713 1.1541a.3462.3462 0 00.4171.4161l1.153-.2713c.075.0638.151.1255.2279.1863l-.0415 1.1845a.3442.3442 0 00.49.327l1.0761-.49c.087.0486.1741.0951.2622.1407l.1903 1.1662a.3483.3483 0 00.5447.2268l.9587-.6904a9.299 9.299 0 00.2855.087l.414 1.1066a.3452.3452 0 00.5781.1154l.8079-.8656c.0972.0111.1954.0203.2936.0294l.6236 1.0073a.3472.3472 0 00.5892 0l.6236-1.0073c.0982-.0091.1964-.0183.2936-.0294l.8069.8656a.3483.3483 0 00.578-.1154l.4141-1.1066a8.4626 8.4626 0 00.2855-.087l.9587.6904a.3452.3452 0 00.5447-.2268l.1903-1.1662c.088-.0456.1751-.0931.2622-.1407l1.0762.49a.3472.3472 0 00.49-.327l-.0415-1.1845a6.7267 6.7267 0 00.2267-.1863l1.1531.2713a.3472.3472 0 00.4171-.416l-.2713-1.1542c.0628-.0749.1255-.1508.1863-.2278l1.1845.0415a.3442.3442 0 00.328-.49l-.49-1.076c.0475-.0872.0951-.1742.1407-.2623l1.1662-.1893a.3483.3483 0 00.2258-.5447l-.6904-.9587.087-.2855 1.1066-.414a.3462.3462 0 00.1154-.5781l-.8656-.8079c.0101-.0972.0202-.1954.0283-.2936l1.0073-.6236a.3442.3442 0 000-.5892zm-6.7413 8.3551a.7138.7138 0 01.2986-1.396.714.714 0 11-.2997 1.396zm-.3422-2.3142a.649.649 0 00-.7715.5l-.3573 1.6685c-1.1035.501-2.3285.7795-3.6193.7795a8.7368 8.7368 0 01-3.6951-.814l-.3574-1.6684a.648.648 0 00-.7714-.499l-1.473.3158a8.7216 8.7216 0 01-.7613-.898h7.1676c.081 0 .1356-.0141.1356-.088v-2.536c0-.074-.0536-.0881-.1356-.0881h-2.0966v-1.6077h2.2677c.2065 0 1.1065.0587 1.394 1.2088.0901.3533.2875 1.5044.4232 1.8729.1346.413.6833 1.2381 1.2685 1.2381h3.5716a.7492.7492 0 00.1296-.0131 8.7874 8.7874 0 01-.8119.9526zM6.8369 20.024a.714.714 0 11-.2997-1.396.714.714 0 01.2997 1.396zM4.1177 8.9972a.7137.7137 0 11-1.304.5791.7137.7137 0 011.304-.579zm-.8352 1.9813l1.5347-.6824a.65.65 0 00.33-.8585l-.3158-.7147h1.2432v5.6025H3.5669a8.7753 8.7753 0 01-.2834-3.348zm6.7343-.5437V8.7836h2.9601c.153 0 1.0792.1772 1.0792.8697 0 .575-.7107.7815-1.2948.7815zm10.7574 1.4862c0 .2187-.008.4363-.0243.651h-.9c-.09 0-.1265.0586-.1265.1477v.413c0 .973-.5487 1.1846-1.0296 1.2382-.4576.0517-.9648-.1913-1.0275-.4717-.2704-1.5186-.7198-1.8436-1.4305-2.4034.8817-.5599 1.799-1.386 1.799-2.4915 0-1.1936-.819-1.9458-1.3769-2.3153-.7825-.5163-1.6491-.6195-1.883-.6195H5.4682a8.7651 8.7651 0 014.907-2.7699l1.0974 1.151a.648.648 0 00.9182.0213l1.227-1.1743a8.7753 8.7753 0 016.0044 4.2762l-.8403 1.8982a.652.652 0 00.33.8585l1.6178.7188c.0283.2875.0425.577.0425.8717zm-9.3006-9.5993a.7128.7128 0 11.984 1.0316.7137.7137 0 01-.984-1.0316zm8.3389 6.71a.7107.7107 0 01.9395-.3625.7137.7137 0 11-.9405.3635z" }, "child": [] }] })(props);
}
function SiRuby(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M20.156.083c3.033.525 3.893 2.598 3.829 4.77L24 4.822 22.635 22.71 4.89 23.926h.016C3.433 23.864.15 23.729 0 19.139l1.645-3 2.819 6.586.503 1.172 2.805-9.144-.03.007.016-.03 9.255 2.956-1.396-5.431-.99-3.9 8.82-.569-.615-.51L16.5 2.114 20.159.073l-.003.01zM0 19.089zM5.13 5.073c3.561-3.533 8.157-5.621 9.922-3.84 1.762 1.777-.105 6.105-3.673 9.636-3.563 3.532-8.103 5.734-9.864 3.957-1.766-1.777.045-6.217 3.612-9.75l.003-.003z" }, "child": [] }] })(props);
}
function SiRedis(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M22.71 13.145c-1.66 2.092-3.452 4.483-7.038 4.483-3.203 0-4.397-2.825-4.48-5.12.701 1.484 2.073 2.685 4.214 2.63 4.117-.133 6.94-3.852 6.94-7.239 0-4.05-3.022-6.972-8.268-6.972-3.752 0-8.4 1.428-11.455 3.685C2.59 6.937 3.885 9.958 4.35 9.626c2.648-1.904 4.748-3.13 6.784-3.744C8.12 9.244.886 17.05 0 18.425c.1 1.261 1.66 4.648 2.424 4.648.232 0 .431-.133.664-.365a100.49 100.49 0 0 0 5.54-6.765c.222 3.104 1.748 6.898 6.014 6.898 3.819 0 7.604-2.756 9.33-8.965.2-.764-.73-1.361-1.261-.73zm-4.349-5.013c0 1.959-1.926 2.922-3.685 2.922-.941 0-1.664-.247-2.235-.568 1.051-1.592 2.092-3.225 3.21-4.973 1.972.334 2.71 1.43 2.71 2.619z" }, "child": [] }] })(props);
}
function SiRclone(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M11.842.6258C9.3647.6813 6.9754 1.9906 5.646 4.2933c-.7593 1.3144-1.0647 2.7662-.966 4.1745a7.99 7.99 0 0 1 2.6568-.4541l1.4705-.0013c-.0093-.5594.1245-1.1284.4245-1.6482.8827-1.5284 2.837-2.0522 4.3654-1.1695 1.5284.8824 2.0519 2.8366 1.1695 4.365l-1.4782 2.5647 1.1955 2.0714 2.3914-.0004 1.4775-2.5655c2.0262-3.5088.8239-7.9959-2.6853-10.0217C14.4614.9118 13.1396.5967 11.842.6258m-1.5451 8.073-2.9605.0029C3.2844 8.7017 0 11.9867 0 16.0383c0 4.052 3.2844 7.3367 7.3364 7.3367 1.5174 0 2.9267-.4609 4.0967-1.2497a8 8 0 0 1-1.72-2.0748l-.7368-1.273c-.4799.288-1.0392.4565-1.6395.4565-1.765 0-3.1958-1.4307-3.1958-3.1958 0-1.7647 1.4307-3.1954 3.1958-3.1954l2.96-.0022 1.1962-2.0708zm9.587.7475a7.99 7.99 0 0 1-.935 2.5278l-.7344 1.2745c.4892.2717.915.6719 1.2153 1.192.8823 1.528.3585 3.4826-1.1699 4.365-1.528.8823-3.4828.3588-4.3651-1.1696l-1.482-2.5628h-2.3915L8.8256 17.144l1.483 2.5626c2.0262 3.5091 6.513 4.7112 10.022 2.685 3.5089-2.0257 4.7112-6.5125 2.6853-10.0216-.7588-1.3144-1.863-2.3052-3.132-2.9237" }, "child": [] }] })(props);
}
function SiRabbitmq(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M23.035 9.601h-7.677a.956.956 0 01-.962-.962V.962a.956.956 0 00-.962-.956H10.56a.956.956 0 00-.962.956V8.64a.956.956 0 01-.962.962H5.762a.956.956 0 01-.961-.962V.962A.956.956 0 003.839 0H.959a.956.956 0 00-.956.962v22.076A.956.956 0 00.965 24h22.07a.956.956 0 00.962-.962V10.58a.956.956 0 00-.962-.98zm-3.86 8.152a1.437 1.437 0 01-1.437 1.443h-1.924a1.437 1.437 0 01-1.436-1.443v-1.917a1.437 1.437 0 011.436-1.443h1.924a1.437 1.437 0 011.437 1.443z" }, "child": [] }] })(props);
}
function SiPython(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M14.25.18l.9.2.73.26.59.3.45.32.34.34.25.34.16.33.1.3.04.26.02.2-.01.13V8.5l-.05.63-.13.55-.21.46-.26.38-.3.31-.33.25-.35.19-.35.14-.33.1-.3.07-.26.04-.21.02H8.77l-.69.05-.59.14-.5.22-.41.27-.33.32-.27.35-.2.36-.15.37-.1.35-.07.32-.04.27-.02.21v3.06H3.17l-.21-.03-.28-.07-.32-.12-.35-.18-.36-.26-.36-.36-.35-.46-.32-.59-.28-.73-.21-.88-.14-1.05-.05-1.23.06-1.22.16-1.04.24-.87.32-.71.36-.57.4-.44.42-.33.42-.24.4-.16.36-.1.32-.05.24-.01h.16l.06.01h8.16v-.83H6.18l-.01-2.75-.02-.37.05-.34.11-.31.17-.28.25-.26.31-.23.38-.2.44-.18.51-.15.58-.12.64-.1.71-.06.77-.04.84-.02 1.27.05zm-6.3 1.98l-.23.33-.08.41.08.41.23.34.33.22.41.09.41-.09.33-.22.23-.34.08-.41-.08-.41-.23-.33-.33-.22-.41-.09-.41.09zm13.09 3.95l.28.06.32.12.35.18.36.27.36.35.35.47.32.59.28.73.21.88.14 1.04.05 1.23-.06 1.23-.16 1.04-.24.86-.32.71-.36.57-.4.45-.42.33-.42.24-.4.16-.36.09-.32.05-.24.02-.16-.01h-8.22v.82h5.84l.01 2.76.02.36-.05.34-.11.31-.17.29-.25.25-.31.24-.38.2-.44.17-.51.15-.58.13-.64.09-.71.07-.77.04-.84.01-1.27-.04-1.07-.14-.9-.2-.73-.25-.59-.3-.45-.33-.34-.34-.25-.34-.16-.33-.1-.3-.04-.25-.02-.2.01-.13v-5.34l.05-.64.13-.54.21-.46.26-.38.3-.32.33-.24.35-.2.35-.14.33-.1.3-.06.26-.04.21-.02.13-.01h5.84l.69-.05.59-.14.5-.21.41-.28.33-.32.27-.35.2-.36.15-.36.1-.35.07-.32.04-.28.02-.21V6.07h2.09l.14.01zm-6.47 14.25l-.23.33-.08.41.08.41.23.33.33.23.41.08.41-.08.33-.23.23-.33.08-.41-.08-.41-.23-.33-.33-.23-.41-.08-.41.08z" }, "child": [] }] })(props);
}
function SiPulumi(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M11.997 0C10.226 0 8.79.83 8.79 1.856c0 1.025 1.436 1.856 3.207 1.856 1.772 0 3.208-.831 3.208-1.856C15.205.83 13.77 0 11.997 0zM5.95 3.488c-1.772 0-3.208.83-3.208 1.856C2.742 6.369 4.178 7.2 5.95 7.2c1.771 0 3.207-.831 3.207-1.856 0-1.025-1.436-1.856-3.207-1.856zm12.103 0c-1.772 0-3.208.83-3.208 1.856 0 1.025 1.436 1.856 3.208 1.856 1.771 0 3.207-.831 3.207-1.856 0-1.025-1.436-1.856-3.207-1.856zm-6.056 3.495c-1.771 0-3.207.831-3.207 1.856 0 1.025 1.436 1.856 3.207 1.856 1.772 0 3.208-.83 3.208-1.856 0-1.025-1.436-1.856-3.208-1.856zm-10.127.67a1.157 1.157 0 0 0-.55.151c-.888.513-.89 2.172-.004 3.706.886 1.534 2.324 2.362 3.211 1.85.888-.513.89-2.171.003-3.706-.72-1.246-1.803-2.027-2.66-2zm20.257.004c-.857-.026-1.941.754-2.661 2-.886 1.535-.884 3.194.003 3.707.888.512 2.325-.316 3.211-1.85.886-1.534.885-3.193-.003-3.706a1.157 1.157 0 0 0-.55-.15zm-6.048 3.492c-.857-.026-1.94.754-2.66 2-.886 1.535-.885 3.194.003 3.706.887.513 2.325-.316 3.21-1.85.887-1.534.885-3.193-.003-3.706a1.157 1.157 0 0 0-.55-.15zm-8.16.001a1.157 1.157 0 0 0-.55.151c-.888.513-.89 2.172-.004 3.706.886 1.535 2.324 2.363 3.211 1.85.888-.512.89-2.171.003-3.705-.72-1.247-1.803-2.028-2.66-2.002zm-6.047 3.494a1.157 1.157 0 0 0-.55.151c-.888.513-.89 2.172-.004 3.706.886 1.534 2.324 2.362 3.212 1.85.887-.513.888-2.172.003-3.706-.72-1.246-1.804-2.027-2.661-2.001zm20.258.002c-.857-.026-1.941.755-2.66 2.001-.887 1.535-.885 3.193.003 3.706.887.512 2.325-.316 3.21-1.85.886-1.534.885-3.193-.003-3.706a1.157 1.157 0 0 0-.55-.15zm-6.047 3.492c-.858-.026-1.942.754-2.661 2-.886 1.535-.885 3.194.003 3.706.888.513 2.325-.315 3.21-1.85.887-1.533.885-3.193-.002-3.705a1.157 1.157 0 0 0-.55-.151zm-8.163.003a1.157 1.157 0 0 0-.55.151c-.887.513-.889 2.172-.003 3.706.886 1.534 2.323 2.363 3.211 1.85.888-.512.89-2.171.004-3.706-.72-1.246-1.804-2.027-2.662-2z" }, "child": [] }] })(props);
}
function SiPostgresql(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M23.5594 14.7228a.5269.5269 0 0 0-.0563-.1191c-.139-.2632-.4768-.3418-1.0074-.2321-1.6533.3411-2.2935.1312-2.5256-.0191 1.342-2.0482 2.445-4.522 3.0411-6.8297.2714-1.0507.7982-3.5237.1222-4.7316a1.5641 1.5641 0 0 0-.1509-.235C21.6931.9086 19.8007.0248 17.5099.0005c-1.4947-.0158-2.7705.3461-3.1161.4794a9.449 9.449 0 0 0-.5159-.0816 8.044 8.044 0 0 0-1.3114-.1278c-1.1822-.0184-2.2038.2642-3.0498.8406-.8573-.3211-4.7888-1.645-7.2219.0788C.9359 2.1526.3086 3.8733.4302 6.3043c.0409.818.5069 3.334 1.2423 5.7436.4598 1.5065.9387 2.7019 1.4334 3.582.553.9942 1.1259 1.5933 1.7143 1.7895.4474.1491 1.1327.1441 1.8581-.7279.8012-.9635 1.5903-1.8258 1.9446-2.2069.4351.2355.9064.3625 1.39.3772a.0569.0569 0 0 0 .0004.0041 11.0312 11.0312 0 0 0-.2472.3054c-.3389.4302-.4094.5197-1.5002.7443-.3102.064-1.1344.2339-1.1464.8115-.0025.1224.0329.2309.0919.3268.2269.4231.9216.6097 1.015.6331 1.3345.3335 2.5044.092 3.3714-.6787-.017 2.231.0775 4.4174.3454 5.0874.2212.5529.7618 1.9045 2.4692 1.9043.2505 0 .5263-.0291.8296-.0941 1.7819-.3821 2.5557-1.1696 2.855-2.9059.1503-.8707.4016-2.8753.5388-4.1012.0169-.0703.0357-.1207.057-.1362.0007-.0005.0697-.0471.4272.0307a.3673.3673 0 0 0 .0443.0068l.2539.0223.0149.001c.8468.0384 1.9114-.1426 2.5312-.4308.6438-.2988 1.8057-1.0323 1.5951-1.6698zM2.371 11.8765c-.7435-2.4358-1.1779-4.8851-1.2123-5.5719-.1086-2.1714.4171-3.6829 1.5623-4.4927 1.8367-1.2986 4.8398-.5408 6.108-.13-.0032.0032-.0066.0061-.0098.0094-2.0238 2.044-1.9758 5.536-1.9708 5.7495-.0002.0823.0066.1989.0162.3593.0348.5873.0996 1.6804-.0735 2.9184-.1609 1.1504.1937 2.2764.9728 3.0892.0806.0841.1648.1631.2518.2374-.3468.3714-1.1004 1.1926-1.9025 2.1576-.5677.6825-.9597.5517-1.0886.5087-.3919-.1307-.813-.5871-1.2381-1.3223-.4796-.839-.9635-2.0317-1.4155-3.5126zm6.0072 5.0871c-.1711-.0428-.3271-.1132-.4322-.1772.0889-.0394.2374-.0902.4833-.1409 1.2833-.2641 1.4815-.4506 1.9143-1.0002.0992-.126.2116-.2687.3673-.4426a.3549.3549 0 0 0 .0737-.1298c.1708-.1513.2724-.1099.4369-.0417.156.0646.3078.26.3695.4752.0291.1016.0619.2945-.0452.4444-.9043 1.2658-2.2216 1.2494-3.1676 1.0128zm2.094-3.988-.0525.141c-.133.3566-.2567.6881-.3334 1.003-.6674-.0021-1.3168-.2872-1.8105-.8024-.6279-.6551-.9131-1.5664-.7825-2.5004.1828-1.3079.1153-2.4468.079-3.0586-.005-.0857-.0095-.1607-.0122-.2199.2957-.2621 1.6659-.9962 2.6429-.7724.4459.1022.7176.4057.8305.928.5846 2.7038.0774 3.8307-.3302 4.7363-.084.1866-.1633.3629-.2311.5454zm7.3637 4.5725c-.0169.1768-.0358.376-.0618.5959l-.146.4383a.3547.3547 0 0 0-.0182.1077c-.0059.4747-.054.6489-.115.8693-.0634.2292-.1353.4891-.1794 1.0575-.11 1.4143-.8782 2.2267-2.4172 2.5565-1.5155.3251-1.7843-.4968-2.0212-1.2217a6.5824 6.5824 0 0 0-.0769-.2266c-.2154-.5858-.1911-1.4119-.1574-2.5551.0165-.5612-.0249-1.9013-.3302-2.6462.0044-.2932.0106-.5909.019-.8918a.3529.3529 0 0 0-.0153-.1126 1.4927 1.4927 0 0 0-.0439-.208c-.1226-.4283-.4213-.7866-.7797-.9351-.1424-.059-.4038-.1672-.7178-.0869.067-.276.1831-.5875.309-.9249l.0529-.142c.0595-.16.134-.3257.213-.5012.4265-.9476 1.0106-2.2453.3766-5.1772-.2374-1.0981-1.0304-1.6343-2.2324-1.5098-.7207.0746-1.3799.3654-1.7088.5321a5.6716 5.6716 0 0 0-.1958.1041c.0918-1.1064.4386-3.1741 1.7357-4.4823a4.0306 4.0306 0 0 1 .3033-.276.3532.3532 0 0 0 .1447-.0644c.7524-.5706 1.6945-.8506 2.802-.8325.4091.0067.8017.0339 1.1742.081 1.939.3544 3.2439 1.4468 4.0359 2.3827.8143.9623 1.2552 1.9315 1.4312 2.4543-1.3232-.1346-2.2234.1268-2.6797.779-.9926 1.4189.543 4.1729 1.2811 5.4964.1353.2426.2522.4522.2889.5413.2403.5825.5515.9713.7787 1.2552.0696.087.1372.1714.1885.245-.4008.1155-1.1208.3825-1.0552 1.717-.0123.1563-.0423.4469-.0834.8148-.0461.2077-.0702.4603-.0994.7662zm.8905-1.6211c-.0405-.8316.2691-.9185.5967-1.0105a2.8566 2.8566 0 0 0 .135-.0406 1.202 1.202 0 0 0 .1342.103c.5703.3765 1.5823.4213 3.0068.1344-.2016.1769-.5189.3994-.9533.6011-.4098.1903-1.0957.333-1.7473.3636-.7197.0336-1.0859-.0807-1.1721-.151zm.5695-9.2712c-.0059.3508-.0542.6692-.1054 1.0017-.055.3576-.112.7274-.1264 1.1762-.0142.4368.0404.8909.0932 1.3301.1066.887.216 1.8003-.2075 2.7014a3.5272 3.5272 0 0 1-.1876-.3856c-.0527-.1276-.1669-.3326-.3251-.6162-.6156-1.1041-2.0574-3.6896-1.3193-4.7446.3795-.5427 1.3408-.5661 2.1781-.463zm.2284 7.0137a12.3762 12.3762 0 0 0-.0853-.1074l-.0355-.0444c.7262-1.1995.5842-2.3862.4578-3.4385-.0519-.4318-.1009-.8396-.0885-1.2226.0129-.4061.0666-.7543.1185-1.0911.0639-.415.1288-.8443.1109-1.3505.0134-.0531.0188-.1158.0118-.1902-.0457-.4855-.5999-1.938-1.7294-3.253-.6076-.7073-1.4896-1.4972-2.6889-2.0395.5251-.1066 1.2328-.2035 2.0244-.1859 2.0515.0456 3.6746.8135 4.8242 2.2824a.908.908 0 0 1 .0667.1002c.7231 1.3556-.2762 6.2751-2.9867 10.5405zm-8.8166-6.1162c-.025.1794-.3089.4225-.6211.4225a.5821.5821 0 0 1-.0809-.0056c-.1873-.026-.3765-.144-.5059-.3156-.0458-.0605-.1203-.178-.1055-.2844.0055-.0401.0261-.0985.0925-.1488.1182-.0894.3518-.1226.6096-.0867.3163.0441.6426.1938.6113.4186zm7.9305-.4114c.0111.0792-.049.201-.1531.3102-.0683.0717-.212.1961-.4079.2232a.5456.5456 0 0 1-.075.0052c-.2935 0-.5414-.2344-.5607-.3717-.024-.1765.2641-.3106.5611-.352.297-.0414.6111.0088.6356.1851z" }, "child": [] }] })(props);
}
function SiPhp(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M7.01 10.207h-.944l-.515 2.648h.838c.556 0 .97-.105 1.242-.314.272-.21.455-.559.55-1.049.092-.47.05-.802-.124-.995-.175-.193-.523-.29-1.047-.29zM12 5.688C5.373 5.688 0 8.514 0 12s5.373 6.313 12 6.313S24 15.486 24 12c0-3.486-5.373-6.312-12-6.312zm-3.26 7.451c-.261.25-.575.438-.917.551-.336.108-.765.164-1.285.164H5.357l-.327 1.681H3.652l1.23-6.326h2.65c.797 0 1.378.209 1.744.628.366.418.476 1.002.33 1.752a2.836 2.836 0 0 1-.305.847c-.143.255-.33.49-.561.703zm4.024.715l.543-2.799c.063-.318.039-.536-.068-.651-.107-.116-.336-.174-.687-.174H11.46l-.704 3.625H9.388l1.23-6.327h1.367l-.327 1.682h1.218c.767 0 1.295.134 1.586.401s.378.7.263 1.299l-.572 2.944h-1.389zm7.597-2.265a2.782 2.782 0 0 1-.305.847c-.143.255-.33.49-.561.703a2.44 2.44 0 0 1-.917.551c-.336.108-.765.164-1.286.164h-1.18l-.327 1.682h-1.378l1.23-6.326h2.649c.797 0 1.378.209 1.744.628.366.417.477 1.001.331 1.751zM17.766 10.207h-.943l-.516 2.648h.838c.557 0 .971-.105 1.242-.314.272-.21.455-.559.551-1.049.092-.47.049-.802-.125-.995s-.524-.29-1.047-.29z" }, "child": [] }] })(props);
}
function SiOpentofu(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "m10.184 23.25.002-.01-.033-.017-8.388-4.611a1.6841 1.6841 0 0 1-.873-1.475V6.864c0-.614.335-1.18.873-1.476l9.424-5.18a1.6868 1.6868 0 0 1 1.622 0l8.31 4.568.022.012.006.002-.004-.001 1.09.599c.538.296.873.862.873 1.476v10.273c0 .614-.335 1.179-.873 1.475l-8.388 4.611-.03.016-1.006.553c-.505.277-1.117.277-1.622 0l-1.003-.552-.002.01Zm.603-1.158-.005-.001.012.006c.252.123.55-.055.558-.338l.001-9.147c0-.141-.078-.272-.202-.34L2.763 7.661c-.259-.142-.576.045-.576.341v9.135c0 .141.077.272.201.34l8.394 4.613.005.002Zm.556-.327Zm0 0Zm-2.539-4.802-.005.003-1.959-1.031-.003-.004c.001-.003.001-.007.001-.01.023-.305.153-.525.346-.632.194-.107.45-.101.72.041.272.143.508.397.671.691.163.293.252.628.229.935v.007ZM5.71 15.177l-.005.002-1.96-1.031-.002-.004.001-.01c.022-.304.152-.524.346-.632.194-.107.449-.101.72.042.271.143.508.396.671.69.162.294.252.628.229.935v.008Zm14.981-8.999-.003-.018a.382.382 0 0 0-.191-.25l-8.31-4.567a.3883.3883 0 0 0-.374 0L3.503 5.91c-.162.089-.226.265-.193.423l.009.007-.009-.007c.022.1.083.194.183.253l8.32 4.572c.116.064.258.064.374 0l8.321-4.573c.151-.089.212-.256.183-.407Zm-17.37.16Zm-.002.002c0-.001-.003-.003-.005-.006-.002-.002-.004-.004-.004-.003l.009.009Zm-.467-1.56-.003.002c.002.004.005.006.005.006l-.002-.008Zm.007.007c-.001.001-.002.001-.003.001h-.002l.005-.001Z" }, "child": [] }] })(props);
}
function SiOpenbsd(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M13.695 1.653c-.202.47-.146 1.02-.293 1.509-.034.112-.146.452-.308.429-.333-.048-.16-.688-.545-.7l.12.934c-.577.073-.498-.829-.733-1.195-.27-.423-.335.192-.317.38.011.122.036.242.05.363.026.21.032.393.005.603-.552-.007-.35-.733-.754-.844l.03.874c-.612-.005-.89-.557-1.159-1.025-.112-.196-.261-.574-.53-.453.126.544.423 1.064.454 1.63.007.145-.13.516-.333.448-.469-.158-.406-1.008-.796-1.231-.08-.045-.204-.006-.29-.002 0 .45.198.996.356 1.418.034.09.129.41-.069.403-.353-.01-.441-.695-.8-.615.044.185.153.335.215.513.037.109.106.219.126.332.044.247-.269.267-.432.22-.384-.114-.66-.428-.935-.703-.076-.076-.277-.344-.404-.222-.141.135.136.373.215.464.234.271.488.589.6.935.049.148.058.36-.09.462-.146.1-.384-.083-.502-.16-.362-.239-.721-.654-1.176-.664l-.107.271.29.392.752.845-.875-.362c.035.229.583.506.475.742-.064.14-.38.142-.505.124-.446-.064-.762-.396-1.177-.515-.366-.105-.298.18-.09.343.072.057.141.117.211.177.125.108.245.219.362.336.183.183.343.378.513.573l-.875-.03v.06l.845.392-.151.603c-.244 0-.442-.067-.664-.163-.151-.066-.31-.175-.482-.163-.206.014-.328.202-.19.377.206.263.62.412.883.617.1.078.247.212.133.345-.225.264-.832-.074-1.128.013v.06c.275.161.839.253 1 .549.128.231-.232.756-.487.736-.227-.019-.436-.275-.603-.41-.401-.322-.83-.7-1.298-.923-.801-.38-1.597.226-2.232.622.081.256.402-.017.603.029.271.061.477.313.651.513.84.968 1.543 2.064 1.857 3.319.083.33.224.725-.023 1.021-.066.08-.165.09-.238.155-.055.05-.052.118.023.141.138.043.34-.021.475-.054.443-.107.949-.346 1.15-.78.125-.271.169-.797.48-.905.068.29.394.673.363.965-.029.259-.302.56-.461.751-.057.068-.193.217-.112.315.082.097.25-.112.3-.16.229-.216.73-.558.865-.062.118.432-.261 1.13-.45 1.509-.054.105-.297.435-.202.553.11.135.338-.218.387-.282.19-.249.856-.987 1.21-.722.431.324.282.555.119.994-.046.123-.216.433-.1.55.111.114.258.01.315-.098.104-.197.383-.78.661-.631.175.093.441.251.543.425.158.272.02.815-.022 1.111-.024.17-.207.702-.055.825.14.113.254-.228.296-.312.149-.295.32-.597.54-.845.08-.089.192-.237.327-.212.7.131-.015.829.273 1.185.058.072.215.067.3.083l.362-.935c.184.07.455.095.591.248.114.128.137.344.17.506.092.454.142.896.084 1.357.057.042.148.138.225.088.097-.062.11-.315.143-.42.106-.332.269-.65.42-.965.099-.207.37-.427.565-.142.2.292.12.804.246 1.138.32-.158.355-.825.362-1.147l.415.061.25.513.45 1.297c.234-.09.16-.538.187-.754.035-.293.103-.882.318-1.1.086-.087.258-.095.37-.137.129.312.199.666.354.965.06.116.198.242.337.17.133-.068.128-.224.111-.35-.042-.313-.113-.62-.138-.936.598-.042.95.441 1.325.845.145.155.271.362.485.422l-.31-.905-.172-.845c.217-.09.676-.534.905-.47.34.097.6 1.046 1.023.823.18-.095.088-.257.003-.383-.126-.188-.506-.639-.465-.874.03-.175.324-.379.494-.377.391.006 1.071.304 1.297.618l.272-.03c-.04-.54-.85-.787-.966-1.328a.404.404 0 01.004-.172c.086-.347.294-.195.51-.102.067.029.213.103.269.02.06-.091-.048-.212-.087-.289-.082-.156-.156-.337-.122-.513.282.074.455.242.694.4.056.038.18.131.251.08.075-.056-.036-.167-.071-.208-.106-.123-.432-.42-.4-.6.022-.122.227-.252.31-.335.276-.276.59-.556.815-.875h.03c.532.621 2.203.186 1.99-.754-.132.019-.256.123-.392.077-.594-.205-.45-1.157-1.116-1.163-.049-.62-.298-1.24-.599-1.78-.138-.247-.424-.473-.525-.725-.055-.14-.046-.36-.052-.512.349-.054.177-.407.05-.603-.142-.218-.292-.477-.475-.66-.226-.227-.562-.374-.533-.758.027-.357.642-.311.747-.633-.183.008-.363.053-.543.083-.449.075-.527-.076-.317-.475.183-.349.474-.613.73-.905.083-.093.336-.306.205-.441-.107-.112-.286.058-.377.119-.333.22-.705.384-1.086.502-.113.035-.448.166-.486-.035-.051-.272.463-.322.395-.628-.205.049-.61.374-.807.223-.238-.18.111-.643.149-.856.038-.216-.136-.224-.258-.09-.043.048-.081.1-.12.15-.07.087-.126.17-.17.271-.494-.288.44-.623.265-.89-.063-.095-.179 0-.235.05-.117.102-.558.61-.654.237-.106-.412.108-.908.22-1.297.028-.102.159-.376.032-.449-.185-.106-.266.253-.31.359a2.333 2.333 0 01-.615.839c-.086.077-.232.225-.36.19-.187-.051-.188-.57-.182-.728.003-.075.045-.205-.028-.26-.096-.071-.147.072-.16.14-.048.222-.186.856-.515.44-.298-.376.163-1.157-.444-1.315l-.332 1.056c-.398-.087-.31-.656-.211-.966l-.181-.06a3.303 3.303 0 01-.112.362c-.16.451-.375.539-.541.03-.127-.388-.082-.807-.145-1.207-.025-.159-.04-.32-.198-.392zm.03.905c.153.364-.008.82.237 1.176.25.364.716.168 1.02.397.108.081.022.256-.007.358-.1.347-.278.604-.465.905.655-.335.875-1.29.965-1.96h.03c-.026.596-.007 1.182 0 1.779.003.27-.037.582.272.633V4.46c.323.093.808.502 1.159.381.179-.061.342-.277.467-.411.094-.102.175-.212.244-.332h.03l-.12.965-.302-.06.663.473.261.226-.2.294-.875.636c.637-.094.958-.564 1.418-.935-.15.63-.491 1.262-.332 1.93h.03l.362-1.448c.274.13.37.476.633.633.383.228.919-.204 1.267-.331-.227.322-.57.548-.633.965l-.272-.12c.236.606.519 1.19.62 1.84.093.594-.024 1.183.016 1.78.02.275.133.517.179.784-.563.191-.666.98-1.207 1.236.043-.188.11-.377.11-.573 0-.14-.066-.282-.03-.422.073-.277.314-.508.412-.784.152-.43.05-.835-.009-1.267l.301.03-.758-1.177-.376-.573.139-.392c-.762.586-1.867 1.188-1.87 2.293l.271-.091.09.664-.422.06v.06c.353.1.722.149 1.056.306.244.114.514.265.682.479.56.71.112 1.818-.31 2.473-.213.33-.594.634-.734.996.382-.092.577-.457.792-.754.091-.127.17-.303.325-.362.24-.09.32.354.371.512.065.2.218.546.18.755-.071.401-.415.662-.34 1.116.166-.202.217-.604.482-.702.17-.062.347.095.513.12.36.053.73-.082.996-.326.285-.263.48-.686.408-1.083-.043-.24-.177-.476-.16-.724.012-.2.148-.362.22-.543.173-.427.152-.912-.257-1.189a.86.86 0 00-.362-.138c.033-.222.264-.706.53-.418.188.202.29.558.396.81.389.918.392 2.006-.163 2.865-.394.61-1.02 1.11-1.548 1.6l-.21-.604h-.061c-.07.36.185.772.332 1.086-.33-.075-.645-.415-.996-.362.099.17.748.572.242.754.003.148-.11.25-.2.362-.201.248-.454.618-.766.724l-.573-1.508h-.03c.084.661.314 1.305.61 1.9.154.307.403.611.506.935-.187-.159-.306-.413-.466-.603a6.313 6.313 0 00-.952-.892c-.227-.177-.45-.376-.754-.345.345.31.868.475.835 1.056-.01.165-.193.237-.322.296-.339.155-.67.322-1.026.438-.098.032-.279.12-.382.087-.11-.037-.097-.277-.109-.369-.037-.285.121-1.028-.172-1.146-.128 1.01.132 1.929.21 2.926h-.03c-.17-.737-.439-1.558-.838-2.202-.11-.177-.343-.597-.579-.543l.62 1.086.013.46-.452.08-1.297.033c.047-.373.13-.746.2-1.116.014-.081.074-.326-.078-.326-.14 0-.169.408-.189.507-.108.542-.204 1.106-.205 1.66h-.03c0-.913-.41-1.73-.784-2.535-.104.155.041.377.086.543.099.371.113.737.065 1.116-.612-.118-1.275-.278-1.84-.543.149-.357.576-.889.573-1.267-.554.556-.804 1.335-1.086 2.052h-.03l.12-1.448-.21-1.237c-.132.133-.06.399-.04.573.033.275.015.688-.188.9-.112.117-.226.014-.346-.034-.335-.136-.582-.36-.875-.564-.104-.072-.293-.15-.28-.302.032-.433.656-.638.672-1.026-.72.31-1.062 1.088-1.629 1.57.186-.785.782-1.703.634-2.535-.152.084-.145.295-.185.453a4.324 4.324 0 01-.388.965c-.4-.231-.72-.623-.983-.996-.073-.102-.233-.26-.235-.392-.002-.128.145-.274.225-.362.244-.265.54-.465.872-.603-.237-.147-.706.2-.965.272.175-.37.65-.732.513-1.177-.393.307-.66.97-.935 1.388h-.03l-.574-1.267.754.271c.023-.27-.36-.373-.573-.422.126-.328.476-.578.392-.965h-.06c-.087.28-.269.759-.573.844l-.09-.482h-.03c-.119.253.029.447-.04.687-.037.125-.217.106-.28.222-.085.158-.092.37-.164.539-.172.407-.5.706-.904.874l-.037-.54.459-.515-.483.361c-.062-.161-.203-.465-.12-.633.073-.145.254-.24.362-.362l-.483.241c-.163-.422.135-.3.302-.603-.122.07-.325.2-.471.133-.187-.085-.384-.64-.464-.827l.512-.09v-.03c-.242.03-.626.12-.663-.211h.633v-.03l-.712-.08-.194-.252-.421-.543c.251-.075.683-.075.935 0-.368-.387-1.024.182-1.327-.453l.754-.15v-.03c-.234 0-.67.135-.874.028-.054-.028-.094-.075-.134-.12-.388-.438.48-.478.766-.44.55.076.975.452 1.358.833.194.193.473.538.754.595.278.055.51-.122.724-.263 0 .212-.022.422.15.573 0-.416.005-.857.07-1.267.023-.152.083-.352.263-.38.225-.034.531.309.693.44.002-.234-.175-.432-.319-.603-.396-.47-1.025-.914-1.58-1.177v-.03c.823.142 1.442.625 2.322.392v-.06l-1.026-.15c.043-.321.276-.734.203-1.057-.1-.44-.568-.644-.746-1.025.306.118.63.29.966.297.188.005.336-.098.512-.14.485-.113.766.123 1.086.446.088-.305-.15-.559-.334-.784-.186-.229-.35-.46-.57-.659-.267-.24-.662-.52-.815-.85.25.049.49.256.694.402.359.255.715.503 1.116.691.211.1.578.265.754.054l-.965-.362c.07-.101.17-.188.221-.302.138-.307-.104-.568-.191-.844.185.068.345.227.543.26.464.078.734-.47 1.086-.653L9.11 6.45c.201-.168.112-.494.078-.724-.099-.664-.493-1.251-.59-1.9h.03c.381.816.835 1.696 1.598 2.201l-.277-.363-.477-.723c.095-.037.188-.077.269-.142.528-.423.078-1.012.002-1.517h.03c.065.155.14.314.235.453.441.638 1.023.536 1.696.482l-.18 1.328h.03c.089-.283.258-.516.318-.815.11-.544-.006-1.084-.017-1.629h.03c.048.322.179.63.282.936.162.482.293 1.01.653 1.387l-.331-1.357c.958-.001 1.219-.647 1.236-1.509zm-.271 2.082l-.483 2.172c.372-.227.45-1.053.483-1.448h.03c.065.348.096.696.238 1.025.056.13.117.305.275.302l-.386-1.357zm-2.956.392c.006.771.387 1.473.24 2.262.146-.088.15-.295.152-.452.004-.365-.06-.723-.06-1.086h.03c.105.364.39 1.09.814 1.146-.05-.196-.211-.344-.319-.513-.238-.374-.472-1.13-.857-1.357zm6.184.332c-.336.526-.736 1.245-1.237 1.629v.03c.38-.068.791-.549.905-.905h.03c-.005.536-.251 1.105-.03 1.629h.03c.16-.543.077-1.184.215-1.75.043-.177.203-.473.087-.633zM14.69 6.57c-.178.402-.265.775-.634 1.056v.06c.265.07.45-.262.513-.482h.03c.026.203.05.624.272.694l-.149-.694zm-6.456.03c.065.743 1.063 1.244.935 2.052.16-.094.119-.269.065-.423-.112-.317-.298-.596-.427-.905.289.264.716.562 1.117.393l-.633-.263zm4.163.242c-.091.3-.347.886-.241 1.176h.06l.211-.724h.03c.075.273.153.687.483.724l-.483-1.176zm-2.021.754l.15 1.267h.061l-.03-.905c.197.137.463.474.724.362-.1-.11-.247-.129-.362-.222-.187-.151-.286-.482-.543-.502zm6.636.18c-.318.32-.584.539-1.025.664v.061c.261.075.514-.07.724-.211-.035.177-.26.64-.09.754l.289-.875zm1.539.624c.138.01.242.186.323.282.239.279.508.575.612.935-.697-.144-1.452-.045-2.142.12.154-.405.446-.834.785-1.1.115-.092.258-.25.422-.237zm-6.697.07l-.181.936c.151-.115.187-.481.211-.664l.272.302a1.058 1.058 0 00-.302-.573zm2.956.091l-.573.573.543-.392.09.543c.106-.154.05-.578-.06-.724zm-6.334.078a.252.252 0 00-.06.013v.03c.253.256.463.61.621.935.088.179.063.376.253.483-.015-.353-.166-.62-.302-.935.214.124.5.31.754.24v-.06c-.342-.152-.607-.281-.905-.518-.11-.088-.224-.2-.361-.188zm-2.082.284c.029.255.237.35.422.49a3.5 3.5 0 01.687.657c.127.166.205.452.37.573-.036-.444-.298-.966-.725-1.147v-.03c.434.084.867.246 1.297.06v-.06l-.513-.02zm14.027.09c.296.115.613.522.724.815l-.664-.09zm-7.3.03l-.271.514.301-.332.181.302zm5.95.712a.536.536 0 01.172.031c.365.143.267.9.19 1.188-.061.234-.17.495-.4.604-.167-.3-.415-.496-.724-.64-.154-.073-.41-.101-.517-.243-.103-.137-.208-.646-.068-.78.152-.147.57-.117.766-.117.163 0 .392-.051.581-.043zm-3.054.013l-.513.392.453-.241-.06.362c.128-.09.175-.371.12-.513zm4.404.18c.136.011.37-.002.47.1.331.34.145 1.25-.259 1.44l-.12-.695c.032.002.062 0 .09-.003v.003h.09l-.04-.013c.356-.085.295-.577-.051-.59l-.09-.03.049.032-.018.001v-.003h-.06l.01.011c-.023.005-.046.01-.071.02zm-1.538.122c-.062.063-.152.11-.198.187-.318.545.886.559.546-.03-.039-.068-.108-.111-.167-.157l-.121.06h-.06zm-6.335.12c0 .154-.03.31.12.392v-.301l.363.12zm-1.676.086c-.046.002-.092.005-.134.005.053.194.137.36.302.482l-.181-.392.362.03c-.07-.127-.211-.131-.349-.125zm3.685.011c-.09.01-.168.168-.169.325l.15-.271.182.12c-.05-.132-.109-.18-.163-.174zm-4.845.084l-.513.09.423.513-.241-.422.361-.06zm-2.655.42c-.307.013-.66.365-.904.515v.06l.875.302c-.018-.229-.315-.297-.513-.331l.603-.544a.386.386 0 00-.06-.002zm1.6.063l-1.237.332v.06l.663.238.393.275c-.043-.32-.383-.375-.604-.543.28-.053.66-.058.785-.362zm3.107.332c-.129.02-.23.12-.091.21zm.995.18l-.03.212c.094-.056.11-.105.09-.211zm1.357 0c-.117.035-.214.118-.09.212zm1.117.302l-.302.09v.121zm1.146.03v.362c.113-.11.113-.25 0-.362zm4.272.179c.425.004.846.395.75.847-.062.29-.242.605-.528.718-.149.06-.486.04-.498-.175-.01-.2.388-.478.468-.694-.558.427-.9.79-1.659.694v-.03c.447-.331.634-.895 1.059-1.224a.645.645 0 01.408-.136zm-9.943.032c-.146.076-.235.236-.272.393l.362.09-.2-.193zm-4.585.061l-1.147.603c.04.225.262.104.423.093.23-.015.657.06.784.27l.211-.03c-.054-.342-.546-.342-.814-.363.197-.2.48-.259.543-.573zm5.822.241l-.332.423.422.15-.302-.18c.063-.132.31-.247.212-.393zm-2.625.09l-.362.333c.142.047.468.233.573.09l-.392-.15zm7.813 0l.422.333v.06l-.392.211a.938.938 0 00.543-.211.883.883 0 00-.573-.392zm-9.683.121c-.183.41-.464.743-.784 1.056-.184.179-.471.346-.543.603L7.45 13.8l.694-.14c-.414-.296-1.14.033-1.539.21.275-.55.813-.769.935-1.418l-.03-.03zm5.701.03c-.13.043-.146.149-.18.272l.18.03zm1.237.212l.03.332a.503.503 0 00.272-.332l-.212.15zm-4.193.422c-.13.038-.2.131-.06.211zm5.34.181l-.031.422-.271-.18c.028.182.156.27.332.3l.03-.542zm-6.758.03c-.22.069-.596.692-.694.905.2-.008.895.018.996-.12l-.664-.091zm3.7.059c-.166.01-.327.105-.502.105-.507 0-1.34-.252-1.775.092-.396.314-.42.734-.669 1.132-.121.194-.336.325-.512.465-.065.052-.184.127-.159.227.03.122.238.187.34.233.228.105.477.187.724.238.131.027.328.022.44.103.204.148.135.653.163.876.227-.13.524-.52.633-.755-.241.073-.347.31-.513.483l-.09-.633c.705-.062 1.015-.833 1.43-1.296.253-.282.57-.405.893-.575-.19-.227-.455.013-.634.15-.479.37-.755.816-1.176 1.238l.241-.633h-.03c-.131.314-.288.65-.603.814l.12-.422h-.03c-.127.303-.27.452-.603.452l.301-.694h-.03l-.392.664-.12-.03.301-.573h-.03c-.152.244-.313.59-.633.512l.27-.512c-.15.118-.216.4-.394.471-.081.032-.235-.027-.202-.135.042-.14.272-.278.363-.397.31-.405.56-1.067 1.018-1.316.376-.205.947.054 1.358.05.235-.004.503-.084.573-.333a.427.427 0 00-.072-.001zm-7.591.092l-.03.181.12-.181zm14.875.029c.228.004.48.037.61.214.133.18.101.427.17.632.052-.216.046-1.024.477-.57.349.367.256 1.162-.087 1.502-.216.213-.735.343-.992.144-.393-.303-.494-.926-.608-1.378-.027-.109-.154-.36-.084-.461.058-.086.209-.08.3-.082.065 0 .138-.002.214-.001zm2.65.182c.569.103.615.907 1.117 1.147v.06c-.285.143-.38-.002-.573-.211l.211.392c-.233-.036-.283-.262-.422-.423l.21.453c-.346 0-.493-.057-.633-.392h-.03l.06.271-.214-.152.114-.39zm-4.735.03c-.123.036-.188.105-.09.212zm-4.163.242l.332.362.15-.362-.15.241zm3.047 0l-.03.452-.302-.18c-.017.198.288.424.453.512l-.06-.784zm-8.175.512c-.094.452-.417.859-.707 1.207-.138.166-.35.333-.41.543.5-.144 1.063-.652 1.6-.603-.138-.268-.783.103-1.026.15.196-.29.463-.542.59-.874.052-.14.086-.327-.047-.423zm6.998.272c-.23.036-.218.264-.271.452-.128-.127-.258-.303-.452-.271l.573.694zm-2.805.03l-.302.272-.03-.151h-.09l.03.392c.176-.03.358-.347.392-.513zm.815.483l-.151.392h-.03l-.242-.332.211.694h.03c.08-.202.365-.572.182-.754zm3.348.18l-.09.031.18.995c-.192-.168-.785-.942-1.025-.663.555.177.786.825 1.267 1.116l-.15-.573zm1.508.242c-.153.374.22.775.362 1.116-.392-.202-.74-.539-1.207-.543v.12c.672.06 1.03.747 1.569 1.057-.005-.563-.488-1.21-.664-1.75zm-6.123.453l-.212.03c.072.169.197.306.256.482.065.196.023.466.227.573.095-.212.327-.557.271-.784-.17.085-.252.268-.27.453h-.031zm-2.806.03c0 .592-.08 1.148-.241 1.72.21.007.32-.211.433-.363.225-.299.45-.628.804-.784v-.03c-.359-.047-.807.49-.935.784h-.03c.106-.41.2-.924.03-1.327zm5.31.03c-.244.093-.182.42-.182.633l-.693-.482c.038.123.136.16.228.245.18.167.337.557.586.6zm1.538.573c-.213.377.097 1.154.15 1.569h-.03c-.168-.355-.492-.649-.754-.935-.037-.04-.228-.301-.296-.192-.071.114.278.385.343.463.241.286.459.609.642.935.105.189.197.44.397.543-.15-.778-.39-1.586-.392-2.383zm-10.045.302c.223.066.35.219.362.452l-.694.483zm5.007.24l-.03.031c.147.405.293.742.364 1.177.034.202.013.465.179.603.17-.322.23-.695.385-1.026.09-.19.234-.356.188-.573-.29.143-.461.787-.543 1.086-.15-.399-.104-1.092-.543-1.297zm2.051.303c.341.677.594 1.314.785 2.05.212-.118.183-.329.18-.542-.005-.497.186-.99.152-1.478-.143.048-.168.194-.193.332-.06.329-.06.669-.14.995-.163-.38-.293-1.279-.784-1.357zm6.365.24l.453.665-.664-.302zM8.657 19.18c.647.057.205.652-.06.935zm8.296.724l.272.845c-.224-.157-.488-.414-.604-.664zm-5.502.455l.344.058-.272.965h-.03l-.06-.754zm2.85.174c.062 0 .121.013.169.053.163.138-.067.805-.141.977l-.332-.965c.086-.022.2-.063.304-.065Z" }, "child": [] }] })(props);
}
function SiNpm(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M1.763 0C.786 0 0 .786 0 1.763v20.474C0 23.214.786 24 1.763 24h20.474c.977 0 1.763-.786 1.763-1.763V1.763C24 .786 23.214 0 22.237 0zM5.13 5.323l13.837.019-.009 13.836h-3.464l.01-10.382h-3.456L12.04 19.17H5.113z" }, "child": [] }] })(props);
}
function SiNodedotjs(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M11.998,24c-0.321,0-0.641-0.084-0.922-0.247l-2.936-1.737c-0.438-0.245-0.224-0.332-0.08-0.383 c0.585-0.203,0.703-0.25,1.328-0.604c0.065-0.037,0.151-0.023,0.218,0.017l2.256,1.339c0.082,0.045,0.197,0.045,0.272,0l8.795-5.076 c0.082-0.047,0.134-0.141,0.134-0.238V6.921c0-0.099-0.053-0.192-0.137-0.242l-8.791-5.072c-0.081-0.047-0.189-0.047-0.271,0 L3.075,6.68C2.99,6.729,2.936,6.825,2.936,6.921v10.15c0,0.097,0.054,0.189,0.139,0.235l2.409,1.392 c1.307,0.654,2.108-0.116,2.108-0.89V7.787c0-0.142,0.114-0.253,0.256-0.253h1.115c0.139,0,0.255,0.112,0.255,0.253v10.021 c0,1.745-0.95,2.745-2.604,2.745c-0.508,0-0.909,0-2.026-0.551L2.28,18.675c-0.57-0.329-0.922-0.945-0.922-1.604V6.921 c0-0.659,0.353-1.275,0.922-1.603l8.795-5.082c0.557-0.315,1.296-0.315,1.848,0l8.794,5.082c0.57,0.329,0.924,0.944,0.924,1.603 v10.15c0,0.659-0.354,1.273-0.924,1.604l-8.794,5.078C12.643,23.916,12.324,24,11.998,24z M19.099,13.993 c0-1.9-1.284-2.406-3.987-2.763c-2.731-0.361-3.009-0.548-3.009-1.187c0-0.528,0.235-1.233,2.258-1.233 c1.807,0,2.473,0.389,2.747,1.607c0.024,0.115,0.129,0.199,0.247,0.199h1.141c0.071,0,0.138-0.031,0.186-0.081 c0.048-0.054,0.074-0.123,0.067-0.196c-0.177-2.098-1.571-3.076-4.388-3.076c-2.508,0-4.004,1.058-4.004,2.833 c0,1.925,1.488,2.457,3.895,2.695c2.88,0.282,3.103,0.703,3.103,1.269c0,0.983-0.789,1.402-2.642,1.402 c-2.327,0-2.839-0.584-3.011-1.742c-0.02-0.124-0.126-0.215-0.253-0.215h-1.137c-0.141,0-0.254,0.112-0.254,0.253 c0,1.482,0.806,3.248,4.655,3.248C17.501,17.007,19.099,15.91,19.099,13.993z" }, "child": [] }] })(props);
}
function SiNetlify(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M6.49 19.04h-.23L5.13 17.9v-.23l1.73-1.71h1.2l.15.15v1.2L6.5 19.04ZM5.13 6.31V6.1l1.13-1.13h.23L8.2 6.68v1.2l-.15.15h-1.2L5.13 6.31Zm9.96 9.09h-1.65l-.14-.13v-3.83c0-.68-.27-1.2-1.1-1.23-.42 0-.9 0-1.43.02l-.07.08v4.96l-.14.14H8.9l-.13-.14V8.73l.13-.14h3.7a2.6 2.6 0 0 1 2.61 2.6v4.08l-.13.14Zm-8.37-2.44H.14L0 12.82v-1.64l.14-.14h6.58l.14.14v1.64l-.14.14Zm17.14 0h-6.58l-.14-.14v-1.64l.14-.14h6.58l.14.14v1.64l-.14.14ZM11.05 6.55V1.64l.14-.14h1.65l.14.14v4.9l-.14.14h-1.65l-.14-.13Zm0 15.81v-4.9l.14-.14h1.65l.14.13v4.91l-.14.14h-1.65l-.14-.14Z" }, "child": [] }] })(props);
}
function SiNatsdotio(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M12.004 0H.404v18.807h9.938l1.714 1.602v-.026L15.966 24v-5.193h7.63V0H12.003zm7.578 14.45H15.38L6.898 6.519v7.93H4.116V4.376h4.349l8.344 7.784V4.375h2.773V14.45z" }, "child": [] }] })(props);
}
function SiMysql(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M16.405 5.501c-.115 0-.193.014-.274.033v.013h.014c.054.104.146.18.214.273.054.107.1.214.154.32l.014-.015c.094-.066.14-.172.14-.333-.04-.047-.046-.094-.08-.14-.04-.067-.126-.1-.18-.153zM5.77 18.695h-.927a50.854 50.854 0 00-.27-4.41h-.008l-1.41 4.41H2.45l-1.4-4.41h-.01a72.892 72.892 0 00-.195 4.41H0c.055-1.966.192-3.81.41-5.53h1.15l1.335 4.064h.008l1.347-4.064h1.095c.242 2.015.384 3.86.428 5.53zm4.017-4.08c-.378 2.045-.876 3.533-1.492 4.46-.482.716-1.01 1.073-1.583 1.073-.153 0-.34-.046-.566-.138v-.494c.11.017.24.026.386.026.268 0 .483-.075.647-.222.197-.18.295-.382.295-.605 0-.155-.077-.47-.23-.944L6.23 14.615h.91l.727 2.36c.164.536.233.91.205 1.123.4-1.064.678-2.227.835-3.483zm12.325 4.08h-2.63v-5.53h.885v4.85h1.745zm-3.32.135l-1.016-.5c.09-.076.177-.158.255-.25.433-.506.648-1.258.648-2.253 0-1.83-.718-2.746-2.155-2.746-.704 0-1.254.232-1.65.697-.43.508-.646 1.256-.646 2.245 0 .972.19 1.686.574 2.14.35.41.877.615 1.583.615.264 0 .506-.033.725-.098l1.325.772.36-.622zM15.5 17.588c-.225-.36-.337-.94-.337-1.736 0-1.393.424-2.09 1.27-2.09.443 0 .77.167.977.5.224.362.336.936.336 1.723 0 1.404-.424 2.108-1.27 2.108-.445 0-.77-.167-.978-.5zm-1.658-.425c0 .47-.172.856-.516 1.156-.344.3-.803.45-1.384.45-.543 0-1.064-.172-1.573-.515l.237-.476c.438.22.833.328 1.19.328.332 0 .593-.073.783-.22a.754.754 0 00.3-.615c0-.33-.23-.61-.648-.845-.388-.213-1.163-.657-1.163-.657-.422-.307-.632-.636-.632-1.177 0-.45.157-.81.47-1.085.315-.278.72-.415 1.22-.415.512 0 .98.136 1.4.41l-.213.476a2.726 2.726 0 00-1.064-.23c-.283 0-.502.068-.654.206a.685.685 0 00-.248.524c0 .328.234.61.666.85.393.215 1.187.67 1.187.67.433.305.648.63.648 1.168zm9.382-5.852c-.535-.014-.95.04-1.297.188-.1.04-.26.04-.274.167.055.053.063.14.11.214.08.134.218.313.346.407.14.11.28.216.427.31.26.16.555.255.81.416.145.094.293.213.44.313.073.05.12.14.214.172v-.02c-.046-.06-.06-.147-.105-.214-.067-.067-.134-.127-.2-.193a3.223 3.223 0 00-.695-.675c-.214-.146-.682-.35-.77-.595l-.013-.014c.146-.013.32-.066.46-.106.227-.06.435-.047.67-.106.106-.027.213-.06.32-.094v-.06c-.12-.12-.21-.283-.334-.395a8.867 8.867 0 00-1.104-.823c-.21-.134-.476-.22-.697-.334-.08-.04-.214-.06-.26-.127-.12-.146-.19-.34-.275-.514a17.69 17.69 0 01-.547-1.163c-.12-.262-.193-.523-.34-.763-.69-1.137-1.437-1.826-2.586-2.5-.247-.14-.543-.2-.856-.274-.167-.008-.334-.02-.5-.027-.11-.047-.216-.174-.31-.235-.38-.24-1.364-.76-1.644-.072-.18.434.267.862.422 1.082.115.153.26.328.34.5.047.116.06.235.107.356.106.294.207.622.347.897.073.14.153.287.247.413.054.073.146.107.167.227-.094.136-.1.334-.154.5-.24.757-.146 1.693.194 2.25.107.166.362.534.703.393.3-.12.234-.5.32-.835.02-.08.007-.133.048-.187v.015c.094.188.188.367.274.555.206.328.566.668.867.895.16.12.287.328.487.402v-.02h-.015c-.043-.058-.1-.086-.154-.133a3.445 3.445 0 01-.35-.4 8.76 8.76 0 01-.747-1.218c-.11-.21-.202-.436-.29-.643-.04-.08-.04-.2-.107-.24-.1.146-.247.273-.32.453-.127.288-.14.642-.188 1.01-.027.007-.014 0-.027.014-.214-.052-.287-.274-.367-.46-.2-.475-.233-1.238-.06-1.785.047-.14.247-.582.167-.716-.042-.127-.174-.2-.247-.303a2.478 2.478 0 01-.24-.427c-.16-.374-.24-.788-.414-1.162-.08-.173-.22-.354-.334-.513-.127-.18-.267-.307-.368-.52-.033-.073-.08-.194-.027-.274.014-.054.042-.075.094-.09.088-.072.335.022.422.062.247.1.455.194.662.334.094.066.195.193.315.226h.14c.214.047.455.014.655.073.355.114.675.28.962.46a5.953 5.953 0 012.085 2.286c.08.154.115.295.188.455.14.33.313.663.455.982.14.315.275.636.476.897.1.14.502.213.682.286.133.06.34.115.46.188.23.14.454.3.67.454.11.076.443.243.463.378z" }, "child": [] }] })(props);
}
function SiMongodb(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M17.193 9.555c-1.264-5.58-4.252-7.414-4.573-8.115-.28-.394-.53-.954-.735-1.44-.036.495-.055.685-.523 1.184-.723.566-4.438 3.682-4.74 10.02-.282 5.912 4.27 9.435 4.888 9.884l.07.05A73.49 73.49 0 0111.91 24h.481c.114-1.032.284-2.056.51-3.07.417-.296.604-.463.85-.693a11.342 11.342 0 003.639-8.464c.01-.814-.103-1.662-.197-2.218zm-5.336 8.195s0-8.291.275-8.29c.213 0 .49 10.695.49 10.695-.381-.045-.765-1.76-.765-2.405z" }, "child": [] }] })(props);
}
function SiMinio(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M13.2072.006c-.6216-.0478-1.2.1943-1.6211.582a2.15 2.15 0 0 0-.0938 3.0352l3.4082 3.5507a3.042 3.042 0 0 1-.664 4.6875l-.463.2383V7.2853a15.4198 15.4198 0 0 0-8.0174 10.4862v.0176l6.5487-3.3281v7.621L13.7794 24V13.6817l.8965-.4629a4.4432 4.4432 0 0 0 1.2207-7.0292l-3.371-3.5254a.7489.7489 0 0 1 .037-1.0547.7522.7522 0 0 1 1.0567.0371l.4668.4863-.006.0059 4.0704 4.2441a.0566.0566 0 0 0 .082 0 .06.06 0 0 0 0-.0703l-3.1406-5.1425-.1484.1425.1484-.1445C14.4945.3926 13.8287.0538 13.2072.006Zm-.9024 9.8652v2.9941l-4.1523 2.1484a13.9787 13.9787 0 0 1 2.7676-3.9277 14.1784 14.1784 0 0 1 1.3847-1.2148z" }, "child": [] }] })(props);
}
function SiKubernetes(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M10.204 14.35l.007.01-.999 2.413a5.171 5.171 0 0 1-2.075-2.597l2.578-.437.004.005a.44.44 0 0 1 .484.606zm-.833-2.129a.44.44 0 0 0 .173-.756l.002-.011L7.585 9.7a5.143 5.143 0 0 0-.73 3.255l2.514-.725.002-.009zm1.145-1.98a.44.44 0 0 0 .699-.337l.01-.005.15-2.62a5.144 5.144 0 0 0-3.01 1.442l2.147 1.523.004-.002zm.76 2.75l.723.349.722-.347.18-.78-.5-.623h-.804l-.5.623.179.779zm1.5-3.095a.44.44 0 0 0 .7.336l.008.003 2.134-1.513a5.188 5.188 0 0 0-2.992-1.442l.148 2.615.002.001zm10.876 5.97l-5.773 7.181a1.6 1.6 0 0 1-1.248.594l-9.261.003a1.6 1.6 0 0 1-1.247-.596l-5.776-7.18a1.583 1.583 0 0 1-.307-1.34L2.1 5.573c.108-.47.425-.864.863-1.073L11.305.513a1.606 1.606 0 0 1 1.385 0l8.345 3.985c.438.209.755.604.863 1.073l2.062 8.955c.108.47-.005.963-.308 1.34zm-3.289-2.057c-.042-.01-.103-.026-.145-.034-.174-.033-.315-.025-.479-.038-.35-.037-.638-.067-.895-.148-.105-.04-.18-.165-.216-.216l-.201-.059a6.45 6.45 0 0 0-.105-2.332 6.465 6.465 0 0 0-.936-2.163c.052-.047.15-.133.177-.159.008-.09.001-.183.094-.282.197-.185.444-.338.743-.522.142-.084.273-.137.415-.242.032-.024.076-.062.11-.089.24-.191.295-.52.123-.736-.172-.216-.506-.236-.745-.045-.034.027-.08.062-.111.088-.134.116-.217.23-.33.35-.246.25-.45.458-.673.609-.097.056-.239.037-.303.033l-.19.135a6.545 6.545 0 0 0-4.146-2.003l-.012-.223c-.065-.062-.143-.115-.163-.25-.022-.268.015-.557.057-.905.023-.163.061-.298.068-.475.001-.04-.001-.099-.001-.142 0-.306-.224-.555-.5-.555-.275 0-.499.249-.499.555l.001.014c0 .041-.002.092 0 .128.006.177.044.312.067.475.042.348.078.637.056.906a.545.545 0 0 1-.162.258l-.012.211a6.424 6.424 0 0 0-4.166 2.003 8.373 8.373 0 0 1-.18-.128c-.09.012-.18.04-.297-.029-.223-.15-.427-.358-.673-.608-.113-.12-.195-.234-.329-.349-.03-.026-.077-.062-.111-.088a.594.594 0 0 0-.348-.132.481.481 0 0 0-.398.176c-.172.216-.117.546.123.737l.007.005.104.083c.142.105.272.159.414.242.299.185.546.338.743.522.076.082.09.226.1.288l.16.143a6.462 6.462 0 0 0-1.02 4.506l-.208.06c-.055.072-.133.184-.215.217-.257.081-.546.11-.895.147-.164.014-.305.006-.48.039-.037.007-.09.02-.133.03l-.004.002-.007.002c-.295.071-.484.342-.423.608.061.267.349.429.645.365l.007-.001.01-.003.129-.029c.17-.046.294-.113.448-.172.33-.118.604-.217.87-.256.112-.009.23.069.288.101l.217-.037a6.5 6.5 0 0 0 2.88 3.596l-.09.218c.033.084.069.199.044.282-.097.252-.263.517-.452.813-.091.136-.185.242-.268.399-.02.037-.045.095-.064.134-.128.275-.034.591.213.71.248.12.556-.007.69-.282v-.002c.02-.039.046-.09.062-.127.07-.162.094-.301.144-.458.132-.332.205-.68.387-.897.05-.06.13-.082.215-.105l.113-.205a6.453 6.453 0 0 0 4.609.012l.106.192c.086.028.18.042.256.155.136.232.229.507.342.84.05.156.074.295.145.457.016.037.043.09.062.129.133.276.442.402.69.282.247-.118.341-.435.213-.71-.02-.039-.045-.096-.065-.134-.083-.156-.177-.261-.268-.398-.19-.296-.346-.541-.443-.793-.04-.13.007-.21.038-.294-.018-.022-.059-.144-.083-.202a6.499 6.499 0 0 0 2.88-3.622c.064.01.176.03.213.038.075-.05.144-.114.28-.104.266.039.54.138.87.256.154.06.277.128.448.173.036.01.088.019.13.028l.009.003.007.001c.297.064.584-.098.645-.365.06-.266-.128-.537-.423-.608zM16.4 9.701l-1.95 1.746v.005a.44.44 0 0 0 .173.757l.003.01 2.526.728a5.199 5.199 0 0 0-.108-1.674A5.208 5.208 0 0 0 16.4 9.7zm-4.013 5.325a.437.437 0 0 0-.404-.232.44.44 0 0 0-.372.233h-.002l-1.268 2.292a5.164 5.164 0 0 0 3.326.003l-1.27-2.296h-.01zm1.888-1.293a.44.44 0 0 0-.27.036.44.44 0 0 0-.214.572l-.003.004 1.01 2.438a5.15 5.15 0 0 0 2.081-2.615l-2.6-.44-.004.005z" }, "child": [] }] })(props);
}
function SiHomebrew(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M7.938 0a.214.214 0 0 0-.206.156c-.316 1.104.179 2.15.838 2.935.153.181.313.347.476.501a2.039 2.039 0 0 0-.665.02c-1.184.233-2.193.985-2.74 2.532a3.893 3.893 0 0 0-.2 1.466 1.565 1.565 0 0 0-1.156 1.504 1.59 1.59 0 0 0 1.227 1.541l.026 12.046c0 .195.1.377.264.482a.214.214 0 0 0 .008.005c.537.31 2.047.812 5.21.812 3.238 0 4.7-.678 5.181-1.04a.214.214 0 0 0 .008-.007.571.571 0 0 0 .206-.439c.002-.344.002-1.136.002-1.604a.143.143 0 0 1 .147-.144c.397.006.869.006 1.318.005a1.826 1.826 0 0 0 1.832-1.825v-5.804a1.826 1.826 0 0 0-1.825-1.826H16.56a.14.14 0 0 1-.143-.144V10.6h.007v-.001a1.573 1.573 0 0 0 1.356-1.556c0-.816-.627-1.489-1.424-1.563-.025-1.438-.437-2.126-.736-2.58a.214.214 0 0 0-.005-.007c-.364-.51-1.193-1.282-2.275-1.316-.503-.016-.842.124-1.125.254-.217.1-.42.177-.67.22.002-1.286.945-1.981.945-1.981a.214.214 0 0 0 .05-.298s-.087-.122-.21-.26c-.121-.136-.269-.294-.47-.378a.214.214 0 0 0-.079-.017.214.214 0 0 0-.145.055 4.308 4.308 0 0 0-.875 1.101 3.42 3.42 0 0 0-.133.273 3.497 3.497 0 0 0-.381-.846C9.794.978 9.063.436 8.017.016A.214.214 0 0 0 7.939 0zm.156.524c.85.378 1.43.83 1.79 1.403.274.438.426.962.484 1.584a3.07 3.07 0 0 0-.012.462 6.897 6.897 0 0 1-.168-.052 5.487 5.487 0 0 1-1.29-1.106c-.551-.657-.935-1.46-.804-2.291zM11.8 1.618c.07.054.141.101.212.18.034.039.032.04.058.073-.332.308-1.07 1.144-.952 2.453a.214.214 0 0 0 .222.195c.469-.017.782-.172 1.056-.299.273-.126.508-.228.931-.214.875.027 1.639.715 1.939 1.134.295.449.65 1 .663 2.36a1.66 1.66 0 0 0-.41.142 1.938 1.938 0 0 0-1.77-1.16 1.94 1.94 0 0 0-1.87 1.448 1.783 1.783 0 0 0-1.356-.64c-.484 0-.91.205-1.233.517a1.873 1.873 0 0 0-1.85-1.625c-.649 0-1.218.335-1.552.84a3.1 3.1 0 0 1 .157-.735c.51-1.437 1.355-2.045 2.42-2.254.367-.073.664-.011.99.095.325.106.671.262 1.094.342a.214.214 0 0 0 .252-.245c-.112-.67.073-1.266.336-1.744a3.71 3.71 0 0 1 .663-.863zM7.44 6.611a1.442 1.442 0 0 1 1.363 1.925.214.214 0 0 0 .168.283h.005a.214.214 0 0 0 .238-.146 1.373 1.373 0 0 1 2.613-.01.214.214 0 0 0 .417-.09 1.509 1.509 0 0 1 1.504-1.664c.678 0 1.249.445 1.442 1.056a.214.214 0 0 0 .259.143l.15-.04a.214.214 0 0 0 .051-.02 1.139 1.139 0 0 1 1.702.995 1.14 1.14 0 0 1-.985 1.131.214.214 0 0 0-.001 0 2.215 2.215 0 0 0-.485.126 10.65 10.65 0 0 1-1.176.365.214.214 0 0 0-.162.186 1.276 1.276 0 0 1-.146.478 2.07 2.07 0 0 0-.239 1.111l.001.151a.438.438 0 0 1-.16.36.665.665 0 0 1-.43.14.586.586 0 0 1-.588-.59.803.803 0 0 0-.38-.681.214.214 0 0 0-.002-.002c-.24-.145-.43-.37-.532-.636a.214.214 0 0 0-.207-.138 19.469 19.469 0 0 1-5.37-.6l-.003-.002a9.007 9.007 0 0 0-.838-.194h.003a1.16 1.16 0 0 1-.937-1.134c0-.619.488-1.118 1.101-1.14a.214.214 0 0 0 .204-.176 1.443 1.443 0 0 1 1.42-1.187zm8.549 4.106v.455c0 .314.259.573.572.573h1.329a1.397 1.397 0 0 1 1.397 1.397v5.804a1.396 1.396 0 0 1-1.402 1.396.214.214 0 0 0-.002 0c-.448.002-.918 0-1.31-.005a.573.573 0 0 0-.584.573c0 .468 0 1.262-.002 1.603a.214.214 0 0 0 0 .001c0 .042-.019.08-.05.107-.346.26-1.75.95-4.915.95-3.107 0-4.587-.52-4.99-.752a.143.143 0 0 1-.065-.118l-.025-11.955c.145.033.288.07.431.11a.214.214 0 0 0 .003 0c.115.031.246.064.383.097v10.37c0 .129.069.247.18.31.453.217 1.767.732 4.071.732 2.32 0 3.595-.626 4.022-.884a.357.357 0 0 0 .164-.3l.001-10.21c.267-.075.531-.158.792-.254zm-7.99.894a.493.493 0 0 1 .494.493v8.578a.493.493 0 0 1-.493.493.493.493 0 0 1-.494-.493v-8.578A.493.493 0 0 1 8 11.611zm8.652 1.14a.663.663 0 0 0-.662.662v5.208a.663.663 0 0 0 .662.662h1.14a.663.663 0 0 0 .662-.662v-5.209a.663.663 0 0 0-.662-.662zm0 .428h1.14a.233.233 0 0 1 .233.233v5.21a.233.233 0 0 1-.233.232h-1.14a.233.233 0 0 1-.233-.233v-5.209a.233.233 0 0 1 .233-.233z" }, "child": [] }] })(props);
}
function SiHeroku(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M20.61 0H3.39C2.189 0 1.23.96 1.23 2.16v19.681c0 1.198.959 2.159 2.16 2.159h17.22c1.2 0 2.159-.961 2.159-2.159V2.16C22.77.96 21.811 0 20.61 0zm.96 21.841c0 .539-.421.96-.96.96H3.39c-.54 0-.96-.421-.96-.96V2.16c0-.54.42-.961.96-.961h17.22c.539 0 .96.421.96.961v19.681zM6.63 20.399L9.33 18l-2.7-2.4v4.799zm9.72-9.719c-.479-.48-1.379-1.08-2.879-1.08-1.621 0-3.301.421-4.5.84V3.6h-2.4v10.38l1.68-.78s2.76-1.26 5.16-1.26c1.2 0 1.5.66 1.5 1.26v7.2h2.4v-7.2c.059-.179.059-1.501-.961-2.52zM13.17 7.5h2.4c1.08-1.26 1.62-2.521 1.8-3.9h-2.399c-.241 1.379-.841 2.64-1.801 3.9z" }, "child": [] }] })(props);
}
function SiHelm(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M12.337 0c-.475 0-.861 1.016-.861 2.269 0 .527.069 1.011.183 1.396a8.514 8.514 0 0 0-3.961 1.22 5.229 5.229 0 0 0-.595-1.093c-.606-.866-1.34-1.436-1.79-1.43a.381.381 0 0 0-.217.066c-.39.273-.123 1.326.596 2.353.267.381.559.705.84.948a8.683 8.683 0 0 0-1.528 1.716h1.734a7.179 7.179 0 0 1 5.381-2.421 7.18 7.18 0 0 1 5.382 2.42h1.733a8.687 8.687 0 0 0-1.32-1.53c.35-.249.735-.643 1.078-1.133.719-1.027.986-2.08.596-2.353a.382.382 0 0 0-.217-.065c-.45-.007-1.184.563-1.79 1.43a4.897 4.897 0 0 0-.676 1.325 8.52 8.52 0 0 0-3.899-1.42c.12-.39.193-.887.193-1.429 0-1.253-.386-2.269-.862-2.269zM1.624 9.443v5.162h1.358v-1.968h1.64v1.968h1.357V9.443H4.62v1.838H2.98V9.443zm5.912 0v5.162h3.21v-1.108H8.893v-.95h1.64v-1.142h-1.64v-.84h1.853V9.443zm4.698 0v5.162h3.218v-1.362h-1.86v-3.8zm4.706 0v5.162h1.364v-2.643l1.357 1.225 1.35-1.232v2.65h1.365V9.443h-.614l-2.1 1.914-2.109-1.914zm-11.82 7.28a8.688 8.688 0 0 0 1.412 1.548 5.206 5.206 0 0 0-.841.948c-.719 1.027-.985 2.08-.596 2.353.39.273 1.289-.338 2.007-1.364a5.23 5.23 0 0 0 .595-1.092 8.514 8.514 0 0 0 3.961 1.219 5.01 5.01 0 0 0-.183 1.396c0 1.253.386 2.269.861 2.269.476 0 .862-1.016.862-2.269 0-.542-.072-1.04-.193-1.43a8.52 8.52 0 0 0 3.9-1.42c.121.4.352.865.675 1.327.719 1.026 1.617 1.637 2.007 1.364.39-.273.123-1.326-.596-2.353-.343-.49-.727-.885-1.077-1.135a8.69 8.69 0 0 0 1.202-1.36h-1.771a7.174 7.174 0 0 1-5.227 2.252 7.174 7.174 0 0 1-5.226-2.252z" }, "child": [] }] })(props);
}
function SiGradle(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M22.695 4.297a3.807 3.807 0 0 0-5.29-.09.368.368 0 0 0 0 .533l.46.47a.363.363 0 0 0 .474.032 2.182 2.182 0 0 1 2.86 3.291c-3.023 3.02-7.056-5.447-16.211-1.083a1.24 1.24 0 0 0-.534 1.745l1.571 2.713a1.238 1.238 0 0 0 1.681.461l.037-.02-.029.02.688-.384a16.083 16.083 0 0 0 2.193-1.635.384.384 0 0 1 .499-.016.357.357 0 0 1 .016.534 16.435 16.435 0 0 1-2.316 1.741H8.77l-.696.39a1.958 1.958 0 0 1-.963.25 1.987 1.987 0 0 1-1.726-.989L3.9 9.696C1.06 11.72-.686 15.603.26 20.522a.363.363 0 0 0 .354.296h1.675a.363.363 0 0 0 .37-.331 2.478 2.478 0 0 1 4.915 0 .36.36 0 0 0 .357.317h1.638a.363.363 0 0 0 .357-.317 2.478 2.478 0 0 1 4.914 0 .363.363 0 0 0 .358.317h1.627a.363.363 0 0 0 .363-.357c.037-2.294.656-4.93 2.42-6.25 6.108-4.57 4.502-8.486 3.088-9.9zm-6.229 6.901l-1.165-.584a.73.73 0 1 1 1.165.587z" }, "child": [] }] })(props);
}
function SiGooglecloud(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M12.19 2.38a9.344 9.344 0 0 0-9.234 6.893c.053-.02-.055.013 0 0-3.875 2.551-3.922 8.11-.247 10.941l.006-.007-.007.03a6.717 6.717 0 0 0 4.077 1.356h5.173l.03.03h5.192c6.687.053 9.376-8.605 3.835-12.35a9.365 9.365 0 0 0-2.821-4.552l-.043.043.006-.05A9.344 9.344 0 0 0 12.19 2.38zm-.358 4.146c1.244-.04 2.518.368 3.486 1.15a5.186 5.186 0 0 1 1.862 4.078v.518c3.53-.07 3.53 5.262 0 5.193h-5.193l-.008.009v-.04H6.785a2.59 2.59 0 0 1-1.067-.23h.001a2.597 2.597 0 1 1 3.437-3.437l3.013-3.012A6.747 6.747 0 0 0 8.11 8.24c.018-.01.04-.026.054-.023a5.186 5.186 0 0 1 3.67-1.69z" }, "child": [] }] })(props);
}
function SiGo(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M1.811 10.231c-.047 0-.058-.023-.035-.059l.246-.315c.023-.035.081-.058.128-.058h4.172c.046 0 .058.035.035.07l-.199.303c-.023.036-.082.07-.117.07zM.047 11.306c-.047 0-.059-.023-.035-.058l.245-.316c.023-.035.082-.058.129-.058h5.328c.047 0 .07.035.058.07l-.093.28c-.012.047-.058.07-.105.07zm2.828 1.075c-.047 0-.059-.035-.035-.07l.163-.292c.023-.035.07-.07.117-.07h2.337c.047 0 .07.035.07.082l-.023.28c0 .047-.047.082-.082.082zm12.129-2.36c-.736.187-1.239.327-1.963.514-.176.046-.187.058-.34-.117-.174-.199-.303-.327-.548-.444-.737-.362-1.45-.257-2.115.175-.795.514-1.204 1.274-1.192 2.22.011.935.654 1.706 1.577 1.835.795.105 1.46-.175 1.987-.77.105-.13.198-.27.315-.434H10.47c-.245 0-.304-.152-.222-.35.152-.362.432-.97.596-1.274a.315.315 0 01.292-.187h4.253c-.023.316-.023.631-.07.947a4.983 4.983 0 01-.958 2.29c-.841 1.11-1.94 1.8-3.33 1.986-1.145.152-2.209-.07-3.143-.77-.865-.655-1.356-1.52-1.484-2.595-.152-1.274.222-2.419.993-3.424.83-1.086 1.928-1.776 3.272-2.02 1.098-.2 2.15-.07 3.096.571.62.41 1.063.97 1.356 1.648.07.105.023.164-.117.2m3.868 6.461c-1.064-.024-2.034-.328-2.852-1.029a3.665 3.665 0 01-1.262-2.255c-.21-1.32.152-2.489.947-3.529.853-1.122 1.881-1.706 3.272-1.95 1.192-.21 2.314-.095 3.33.595.923.63 1.496 1.484 1.648 2.605.198 1.578-.257 2.863-1.344 3.962-.771.783-1.718 1.273-2.805 1.495-.315.06-.63.07-.934.106zm2.78-4.72c-.011-.153-.011-.27-.034-.387-.21-1.157-1.274-1.81-2.384-1.554-1.087.245-1.788.935-2.045 2.033-.21.912.234 1.835 1.075 2.21.643.28 1.285.244 1.905-.07.923-.48 1.425-1.228 1.484-2.233z" }, "child": [] }] })(props);
}
function SiGitlab(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "m23.6004 9.5927-.0337-.0862L20.3.9814a.851.851 0 0 0-.3362-.405.8748.8748 0 0 0-.9997.0539.8748.8748 0 0 0-.29.4399l-2.2055 6.748H7.5375l-2.2057-6.748a.8573.8573 0 0 0-.29-.4412.8748.8748 0 0 0-.9997-.0537.8585.8585 0 0 0-.3362.4049L.4332 9.5015l-.0325.0862a6.0657 6.0657 0 0 0 2.0119 7.0105l.0113.0087.03.0213 4.976 3.7264 2.462 1.8633 1.4995 1.1321a1.0085 1.0085 0 0 0 1.2197 0l1.4995-1.1321 2.4619-1.8633 5.006-3.7489.0125-.01a6.0682 6.0682 0 0 0 2.0094-7.003z" }, "child": [] }] })(props);
}
function SiGithubactions(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M10.984 13.836a.5.5 0 0 1-.353-.146l-.745-.743a.5.5 0 1 1 .706-.708l.392.391 1.181-1.18a.5.5 0 0 1 .708.707l-1.535 1.533a.504.504 0 0 1-.354.146zm9.353-.147l1.534-1.532a.5.5 0 0 0-.707-.707l-1.181 1.18-.392-.391a.5.5 0 1 0-.706.708l.746.743a.497.497 0 0 0 .706-.001zM4.527 7.452l2.557-1.585A1 1 0 0 0 7.09 4.17L4.533 2.56A1 1 0 0 0 3 3.406v3.196a1.001 1.001 0 0 0 1.527.85zm2.03-2.436L4 6.602V3.406l2.557 1.61zM24 12.5c0 1.93-1.57 3.5-3.5 3.5a3.503 3.503 0 0 1-3.46-3h-2.08a3.503 3.503 0 0 1-3.46 3 3.502 3.502 0 0 1-3.46-3h-.558c-.972 0-1.85-.399-2.482-1.042V17c0 1.654 1.346 3 3 3h.04c.244-1.693 1.7-3 3.46-3 1.93 0 3.5 1.57 3.5 3.5S13.43 24 11.5 24a3.502 3.502 0 0 1-3.46-3H8c-2.206 0-4-1.794-4-4V9.899A5.008 5.008 0 0 1 0 5c0-2.757 2.243-5 5-5s5 2.243 5 5a5.005 5.005 0 0 1-4.952 4.998A2.482 2.482 0 0 0 7.482 12h.558c.244-1.693 1.7-3 3.46-3a3.502 3.502 0 0 1 3.46 3h2.08a3.503 3.503 0 0 1 3.46-3c1.93 0 3.5 1.57 3.5 3.5zm-15 8c0 1.378 1.122 2.5 2.5 2.5s2.5-1.122 2.5-2.5-1.122-2.5-2.5-2.5S9 19.122 9 20.5zM5 9c2.206 0 4-1.794 4-4S7.206 1 5 1 1 2.794 1 5s1.794 4 4 4zm9 3.5c0-1.378-1.122-2.5-2.5-2.5S9 11.122 9 12.5s1.122 2.5 2.5 2.5 2.5-1.122 2.5-2.5zm9 0c0-1.378-1.122-2.5-2.5-2.5S18 11.122 18 12.5s1.122 2.5 2.5 2.5 2.5-1.122 2.5-2.5zm-13 8a.5.5 0 1 0 1 0 .5.5 0 0 0-1 0zm2 0a.5.5 0 1 0 1 0 .5.5 0 0 0-1 0zm12 0c0 1.93-1.57 3.5-3.5 3.5a3.503 3.503 0 0 1-3.46-3.002c-.007.001-.013.005-.021.005l-.506.017h-.017a.5.5 0 0 1-.016-.999l.506-.017c.018-.002.035.006.052.007A3.503 3.503 0 0 1 20.5 17c1.93 0 3.5 1.57 3.5 3.5zm-1 0c0-1.378-1.122-2.5-2.5-2.5S18 19.122 18 20.5s1.122 2.5 2.5 2.5 2.5-1.122 2.5-2.5z" }, "child": [] }] })(props);
}
function SiGithub(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" }, "child": [] }] })(props);
}
function SiGit(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M23.546 10.93L13.067.452c-.604-.603-1.582-.603-2.188 0L8.708 2.627l2.76 2.76c.645-.215 1.379-.07 1.889.441.516.515.658 1.258.438 1.9l2.658 2.66c.645-.223 1.387-.078 1.9.435.721.72.721 1.884 0 2.604-.719.719-1.881.719-2.6 0-.539-.541-.674-1.337-.404-1.996L12.86 8.955v6.525c.176.086.342.203.488.348.713.721.713 1.883 0 2.6-.719.721-1.889.721-2.609 0-.719-.719-.719-1.879 0-2.598.182-.18.387-.316.605-.406V8.835c-.217-.091-.424-.222-.6-.401-.545-.545-.676-1.342-.396-2.009L7.636 3.7.45 10.881c-.6.605-.6 1.584 0 2.189l10.48 10.477c.604.604 1.582.604 2.186 0l10.43-10.43c.605-.603.605-1.582 0-2.187" }, "child": [] }] })(props);
}
function SiElasticsearch(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M13.394 0C8.683 0 4.609 2.716 2.644 6.667h15.641a4.77 4.77 0 0 0 3.073-1.11c.446-.375.864-.785 1.247-1.243l.001-.002A11.974 11.974 0 0 0 13.394 0zM1.804 8.889a12.009 12.009 0 0 0 0 6.222h14.7a3.111 3.111 0 1 0 0-6.222zm.84 8.444C4.61 21.283 8.684 24 13.395 24c3.701 0 7.011-1.677 9.212-4.312l-.001-.002a9.958 9.958 0 0 0-1.247-1.243 4.77 4.77 0 0 0-3.073-1.11z" }, "child": [] }] })(props);
}
function SiDocker(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M13.983 11.078h2.119a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.119a.185.185 0 00-.185.185v1.888c0 .102.083.185.185.185m-2.954-5.43h2.118a.186.186 0 00.186-.186V3.574a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m0 2.716h2.118a.187.187 0 00.186-.186V6.29a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.887c0 .102.082.185.185.186m-2.93 0h2.12a.186.186 0 00.184-.186V6.29a.185.185 0 00-.185-.185H8.1a.185.185 0 00-.185.185v1.887c0 .102.083.185.185.186m-2.964 0h2.119a.186.186 0 00.185-.186V6.29a.185.185 0 00-.185-.185H5.136a.186.186 0 00-.186.185v1.887c0 .102.084.185.186.186m5.893 2.715h2.118a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m-2.93 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.083.185.185.185m-2.964 0h2.119a.185.185 0 00.185-.185V9.006a.185.185 0 00-.184-.186h-2.12a.186.186 0 00-.186.186v1.887c0 .102.084.185.186.185m-2.92 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.082.185.185.185M23.763 9.89c-.065-.051-.672-.51-1.954-.51-.338.001-.676.03-1.01.087-.248-1.7-1.653-2.53-1.716-2.566l-.344-.199-.226.327c-.284.438-.49.922-.612 1.43-.23.97-.09 1.882.403 2.661-.595.332-1.55.413-1.744.42H.751a.751.751 0 00-.75.748 11.376 11.376 0 00.692 4.062c.545 1.428 1.355 2.48 2.41 3.124 1.18.723 3.1 1.137 5.275 1.137.983.003 1.963-.086 2.93-.266a12.248 12.248 0 003.823-1.389c.98-.567 1.86-1.288 2.61-2.136 1.252-1.418 1.998-2.997 2.553-4.4h.221c1.372 0 2.215-.549 2.68-1.009.309-.293.55-.65.707-1.046l.098-.288Z" }, "child": [] }] })(props);
}
function SiDebian(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M13.88 12.685c-.4 0 .08.2.601.28.14-.1.27-.22.39-.33a3.001 3.001 0 01-.99.05m2.14-.53c.23-.33.4-.69.47-1.06-.06.27-.2.5-.33.73-.75.47-.07-.27 0-.56-.8 1.01-.11.6-.14.89m.781-2.05c.05-.721-.14-.501-.2-.221.07.04.13.5.2.22M12.38.31c.2.04.45.07.42.12.23-.05.28-.1-.43-.12m.43.12l-.15.03.14-.01V.43m6.633 9.944c.02.64-.2.95-.38 1.5l-.35.181c-.28.54.03.35-.17.78-.44.39-1.34 1.22-1.62 1.301-.201 0 .14-.25.19-.34-.591.4-.481.6-1.371.85l-.03-.06c-2.221 1.04-5.303-1.02-5.253-3.842-.03.17-.07.13-.12.2a3.551 3.552 0 012.001-3.501 3.361 3.362 0 013.732.48 3.341 3.342 0 00-2.721-1.3c-1.18.01-2.281.76-2.651 1.57-.6.38-.67 1.47-.93 1.661-.361 2.601.66 3.722 2.38 5.042.27.19.08.21.12.35a4.702 4.702 0 01-1.53-1.16c.23.33.47.66.8.91-.55-.18-1.27-1.3-1.48-1.35.93 1.66 3.78 2.921 5.261 2.3a6.203 6.203 0 01-2.33-.28c-.33-.16-.77-.51-.7-.57a5.802 5.803 0 005.902-.84c.44-.35.93-.94 1.07-.95-.2.32.04.16-.12.44.44-.72-.2-.3.46-1.24l.24.33c-.09-.6.74-1.321.66-2.262.19-.3.2.3 0 .97.29-.74.08-.85.15-1.46.08.2.18.42.23.63-.18-.7.2-1.2.28-1.6-.09-.05-.28.3-.32-.53 0-.37.1-.2.14-.28-.08-.05-.26-.32-.38-.861.08-.13.22.33.34.34-.08-.42-.2-.75-.2-1.08-.34-.68-.12.1-.4-.3-.34-1.091.3-.25.34-.74.54.77.84 1.96.981 2.46-.1-.6-.28-1.2-.49-1.76.16.07-.26-1.241.21-.37A7.823 7.824 0 0017.702 1.6c.18.17.42.39.33.42-.75-.45-.62-.48-.73-.67-.61-.25-.65.02-1.06 0C15.082.73 14.862.8 13.8.4l.05.23c-.77-.25-.9.1-1.73 0-.05-.04.27-.14.53-.18-.741.1-.701-.14-1.431.03.17-.13.36-.21.55-.32-.6.04-1.44.35-1.18.07C9.6.68 7.847 1.3 6.867 2.22L6.838 2c-.45.54-1.96 1.611-2.08 2.311l-.131.03c-.23.4-.38.85-.57 1.261-.3.52-.45.2-.4.28-.6 1.22-.9 2.251-1.16 3.102.18.27 0 1.65.07 2.76-.3 5.463 3.84 10.776 8.363 12.006.67.23 1.65.23 2.49.25-.99-.28-1.12-.15-2.08-.49-.7-.32-.85-.7-1.34-1.13l.2.35c-.971-.34-.57-.42-1.361-.67l.21-.27c-.31-.03-.83-.53-.97-.81l-.34.01c-.41-.501-.63-.871-.61-1.161l-.111.2c-.13-.21-1.52-1.901-.8-1.511-.13-.12-.31-.2-.5-.55l.14-.17c-.35-.44-.64-1.02-.62-1.2.2.24.32.3.45.33-.88-2.172-.93-.12-1.601-2.202l.15-.02c-.1-.16-.18-.34-.26-.51l.06-.6c-.63-.74-.18-3.102-.09-4.402.07-.54.53-1.1.88-1.981l-.21-.04c.4-.71 2.341-2.872 3.241-2.761.43-.55-.09 0-.18-.14.96-.991 1.26-.7 1.901-.88.7-.401-.6.16-.27-.151 1.2-.3.85-.7 2.421-.85.16.1-.39.14-.52.26 1-.49 3.151-.37 4.562.27 1.63.77 3.461 3.011 3.531 5.132l.08.02c-.04.85.13 1.821-.17 2.711l.2-.42M9.54 13.236l-.05.28c.26.35.47.73.8 1.01-.24-.47-.42-.66-.75-1.3m.62-.02c-.14-.15-.22-.34-.31-.52.08.32.26.6.43.88l-.12-.36m10.945-2.382l-.07.15c-.1.76-.34 1.511-.69 2.212.4-.73.65-1.541.75-2.362M12.45.12c.27-.1.66-.05.95-.12-.37.03-.74.05-1.1.1l.15.02M3.006 5.142c.07.57-.43.8.11.42.3-.66-.11-.18-.1-.42m-.64 2.661c.12-.39.15-.62.2-.84-.35.44-.17.53-.2.83" }, "child": [] }] })(props);
}
function SiComposer(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M16.66 0c-.07 0-.114.034-.164.095a.416.416 0 00-.07.43c.19.41.363.83.528 1.25.01.02.022.04.039.068-.04-.002-.05-.022-.063-.043-.297-.31-.648-.557-.998-.804-.473-.337-.99-.603-1.503-.872a.578.578 0 00-.214-.065l-.384-.04c-.202-.025-.355.09-.355.292 0 .108-.046.132-.135.14-.08.004-.187.115-.196.192a.694.694 0 00.228.619c.444.415.873.845 1.303 1.275l.015.007a.1.1 0 01.028.038c-.007.003-.014.003-.02.003a.057.057 0 01-.035-.022c-.002-.002-.005-.005-.005-.007-.062-.036-.127-.07-.187-.11-.3-.2-.595-.404-.895-.598a.943.943 0 00-.461-.17.453.453 0 00-.392.143.28.28 0 00-.088.253c.016.146.115.237.223.312.502.338.95.734 1.366 1.174.036.038.074.079.115.112.118.096.19.224.262.356.033.06.02.074-.043.074-.428 0-.836.118-1.246.204-.168.036-.334.094-.394.28-.065.21-.096.328.16.392a9.57 9.57 0 011.49.516.55.55 0 01.117.077c.12.104.23.219.362.303.38.247.77.478 1.22.583.053.012.1.039.15.05.05.015.085.044.095.094.029.178.139.279.305.33.02.006.038.02.06.028.052.017.076.055.093.108.067.24.137.478.212.715.026.08.002.1-.07.123-.372.108-.742.22-1.112.334-.132.04-.134.043-.067.163l.908 1.635c.127.23.132.23.365.11.024-.012.057-.053.079-.014.02.036.06.089.024.13-.113.129-.19.28-.286.42-.031.045-.031.074-.005.117.1.166.202.334.3.502.012.019.034.043.03.058l-.123.367a2.538 2.538 0 00-.317-.716c-.18-.288-.41-.542-.62-.811-.033-.04-.072-.077-.11-.115-.2-.207-.456-.332-.7-.478a1.026 1.026 0 00-.34-.127c-.374-.08-.746-.11-1.12.004-.075.024-.116.005-.161-.06-.092-.127-.166-.273-.29-.372-.3-.24-.616-.458-.985-.583a2.95 2.95 0 00-.865-.168 4.267 4.267 0 00-.463.017c-.396.03-.79.074-1.14.293-.07.043-.15.067-.221.108-.36.194-.716.386-1.016.679a13.1 13.1 0 00-.897.944c-.322.384-.565.818-.783 1.267-.015.03-.022.07-.07.096l-.12-.744c-.007-.046.022-.043.053-.038.089.01.175.014.264.026.067.01.103-.005.12-.08.022-.102.046-.206.067-.311.082-.397.2-.78.303-1.17.02-.074.007-.1-.07-.12-.381-.09-.763-.192-1.145-.283-.072-.017-.106-.043-.084-.12.087-.298.125-.61.242-.9a.178.178 0 01.056-.087c.098-.076.17-.165.16-.302-.007-.103.041-.168.14-.214.182-.086.358-.187.53-.288a.84.84 0 00.327-.333c.322-.605.59-1.242.98-1.81.033-.051.06-.106.1-.15.252-.264.488-.544.771-.78.089-.074.113-.175.115-.285 0-.128-.074-.217-.151-.305-.075-.087-.151-.161-.279-.147-.028.003-.057-.01-.088-.014.019-.04.05-.048.076-.065.339-.218.677-.437 1.016-.658.41-.264.819-.53 1.232-.794.052-.034.076-.06.019-.11-.015-.013-.024-.03-.036-.044-.084-.099-.084-.099-.2-.03L8.084 3.693c-.101.062-.101.062-.152-.05-.112-.263-.177-.54-.261-.81-.02-.062-.003-.098.045-.137.289-.23.553-.49.82-.742a.604.604 0 00.186-.37c.022-.17-.09-.259-.244-.196a1.707 1.707 0 00-.221.105c-.68.375-1.405.632-2.149.848-.043.012-.082.026-.118-.02-.074-.09-.185-.14-.278-.208a.073.073 0 00-.063-.015c-.1.027-.204.056-.266.147-.159.233-.358.44-.507.682-.17.28-.333.562-.525.828-.036.05-.05.058-.084-.002L3.63 2.635a2.837 2.837 0 00-.223-.338c-.094-.118-.209-.176-.358-.16-.026.004-.06-.004-.07.037-.02.11-.07.226-.057.332.034.27.082.542.15.806.114.459.244.912.38 1.364.133.444.282.88.426 1.323.012.038.033.072-.02.103-.067.038-.175.058-.187.125-.012.07.05.15.08.225l.007.017c.024.058.036.144.08.166.057.029.11-.05.162-.082.048-.03.065-.021.087.029.124.293.252.583.38.876a.18.18 0 01.006.137 4.138 4.138 0 00-.192.72c-.012.07-.038.07-.09.055a107.637 107.637 0 00-.834-.21c-.123-.032-.123-.032-.137.093v.01c-.06.665-.12 1.33-.183 1.994-.004.06.003.085.068.092.194.024.386.055.578.084.036.005.067.007.058.06-.043.225-.077.453-.125.677a.178.178 0 00.034.163l.2.264c.045.063.08.144.037.209a.201.201 0 00-.033.118c.007.415.007.83.026 1.246.01.2.007.403.012.605.01.535.04 1.068.06 1.603.01.262-.036.52-.024.783.002.065.017.1.084.122.16.05.312.116.473.166a.28.28 0 01.185.156.436.436 0 01.038.219c-.002.072.024.115.082.156.247.177.492.36.74.542.65.48 1.3.963 1.954 1.44.06.045.074.081.038.146-.034.062-.055.135-.089.197-.029.058-.024.094.031.134.082.058.161.123.236.188.065.055.067.141.048.208-.015.05-.087.005-.132 0-.032-.002-.063-.01-.094-.014-.31-.05-.617-.13-.932-.156-.5-.04-1.003-.084-1.51-.07-.026 0-.067-.024-.074.03-.007.042-.017.088.031.117.024.014.05.026.077.036.283.098.547.24.807.39.168.095.333.203.518.268.034.012.068.038.108.002-.278-.22-.554-.442-.833-.665.04-.029.07-.017.1-.014.332.026.664.072.988.15.713.17 1.421.361 2.122.572.23.07.475.104.682.243.05.033.08.067.074.13.012.014.027.033.01.045-.02.012-.036-.012-.05-.024-.164-.014-.327-.026-.488-.043-.463-.046-.924-.11-1.392-.096-.35.01-.701-.015-1.05.01-.494.033-.989.098-1.48.15-.025.003-.063-.002-.063.027 0 .036.014.077.06.087a.58.58 0 00.113.012c.25.01.497.007.746.011.62.015 1.242-.012 1.86.041.224.02.45.01.668.05 1.03.193 2.055.394 3.078.618.12.026.243.045.36.103-.055.05-.127.065-.158.137-.22.506-.363 1.04-.53 1.563-.03.09.03.192.12.216a.278.278 0 00.352-.22c.02-.109.039-.217.053-.328.005-.036.017-.055.053-.067.132-.053.26-.108.393-.16a1.63 1.63 0 00.529-.325c.134-.127.247-.274.25-.47 0-.06.014-.099.062-.135.22-.17.418-.365.61-.564a6.03 6.03 0 01.6-.533c.024-.02.043-.048.08-.034l.56.221c-.374.228-.73.447-1.082.66-.017.01-.036.015-.053.02a.813.813 0 00-.338.201c-.375.372-.567.814-.545 1.35.014.36.22.53.57.45.616-.145 1.14-.734 1.233-1.38.024-.18.052-.357-.077-.513a2.25 2.25 0 00-.178-.195c.02-.012.029-.019.039-.026.777-.463 1.625-.778 2.475-1.07 1.04-.359 2.1-.644 3.164-.918l-.075-.017c-.07.007-.136.015-.206.02a5.097 5.097 0 00-.872.134l-.016.007a.226.226 0 01-.094.015c-.014 0-.03 0-.048.002.065-.062.252-.264.303-.25l.002-.005h.005c0-.007.019-.02.019-.02.017-.03.04-.049.074-.05a.694.694 0 01.197-.189c.05-.03.103-.062.16-.086h-.001c.16 0 .319-.194.486-.262-.001-.006-.01-.01-.013-.017-.24.034-.476.072-.706.16-.492.181-1.001.323-1.481.534-.742.324-1.482.648-2.195 1.035a.818.818 0 01-.077.036l-.055-.504c-.005-.034.012-.048.04-.063.632-.334 1.266-.665 1.926-.938.543-.226 1.08-.47 1.626-.691.002-.005.005-.01.01-.01h.004c.003 0 .003.003.005.003.007.012.002.02-.005.026-.002.003-.005.003-.01.005h-.002a3.358 3.358 0 00-.372.66c.038.01.053-.003.067-.018.113-.12.226-.237.336-.357.214-.234.44-.458.704-.64.017-.012.045-.022.033-.048-.014-.03-.045-.015-.067-.01-.247.05-.494.096-.74.154-.081.019-.076-.01-.08-.067-.001-.197.028-.39.035-.586a.63.63 0 01.058-.247c.098-.226.197-.45.297-.675.05-.113.08-.233.099-.353.03-.192.055-.386.074-.58.03-.3.137-.58.187-.875.065-.374.118-.751.257-1.11.125-.316.245-.633.372-.947.176-.428.399-.833.505-1.29.036-.158.076-.302.004-.458-.04-.084-.052-.18-.081-.271a.392.392 0 01-.012-.204c.048-.245.07-.488-.063-.716-.036-.062.008-.1.044-.14.088-.09.093-.131.016-.23-.088-.11-.175-.223-.27-.326-.08-.084-.154-.175-.234-.262-.055-.033-.05-.055.012-.076.14-.048.276-.108.418-.152.08-.024.1-.07.106-.141.045-.605.09-1.213.139-1.818.007-.084-.007-.1-.094-.074-.454.144-.907.28-1.363.422-.14.044-.142.044-.204-.093-.231-.52-.411-1.057-.6-1.59a.392.392 0 01.007-.316c.067-.188.024-.377.019-.567a.104.104 0 01-.005-.03 9.16 9.16 0 00-.254-1.547 6.02 6.02 0 00-.5-1.27c-.228-.432-.473-.86-.737-1.275-.113-.178-.233-.339-.434-.427A.702.702 0 0016.66 0zm-2.642.26a.364.364 0 01.2.051 19.041 19.041 0 011.469.805c.247.158.482.338.715.52.11.087.192.217.284.33.038.047.012.09-.024.124-.024.024-.058.039-.087.055-.031.022-.072.04-.06.087.01.04.055.05.09.058a.27.27 0 00.16-.015c.168-.07.31.048.418.166.028.03.04.093.093.074.055-.021.063-.081.058-.137-.012-.15-.05-.297-.084-.444-.09-.377-.27-.718-.418-1.073-.053-.127-.11-.254-.163-.382-.03-.07.01-.132.048-.182.03-.04.08-.005.122.014.152.068.238.19.312.332.08.15.178.29.262.436.144.255.322.495.437.762.168.388.382.758.483 1.176.086.37.208.732.252 1.114.016.144-.01.283.007.422.033.279-.008.543-.123.798-.03.07-.021.136.012.208.252.533.46 1.083.67 1.635.027.072.015.1-.06.123-.482.14-.965.288-1.447.434-.07.022-.092.003-.113-.06-.123-.326-.24-.646-.353-.967-.024-.068-.053-.104-.128-.087-.088.022-.136-.017-.175-.096-.062-.127-.113-.28-.216-.36-.103-.08-.266-.082-.403-.115-.103-.027-.207-.058-.312-.075a1.428 1.428 0 01-.612-.273c-.303-.224-.615-.43-.934-.627-.104-.007-.202-.036-.303-.06-.278-.057-.554-.117-.833-.17-.067-.012-.08-.063-.084-.108-.007-.056.007-.11.065-.144.089-.053.19-.063.29-.08a9.69 9.69 0 011.345-.13c.11-.002.209.04.312.066a.18.18 0 00.166-.03c.216-.143.434-.28.65-.422.034-.021.096-.036.07-.093a.083.083 0 00-.015-.022c-.012-.01-.026-.012-.043-.012l-.05.002h-.007a1.159 1.159 0 00-.668.2c-.08.05-.26.019-.31-.056-.34-.516-.823-.888-1.282-1.29-.204-.176-.403-.361-.62-.525-.054-.04-.08-.144-.042-.196.048-.072.11-.041.168-.015.185.082.362.175.528.293.564.403 1.17.744 1.772 1.085a.51.51 0 00.05.027c.092.03.14-.01.125-.106a.267.267 0 00-.062-.134c-.488-.574-1.001-1.124-1.506-1.683-.105-.116-.23-.216-.348-.32a.854.854 0 01-.22-.278.16.16 0 01.023-.19c.04-.045.077-.055.137-.024.17.082.332.178.483.293.266.202.535.403.804.605l.807.603c.02.017.043.033.062.05.05.046.094.094.142.142l.029.029c.019.019.036.045.06.06.055.033.112.062.17.004.02-.02.029-.036.03-.055 0-.007.004-.014 0-.021l-.001-.01a.171.171 0 00-.043-.072l-.18-.187a4.537 4.537 0 00-.312-.298c-.35-.29-.706-.571-1.066-.845-.183-.14-.397-.233-.596-.348-.072-.041-.12-.101-.173-.159a.144.144 0 01-.024-.15c.022-.054.075-.051.12-.056zM8.252 1.649a.045.045 0 01.029.005c.048.027.03.077.03.135.013.06-.026.11-.08.16-.346.322-.707.627-1.076.922-.147.118-.327.173-.49.262-.034.017-.053 0-.072-.024-.12-.154-.238-.31-.358-.463-.045-.055.017-.053.046-.065.254-.091.504-.195.756-.295.365-.144.696-.35 1.04-.533.036-.02.07-.043.105-.063.024-.01.044-.037.07-.041zm-2.619.83a.223.223 0 01.134.064c.072.067.13.144.18.228.173.28.413.506.646.737.163.163.33.32.502.47.057.05.067.127.098.192.012.024.002.043-.02.055-.011.008-.023.013-.03.02-.142.12-.276.103-.442.019a3.182 3.182 0 01-.864-.646c-.01-.01-.02-.017-.03-.024-.114-.086-.12-.082-.17.05-.052.135-.086.274-.146.404-.022.045.012.094.046.127.038.039.064.099.134.089.031-.005.048-.022.055-.055.017-.08.04-.16.06-.257.262.22.553.39.84.583l-.278.159c-.713.4-1.428.8-2.139 1.205-.058.03-.082.038-.106-.034-.273-.847-.56-1.69-.79-2.552-.052-.2-.074-.408-.112-.612-.012-.06.028-.091.067-.113.053-.026.055.036.074.06.377.52.634 1.11.941 1.669.092.168.195.33.293.497.02.03.034.057.082.04.053-.02.043-.052.034-.09-.039-.174-.128-.33-.193-.493a.18.18 0 01.003-.16c.137-.284.33-.531.48-.803.14-.247.317-.468.451-.717a.205.205 0 01.2-.111zm1.774.492c.014.003.024.016.036.042.12.27.201.555.302.83.01.027.012.049-.017.066l-.256.158c-.008.005-.017.007-.046.02-.007-.013-.017-.034-.031-.051l-.54-.62c-.024-.028-.048-.055 0-.081.177-.101.312-.264.499-.35.024-.011.04-.017.053-.014zm1.929.486a.204.204 0 01.14.046.21.21 0 01.08.218.556.556 0 01-.161.29 5.528 5.528 0 00-.882 1.093c-.228.36-.453.718-.624 1.11a.768.768 0 01-.146.206c-.24.273-.526.485-.855.638a.17.17 0 00-.108.159c-.005.06-.024.118-.029.178a.48.48 0 01-.19.38c-.04.032-.045.083-.06.126l-.273.915c0 .007 0 .014-.002.019 0 .014.002.03-.017.038-.04.01-.077-.002-.113-.021a41.397 41.397 0 01-1.33-.334c-.055-.012-.108-.03-.166-.036-.088-.012-.096-.053-.055-.12.058-.281.125-.56.298-.797.038-.053.036-.096.002-.154-.19-.317-.334-.658-.492-.99-.026-.054-.017-.08.034-.11A574.255 574.255 0 006.97 4.706c.045-.03.089-.012.132-.022.151-.034.298-.08.43-.163.01-.007.026-.012.03-.022.097-.213.31-.286.49-.37.411-.187.826-.36 1.189-.633a.18.18 0 01.095-.04zm11.443 3.772v.005l.002-.001c-.021.256-.043.498-.062.74l-.043.535c-.005.065-.024.106-.094.13a561.275 561.275 0 00-3.37 1.17l-.04.009c-.035.005-.054-.012-.08-.055-.217-.394-.438-.785-.661-1.177-.03-.05-.038-.077.034-.096l4.254-1.246c.014-.005.03-.007.06-.014zm-.41.386c-.154.003-.293.147-.286.293.007.137.124.257.254.252.137-.002.27-.153.267-.302-.005-.166-.082-.245-.236-.243zm-16.83.87c.01 0 .024.002.04.007L5.512 9l1.937.51c.062.017.082.036.06.1l-.278.913c-.01.036-.017.074-.058.074a.06.06 0 01-.02-.002l-1.036-.142c-.226-.03-.45-.062-.675-.093a254.996 254.996 0 00-2.055-.286c-.043-.012-.058-.038-.05-.098.052-.476.103-.951.153-1.43.003-.011.002-.02.005-.03a.035.035 0 00.005-.015c.007-.014.021-.02.038-.02zm8.136.103l.113.002c.197.01.389.086.569.166.08.036.159.07.238.108l.057.029c.058.028.118.057.173.09l.113.065c.036.025.075.046.108.073.072.05.142.105.207.165.218.202.372.44.463.72.065.202.113.409.13.617.016.202-.044.399-.096.593-.008.03-.02.036-.03.034-.014-.005-.021-.022-.033-.036l-.216-.25a2.105 2.105 0 00-1.042-.684 4.159 4.159 0 00-.994-.154 3.799 3.799 0 00-.804.092c-.211.04-.423.074-.631.113-.137.024-.262.086-.387.14-.06.028-.12.054-.18.077l-.02.004c-.376.132-.695.36-1.024.57-.09.06-.165.14-.243.218l-.01.008-.064.065c-.152.147-.3.296-.464.43-.074.103-.175.175-.268.266.024-.17.07-.328.146-.472a4.6 4.6 0 01.262-.435c.048-.07.096-.14.146-.206a7.17 7.17 0 01.315-.396c.081-.097.163-.193.247-.29l.25-.284a.917.917 0 01.115-.1l.026-.03c.078-.066.147-.136.238-.21l.012-.01.067-.061c.24-.228.519-.406.797-.583.028-.02.057-.035.086-.051l.111-.048c.01-.004.02-.01.029-.012a2.78 2.78 0 01.173-.065l.117-.036c.14-.04.279-.074.416-.117a2.45 2.45 0 01.782-.115zm-7.57.449c-.07.004-.153-.003-.215.057a.462.462 0 00.012.665.286.286 0 00.38 0c.145-.127.182-.314.095-.535-.053-.137-.125-.187-.27-.187zm15.846.062c.087-.001.163.053.23.146.014.01.029.02.043.032.022.019.03.04.053.064.099.113.207.224.31.334a.064.064 0 01.014.024.023.023 0 01-.002.022.04.04 0 01-.015.014l-.01.015-.002.002c-.002.002-.002.005-.004.01 0 .002-.003.004-.003.004h.003v.008c-.145.146-.106.283.01.415.006.012.014.024.014.036.096.127.016.254 0 .382-.003.012-.005.016-.015.02l-.007.004a.116.116 0 01-.03-.005l-.01-.003a9.772 9.772 0 01-.251-.077c-.007 0-.012-.004-.02-.007-.006 0-.011-.007-.018-.007a.284.284 0 01-.118-.02.252.252 0 00-.292.05.054.054 0 01-.005.02c.04.06.108.075.168.094.245.08.453.23.68.348.052.03.062.092.057.152-.003.033-.012.067-.02.103l-.072.31a.127.127 0 01-.02.076c.004.168-.114.293-.17.437-.006.012-.011.017-.02.04a3.223 3.223 0 01-.128.299c0 .007-.01.017-.012.024v-.005c0 .002-.002.002-.002.005l-.005.01c-.003.002-.003.004-.005.007-.012.045-.02.093-.058.132a1.913 1.913 0 01-.187.432c-.007.012-.012.012-.017.036-.062.144-.127.317-.19.475-.014.058-.026.115-.04.17l-.008.015c0 .002-.002.002-.002.005 0 .005-.005.01-.007.014a.45.45 0 01-.036.192c-.012.039-.022.082-.034.12a.074.074 0 01-.005.02l-.201.912c-.055.25-.077.504-.118.754-.038.235-.048.477-.106.708-.04.168-.136.324-.213.48-.072.146-.118.302-.207.444l-.007.015a.169.169 0 00-.012.03c-.002.006-.002.013-.005.018l-.007.033a.182.182 0 00-.002.036c0 .012 0 .024-.003.036v.036a.71.71 0 01-.002.072c-.02.257-.053.514-.041.773.002.048-.012.075-.058.09l-.057.023a1.598 1.598 0 00-.113.048l-.06.024c-.031.012-.05.022-.1.034v-.005s-.006.005-.01.005l-.133.055-.093.038a.635.635 0 01-.211.092l-.036.02a25.181 25.181 0 00-.474.212c-.081.024-.165.072-.247.11-.09.04-.175.075-.264.114-.14.062-.278.12-.418.181-.004.002-.012 0-.016 0-.128.048-.26.118-.38.173-.048.026-.117.053-.177.077-.11.043-.135.038-.16-.075-.071-.052-.078-.14-.104-.216-.027-.072-.048-.15-.072-.222-.005-.024-.017-.02-.017-.034-.024-.033-.024-.064-.036-.098l-.003-.017c-.007-.005-.007-.012-.01-.02l-.006-.016h.004c-.033-.1-.07-.2-.093-.3-.024-.067-.067-.132-.08-.202a.17.17 0 010-.07l.008-.033.004-.017c.02-.047.05-.093.075-.14.017-.037.03-.076.048-.114.017-.038.03-.067.048-.115.038-.072.062-.156.11-.24 0-.02.015-.04.02-.058.043-.146.09-.295.149-.437 0-.005-.005-.012-.003-.017.017-.086.098-.117.146-.168v.003c.024-.008.037-.022.049-.022.014-.024.028-.034.043-.048a1.518 1.518 0 00.108-.15c.045-.066.086-.136.137-.203.016-.021.03-.055.057-.055.005 0 .007 0 .012.002.039.01.027.055.022.084a.88.88 0 000 .327c.012.084.026.168.033.252l-.002.038a.578.578 0 01.036.19c.02.082.036.16.06.242.072.15.125.3.173.454l.005-.002c.08.12.163.26.245.39.024.032.05.066.074.09h.005v.02c.024 0 .036.052.072.004-.007-.024-.012-.024-.02-.024a.448.448 0 01-.03-.08c-.005-.016-.013-.035-.015-.05a.387.387 0 01-.012-.05c-.002-.007-.002-.017-.005-.024a.282.282 0 00-.01-.048l-.011-.075-.013-.074c-.007-.007-.007-.017-.007-.026-.002-.01-.004-.02-.01-.03-.002-.028-.007-.057-.011-.086l-.022-.172c-.002-.03-.012-.058-.014-.087a3.634 3.634 0 01.036-.941h.014c.029-.144.058-.31.086-.466.008 0 .015.003.024.003-.01.26.017.52.075.775.002.005.002.012.002.017.036.098.075.197.106.298.007.02.014.043.022.062a.338.338 0 00.055.094c.007.012.02.024.02.036.025.019.037.04.057.06.014.016.026.036.04.053.05.048.104.093.166.156a3.667 3.667 0 01-.017-.14c-.004-.043-.012-.086-.016-.134 0 0-.013-.007-.013-.012a.82.82 0 00-.01-.108l-.04-.33c0-.01 0-.016.002-.025 0-.01.003-.027.003-.027a2.705 2.705 0 01-.02-.415l-.002-.017a1.122 1.122 0 01-.002-.37c.005-.033.002-.07.005-.103 0-.007-.003-.012-.003-.02 0-.158.007-.32.055-.472l.003-.017c.012-.072.024-.158.036-.238.012-.08.024-.16.033-.24.005-.033.015-.05.034-.05.01 0 .024.005.04.017l.05.03.076.049c.024.017.048.033.07.055.002.002.004.005.009.007a.116.116 0 00.017.012h.005v-.002c.168.084.26.226.374.358a.31.31 0 01.11.15c.075.099.13.205.169.323.002.01.007.02.01.03.002.01.007.006.009.03.02.024.03.055.043.084l.034.084.019.04c.005.01.01.017.017.024a.07.07 0 00.04.024c.027-.088-.035-.172-.011-.256h.007c0-.024-.007-.025-.007-.037-.024-.156-.044-.31-.11-.453l-.001-.04c-.058-.143-.086-.29-.17-.416a.103.103 0 01-.037-.063c-.026-.024-.04-.053-.055-.081a4.135 4.135 0 01-.038-.063v.017c0-.002-.005-.005-.005-.007v-.003a2.828 2.828 0 00-.22-.278l-.01-.01c-.01-.01-.02-.01-.03-.033-.057-.024-.112-.096-.17-.147-.007-.007-.014-.01-.02-.017-.004-.004 0-.01-.023-.016-.12-.082-.21-.183-.314-.255-.02-.024-.044-.01-.053-.048.31-.02.61.017.922.036v-.012h.002c.154.024.298.053.437.113.005 0 .01.007.017.007v.005c.096.022.187.065.278.108.02.01.044.04.065.012.017-.024-.01-.046-.024-.065-.036-.05-.07-.1-.108-.151-.007-.012-.02-.024-.02-.036-.071-.07-.126-.15-.19-.22a.953.953 0 01-.06-.063 1.162 1.162 0 01-.208-.17c-.012-.008-.024-.022-.036-.022-.03 0-.064-.034-.096-.056-.03-.021-.064-.04-.096-.062-.012-.007-.024-.012-.036-.02-.146-.055-.293-.105-.44-.16-.004 0-.013-.003-.013-.005 0 0-.013 0-.017-.002a.11.11 0 01-.072-.03.079.079 0 01-.027-.035l-.005-.012c-.007-.02-.01-.041-.007-.063a.968.968 0 00-.012-.22c-.002-.022-.007-.041-.012-.063a2.158 2.158 0 00-.014-.06l-.015-.062a2.29 2.29 0 00-.024-.09s-.01-.002-.01-.01c-.023-.145-.08-.292-.124-.436l-.017-.057a.369.369 0 01-.057-.168c0-.02 0-.036.002-.056l.002-.026c.005-.027.01-.055.02-.082l.033-.108c0-.005 0-.017.003-.017h-.003c.03-.17.099-.314.147-.468 0-.002.005-.002.005-.005l.01-.01c.002-.002.004-.002.004-.004a.265.265 0 00.053-.185.326.326 0 00-.027-.103c-.016-.043-.038-.084-.06-.127-.002-.005-.01-.01-.014-.012-.002-.003-.005-.005-.005-.008a1.196 1.196 0 01-.21-.355l-.015-.038c-.005-.005-.005-.01-.008-.017l-.002-.007a.12.12 0 01-.007-.017l.002.002-.002-.005a.276.276 0 01.012-.043c.004-.01.01-.017.014-.026.005-.007.012-.014.02-.022l.009-.007c.065-.094.125-.192.197-.283a.26.26 0 00.05-.252c-.04-.137-.036-.14.1-.19.025-.01.316-.12.433-.156l.075-.03.019-.006a41.644 41.644 0 01.509-.19c.005-.002.012-.002.017-.002.14-.072.293-.118.44-.168.02-.007.037-.015.06-.02.025-.02.097-.035.12-.055.12-.038.217-.093.325-.117a.287.287 0 01.167-.067zm-5.432.603a.82.82 0 01.23.036l.014.004c.259.08.523.142.77.26.04.019.084.038.113.077.16.115.307.247.43.405.19.245.38.492.557.773-.011-.003-.022-.008-.034-.013v-.001a1.018 1.018 0 01-.185-.103 6.452 6.452 0 00-.674-.356 1.467 1.467 0 00-.331-.1 3.307 3.307 0 00-.91-.041c-.084.007-.17 0-.255 0-.062 0-.091-.03-.091-.092 0-.235.012-.472-.06-.7-.015-.048.014-.068.055-.082a1.12 1.12 0 01.372-.067zm-2.75.773c.423-.015.812.105 1.167.324.132.08.253.176.363.284l.014.013c.122.123.23.26.32.41.08.13.059.272.032.414-.072.406-.316.706-.592.987-.265.269-.596.444-.903.648-.435.29-.932.403-1.438.478-.632.093-1.273.103-1.906.187-.23.029-.464.048-.694.089a1.07 1.07 0 00-.68.41c-.062.084-.1.187-.16.303a.527.527 0 01.026-.394 1.12 1.12 0 01.533-.54c.415-.22.879-.262 1.323-.375.36-.091.73-.144 1.087-.242a7.234 7.234 0 001.426-.55c.24-.125.49-.252.656-.485a.73.73 0 00.12-.557c-.005-.034-.015-.05-.027-.053-.012-.002-.03.007-.05.027-.18.16-.367.314-.571.449-.32.206-.673.33-1.038.42-.58.144-1.166.266-1.764.31a4.84 4.84 0 00-1.239.242c-.34.118-.687.235-.96.49-.034.03-.075.057-.13.098l.007-.038-.026.019v-.005c.01-.006.016-.013.024-.017a.599.599 0 01.084-.2l.646-1.022a.285.285 0 01.041-.053c.334-.33.653-.677 1.023-.965.614-.48 1.284-.855 2.055-1.02.187-.041.377-.07.57-.07.22-.002.443-.01.66-.017zm-7.632.022c.013 0 .03.002.048.009.03.01.062.007.094.01.127.028.26.03.386.062.012 0 .017.002.034.01a2.174 2.174 0 01.4.057c.145.02.29.036.433.06.033 0 .062-.002.093.017.005 0 .012-.002.012 0 .168.02.3.03.445.055h-.015v.005c.096.012.16.024.233.036.077.012.156.03.23.03h.003c.007 0 .012.004.017.004l.021.005c.048.002.067.028.075.07.038.227.07.455.117.683 0 .017.01.032.008.046l.02.11.061.332c0 .01 0 .03.003.036v.01c.024.143.05.273.074.41v.046a1.717 1.717 0 00-.3.46c-.03.075-.07.152-.1.226l-.006.003c-.024.076-.062.15-.098.223-.003 0-.005.005-.007.01-.005.009-.008.024-.012.03v.003a2.478 2.478 0 01-.192.415c-.008.02-.024.039-.024.056-.024.09-.046.182-.092.266a.757.757 0 01-.074.226 2.102 2.102 0 01-.13.394c-.007.019-.019.036-.019.055l-.002.007c-.003.007-.005.02-.01.029a.106.106 0 01-.01.03l-.002.01-.038.742.021.008.094-.185c.031-.06.055-.123.09-.185.018-.043.05-.086.05-.13.071-.12.136-.24.21-.35.008-.012.022-.02.03-.043.062-.097.134-.224.208-.334.026-.043.054-.08.078-.123.016-.048.042-.055.064-.076.021-.022.033-.044.081-.065 0 .019.005.036.003.053l-.003.01c0 .009-.004.018-.007.028l-.002.01c-.003.007-.003.012-.005.019a.054.054 0 00-.002.02c0 .006-.005.01-.003.018l-.003.015h.003c-.022.144-.02.307-.024.458 0 .007-.005.02-.005.024l.005-.002c.02.144.043.288.062.432h-.002c.003 0 .005.03.005.043.024.144.055.29.072.437l.002.017c.003.01.005.017.005.026.024.116.11.195.163.296.039.055.08.12.116.168h.002v.002c.12.106.22.214.355.31.02 0 .039.024.058.024h-.002v.012c.048.005.088.043.139.029a.087.087 0 00.026-.012c.007-.005.017-.01.02-.017.011-.022-.01-.034-.027-.041-.197-.125-.166-.33-.19-.521h.008v-.003c.048.046.081.09.122.14a.1.1 0 00.024.026l.05.055c.034.036.07.07.108.1.039.032.08.066.125.09.02.007.039.024.056.024h-.005c.144.07.269.137.4.206a.15.15 0 01.08.036c.048.144.105.288.091.456.005 0 .01.017.012.03a.066.066 0 01-.002.03c.017.14.017.28-.003.42a.044.044 0 01-.002.039c-.003.005 0 .007-.002.012h.002c0 .14-.002.278-.038.415-.003.137-.046.27-.06.406 0 .005-.003.01-.005.017-.008.026-.02.057.038.05v-.002c.13-.136.26-.267.38-.418v.01c.002-.048.03-.073.057-.096.05-.05.1-.13.151-.2.05-.07.101-.137.152-.206l.002-.012c.007-.024.017-.04.029-.046.005-.002.01-.005.014-.005H9.3a.133.133 0 01.05.02.835.835 0 01.077.048c.144.079.307.132.415.269.012.012.026.014.038.038.05.024.096.08.133.132l.038.036c.002.002.005.002.007.005.19.16.204.246.067.46-.004.007-.012.014-.016.014a.236.236 0 01-.024.055.216.216 0 01-.02.036l-.01.017c-.035.058-.074.118-.088.185a.443.443 0 00-.012.168c.026.094.05.19.07.286.012.057.024.115.028.175.02.142-.048.228-.168.288v-.002c-.024.002-.026.017-.038.024a.078.078 0 01-.02.014.362.362 0 01-.038.026.192.192 0 00-.077.087c0 .007 0 .005-.002.01-.002.004 0 .014-.002.014h.007v.014c-.024.07-.036.12-.048.156-.003.01-.007.017-.01.024-.002.008-.007.012-.01.017-.002.005-.007.01-.009.012a.045.045 0 01-.024.012h-.007a.165.165 0 01-.05-.012c-.034-.012-.078-.029-.138-.048-.004-.002-.009-.002-.011-.005a.025.025 0 00-.012-.004l-.027-.012h-.01v-.01h-.002c-.072-.024-.14-.038-.204-.065-.038-.014-.08-.026-.12-.043-.05-.012-.1-.036-.151-.036-.14-.048-.281-.072-.416-.12-.011 0-.019.002-.043 0v.002c-.096-.019-.173-.043-.264-.06-.089-.014-.122-.06-.113-.148.005-.037.003-.08.003-.116 0-.012-.003-.017-.003-.04-.014-.025-.036-.053-.055-.085a.11.11 0 01-.014-.026c-.012-.012-.036-.024-.036-.038-.024-.005-.015-.01-.022-.015-.074-.07-.053-.163-.043-.252l.002-.029.008-.055c.002-.01.002-.02.004-.026.039-.15.048-.29-.113-.38-.019-.012-.03-.024-.055-.04v.004a2.869 2.869 0 00-.225-.165c-.012-.024-.015-.029-.039-.039a1.418 1.418 0 01-.31-.227l-.074-.04h.01c-.015-.025-.032-.022-.044-.034-.019-.014-.036-.024-.06-.04-.12-.102-.283-.198-.413-.315-.045-.015-.074-.05-.11-.08v-.004c-.127-.09-.252-.176-.377-.272h.003c-.015 0-.015-.012-.039-.024-.072-.036-.144-.096-.206-.144-.02-.024-.039-.024-.058-.024-.058-.048-.108-.07-.156-.113-.02-.012-.036-.026-.06-.04a2.178 2.178 0 01-.396-.29l-.012-.011-.022-.024a.188.188 0 01-.038-.081v.019c-.087-.094-.144-.202-.216-.3l-.007-.015a.027.027 0 01-.005-.014.107.107 0 01-.003-.026.118.118 0 01.024-.053c0-.005.003-.012.003-.02.024-.153.108-.292.168-.436v-.037s0-.022-.003-.032l-.004-.014-.005-.005a.038.038 0 00-.017-.01h-.007a.122.122 0 00-.058.022.312.312 0 00-.055.043l-.02.015a.13.13 0 00-.014.019l-.007.01c0 .002-.002 0-.002 0 0 .002-.003 0-.003 0v.002c-.048.055-.12.103-.182.154-.012.012-.034.026-.034.038v-.002h-.007c-.02.024-.045.024-.072.012l-.31-.137c-.024-.012-.036-.038-.04-.062a.64.64 0 01-.008-.032l-.007-.026v.005c-.036-.168.022-.293.053-.437.002-.012.005-.024.005-.036.024-.14.033-.288.074-.423v-.062c-.02-.154-.022-.305-.033-.46l.002-.078c-.014-.286-.033-.571-.043-.857-.022-.598-.07-1.193-.053-1.79a.636.636 0 00-.074-.315 1.968 1.968 0 00-.099-.164.264.264 0 01-.048-.237c.036-.14.063-.284.09-.425.008-.05.021-.084.06-.086zm-.166.38l.005.015c.005.032-.007.065-.02.113a.117.117 0 010-.086.295.295 0 01.015-.041zm10.715.003c.13-.002.257.005.38.024.22.017.42.058.55.164.095.04.189.09.28.144.22.132.44.269.662.403a.389.389 0 01.118.108l.223.315c.012.016.03.036.015.057a.038.038 0 01-.02.014c-.018.004-.034-.002-.05-.011-.098-.056-.2-.108-.298-.164a4.76 4.76 0 00-1.184-.46c-.107-.03-.208-.06-.323-.075l-.152-.034c-.004.003.005.012.017.024.005.005.01.01.012.015a.138.138 0 00.04.033l.02.01c.228.115.613.187.893.317l.058.029c.156.08.298.182.44.29l.268.207c.404.293.65.689.77 1.169.003.014.008.029.01.043l.01.014c.02.03.024.065.017.096.002.008.002.015.005.022-.005.07-.06.04-.092.04a2.504 2.504 0 01-.61-.11h-.006c-.051-.016-.118-.04-.165-.054-.211-.075-.41-.163-.615-.238-.252-.09-.45-.261-.662-.413a7.777 7.777 0 01-1.001-.816.34.34 0 01-.08-.106 4.11 4.11 0 01-.062-.153l-.036-.094a1.088 1.088 0 00-.024-.06l-.002-.005c-.003-.002-.003-.007-.003-.01v-.002l-.002-.01a.168.168 0 01.007-.122c.002-.005.002-.01.005-.014l.005-.017.004-.014c.003-.005.003-.013.005-.017l.003-.015.002-.017.003-.014.002-.017.002-.014.003-.017.002-.014.003-.017c0-.005 0-.01.002-.015 0-.004 0-.012.003-.016v-.266c-.003-.082.026-.114.108-.111.08.002.162-.001.243-.005l.075.004c.04-.002.08-.005.122-.005zm.284.532a.12.12 0 00.028.008H15c-.012.008-.028.005-.033.02-.004-.02-.002-.027.003-.028zm.88.342a.206.206 0 00.012.006h.003zm-1.908.177l.002.003c.007.003.014.01.022.024.076.154.182.28.3.399.124.12.259.23.389.348.268.242.542.48.818.713.178.15.392.228.62.288.518.132 1.049.182 1.575.254.139.02.264.065.374.156h-.007c.01.008.017.012.024.02-.296-.043-.59-.04-.886-.046-.324-.007-.641.03-.96.067a.986.986 0 01-.336-.026c-.308-.07-.598-.195-.89-.317-.328-.14-.601-.353-.861-.588l-.057-.055a1.002 1.002 0 01-.205-.285l-.002-.006c-.09-.212-.085-.448-.016-.708.019-.07.04-.14.062-.21.007-.022.02-.034.034-.031zm-.248 1.18c.065.233.233.396.375.573l.029.039.028.038a.57.57 0 00.106.094c.017.012.03.02.046.033l.02.017a10.088 10.088 0 00.539.396l.329.229c.149.103.305.19.468.266.04.02.082.036.123.055.124.053.25.099.379.14l.02.007c.08.02.167.028.25.038.032.002.064.007.092.01a.195.195 0 01.06.024.411.411 0 01.068.05c.074.067.144.163.148.22 0 .01 0 .018-.002.025-.002.005-.002.007-.005.01-.01.016-.024.03-.033.048-.03.05-.06.1-.085.153l-.011.027a.311.311 0 00.002.26c.115-.114.218-.236.293-.376a1.139 1.139 0 00.086-.201c.01-.027.003-.058.01-.084.01-.03-.024-.07-.01-.09 0-.001.003-.001.005-.004a.04.04 0 01.014-.007c.01-.002.02-.005.027-.005.019-.002.036-.005.055-.005.048 0 .094.008.14.022.028.01.019.045.016.072v.005c-.005.086-.04.165-.072.242a.554.554 0 01-.024.055 1.68 1.68 0 01-.192.375c-.118.156-.254.302-.475.31h-.063c-.038 0-.077.01-.115.012a.085.085 0 00-.086.057c-.017.039-.04.072-.058.11l-.007.017a1.534 1.534 0 01-.408.57c-.08.07-.164.139-.25.203a1.95 1.95 0 01-.468.224l-.036.014-.034.015-.02.007c-.01.002-.021.007-.03.01-.036.014-.065.035-.046.09.02.06.063.077.118.08.012 0 .026 0 .04-.003a.613.613 0 00.15-.033c.048-.017.096-.04.146-.06.034-.015.067-.03.103-.041-.03.122-.045.235-.084.34l-.021.054a6.794 6.794 0 01-.09.192c-.018.043-.04.084-.062.125-.115.23-.245.45-.405.655a1.682 1.682 0 01-.356.34 3.954 3.954 0 01-.103.073 2.788 2.788 0 01-.38.205l-.064.03-.053.02-.043.018c-.04.016-.082.03-.123.045a2.674 2.674 0 01-.168.053 4.848 4.848 0 01-.57.134c-.008 0-.013.003-.02.003-.055.01-.108.017-.163.026-.058.008-.116.017-.176.024a2.156 2.156 0 01-.605-.02l-.028-.008a.68.68 0 01-.145-.06c-.062-.034-.12-.07-.182-.1a1.728 1.728 0 01-.13-.073 1.868 1.868 0 01-.16-.106.632.632 0 01-.233-.278 1.794 1.794 0 00-.092-.194c-.01-.02-.021-.036-.03-.053a2.718 2.718 0 00-.277-.367 2.76 2.76 0 00-.125-.142c-.021-.024-.04-.048-.062-.07a7.07 7.07 0 00-.26-.276l-.067-.067a2.787 2.787 0 00-.364-.302 2.784 2.784 0 00-.303-.192l-.06-.04a1.58 1.58 0 01-.63-.761c-.043-.093-.107-.122-.22-.124a.63.63 0 01-.252-.048l-.002-.002a.457.457 0 01-.132-.084l-.026-.016c-.022-.026-.038-.058-.058-.09a5.295 5.295 0 01-.386-.658c0 .003.002.005.003.008l-.006-.013.003.005a3.772 3.772 0 00-.073-.196l-.036-.086a.382.382 0 01-.014-.154l.007-.031c.002-.005.002-.01.005-.015a.145.145 0 01.012-.03.46.46 0 01.127-.14.898.898 0 01.067-.05c.046-.034.094-.063.14-.094.071-.044.143-.084.218-.123.271-.14.56-.238.857-.314.017-.005.033-.008.053-.012.033-.008.07-.01.105-.015.036-.002.072-.005.106-.005l.106-.002c.016 0 .036 0 .052-.002a17.864 17.864 0 00.9-.063c.18-.017.36-.036.54-.055a3.504 3.504 0 001.127-.324c.036-.02.074-.036.11-.055l.063-.034c.144-.077.288-.151.427-.233.014-.02.03-.026.055-.033l.01-.003v.012a.06.06 0 01-.02.034l-.021.014c-.14.178-.331.3-.497.45a.415.415 0 00-.05.045c-.053.043-.106.089-.166.137.209 0 .41-.024.598-.08a1.654 1.654 0 00.869-.6c.103-.137.197-.297.278-.482zm-3.265.016a1.244 1.244 0 01-.343.109c-.56.139-1.13.22-1.697.326a2.603 2.603 0 00-1.105.487c-.019.015-.04.032-.062.043-.026.017-.039.013-.043-.01-.003-.004-.003-.011-.003-.018-.01-.144.034-.214.166-.274.18-.082.36-.168.54-.252.235-.108.487-.142.742-.168.396-.043.792-.094 1.19-.14l.524-.086zm2.386 1.245h-.026c-.038.01-.036.05-.036.08.003.1.007.202.02.303.01.11.047.219.112.307a.842.842 0 00.51.334c.155.036.155.038.17.2.007.069.016.13.08.17.114.067.227.137.364.146.084.007.17.012.242.068a.583.583 0 00.32.098c.084.007.17.01.254.024.067.012.113-.01.16-.05.239-.197.474-.397.697-.617-.026-.03-.065-.04-.118-.012a6.25 6.25 0 00-.415.223.315.315 0 01-.113.048 4.032 4.032 0 01-.722.074.68.68 0 01-.368-.13c-.067-.043-.134-.105-.146-.201.036-.012.07.002.103.007.127.017.252.063.382.055.312-.02.605-.113.898-.213l.283-.103c.043-.015.055-.03.017-.07-.046-.05-.096-.04-.147-.034a5.625 5.625 0 01-1.87-.045c-.18-.034-.372-.046-.442-.27-.02-.06-.038-.12-.05-.182a.37.37 0 00-.094-.17.094.094 0 00-.065-.04zm-.573.065c-.048 0-.08.05-.103.093-.06.103-.137.196-.207.292-.108.147-.26.178-.418.154a17.985 17.985 0 00-1.718-.18c-.03-.002-.058-.01-.082.01-.183.134-.367.264-.483.468.007.002.015.007.02.007.019-.002.035-.007.055-.01.297-.074.607-.098.922-.072.398.034.792.113 1.188.168.053.008.106.01.156.036.12.063.18.173.226.29.07.18.09.373.103.565.01.15-.022.278-.144.38a.556.556 0 00-.2.278c.154 0 .286.026.387.156.063.08.144.149.223.218a.379.379 0 00.586-.081c.058-.094.113-.19.175-.281.087-.127.17-.264.325-.32.093-.03.052-.076.02-.115-.061-.08-.177-.081-.28-.02-.16.097-.266.239-.381.376-.034.04-.068.08-.113.115-.058.04-.108.043-.16-.01-.056-.057-.114-.117-.176-.168-.053-.043-.063-.082-.032-.144a.728.728 0 00.082-.413c-.03-.312-.08-.62-.3-.867-.024-.026-.024-.04.01-.064a.94.94 0 00.408-.701c.007-.075-.007-.135-.067-.156a.075.075 0 00-.022-.004zm4.46.035c.206 0 .388.08.567.182-.005 0-.007 0-.012.003l.03.017c-.27.04-.54.06-.81.03-.084-.01-.168-.026-.255-.023-.17.005-.307-.084-.451-.161h.017c-.012-.007-.024-.012-.036-.02.024.003.05.003.074.005.029.003.055.01.084.015.238.05.468-.02.704-.043a.8.8 0 01.089-.005zm-8.689.714a.045.045 0 00-.016.004c-.05.019-.098.048-.112.115-.048.223.055.437.278.552.1.053.178.127.226.23.016.037.019.106.072.094.052-.012.01-.077.021-.103.008-.135-.019-.25-.127-.32-.08-.05-.11-.12-.14-.201-.038-.106-.047-.223-.134-.307-.02-.021-.036-.064-.069-.064zm1.843.354c-.11.027-.236.053-.353.106-.082.038-.087.084-.015.139.043.034.087.05.14.03a.466.466 0 01.494.097.509.509 0 00.523.087c.106-.036.197-.096.293-.15a.319.319 0 01.113-.04c.144-.014.288-.033.43-.053.038-.005.098.01.108-.036.01-.048-.046-.077-.08-.108-.016-.017-.045-.02-.07-.026a.82.82 0 00-.436-.015 2.092 2.092 0 01-.888 0c-.08-.02-.163-.02-.26-.03zm6.903.889c.006 0 .01.003.015.007a.05.05 0 01.012.014l.008.005c.043.034-.007.11-.02.168-.03.168-.057.334-.086.502-.007.048-.012.098-.048.165l-.007-.043-.012.024a5.307 5.307 0 01-.075-.706c-.002-.053.034-.065.068-.077.048-.016.107-.066.145-.06zm-3.22.902a.08.08 0 00-.022.01c-.19.105-.404.11-.613.137-.088.012-.2-.015-.264.05-.158.156-.293.09-.432-.02-.007-.004-.014-.011-.024-.014-.206-.11-.413-.15-.624-.005a.338.338 0 01-.267.068c-.074-.02-.131-.015-.19.038-.028.027-.066.048-.1.07-.094.062-.094.072-.007.14.02.018.043.025.067.033.2.06.387.016.562-.08.182-.098.353-.093.518.032.152.112.312.115.48.045a2.97 2.97 0 01.653-.213c.034-.005.068-.017.099.01.096.088.187.026.279-.01.036-.015.04-.044.038-.08-.007-.076-.065-.12-.098-.18-.015-.025-.032-.035-.054-.03zm-4.717.07c.009 0 .02.006.032.017.039.036.075.074.113.11l.015.014c.019.017.021.039.012.06l-.224.45-.024-.008c0-.005.003-.007.003-.012.048-.197.029-.4.055-.6.002-.02.009-.03.018-.03zm3.9.588c-.238.007-.48.046-.703.122-.185.063-.392.106-.488.32-.055.124-.048.256-.086.38.017.1.017.197.074.281.017.024.024.063.065.06.043-.002.058-.038.07-.067.043-.09.053-.194.08-.29.047-.156.119-.28.282-.35.17-.072.343-.14.516-.206a.184.184 0 01.1-.012c.215.03.438.02.628.146a.079.079 0 00.062.012c.072-.017.08-.04.036-.098a.723.723 0 00-.636-.298zm-2.218.741l.014.017c.094.117.187.218.25.336.15.29.374.501.662.655.135.072.256.172.414.19l.003.001h.018c.017 0 .04-.004.036.023-.003.014-.017.014-.031.012h-.007c-.005 0-.01 0-.015-.003-.167.005-.33.033-.493.067-.085.018-.17.038-.255.058a7.838 7.838 0 01-.243.055h-.003c-.033.008-.048.024-.043.058.005.04.02.062.067.072a1.305 1.305 0 00.274.017c.118-.003.235-.015.353-.034a2.602 2.602 0 01.778-.002c-.43.07-.785.312-1.174.475-.202.084-.358.245-.55.348-.014.017-.022.044-.036.06-.031.04-.036.118-.087.11h-.004c-.005 0-.01.003-.015 0a.623.623 0 01-.266-.086c-.03-.019-.022-.055-.022-.089v-.453c0-.032.012-.067-.019-.09-.106-.066-.08-.182-.106-.278-.01-.038.017-.057.039-.08l.278-.31c.063-.068.089-.143.043-.224-.086-.163-.072-.32-.002-.485.055-.13.091-.267.142-.42zm4.585.177c.005.003.01.005.012.008l.007-.008c.039.022.04.05.05.075.102.247.2.497.3.744.025.055.03.103-.006.15a.502.502 0 00-.077.49c.067.205.019.347-.183.448a.229.229 0 01-.12.036.124.124 0 01-.088-.03c-.375-.259-.821-.345-1.242-.494-.06-.02-.117-.043-.18-.057-.072-.017-.067-.065-.057-.116.007-.036.026-.04.045-.038.02-.005.046.01.063.014.48.12.965.216 1.428.396.017.008.03.01.043.013.034-.005.044-.037.039-.082-.01-.108-.02-.214-.144-.27a2.8 2.8 0 00-.975-.234c-.05-.005-.098-.007-.15-.01.239-.144.5-.22.714-.406a.999.999 0 00.075-.067l.398-.482zm-1.882 1.133h.02c.03-.002.054.005.057.053 0 .044.01.082-.06.092a1.752 1.752 0 01-.274.021c-.094 0-.185-.01-.278-.03-.05-.013-.07-.047-.065-.087.002-.027.02-.027.04-.027a.103.103 0 01.039.003h.18a1.143 1.143 0 00.34-.024zm.036.396c.006 0 .012.002.02.005l.844.35c-.132.11-.254.207-.374.303-.221.178-.44.358-.646.553-.05.048-.09.05-.147.014a9.33 9.33 0 00-1.097-.545c-.165-.07-.34-.098-.511-.158.02-.036.055-.036.084-.046.367-.137.742-.26 1.102-.42.094-.043.187-.007.278.005.137.02.27.021.394-.046a.092.092 0 01.053-.015zm-2.161.698a.27.27 0 01.082.018c.197.077.38.185.569.274a.04.04 0 01.029.01c.004.002.005.004.005.011v.005c0 .003-.003.003-.003.005-.002.003-.005.003-.007.003l-.01-.003a.03.03 0 01-.012-.012l-.862-.214c.074-.059.133-.1.209-.097zm8.17.535c-.142-.004-.26.062-.372.15-.03.022-.046.048-.094.017-.105-.072-.206-.053-.295.04a.402.402 0 00-.103.186c-.125.504-.252 1.006-.372 1.512-.041.17.048.255.223.23.158-.026.238-.117.264-.32.026-.198.053-.392.11-.596.15.187.29.362.433.538.139.17.29.321.494.412.144.065.269.027.382-.074a.186.186 0 00.055-.206.157.157 0 00-.158-.125.246.246 0 01-.152-.07 2.27 2.27 0 01-.362-.396c-.09-.12-.094-.12.026-.202.252-.173.34-.417.322-.71-.014-.219-.132-.346-.34-.38a.454.454 0 00-.061-.006zm-10.733.03c-.04 0-.077.02-.097.075-.019.05-.053.043-.091.038a.751.751 0 00-.665.22c-.38.37-.574.813-.552 1.353.014.358.22.53.569.451.689-.16 1.224-.835 1.253-1.582.007-.192-.168-.47-.34-.538a.214.214 0 00-.077-.016zm-1.93.058a.943.943 0 00-.613.238c-.346.302-.547.693-.646 1.138a.642.642 0 00.075.482c.07.118.158.161.292.135a3.12 3.12 0 00.87-.305.867.867 0 00.225-.168.291.291 0 00.084-.204c0-.075-.033-.1-.103-.104-.07-.002-.13.024-.192.046-.207.075-.408.166-.622.22-.105.027-.14.003-.163-.105a.301.301 0 01.005-.122c.04-.168.098-.33.187-.483a.82.82 0 01.245-.283c.14-.089.283-.137.442-.04.052.03.103.016.15-.013a.352.352 0 00.15-.2c.016-.05.002-.09-.044-.117a.773.773 0 00-.343-.115zm9.2.07a.692.692 0 00-.517.206c-.156.161-.183.324-.084.526.074.151.177.28.278.415.072.094.149.187.216.286.048.07.024.125-.058.151a.199.199 0 01-.14-.005 1.076 1.076 0 01-.373-.23.243.243 0 01-.082-.125c-.012-.074-.053-.108-.125-.115-.081-.007-.156-.007-.204.08-.08.138-.057.263.087.393.276.245.605.353.933.38.3.004.485-.267.387-.522-.043-.115-.118-.216-.19-.314-.12-.159-.245-.313-.357-.476-.09-.125-.048-.216.098-.264.135-.043.25-.005.36.08.13.1.24.047.269-.116.017-.086-.03-.144-.09-.194a.68.68 0 00-.41-.157zm1.905.06c-.137-.003-.274 0-.41.016-.164.02-.32.065-.38.248-.002.01-.014.024-.024.026-.187.048-.252.202-.302.358-.106.346-.2.696-.298 1.042-.024.084.01.14.08.182.054.034.11.032.172.015.324-.08.648-.166.987-.142a.26.26 0 00.127-.029.242.242 0 00.117-.24c-.014-.09-.086-.117-.163-.13a1.484 1.484 0 00-.177-.016 3.855 3.855 0 00-.62.052c.03-.228.048-.242.264-.242.16 0 .322-.01.473-.072.1-.043.166-.113.176-.226.007-.076-.025-.122-.104-.124a1.65 1.65 0 00-.19.002l-.453.04c.024-.052.036-.1.062-.136.044-.062-.007-.178.084-.209.075-.024.164-.007.245-.01.214-.004.427-.007.634-.074a.347.347 0 00.192-.13c.07-.108.043-.18-.082-.185-.136-.006-.273-.014-.41-.017zm-6.664.008c-.071-.003-.13.042-.185.093a3.95 3.95 0 00-.392.434l-.367.456c-.02.024-.04.07-.08.05-.03-.014-.018-.055-.014-.086.01-.11.024-.218.036-.329.015-.144.034-.288.01-.432-.031-.173-.156-.22-.295-.113a.836.836 0 00-.094.091 3.168 3.168 0 00-.298.414c-.225.348-.432.71-.703 1.027-.05.06-.103.118-.149.182-.048.072-.067.154-.022.23.041.068.11.092.188.087.081-.004.125-.064.168-.122l.626-.852c.012-.015.017-.044.053-.034a1.37 1.37 0 00-.012.11c-.01.137-.038.274-.01.413.034.16.16.224.306.152a.902.902 0 00.204-.152c.117-.112.228-.233.33-.362.114-.144.229-.29.349-.447.036.12.022.228.017.336-.012.188-.048.375-.012.565.024.117.091.187.187.194a.44.44 0 00.278-.07c.125-.079.137-.237.02-.343a.19.19 0 01-.063-.113c-.026-.13-.004-.257.017-.384.039-.245.115-.485.103-.737-.004-.098-.02-.19-.12-.237a.19.19 0 00-.076-.02zm8.04.19c.117-.01.175.063.14.176a.387.387 0 01-.07.132c-.128.161-.291.27-.495.353a1.56 1.56 0 01.11-.425c.062-.134.163-.223.315-.237zm-6.651.02a.292.292 0 01.15.034c.076.043.098.146.045.233a.676.676 0 01-.185.184 1.47 1.47 0 01-.483.243c.07-.216.128-.415.245-.586a.286.286 0 01.228-.108zm1.6.091a.509.509 0 01.213.034c.113.046.15.1.149.27a1.257 1.257 0 01-.425.818.562.562 0 01-.324.136c-.147.012-.262-.08-.247-.228.028-.32.115-.624.33-.876a.436.436 0 01.304-.154zm-5.882.003a.501.501 0 01.218.036c.11.043.149.098.144.262a1.243 1.243 0 01-.422.818.581.581 0 01-.325.14c-.15.011-.266-.082-.252-.233.03-.315.116-.613.325-.86a.442.442 0 01.312-.163z" }, "child": [] }] })(props);
}
function SiCircleci(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M8.963 12c0-1.584 1.284-2.855 2.855-2.855 1.572 0 2.856 1.284 2.856 2.855 0 1.572-1.284 2.856-2.856 2.856-1.57 0-2.855-1.284-2.855-2.856zm2.855-12C6.215 0 1.522 3.84.19 9.025c-.01.036-.01.07-.01.12 0 .313.252.576.575.576H5.59c.23 0 .433-.13.517-.333.997-2.16 3.18-3.672 5.712-3.672 3.466 0 6.286 2.82 6.286 6.287 0 3.47-2.82 6.29-6.29 6.29-2.53 0-4.714-1.5-5.71-3.673-.097-.19-.29-.336-.517-.336H.755c-.312 0-.575.253-.575.576 0 .037.014.072.014.12C1.514 20.16 6.214 24 11.818 24c6.624 0 12-5.375 12-12 0-6.623-5.376-12-12-12z" }, "child": [] }] })(props);
}
function SiBorgbackup(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M0 8.144v6.023h2.006V8.144Zm2.324 0v1.203h1.488v1.285H2.324v1.048h1.488v1.284H2.324v1.203h2.328l1.207-1.203V11.78l-.603-.604.603-.603V9.347L4.652 8.144Zm5.569 1.203L6.69 10.55v2.414l1.203 1.203H9.24v-1.125h-.522V10.55h.522V9.347Zm1.665 0v1.203h.5v2.492h-.5v1.125h1.344l1.202-1.203V10.55l-1.202-1.203Zm3.454 0v4.82h2.006v-4.82Zm3 0-.672.676v.527h.854v1.171h2.01v-1.248l-.975-1.126Zm3.971 0-1.202 1.203v2.414l1.202 1.203h1.094l.6-.594v-.531h-.89V9.347Zm1.121 0v1.203h.89v4.253h-2.446v.444l.603.609h2.646L24 14.644V10.55l-1.203-1.203Z" }, "child": [] }] })(props);
}
function SiApachemaven(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M4.237.001c-.312-.013-.665.072-.828.457-.158.374-.283 1.188-.34 2.276l1.223.591c-.02-.737.007-1.43.076-2.066-.026.299-.056.96.006 2.039.019.342.049.725.088 1.15.002.024.002.047.007.069a45.485 45.485 0 0 0 .309 2.412c.057.368.126.752.195 1.16l-.01.01c.014.01.015.018.014.023l.03.16c.03.162.06.328.093.494l.108.553.056.289a61.72 61.72 0 0 0 .457 2.068c.09.382.186.78.287 1.186.098.386.199.783.309 1.193.096.362.199.735.303 1.117.003.018.012.036.015.055a145.826 145.826 0 0 0 .34 1.185l.049.174c.078.261.158.533.242.805a4.2 4.2 0 0 1-.293-.135l-.19-.654c-.02-.077-.042-.148-.062-.225l-.002-.004-.004-.002c-.087-.3-.17-.607-.257-.916-.023-.087-.044-.173-.069-.263l-.314-1.178c-.1-.381-.194-.765-.29-1.154-.094-.39-.185-.78-.277-1.172-.093-.401-.181-.8-.265-1.203-.085-.396-.161-.798-.24-1.193a50.315 50.315 0 0 1-.211-1.17c-.004-.013-.006-.03-.01-.041l.004-.002c-.057-.386-.116-.77-.174-1.15a60.905 60.905 0 0 1-.154-1.204 27.447 27.447 0 0 1-.172-2.41l-1.22-.59c-.004.074-.01.15-.013.23-.012.294-.02.605-.023.93a45.3 45.3 0 0 0 .006 1.157c.009.37.025.755.045 1.148.02.336.042.675.07 1.022l.002.039.006.004c.003.023.007.05.006.076.033.368.064.739.107 1.115a34.493 34.493 0 0 0 .303 2.125c.01.064.024.131.035.195a23.418 23.418 0 0 0 .547 2.32c.07.237.14.464.21.68.063.182.13.365.194.545.155.422.327.832.512 1.232l.006.004a.318.318 0 0 0 .02.05c.225.485.475.95.755 1.395.01.013.02.033.03.047-.455-.183-1.259-.098-1.253-.097.83.288 1.557.64 2.016 1.175-.183.2-.523.352-.953.477.594.064.924-.039 1.045-.092-.31.26-.483.732-.635 1.24.35-.57.696-.949 1.033-1.094.078.258.162.524.244.788A147.532 147.532 0 0 0 5.157 24a.56.56 0 0 0 .43-.312c.13-.282.83-1.775 1.908-3.875.413 1.303.88 2.679 1.386 4.109a.494.494 0 0 0 .076-.465 103.735 103.735 0 0 1-1.308-3.945c.154-.299.316-.612.484-.932.125.04.255.094.389.155.203.186.352.491.482.84a1.515 1.515 0 0 0-.334-1.098c1.335.258 2.547.09 3.287-.81a3.97 3.97 0 0 0 .192-.258c-.325.304-.682.404-1.313.273.996-.281 1.523-.617 2.035-1.22.12-.145.244-.303.371-.48-.943.722-1.927.822-2.9.493l-.045-.018c.914.02 2.203-.474 3.092-1.189.41-.33.796-.73 1.17-1.21.28-.359.55-.76.82-1.216.234-.393.468-.824.7-1.293a2.83 2.83 0 0 1-.74.137l-.144.008c-.048.002-.093 0-.146.002.885-.198 1.5-.74 1.994-1.447-.24.117-.628.262-1.07.297-.058.006-.12.006-.182.006-.013-.002-.028 0-.047-.002.306-.078.574-.178.81-.309a3.363 3.363 0 0 0 .358-.236c.044-.037.088-.07.13-.106.099-.086.193-.18.28-.287.028-.034.056-.063.08-.098.036-.05.073-.098.104-.146a8.388 8.388 0 0 0 .51-.828c.015-.031.032-.057.046-.088.04-.084.08-.16.11-.227.042-.099.074-.179.092-.238a.515.515 0 0 1-.108.051c-.273.112-.727.187-1.086.201-.004 0-.008 0-.013.004h-.067c.72-.214 1.067-.45 1.422-.818a13.883 13.883 0 0 0 1.154-1.428c.264-.37.505-.738.692-1.072a6.5 6.5 0 0 0 .298-.592c.066-.157.122-.305.172-.45-.466.01-.986.011-1.48 0 .495.01 1.015.007 1.484-.005.5-1.485.063-2.262.063-2.262s-.526-1.212-1.4-.851c-.426.175-1.172.73-2.083 1.56l.514 1.45a17.561 17.561 0 0 1 1.703-1.602c-.257.22-.807.726-1.615 1.644-.256.29-.537.624-.844.997-.017.02-.035.038-.047.06a51.435 51.435 0 0 0-1.666 2.187c-.248.34-.498.704-.765 1.088h-.016c.002.02-.004.028-.01.032l-.101.152c-.104.155-.213.31-.318.47l-.352.534c-.061.09-.124.181-.186.277-.184.282-.367.573-.558.873a97.351 97.351 0 0 0-1.428 2.338 96.866 96.866 0 0 0-1.341 2.343c-.012.017-.02.04-.034.057a197.256 197.256 0 0 0-.668 1.223l-.097.181c-.17.318-.346.642-.52.979 0 .004-.005.008-.006.013-.026.048-.05.093-.072.141-.117.222-.218.424-.45.87a1.352 1.352 0 0 0-.233-.182l.345-.65c.047-.089.096-.177.143-.27l.04-.077.546-1.001.13-.233v-.006l-.001-.006c.169-.31.345-.62.52-.94.051-.087.102-.173.153-.265.224-.395.454-.794.684-1.197a91.685 91.685 0 0 1 2.135-3.504c.247-.386.503-.77.754-1.152.092-.138.182-.272.279-.41a72.9 72.9 0 0 1 .48-.701c.007-.012.019-.024.026-.037h.006c.26-.356.517-.713.773-1.065.278-.373.554-.735.83-1.09a31.075 31.075 0 0 1 1.777-2.075l-.515-1.446c-.06.057-.126.116-.192.178a32.37 32.37 0 0 0-.758.729c-.295.294-.597.606-.912.935a46.032 46.032 0 0 0-1.632 1.838l-.03.033.002.008c-.017.02-.033.044-.054.064-.266.323-.538.649-.801.985a39.105 39.105 0 0 0-1.445 1.95c-.043.06-.085.126-.127.186a26.458 26.458 0 0 0-1.403 2.303c-.13.247-.256.485-.37.715-.096.195-.187.395-.278.591-.21.463-.398.93-.566 1.399l.002.006a.36.36 0 0 0-.026.058c-.108.303-.203.608-.29.914-.14.174-.302.325-.483.46a3.505 3.505 0 0 0-.131-.153 5.148 5.148 0 0 0 .824-2.211 6.4 6.4 0 0 0-.016-1.488c-.046-.4-.126-.82-.238-1.274-.097-.393-.217-.81-.363-1.248-.091.185-.22.367-.379.545l-.086.094c-.029.032-.06.06-.092.094.434-.674.486-1.397.358-2.148a2.722 2.722 0 0 1-.49.85c-.033.038-.072.077-.11.116-.01.007-.019.018-.033.028.144-.24.25-.467.318-.698a1.29 1.29 0 0 0 .04-.146 2.85 2.85 0 0 0 .038-.225l.018-.146a2.11 2.11 0 0 0-.002-.354c-.003-.04-.004-.076-.01-.113-.01-.055-.016-.105-.027-.154a7.416 7.416 0 0 0-.193-.84c-.01-.028-.015-.056-.026-.084-.027-.079-.048-.149-.072-.209a2.1 2.1 0 0 0-.09-.209.455.455 0 0 1-.035.1c-.102.24-.34.57-.557.8-.003.003-.007.005-.007.01l-.04.043c.318-.58.39-.946.385-1.398a12.274 12.274 0 0 0-.16-1.615 10.68 10.68 0 0 0-.232-1.104 5.853 5.853 0 0 0-.18-.558 6.337 6.337 0 0 0-.172-.391 26.18 26.18 0 0 0 .002-.004C5.576.341 4.82.124 4.82.124s-.27-.11-.582-.123zm3.38 15.783l.032.082v.002c-.06.033-.116.067-.178.097-.012.004-.024.012-.039.018a2.41 2.41 0 0 0 .186-.2zm-.603 1.626c.13.136.25.242.354.32l.07.227a1.866 1.866 0 0 0-.246.053l-.03-.098c-.024-.084-.048-.17-.076-.257l-.021-.073zm.26.875a2.34 2.34 0 0 1 .271.01l.07.229a.778.778 0 0 1 .247-.004l-.326.627a127.643 127.643 0 0 1-.262-.862z" }, "child": [] }] })(props);
}
function SiApachekafka(props) {
  return GenIcon({ "attr": { "role": "img", "viewBox": "0 0 24 24" }, "child": [{ "tag": "path", "attr": { "d": "M9.71 2.136a1.43 1.43 0 0 0-2.047 0h-.007a1.48 1.48 0 0 0-.421 1.042c0 .41.161.777.422 1.039l.007.007c.257.264.616.426 1.019.426.404 0 .766-.162 1.027-.426l.003-.007c.261-.262.421-.629.421-1.039 0-.408-.159-.777-.421-1.042H9.71zM8.683 22.295c.404 0 .766-.167 1.027-.429l.003-.008c.261-.261.421-.631.421-1.036 0-.41-.159-.778-.421-1.044H9.71a1.42 1.42 0 0 0-1.027-.432 1.4 1.4 0 0 0-1.02.432h-.007c-.26.266-.422.634-.422 1.044 0 .406.161.775.422 1.036l.007.008c.258.262.617.429 1.02.429zm7.89-4.462c.359-.096.683-.33.882-.684l.027-.052a1.47 1.47 0 0 0 .114-1.067 1.454 1.454 0 0 0-.675-.896l-.021-.014a1.425 1.425 0 0 0-1.078-.132c-.36.091-.684.335-.881.686-.2.349-.241.75-.146 1.119.099.363.33.691.675.896h.002c.346.203.737.239 1.101.144zm-6.405-7.342a2.083 2.083 0 0 0-1.485-.627c-.58 0-1.103.242-1.482.627-.378.385-.612.916-.612 1.507s.233 1.124.612 1.514a2.08 2.08 0 0 0 2.967 0c.379-.39.612-.923.612-1.514s-.233-1.122-.612-1.507zm-.835-2.51c.843.141 1.6.552 2.178 1.144h.004c.092.093.182.196.265.299l1.446-.851a3.176 3.176 0 0 1-.047-1.808 3.149 3.149 0 0 1 1.456-1.926l.025-.016a3.062 3.062 0 0 1 2.345-.306c.77.21 1.465.721 1.898 1.482v.002c.431.757.518 1.626.313 2.408a3.145 3.145 0 0 1-1.456 1.928l-.198.118h-.02a3.095 3.095 0 0 1-2.154.201 3.127 3.127 0 0 1-1.514-.944l-1.444.848a4.162 4.162 0 0 1 0 2.879l1.444.846c.413-.47.939-.789 1.514-.944a3.041 3.041 0 0 1 2.371.319l.048.023v.002a3.17 3.17 0 0 1 1.408 1.906 3.215 3.215 0 0 1-.313 2.405l-.026.053-.003-.005a3.147 3.147 0 0 1-1.867 1.436 3.096 3.096 0 0 1-2.371-.318v-.006a3.156 3.156 0 0 1-1.456-1.927 3.175 3.175 0 0 1 .047-1.805l-1.446-.848a3.905 3.905 0 0 1-.265.294l-.004.005a3.938 3.938 0 0 1-2.178 1.138v1.699a3.09 3.09 0 0 1 1.56.862l.002.004c.565.572.914 1.368.914 2.243 0 .873-.35 1.664-.914 2.239l-.002.009a3.1 3.1 0 0 1-2.21.931 3.1 3.1 0 0 1-2.206-.93h-.002v-.009a3.186 3.186 0 0 1-.916-2.239c0-.875.35-1.672.916-2.243v-.004h.002a3.1 3.1 0 0 1 1.558-.862v-1.699a3.926 3.926 0 0 1-2.176-1.138l-.006-.005a4.098 4.098 0 0 1-1.173-2.874c0-1.122.452-2.136 1.173-2.872h.006a3.947 3.947 0 0 1 2.176-1.144V6.289a3.137 3.137 0 0 1-1.558-.864h-.002v-.004a3.192 3.192 0 0 1-.916-2.243c0-.871.35-1.669.916-2.243l.002-.002A3.084 3.084 0 0 1 8.683 0c.861 0 1.641.355 2.21.932v.002h.002c.565.574.914 1.372.914 2.243 0 .876-.35 1.667-.914 2.243l-.002.005a3.142 3.142 0 0 1-1.56.864v1.692zm8.121-1.129l-.012-.019a1.452 1.452 0 0 0-.87-.668 1.43 1.43 0 0 0-1.103.146h.002c-.347.2-.58.529-.677.896-.095.365-.054.768.146 1.119l.007.009c.2.347.519.579.874.673.357.103.755.059 1.098-.144l.019-.009a1.47 1.47 0 0 0 .657-.885 1.493 1.493 0 0 0-.141-1.118" }, "child": [] }] })(props);
}
function VscAzure(props) {
  return GenIcon({ "attr": { "viewBox": "0 0 16 16", "fill": "currentColor" }, "child": [{ "tag": "path", "attr": { "fillRule": "evenodd", "clipRule": "evenodd", "d": "M15.3702 13.6799L11.3702 1.67989C11.3006 1.47291 11.1652 1.29438 10.9846 1.17159C10.804 1.0488 10.5882 0.988513 10.3702 0.999896H5.63017C5.42052 0.999354 5.21598 1.0647 5.04551 1.18672C4.87504 1.30875 4.74724 1.48127 4.68015 1.67989L0.630165 13.6799C0.577646 13.8346 0.56382 13.9998 0.589943 14.1611C0.616066 14.3225 0.681335 14.4749 0.780007 14.6052C0.878678 14.7354 1.00778 14.8395 1.15598 14.9083C1.30419 14.9771 1.46699 15.0086 1.63017 14.9999H4.56016C4.76809 14.9984 4.97035 14.932 5.13883 14.8101C5.30731 14.6883 5.43363 14.5169 5.50016 14.3199L6.11015 12.5399L9.11015 14.8099C9.28448 14.9362 9.49495 15.0028 9.71018 14.9999H14.3902C14.5517 15.0052 14.7121 14.9712 14.8576 14.901C15.0032 14.8307 15.1295 14.7263 15.2259 14.5965C15.3222 14.4668 15.3856 14.3156 15.4107 14.156C15.4359 13.9963 15.422 13.833 15.3702 13.6799ZM9.75016 14.3399C9.67748 14.3399 9.60693 14.3153 9.55015 14.2699L3.90018 10.0799L3.81016 10.0099H6.81016L6.89017 9.79988L7.89017 7.26988L10.1302 13.8999C10.1482 13.9555 10.1515 14.0148 10.1399 14.072C10.1283 14.1293 10.1022 14.1826 10.064 14.2269C10.0258 14.2711 9.97689 14.3047 9.92191 14.3245C9.86694 14.3443 9.80778 14.3496 9.75016 14.3399V14.3399ZM14.4201 14.3399H10.7002C10.7749 14.1262 10.7749 13.8935 10.7002 13.6799L6.65018 1.67989H10.3702C10.4408 1.68024 10.5095 1.70258 10.5669 1.74379C10.6242 1.78501 10.6673 1.84308 10.6902 1.9099L14.7402 13.9099C14.7538 13.9597 14.756 14.012 14.7464 14.0628C14.7369 14.1136 14.7159 14.1615 14.6851 14.203C14.6542 14.2444 14.6144 14.2783 14.5685 14.302C14.5226 14.3257 14.4718 14.3387 14.4201 14.3399V14.3399Z" }, "child": [] }] })(props);
}
const EXTENSION_BRANDS = {
  git: { slug: "git", label: "Git", color: "F05032" },
  github: { slug: "github", label: "GitHub", color: "181717" },
  "github-actions": { slug: "github-actions", label: "GitHub Actions", color: "2088FF" },
  gitlab: { slug: "gitlab", label: "GitLab", color: "FC6D26" },
  circleci: { slug: "circleci", label: "CircleCI", color: "343434" },
  aws: { slug: "aws", label: "AWS", color: "FF9900" },
  gcp: { slug: "gcp", label: "Google Cloud", color: "4285F4" },
  azure: { slug: "azure", label: "Azure", color: "0078D4" },
  postgresql: { slug: "postgresql", label: "PostgreSQL", color: "4169E1" },
  mysql: { slug: "mysql", label: "MySQL", color: "4479A1" },
  mongodb: { slug: "mongodb", label: "MongoDB", color: "47A248" },
  redis: { slug: "redis", label: "Redis", color: "FF4438" },
  sqlite: { slug: "sqlite", label: "SQLite", color: "003B57" },
  supabase: { slug: "supabase", label: "Supabase", color: "3FCF8E" },
  vercel: { slug: "vercel", label: "Vercel", color: "000000" },
  netlify: { slug: "netlify", label: "Netlify", color: "00C7B7" },
  heroku: { slug: "heroku", label: "Heroku", color: "430098" },
  minio: { slug: "minio", label: "MinIO", color: "C72E49" },
  elasticsearch: { slug: "elasticsearch", label: "Elasticsearch", color: "005571" },
  kafka: { slug: "kafka", label: "Apache Kafka", color: "231F20" },
  rabbitmq: { slug: "rabbitmq", label: "RabbitMQ", color: "FF6600" },
  nats: { slug: "nats", label: "NATS", color: "27AAE1" },
  docker: { slug: "docker", label: "Docker", color: "2496ED" },
  kubernetes: { slug: "kubernetes", label: "Kubernetes", color: "326CE5" },
  helm: { slug: "helm", label: "Helm", color: "0F1689" },
  launchdarkly: { slug: "launchdarkly", label: "LaunchDarkly", color: "A34FDE" },
  stripe: { slug: "stripe", label: "Stripe", color: "635BFF" },
  npm: { slug: "npm", label: "npm", color: "CB3837" },
  node: { slug: "node", label: "Node.js", color: "5FA04E" },
  python: { slug: "python", label: "Python", color: "3776AB" },
  rust: { slug: "rust", label: "Rust", color: "000000" },
  go: { slug: "go", label: "Go", color: "00ADD8" },
  ruby: { slug: "ruby", label: "Ruby", color: "CC342D" },
  php: { slug: "php", label: "PHP", color: "777BB4" },
  composer: { slug: "composer", label: "Composer", color: "885630" },
  maven: { slug: "maven", label: "Maven", color: "C71A36" },
  gradle: { slug: "gradle", label: "Gradle", color: "02303A" },
  homebrew: { slug: "homebrew", label: "Homebrew", color: "FBB040" },
  debian: { slug: "debian", label: "Debian", color: "A81D33" },
  terraform: { slug: "terraform", label: "Terraform", color: "844FBA" },
  opentofu: { slug: "opentofu", label: "OpenTofu", color: "FFDA18" },
  pulumi: { slug: "pulumi", label: "Pulumi", color: "8A3391" },
  windows: { slug: "windows", label: "Windows", color: "0078D4" },
  rclone: { slug: "rclone", label: "Rclone", color: "3F79AD" },
  restic: { slug: "restic", label: "Restic", color: "2EA043" },
  borg: { slug: "borg", label: "Borg", color: "00B000" },
  velero: { slug: "velero", label: "Velero", color: "326CE5" },
  openssh: { slug: "openssh", label: "OpenSSH", color: "F2CA30" }
};
const CLOUD_CLUSTER = ["aws", "gcp", "azure"];
const BY_EXTENSION_ID = {
  "command.git": ["git"],
  "command.github": ["github"],
  "command.filesystem": [],
  "command.system": [],
  "command.windows": ["windows"],
  "command.container-runtime": ["docker"],
  "command.data-protection": [],
  "command.encoded-execution": [],
  "command.guard-self-protection": [],
  "command.kubernetes-secrets": ["kubernetes"],
  "command.shell-mutations": [],
  "command.package.node": ["node", "npm"],
  "command.package.python": ["python"],
  "command.package.rust": ["rust"],
  "command.package.go": ["go"],
  "command.package.jvm": ["maven", "gradle"],
  "command.package.ruby": ["ruby"],
  "command.package.php": ["php", "composer"],
  "command.package.system": ["homebrew", "debian"],
  "command.cloud.aws": ["aws"],
  "command.cloud.gcp": ["gcp"],
  "command.cloud.azure": ["azure"],
  "command.database.postgresql": ["postgresql"],
  "command.database.mysql": ["mysql"],
  "command.database.mongodb": ["mongodb"],
  "command.database.redis": ["redis"],
  "command.database.sqlite": ["sqlite"],
  "command.database.supabase": ["supabase"],
  "command.storage.aws-s3": ["aws"],
  "command.storage.google-cloud": ["gcp"],
  "command.storage.azure-blob": ["azure"],
  "command.storage.minio": ["minio"],
  "command.backup.rclone": ["rclone"],
  "command.backup.restic": ["restic"],
  "command.backup.borg": ["borg"],
  "command.backup.velero": ["velero"],
  "command.remote.ssh": [],
  "command.remote.scp": [],
  "command.remote.rsync": [],
  "command.cicd.github": ["github-actions"],
  "command.cicd.gitlab": ["gitlab"],
  "command.cicd.circleci": ["circleci"],
  "command.platform.vercel": ["vercel"],
  "command.platform.netlify": ["netlify"],
  "command.platform.heroku": ["heroku"],
  "command.dns": CLOUD_CLUSTER,
  "command.cdn": CLOUD_CLUSTER,
  "command.api-gateway": CLOUD_CLUSTER,
  "command.load-balancer": CLOUD_CLUSTER,
  "command.monitoring": CLOUD_CLUSTER,
  "command.email": ["aws"],
  "command.feature-flags": ["launchdarkly"],
  "command.payment": ["stripe"],
  "command.search.elasticsearch": ["elasticsearch"],
  "command.messaging.kafka": ["kafka"],
  "command.messaging.rabbitmq": ["rabbitmq"],
  "command.messaging.nats": ["nats"],
  "command.kubernetes-operations": ["kubernetes", "helm"],
  "command.infrastructure-as-code": ["terraform", "opentofu", "pulumi"]
};
Object.freeze(Object.keys(BY_EXTENSION_ID));
const INFERENCE = [
  { slug: "github-actions", pattern: /\bgithub actions\b/ },
  { slug: "github", pattern: /\bgithub\b/ },
  { slug: "gitlab", pattern: /\bgitlab\b/ },
  { slug: "circleci", pattern: /\bcircleci\b/ },
  { slug: "git", pattern: /\bgit\b/ },
  { slug: "aws", pattern: /\b(?:aws|amazon|s3)\b/ },
  { slug: "gcp", pattern: /\b(?:gcp|gcloud|google cloud)\b/ },
  { slug: "azure", pattern: /\bazure\b/ },
  { slug: "postgresql", pattern: /\b(?:postgres|postgresql|psql)\b/ },
  { slug: "mysql", pattern: /\bmysql\b/ },
  { slug: "mongodb", pattern: /\b(?:mongo|mongodb)\b/ },
  { slug: "redis", pattern: /\bredis\b/ },
  { slug: "sqlite", pattern: /\bsqlite\b/ },
  { slug: "supabase", pattern: /\bsupabase\b/ },
  { slug: "vercel", pattern: /\bvercel\b/ },
  { slug: "netlify", pattern: /\bnetlify\b/ },
  { slug: "heroku", pattern: /\bheroku\b/ },
  { slug: "minio", pattern: /\bminio\b/ },
  { slug: "elasticsearch", pattern: /\b(?:elastic|elasticsearch)\b/ },
  { slug: "kafka", pattern: /\bkafka\b/ },
  { slug: "rabbitmq", pattern: /\brabbit(?:mq)?\b/ },
  { slug: "nats", pattern: /\bnats\b/ },
  { slug: "docker", pattern: /\b(?:docker|podman|container)\b/ },
  { slug: "kubernetes", pattern: /\b(?:kubernetes|kubectl|k8s)\b/ },
  { slug: "helm", pattern: /\bhelm\b/ },
  { slug: "launchdarkly", pattern: /\b(?:launchdarkly|feature.?flag)\b/ },
  { slug: "stripe", pattern: /\bstripe\b/ },
  { slug: "npm", pattern: /\bnpm\b/ },
  { slug: "node", pattern: /\b(?:node|nodejs|nodedotjs)\b/ },
  { slug: "python", pattern: /\b(?:python|pip|poetry)\b/ },
  { slug: "rust", pattern: /\b(?:rust|cargo)\b/ },
  { slug: "go", pattern: /\bgolang\b|\bgo\b/ },
  { slug: "ruby", pattern: /\b(?:ruby|gem|bundler)\b/ },
  { slug: "php", pattern: /\bphp\b/ },
  { slug: "composer", pattern: /\bcomposer\b/ },
  { slug: "maven", pattern: /\b(?:maven|mvn)\b/ },
  { slug: "gradle", pattern: /\bgradle\b/ },
  { slug: "homebrew", pattern: /\b(?:homebrew|brew)\b/ },
  { slug: "debian", pattern: /\b(?:debian|apt)\b/ },
  { slug: "terraform", pattern: /\bterraform\b/ },
  { slug: "opentofu", pattern: /\b(?:opentofu|tofu)\b/ },
  { slug: "pulumi", pattern: /\bpulumi\b/ },
  { slug: "windows", pattern: /\bwindows\b/ },
  { slug: "rclone", pattern: /\brclone\b/ },
  { slug: "restic", pattern: /\brestic\b/ },
  { slug: "borg", pattern: /\bborg\b/ },
  { slug: "velero", pattern: /\bvelero\b/ },
  { slug: "openssh", pattern: /\b(?:ssh|scp|openssh)\b/ }
];
function searchableText(input) {
  return [
    input.extension_id,
    input.name ?? "",
    ...input.executables ?? [],
    ...input.ecosystem_ids ?? []
  ].join(" ").replace(/[._/-]+/g, " ").toLowerCase();
}
function uniqueSlugs(slugs) {
  const seen = /* @__PURE__ */ new Set();
  const ordered = [];
  for (const slug of slugs) {
    if (seen.has(slug)) continue;
    seen.add(slug);
    ordered.push(slug);
  }
  return ordered.slice(0, 3);
}
function inferSlugs(input) {
  const text2 = searchableText(input);
  const found = [];
  for (const entry of INFERENCE) {
    if (entry.pattern.test(text2)) found.push(entry.slug);
  }
  return uniqueSlugs(found);
}
function fallbackForExtensionId(extensionId) {
  if (extensionId === "command.guard-self-protection") return "shield";
  if (extensionId.includes("secret") || extensionId.includes("data-protection")) return "lock";
  if (extensionId.includes("package")) return "cube";
  if (extensionId.includes("cloud") || extensionId.includes("platform")) return "cloud";
  if (extensionId.includes("database") || extensionId.includes("storage") || extensionId.includes("backup")) return "server";
  if (extensionId.includes("remote") || extensionId.includes("network")) return "globe";
  if (extensionId.includes("filesystem")) return "folder";
  if (extensionId.includes("shell") || extensionId.includes("system") || extensionId.includes("encoded") || extensionId.includes("rsync")) return "terminal";
  if (extensionId.includes("payment") || extensionId.includes("feature")) return "bolt";
  return "shield";
}
function isNearBlackBrand(color) {
  const hex = color.toLowerCase();
  return hex === "000000" || hex === "181717" || hex === "231f20" || hex === "343434";
}
function resolveExtensionBrand(input) {
  const fallback = fallbackForExtensionId(input.extension_id);
  if (input.extension_id === "command.guard-self-protection") {
    return { kind: "guard", marks: [], fallback: "shield" };
  }
  const mapped = BY_EXTENSION_ID[input.extension_id];
  const slugs = uniqueSlugs(mapped ?? inferSlugs(input));
  if (slugs.length === 0) {
    return { kind: "fallback", marks: [], fallback };
  }
  return {
    kind: "marks",
    marks: slugs.map((slug) => EXTENSION_BRANDS[slug]),
    fallback
  };
}
function extensionBrandTestId(resolution) {
  if (resolution.kind === "guard") return "guard";
  if (resolution.kind === "marks") return resolution.marks.map((mark) => mark.slug).join(" ");
  return `fallback-${resolution.fallback}`;
}
function OriginalMark(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("svg", { viewBox: "0 0 24 24", className: props.className, "aria-hidden": "true", focusable: "false", children: props.children });
}
function LaunchDarklyMark({ className }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(OriginalMark, { className, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("rect", { x: "2.5", y: "8", width: "19", height: "8", rx: "4" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("circle", { cx: "15.5", cy: "12", r: "2.6", fill: "#fff" })
  ] });
}
function ResticMark({ className }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(OriginalMark, { className, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("ellipse", { cx: "12", cy: "6.5", rx: "8", ry: "2.6" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("path", { d: "M4 6.5v11c0 1.5 3.6 2.6 8 2.6s8-1.1 8-2.6v-11", fill: "none", stroke: "currentColor", strokeWidth: "2" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("ellipse", { cx: "12", cy: "12", rx: "8", ry: "2.6", fill: "none", stroke: "currentColor", strokeWidth: "2" })
  ] });
}
function VeleroMark({ className }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(OriginalMark, { className, children: /* @__PURE__ */ jsxRuntimeExports.jsx("path", { d: "M5 20V4l14 9.5H9.5z" }) });
}
const BRAND_ICONS = {
  git: SiGit,
  github: SiGithub,
  "github-actions": SiGithubactions,
  gitlab: SiGitlab,
  circleci: SiCircleci,
  aws: FaAws,
  gcp: SiGooglecloud,
  azure: VscAzure,
  postgresql: SiPostgresql,
  mysql: SiMysql,
  mongodb: SiMongodb,
  redis: SiRedis,
  sqlite: SiSqlite,
  supabase: SiSupabase,
  vercel: SiVercel,
  netlify: SiNetlify,
  heroku: SiHeroku,
  minio: SiMinio,
  elasticsearch: SiElasticsearch,
  kafka: SiApachekafka,
  rabbitmq: SiRabbitmq,
  nats: SiNatsdotio,
  docker: SiDocker,
  kubernetes: SiKubernetes,
  helm: SiHelm,
  launchdarkly: LaunchDarklyMark,
  stripe: SiStripe,
  npm: SiNpm,
  node: SiNodedotjs,
  python: SiPython,
  rust: SiRust,
  go: SiGo,
  ruby: SiRuby,
  php: SiPhp,
  composer: SiComposer,
  maven: SiApachemaven,
  gradle: SiGradle,
  homebrew: SiHomebrew,
  debian: SiDebian,
  terraform: SiTerraform,
  opentofu: SiOpentofu,
  pulumi: SiPulumi,
  windows: FaWindows,
  rclone: SiRclone,
  restic: ResticMark,
  borg: SiBorgbackup,
  velero: VeleroMark,
  openssh: SiOpenbsd
};
const FALLBACK_ICONS = {
  shield: HiMiniShieldCheck,
  folder: HiMiniFolder,
  terminal: HiMiniCommandLine,
  server: HiMiniServerStack,
  cloud: HiMiniCloud,
  lock: HiMiniLockClosed,
  cube: HiMiniCube,
  globe: HiMiniGlobeAlt,
  bolt: HiMiniBolt
};
function tileStyle(color) {
  const hex = isNearBlackBrand(color) ? "3f4174" : color;
  return { ["--extension-brand"]: `#${hex}` };
}
function MarkTile(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "span",
    {
      className: "guard-extension-mark",
      "data-size": props.size,
      "data-stacked": props.stacked ? "true" : void 0,
      style: tileStyle(props.color),
      title: props.label,
      "aria-hidden": "true",
      children: props.children
    }
  );
}
function ExtensionBrandMark(props) {
  const size = props.size ?? "md";
  const resolution = resolveExtensionBrand(props);
  const testId = extensionBrandTestId(resolution);
  if (resolution.kind === "guard") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "guard-extension-mark", "data-size": size, "data-extension-brand": testId, "data-kind": "guard", "aria-hidden": "true", children: /* @__PURE__ */ jsxRuntimeExports.jsx("img", { src: "/brand/Logo_Icon_Dark.png", alt: "" }) });
  }
  if (resolution.kind === "fallback") {
    const FallbackIcon = FALLBACK_ICONS[resolution.fallback];
    return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "guard-extension-mark", "data-size": size, "data-extension-brand": testId, "data-kind": "fallback", style: tileStyle("5599fe"), "aria-hidden": "true", children: /* @__PURE__ */ jsxRuntimeExports.jsx(FallbackIcon, {}) });
  }
  if (resolution.marks.length === 1) {
    const mark = resolution.marks[0];
    const Icon = BRAND_ICONS[mark.slug];
    return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "data-extension-brand": testId, "data-kind": "marks", "aria-hidden": "true", children: /* @__PURE__ */ jsxRuntimeExports.jsx(MarkTile, { color: mark.color, label: mark.label, size, children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, {}) }) });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "guard-extension-mark-cluster", "data-extension-brand": testId, "data-kind": "marks", "data-size": size, "aria-hidden": "true", children: resolution.marks.map((mark) => {
    const Icon = BRAND_ICONS[mark.slug];
    return /* @__PURE__ */ jsxRuntimeExports.jsx(MarkTile, { color: mark.color, label: mark.label, size, stacked: true, children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, {}) }, mark.slug);
  }) });
}
function ProtectionStatusHero(props) {
  const safe = props.status.tone === "safe";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "protection-status-heading", className: "guard-status-bar", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "guard-status-bar-icon", "data-tone": props.status.tone, "aria-hidden": "true", children: safe ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-4" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "size-4" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-slate-400", children: "Local protection" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-0.5 flex flex-wrap items-baseline gap-x-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "protection-status-heading", className: "text-sm font-semibold text-brand-dark", children: props.status.title }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm leading-5 text-brand-dark/70", children: props.status.summary })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      ProtectionStatusAction,
      {
        busy: props.busy === true,
        safe,
        primaryActionLabel: props.status.primaryActionLabel,
        onPrimaryAction: props.onPrimaryAction
      }
    ),
    props.children ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "w-full border-t border-[rgba(63,65,116,0.08)] pt-2", children: props.children }) : null
  ] });
}
function ProtectionStatusAction(props) {
  if (props.primaryActionLabel && props.onPrimaryAction) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        "aria-busy": props.busy,
        disabled: props.busy,
        onClick: props.onPrimaryAction,
        className: "min-h-11 shrink-0 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white shadow-sm hover:bg-brand-dark disabled:cursor-wait disabled:opacity-60",
        children: props.busy ? "Working…" : props.primaryActionLabel
      }
    );
  }
  if (props.safe) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex min-h-9 shrink-0 items-center gap-1.5 self-center rounded-full border border-emerald-200 bg-[#e8f7ee] px-3 text-xs font-semibold text-emerald-800", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "size-3.5" }),
      "No action required"
    ] });
  }
  return null;
}
function ProtectionDecisionBadge({ result }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${decisionBadgeClasses(result)}`, children: decisionBadgeLabel(result) });
}
function decisionBadgeLabel(result) {
  if (result === "allowed") return "Allowed";
  if (result === "ask-first") return "Ask once";
  return "Blocked";
}
function decisionBadgeClasses(result) {
  if (result === "allowed") return "border-emerald-200 bg-emerald-50 text-emerald-800";
  if (result === "ask-first") return "border-amber-200 bg-amber-50 text-amber-800";
  return "border-red-200 bg-red-50 text-red-800";
}
function ProtectionModuleRow(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onOpen, className: `${EXTENSION_ROW_CLASS} motion-reduce:transition-none`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      ExtensionBrandMark,
      {
        extension_id: props.extensionId,
        name: props.name,
        executables: props.executables,
        ecosystem_ids: props.ecosystemIds,
        size: "md"
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-sm text-brand-dark", children: props.name }),
        props.required ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold text-brand-dark/55", children: "Required by Guard" }) : null,
        props.managed ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold text-brand-dark/55", children: props.managedLabel ?? "Synced from Guard Cloud" }) : null,
        props.custom ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold text-brand-dark/55", children: "Custom" }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 block truncate text-sm text-brand-dark/70", children: props.behavior })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { className: "size-5 shrink-0 text-brand-dark/35", "aria-hidden": "true" })
  ] });
}
function TechnicalDetails(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: `${EXTENSION_PANEL_CLASS}`, "data-testid": props.testId, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer list-none text-sm font-semibold text-brand-dark", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-2", children: [
      props.title ?? "Technical details",
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronDown, { className: "size-4", "aria-hidden": "true" })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 text-sm text-brand-dark/80", children: props.children })
  ] });
}
function InlineError({ message }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800", children: message });
}
function customExtensionContinuityView(state) {
  const privacyDisclosure = "Guard Cloud receives stable identity and compatibility metadata, not local source paths.";
  switch (state) {
    case "local-only":
      return {
        state,
        title: "Available on this device",
        description: "This custom protection remains local until portable continuity is enabled.",
        canApplyAcrossDevices: false,
        privacyDisclosure
      };
    case "identity-matched":
      return {
        state,
        title: "Matched on another device",
        description: "Guard matched the stable identity. Each device still uses its own verified definition.",
        canApplyAcrossDevices: true,
        privacyDisclosure
      };
    case "portable":
      return {
        state,
        title: "Portable continuity enabled",
        description: "A verified portable definition is available to compatible devices.",
        canApplyAcrossDevices: true,
        privacyDisclosure
      };
    case "incompatible":
      return {
        state,
        title: "Needs a compatible definition",
        description: "This device cannot apply the shared custom protection safely.",
        canApplyAcrossDevices: false,
        privacyDisclosure
      };
    case "pending-observation":
      return {
        state,
        title: "Waiting for this device",
        description: "Cloud settings stay pending until Guard observes the same extension identity locally.",
        canApplyAcrossDevices: false,
        privacyDisclosure
      };
    case "changed-identity":
      return {
        state,
        title: "Identity changed",
        description: "Guard refused the Cloud settings because this device observed a different identity.",
        canApplyAcrossDevices: false,
        privacyDisclosure
      };
    case "locally-overridden":
      return {
        state,
        title: "Changed on this device",
        description: "Guard kept this device's local setting until a newer Cloud revision is available.",
        canApplyAcrossDevices: false,
        privacyDisclosure
      };
    case "removed":
      return {
        state,
        title: "Removed on this device",
        description: "The local setting was removed. Guard did not delete the script, executable, or MCP configuration.",
        canApplyAcrossDevices: false,
        privacyDisclosure
      };
    case "stale":
      return {
        state,
        title: "Cloud observation is stale",
        description: "Guard kept the last-known-good local setting and did not apply expired Cloud state.",
        canApplyAcrossDevices: false,
        privacyDisclosure
      };
  }
}
function randomToken$2() {
  return crypto.randomUUID().replaceAll("-", "");
}
function AddCustomExtensionWorkspace(props) {
  const { resolvedApprovalGate, resolveApprovalGate, refreshApprovalGate } = useResolvedApprovalGate(null);
  const [command, setCommand] = reactExports.useState("");
  const [recognized, setRecognized] = reactExports.useState(null);
  const [commands, setCommands] = reactExports.useState([]);
  const [summary, setSummary] = reactExports.useState(null);
  const [pending, setPending] = reactExports.useState(null);
  const [step, setStep] = reactExports.useState("pick");
  const [password, setPassword] = reactExports.useState("");
  const [totp, setTotp] = reactExports.useState("");
  const [busy, setBusy] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [reviewingScripts, setReviewingScripts] = reactExports.useState(false);
  const recognizeGeneration = reactExports.useRef(0);
  const autoRecognizedCommand = reactExports.useRef("");
  const didAutoSelect = reactExports.useRef(false);
  const rememberedProjects = suggestedPackageScriptExtensions(props.items);
  const packageScriptSuggestions = filterExtensionSuggestions(rememberedProjects, command).slice(0, 8);
  const harnessSuggestions = filterExtensionSuggestions(suggestedHarnessExtensions(props.items), command).slice(0, 8);
  const seenSuggestions = filterExtensionSuggestions(suggestedSeenExtensions(props.items), command).slice(0, 6);
  const hasSuggestions = packageScriptSuggestions.length > 0 || harnessSuggestions.length > 0 || seenSuggestions.length > 0;
  reactExports.useEffect(() => {
    void resolveApprovalGate({ failClosed: true }).catch(() => {
      setError("Guard could not load local approval settings yet.");
    });
  }, [resolveApprovalGate]);
  const resetRecognition = reactExports.useCallback(() => {
    recognizeGeneration.current += 1;
    autoRecognizedCommand.current = "";
    setBusy(false);
    setRecognized(null);
    setCommands([]);
    setSummary(null);
    setPending(null);
    setReviewingScripts(false);
    setStep("pick");
  }, []);
  const handleCommand = reactExports.useCallback((event) => {
    const value = event.target.value;
    const keepCatalog = recognized?.surface === "package-scripts" && keepsPackageScriptCatalog(value, commands);
    setCommand(value);
    setError(null);
    if (keepCatalog) return;
    resetRecognition();
  }, [commands, recognized, resetRecognition]);
  const handlePassword = reactExports.useCallback((event) => {
    setPassword(event.target.value);
  }, []);
  const handleTotp = reactExports.useCallback((event) => {
    const digits = event.target.value.replace(/\D/g, "").slice(0, 6);
    event.target.value = digits;
    setTotp(digits);
  }, []);
  const markRecognized = reactExports.useCallback((item, nextSummary) => {
    setRecognized(item);
    setCommands(item.commands);
    setSummary(nextSummary);
    setPending("allowed");
    setReviewingScripts(false);
    setStep("review");
  }, []);
  const runRecognize = reactExports.useCallback(async (commandText, cliId, silent = false) => {
    const generation = recognizeGeneration.current + 1;
    recognizeGeneration.current = generation;
    setBusy(true);
    if (!silent) setError(null);
    try {
      const result = await recognizeLocalCli(commandText, cliId ? { cliId } : void 0);
      if (recognizeGeneration.current !== generation) return;
      markRecognized(result.item, result.summary);
      setError(null);
    } catch (caught) {
      if (recognizeGeneration.current !== generation) return;
      setRecognized(null);
      setSummary(null);
      setStep("pick");
      if (!silent) {
        setError(caught instanceof LocalCliApiError ? caught.message : "Guard could not identify that command.");
      }
    } finally {
      if (recognizeGeneration.current === generation) setBusy(false);
    }
  }, [markRecognized]);
  const selectSuggestion = reactExports.useCallback((item) => {
    if (item.surface !== "package-scripts") setCommand(item.example_label);
    setError(null);
    if (item.surface === "mcp" && item.commands.length === 0) {
      setRecognized(null);
      setCommands([]);
      setSummary(null);
      setPending(null);
      setStep("pick");
      void runRecognize(item.example_label, item.cli_id);
      return;
    }
    markRecognized(item, suggestionSummary(item));
  }, [markRecognized, runRecognize]);
  const findTool = reactExports.useCallback(async () => {
    await runRecognize(command);
  }, [command, runRecognize]);
  reactExports.useEffect(() => {
    if (didAutoSelect.current || recognized !== null || command.trim() !== "") return;
    const preferred = preferredPackageScriptExtension(props.items);
    if (preferred === null) return;
    didAutoSelect.current = true;
    selectSuggestion(preferred);
  }, [command, props.items, recognized, selectSuggestion]);
  reactExports.useEffect(() => {
    const trimmed = command.trim();
    if (recognized !== null || !looksLikePackageScriptPaste(trimmed)) return;
    if (autoRecognizedCommand.current === trimmed) return;
    const handle = window.setTimeout(() => {
      autoRecognizedCommand.current = trimmed;
      void runRecognize(trimmed, void 0, true);
    }, 280);
    return () => window.clearTimeout(handle);
  }, [busy, command, recognized, runRecognize]);
  const requestAllow = reactExports.useCallback(() => setPending("allowed"), []);
  const requestBlock = reactExports.useCallback(() => setPending("blocked"), []);
  const openScriptReview = reactExports.useCallback(() => setReviewingScripts(true), []);
  const closeScriptReview = reactExports.useCallback(() => setReviewingScripts(false), []);
  const backToReview = reactExports.useCallback(() => {
    setStep("review");
    setError(null);
  }, []);
  const applyBulk = reactExports.useCallback((state) => {
    setCommands((current) => applyBulkCommandState(
      current,
      state,
      recognized?.surface === "package-scripts" ? /* @__PURE__ */ new Set(["root", "other"]) : /* @__PURE__ */ new Set()
    ));
    setPending(state === "block" ? "blocked" : "allowed");
  }, [recognized]);
  const handleSubmit = reactExports.useCallback(async (event) => {
    event.preventDefault();
    if (recognized === null) {
      await findTool();
      return;
    }
    if (step !== "confirm") {
      setStep("confirm");
      setError(null);
      setBusy(true);
      try {
        await refreshApprovalGate({ failClosed: true });
      } catch {
        setError("Guard could not load local approval settings yet.");
      } finally {
        setBusy(false);
      }
      return;
    }
    if (pending === null) return;
    setBusy(true);
    setError(null);
    try {
      const payload = {
        cli_id: recognized.cli_id,
        identity_hash: recognized.identity_hash,
        name: recognized.name,
        kind: recognized.kind,
        example_label: recognized.example_label,
        interpreter_name: recognized.interpreter_name,
        state: pending,
        previous_revision: props.revision,
        session_nonce: randomToken$2(),
        commands: enrollmentCommandStates(commands, pending, recognized.surface),
        ...buildApprovalProofCredentials(resolvedApprovalGate, {
          approvalPassword: password,
          approvalTotpCode: totp
        })
      };
      await previewLocalCliMutation(payload);
      await applyLocalCliMutation(payload);
      await refreshApprovalGate();
      props.onAdded(recognized.cli_id);
    } catch (caught) {
      setError(caught instanceof LocalCliApiError ? caught.message : "Guard could not add this custom extension.");
    } finally {
      setBusy(false);
    }
  }, [commands, findTool, password, pending, props, recognized, refreshApprovalGate, resolvedApprovalGate, step, totp]);
  const handleCommandState = reactExports.useCallback((commandId, state) => {
    setCommands((current) => withCommandState(current, commandId, state));
  }, []);
  const proofReady = pending !== null && recognized !== null;
  const confirming = step === "confirm" && recognized !== null;
  const submitDisabled = enrollSubmitDisabled({
    recognized,
    command,
    confirming,
    proofReady,
    proofBlocked: isApprovalProofSubmitDisabled(
      resolvedApprovalGate,
      { approvalPassword: password, approvalTotpCode: totp },
      busy
    ),
    busy
  });
  const showingPackageCatalog = recognized?.surface === "package-scripts";
  const showingMcpCatalog = recognized?.surface === "mcp";
  const showingCatalog = showingPackageCatalog || showingMcpCatalog;
  const enrollable = showingPackageCatalog ? enrollablePackageScriptCommands(commands) : commands;
  const visibleCommands = showingPackageCatalog ? filterPackageScriptCommands(enrollable, command) : commands;
  const previewNames = visibleCommands.slice(0, 8).map((entry) => entry.name);
  const bulkState = bulkCommandState(enrollable);
  const recentlySatisfied = approvalProofRecentlySatisfied(resolvedApprovalGate);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "form",
    {
      "data-testid": "add-custom-extension",
      onSubmit: handleSubmit,
      className: "flex min-h-[70vh] w-full flex-col",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "button",
          {
            type: "button",
            onClick: confirming ? backToReview : props.onBack,
            className: "inline-flex min-h-11 w-fit items-center gap-2 rounded-lg px-1 text-sm font-semibold text-brand-dark/80 hover:text-brand-dark",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowLeft, { className: "size-4", "aria-hidden": "true" }),
              confirming ? "Back to settings" : "Extensions"
            ]
          }
        ),
        confirming && recognized ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-6 max-w-xl", "aria-labelledby": "custom-extension-confirm-title", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { id: "custom-extension-confirm-title", className: "text-2xl font-semibold tracking-tight text-brand-dark", children: pending === "blocked" ? blockActionLabel(recognized.surface) : allowActionLabel(recognized.surface) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-6 text-slate-500", children: recognized.source_label ? `${recognized.name} · ${recognized.source_label}` : recognized.name }),
          summary ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-6 text-slate-500", children: summary }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-5 text-sm leading-6 text-brand-dark/80", children: enrollConfirmCopy(recognized.surface, recentlySatisfied, resolvedApprovalGate?.totp_enabled === true) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5 max-w-sm", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
            ApprovalProofFieldInputs,
            {
              approvalGate: resolvedApprovalGate,
              approvalPassword: password,
              approvalTotpCode: totp,
              onApprovalPasswordChange: handlePassword,
              onApprovalTotpCodeChange: handleTotp
            }
          ) })
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "mt-3 max-w-2xl pb-4", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { id: "add-custom-extension-title", className: "text-2xl font-semibold tracking-tight text-brand-dark", children: "Add a custom extension" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-6 text-slate-500", children: dialogIntro(rememberedProjects.length > 0, recognized?.surface ?? null) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: "custom-extension-command", className: "mt-4 block text-sm font-semibold text-brand-dark", children: commandFieldLabel(recognized?.surface ?? null) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              id: "custom-extension-command",
              value: command,
              onChange: handleCommand,
              spellCheck: false,
              autoComplete: "off",
              placeholder: showingPackageCatalog ? "guard:audit" : "npm run guard:audit",
              className: "mt-2 min-h-11 w-full max-w-xl rounded-xl border border-slate-300 bg-white px-3 text-sm text-brand-dark placeholder:text-brand-dark/40 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/30"
            }
          ),
          recognized !== null && showingPackageCatalog ? /* @__PURE__ */ jsxRuntimeExports.jsx(ProjectSwitcher, { items: rememberedProjects, currentId: recognized.cli_id, onSelect: selectSuggestion }) : null,
          recognized ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-5 max-w-3xl", "aria-labelledby": "custom-extension-selected", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "custom-extension-selected", className: "text-xl font-semibold tracking-tight text-brand-dark", children: recognized.name }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 font-mono text-xs text-brand-dark/70", children: recognized.source_label ? `${recognized.source_label} · ${recognized.example_label}` : recognized.example_label }),
            summary ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-sm leading-6 text-slate-500", children: summary }) : null,
            showingCatalog && enrollable.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(BulkPolicyPicker, { value: bulkState, disabled: busy, onChange: applyBulk }) : null,
            showingCatalog ? /* @__PURE__ */ jsxRuntimeExports.jsx(
              CatalogPreview,
              {
                query: command,
                showFilterCount: showingPackageCatalog,
                previewNames,
                visibleCount: visibleCommands.length,
                totalCount: enrollable.length,
                reviewing: reviewingScripts,
                adjustLabel: showingMcpCatalog ? "Adjust individual tools" : "Adjust individual scripts",
                hideLabel: "Hide individual settings",
                onOpenReview: openScriptReview,
                onCloseReview: closeScriptReview,
                children: visibleCommands.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 overflow-hidden rounded-2xl border border-slate-200 bg-white", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
                  CustomExtensionCommandList,
                  {
                    commands: visibleCommands,
                    disabled: busy,
                    surface: recognized.surface,
                    onChange: handleCommandState
                  }
                ) }) : null
              }
            ) : null,
            !showingCatalog && visibleCommands.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 overflow-hidden rounded-2xl border border-slate-200 bg-white", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
              CustomExtensionCommandList,
              {
                commands: visibleCommands,
                disabled: busy,
                surface: recognized.surface,
                onChange: handleCommandState
              }
            ) }) : null
          ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx(
            SuggestionPanel,
            {
              query: command,
              hasSuggestions,
              packageScriptSuggestions,
              harnessSuggestions,
              seenSuggestions,
              onSelect: selectSuggestion
            }
          )
        ] }),
        error ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 max-w-xl", children: /* @__PURE__ */ jsxRuntimeExports.jsx(InlineError, { message: error }) }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "sticky bottom-0 mt-auto border-t border-slate-200 bg-white py-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "submit", disabled: submitDisabled, className: "min-h-11 rounded-xl bg-brand-blue px-5 text-sm font-semibold text-white disabled:opacity-60", children: addDialogSubmitLabel({ recognized, busy, pending, step: recognized ? step : "pick" }) }),
          recognized && confirming && pending === "allowed" ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: requestBlock, className: "min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark", children: blockActionLabel(recognized.surface) }) : null,
          recognized && confirming && pending === "blocked" ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: requestAllow, className: "min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark", children: allowActionLabel(recognized.surface) }) : null
        ] }) })
      ]
    }
  );
}
function randomToken$1() {
  return crypto.randomUUID().replaceAll("-", "");
}
function detailPolicyCopy(surface) {
  if (surface === "mcp") {
    return "Recommended keeps Guard's usual review. Allow or block applies to that tool from this MCP server. Destructive tools stay under Guard's usual rules.";
  }
  if (surface === "package-scripts") {
    return "Recommended keeps Guard's usual review. Allow or block applies to that npm, pnpm, yarn, or bun script in this project. Nested names such as guard:audit stay grouped.";
  }
  return "Recommended keeps Guard's usual review. Allow or block applies to that command from this file. Pipes, wrappers, and destructive commands stay under Guard's usual rules.";
}
function detailCatalogHeading(surface) {
  if (surface === "mcp") return "MCP tools";
  if (surface === "package-scripts") return "Package scripts";
  return "Command patterns";
}
function detailCatalogHelper(surface) {
  if (surface === "mcp") {
    return "Same settings as built-in tools. Recommended is the safe default for each MCP tool.";
  }
  if (surface === "package-scripts") {
    return "Same settings as built-in tools. Nested scripts stay indented under their prefix.";
  }
  return "Same settings as built-in tools. Recommended is the safe default.";
}
function bulkPolicyCopy(surface) {
  if (surface === "mcp") {
    return {
      groupLabel: "All tools protection setting",
      mixedCopy: "Custom mix. Pick Recommended, Allow all, or Block all to reset every tool."
    };
  }
  if (surface === "package-scripts") {
    return {
      groupLabel: "All scripts protection setting",
      mixedCopy: "Custom mix. Pick Recommended, Allow all, or Block all to reset every script."
    };
  }
  return {
    groupLabel: "All commands protection setting",
    mixedCopy: "Custom mix. Pick Recommended, Allow all, or Block all to reset every command."
  };
}
function reviewTitle(name, state) {
  if (state === "allowed") return `Save ${name} command settings`;
  if (state === "blocked") return `Block ${name}`;
  return `Remove ${name}`;
}
function reviewModalDetail(gate) {
  if (approvalProofRecentlySatisfied(gate)) {
    return "Recently confirmed with your authenticator. A new code is not needed yet.";
  }
  if (gate?.totp_enabled === true) {
    return "Enter the current authenticator code to save these settings on this device.";
  }
  return "This custom Extension remains local to this device until portable continuity is enabled.";
}
function customExtensionUnits(surface) {
  if (surface === "mcp") return { unit: "tool", units: "tools", source: "this server" };
  if (surface === "package-scripts") return { unit: "script", units: "scripts", source: "this project" };
  return { unit: "command", units: "commands", source: "this file" };
}
function customExtensionStateLabel(item) {
  const { unit, units, source } = customExtensionUnits(item.surface);
  if (item.stale) {
    return item.surface === "package-scripts" ? "package.json scripts changed. Review the extension again." : "This file changed. Review the extension again.";
  }
  if (item.state === "blocked") return `Every ${unit} from ${source} is blocked.`;
  if (item.state === "allowed") {
    if (item.commands.length === 0) {
      return `Matching ${units} from ${source} are allowed.`;
    }
    const allowed = item.commands.filter((command) => command.state === "allow").length;
    if (allowed > 0) return `${allowed} ${allowed === 1 ? unit : units} allowed. The rest follow Recommended.`;
    return `${units.charAt(0).toUpperCase()}${units.slice(1)} follow Recommended until you allow or block them.`;
  }
  return item.example_label;
}
function continuityCopy(item) {
  const status = item.continuity?.status;
  if (status === "applied") {
    const view = customExtensionContinuityView("identity-matched");
    return { title: view.title, description: view.description };
  }
  if (status === "pending_observation") return customExtensionContinuityView("pending-observation");
  if (status === "changed_identity") return customExtensionContinuityView("changed-identity");
  if (status === "locally_overridden") return customExtensionContinuityView("locally-overridden");
  if (status === "removed") return customExtensionContinuityView("removed");
  if (status === "stale") return customExtensionContinuityView("stale");
  return null;
}
function CustomExtensionsSection(props) {
  const added = addedCustomExtensions(props.items);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-10", "aria-labelledby": "custom-extensions-heading", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "custom-extensions-heading", className: "text-xl font-semibold tracking-tight text-brand-dark", children: "Custom extensions" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Your own scripts, binaries, and MCP servers, not Guard's built-in catalog." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onAdd, className: "inline-flex min-h-11 items-center gap-2 rounded-xl px-3 text-sm font-semibold text-brand-blue", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniPlus, { className: "size-4", "aria-hidden": "true" }),
        "Add custom extension"
      ] })
    ] }),
    added.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 text-sm leading-6 text-brand-dark/75", children: "None yet. Add one by pasting the command, or pick an MCP server Guard found in your apps." }) : /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: added.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx(CustomExtensionRow, { item, onOpen: props.onOpen }, item.cli_id)) })
  ] });
}
function AddCustomExtensionButton(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onClick, className: "inline-flex min-h-11 items-center gap-2 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniPlus, { className: "size-4", "aria-hidden": "true" }),
    "Add custom extension"
  ] });
}
function CustomExtensionRow(props) {
  const handleOpen = reactExports.useCallback(() => {
    props.onOpen(props.item.cli_id);
  }, [props]);
  const continuity = continuityCopy(props.item);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    ProtectionModuleRow,
    {
      extensionId: props.item.cli_id,
      name: props.item.name,
      description: props.item.source_label ? `${props.item.example_label} · ${props.item.source_label}` : props.item.example_label,
      behavior: continuity ? `${continuity.title}. ${continuity.description}` : customExtensionStateLabel(props.item),
      custom: true,
      executables: [props.item.name],
      onOpen: handleOpen
    }
  );
}
function LocalCliDetail(props) {
  const { resolvedApprovalGate, resolveApprovalGate, refreshApprovalGate } = useResolvedApprovalGate(null);
  const [pending, setPending] = reactExports.useState(null);
  const [commands, setCommands] = reactExports.useState(props.item.commands);
  const [busy, setBusy] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const added = props.item.state !== "unset";
  const commandsDirty = commands.some((command, index) => command.state !== props.item.commands[index]?.state);
  reactExports.useEffect(() => {
    setCommands(props.item.commands);
  }, [props.item.cli_id, props.item.grant_revision]);
  const openPending = reactExports.useCallback(async (state) => {
    await refreshApprovalGate();
    setPending(state);
  }, [refreshApprovalGate]);
  const requestAdd = reactExports.useCallback(() => openPending("allowed"), [openPending]);
  const requestAllow = reactExports.useCallback(() => openPending("allowed"), [openPending]);
  const requestBlock = reactExports.useCallback(() => openPending("blocked"), [openPending]);
  const requestRemove = reactExports.useCallback(() => openPending("unset"), [openPending]);
  const requestSaveCommands = reactExports.useCallback(() => {
    openPending(props.item.state === "blocked" ? "blocked" : "allowed");
  }, [openPending, props.item.state]);
  const handleCommandState = reactExports.useCallback((commandId, state) => {
    setCommands((current) => withCommandState(current, commandId, state));
  }, []);
  const applyBulk = reactExports.useCallback((state) => {
    setCommands((current) => applyBulkCommandState(
      current,
      state,
      props.item.surface === "package-scripts" ? /* @__PURE__ */ new Set(["root", "other"]) : /* @__PURE__ */ new Set()
    ));
  }, [props.item.surface]);
  const bulkTargets = props.item.surface === "package-scripts" ? enrollablePackageScriptCommands(commands) : commands;
  const bulkState = bulkCommandState(bulkTargets);
  const bulkCopy = bulkPolicyCopy(props.item.surface);
  const continuity = customExtensionContinuityView("local-only");
  const clearPending = reactExports.useCallback(() => {
    if (!busy) setPending(null);
  }, [busy]);
  const confirmChange = reactExports.useCallback(async (credentials) => {
    if (pending === null) return;
    setBusy(true);
    setError(null);
    try {
      const payload = {
        cli_id: props.item.cli_id,
        identity_hash: props.item.identity_hash,
        name: props.item.name,
        kind: props.item.kind,
        example_label: props.item.example_label,
        interpreter_name: props.item.interpreter_name,
        state: pending,
        previous_revision: props.revision,
        session_nonce: randomToken$1(),
        commands: commandStatesPayload(commands),
        ...credentials
      };
      await previewLocalCliMutation(payload);
      await applyLocalCliMutation(payload);
      await props.onRefresh();
      await refreshApprovalGate();
      setPending(null);
    } catch (caught) {
      setError(caught instanceof LocalCliApiError ? caught.message : "Guard could not update this custom extension.");
    } finally {
      setBusy(false);
    }
  }, [commands, pending, props, refreshApprovalGate]);
  reactExports.useEffect(() => {
    void resolveApprovalGate({ failClosed: true }).catch(() => {
      setError("Guard could not load the local approval settings yet.");
    });
  }, [resolveApprovalGate]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { "data-testid": "local-cli-detail", className: "w-full", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onBack, className: "inline-flex min-h-11 items-center gap-2 rounded-lg px-1 text-sm font-semibold text-brand-dark/80 hover:text-brand-dark", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowLeft, { className: "size-4", "aria-hidden": "true" }),
      "Extensions"
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "mt-4 border-b border-slate-200 pb-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-mono text-xs font-semibold tracking-[0.14em] text-slate-400", children: props.item.example_label }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "mt-2 text-2xl font-semibold tracking-tight text-brand-dark", children: props.item.name }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-sm leading-6 text-slate-500", children: customExtensionStateLabel(props.item) }),
      continuityCopy(props.item) ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 max-w-2xl rounded-xl border border-slate-200 bg-slate-50 p-3", "data-testid": "custom-extension-continuity", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: continuityCopy(props.item)?.title }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm leading-6 text-slate-600", children: continuityCopy(props.item)?.description })
      ] }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 max-w-2xl text-sm leading-6 text-brand-dark/75", children: detailPolicyCopy(props.item.surface) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5 flex flex-wrap gap-3", children: added ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        props.item.state === "allowed" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "inline-flex min-h-11 items-center rounded-xl bg-slate-100 px-4 text-sm font-semibold text-brand-dark", children: "Allowed on this device" }) : /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white", onClick: requestAllow, children: "Allow this extension's commands" }),
        props.item.state === "blocked" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "inline-flex min-h-11 items-center rounded-xl bg-slate-100 px-4 text-sm font-semibold text-brand-dark", children: "Blocked" }) : /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark", onClick: requestBlock, children: "Block this extension" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark/80", onClick: requestRemove, children: "Remove custom extension" })
      ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white", onClick: requestAdd, children: "Add custom extension" }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-6 rounded-2xl border border-slate-200 bg-slate-50 p-4", "aria-labelledby": "custom-extension-continuity-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "custom-extension-continuity-heading", className: "text-sm font-semibold text-brand-dark", children: continuity.title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-6 text-brand-dark/75", children: props.continuity.summary || continuity.description }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs leading-5 text-brand-dark/60", children: continuity.privacyDisclosure })
    ] }),
    added ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-8", "aria-labelledby": "custom-extension-commands-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "custom-extension-commands-heading", className: "text-lg font-semibold text-brand-dark", children: detailCatalogHeading(props.item.surface) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-2xl text-sm leading-6 text-slate-500", children: detailCatalogHelper(props.item.surface) }),
      bulkTargets.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        BulkPolicyPicker,
        {
          value: bulkState,
          disabled: busy,
          onChange: applyBulk,
          groupLabel: bulkCopy.groupLabel,
          mixedCopy: bulkCopy.mixedCopy
        }
      ) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        CustomExtensionCommandList,
        {
          commands,
          disabled: busy,
          surface: props.item.surface,
          onChange: handleCommandState
        }
      ) }),
      commandsDirty ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "mt-4 min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white", onClick: requestSaveCommands, children: "Review command changes" }) : null
    ] }) : null,
    error && !pending ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(InlineError, { message: error }) }) : null,
    pending ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      CustomExtensionReviewModal,
      {
        item: props.item,
        nextState: pending,
        busy,
        error,
        approvalGate: resolvedApprovalGate,
        onCancel: clearPending,
        onConfirm: confirmChange
      }
    ) : null
  ] });
}
function CustomExtensionReviewModal(props) {
  const [password, setPassword] = reactExports.useState("");
  const [totp, setTotp] = reactExports.useState("");
  const dialogRef = useModalDialog(props.onCancel, !props.busy);
  const title = reviewTitle(props.item.name, props.nextState);
  const handlePassword = reactExports.useCallback((event) => {
    setPassword(event.target.value);
  }, []);
  const handleTotp = reactExports.useCallback((event) => {
    const digits = event.target.value.replace(/\D/g, "").slice(0, 6);
    event.target.value = digits;
    setTotp(digits);
  }, []);
  const handleSubmit = reactExports.useCallback((event) => {
    event.preventDefault();
    props.onConfirm(buildApprovalProofCredentials(props.approvalGate, {
      approvalPassword: password,
      approvalTotpCode: totp
    }));
  }, [password, props, totp]);
  const submitDisabled = isApprovalProofSubmitDisabled(
    props.approvalGate,
    { approvalPassword: password, approvalTotpCode: totp },
    props.busy
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "fixed inset-0 z-50 grid place-items-center bg-slate-950/45 p-4 backdrop-blur-sm", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("form", { ref: dialogRef, tabIndex: -1, role: "dialog", "aria-modal": "true", "aria-labelledby": "custom-extension-review-title", onSubmit: handleSubmit, className: "w-full max-w-lg rounded-3xl bg-white p-6 shadow-2xl focus:outline-none", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "custom-extension-review-title", className: "text-xl font-semibold text-brand-dark", children: title }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-6 text-brand-dark/80", children: reviewModalDetail(props.approvalGate) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      ApprovalProofFieldInputs,
      {
        approvalGate: props.approvalGate,
        approvalPassword: password,
        approvalTotpCode: totp,
        onApprovalPasswordChange: handlePassword,
        onApprovalTotpCodeChange: handleTotp
      }
    ) }),
    props.error ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(InlineError, { message: props.error }) }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 flex justify-end gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.busy, onClick: props.onCancel, className: "min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark", children: "Cancel" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "submit", disabled: submitDisabled, className: "min-h-11 rounded-xl bg-brand-blue px-5 text-sm font-semibold text-white disabled:opacity-60", children: props.busy ? "Saving…" : "Confirm" })
    ] })
  ] }) });
}
function useLocalCliCatalog() {
  const [data, setData] = reactExports.useState(null);
  const [error, setError] = reactExports.useState(null);
  const load = reactExports.useCallback(async () => {
    try {
      setData(await fetchLocalCliList());
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Guard could not load custom extensions.");
    }
  }, []);
  reactExports.useEffect(() => {
    void load();
  }, [load]);
  return { data, error, load };
}
const PROTECTION_TERMS = {
  pageTitle: "Extensions"
};
function looksLikeUnauthorizedSession(message) {
  const lower = message.trim().toLowerCase();
  if (!lower || lower === "unauthorized" || lower.includes("unauthorized") || lower.includes("session")) return true;
  return /(^|[^0-9])401([^0-9]|$)/.test(lower);
}
function protectionCenterLoadError(message) {
  if (looksLikeUnauthorizedSession(message)) {
    return {
      title: "This view needs a signed local session",
      detail: "Local protection is still running on this device. Open Extensions from the local Guard dashboard and try again after Guard signs this session."
    };
  }
  return {
    title: "Extensions unavailable",
    detail: message.trim() || "Guard could not load protection settings. Local protection continues. Try again."
  };
}
function authorityNoticeView(health) {
  switch (health) {
    case "tampered":
    case "recovery-required":
      return {
        tone: "warning",
        title: "Protection needs repair",
        body: "Guard found a problem with this device's trusted protection settings and is staying fail-safe. Protection changes stay locked until the settings are rebuilt with your approval. Commands keep being checked in the meantime.",
        action: { kind: "repair" },
        actionLabel: "Repair protection",
        actionDetail: "Rebuilding the trusted settings needs your approval password. Guard verifies the repair before protection changes unlock again.",
        command: "hol-guard command controls recover-authority",
        commandLabel: "Repair from the terminal",
        copyButtonLabel: "Copy repair command",
        terminalSummary: "Run this in your terminal if the button above cannot reach the approval gate."
      };
    case "degraded-unacknowledged":
      return {
        tone: "warning",
        title: "Protection is limited",
        body: "Guard cannot fully verify the trusted protection settings and is staying fail-safe until that is resolved. Acknowledging records the limited state honestly — it does not restore full protection.",
        action: { kind: "acknowledge" },
        actionLabel: "Acknowledge limited state",
        actionDetail: "Acknowledging the limited state needs your approval password. Guard keeps protecting fail-safe afterwards.",
        command: "hol-guard command controls recover-authority",
        commandLabel: "Repair from the terminal",
        copyButtonLabel: "Copy repair command",
        terminalSummary: "A full repair runs from your terminal."
      };
    case "degraded-acknowledged":
      return {
        tone: "warning",
        title: "Protection is limited",
        body: "The limited state is acknowledged. Guard keeps protection changes locked until the trusted settings are rebuilt from this device's terminal. Commands keep being checked in the meantime.",
        action: { kind: "none" },
        actionLabel: null,
        actionDetail: null,
        command: "hol-guard command controls recover-authority",
        commandLabel: "Repair from the terminal",
        copyButtonLabel: "Copy repair command",
        terminalSummary: "Run this in your terminal to rebuild the trusted settings."
      };
    default:
      return {
        tone: "info",
        title: "Finish setting up protection",
        body: "Command protection settings are not enrolled on this device yet. One command in your terminal creates this device's trusted settings. Local command checking already runs without them.",
        action: { kind: "none" },
        actionLabel: null,
        actionDetail: null,
        command: "hol-guard command controls enroll",
        commandLabel: "Enroll from the terminal",
        copyButtonLabel: "Copy setup command",
        terminalSummary: "Run this in your terminal to create the trusted settings."
      };
  }
}
function ProtectionAuthorityNotice(props) {
  const health = props.effective.health;
  if (health === "protected") return null;
  const view = authorityNoticeView(health);
  const [proofOpen, setProofOpen] = reactExports.useState(false);
  const [pendingAction, setPendingAction] = reactExports.useState(null);
  const [copyState, setCopyState] = reactExports.useState("idle");
  reactExports.useEffect(() => {
    if (props.status) setProofOpen(false);
  }, [props.status]);
  const gatePending = props.approvalGate === null;
  const copyCommand = async () => {
    try {
      await navigator.clipboard.writeText(view.command);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  };
  const warning2 = view.tone === "warning";
  const panelClass = warning2 ? "border border-amber-200 bg-amber-50" : "border border-brand-blue/25 bg-[rgba(85,153,254,0.06)]";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "protection-authority-notice-heading", className: `mt-4 rounded-2xl p-5 sm:p-6 ${panelClass}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
      warning2 ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-5 shrink-0 text-amber-600", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniInformationCircle, { className: "mt-0.5 size-5 shrink-0 text-brand-blue", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "protection-authority-notice-heading", className: `text-base font-semibold ${warning2 ? "text-amber-950" : "text-brand-dark"}`, children: view.title }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: `mt-1 max-w-3xl text-sm leading-6 ${warning2 ? "text-amber-950/90" : "text-brand-dark/80"}`, children: view.body }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-wrap items-center gap-2", children: [
          view.actionLabel && view.action.kind !== "none" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              "aria-busy": props.busy,
              disabled: props.busy || gatePending,
              onClick: () => {
                setPendingAction(view.action.kind === "repair" ? "repair" : "acknowledge");
                setProofOpen(true);
              },
              className: "inline-flex min-h-11 items-center rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white hover:bg-brand-dark disabled:opacity-60",
              children: gatePending && !props.error ? "Loading approval settings…" : view.actionLabel
            }
          ) : null,
          view.action.kind === "none" ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "button",
            {
              type: "button",
              onClick: () => {
                void copyCommand();
              },
              className: "inline-flex min-h-11 items-center gap-2 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white hover:bg-brand-dark",
              children: [
                copyState === "copied" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboardDocumentCheck, { className: "size-4", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboard, { className: "size-4", "aria-hidden": "true" }),
                copyState === "copied" ? "Command copied" : view.copyButtonLabel
              ]
            }
          ) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              disabled: props.busy,
              onClick: props.onCheckAgain,
              className: "inline-flex min-h-11 items-center rounded-xl border border-slate-200 bg-white px-4 text-sm font-semibold text-brand-dark hover:border-brand-blue/40 disabled:opacity-60",
              children: "Check again"
            }
          )
        ] }),
        props.busy ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: `mt-3 text-sm font-medium ${warning2 ? "text-amber-950" : "text-brand-dark"}`, children: pendingAction === "acknowledge" ? "Confirming the limited state…" : "Repairing local protection…" }) : null,
        props.error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-3 rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800", children: props.error }) : null,
        props.status ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-3 text-sm font-medium text-brand-dark", children: props.status }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: `cursor-pointer text-sm font-semibold ${warning2 ? "text-amber-950" : "text-brand-dark"}`, children: view.commandLabel }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: `mt-2 text-sm leading-6 ${warning2 ? "text-amber-950/80" : "text-brand-dark/70"}`, children: view.terminalSummary }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex flex-col gap-2 sm:flex-row sm:items-center", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "min-w-0 flex-1 overflow-x-auto rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-xs text-brand-dark", children: view.command }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs(
              "button",
              {
                type: "button",
                onClick: () => {
                  void copyCommand();
                },
                className: "inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white px-4 text-sm font-semibold text-brand-blue hover:border-brand-blue/40",
                children: [
                  copyState === "copied" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboardDocumentCheck, { className: "size-4", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboard, { className: "size-4", "aria-hidden": "true" }),
                  copyState === "copied" ? "Copied" : "Copy command"
                ]
              }
            )
          ] })
        ] })
      ] })
    ] }),
    proofOpen && view.action.kind !== "none" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ApprovalProofModal,
      {
        title: view.action.kind === "repair" ? "Repair protection" : "Acknowledge limited state",
        detail: view.actionDetail ?? "",
        confirmLabel: view.actionLabel ?? "Confirm",
        approvalGate: props.approvalGate,
        busy: props.busy,
        error: props.error,
        onCancel: () => {
          if (!props.busy) setProofOpen(false);
        },
        onConfirm: (credentials) => {
          props.onAction(view.action.kind === "repair" ? "repair" : "acknowledge", credentials);
        }
      }
    ) : null
  ] });
}
const PROTECTION_CENTER_PERFORMANCE_BUDGETS = Object.freeze({
  simpleRuleRenderCap: 500,
  recentDecisionCap: 20,
  humanSearchCharacterCap: 160,
  humanSearchTermCap: 8,
  developerRelationshipCap: 1024
});
const COMMAND_PATTERN_DISPLAY_LIMIT = 24;
function patternSearchText(extension2, permission2) {
  return [
    permission2.label,
    permission2.description,
    permission2.example_command ?? "",
    permission2.family ?? "",
    permission2.permission_id,
    extension2.name,
    extension2.extension_id,
    ...extension2.executables
  ].join(" ").toLowerCase();
}
function searchCommandPatterns(extensions, rawQuery, limit = COMMAND_PATTERN_DISPLAY_LIMIT) {
  const normalized = rawQuery.trim().toLowerCase().slice(0, PROTECTION_CENTER_PERFORMANCE_BUDGETS.humanSearchCharacterCap);
  if (!normalized) return [];
  const terms = normalized.split(/\s+/).filter(Boolean).slice(0, PROTECTION_CENTER_PERFORMANCE_BUDGETS.humanSearchTermCap);
  const matches = [];
  for (const extension2 of extensions) {
    for (const permission2 of extension2.permissions) {
      const text2 = patternSearchText(extension2, permission2);
      if (terms.every((term) => text2.includes(term))) {
        matches.push({ extension: extension2, permission: permission2, score: terms.length });
      }
    }
  }
  return matches.sort(
    (left, right) => right.permission.risk_tier.localeCompare(left.permission.risk_tier) || left.permission.label.localeCompare(right.permission.label) || left.extension.name.localeCompare(right.extension.name)
  ).slice(0, limit);
}
const QUICK_APPLY_CHOICES = [
  {
    state: "inherit",
    label: "Recommended",
    detail: "Use Guard defaults for every matching capability.",
    icon: HiMiniSparkles
  },
  {
    state: "allow",
    label: "Allow all",
    detail: "Allow every matching capability that organization policy permits.",
    icon: HiMiniCheckCircle
  },
  {
    state: "block",
    label: "Deny all",
    detail: "Add a local block to every matching capability.",
    icon: HiMiniNoSymbol
  }
];
function quickApplyPermissionIds(permissions, effective, state) {
  return permissions.filter((permission2) => permission2.configurable).filter((permission2) => state !== "allow" || managedPermissionState(effective, permission2.permission_id) !== "disabled").map((permission2) => permission2.permission_id);
}
function QuickApplyToolbar(props) {
  const configurableCount = props.permissions.filter((permission2) => permission2.configurable).length;
  const managedBlockCount = props.permissions.filter(
    (permission2) => permission2.configurable && managedPermissionState(props.effective, permission2.permission_id) === "disabled"
  ).length;
  let managedBlockCopy = "";
  if (managedBlockCount) {
    const subject = managedBlockCount === 1 ? "block stays" : "blocks stay";
    managedBlockCopy = ` ${managedBlockCount} organization ${subject} enforced.`;
  }
  if (!configurableCount) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-col gap-3 border-y border-[rgba(63,65,116,0.12)] bg-[rgba(85,153,254,0.045)] px-3 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm font-semibold text-brand-dark", children: [
        "Quick apply to ",
        configurableCount,
        " matching ",
        configurableCount === 1 ? "capability" : "capabilities"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-0.5 text-xs leading-5 text-brand-dark/65", children: [
        "Changes stay in draft until you review and approve them.",
        managedBlockCopy
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "group", "aria-label": `Quick apply to ${configurableCount} matching capabilities`, className: "flex flex-wrap gap-2", children: QUICK_APPLY_CHOICES.map((choice) => /* @__PURE__ */ jsxRuntimeExports.jsx(
      QuickApplyButton,
      {
        choice,
        permissionIds: quickApplyPermissionIds(props.permissions, props.effective, choice.state),
        disabled: props.disabled,
        permissionState: props.permissionState,
        onApply: props.onApply
      },
      choice.state
    )) })
  ] });
}
function QuickApplyButton(props) {
  const active = props.permissionIds.length > 0 && props.permissionIds.every((permissionId) => props.permissionState(permissionId) === props.choice.state);
  const handleClick = reactExports.useCallback(() => {
    props.onApply(props.permissionIds, props.choice.state);
  }, [props.choice.state, props.onApply, props.permissionIds]);
  const Icon = props.choice.icon;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      type: "button",
      "aria-pressed": active,
      title: props.choice.detail,
      disabled: props.disabled || props.permissionIds.length === 0,
      onClick: handleClick,
      className: "inline-flex min-h-10 items-center gap-2 rounded-lg border border-[rgba(63,65,116,0.18)] bg-white px-3 text-xs font-semibold text-brand-dark shadow-sm transition-colors hover:border-brand-blue hover:text-brand-blue disabled:cursor-not-allowed disabled:opacity-45 aria-pressed:border-brand-blue aria-pressed:bg-brand-blue aria-pressed:text-white",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "size-4", "aria-hidden": "true" }),
        props.choice.label
      ]
    }
  );
}
function PatternSearchConsole(props) {
  const [internalQuery, setInternalQuery] = reactExports.useState("");
  const query = props.query ?? internalQuery;
  const setQuery = props.onQueryChange ?? setInternalQuery;
  const [focused, setFocused] = reactExports.useState(false);
  const inputRef = reactExports.useRef(null);
  const searchActive = props.active ?? true;
  const draft = useExtensionPolicyDraft({ effective: props.effective, onRefresh: props.onRefresh });
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  const {
    baseEffective,
    dirty,
    preview,
    previewBusy,
    applyBusy,
    reviewOpen,
    error,
    stale,
    refreshRequired,
    lastApplied,
    undoLastApplied,
    changedPermissionCount,
    setReviewOpen,
    setPermissionState,
    setPermissionStates,
    resetDraft,
    runPreview,
    apply,
    permissionState
  } = draft;
  reactExports.useEffect(() => {
    if (!searchActive) return;
    const onKeyDown = (event) => {
      if (event.key !== "/" || event.defaultPrevented) return;
      const target2 = event.target;
      if (target2 && (target2.tagName === "INPUT" || target2.tagName === "TEXTAREA" || target2.isContentEditable)) return;
      event.preventDefault();
      inputRef.current?.focus();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [searchActive]);
  const totalPermissionCount = reactExports.useMemo(
    () => props.catalog.reduce((total, extension2) => total + extension2.permissions.length, 0),
    [props.catalog]
  );
  const allMatches = reactExports.useMemo(
    () => searchCommandPatterns(props.catalog, query, totalPermissionCount),
    [props.catalog, query, totalPermissionCount]
  );
  const matches = reactExports.useMemo(() => allMatches.slice(0, COMMAND_PATTERN_DISPLAY_LIMIT), [allMatches]);
  const toolMatches = reactExports.useMemo(() => {
    const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (!terms.length) return [];
    return props.catalog.filter((extension2) => {
      const text2 = [extension2.name, extension2.extension_id, ...extension2.executables, ...extension2.aliases].join(" ").toLowerCase();
      return terms.every((term) => text2.includes(term));
    });
  }, [props.catalog, query]);
  const grouped = reactExports.useMemo(() => {
    const groups = /* @__PURE__ */ new Map();
    for (const match of matches) {
      const group = groups.get(match.extension.extension_id) ?? { extension: match.extension, permissionIds: [] };
      group.permissionIds.push(match.permission.permission_id);
      groups.set(match.extension.extension_id, group);
    }
    return [...groups.values()];
  }, [matches]);
  const involvedPermissions = reactExports.useMemo(() => allMatches.map((match) => match.permission), [allMatches]);
  const changeCount = changedPermissionCount;
  const showResults = query.trim().length > 0;
  reactExports.useEffect(() => {
    if (!reviewOpen) return;
    void resolveApprovalGate({ failClosed: true }).catch(() => {
    });
  }, [reviewOpen, resolveApprovalGate]);
  const managedCount = involvedPermissions.filter(
    (permission2) => managedPermissionState(baseEffective, permission2.permission_id) !== null
  ).length;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "pattern-search-heading", className: "mt-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "pattern-search-heading", className: "sr-only", children: "Search command patterns" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "relative block", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: "Search command patterns" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { className: "pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-brand-dark/55", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          ref: inputRef,
          type: "text",
          role: "searchbox",
          enterKeyHint: "search",
          value: query,
          onFocus: () => setFocused(true),
          onChange: (event) => setQuery(event.target.value.slice(0, 160)),
          placeholder: 'Search any command Guard watches — "squash", "git push --force", "kubectl"…',
          "aria-describedby": "pattern-search-hint",
          className: "min-h-12 w-full rounded-2xl border border-[rgba(63,65,116,0.14)] bg-white/85 py-2.5 pl-9 pr-10 text-sm text-brand-dark shadow-sm focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100"
        }
      ),
      showResults ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          onClick: () => {
            setQuery("");
            inputRef.current?.focus();
          },
          "aria-label": "Clear search",
          className: "absolute right-2 top-1/2 grid size-8 -translate-y-1/2 place-items-center rounded-lg text-brand-dark/55 hover:bg-[rgba(63,65,116,0.06)] hover:text-brand-dark",
          children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-4", "aria-hidden": "true" })
        }
      ) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { id: "pattern-search-hint", className: `mt-2 text-xs text-brand-dark/60 ${focused || showResults ? "" : "sr-only"}`, children: "Matches patterns across every tool. Press / to focus search from anywhere on this page." }),
    props.actionSlot ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: props.actionSlot }) : null,
    showResults ? matches.length || toolMatches.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3", children: [
      matches.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          QuickApplyToolbar,
          {
            permissions: involvedPermissions,
            effective: baseEffective,
            disabled: refreshRequired || previewBusy || applyBusy || baseEffective.health !== "protected",
            permissionState,
            onApply: setPermissionStates
          }
        ),
        allMatches.length > matches.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { role: "status", className: "mt-3 text-xs text-brand-dark/65", children: [
          "Showing ",
          matches.length,
          " of ",
          allMatches.length,
          " matching capabilities. Quick actions apply to all ",
          allMatches.length,
          "."
        ] }) : null
      ] }) : null,
      grouped.map((group) => /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": `${group.extension.name} patterns`, className: "guard-pattern-family", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("h3", { className: "guard-pattern-family-heading", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            ExtensionBrandMark,
            {
              extension_id: group.extension.extension_id,
              name: group.extension.name,
              executables: group.extension.executables,
              ecosystem_ids: group.extension.ecosystem_ids,
              size: "sm"
            }
          ),
          group.extension.executables.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("code", { children: group.extension.executables[0] }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: extensionDisplayName(group.extension.name) })
        ] }),
        group.permissionIds.map((permissionId) => {
          const permission2 = group.extension.permissions.find((item) => item.permission_id === permissionId);
          if (!permission2) return null;
          return /* @__PURE__ */ jsxRuntimeExports.jsx(
            PermissionPolicyRow,
            {
              permission: permission2,
              extension: group.extension,
              effective: baseEffective,
              draftState: permissionState(permission2.permission_id),
              disabled: refreshRequired,
              onChange: (state) => setPermissionState(permission2.permission_id, state)
            },
            permission2.permission_id
          );
        })
      ] }, group.extension.extension_id)),
      toolMatches.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": "Matching tools", className: "guard-pattern-family", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "guard-pattern-family-heading", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Tools" }) }),
        toolMatches.map((extension2) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          ProtectionModuleRow,
          {
            extensionId: extension2.extension_id,
            name: extensionDisplayName(extension2.name),
            description: extension2.description,
            behavior: extension2.executables.join(" · ") || extension2.description,
            required: extension2.required,
            executables: extension2.executables,
            ecosystemIds: extension2.ecosystem_ids,
            onOpen: () => props.onOpenExtension(extension2)
          },
          extension2.extension_id
        ))
      ] }) : null,
      managedCount ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-3 text-xs text-indigo-950", children: [
        managedCount,
        " matched setting",
        managedCount === 1 ? "" : "s are",
        " managed by your organization and cannot be weakened on this device."
      ] }) : null
    ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-sm text-brand-dark/75", children: "No command patterns or tools match this search." }) : null,
    dirty ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-review-bar", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "text-sm text-brand-dark", children: [
        changeCount,
        " unsaved setting change",
        changeCount === 1 ? "" : "s",
        "."
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: previewBusy || applyBusy, onClick: resetDraft, className: "min-h-11 rounded-xl border border-[rgba(63,65,116,0.2)] px-4 text-sm font-semibold text-brand-dark", children: "Reset changes" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", disabled: previewBusy || applyBusy || baseEffective.health !== "protected" || stale, onClick: () => {
          void runPreview();
        }, className: "inline-flex min-h-11 items-center gap-2 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-[#f4f7fb] disabled:opacity-40", children: [
          previewBusy ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-4 animate-spin motion-reduce:animate-none" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "size-4" }),
          "Review ",
          changeCount,
          " change",
          changeCount === 1 ? "" : "s"
        ] })
      ] })
    ] }) }) : null,
    lastApplied ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      AppliedPolicyToast,
      {
        revision: lastApplied.revision,
        onUndo: () => {
          undoLastApplied();
        },
        onViewHistory: () => {
          document.getElementById("pattern-search-heading")?.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      }
    ) : null,
    error ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "alert", className: "mt-4 text-sm text-red-950", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-5 shrink-0" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: error })
    ] }) }) : dirty && !preview ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex items-start gap-3 text-sm text-brand-dark", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniInformationCircle, { className: "mt-0.5 size-5 shrink-0" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Review is required before approval. Guard calculates the real outcome from current protections, dependencies, organization settings, and Emergency Lockdown before anything can change." })
    ] }) : null,
    reviewOpen && preview ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyReviewSheet,
      {
        preview,
        approvalGate: resolvedApprovalGate,
        busy: applyBusy,
        error,
        onClose: () => {
          if (!applyBusy) setReviewOpen(false);
        },
        onApply: (credentials) => {
          void apply(credentials);
        }
      }
    ) : null
  ] });
}
function safeCloudSignInHref(value) {
  if (!value) return null;
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:" ? url.toString() : null;
  } catch {
    return null;
  }
}
function ManagedControlsPrimaryAction(props) {
  if (!props.action) return null;
  if (props.action.href) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("a", { href: props.action.href, target: "_blank", rel: "noopener noreferrer", className: "inline-flex min-h-11 items-center gap-2 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white", children: [
      props.action.label,
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "size-4", "aria-hidden": "true" })
    ] });
  }
  if (props.action.action === "refresh") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: props.onRefresh, className: "min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white", children: props.action.label });
  }
  if (props.action.action === "connect-cloud") {
    if (props.connectHref) {
      return /* @__PURE__ */ jsxRuntimeExports.jsxs("a", { href: props.connectHref, className: "inline-flex min-h-11 items-center gap-2 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloud, { className: "size-4", "aria-hidden": "true" }),
        "Open Guard Cloud sign-in"
      ] });
    }
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: props.onConnect, disabled: props.connecting, className: "inline-flex min-h-11 items-center gap-2 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark disabled:opacity-50", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloud, { className: "size-4", "aria-hidden": "true" }),
      props.connecting ? "Starting sign-in..." : props.action.label
    ] });
  }
  return null;
}
function layerTargetsExtension(effective, extension2, kind) {
  const permissionIds = new Set(extension2.permissions.map((permission2) => permission2.permission_id));
  return effective.layers.some(
    (layer) => layer.kind === kind && layer.controls.some(
      (control) => control.target_kind === "extension" && control.target_id === extension2.extension_id || control.target_kind === "permission" && permissionIds.has(control.target_id)
    )
  );
}
function managedSource(effective) {
  const managed = effective.managed_controls;
  return managed?.authority_mode === "managed-restrictive" ? `Managed by ${managed.workspace_id}` : "Synced from Guard Cloud";
}
function extensionProtectionAuthority(effective, extension2) {
  if (effective.global_lockdown) {
    return { effectiveState: "lockdown", source: "Emergency Lockdown", sources: ["Emergency Lockdown"] };
  }
  const permissionIds = new Set(extension2.permissions.map((permission2) => permission2.permission_id));
  const extensionProjection = effective.projection?.extensions.find(
    (item) => item.extension_id === extension2.extension_id
  );
  const permissionProjections = effective.projection?.permissions.filter(
    (item) => item.extension_id === extension2.extension_id || permissionIds.has(item.permission_id)
  ) ?? [];
  const projections = extensionProjection ? [extensionProjection, ...permissionProjections] : permissionProjections;
  const managed = managedSource(effective);
  const hasManaged = projections.some((item) => item.managed_state !== "inherited") || layerTargetsExtension(effective, extension2, "signed-cloud");
  const hasLocal = projections.some((item) => item.local_state !== "inherited") || layerTargetsExtension(effective, extension2, "local-admin");
  const sources = [];
  if (hasManaged) sources.push(managed);
  if (hasLocal) sources.push("Set on this device");
  if (sources.length === 0) sources.push(extension2.required ? "Required by Guard" : "Recommended by Guard");
  const managedBlocks = projections.some(
    (item) => item.effective_state === "blocked" && item.managed_state === "disabled"
  ) || effective.layers.some((layer) => layer.kind === "signed-cloud" && layer.controls.some(
    (control) => control.state === "disabled" && (control.target_kind === "extension" && control.target_id === extension2.extension_id || control.target_kind === "permission" && permissionIds.has(control.target_id))
  ));
  const localBlocks = projections.some(
    (item) => item.effective_state === "blocked" && item.local_state === "disabled"
  ) || effective.layers.some((layer) => layer.kind === "local-admin" && layer.controls.some(
    (control) => control.state === "disabled" && (control.target_kind === "extension" && control.target_id === extension2.extension_id || control.target_kind === "permission" && permissionIds.has(control.target_id))
  ));
  const extensionBlocked = extensionProjection?.effective_state === "blocked" || extensionEffectiveState(effective, extension2) === "disabled";
  const permissionStates = extension2.permissions.map(
    (permission2) => permissionEffectiveState(effective, extension2, permission2)
  );
  const blockedPermissionCount = permissionStates.filter((state) => state === "disabled").length;
  let effectiveState;
  if (extensionBlocked) effectiveState = "blocked";
  else if (blockedPermissionCount > 0 && blockedPermissionCount < permissionStates.length) effectiveState = "partial";
  else if (blockedPermissionCount > 0 || localBlocks || managedBlocks) effectiveState = "blocked";
  else if (extension2.required) effectiveState = "required";
  else effectiveState = extensionEffectiveState(effective, extension2) === "enabled" ? "allowed" : "blocked";
  let source = sources.at(-1) ?? "Recommended by Guard";
  if (localBlocks) source = "Set on this device";
  if (managedBlocks) source = managed;
  return { effectiveState, source, sources };
}
function extensionProtectionSource(effective, extension2) {
  return extensionProtectionAuthority(effective, extension2).source;
}
function cloudBase(runtime) {
  const candidate = runtime?.dashboard_url?.trim() || runtime?.connect_url?.trim();
  return candidate || void 0;
}
function recoveryNotice(recovery) {
  if (recovery === "unsupported-version") {
    return "This Control Set uses a newer control schema. Update Guard before applying it; the last verified authority remains in force.";
  }
  if (recovery === "catalog-mismatch") {
    return "The Control Set and local Extension catalog do not match. Guard keeps the last verified authority fail-safe until compatibility is restored.";
  }
  if (recovery === "degraded") {
    return "Local control authority needs recovery. Guard keeps the last verified authority fail-safe while you refresh or repair it.";
  }
  return "Cloud sync is stale. Guard keeps the last verified authority fail-safe until a fresh acknowledgement succeeds.";
}
function extensionLocalProtectionInput(extension2, effective, runtime) {
  const managed = effective.managed_controls;
  const authority = extensionProtectionAuthority(effective, extension2);
  const failureCodes = new Set(effective.failures.map((failure) => failure.code.toLowerCase()));
  let recovery;
  if (failureCodes.has("unsupported-control-schema")) recovery = "unsupported-version";
  else if (failureCodes.has("catalog-digest-mismatch") || failureCodes.has("catalog-unavailable")) recovery = "catalog-mismatch";
  else if (runtime?.cloud_policy_sync_error || [...failureCodes].some((code) => code.includes("stale"))) recovery = "stale";
  else if (effective.health !== "protected") recovery = "degraded";
  return {
    extensionName: extension2.name,
    extensionId: extension2.extension_id,
    effectiveState: authority.effectiveState,
    source: authority.source,
    sources: authority.sources,
    catalogDigest: effective.catalog_digest,
    recovery,
    cloudControlsUrl: cloudBase(runtime),
    controlSetName: managed?.control_set_name ?? managed?.control_set_id,
    controlSetVersion: managed?.bundle_version,
    workspace: managed?.workspace_id,
    authorityMode: managed?.authority_mode,
    acknowledgementRevision: managed?.acknowledgement.extension_authority_revision,
    acknowledgementStatus: managed?.acknowledgement.status,
    lastAcknowledgedAt: runtime?.cloud_policy_last_ack_at ?? void 0,
    effectiveProjectionDigest: managed?.acknowledgement.effective_projection_digest
  };
}
function ExtensionManagedControlsPanel(props) {
  const [connecting, setConnecting] = reactExports.useState(false);
  const [connectHref, setConnectHref] = reactExports.useState(null);
  const [connectMessage, setConnectMessage] = reactExports.useState(null);
  const input = extensionLocalProtectionInput(props.extension, props.effective, props.runtime);
  const view = buildLocalProtectionView(input);
  const connected = props.runtime?.cloud_state === "paired_active" || props.runtime?.cloud_state === "paired_waiting";
  const hasManagedControl = layerTargetsExtension(props.effective, props.extension, "signed-cloud");
  const refresh = () => {
    void props.onRefresh();
  };
  const connect = reactExports.useCallback(() => {
    setConnecting(true);
    setConnectMessage(null);
    void startGuardCloudConnect().then((status) => {
      if (!status.connect_required) {
        setConnectMessage("Guard Cloud is connected.");
        return;
      }
      const href = safeCloudSignInHref(status.connect_flow?.authorize_url) ?? safeCloudSignInHref(status.connect_flow?.connect_url);
      setConnectHref(href);
      setConnectMessage(href ? "Complete sign-in to resume synced Control Sets." : "Guard could not start sign-in. Try again.");
    }).catch((error) => {
      setConnectMessage(error instanceof Error ? error.message : "Guard could not start sign-in. Try again.");
    }).finally(() => setConnecting(false));
  }, []);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "managed-controls-heading", className: "space-y-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-3xl border border-slate-200 bg-white p-5 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Source and authority" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "managed-controls-heading", className: "mt-1 text-lg font-semibold text-brand-dark", children: hasManagedControl ? "Active managed control" : "No Control Set targets this Extension" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-sm leading-6 text-brand-dark/75", children: view.summary })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "inline-flex self-start rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-semibold text-brand-dark", children: view.source })
      ] }),
      view.status === "needs-attention" || view.status === "unsupported" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { role: "alert", className: "mt-4 flex gap-2 rounded-xl border border-amber-200 bg-amber-50 p-3 text-sm text-amber-950", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 size-4 shrink-0" }),
        recoveryNotice(input.recovery)
      ] }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx("dl", { className: "mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-3", children: view.technicalDetails.map((detail) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase tracking-wide text-brand-dark/55", children: detail.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 break-all text-sm text-brand-dark", children: detail.value })
      ] }, detail.label)) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5 flex flex-wrap gap-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        ManagedControlsPrimaryAction,
        {
          action: view.primaryAction,
          connecting,
          connectHref,
          onConnect: connect,
          onRefresh: refresh
        }
      ) }),
      connectMessage ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-3 text-sm text-brand-dark/75", children: connectMessage }) : null
    ] }),
    !connected ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm leading-6 text-brand-dark/75", children: "Guard Cloud is disconnected. Local protection and local tightening remain available on this device; cross-device Control Sets resume after reconnecting." }) : null,
    hasManagedControl && input.authorityMode === "managed-restrictive" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "rounded-2xl border border-indigo-200 bg-indigo-50 p-4 text-sm leading-6 text-indigo-950", children: "This is a managed-restrictive Control Set. Local settings can add stricter blocks, but they cannot weaken this workspace restriction." }) : null
  ] });
}
function sourceIsManaged(effective, extensionId) {
  return effective.layers.some((layer) => layer.kind === "signed-cloud" && layer.controls.some(
    (control) => control.target_kind === "extension" && control.target_id === extensionId
  ));
}
function catalogRowSecondLine(extension2, state) {
  if (state === "Blocked" || state === "Managed" || state === "Lockdown" || state === "Unavailable") return state;
  const executables = extension2.executables.join(" · ").trim();
  return executables || extension2.description;
}
function CatalogExtensionRow(props) {
  const handleOpen = reactExports.useCallback(() => {
    props.onOpen(props.extension);
  }, [props]);
  const source = extensionProtectionSource(props.effective, props.extension);
  const cloudSource = source === "Synced from Guard Cloud" || source.startsWith("Managed by ");
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    ProtectionModuleRow,
    {
      extensionId: props.extension.extension_id,
      name: extensionDisplayName(props.extension.name),
      description: props.extension.description,
      behavior: catalogRowSecondLine(props.extension, extensionStateLabel(props.effective, props.extension)),
      required: props.extension.required,
      managed: cloudSource || sourceIsManaged(props.effective, props.extension.extension_id),
      managedLabel: cloudSource ? source : void 0,
      executables: props.extension.executables,
      ecosystemIds: props.extension.ecosystem_ids,
      onOpen: handleOpen
    }
  );
}
function ExtensionsOverview(props) {
  const [query, setQuery] = reactExports.useState("");
  const searching = query.trim().length > 0;
  const addedCustomCount = addedCustomExtensions(props.localCliItems).length;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { hidden: !props.active, inert: !props.active || void 0, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      WorkspacePageHeader,
      {
        eyebrow: "On this device",
        title: PROTECTION_TERMS.pageTitle,
        description: "Choose an Extension to review its permissions and effective protection."
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        ProtectionStatusHero,
        {
          status: props.status,
          onPrimaryAction: props.status.primaryAction === "review-lockdown" ? props.onPrimaryStatusAction : void 0
        }
      ),
      props.recoveryStatus && !props.healthBroken ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mt-3 text-sm font-medium text-emerald-800", children: props.recoveryStatus }) : null
    ] }),
    props.mutationError ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(InlineError, { message: props.mutationError }) }) : null,
    props.localCliError ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(InlineError, { message: props.localCliError }) }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      PatternSearchConsole,
      {
        catalog: props.catalogExtensions,
        effective: props.effective,
        active: props.active,
        query,
        onQueryChange: setQuery,
        onRefresh: props.onRefresh,
        onOpenExtension: props.onOpenExtension,
        actionSlot: searching ? /* @__PURE__ */ jsxRuntimeExports.jsx(AddCustomExtensionButton, { onClick: props.onAddCustom }) : null
      }
    ),
    searching ? null : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      addedCustomCount ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        CustomExtensionsSection,
        {
          items: props.localCliItems,
          onOpen: props.onOpenLocalCli,
          onAdd: props.onAddCustom
        }
      ) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "mt-10", "aria-labelledby": "all-tools-heading", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "all-tools-heading", className: "text-xl font-semibold tracking-tight text-brand-dark", children: "All tools" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Every built-in tool Guard can watch on this device. Open one to adjust its command patterns." })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-3", children: [
            addedCustomCount ? null : /* @__PURE__ */ jsxRuntimeExports.jsx(AddCustomExtensionButton, { onClick: props.onAddCustom }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-sm text-brand-dark/70", children: [
              props.catalogExtensions.length,
              " tools"
            ] })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: props.catalogExtensions.map((extension2) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          CatalogExtensionRow,
          {
            extension: extension2,
            effective: props.effective,
            onOpen: props.onOpenExtension
          },
          extension2.extension_id
        )) })
      ] })
    ] })
  ] });
}
function pushExtensionHistory(href) {
  window.history.pushState({}, "", guardAwareHref(href));
}
function replaceExtensionHistory(href) {
  window.history.replaceState({}, "", guardAwareHref(href));
}
function receiptMatchesExtension(receipt, extension2) {
  const identities = /* @__PURE__ */ new Set([
    extension2.extension_id,
    ...extension2.permissions.map((permission2) => permission2.permission_id),
    ...extension2.rules.map((rule2) => rule2.rule_id)
  ]);
  if (identities.has(receipt.artifact_id)) return true;
  if (receipt.changed_capabilities.some((capability) => identities.has(capability))) return true;
  const envelope = receipt.action_envelope_json;
  if (!envelope) return false;
  if (envelope.command_category === extension2.extension_id) return true;
  const toolName = envelope.tool_name?.trim().toLowerCase();
  return Boolean(toolName && extension2.executables.some((executable) => executable.toLowerCase() === toolName));
}
function recentExtensionReceipts(receipts, extension2, limit = 8) {
  return receipts.filter((receipt) => receiptMatchesExtension(receipt, extension2)).sort((left, right) => Date.parse(right.timestamp) - Date.parse(left.timestamp)).slice(0, limit);
}
function receiptDecisionLabel(receipt) {
  if (receipt.policy_decision === "allow") return "Allowed";
  if (receipt.policy_decision === "block") return "Blocked";
  return "Reviewed";
}
function ExtensionActivity(props) {
  const receipts = recentExtensionReceipts(props.receipts, props.extension);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "rounded-3xl border border-slate-200 bg-white p-5 shadow-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-lg font-semibold text-brand-dark", children: "Recent Extension decisions" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-6 text-brand-dark/75", children: "Receipt-backed decisions mapped to this canonical Extension. Guard does not synthesize activity." }),
    receipts.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-4 divide-y divide-slate-100", "aria-label": "Recent Extension receipts", children: receipts.map((receipt) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex flex-col gap-2 py-3 sm:flex-row sm:items-center sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm font-semibold text-brand-dark", children: [
          receiptDecisionLabel(receipt),
          " · ",
          receipt.harness
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-brand-dark/60", children: [
          receipt.capabilities_summary,
          " · ",
          new Date(receipt.timestamp).toLocaleString()
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("a", { href: `/evidence?view=actions&selected=${encodeURIComponent(receipt.receipt_id)}&search=${encodeURIComponent(receipt.receipt_id)}`, className: "inline-flex min-h-11 items-center gap-2 text-sm font-semibold text-brand-blue hover:underline", children: [
        "Open receipt ",
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "size-4", "aria-hidden": "true" })
      ] })
    ] }, receipt.receipt_id)) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 rounded-2xl bg-slate-50 p-4 text-sm text-brand-dark/70", children: "No matching receipts are available on this device yet." }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("a", { href: `/evidence?view=actions&search=${encodeURIComponent(props.extension.extension_id)}`, className: "mt-4 inline-flex min-h-11 items-center gap-2 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark", children: [
      "View matching Evidence ",
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "size-4", "aria-hidden": "true" })
    ] })
  ] });
}
const DECISIONS = /* @__PURE__ */ new Set(["allowed", "ask-first", "blocked"]);
const MINIMUM_ACTIONS = /* @__PURE__ */ new Set(["allow", "monitor", "review", "block"]);
const SEVERITIES = /* @__PURE__ */ new Set(["low", "medium", "high", "critical"]);
function record(value) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("Guard returned an invalid Test Lab response");
  return value;
}
function boundedString(value, field, limit = 512) {
  if (typeof value !== "string" || !value.trim() || value.length > limit) throw new Error(`Guard returned an invalid ${field}`);
  return value;
}
function stringList(value, field, limit) {
  if (!Array.isArray(value) || value.length > limit || !value.every((item) => typeof item === "string" && item.length <= 320)) {
    throw new Error(`Guard returned an invalid ${field}`);
  }
  return [...value];
}
function normalizeProtectionTestResult(value) {
  const raw = record(value);
  if (raw.schema_version !== "guard.daemon.extension-control-test.v1") throw new Error("Guard returned an unsupported Test Lab response");
  if (typeof raw.decision !== "string" || !DECISIONS.has(raw.decision)) throw new Error("Guard returned an invalid Test Lab decision");
  if (typeof raw.minimum_action !== "string" || !MINIMUM_ACTIONS.has(raw.minimum_action)) throw new Error("Guard returned an invalid Test Lab action");
  if (typeof raw.matched !== "boolean" || typeof raw.module_matched !== "boolean" || typeof raw.other_protection_matched !== "boolean") {
    throw new Error("Guard returned invalid Test Lab match state");
  }
  if (!Array.isArray(raw.matches) || raw.matches.length > 32) throw new Error("Guard returned too many Test Lab matches");
  const matches = raw.matches.map((item) => {
    const match = record(item);
    if (typeof match.severity !== "string" || !SEVERITIES.has(match.severity)) throw new Error("Guard returned an invalid Test Lab severity");
    return {
      extension_id: boundedString(match.extension_id, "extension ID", 256),
      extension_name: boundedString(match.extension_name, "extension name", 120),
      rule_id: boundedString(match.rule_id, "rule ID", 256),
      permission_id: typeof match.permission_id === "string" && match.permission_id.trim() ? match.permission_id : null,
      rule_title: boundedString(match.rule_title, "rule title", 160),
      description: boundedString(match.description, "rule description", 320),
      severity: match.severity,
      risk_classes: stringList(match.risk_classes, "risk classes", 16)
    };
  });
  if (typeof raw.revision !== "number" || !Number.isSafeInteger(raw.revision) || raw.revision < 0) throw new Error("Guard returned an invalid Test Lab revision");
  return {
    schema_version: "guard.daemon.extension-control-test.v1",
    decision: raw.decision,
    minimum_action: raw.minimum_action,
    matched: raw.matched,
    module_matched: raw.module_matched,
    other_protection_matched: raw.other_protection_matched,
    explanation: boundedString(raw.explanation, "Test Lab explanation", 320),
    matches,
    safer_alternatives: stringList(raw.safer_alternatives, "safer alternatives", 8),
    authority_health: boundedString(raw.authority_health, "authority health", 64),
    revision: raw.revision,
    catalog_digest: boundedString(raw.catalog_digest, "catalog digest", 128)
  };
}
async function testProtectionCommand(extensionId, command) {
  const response = await fetchExtensionControlApi("/v1/extension-controls/test", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ extension_id: extensionId, command })
  });
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error(`Guard returned invalid JSON (${response.status})`);
  }
  if (!response.ok) {
    const raw = typeof payload === "object" && payload !== null && !Array.isArray(payload) ? payload : {};
    throw new Error(typeof raw.error === "string" ? raw.error.replaceAll("_", " ") : `Test Lab request failed (${response.status})`);
  }
  return normalizeProtectionTestResult(payload);
}
function safeExamples(extension2) {
  const executable = extension2.executables[0];
  const examples = extension2.extension_id === "command.git" ? ["git status", "git reset --hard HEAD~1", "git push --force-with-lease"] : executable ? [`${executable} --help`] : [];
  return examples.slice(0, 3);
}
function resultTitle(result) {
  if (result.decision === "blocked") return "Guard would block this";
  if (result.decision === "ask-first") return "Guard would ask first";
  return "Guard would allow this";
}
function ProtectionTestLab({ extension: extension2 }) {
  const [command, setCommand] = reactExports.useState("");
  const [result, setResult] = reactExports.useState(null);
  const [busy, setBusy] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const examples = reactExports.useMemo(() => safeExamples(extension2), [extension2]);
  const run = async () => {
    const candidate = command.trim();
    if (!candidate || busy) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await testProtectionCommand(extension2.extension_id, candidate));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Test Lab could not evaluate this command.");
    } finally {
      setBusy(false);
    }
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "protection-test-lab-heading", className: "mt-10 rounded-2xl border border-slate-200 bg-white p-5 sm:p-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-baseline justify-between gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "protection-test-lab-heading", className: "text-lg font-semibold tracking-tight text-brand-dark", children: "Test Lab" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Nothing is executed. The check runs locally and is not saved." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-sm text-slate-500", children: [
      "See how Guard would handle a ",
      extension2.name,
      " command without running it."
    ] }),
    examples.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 flex flex-wrap gap-2", children: examples.map((example) => /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: busy, onClick: () => {
      setCommand(example);
      setResult(null);
      setError(null);
    }, className: `${EXTENSION_CHIP_CLASS} disabled:cursor-not-allowed disabled:opacity-50`, children: example }, example)) }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex flex-col gap-2 sm:flex-row", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          value: command,
          disabled: busy,
          onChange: (event) => {
            setCommand(event.target.value.slice(0, 4096));
            setResult(null);
            setError(null);
          },
          onKeyDown: (event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              void run();
            }
          },
          maxLength: 4096,
          spellCheck: false,
          autoComplete: "off",
          "aria-label": "Command to check",
          placeholder: "Paste a command Guard stopped, like git reset --hard HEAD~1",
          className: "min-h-11 w-full flex-1 rounded-xl border border-slate-200 bg-white px-3 font-mono text-sm text-brand-dark placeholder:font-sans placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: () => {
        void run();
      }, disabled: busy || !command.trim(), className: "min-h-11 shrink-0 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-50", children: busy ? "Checking…" : "Check safely" })
    ] }),
    error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-4 rounded-xl border border-red-200 bg-red-50 p-3 text-sm text-red-800", children: error }) : null,
    result ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "status", className: "mt-5 rounded-xl bg-slate-50 p-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(ProtectionDecisionBadge, { result: result.decision }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-sm text-brand-dark", children: resultTitle(result) }),
        result.decision === "allowed" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "size-5 text-emerald-700", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "size-5 text-amber-700", "aria-hidden": "true" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-sm leading-6 text-brand-dark/80", children: result.explanation }),
      result.matches.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.14em] text-slate-400", children: "Protection rules involved" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 space-y-2", children: result.matches.slice(0, 6).map((match) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl bg-white p-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "text-sm text-brand-dark", children: match.rule_title }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-xs font-semibold capitalize text-brand-dark/55", children: [
              match.severity,
              " risk"
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-5 text-brand-dark/70", children: match.description })
        ] }, `${match.extension_id}:${match.rule_id}`)) })
      ] }) : null,
      result.safer_alternatives.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.14em] text-slate-400", children: "Safer alternatives" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 list-disc space-y-1 pl-5 text-sm text-brand-dark/80", children: result.safer_alternatives.map((alternative) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: alternative }, alternative)) })
      ] }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 text-xs text-slate-500", children: "This result uses the current local protection state. It is a read-only evaluation and does not create an approval or receipt." })
    ] }) : null
  ] });
}
const DETAIL_TABS = [
  { id: "overview", label: "Overview" },
  { id: "permissions", label: "Permissions" },
  { id: "managed-controls", label: "Managed controls" },
  { id: "activity", label: "Activity" },
  { id: "technical", label: "Technical details" }
];
function canonicalProtectionDetailTab(tab) {
  if (tab === "commands" || tab === "policy") return "permissions";
  if (tab === "test-lab") return "activity";
  if (tab === "managed-controls" || tab === "permissions" || tab === "technical") return tab;
  return tab === "activity" ? "activity" : "overview";
}
function requiredLine(extension2) {
  if (!extension2.required) return null;
  return "Required by Guard — this protection stays on. The command patterns below can still follow recommended settings or be blocked on this device.";
}
function protectionStateLabel(state) {
  return state.charAt(0).toUpperCase() + state.slice(1);
}
function DeveloperModuleDetails(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(TechnicalDetails, { title: "Developer details", testId: "protection-more-detail", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold text-brand-dark", children: "Canonical module" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-3 grid gap-3 sm:grid-cols-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/80", children: "Extension ID" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "break-all text-xs", children: props.extension.extension_id }) })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/80", children: "Version" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "text-sm", children: props.extension.version })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/80", children: "Catalog digest" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "break-all text-xs", children: props.catalogDigest }) })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/80", children: "Provenance" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "text-sm", children: controlProvenance(props.effective, "extension", props.extension.extension_id).join(" · ") })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold text-brand-dark", children: "Detections" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 max-h-96 overflow-auto", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("table", { className: "min-w-full text-left text-xs", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("thead", { className: "sticky top-0 bg-[var(--surface-1)] text-brand-dark/80", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-3 py-2", children: "Detection" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-3 py-2", children: "Severity" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-3 py-2", children: "Matcher" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("th", { className: "px-3 py-2", children: "Default" })
        ] }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("tbody", { children: props.extension.rules.map((rule2) => /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { className: "border-t border-[rgba(63,65,116,0.08)]", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("td", { className: "px-3 py-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "font-medium text-brand-dark/80", children: rule2.title }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "break-all text-[10px] text-brand-dark/80", children: rule2.rule_id })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-3 py-2", children: rule2.severity }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-3 py-2", children: rule2.matcher_kind }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-3 py-2", children: treatmentLabel(rule2.default_mode) })
        ] }, rule2.rule_id)) })
      ] }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "font-semibold text-brand-dark", children: "Protection setting identifiers" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 space-y-2", children: props.extension.permissions.map((permission2) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "py-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "text-sm font-medium text-brand-dark/80", children: permission2.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-1 block break-all text-[11px] text-brand-dark/80", children: permission2.permission_id }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-1 text-xs text-brand-dark/80", children: permission2.action_classes.join(", ") || "No action classes" })
      ] }, permission2.permission_id)) })
    ] })
  ] }) });
}
function ProtectionModuleDetail(props) {
  const [policyDirty, setPolicyDirty] = reactExports.useState(false);
  reactExports.useEffect(() => {
    let highlightTimer = 0;
    let highlighted = null;
    const clearHighlight = () => {
      if (highlightTimer) window.clearTimeout(highlightTimer);
      highlightTimer = 0;
      highlighted?.classList.remove("guard-pattern-row-highlight");
      highlighted = null;
    };
    const highlight = () => {
      const anchor = window.location.hash;
      let rowId = null;
      let ruleId = null;
      if (anchor.startsWith("#pattern-")) {
        rowId = anchor.slice(1);
      } else if (anchor.startsWith("#rule-")) {
        ruleId = anchor.slice("#rule-".length);
      } else {
        const fragment = anchor.startsWith("#") ? anchor.slice(1) : anchor;
        const requested = new URLSearchParams(fragment).get("rule");
        if (requested) ruleId = requested;
      }
      if (ruleId) {
        const rule2 = props.extension.rules.find((item) => item.rule_id === ruleId);
        const permission2 = rule2 ? permissionForRule(props.extension, rule2) : null;
        rowId = permission2 ? `pattern-${permission2.permission_id}` : null;
      }
      clearHighlight();
      if (!rowId) return;
      const row = document.getElementById(rowId);
      if (!row) return;
      row.scrollIntoView({ behavior: "smooth", block: "center" });
      row.classList.add("guard-pattern-row-highlight");
      highlighted = row;
      highlightTimer = window.setTimeout(clearHighlight, 2400);
    };
    highlight();
    window.addEventListener("hashchange", highlight);
    return () => {
      window.removeEventListener("hashchange", highlight);
      clearHighlight();
    };
  }, [props.extension.extension_id, props.extension.rules]);
  const requiredNote = requiredLine(props.extension);
  const extensionEnabled = !props.effective.layers.some(
    (layer) => layer.controls.some((control) => control.target_kind === "extension" && control.target_id === props.extension.extension_id && control.state === "disabled")
  );
  const requestExtensionChange = props.extension.required ? void 0 : props.onRequestExtensionChange;
  const activeTab = canonicalProtectionDetailTab(props.urlState?.tab ?? "overview");
  const protectionView = buildLocalProtectionView(
    extensionLocalProtectionInput(props.extension, props.effective, props.runtime)
  );
  const orgManaged = protectionView.sources.some(
    (source) => source === "Synced from Guard Cloud" || source.startsWith("Managed by ")
  );
  const cloudControlsUrl = props.runtime?.dashboard_url?.trim() || props.runtime?.connect_url?.trim() || void 0;
  const setActiveTab = reactExports.useCallback((tab) => {
    if (!props.onUrlState) return false;
    if (tab !== activeTab && policyDirty && !window.confirm("Discard your unreviewed protection setting changes?")) {
      return false;
    }
    props.onUrlState({
      ...props.urlState ?? {
        tab: "overview",
        query: "",
        risk: "all",
        state: "all",
        configurable: "all",
        source: "all",
        deprecated: "all",
        type: "all",
        sort: "name",
        ruleId: null
      },
      tab,
      ruleId: null
    });
    return true;
  }, [activeTab, policyDirty, props.onUrlState, props.urlState]);
  const handleTabKeyDown = (event, tab) => {
    if (!event.key.startsWith("Arrow") && event.key !== "Home" && event.key !== "End") return;
    const index = DETAIL_TABS.findIndex((item) => item.id === tab);
    let nextIndex = index;
    if (event.key === "ArrowRight") nextIndex = (index + 1) % DETAIL_TABS.length;
    if (event.key === "ArrowLeft") nextIndex = (index - 1 + DETAIL_TABS.length) % DETAIL_TABS.length;
    if (event.key === "Home") nextIndex = 0;
    if (event.key === "End") nextIndex = DETAIL_TABS.length - 1;
    if (nextIndex === index && event.key !== "Home" && event.key !== "End") return;
    event.preventDefault();
    const next = DETAIL_TABS[nextIndex];
    if (!next) return;
    if (!setActiveTab(next.id)) return;
    window.requestAnimationFrame(() => document.getElementById(`protection-tab-${next.id}`)?.focus());
  };
  const handleBack = () => {
    if (policyDirty && !window.confirm("Discard your unreviewed protection setting changes?")) return;
    props.onBack();
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { "data-testid": "protection-module-detail", className: "w-full", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", onClick: handleBack, className: "inline-flex min-h-11 items-center gap-2 rounded-lg px-1 text-sm font-semibold text-brand-dark/80 hover:text-brand-dark", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowLeft, { className: "size-4", "aria-hidden": "true" }),
      "Extensions"
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "mt-4 border-b border-slate-200 pb-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          ExtensionBrandMark,
          {
            extension_id: props.extension.extension_id,
            name: props.extension.name,
            executables: props.extension.executables,
            ecosystem_ids: props.extension.ecosystem_ids,
            size: "lg"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-mono text-xs font-semibold tracking-[0.14em] text-slate-400", children: props.extension.executables.join(" · ") }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "mt-2 text-2xl font-semibold tracking-tight text-brand-dark", children: props.extension.name }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-sm leading-6 text-slate-500", children: props.extension.description }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-3 inline-flex rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-semibold text-brand-dark", children: protectionView.source })
        ] })
      ] }),
      requiredNote ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 max-w-2xl text-sm leading-6 text-brand-dark/80", children: requiredNote }) : null,
      requestExtensionChange ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-wrap items-center gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            role: "switch",
            "aria-checked": extensionEnabled,
            disabled: props.effective.health !== "protected",
            onClick: () => requestExtensionChange(props.extension, !extensionEnabled),
            className: "guard-tool-switch",
            "data-testid": "extension-availability-switch",
            children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "guard-tool-switch-knob" })
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Commands available" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-5 text-brand-dark/75", children: extensionEnabled ? "Matching commands follow the protection settings below. Turn off to block every command this tool owns on this device." : "Every command this tool owns is blocked on this device. Turn on to follow the protection settings below." })
        ] })
      ] }) : null,
      orgManaged ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-sm text-brand-dark/80", children: "Your organization controls part of this protection. Local changes cannot weaken organization policy." }) : null,
      props.effective.global_lockdown ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { role: "status", className: "mt-4 flex gap-2 text-sm text-brand-dark", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "mt-0.5 size-4 shrink-0" }),
        "Emergency Lockdown currently controls this module. Matching optional actions remain blocked."
      ] }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("nav", { className: "mt-5 flex gap-5 overflow-x-auto border-b border-slate-200", role: "tablist", "aria-label": "Extension detail sections", children: DETAIL_TABS.map((tab) => /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        id: `protection-tab-${tab.id}`,
        type: "button",
        role: "tab",
        "aria-selected": activeTab === tab.id,
        "aria-controls": `protection-panel-${tab.id}`,
        tabIndex: activeTab === tab.id ? 0 : -1,
        onClick: () => setActiveTab(tab.id),
        onKeyDown: (event) => handleTabKeyDown(event, tab.id),
        className: `-mb-px min-h-11 shrink-0 whitespace-nowrap border-b-2 px-1 pb-3 text-sm font-semibold focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue ${activeTab === tab.id ? "border-brand-blue text-brand-blue" : "border-transparent text-brand-dark/60 hover:text-brand-dark"}`,
        children: tab.label
      },
      tab.id
    )) }),
    activeTab === "overview" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { id: "protection-panel-overview", role: "tabpanel", "aria-labelledby": "protection-tab-overview", className: "mt-6 grid gap-4 lg:grid-cols-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "rounded-3xl border border-slate-200 bg-white p-5 shadow-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-lg font-semibold text-brand-dark", children: "Effective protection" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-6 text-brand-dark/75", children: protectionView.summary }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-5 grid gap-4 sm:grid-cols-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "State" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-sm font-semibold text-brand-dark", children: protectionStateLabel(protectionView.effectiveState) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "Source" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-sm font-semibold text-brand-dark", children: protectionView.source })
          ] }),
          protectionView.sources.length > 1 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "Contributors" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-sm text-brand-dark", children: protectionView.sources.join(" · ") })
          ] }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "Required" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-sm text-brand-dark", children: props.extension.required ? "Yes" : "No" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "Delegated protection" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-sm text-brand-dark", children: props.extension.delegated_protection === "package-firewall" ? "Package Firewall" : props.extension.delegated_protection ?? "None" })
          ] })
        ] }),
        props.extension.delegated_protection === "package-firewall" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("a", { href: "/supply-chain", className: "mt-4 inline-flex min-h-11 items-center gap-2 text-sm font-semibold text-brand-blue hover:underline", children: [
          "Open Package Firewall enforcement ",
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "size-4", "aria-hidden": "true" })
        ] }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "rounded-3xl border border-slate-200 bg-white p-5 shadow-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-lg font-semibold text-brand-dark", children: "What this Extension protects" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-6 text-brand-dark/75", children: "Choose Permissions to review effective behavior, built-in floors, and settings you may tighten locally." }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-5 grid gap-4 sm:grid-cols-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "Permissions" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-sm text-brand-dark", children: props.extension.permission_count })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "Detection rules" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-sm text-brand-dark", children: props.extension.rule_count })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "Baseline floors" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-sm text-brand-dark", children: [...new Set(props.extension.permissions.map((permission2) => treatmentLabel(permission2.baseline_floor)))].join(", ") || "Built-in" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs font-semibold uppercase text-brand-dark/55", children: "Configurable" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("dd", { className: "mt-1 text-sm text-brand-dark", children: [
              props.extension.permissions.filter((permission2) => permission2.configurable).length,
              " of ",
              props.extension.permission_count
            ] })
          ] })
        ] })
      ] })
    ] }) : null,
    activeTab === "permissions" ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { id: "protection-panel-permissions", role: "tabpanel", "aria-labelledby": "protection-tab-permissions", className: "mt-6", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      ExtensionPolicyPanel,
      {
        extension: props.extension,
        effective: props.effective,
        catalogDigest: props.catalogDigest,
        onRefresh: props.onRefresh,
        onDirtyChange: setPolicyDirty,
        cloudControlsUrl
      }
    ) }) : null,
    activeTab === "managed-controls" ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { id: "protection-panel-managed-controls", role: "tabpanel", "aria-labelledby": "protection-tab-managed-controls", className: "mt-6", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      ExtensionManagedControlsPanel,
      {
        extension: props.extension,
        effective: props.effective,
        runtime: props.runtime,
        onRefresh: props.onRefresh
      }
    ) }) : null,
    activeTab === "activity" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { id: "protection-panel-activity", role: "tabpanel", "aria-labelledby": "protection-tab-activity", className: "mt-6 space-y-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionActivity, { extension: props.extension, receipts: props.runtime?.latest_receipts ?? [] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ProtectionTestLab, { extension: props.extension })
    ] }) : null,
    activeTab === "technical" ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { id: "protection-panel-technical", role: "tabpanel", "aria-labelledby": "protection-tab-technical", className: "mt-6", children: /* @__PURE__ */ jsxRuntimeExports.jsx(DeveloperModuleDetails, { extension: props.extension, effective: props.effective, catalogDigest: props.catalogDigest }) }) : null
  ] });
}
function ExtensionsLoadingState(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid min-h-[60vh] place-items-center", "aria-busy": "true", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col items-center gap-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-8 w-48" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/70", children: props.label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      HiMiniArrowPath,
      {
        className: "size-7 animate-spin text-brand-blue motion-reduce:animate-none",
        "aria-hidden": "true"
      }
    )
  ] }) });
}
function ExtensionsLoadError(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mx-auto max-w-4xl", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `${EXTENSION_PANEL_CLASS} guard-extensions-tone-danger`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "text-xl font-semibold text-red-950", children: props.title }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-2 text-sm text-red-800", children: props.detail }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs font-medium text-red-900", children: "Local protection continues on this device." }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        onClick: props.onRetry,
        className: "mt-4 min-h-11 rounded-xl bg-red-800 px-4 text-sm font-semibold text-white",
        children: "Try again"
      }
    )
  ] }) });
}
function ExtensionsNotFound(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mx-auto max-w-4xl", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `${EXTENSION_PANEL_CLASS} guard-extensions-tone-attention`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "font-semibold text-amber-950", children: props.title }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-amber-900", children: props.detail }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        onClick: props.onBack,
        className: "mt-4 min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white",
        children: "Back to Extensions"
      }
    )
  ] }) });
}
function deriveProtectionStatus(effective) {
  if (effective.global_lockdown) {
    return {
      status: "lockdown",
      title: "Emergency Lockdown active",
      summary: "Guard is blocking matching optional actions until you review and end lockdown.",
      tone: "danger",
      primaryAction: "review-lockdown",
      primaryActionLabel: "Review lockdown"
    };
  }
  switch (effective.health) {
    case "protected":
      return {
        status: "protected",
        title: "Protected",
        summary: "Guard is actively applying the trusted protection settings on this device.",
        tone: "safe",
        primaryAction: "none",
        primaryActionLabel: null
      };
    case "unenrolled":
      return {
        status: "finish-setup",
        title: "Finish setup",
        summary: "Complete local setup so Guard can protect and verify settings on this device.",
        tone: "attention",
        primaryAction: "finish-setup",
        primaryActionLabel: "Show setup steps"
      };
    case "tampered":
    case "recovery-required":
      return {
        status: "needs-repair",
        title: "Needs repair",
        summary: "Guard detected a problem with trusted protection settings and is staying fail-safe until they are repaired.",
        tone: "danger",
        primaryAction: "repair",
        primaryActionLabel: "Repair protection"
      };
    case "degraded-unacknowledged":
      return {
        status: "limited",
        title: "Protection limited",
        summary: "Guard is staying fail-safe because it cannot fully verify protection settings. Repair is recommended.",
        tone: "attention",
        primaryAction: "repair",
        primaryActionLabel: "Restore protection"
      };
    case "degraded-acknowledged":
      return {
        status: "limited",
        title: "Protection limited",
        summary: "Guard is still staying fail-safe. The earlier acknowledgement did not restore trusted protection.",
        tone: "attention",
        primaryAction: "retry-repair",
        primaryActionLabel: "Try repair again"
      };
    default:
      return {
        status: "unavailable",
        title: "Protection status unavailable",
        summary: "Guard could not verify the current protection state. Refresh before making any protection changes.",
        tone: "neutral",
        primaryAction: "refresh",
        primaryActionLabel: "Check again"
      };
  }
}
function summarizeProtectionChange(change) {
  if ("globalLockdown" in change) {
    if (change.globalLockdown) {
      return { current: "Off", requested: "Active", title: "Enable Emergency Lockdown" };
    }
    return { current: "Active", requested: "Off", title: "Disable Emergency Lockdown" };
  }
  if (change.enabled) {
    return {
      current: "Blocked",
      requested: "Allowed within Guard safety rules",
      title: `Permit ${change.extension.name}`
    };
  }
  return {
    current: "Allowed",
    requested: "Blocked",
    title: `Block ${change.extension.name}`
  };
}
function ReviewModal(props) {
  const [password, setPassword] = reactExports.useState("");
  const [totp, setTotp] = reactExports.useState("");
  const dialogRef = useModalDialog(props.onCancel, !props.busy);
  const { current, requested, title } = summarizeProtectionChange(props.change);
  const handlePassword = reactExports.useCallback((event) => {
    setPassword(event.target.value);
  }, []);
  const handleTotp = reactExports.useCallback((event) => {
    setTotp(event.target.value);
  }, []);
  const handleSubmit = reactExports.useCallback((event) => {
    event.preventDefault();
    props.onConfirm(buildApprovalProofCredentials(props.approvalGate, { approvalPassword: password, approvalTotpCode: totp }));
  }, [password, props, totp]);
  const submitDisabled = isApprovalProofSubmitDisabled(props.approvalGate, { approvalPassword: password, approvalTotpCode: totp }, props.busy);
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "fixed inset-0 z-50 grid place-items-center bg-slate-950/45 p-4 backdrop-blur-sm", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("form", { ref: dialogRef, tabIndex: -1, role: "dialog", "aria-modal": "true", "aria-labelledby": "protection-review-title", onSubmit: handleSubmit, className: "w-full max-w-lg rounded-3xl bg-white p-6 shadow-2xl focus:outline-none", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-bold uppercase tracking-[0.18em] text-brand-blue", children: "Review protection change" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "protection-review-title", className: "mt-2 text-xl font-semibold text-brand-dark", children: title })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.busy, onClick: props.onCancel, "aria-label": "Close review", className: "grid size-11 place-items-center rounded-full text-brand-dark hover:bg-white/70 disabled:opacity-50", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-5" }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 grid grid-cols-[1fr_auto_1fr] items-center gap-3 rounded-2xl bg-[rgba(85,153,254,0.08)] p-4 text-sm text-brand-dark", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Current" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", children: "→" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Requested" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: current }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", {}),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: requested })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 text-sm leading-6 text-brand-dark", children: "Guard's built-in minimum safety rules and organization policy remain active. This change does not disable detection." }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ApprovalProofFieldInputs, { approvalGate: props.approvalGate, approvalPassword: password, approvalTotpCode: totp, onApprovalPasswordChange: handlePassword, onApprovalTotpCodeChange: handleTotp }) }),
    props.error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-4 rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800", children: props.error }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 flex justify-end gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", disabled: props.busy, onClick: props.onCancel, className: "min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark hover:bg-white/70 disabled:opacity-50", children: "Cancel" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "submit", disabled: submitDisabled, className: "min-h-11 rounded-xl bg-brand-blue px-5 text-sm font-semibold text-white hover:bg-brand-dark disabled:opacity-60", children: props.busy ? "Verifying…" : "Confirm change" })
    ] })
  ] }) });
}
function currentExtensionRouteState() {
  return {
    route: parseProtectionRoute(window.location.pathname),
    detail: readExtensionDetailUrlState(window.location.search)
  };
}
function requiresExtensionRecoveryApproval(error) {
  return error instanceof ExtensionControlApiError && (error.code === "approval_required" || error.code?.startsWith("approval_gate_") === true);
}
function authorityActionErrorMessage(error) {
  if (error instanceof ExtensionControlApiError) {
    if (error.code === "authority_not_recoverable") {
      return "Guard could not start this repair because the protection state changed underneath it. Guard reloaded the latest status. If protection still needs attention, run `hol-guard command controls recover-authority` in your terminal.";
    }
    if (error.code === "authority_recovery_failed" || error.code === "authority_recovery_incomplete") {
      return "Guard started the repair but could not verify a fully protected state. Protection stays fail-safe. Try again, or run `hol-guard command controls recover-authority` in your terminal.";
    }
    if (error.code === "authority_not_degraded") {
      return "The limited state already changed. Guard reloaded the latest status.";
    }
    if (requiresExtensionRecoveryApproval(error)) {
      return "Guard needs your approval password to continue. Enter it and try again.";
    }
  }
  return error instanceof Error && error.message && !/^authority_|^approval_/.test(error.message) ? error.message : "Guard could not complete this action. Local protection continues. Try again, or run `hol-guard command controls recover-authority` in your terminal.";
}
function randomToken() {
  return crypto.randomUUID().replaceAll("-", "");
}
function buildExtensionMutation(state, change) {
  const layers = structuredClone(state.effective.layers);
  let local = layers.find((layer) => layer.kind === "local-admin");
  if (!local) {
    local = {
      schema_version: "1.0.0",
      kind: "local-admin",
      catalog_digest: state.catalog.catalog_digest,
      global_lockdown: false,
      controls: []
    };
    layers.push(local);
  }
  if ("globalLockdown" in change) {
    local.global_lockdown = change.globalLockdown;
  } else {
    local.controls = local.controls.filter(
      (control) => control.target_kind !== "extension" || control.target_id !== change.extension.extension_id
    );
    local.controls.push({
      target_kind: "extension",
      target_id: change.extension.extension_id,
      state: change.enabled ? "enabled" : "disabled"
    });
    local.controls.sort(
      (left, right) => `${left.target_kind}:${left.target_id}`.localeCompare(`${right.target_kind}:${right.target_id}`)
    );
  }
  return {
    previous_revision: state.effective.revision,
    catalog_digest: state.catalog.catalog_digest,
    layers,
    actor_id: "dashboard-admin",
    idempotency_key: randomToken(),
    nonce: randomToken()
  };
}
function ProtectionCenterWorkspace(props) {
  const [state, setState] = reactExports.useState({ kind: "loading" });
  const [routeState, setRouteState] = reactExports.useState(() => currentExtensionRouteState());
  const [pending, setPending] = reactExports.useState(null);
  const [busy, setBusy] = reactExports.useState(false);
  const [mutationError, setMutationError] = reactExports.useState(null);
  const [recoveryBusy, setRecoveryBusy] = reactExports.useState(false);
  const [recoveryError, setRecoveryError] = reactExports.useState(null);
  const [recoveryStatus, setRecoveryStatus] = reactExports.useState(null);
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  const aliasRedirected = reactExports.useRef(null);
  const overviewKeepAlive = reactExports.useRef(false);
  const localClis = useLocalCliCatalog();
  const load = reactExports.useCallback(async () => {
    setState((current) => current.kind === "ready" ? current : { kind: "loading" });
    try {
      const [catalog, effective] = await Promise.all([fetchExtensionCatalog(), fetchEffectiveExtensionControls()]);
      if (catalog.catalog_digest !== effective.catalog_digest) throw new Error("Protection data changed while Guard was loading. Check again before making changes.");
      setState({ kind: "ready", catalog, effective });
      return effective;
    } catch (error) {
      setState((current) => current.kind === "ready" ? current : { kind: "error", message: error instanceof Error ? error.message : "Extensions are unavailable" });
      return null;
    }
  }, []);
  reactExports.useEffect(() => {
    void load();
  }, [load]);
  reactExports.useEffect(() => {
    const onPopState = () => setRouteState(currentExtensionRouteState());
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);
  const catalogExtensions = reactExports.useMemo(() => state.kind === "ready" ? [...state.catalog.extensions].sort((a, b) => a.name.localeCompare(b.name)) : [], [state]);
  const requestedExtensionId = routeState.route.kind === "detail" ? routeState.route.extensionId : null;
  const canonicalSelected = reactExports.useMemo(() => canonicalExtensionId(catalogExtensions, requestedExtensionId), [catalogExtensions, requestedExtensionId]);
  const selectedExtension = reactExports.useMemo(() => catalogExtensions.find((item) => item.extension_id === canonicalSelected) ?? null, [catalogExtensions, canonicalSelected]);
  reactExports.useEffect(() => {
    if (state.kind !== "ready" || routeState.route.kind !== "detail" || !canonicalSelected) return;
    if (routeState.route.extensionId === canonicalSelected) return;
    const key = `${routeState.route.extensionId}->${canonicalSelected}`;
    if (aliasRedirected.current === key) return;
    aliasRedirected.current = key;
    replaceExtensionHistory(extensionDetailHref(canonicalSelected, routeState.detail));
    setRouteState({ route: { kind: "detail", extensionId: canonicalSelected }, detail: routeState.detail });
  }, [canonicalSelected, routeState, state]);
  const openExtension = reactExports.useCallback((extension2) => {
    pushExtensionHistory(extensionDetailHref(extension2.extension_id, DEFAULT_EXTENSION_DETAIL_URL_STATE));
    setRouteState({ route: { kind: "detail", extensionId: extension2.extension_id }, detail: DEFAULT_EXTENSION_DETAIL_URL_STATE });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, []);
  const closeExtension = reactExports.useCallback(() => {
    pushExtensionHistory("/extensions");
    setRouteState({ route: { kind: "overview" }, detail: DEFAULT_EXTENSION_DETAIL_URL_STATE });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, []);
  const updateExtensionDetailState = reactExports.useCallback((detail) => {
    if (!canonicalSelected) return;
    pushExtensionHistory(extensionDetailHref(canonicalSelected, detail));
    setRouteState({ route: { kind: "detail", extensionId: canonicalSelected }, detail });
  }, [canonicalSelected]);
  const openLocalCliDetail = reactExports.useCallback((cliId) => {
    pushExtensionHistory(localCliHref(cliId));
    setRouteState({ route: { kind: "local-cli", cliId }, detail: DEFAULT_EXTENSION_DETAIL_URL_STATE });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, []);
  const openAddCustom = reactExports.useCallback(() => {
    pushExtensionHistory(addCustomExtensionHref());
    setRouteState({ route: { kind: "add-custom" }, detail: DEFAULT_EXTENSION_DETAIL_URL_STATE });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, []);
  const handleCustomExtensionAdded = reactExports.useCallback((cliId) => {
    void localClis.load();
    openLocalCliDetail(cliId);
  }, [localClis.load, openLocalCliDetail]);
  const retryLocalClis = reactExports.useCallback(() => {
    void localClis.load();
  }, [localClis.load]);
  const retryLoad = reactExports.useCallback(() => {
    void load();
  }, [load]);
  const refreshProtection = reactExports.useCallback(async () => {
    await load();
  }, [load]);
  const handleCancelPending = reactExports.useCallback(() => {
    if (!busy) setPending(null);
  }, [busy]);
  const requestChange = reactExports.useCallback((change) => {
    setMutationError(null);
    void resolveApprovalGate({ failClosed: true }).then(() => setPending(change)).catch(() => setMutationError("Guard could not load local approval settings. Check the local connection and try again."));
  }, [resolveApprovalGate]);
  const handleRequestExtensionChange = reactExports.useCallback((extension2, enabled) => {
    requestChange({ extension: { extension_id: extension2.extension_id, name: extension2.name }, enabled });
  }, [requestChange]);
  const confirm = reactExports.useCallback(async (credentials) => {
    if (state.kind !== "ready" || !pending) return;
    setBusy(true);
    setMutationError(null);
    try {
      const payload = buildExtensionMutation(state, pending);
      Object.assign(payload, credentials);
      payload.session_nonce = randomToken();
      const preview = await previewExtensionMutation(payload);
      if (typeof preview.proof_id !== "string") throw new Error("Guard did not issue a one-use proof for this protection change.");
      payload.proof_id = preview.proof_id;
      await applyExtensionMutation(payload);
      setPending(null);
      await load();
    } catch (error) {
      const recovery = error instanceof ExtensionControlApiError ? error.recoveryAction : void 0;
      setMutationError(`${error instanceof Error ? error.message : "Protection change failed"}${recovery ? ` · ${recovery}` : ""}`);
    } finally {
      setBusy(false);
    }
  }, [load, pending, state]);
  const runAuthorityAction = reactExports.useCallback(async (kind, credentials) => {
    const startHealth = state.kind === "ready" ? state.effective.health : null;
    setRecoveryBusy(true);
    setRecoveryError(null);
    setRecoveryStatus(null);
    try {
      const effective = kind === "acknowledge" ? await acknowledgeDegradedExtensionControlAuthority(credentials) : await recoverExtensionControlAuthority(credentials);
      if (kind === "acknowledge") {
        if (effective.health !== "degraded-acknowledged") throw new Error("Guard could not confirm the limited state.");
        setRecoveryStatus("The limited state is acknowledged. Guard remains fail-safe until trusted protection can be restored.");
      } else {
        if (effective.health !== "protected") throw new Error("Guard could not verify repaired protection.");
        setRecoveryStatus("Local protection repaired and verified.");
      }
      if (state.kind === "ready") setState({ ...state, effective });
    } catch (error) {
      const fresh = await load();
      const wanted = kind === "acknowledge" ? "degraded-acknowledged" : "protected";
      if (fresh && fresh.health === wanted) {
        setRecoveryError(null);
        setRecoveryStatus(kind === "acknowledge" ? "The limited state is acknowledged. Guard remains fail-safe until trusted protection can be restored." : "Local protection repaired and verified.");
      } else if (fresh && startHealth !== null && fresh.health !== startHealth) {
        setRecoveryError(null);
        setRecoveryStatus("The protection state changed during the attempt. This page now shows the latest status.");
      } else {
        setRecoveryStatus(null);
        setRecoveryError(authorityActionErrorMessage(error));
      }
    } finally {
      setRecoveryBusy(false);
    }
  }, [load, state]);
  const handleAuthorityAction = reactExports.useCallback((kind, credentials) => {
    void runAuthorityAction(kind, credentials);
  }, [runAuthorityAction]);
  const handleCheckAgain = reactExports.useCallback(() => {
    void load();
    setRecoveryError(null);
    void resolveApprovalGate({ failClosed: true }).catch(() => {
      setRecoveryError("Guard could not load the local approval settings yet. Check the connection and try again, or run `hol-guard command controls recover-authority` in your terminal.");
    });
  }, [load, resolveApprovalGate]);
  const authorityNeedsAttention = state.kind === "ready" && state.effective.health !== "protected";
  reactExports.useEffect(() => {
    if (!authorityNeedsAttention) return;
    void resolveApprovalGate({ failClosed: true }).catch(() => {
      setRecoveryError("Guard could not load the local approval settings yet. Check the connection and try again, or run `hol-guard command controls recover-authority` in your terminal.");
    });
  }, [authorityNeedsAttention, resolveApprovalGate]);
  const showOverview = state.kind === "ready" && routeState.route.kind === "overview";
  if (showOverview) overviewKeepAlive.current = true;
  const keepOverviewMounted = state.kind === "ready" && (showOverview || overviewKeepAlive.current);
  const localCliRoute = routeState.route.kind === "local-cli" ? routeState.route : null;
  const selectedLocalCli = localCliRoute ? localClis.data?.items.find((item) => item.cli_id === localCliRoute.cliId) ?? null : null;
  const showLocalCli = localCliRoute !== null;
  const showDetail = routeState.route.kind === "detail" && selectedExtension !== null;
  const showNotFound = routeState.route.kind === "invalid" || routeState.route.kind === "detail" && selectedExtension === null && state.kind === "ready" || showLocalCli && localClis.data !== null && selectedLocalCli === null;
  const handlePrimaryStatusAction = reactExports.useCallback(() => {
    requestChange({ globalLockdown: false });
  }, [requestChange]);
  const loadError = state.kind === "error" ? protectionCenterLoadError(state.message) : null;
  const status = state.kind === "ready" ? deriveProtectionStatus(state.effective) : null;
  const healthBroken = state.kind === "ready" && state.effective.health !== "protected";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "w-full", "data-testid": "extensions-workspace", children: [
    state.kind === "loading" ? /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionsLoadingState, { label: "Loading Extensions" }) : null,
    state.kind === "error" && loadError ? /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionsLoadError, { title: loadError.title, detail: loadError.detail, onRetry: retryLoad }) : null,
    state.kind === "ready" && healthBroken ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ProtectionAuthorityNotice,
      {
        effective: state.effective,
        busy: recoveryBusy,
        error: recoveryError,
        status: recoveryStatus,
        approvalGate: resolvedApprovalGate,
        onAction: handleAuthorityAction,
        onCheckAgain: handleCheckAgain
      }
    ) : null,
    state.kind === "ready" && recoveryStatus && !healthBroken && !showOverview ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "mb-3 text-sm font-medium text-emerald-800", children: recoveryStatus }) : null,
    keepOverviewMounted && state.kind === "ready" && status ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ExtensionsOverview,
      {
        catalogExtensions,
        effective: state.effective,
        localCliItems: localClis.data?.items ?? [],
        localCliError: localClis.error,
        mutationError: mutationError && !pending ? mutationError : null,
        recoveryStatus,
        healthBroken,
        status,
        active: showOverview,
        onPrimaryStatusAction: handlePrimaryStatusAction,
        onRefresh: refreshProtection,
        onOpenExtension: openExtension,
        onOpenLocalCli: openLocalCliDetail,
        onAddCustom: openAddCustom
      }
    ) : null,
    showLocalCli && localClis.error && !localClis.data ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ExtensionsLoadError,
      {
        title: "Custom extension unavailable",
        detail: localClis.error,
        onRetry: retryLocalClis
      }
    ) : null,
    showLocalCli && localClis.error && localClis.data ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mb-3 text-sm font-medium text-rose-800", children: localClis.error }) : null,
    showLocalCli && !localClis.data && !localClis.error ? /* @__PURE__ */ jsxRuntimeExports.jsx(ExtensionsLoadingState, { label: "Loading custom extension" }) : null,
    routeState.route.kind === "add-custom" && state.kind === "ready" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      AddCustomExtensionWorkspace,
      {
        items: localClis.data?.items ?? [],
        revision: localClis.data?.revision ?? 0,
        onBack: closeExtension,
        onAdded: handleCustomExtensionAdded
      }
    ) : null,
    showLocalCli && selectedLocalCli && localClis.data ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      LocalCliDetail,
      {
        item: selectedLocalCli,
        revision: localClis.data.revision,
        continuity: localClis.data.cloud,
        onBack: closeExtension,
        onRefresh: localClis.load
      }
    ) : null,
    showDetail && selectedExtension && state.kind === "ready" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ProtectionModuleDetail,
      {
        extension: selectedExtension,
        effective: state.effective,
        catalogDigest: state.catalog.catalog_digest,
        runtime: props.runtime,
        urlState: routeState.detail,
        onUrlState: updateExtensionDetailState,
        onBack: closeExtension,
        onRefresh: refreshProtection,
        onRequestExtensionChange: handleRequestExtensionChange
      }
    ) : null,
    showNotFound ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ExtensionsNotFound,
      {
        title: showLocalCli ? "Custom extension not found" : "Extension not found",
        detail: showLocalCli ? "This link does not match a CLI Guard has seen on this device." : "This link does not match an extension in the current Guard catalog.",
        onBack: closeExtension
      }
    ) : null,
    pending ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ReviewModal,
      {
        change: pending,
        busy,
        error: mutationError,
        approvalGate: resolvedApprovalGate,
        onCancel: handleCancelPending,
        onConfirm: confirm
      }
    ) : null
  ] });
}
export {
  ProtectionCenterWorkspace as ExtensionsWorkspace,
  ProtectionAuthorityNotice,
  ReviewModal,
  authorityActionErrorMessage,
  buildExtensionMutation,
  currentExtensionRouteState,
  requiresExtensionRecoveryApproval
};
