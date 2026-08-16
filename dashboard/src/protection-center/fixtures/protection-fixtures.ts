import type {
  EffectiveExtensionControls,
  ExtensionCatalogItem,
  ExtensionPermission,
  ExtensionRule,
} from "../../extension-controls-api";

const DIGEST = "a".repeat(64);

export function protectionAuthorityFixture(
  health: EffectiveExtensionControls["health"],
  options: { lockdown?: boolean; revision?: number; layers?: EffectiveExtensionControls["layers"] } = {},
): EffectiveExtensionControls {
  return {
    schema_version: "1.0.0",
    health,
    revision: options.revision ?? 1,
    catalog_digest: DIGEST,
    global_lockdown: options.lockdown ?? false,
    controls: [],
    layers: options.layers ?? [],
    failures: health === "protected" ? [] : [{ code: "fixture-state" }],
  };
}

const managedBlockLayer: EffectiveExtensionControls["layers"][number] = {
  schema_version: "1.0.0",
  kind: "signed-cloud",
  catalog_digest: DIGEST,
  global_lockdown: false,
  controls: [{ target_kind: "extension", target_id: "command.git", state: "disabled" }],
};

const localStricterLayer: EffectiveExtensionControls["layers"][number] = {
  schema_version: "1.0.0",
  kind: "local-admin",
  catalog_digest: DIGEST,
  global_lockdown: false,
  controls: [{ target_kind: "extension", target_id: "command.git", state: "disabled" }],
};

export const PROTECTION_AUTHORITY_FIXTURES = {
  protected: protectionAuthorityFixture("protected"),
  unenrolled: protectionAuthorityFixture("unenrolled"),
  tampered: protectionAuthorityFixture("tampered"),
  recoveryRequired: protectionAuthorityFixture("recovery-required"),
  degradedUnacknowledged: protectionAuthorityFixture("degraded-unacknowledged"),
  degradedAcknowledged: protectionAuthorityFixture("degraded-acknowledged"),
  lockdown: protectionAuthorityFixture("protected", { lockdown: true }),
  managedBlock: protectionAuthorityFixture("protected", { layers: [managedBlockLayer] }),
  localStricterBlock: protectionAuthorityFixture("protected", { layers: [localStricterLayer] }),
} as const;

export function protectionModuleFixture(overrides: Partial<ExtensionCatalogItem> = {}): ExtensionCatalogItem {
  return {
    schema_version: 2,
    extension_id: "command.git",
    version: "1.0.0",
    name: "Git",
    description: "Protects source-control history and destructive repository operations.",
    enabled: true,
    required: false,
    source: "built-in",
    aliases: [],
    dependencies: [],
    conflicts: [],
    delegated_protection: null,
    ecosystem_ids: ["git"],
    executables: ["git"],
    project_markers: [".git"],
    reference_urls: [],
    action_classes: ["git.history.rewrite"],
    risk_classes: ["history-rewrite"],
    safer_alternatives: ["Create a checkpoint before rewriting repository history."],
    rule_count: 0,
    rules: [],
    permission_count: 0,
    permissions: [],
    ...overrides,
  };
}

export const FIXED_PROTECTION_PERMISSION: ExtensionPermission = {
  permission_id: "command.git.permission.required-safety",
  schema_version: 1,
  extension_id: "command.git",
  implementation_version: "1.0.0",
  label: "Required destructive-operation protection",
  description: "Guard keeps this minimum protection active.",
  risk_tier: "high",
  baseline_floor: "review",
  default_enabled: true,
  configurable: false,
  fixed_reason: "This minimum protection is required by Guard's built-in safety model.",
  typed_capabilities: [],
  action_classes: ["git.history.rewrite"],
  rule_ids: ["command.git.required-safety"],
  dependencies: [],
  conflicts: [],
  implied_permissions: [],
  introduced_version: "1.0.0",
  deprecated: false,
  replacement_permission_id: null,
  safer_guidance: ["Create a checkpoint before rewriting repository history."],
  example_command: null,
  family: null,
};

export const FIXED_PROTECTION_MODULE = protectionModuleFixture({
  permission_count: 1,
  permissions: [FIXED_PROTECTION_PERMISSION],
});

function largeRule(index: number): ExtensionRule {
  return {
    rule_id: `command.fixture.rule-${String(index).padStart(3, "0")}`,
    rule_version: 1,
    title: `Fixture detection ${index}`,
    description: "Synthetic deterministic rule for Developer-mode performance coverage.",
    severity: index % 10 === 0 ? "high" : "low",
    risk_classes: index % 10 === 0 ? ["destructive-operation"] : [],
    action_classes: ["fixture.operation"],
    safer_alternatives: [],
    default_mode: index % 10 === 0 ? "review" : "monitor",
    matcher_kind: "SyntheticMatcher",
    safe_variants: [],
    compatibility_fallback: false,
  };
}

export function largeDeveloperModuleFixture(ruleCount = 500): ExtensionCatalogItem {
  if (!Number.isInteger(ruleCount) || ruleCount < 1 || ruleCount > 500) throw new Error("Invalid fixture rule count");
  const rules = Array.from({ length: ruleCount }, (_, index) => largeRule(index + 1));
  return protectionModuleFixture({
    extension_id: "command.fixture-large",
    name: "Large fixture module",
    description: "Synthetic deterministic module for Developer-mode performance coverage.",
    ecosystem_ids: ["fixture"],
    executables: ["fixture"],
    project_markers: [],
    action_classes: ["fixture.operation"],
    risk_classes: [],
    rule_count: rules.length,
    rules,
  });
}

export const SYNTHETIC_PROTECTION_DECISIONS = [
  { id: "decision-allowed", result: "allowed" as const, module: "Git", reason: "The operation only inspected repository state." },
  { id: "decision-review", result: "ask-first" as const, module: "Packages", reason: "The install can run package lifecycle code, so Guard asks first." },
  { id: "decision-blocked", result: "blocked" as const, module: "Files and secrets", reason: "The operation could expose sensitive local credentials." },
] as const;

export const NO_PROTECTION_DECISIONS = [] as const;

export const STALE_POLICY_DRAFT_FIXTURE = {
  baseRevision: 4,
  currentRevision: 5,
  dirty: true,
  conflictingTargetIds: ["command.git.permission.required-safety"],
} as const;

export type ProtectionCloudFixture = {
  signedIn: boolean;
  syncConfigured: boolean;
  state: "local_only" | "paired_waiting" | "paired_active" | "unavailable";
  label: string;
};

export const CLOUD_OFFLINE_FIXTURE: ProtectionCloudFixture = {
  signedIn: false,
  syncConfigured: false,
  state: "local_only",
  label: "Cloud continuity not connected",
};

export const CLOUD_CONNECTED_FIXTURE: ProtectionCloudFixture = {
  signedIn: true,
  syncConfigured: true,
  state: "paired_active",
  label: "Cloud continuity connected",
};

export const MALFORMED_PROTECTION_STATE_FIXTURE: unknown = {
  schema_version: 999,
  health: "unexpected",
  revision: -1,
  catalog_digest: "not-a-digest",
  global_lockdown: "yes",
};
