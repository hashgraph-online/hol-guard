import type { GuardPolicyDecision } from "./guard-types";
import type { RuleAuthority } from "./managed-controls/rules-exceptions-model";

const CANONICAL_EXTENSION_ID = /^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const CANONICAL_PERMISSION_ID = /^(command\.[a-z0-9]+(?:[.-][a-z0-9]+)*)\.permission\.[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const CLOUD_MANAGED_SOURCES = new Set(["cloud-sync", "team-policy", "policy-bundle"]);

export function isCloudManagedPolicySource(source: string): boolean {
  return CLOUD_MANAGED_SOURCES.has(source);
}

export function resolvePolicyRowSourceLabel(policy: GuardPolicyDecision): RuleAuthority | "Trusted local tool" {
  if (policy.source === "trusted-local-tool") return "Trusted local tool";
  if (!isCloudManagedPolicySource(policy.source)) return "Remembered on this device";
  if (policy.authority_mode === "managed-restrictive") {
    const workspace = policy.cloud_workspace_label?.trim() || policy.workspace_label?.trim();
    return workspace ? `Managed by ${workspace}` : "Managed by workspace";
  }
  return "Synced contextual rule";
}

export function resolvePolicyGoverningExtensionId(policy: GuardPolicyDecision): string | null {
  const explicit = policy.extension_id?.trim().toLowerCase();
  if (explicit && CANONICAL_EXTENSION_ID.test(explicit)) return explicit;
  const permission = policy.permission_id?.trim().toLowerCase();
  const permissionMatch = permission?.match(CANONICAL_PERMISSION_ID);
  if (permissionMatch?.[1]) return permissionMatch[1];
  const artifact = policy.artifact_id?.trim().toLowerCase();
  if (artifact && CANONICAL_EXTENSION_ID.test(artifact)) return artifact;
  return artifact?.match(CANONICAL_PERMISSION_ID)?.[1] ?? null;
}
