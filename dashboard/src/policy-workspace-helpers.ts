import type { GuardPolicyDecision } from "./guard-types";
import { harnessDisplayName, policyActionLabel, scopeLabel } from "./approval-center-utils";

const MATCHER_FAMILY_LABELS: Record<string, string> = {
  "package-request": "package install",
  "tool-action": "shell or tool command",
  "tool-output": "command output review",
  prompt: "prompt submission",
  "prompt-env-read": "environment variable read",
  mcp: "MCP server call",
  "file-read": "file read",
};

const GENERIC_REASONS = [
  "approved in review",
  "approved in local approval center",
  "local auto-resume proof",
  "local e2e approval proof",
];

export type PolicyDisplay = {
  headline: string;
  subtitle: string;
  technicalId: string | null;
};

export function isCloudManagedPolicy(source: string): boolean {
  return source === "cloud-sync" || source === "team-policy" || source === "cloud-bundle";
}

export function resolvePolicySourceLabel(source: string): string {
  if (isCloudManagedPolicy(source)) {
    return "Guard Cloud";
  }
  if (source === "manual" || source === "local") {
    return "This device";
  }
  return source.replace(/_/g, " ");
}

export function policyTargetLabel(policy: GuardPolicyDecision): string {
  return policy.artifact_id ?? policy.publisher ?? policy.workspace ?? "Global";
}

function isGenericReason(reason: string | null | undefined): boolean {
  if (!reason?.trim()) {
    return true;
  }
  const normalized = reason.trim().toLowerCase();
  return GENERIC_REASONS.some((phrase) => normalized.includes(phrase));
}

function extractMatcherFamily(artifactId: string): string | null {
  if (artifactId.startsWith("family:")) {
    return artifactId.slice("family:".length);
  }
  const parts = artifactId.split(":");
  for (const family of Object.keys(MATCHER_FAMILY_LABELS)) {
    if (parts.includes(family)) {
      return family;
    }
  }
  return null;
}

function resolveRuntimeActionLabel(artifactId: string): string | null {
  const parts = artifactId.split(":");
  const runtimeIndex = parts.indexOf("runtime");
  if (runtimeIndex < 0) {
    return null;
  }
  const tail = parts.slice(runtimeIndex + 1);
  if (tail[0] === "global" && tail.length >= 3) {
    const tool = tail[1].replace(/-/g, " ");
    const action = tail.slice(2).join(" ").replace(/_/g, " ");
    return `${tool}: ${action}`;
  }
  return null;
}

function resolvePromptSubtypeLabel(artifactId: string): string | null {
  const parts = artifactId.split(":");
  const promptIndex = parts.indexOf("prompt");
  if (promptIndex < 0) {
    return null;
  }
  const subtype = parts[promptIndex + 1];
  if (!subtype) {
    return "prompt review";
  }
  return subtype.replace(/_/g, " ");
}

export function resolveWorkspaceLabel(workspace: string | null | undefined): string {
  if (!workspace?.trim()) {
    return "this project";
  }
  const value = workspace.trim();
  if (value.startsWith("workspace:")) {
    return "this project";
  }
  if (value.startsWith("/")) {
    const segments = value.split("/").filter(Boolean);
    return segments[segments.length - 1] ?? "this project";
  }
  if (value.length > 32 && /^[a-f0-9]+$/i.test(value)) {
    return "this project";
  }
  return value;
}

function resolveActionVerb(action: string): string {
  if (action === "allow") {
    return "Allow";
  }
  if (action === "block") {
    return "Block";
  }
  return policyActionLabel(action);
}

function resolveScopeSubtitle(policy: GuardPolicyDecision): string {
  const app = harnessDisplayName(policy.harness);
  if (policy.scope === "artifact") {
    return `Applies once in ${app}`;
  }
  if (policy.scope === "workspace") {
    return `Applies every time in ${resolveWorkspaceLabel(policy.workspace)} (${app})`;
  }
  if (policy.scope === "harness") {
    return `Applies every time in ${app}`;
  }
  if (policy.scope === "publisher") {
    const publisher = policy.publisher?.trim() || "this publisher";
    return `Applies to ${publisher} in ${app}`;
  }
  if (policy.scope === "global") {
    return "Applies on every project on this device";
  }
  return scopeLabel(policy.scope);
}

function resolveWhatPhrase(policy: GuardPolicyDecision): string {
  const artifactId = policy.artifact_id?.trim() ?? "";
  const publisher = policy.publisher?.trim();

  if (policy.scope === "global" && !artifactId && !publisher) {
    return "all guarded actions on this device";
  }

  const runtimeLabel = artifactId ? resolveRuntimeActionLabel(artifactId) : null;
  if (runtimeLabel) {
    return runtimeLabel;
  }

  const family = artifactId ? extractMatcherFamily(artifactId) : null;
  const familyPhrase = family ? MATCHER_FAMILY_LABELS[family] ?? family.replace(/-/g, " ") : null;

  if (familyPhrase) {
    if (artifactId.startsWith("family:") || policy.scope === "harness") {
      return `all ${familyPhrase}s`;
    }
    if (family === "prompt") {
      const subtype = resolvePromptSubtypeLabel(artifactId);
      return subtype ? `${familyPhrase} (${subtype})` : familyPhrase;
    }
    return familyPhrase;
  }

  if (publisher) {
    return `actions from ${publisher}`;
  }

  return "matching guarded actions";
}

export function resolvePolicyDisplay(policy: GuardPolicyDecision): PolicyDisplay {
  const reason = policy.reason?.trim() ?? null;
  const actionVerb = resolveActionVerb(policy.action);

  if (reason && !isGenericReason(reason)) {
    return {
      headline: `${actionVerb}: ${reason}`,
      subtitle: resolveScopeSubtitle(policy),
      technicalId: policy.artifact_id,
    };
  }

  const what = resolveWhatPhrase(policy);
  return {
    headline: `${actionVerb} ${what}`,
    subtitle: resolveScopeSubtitle(policy),
    technicalId: policy.artifact_id,
  };
}

export function resolvePolicyEvidenceSearchTerm(policy: GuardPolicyDecision): string | null {
  const hash = policy.artifact_hash?.trim();
  if (hash) {
    const normalized = hash.replace(/^sha256:/i, "");
    return normalized.slice(0, 12);
  }
  const target = policyTargetLabel(policy);
  if (!target || target === "Global") {
    return null;
  }
  if (target.startsWith("family:")) {
    return target.slice("family:".length);
  }
  const parts = target.split(":");
  const last = parts[parts.length - 1];
  if (last && last.length >= 12 && /^[a-f0-9]+$/i.test(last)) {
    return last.slice(0, 12);
  }
  return null;
}

export function resolvePolicyEvidenceHref(policy: GuardPolicyDecision): string {
  const params = new URLSearchParams();
  const searchTerm = resolvePolicyEvidenceSearchTerm(policy);
  if (searchTerm) {
    params.set("search", searchTerm);
  }
  const query = params.toString();
  return query ? `/evidence?${query}` : "/evidence";
}

export function resolveCloudPolicyControlsUrl(snapshot: { dashboard_url?: string | null }): string | null {
  const url = snapshot.dashboard_url?.trim();
  return url || null;
}

export function resolvePolicyMatcherFamily(policy: GuardPolicyDecision): string | null {
  const target = policy.artifact_id?.trim();
  if (!target) {
    return null;
  }
  return extractMatcherFamily(target);
}

export function groupPoliciesByHarness(
  policies: GuardPolicyDecision[],
): Map<string, GuardPolicyDecision[]> {
  const map = new Map<string, GuardPolicyDecision[]>();
  for (const policy of policies) {
    const key = policy.harness || "global";
    const existing = map.get(key) ?? [];
    map.set(key, [...existing, policy]);
  }
  return map;
}

export function resolveSecurityModeCopy(
  level: string | undefined,
): { label: string; description: string; tone: "green" | "attention" | "slate" } {
  if (level === "strict") {
    return {
      label: "Strict mode",
      description:
        "Guard asks before most actions including new network connections and file writes. Higher noise, maximum protection.",
      tone: "attention",
    };
  }
  if (level === "balanced") {
    return {
      label: "Balanced (default)",
      description:
        "Guard asks for secrets, destructive commands, and new network destinations. Low noise, solid coverage.",
      tone: "green",
    };
  }
  if (level === "gentle" || level === "relaxed") {
    return {
      label: "Low noise",
      description: "Guard only asks for the highest-risk actions. Minimal interruptions.",
      tone: "slate",
    };
  }
  return {
    label: level ?? "Custom",
    description: "Custom policy rules apply. Review individual rules below.",
    tone: "slate",
  };
}

export function resolveCloudPolicyBundleCopy(snapshot: {
  cloud_policy_bundle_version?: string | null;
  cloud_policy_rollout_state?: string | null;
  cloud_policy_sync_error?: string | null;
}): {
  label: string;
  detail: string;
  tone: "green" | "attention" | "slate";
} | null {
  const bundleVersion = snapshot.cloud_policy_bundle_version?.trim();
  if (!bundleVersion) {
    return null;
  }
  const rollout = snapshot.cloud_policy_rollout_state?.trim() || "unknown";
  const syncError = snapshot.cloud_policy_sync_error?.trim();
  if (syncError) {
    return {
      label: `Cloud bundle ${bundleVersion}`,
      detail: `Guard Cloud Controls owns rollout and authoring. Latest sync issue: ${syncError}.`,
      tone: "attention",
    };
  }
  return {
    label: `Cloud bundle ${bundleVersion}`,
    detail: `Guard Cloud Controls owns authoring and rollout. This local workspace reflects rollout state ${rollout}.`,
    tone: "green",
  };
}
