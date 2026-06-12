import type { GuardPolicyDecision, GuardRuntimeSnapshot } from "./guard-types";

const CLOUD_POLICY_SOURCES = new Set(["cloud-sync", "team-policy", "policy-bundle"]);

export function isCloudManagedPolicy(source: string): boolean {
  return CLOUD_POLICY_SOURCES.has(source);
}

export function policyTargetLabel(policy: GuardPolicyDecision): string {
  return policy.artifact_id ?? policy.publisher ?? policy.workspace ?? "Global";
}

export function resolvePolicyEvidenceSearchTerm(policy: GuardPolicyDecision): string | null {
  if (policy.artifact_hash) {
    const normalized = policy.artifact_hash.replace(/^sha256:/i, "").trim();
    if (normalized.length >= 8) {
      return normalized.slice(0, 12);
    }
  }
  if (policy.artifact_id) {
    if (policy.artifact_id.startsWith("family:")) {
      return policy.artifact_id.slice("family:".length);
    }
    const segments = policy.artifact_id.split(":");
    const tail = segments[segments.length - 1]?.trim() ?? "";
    if (tail.length >= 12) {
      return tail;
    }
    return policy.artifact_id;
  }
  if (policy.publisher) {
    return policy.publisher;
  }
  if (policy.workspace) {
    return policy.workspace;
  }
  return null;
}

export function resolvePolicyEvidenceHref(policy: GuardPolicyDecision): string {
  const params = new URLSearchParams();
  const searchTerm = resolvePolicyEvidenceSearchTerm(policy);
  if (searchTerm) {
    params.set("search", searchTerm);
  }
  if (!searchTerm && policy.harness && policy.harness !== "global") {
    params.set("harness", policy.harness);
  }
  const query = params.toString();
  return query.length > 0 ? `/evidence?${query}` : "/evidence";
}

export function resolveCloudPolicyControlsUrl(snapshot: GuardRuntimeSnapshot): string | null {
  const dashboardUrl = snapshot.dashboard_url?.trim();
  if (dashboardUrl) {
    return dashboardUrl;
  }
  const connectUrl = snapshot.connect_url?.trim();
  return connectUrl && connectUrl.length > 0 ? connectUrl : null;
}

export function resolvePolicyRuleSummary(
  policy: GuardPolicyDecision,
  labels: {
    appName: string;
    scopeLabel: string;
    actionLabel: string;
  },
): string {
  const target = policyTargetLabel(policy);
  const reason = policy.reason?.trim();
  const targetPhrase = target === "Global" ? "all matching actions" : `"${target}"`;

  if (policy.scope === "global") {
    return `${labels.actionLabel} ${targetPhrase} on this device.`;
  }
  if (policy.scope === "harness") {
    return `${labels.actionLabel} ${targetPhrase} anywhere in ${labels.appName}.`;
  }
  if (policy.scope === "workspace") {
    const project = policy.workspace?.trim() || "this project";
    return `${labels.actionLabel} ${targetPhrase} in ${project} (${labels.scopeLabel}).`;
  }
  if (policy.scope === "publisher") {
    const publisher = policy.publisher?.trim() || "this source";
    return `${labels.actionLabel} actions from ${publisher} in ${labels.appName}.`;
  }
  const summary = `${labels.actionLabel} ${targetPhrase} in ${labels.appName} (${labels.scopeLabel}).`;
  if (reason) {
    return `${summary} Reason: ${reason}.`;
  }
  return summary;
}

export function resolvePolicySourceLabel(source: string): string {
  if (source === "cloud-sync" || source === "team-policy" || source === "policy-bundle") {
    return "Guard Cloud";
  }
  if (source === "manual") {
    return "Remembered locally";
  }
  return "Local device";
}
