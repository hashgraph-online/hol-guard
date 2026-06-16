import type { GuardPolicyDecision } from "./guard-types";
import { harnessDisplayName, policyActionLabel, scopeLabel } from "./approval-center-utils";

const MATCHER_FAMILY_LABELS: Record<string, string> = {
  "package-request": "Package install",
  "tool-action": "Shell or tool command",
  "tool-output": "Command output review",
  prompt: "Prompt submission",
  "prompt-env-read": "Environment variable read",
  mcp: "MCP server call",
  "file-read": "File read",
};

const GENERIC_REASONS = [
  "approved in review",
  "approved in local approval center",
  "local auto-resume proof",
  "local e2e approval proof",
];

const SCANNER_GENERATED_LABEL_MARKERS = [
  "credential-looking",
  "credential looking",
  "secret-looking",
  "suspicious output",
  "looking output",
  "scanner flagged",
];

export function isScannerGeneratedPolicyLabel(value: string | null | undefined): boolean {
  if (!value?.trim()) {
    return true;
  }
  const lowered = value.trim().toLowerCase();
  return SCANNER_GENERATED_LABEL_MARKERS.some((marker) => lowered.includes(marker));
}

export type PolicyDisplay = {
  headline: string;
  kindLine: string | null;
  pathLine: string | null;
  projectLabel: string | null;
  rememberSentence: string;
  technicalId: string | null;
};

export function formatPolicyScopePath(path: string | null | undefined): string | null {
  if (!path?.trim()) {
    return null;
  }
  const value = path.trim();
  if (value.length <= 72) {
    return value;
  }
  const segments = value.split(/[/\\]/).filter(Boolean);
  if (segments.length <= 2) {
    return value;
  }
  return `…/${segments.slice(-2).join("/")}`;
}

export function isCloudManagedPolicy(source: string): boolean {
  return source === "cloud-sync" || source === "team-policy" || source === "policy-bundle";
}

export function resolvePolicySourceLabel(source: string): string {
  if (isCloudManagedPolicy(source)) {
    return "Guard Cloud";
  }
  if (source === "manual" || source === "local") {
    return "Local";
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
    return "prompt review";
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
  if (value.startsWith("/") || value.startsWith("~")) {
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

function resolveRememberSentence(policy: GuardPolicyDecision, commandLabel: string): string {
  const app = harnessDisplayName(policy.harness);
  const folder = policy.workspace_label?.trim() || resolveWorkspaceLabel(policy.workspace);
  const verb = policy.action === "block" ? "block" : "allow";

  if (policy.scope === "artifact") {
    return `Guard will ${verb} "${commandLabel}" the next time ${app} retries this exact action.`;
  }
  if (policy.scope === "workspace") {
    return `Guard will ${verb} "${commandLabel}" every time ${app} runs it in ${folder}.`;
  }
  if (policy.scope === "harness") {
    return `Guard will ${verb} "${commandLabel}" every time ${app} runs a matching action.`;
  }
  if (policy.scope === "publisher") {
    const publisher = policy.publisher?.trim() || "this publisher";
    return `Guard will ${verb} actions from ${publisher} in ${app}.`;
  }
  if (policy.scope === "global") {
    return `Guard will ${verb} matching actions on every project on this device.`;
  }
  return `Guard will ${verb} matching actions when ${scopeLabel(policy.scope).toLowerCase()} rules apply.`;
}

function resolveScopeSubtitle(policy: GuardPolicyDecision): string {
  const app = harnessDisplayName(policy.harness);
  if (policy.scope === "artifact") {
    return `Once in ${app}`;
  }
  if (policy.scope === "workspace") {
    const folder = policy.workspace_label?.trim() || resolveWorkspaceLabel(policy.workspace);
    return `This project · ${folder}`;
  }
  if (policy.scope === "harness") {
    return `Every time in ${app}`;
  }
  if (policy.scope === "publisher") {
    const publisher = policy.publisher?.trim() || "this publisher";
    return `${publisher} in ${app}`;
  }
  if (policy.scope === "global") {
    return "Every project on this device";
  }
  return scopeLabel(policy.scope, "policy");
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
      return `all ${familyPhrase.toLowerCase()}s`;
    }
    if (family === "prompt") {
      const subtype = resolvePromptSubtypeLabel(artifactId);
      return subtype ? `${familyPhrase} (${subtype})` : familyPhrase;
    }
    return familyPhrase.toLowerCase();
  }

  if (publisher) {
    return `actions from ${publisher}`;
  }

  return "matching guarded actions";
}

function resolveKindLine(policy: GuardPolicyDecision): string | null {
  const remembered = policy.remembered_context?.trim();
  if (remembered && !isScannerGeneratedPolicyLabel(remembered)) {
    return remembered;
  }
  const family = policy.artifact_id ? extractMatcherFamily(policy.artifact_id) : null;
  if (family && MATCHER_FAMILY_LABELS[family]) {
    return MATCHER_FAMILY_LABELS[family];
  }
  return resolveScopeSubtitle(policy);
}

function resolvePathLine(policy: GuardPolicyDecision): string | null {
  return formatPolicyScopePath(policy.source_scope_path);
}

function resolveProjectLabel(policy: GuardPolicyDecision): string | null {
  const label = policy.workspace_label?.trim();
  if (label) {
    return label;
  }
  const workspace = policy.workspace?.trim();
  if (!workspace || workspace.startsWith("workspace:")) {
    return null;
  }
  return resolveWorkspaceLabel(workspace);
}

export function resolvePolicyDisplay(policy: GuardPolicyDecision): PolicyDisplay {
  const reason = policy.reason?.trim() ?? null;
  const rememberedCommand = policy.remembered_command?.trim();
  const kindLine = resolveKindLine(policy);
  const pathLine = resolvePathLine(policy);
  const projectLabel = resolveProjectLabel(policy);

  if (rememberedCommand && !isScannerGeneratedPolicyLabel(rememberedCommand)) {
    return {
      headline: rememberedCommand,
      kindLine,
      pathLine,
      projectLabel,
      rememberSentence: resolveRememberSentence(policy, rememberedCommand),
      technicalId: policy.artifact_id,
    };
  }

  const actionVerb = resolveActionVerb(policy.action);

  if (reason && !isGenericReason(reason) && !isScannerGeneratedPolicyLabel(reason)) {
    return {
      headline: reason,
      kindLine,
      pathLine,
      projectLabel,
      rememberSentence: resolveRememberSentence(policy, reason),
      technicalId: policy.artifact_id,
    };
  }

  const what = resolveWhatPhrase(policy);
  const headline = `${actionVerb} ${what}`;
  return {
    headline,
    kindLine,
    pathLine,
    projectLabel,
    rememberSentence: resolveRememberSentence(policy, what),
    technicalId: policy.artifact_id,
  };
}

export function resolvePolicyRowFrequency(policy: GuardPolicyDecision): string {
  return scopeLabel(policy.scope, "policy");
}

export function resolvePolicyRowFolder(policy: GuardPolicyDecision): string | null {
  const pathLine = formatPolicyScopePath(policy.source_scope_path);
  if (pathLine) {
    return pathLine;
  }
  const label = policy.workspace_label?.trim();
  if (label) {
    return label;
  }
  const workspace = policy.workspace?.trim();
  if (!workspace || workspace.startsWith("workspace:")) {
    return null;
  }
  return formatPolicyScopePath(workspace) ?? resolveWorkspaceLabel(workspace);
}

export function resolvePolicyRowSubtitle(policy: GuardPolicyDecision, display: PolicyDisplay): string | null {
  const parts: string[] = [];
  const folder = resolvePolicyRowFolder(policy);
  if (folder) {
    parts.push(folder);
  }
  parts.push(resolvePolicyRowFrequency(policy));
  if (display.kindLine && !parts.includes(display.kindLine)) {
    parts.unshift(display.kindLine);
  }
  return parts.length > 0 ? parts.join(" · ") : null;
}

export function resolvePolicyRowTitle(policy: GuardPolicyDecision, display: PolicyDisplay): string {
  const rememberedCommand = policy.remembered_command?.trim();
  if (rememberedCommand && !isScannerGeneratedPolicyLabel(rememberedCommand)) {
    return rememberedCommand;
  }

  const reason = policy.reason?.trim();
  if (reason && !isGenericReason(reason) && !isScannerGeneratedPolicyLabel(reason)) {
    return reason;
  }

  const artifactId = policy.artifact_id?.trim();
  if (artifactId && !artifactId.startsWith("family:") && !artifactId.includes(":")) {
    const slashIndex = artifactId.lastIndexOf("/");
    const candidate =
      slashIndex >= 0 && slashIndex < artifactId.length - 1
        ? artifactId.slice(slashIndex + 1)
        : artifactId;
    if (candidate.length <= 64 && !isScannerGeneratedPolicyLabel(candidate)) {
      return candidate;
    }
  }

  const headline = display.headline.trim();
  const verb = policyActionLabel(policy.action);
  if (headline.toLowerCase().startsWith(verb.toLowerCase())) {
    return headline.slice(verb.length).trim() || headline;
  }
  return headline;
}

export function resolvePolicyRowSourceLabel(policy: GuardPolicyDecision): string {
  return resolvePolicySourceLabel(policy.source);
}

export type PolicySortKey = "action" | "rule" | "source" | "scope" | "app" | "updated" | "approval";
export type PolicySortState = { key: PolicySortKey; direction: "asc" | "desc" } | null;

export function sortPolicyDecisions(
  policies: GuardPolicyDecision[],
  sort: PolicySortState,
): GuardPolicyDecision[] {
  if (!sort) {
    return policies;
  }
  const direction = sort.direction === "asc" ? 1 : -1;
  const sorted = [...policies];
  sorted.sort((left, right) => {
    const compareText = (a: string, b: string) => direction * a.localeCompare(b, undefined, { sensitivity: "base" });
    switch (sort.key) {
      case "action":
        return compareText(left.action, right.action);
      case "rule": {
        const leftTitle = resolvePolicyRowTitle(left, resolvePolicyDisplay(left));
        const rightTitle = resolvePolicyRowTitle(right, resolvePolicyDisplay(right));
        return compareText(leftTitle, rightTitle);
      }
      case "source":
        return compareText(resolvePolicyRowSourceLabel(left), resolvePolicyRowSourceLabel(right));
      case "scope":
        return compareText(scopeLabel(left.scope, "policy"), scopeLabel(right.scope, "policy"));
      case "app":
        return compareText(harnessDisplayName(left.harness), harnessDisplayName(right.harness));
      case "updated": {
        const leftTime = new Date(left.updated_at || 0).getTime();
        const rightTime = new Date(right.updated_at || 0).getTime();
        return direction * (leftTime - rightTime);
      }
      case "approval":
        return compareText(
          resolvePolicyApprovalRecordLabel(left),
          resolvePolicyApprovalRecordLabel(right),
        );
      default:
        return 0;
    }
  });
  return sorted;
}

export function formatPolicyDateTime(timestamp: string | null | undefined): string | null {
  if (!timestamp?.trim()) {
    return null;
  }
  try {
    return new Intl.DateTimeFormat(undefined, {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "numeric",
      minute: "2-digit",
    }).format(new Date(timestamp));
  } catch {
    return null;
  }
}

export function resolvePolicyEvidenceSearchTerm(policy: GuardPolicyDecision): string | null {
  const receiptId = policy.source_receipt_id?.trim();
  if (receiptId) {
    return receiptId;
  }
  const hash = policy.artifact_hash?.trim();
  if (hash) {
    return hash.replace(/^sha256:/i, "").slice(0, 12);
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
  params.set("view", "actions");
  if (policy.harness?.trim()) {
    params.set("harness", policy.harness.trim());
  }
  const receiptId = policy.source_receipt_id?.trim();
  if (receiptId) {
    params.set("selected", receiptId);
    params.set("search", receiptId);
    return `/evidence?${params.toString()}`;
  }
  const searchTerm = resolvePolicyEvidenceSearchTerm(policy);
  if (searchTerm) {
    params.set("search", searchTerm);
  }
  const query = params.toString();
  return query ? `/evidence?${query}` : "/evidence";
}

export function resolvePolicyApprovalRecordLabel(policy: GuardPolicyDecision): string {
  const receiptId = policy.source_receipt_id?.trim();
  if (receiptId) {
    if (/^receipt[_-]/i.test(receiptId) && receiptId.endsWith(".json")) {
      return receiptId.length <= 28 ? receiptId : `receipt_${receiptId.slice(8, 16)}.json`;
    }
    const normalized = receiptId.replace(/^receipt[-_]?/i, "").replace(/\.json$/i, "");
    const shortId = normalized.length <= 8 ? normalized : normalized.slice(0, 8);
    return `receipt_${shortId}.json`;
  }
  const hash = policy.artifact_hash?.replace(/^sha256:/i, "").slice(0, 8);
  if (hash) {
    return `receipt_${hash}.json`;
  }
  return "View in Evidence";
}

export function resolveCloudPolicyControlsUrl(snapshot: {
  dashboard_url?: string | null;
  connect_url?: string | null;
}): string | null {
  const dashboardUrl = snapshot.dashboard_url?.trim();
  if (dashboardUrl) {
    return dashboardUrl;
  }
  const connectUrl = snapshot.connect_url?.trim();
  return connectUrl && connectUrl.length > 0 ? connectUrl : null;
}

export function resolveCloudBundleSurfaceClass(tone: "green" | "attention" | "slate"): string {
  if (tone === "attention") {
    return "rounded-2xl border border-amber-200/70 bg-amber-50/70 p-4 shadow-sm";
  }
  if (tone === "green") {
    return "rounded-2xl border border-emerald-200/70 bg-emerald-50/70 p-4 shadow-sm";
  }
  return "rounded-2xl border border-slate-200/70 bg-slate-50/70 p-4 shadow-sm";
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
      label: "Protect",
      description:
        "Guard asks before risky actions that are not already allowed by policy, remembered rules, or Cloud exceptions.",
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
  cloud_policy_bundle_hash?: string | null;
  cloud_policy_last_ack_at?: string | null;
}): {
  label: string;
  detail: string;
  hash: string | null;
  tone: "green" | "attention" | "slate";
} | null {
  const bundleVersion = snapshot.cloud_policy_bundle_version?.trim();
  if (!bundleVersion) {
    return null;
  }
  const rollout = snapshot.cloud_policy_rollout_state?.trim() || "unknown";
  const syncError = snapshot.cloud_policy_sync_error?.trim();
  const hash = snapshot.cloud_policy_bundle_hash?.trim() || null;
  if (syncError) {
    return {
      label: "Needs attention",
      detail: `Bundle ${bundleVersion} is connected, but the latest sync reported: ${syncError}`,
      hash,
      tone: "attention",
    };
  }
  return {
    label: "Synced",
    detail: `Bundle ${bundleVersion} is active on this device (${rollout}).`,
    hash,
    tone: "green",
  };
}

export function resolveCloudExceptionsConnected(snapshot: {
  cloud_state?: string | null;
}): boolean {
  return snapshot.cloud_state === "paired_active" || snapshot.cloud_state === "paired_waiting";
}
