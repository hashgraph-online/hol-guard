import type {
  GuardApprovalExtensionRecommendation,
  GuardApprovalExtensionRecommendationPermission,
} from "./approval-extension-recommendation-types";

const RECOMMENDATION_SCHEMA = "guard.approval-extension-recommendation.v1";
const MAX_PERMISSIONS = 3;
const CATALOG_ID = /^command\.[A-Za-z0-9._-]{1,248}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const CAUTION_REASONS = new Set(["critical", "destructive", "sensitive"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function boundedText(value: unknown, limit: number): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.replace(/\s+/g, " ").trim();
  return normalized ? normalized.slice(0, limit) : null;
}

function catalogId(value: unknown): string | null {
  return typeof value === "string" && CATALOG_ID.test(value) ? value : null;
}

function normalizePermission(raw: unknown): GuardApprovalExtensionRecommendationPermission | null {
  if (!isRecord(raw)) return null;
  const permissionId = catalogId(raw.permission_id);
  const extensionId = catalogId(raw.extension_id);
  const label = boundedText(raw.label, 120);
  const extensionName = boundedText(raw.extension_name, 120);
  if (permissionId === null || extensionId === null || label === null || extensionName === null) return null;
  if (typeof raw.caution !== "boolean") return null;
  const ruleId = raw.rule_id === null || raw.rule_id === undefined ? null : catalogId(raw.rule_id);
  if (raw.rule_id !== null && raw.rule_id !== undefined && ruleId === null) return null;
  const cautionReason =
    typeof raw.caution_reason === "string" && CAUTION_REASONS.has(raw.caution_reason)
      ? (raw.caution_reason as GuardApprovalExtensionRecommendationPermission["caution_reason"])
      : null;
  return {
    permission_id: permissionId,
    label,
    description: boundedText(raw.description, 240),
    example_command: boundedText(raw.example_command, 160),
    extension_id: extensionId,
    extension_name: extensionName,
    rule_id: ruleId,
    risk_tier: boundedText(raw.risk_tier, 32),
    caution: raw.caution,
    caution_reason: raw.caution ? cautionReason : null,
    caution_detail: raw.caution ? boundedText(raw.caution_detail, 240) : null,
    // The CLI line is rebuilt from the validated id; never echo daemon text into a copyable command.
    cli_command: `hol-guard command controls set ${permissionId} --state allow`,
  };
}

/** Strictly validate the daemon recommendation; any malformed field drops the whole card. */
export function normalizeApprovalExtensionRecommendation(raw: unknown): GuardApprovalExtensionRecommendation | null {
  if (!isRecord(raw) || raw.schema !== RECOMMENDATION_SCHEMA) return null;
  if (raw.status !== "available" && raw.status !== "authority_unavailable") return null;
  if (!Array.isArray(raw.permissions) || raw.permissions.length === 0 || raw.permissions.length > MAX_PERMISSIONS) {
    return null;
  }
  const permissions = raw.permissions.map(normalizePermission);
  if (permissions.some((permission) => permission === null)) return null;
  const valid = permissions as GuardApprovalExtensionRecommendationPermission[];
  if (new Set(valid.map((permission) => permission.permission_id)).size !== valid.length) return null;
  if (typeof raw.revision !== "number" || !Number.isInteger(raw.revision) || raw.revision < 0) return null;
  if (typeof raw.catalog_digest !== "string" || !DIGEST.test(raw.catalog_digest)) return null;
  return {
    schema: RECOMMENDATION_SCHEMA,
    status: raw.status,
    permissions: valid,
    caution: valid.some((permission) => permission.caution),
    revision: raw.revision,
    catalog_digest: raw.catalog_digest,
  };
}

export function recommendationCommandLabel(permission: GuardApprovalExtensionRecommendationPermission): string {
  return permission.example_command ?? permission.label;
}

function joinLabels(labels: readonly string[]): string {
  if (labels.length <= 1) return labels[0] ?? "";
  return `${labels.slice(0, -1).join(", ")} and ${labels[labels.length - 1]}`;
}

function extensionNames(recommendation: GuardApprovalExtensionRecommendation): string {
  return joinLabels([...new Set(recommendation.permissions.map((permission) => permission.extension_name))]);
}

export type ApprovalExtensionRecommendationCopy = {
  commands: string[];
  title: string;
  body: string;
  primaryLabel: string;
  configureLabel: string;
  confirmTitle: string;
  confirmDetail: string;
  cautionLines: string[];
  successMessage: string;
};

const CAUTION_REASON_COPY: Record<NonNullable<GuardApprovalExtensionRecommendationPermission["caution_reason"]>, string> = {
  critical: "is a critical-risk command",
  destructive: "can destroy work or history",
  sensitive: "touches sensitive data or access",
};

export function approvalExtensionRecommendationCopy(
  recommendation: GuardApprovalExtensionRecommendation,
): ApprovalExtensionRecommendationCopy {
  const commands = recommendation.permissions.map(recommendationCommandLabel);
  const commandText = joinLabels(commands);
  const owner = extensionNames(recommendation);
  const cautionLines = recommendation.permissions
    .filter((permission) => permission.caution)
    .map((permission) => {
      const command = recommendationCommandLabel(permission);
      const reason = CAUTION_REASON_COPY[permission.caution_reason ?? "sensitive"];
      return permission.caution_detail ? `${command} ${reason}. ${permission.caution_detail}` : `${command} ${reason}.`;
    });
  const firstExtension = recommendation.permissions[0]?.extension_name ?? owner;
  return {
    commands,
    title: `${owner} covers ${commandText}`,
    body: `${owner} asks before agents run ${commandText}. Allow it in ${owner} and future ${commandText} commands run without asking. Other protections still apply.`,
    primaryLabel: `Approve & always allow ${commandText}`,
    configureLabel: `Configure in ${firstExtension}`,
    confirmTitle: `Always allow ${commandText}?`,
    confirmDetail:
      `This approves this request and changes ${owner} so agents can run ${commandText} without asking. ` +
      "Other protections, secret-file rules, and blocks still apply. You can change this anytime in the extension settings.",
    cautionLines,
    successMessage: `Approved. ${owner} now allows ${commandText} automatically.`,
  };
}
