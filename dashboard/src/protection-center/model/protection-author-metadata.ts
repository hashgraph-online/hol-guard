import type { ExtensionCatalogItem } from "../../extension-controls-api";

export type ProtectionPresentationIssue =
  | "missing-name"
  | "missing-description"
  | "missing-action-example"
  | "missing-risk-language"
  | "missing-safer-guidance";

function hasText(values: readonly string[]): boolean {
  return values.some((value) => value.trim().length > 0);
}

export function protectionPresentationIssues(extension: ExtensionCatalogItem): ProtectionPresentationIssue[] {
  const issues: ProtectionPresentationIssue[] = [];
  if (!extension.name.trim()) issues.push("missing-name");
  if (!extension.description.trim()) issues.push("missing-description");
  if (!hasText(extension.executables) && !hasText(extension.ecosystem_ids)) issues.push("missing-action-example");
  if (!hasText(extension.risk_classes) && !hasText(extension.action_classes)) issues.push("missing-risk-language");
  if (!hasText(extension.safer_alternatives)) issues.push("missing-safer-guidance");
  return issues;
}

export function protectionPresentationComplete(extension: ExtensionCatalogItem): boolean {
  return protectionPresentationIssues(extension).length === 0;
}
