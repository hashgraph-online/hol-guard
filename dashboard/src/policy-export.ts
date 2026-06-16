import type { GuardPolicyDecision } from "./guard-types";
import { harnessDisplayName, policyActionLabel, scopeLabel } from "./approval-center-utils";
import { downloadBlob } from "./history-export";
import {
  resolvePolicyApprovalRecordLabel,
  resolvePolicyDisplay,
  resolvePolicyRowSourceLabel,
  resolvePolicyRowTitle,
} from "./policy-workspace-helpers";

function escapeCsvCell(value: string | null | undefined): string {
  const str = value ?? "";
  if (/[",\n]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

function policyExportRow(policy: GuardPolicyDecision): string[] {
  const display = resolvePolicyDisplay(policy);
  return [
    policyActionLabel(policy.action),
    resolvePolicyRowTitle(policy, display),
    display.kindLine ?? "",
    resolvePolicyRowSourceLabel(policy),
    scopeLabel(policy.scope, "policy"),
    harnessDisplayName(policy.harness),
    policy.updated_at ?? "",
    policy.source_receipt_id ?? "",
    resolvePolicyApprovalRecordLabel(policy),
  ];
}

const CSV_HEADERS = [
  "Action",
  "Rule",
  "Kind",
  "Source",
  "Scope",
  "App",
  "Updated",
  "Receipt ID",
  "Approval record",
];

export function exportPoliciesCsv(policies: GuardPolicyDecision[]): { blob: Blob; filename: string } {
  const lines = [
    CSV_HEADERS.map(escapeCsvCell).join(","),
    ...policies.map((policy) => policyExportRow(policy).map(escapeCsvCell).join(",")),
  ];
  const today = new Date().toISOString().slice(0, 10);
  return {
    blob: new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" }),
    filename: `hol-guard-policy-rules-${today}.csv`,
  };
}

export function exportPoliciesJson(policies: GuardPolicyDecision[]): { blob: Blob; filename: string } {
  const payload = policies.map((policy) => {
    const display = resolvePolicyDisplay(policy);
    return {
      action: policy.action,
      rule: resolvePolicyRowTitle(policy, display),
      kind: display.kindLine,
      source: resolvePolicyRowSourceLabel(policy),
      scope: scopeLabel(policy.scope, "policy"),
      app: policy.harness,
      updated_at: policy.updated_at,
      receipt_id: policy.source_receipt_id,
      approval_record: resolvePolicyApprovalRecordLabel(policy),
      artifact_id: policy.artifact_id,
      workspace: policy.workspace,
    };
  });
  const today = new Date().toISOString().slice(0, 10);
  return {
    blob: new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }),
    filename: `hol-guard-policy-rules-${today}.json`,
  };
}

export function downloadPolicies(format: "csv" | "json", policies: GuardPolicyDecision[]): void {
  const result = format === "csv" ? exportPoliciesCsv(policies) : exportPoliciesJson(policies);
  downloadBlob(result.blob, result.filename);
}
