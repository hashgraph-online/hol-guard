export type GuardApprovalExtensionRecommendationPermission = {
  permission_id: string;
  label: string;
  description: string | null;
  example_command: string | null;
  extension_id: string;
  extension_name: string;
  rule_id: string | null;
  risk_tier: string | null;
  caution: boolean;
  caution_reason: "critical" | "destructive" | "sensitive" | null;
  caution_detail: string | null;
  cli_command: string;
};

export type GuardApprovalExtensionRecommendation = {
  schema: "guard.approval-extension-recommendation.v1";
  status: "available" | "authority_unavailable";
  permissions: GuardApprovalExtensionRecommendationPermission[];
  caution: boolean;
  revision: number;
  catalog_digest: string;
};
