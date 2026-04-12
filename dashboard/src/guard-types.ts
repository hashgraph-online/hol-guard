export type DecisionScope = "artifact" | "workspace" | "publisher" | "harness" | "global";

export type GuardApprovalRequest = {
  request_id: string;
  harness: string;
  artifact_id: string;
  artifact_name: string;
  artifact_type: string;
  artifact_hash: string;
  publisher: string | null;
  policy_action: string;
  recommended_scope: DecisionScope;
  risk_headline?: string;
  risk_summary?: string;
  risk_signals?: string[];
  why_now?: string;
  trigger_summary?: string;
  changed_fields: string[];
  source_scope: string;
  config_path: string;
  workspace?: string | null;
  launch_target?: string | null;
  transport: string | null;
  review_command: string;
  approval_url: string;
  status: string;
  resolution_action: string | null;
  resolution_scope: string | null;
  reason: string | null;
  created_at: string;
  resolved_at: string | null;
};

export type GuardReceipt = {
  receipt_id: string;
  harness: string;
  artifact_id: string;
  artifact_hash: string;
  policy_decision: string;
  capabilities_summary: string;
  changed_capabilities: string[];
  provenance_summary: string;
  user_override: string | null;
  artifact_name: string | null;
  source_scope: string | null;
  timestamp: string;
};

export type GuardArtifactDiff = {
  artifact_id: string;
  harness: string;
  changed_fields: string[];
  previous_hash: string | null;
  current_hash: string;
  recorded_at: string;
};

export type GuardPolicyDecision = {
  harness: string;
  scope: DecisionScope;
  artifact_id: string | null;
  workspace: string | null;
  publisher: string | null;
  action: string;
  reason: string | null;
  updated_at: string;
};
