export type DecisionScope = "artifact" | "workspace" | "publisher" | "harness" | "global";
export type GuardHeadlineState =
  | "setup"
  | "protected"
  | "blocked"
  | "local_only"
  | "connected";

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

export type GuardRuntimeState = {
  session_id: string;
  daemon_host: string;
  daemon_port: number;
  started_at: string;
  last_heartbeat_at: string;
  approval_center_url: string;
};

export type GuardRuntimeSnapshot = {
  generated_at: string;
  approval_center_url: string | null;
  runtime_state: GuardRuntimeState | null;
  pending_count: number;
  receipt_count: number;
  headline_state: GuardHeadlineState;
  headline_label: string;
  headline_detail: string;
  sync_configured: boolean;
  cloud_state: "local_only" | "paired_waiting" | "paired_active";
  cloud_state_label: string;
  cloud_state_detail: string;
  dashboard_url: string;
  inbox_url: string;
  fleet_url: string;
  connect_url: string;
  items: GuardApprovalRequest[];
  latest_receipts: GuardReceipt[];
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
