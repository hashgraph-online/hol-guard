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

export type GuardSurfaceClientAttachment = {
  client_id: string;
  surface: string;
  session_id: string | null;
  metadata: Record<string, unknown>;
  lease_id: string;
  lease_expires_at: string | null;
  attached_at: string;
  last_seen_at: string;
};

export type GuardSession = {
  session_id: string;
  harness: string;
  surface: string;
  status: string;
  client_name: string;
  client_title: string | null;
  client_version: string | null;
  workspace: string | null;
  capabilities: string[];
  created_at: string;
  updated_at: string;
};

export type GuardOperation = {
  operation_id: string;
  session_id: string;
  harness: string;
  operation_type: string;
  status: string;
  approval_request_ids: string[];
  resume_token: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type GuardSessionResume = {
  session: GuardSession;
  attachments: GuardSurfaceClientAttachment[];
  operations: GuardOperation[];
};

export type GuardRuntimeSummary = {
  session: GuardSession | null;
  attachments: GuardSurfaceClientAttachment[];
  operations: GuardOperation[];
  activeOperation: GuardOperation | null;
};

export type GuardConnectState = {
  request_id: string;
  sync_url: string;
  allowed_origin: string;
  status: string;
  milestone: string;
  reason: string | null;
  created_at: string;
  updated_at: string;
  expires_at: string;
  completed_at: string | null;
  proof: Record<string, unknown>;
  version: string;
  poll_after_ms: number;
};

export type GuardLocalStateSummary = {
  headline_state: string;
  pending_approvals: number;
  receipt_count: number;
  sync_configured: boolean;
  latest_sync: Record<string, unknown> | null;
  latest_connect_state: GuardConnectState | null;
  runtime: {
    sessions: number;
    operations: number;
    latest_session: GuardSession | null;
    latest_operation: GuardOperation | null;
  };
  portal_links: Record<string, string>;
  guidance: {
    title: string;
    body: string;
    command: string | null;
    primary_link: string | null;
  };
  updated_at: string;
};
