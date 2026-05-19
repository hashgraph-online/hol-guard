export type DecisionScope = "artifact" | "workspace" | "publisher" | "harness" | "global";

export const GUARD_ACTION_TYPES = [
  "prompt",
  "shell_command",
  "file_read",
  "file_write",
  "mcp_tool",
  "package_script",
  "network_request",
  "config_change",
  "browser_action",
  "harness_start"
] as const;

export type GuardActionType = (typeof GUARD_ACTION_TYPES)[number];

export const GUARD_DECISION_V2_ACTIONS = ["allow", "warn", "ask", "block"] as const;
export const GUARD_DECISION_V2_CONFIDENCES = ["weak", "likely", "strong"] as const;
export const GUARD_RISK_SIGNAL_V2_CATEGORIES = [
  "secret",
  "network",
  "prompt",
  "mcp",
  "skill",
  "supply_chain",
  "encoded",
  "persistence",
  "bypass",
  "false_positive",
  "filesystem",
  "execution",
  "publisher",
  "policy",
  "provenance"
] as const;
export const GUARD_RISK_SIGNAL_V2_SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export const GUARD_RISK_SIGNAL_V2_REDACTION_LEVELS = ["none", "summary", "redacted"] as const;

export type GuardDecisionV2Action = (typeof GUARD_DECISION_V2_ACTIONS)[number];
export type GuardDecisionV2Confidence = (typeof GUARD_DECISION_V2_CONFIDENCES)[number];
export type RiskSignalV2Category = (typeof GUARD_RISK_SIGNAL_V2_CATEGORIES)[number];
export type RiskSignalV2Severity = (typeof GUARD_RISK_SIGNAL_V2_SEVERITIES)[number];
export type RiskSignalV2RedactionLevel = (typeof GUARD_RISK_SIGNAL_V2_REDACTION_LEVELS)[number];

export type RiskSignalV2 = {
  signal_id: string;
  category: RiskSignalV2Category;
  severity: RiskSignalV2Severity;
  confidence: GuardDecisionV2Confidence;
  detector: string;
  title: string;
  plain_reason: string;
  technical_detail: string | null;
  evidence_ref: string | null;
  redaction_level: RiskSignalV2RedactionLevel;
  false_positive_hint: string | null;
  advisory_id: string | null;
};

export type GuardDecisionV2 = {
  action: GuardDecisionV2Action;
  reason: string;
  user_title: string;
  user_body: string;
  harness_message: string;
  dashboard_primary_detail: string;
  approval_scopes: string[];
  retry_instruction: string | null;
  signals: RiskSignalV2[];
  confidence: GuardDecisionV2Confidence;
};

export type GuardActionEnvelope = {
  schema_version: number;
  action_id: string;
  harness: string;
  event_name: string;
  action_type: GuardActionType;
  workspace: string | null;
  workspace_hash: string | null;
  tool_name: string | null;
  command: string | null;
  prompt_excerpt: string | null;
  target_paths: string[];
  network_hosts: string[];
  mcp_server: string | null;
  mcp_tool: string | null;
  package_manager: string | null;
  package_name: string | null;
  script_name: string | null;
  raw_payload_redacted: Record<string, unknown>;
};

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
  launch_summary?: string;
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
  action_envelope_json?: GuardActionEnvelope | null;
  decision_v2_json?: GuardDecisionV2 | null;
  action_identity?: string | null;
  queue_group_id?: string | null;
  dedupe_count?: number;
  last_seen_at?: string | null;
  display_status?: string;
};

export type GuardApprovalPageStatus = "pending" | "resolved" | "all";

export type GuardApprovalPageFilters = {
  status?: GuardApprovalPageStatus;
  harness?: string;
  search?: string;
  cursor?: string;
  limit?: number;
};

export type GuardApprovalPage = {
  items: GuardApprovalRequest[];
  next_cursor: string | null;
  total_pending_count: number;
  total_count: number;
  status: GuardApprovalPageStatus;
};

export type GuardQueueSummary = {
  active_request_id: string | null;
  next_request_id: string | null;
  remaining_pending_count: number;
  next_selectable_request_id: string | null;
};

export type GuardQueueResolutionCopy = {
  title: string;
  body: string;
};

export const CODEX_RESUME_STATUSES = ["pending", "in_progress", "sent", "already_sent", "failed", "skipped"] as const;
export type CodexResumeStatus = (typeof CODEX_RESUME_STATUSES)[number];

export type GuardCodexResumeResult = {
  request_id: string | null;
  operation_id: string | null;
  harness: string | null;
  resolution_action: string | null;
  strategy: string | null;
  supported: boolean;
  status: CodexResumeStatus;
  thread_id: string | null;
  reason: string | null;
  message: string | null;
  last_error: string | null;
  attempt_count: number;
  created_at: string | null;
  updated_at: string | null;
  last_attempt_at: string | null;
  sent_at: string | null;
};

export type GuardQueueResolutionResult = {
  resolved: boolean;
  item: GuardApprovalRequest | null;
  resolved_request: GuardApprovalRequest | null;
  remaining_pending_count: number;
  next_selectable_request_id: string | null;
  remaining_pending_summaries: GuardApprovalRequest[];
  resolved_duplicate_ids: string[];
  resolved_scope_ids?: string[];
  resolution_summary: string;
  retry_hint: string | null;
  copy: GuardQueueResolutionCopy | null;
  codex_resume?: GuardCodexResumeResult | null;
};

export type GuardRuntimeState = {
  session_id: string;
  daemon_host: string;
  daemon_port: number;
  started_at: string;
  last_heartbeat_at: string;
  approval_center_url: string;
};

export type GuardCloudPairingState = {
  state: "local_only" | "paired_waiting" | "paired_active";
  label: string;
  detail: string;
  sync_configured: boolean;
  dashboard_url: string;
  inbox_url: string;
  fleet_url: string;
  connect_url: string;
};

export type GuardCloudSyncHealth = {
  state: "healthy" | "pending" | "failed" | "degraded" | "disabled" | "stale";
  label: string;
  detail: string;
  pending_events: number;
  last_synced_at: string | null;
  next_retry_after: string | null;
};

export type GuardRuntimeDevice = {
  installation_id: string;
  device_label: string;
  local_registered: boolean;
};

export type GuardConnectProof = {
  pairing_completed_at: string | null;
  first_synced_at: string | null;
  receipts_stored: number;
  inventory_items: number;
  runtime_session_id: string | null;
  runtime_session_synced_at: string | null;
};

export type GuardLatestConnectState = {
  request_id: string | null;
  status: string | null;
  milestone: string | null;
  reason: string | null;
  created_at: string | null;
  updated_at: string | null;
  expires_at: string | null;
  completed_at: string | null;
  proof: GuardConnectProof;
};

export type GuardProofStatus = GuardConnectProof & {
  state:
    | "not_connected"
    | "waiting"
    | "pending"
    | "synced"
    | "failed"
    | "expired"
    | "sync_unavailable";
  label: string;
  detail: string;
  request_id: string | null;
};

export type GuardRuntimeSnapshot = {
  generated_at: string;
  approval_center_url: string | null;
  runtime_state: GuardRuntimeState | null;
  device: GuardRuntimeDevice;
  latest_connect_state: GuardLatestConnectState | null;
  proof_status: GuardProofStatus;
  pending_count: number;
  receipt_count: number;
  headline_state: GuardHeadlineState;
  headline_label: string;
  headline_detail: string;
  thread_count?: number;
  sync_configured: boolean;
  cloud_state: "local_only" | "paired_waiting" | "paired_active";
  cloud_state_label: string;
  cloud_state_detail: string;
  cloud_pairing_state: GuardCloudPairingState;
  cloud_sync_health: GuardCloudSyncHealth;
  dashboard_url: string;
  inbox_url: string;
  fleet_url: string;
  connect_url: string;
  items: GuardApprovalRequest[];
  queue_summary?: GuardQueueSummary;
  latest_receipts: GuardReceipt[];
  managed_installs?: GuardManagedInstall[];
  inventory?: GuardInventoryItem[];
  security_level?: "balanced" | "strict" | "custom";
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
  artifact_hash?: string | null;
  workspace: string | null;
  publisher: string | null;
  action: string;
  reason: string | null;
  source: string;
  updated_at: string;
};

export type GuardManagedInstall = {
  harness: string;
  active: boolean;
  workspace: string | null;
  manifest: Record<string, unknown>;
  updated_at: string;
};

export type GuardHarnessAction = "install" | "verify" | "repair" | "uninstall";

export type GuardHarnessSetupStep = {
  step_id: string;
  title: string;
  body: string;
  command: string[];
  writes_config: boolean;
  requires_confirmation: boolean;
};

export type GuardHarnessCoverage = {
  native_hooks: boolean;
  browser_fallback: boolean;
  mcp_proxy: boolean;
  prompt_hooks: boolean;
  blind_spots: string[];
};

export type GuardHarnessSetupContract = {
  harness: string;
  display_name: string;
  install_aliases: string[];
  setup_steps: GuardHarnessSetupStep[];
  verify_steps: GuardHarnessSetupStep[];
  repair_steps: GuardHarnessSetupStep[];
  coverage: GuardHarnessCoverage;
};

export type GuardHarnessVerification = {
  checked: boolean;
  writes_config: boolean;
  installed: boolean;
  command_available: boolean;
  config_paths: string[];
  artifact_count: number;
  warnings: string[];
  steps: GuardHarnessSetupStep[];
};

export type GuardHarnessActionResult = {
  harness: string;
  action?: GuardHarnessAction;
  dry_run?: boolean;
  safe?: boolean;
  contract?: GuardHarnessSetupContract;
  steps?: GuardHarnessSetupStep[];
  workspace?: string | null;
  verification?: GuardHarnessVerification;
  managed_install?: GuardManagedInstall;
  managed_installs?: GuardManagedInstall[];
  auto_detected?: boolean;
  confirmation_phrase?: string;
  confirm_command?: string;
};

export type GuardHarnessActionErrorPayload = {
  error: string;
  harness?: string;
  confirmation_phrase?: string;
  confirm_command?: string;
};

export type GuardInventoryItem = {
  artifact_id: string;
  harness: string;
  artifact_name: string;
  artifact_type: string;
  source_scope: string;
  config_path: string;
  publisher: string | null;
  origin_url: string | null;
  launch_command: string | null;
  transport: string | null;
  first_seen_at: string;
  last_seen_at: string;
  last_changed_at: string | null;
  last_approved_at: string | null;
  removed_at: string | null;
  present: boolean;
  last_policy_action: string;
  artifact_hash: string;
};

export type GuardSettings = {
  mode: "observe" | "prompt" | "enforce";
  security_level: "relaxed" | "gentle" | "balanced" | "strict" | "custom";
  default_action: string;
  unknown_publisher_action: string;
  changed_hash_action: string;
  new_network_domain_action: string;
  subprocess_action: string;
  risk_actions: Record<string, string>;
  risk_action_overrides: Record<string, string>;
  harness_risk_actions: Record<string, Record<string, string>>;
  approval_wait_timeout_seconds: number;
  approval_surface_policy: string;
  telemetry: boolean;
  sync: boolean;
  billing: boolean;
};

export type GuardSettingsPayload = {
  guard_home: string;
  config_path: string;
  settings: GuardSettings;
};

export type GuardNotificationSetupResult = {
  platform: string;
  supported: boolean;
  preview_sent: boolean;
  settings_opened: boolean;
  settings_url: string | null;
  already_prompted: boolean;
  notifier_path: string | null;
  guidance: string | null;
};

export type GuardSettingsExport = {
  schema_version: 1;
  privacy_warning: string;
  settings: GuardSettings;
};
