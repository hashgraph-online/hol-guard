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

export type GuardSupplyChainScannerEvidence = {
  operation: string;
  status?: string;
  audit_status?: string;
  audit_decision?: string;
  blocked_package_count?: number;
  total_packages?: number;
  manifest_paths?: string[];
  lockfile_paths?: string[];
  package_inventory?: unknown;
  package_findings?: unknown;
};

export type GuardScannerEvidence = RiskSignalV2 | GuardSupplyChainScannerEvidence;

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
  prompt_text?: string | null;
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
  includeTotals?: boolean;
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

export type PackageManagerProtection = {
  path_status: "in_path" | "restart_required" | "missing_from_path";
  path_contains_shim_dir: boolean;
  restart_shell_required: boolean;
  shell_profile_configured: boolean;
  shell_profile_path: string | null;
  shim_dir: string;
  supported_managers: string[];
  installed_managers: string[];
  active_managers: string[];
  missing_shims: string[];
  protected_managers: string[];
  unprotected_managers: string[];
};

export type SupplyChainBundleAdvisory = {
  advisoryId: string;
  aliases: string[];
  confidence: number;
  exploitLevel: string;
  knownExploited: boolean;
  malwareState: string;
  normalizedSeverity: string;
  recommendedFixVersion: string | null;
  sourceKey: string;
  summary: string;
  title: string;
};

export type SupplyChainBundlePackage = {
  confidence: number;
  defaultAction: string;
  ecosystem: string;
  exploitLevel: string;
  knownExploited: boolean;
  malwareState: string;
  name: string;
  namespace: string | null;
  normalizedSeverity: string;
  packageAgeState: string;
  purl: string;
  reachability: string;
  recommendedFixVersion: string | null;
  relatedAdvisoryIds: string[];
  riskScore: number;
  sourceIntegrityState: string;
  version: string;
};

export type SupplyChainBundle = {
  bundleVersion: string;
  expiresAt: string;
  feedSnapshotHash: string;
  generatedAt: string;
  keyId: string;
  policyHash: string;
  scoringVersion: string;
  advisories: SupplyChainBundleAdvisory[];
  packages: SupplyChainBundlePackage[];
  policyRules: unknown[];
  cached_at?: string;
};

export type SupplyChainSnapshot = {
  package_manager_protection: PackageManagerProtection;
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
  cloud_policy_bundle_hash?: string | null;
  cloud_policy_bundle_version?: string | null;
  cloud_policy_rollout_state?: string | null;
  cloud_policy_sync_error?: string | null;
  cloud_policy_last_ack_at?: string | null;
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
  supply_chain?: SupplyChainSnapshot;
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
  artifact_name?: string | null;
  artifact_type?: string | null;
  source_scope: string | null;
  timestamp: string;
  diff_summary?: string | null;
  scanner_evidence?: GuardScannerEvidence[];
  action_envelope_json?: GuardActionEnvelope | null;
};

export type GuardReceiptAnalyticsBucket = {
  date_key: string;
  label: string;
  allowed: number;
  blocked: number;
  reviewed: number;
};

export type GuardReceiptDailyActivity = {
  date_key: string;
  total: number;
};

export type GuardReceiptHarnessStat = {
  harness: string;
  total: number;
  allowed: number;
  blocked: number;
};

export type GuardReceiptArtifactStat = {
  name: string;
  total: number;
  allowed: number;
  blocked: number;
};

export type GuardReceiptAnalytics = {
  total: number;
  allowed: number;
  blocked: number;
  reviewed: number;
  first_activity_at: string | null;
  last_activity_at: string | null;
  active_day_streak: number;
  peak_day_total: number;
  daily_activity: GuardReceiptDailyActivity[];
  trend_buckets: GuardReceiptAnalyticsBucket[];
  by_harness: GuardReceiptHarnessStat[];
  top_artifacts: GuardReceiptArtifactStat[];
  loaded_sample_limit: number;
};

export type GuardInsightsShareResult = {
  slug: string;
  publicUrl: string;
  ogImageUrl: string;
  expiresAt: string;
};

export type GuardInsightsShareHeatmapCell = {
  date: string;
  level: 0 | 1 | 2 | 3 | 4;
};

export type GuardInsightsShareOverviewStats = {
  pending: number;
  apps: number;
  recorded: number;
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
  decision_id?: number;
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
  source_receipt_id?: string | null;
  remembered_command?: string | null;
  remembered_context?: string | null;
  workspace_label?: string | null;
  source_scope_path?: string | null;
};

export const GUARD_CLOUD_EXCEPTION_ACK_STATUSES = [
  "pending",
  "synced",
  "failed",
  "offline",
] as const;

export type GuardCloudExceptionAckStatus = (typeof GUARD_CLOUD_EXCEPTION_ACK_STATUSES)[number];

export const GUARD_CLOUD_EXCEPTION_EFFECTS = ["allow"] as const;

export type GuardCloudExceptionEffect = (typeof GUARD_CLOUD_EXCEPTION_EFFECTS)[number];

export type GuardCloudExceptionScope = DecisionScope | "global";

export type GuardCloudException = {
  id: string;
  effect: GuardCloudExceptionEffect;
  scope: GuardCloudExceptionScope;
  harness: string | null;
  owner: string;
  approver: string | null;
  expiry: string;
  expires_at?: string;
  artifact_id?: string | null;
  publisher?: string | null;
  source_receipt_id: string | null;
  bundle_hash: string | null;
  ack_status: GuardCloudExceptionAckStatus | null;
  last_used_at: string | null;
  rejection_reason: string | null;
  provenance?: "receipt-sync" | "policy-bundle";
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
  message?: string;
  harness?: string;
  operation?: string;
  confirmation_phrase?: string;
  confirm_command?: string;
  retryable?: boolean;
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

export type GuardApprovalGatePublicConfig = {
  enabled: boolean;
  configured: boolean;
  cooldown_seconds: number;
  cooldown_active: boolean;
  cooldown_expires_at: string | null;
  locked_until: string | null;
  fail_closed: boolean;
  strict_all_decisions: boolean;
  totp_enabled?: boolean;
  totp_pending?: boolean;
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
  approval_gate?: GuardApprovalGatePublicConfig;
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

export const PACKAGE_FIREWALL_ACTION_TYPES = ["install", "repair", "test", "remove"] as const;
export type PackageFirewallActionType = (typeof PACKAGE_FIREWALL_ACTION_TYPES)[number];
export const PACKAGE_FIREWALL_GLOBAL_ACTION_TYPES = ["audit", "sync"] as const;
export type PackageFirewallGlobalActionType = (typeof PACKAGE_FIREWALL_GLOBAL_ACTION_TYPES)[number];

export type PackageFirewallActionState =
  | "available"
  | "connect_required"
  | "paid_required"
  | "reconnect_required"
  | "pending"
  | "disabled";

export type PackageFirewallEntitlement = {
  allowed: boolean;
  reason: string;
  tier: string;
  upgrade_cta: string | null;
  upgrade_url: string | null;
};

export type PackageShimEntry = {
  active: boolean;
  activation_state: "protected" | "restart_required" | "repair_required" | "uninstalled";
  detected: boolean;
  installed: boolean;
  integrity: string;
  last_intercept_proof_at: string | null;
  manager: string;
  path_broken: boolean;
  path_index: number | null;
  path_summary: string | null;
  real_binary_found: boolean;
  real_binary_path: string | null;
  real_binary_path_index: number | null;
  shim_path: string | null;
  tested: boolean;
};

export type PackageFirewallReceipt = {
  id: string;
  operation: string;
  status: string;
  timestamp: string;
};

export type PackageFirewallCliFallback = {
  connect?: string;
  install?: string;
  status?: string;
  remove?: string;
};

export type PackageFirewallConnectFlow = {
  state: "idle" | "running" | "failed";
  title: string;
  detail: string;
  action_label: string;
  connect_url: string;
  authorize_url: string | null;
  browser_opened: boolean | null;
  request_id: string | null;
  poll_after_ms: number | null;
};

export type GuardCloudConnectFlow = PackageFirewallConnectFlow;

export type GuardCloudConnectStatusResponse = {
  connect_required: boolean;
  connect_flow: GuardCloudConnectFlow | null;
};

export type PackageFirewallStatusResponse = {
  operation: string;
  status: string;
  supported_managers: string[];
  detected_managers: string[];
  last_audit_proof_at: string | null;
  audit_workspace_dir?: string | null;
  protection: PackageManagerProtection | null;
  package_shims: PackageShimEntry[];
  entitlement: PackageFirewallEntitlement;
  actions: Partial<Record<PackageFirewallActionType | PackageFirewallGlobalActionType, PackageFirewallActionState>>;
  cli_fallback: PackageFirewallCliFallback | null;
  connect_flow: PackageFirewallConnectFlow | null;
};

export type PackageFirewallActionResponse = {
  operation: string;
  status: string;
  result: string;
  result_detail: Record<string, unknown>;
  receipt: PackageFirewallReceipt | null;
  entitlement: PackageFirewallEntitlement;
};

export type SupplyChainAuditDecision = "allow" | "monitor" | "warn" | "ask" | "block";

export type SupplyChainAuditSeverity = "critical" | "high" | "medium" | "low" | "unknown";

export type SupplyChainAuditFindingReason = {
  code: string;
  message: string;
  severity: SupplyChainAuditSeverity;
};

export type SupplyChainAuditFinding = {
  id: string;
  packageName: string;
  ecosystem: string;
  namespace: string | null;
  decision: SupplyChainAuditDecision;
  severity: SupplyChainAuditSeverity;
  reasons: SupplyChainAuditFindingReason[];
  advisoryAliases: string[];
  status: string | null;
};

export type SupplyChainAuditInventory = {
  totalPackages: number;
  directPackageCount: number;
  transitivePackageCount: number;
  sbomPackageCount: number;
};

export type SupplyChainAuditSnapshot = {
  generatedAt: string;
  source: string | null;
  decision: SupplyChainAuditDecision;
  inventory: SupplyChainAuditInventory;
  packages: SupplyChainAuditFinding[];
  findings: SupplyChainAuditFinding[];
  manifestPaths: string[];
  lockfilePaths: string[];
  receiptId: string | null;
};

export type PackageWorkbenchSortKey = "severity" | "package" | "ecosystem" | "decision";

export type PackageWorkbenchFilters = {
  ecosystem: string;
  decision: SupplyChainAuditDecision | "all";
  severity: SupplyChainAuditSeverity | "all";
  search: string;
};

export type GuardUpdateVersionCheck = {
  source: string;
  status: string;
  current_version: string | null;
  latest_version: string | null;
  update_available: boolean | null;
};

export type GuardUpdateStatus = {
  current_version: string;
  latest_version: string | null;
  installer: string;
  version_check: GuardUpdateVersionCheck;
  auto_updatable: boolean;
  update_available: boolean;
  blocked_reason: string | null;
  recovery_reinstall_available?: boolean;
  recovery_reinstall_command?: string;
  update_in_progress?: boolean;
  update_suppressed?: boolean;
  retry_command?: string;
  update_attempt_message?: string;
};

export type GuardUpdateReconnectOptions = {
  expectedPreviousVersion?: string | null;
  expectedLatestVersion?: string | null;
  sawUpdateInProgress?: boolean;
};

export type GuardUpdateScheduleResult = {
  scheduled: boolean;
  message?: string;
  error?: string;
};

export type GuardUpdatePhase = "idle" | "checking" | "updating" | "reconnecting" | "error";
