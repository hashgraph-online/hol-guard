const now = new Date().toISOString();
const recentSyncAt = new Date(Date.now() - 5 * 60 * 1000).toISOString();
const staleSyncAt = new Date(Date.now() - 35 * 60 * 1000).toISOString();

const baseDevice = {
  installation_id: "e2e-test-device",
  device_label: "E2E Test Machine",
  local_registered: true,
};

const baseProofStatus = {
  state: "not_connected" as const,
  label: "Not connected",
  detail: "",
  request_id: null,
  pairing_completed_at: null,
  first_synced_at: null,
  receipts_stored: 0,
  inventory_items: 0,
  runtime_session_id: null,
  runtime_session_synced_at: null,
};

export const freeStateSnapshot = {
  generated_at: now,
  approval_center_url: null,
  runtime_state: null,
  device: baseDevice,
  latest_connect_state: null,
  proof_status: baseProofStatus,
  pending_count: 0,
  receipt_count: 0,
  headline_state: "local_only",
  headline_label: "Local only",
  headline_detail: "Guard is running locally without cloud sync.",
  sync_configured: false,
  cloud_state: "local_only",
  cloud_state_label: "Offline, free",
  cloud_state_detail: "Guard is running locally. Enable cloud sync to unlock live feed.",
  cloud_pairing_state: {
    state: "local_only",
    label: "Not connected",
    detail: "No cloud pairing configured.",
    sync_configured: false,
    dashboard_url: "",
    inbox_url: "",
    fleet_url: "",
    connect_url: "",
  },
  cloud_sync_health: {
    state: "disabled",
    label: "Cloud sync disabled",
    detail: "Cloud sync is turned off.",
    pending_events: 0,
    last_synced_at: null,
    next_retry_after: null,
  },
  dashboard_url: "",
  inbox_url: "",
  fleet_url: "",
  connect_url: "",
  items: [],
  latest_receipts: [],
  managed_installs: [],
  supply_chain: undefined,
};

export const paidStateSnapshot = {
  ...freeStateSnapshot,
  sync_configured: true,
  cloud_state: "paired_active",
  cloud_state_label: "Connected",
  cloud_state_detail: "Guard Cloud is active. All events are syncing.",
  cloud_pairing_state: {
    state: "paired_active",
    label: "Connected",
    detail: "Cloud sync is active and healthy.",
    sync_configured: true,
    dashboard_url: "https://hol.org/guard",
    inbox_url: "https://hol.org/guard/inbox",
    fleet_url: "https://hol.org/guard/protect",
    connect_url: "https://hol.org/guard/connect",
  },
  cloud_sync_health: {
    state: "healthy",
    label: "Cloud sync healthy",
    detail: "All events synced successfully.",
    pending_events: 0,
    last_synced_at: recentSyncAt,
    next_retry_after: null,
  },
  dashboard_url: "https://hol.org/guard",
  inbox_url: "https://hol.org/guard/inbox",
  fleet_url: "https://hol.org/guard/protect",
  connect_url: "https://hol.org/guard/connect",
};

export const degradedStateSnapshot = {
  ...freeStateSnapshot,
  sync_configured: true,
  cloud_state: "paired_waiting",
  cloud_state_label: "Degraded",
  cloud_state_detail: "Cloud sync is experiencing issues. Retrying.",
  cloud_pairing_state: {
    state: "paired_waiting",
    label: "Degraded",
    detail: "Cloud sync is degraded. Events may be delayed.",
    sync_configured: true,
    dashboard_url: "https://hol.org/guard",
    inbox_url: "https://hol.org/guard/inbox",
    fleet_url: "https://hol.org/guard/protect",
    connect_url: "https://hol.org/guard/connect",
  },
  cloud_sync_health: {
    state: "degraded",
    label: "Cloud sync degraded",
    detail: "Sync is experiencing issues. Events may be delayed.",
    pending_events: 7,
    last_synced_at: staleSyncAt,
    next_retry_after: new Date(Date.now() + 3 * 60 * 1000).toISOString(),
  },
  dashboard_url: "https://hol.org/guard",
  inbox_url: "https://hol.org/guard/inbox",
  fleet_url: "https://hol.org/guard/protect",
  connect_url: "https://hol.org/guard/connect",
};

export const emptyReceiptsPayload = { items: [] };
export const emptyPoliciesPayload = { items: [], cloud_exceptions: [] };

export const connectedCloudExceptionsPayload = {
  items: [
    {
      id: "artifact:codex:e2e-active",
      effect: "allow",
      scope: "artifact",
      harness: "codex",
      owner: "owner@example.com",
      approver: "approver@example.com",
      expiry: "2099-01-01T00:00:00+00:00",
      artifact_id: "codex:project:e2e-active",
      source_receipt_id: "receipt-e2e",
      bundle_hash: "sha256:e2e-bundle",
      ack_status: "synced",
      last_used_at: null,
      rejection_reason: null,
    },
  ],
};

export const ackFailureCloudExceptionsPayload = {
  items: [
    {
      id: "artifact:codex:e2e-failed",
      effect: "allow",
      scope: "artifact",
      harness: "codex",
      owner: "owner@example.com",
      approver: "approver@example.com",
      expiry: "2099-01-01T00:00:00+00:00",
      artifact_id: "codex:project:e2e-failed",
      source_receipt_id: "receipt-e2e-failed",
      bundle_hash: "sha256:e2e-bundle-failed",
      ack_status: "failed",
      last_used_at: null,
      rejection_reason: "Bundle signature mismatch",
    },
  ],
};

export const pendingCloudExceptionRequestsPayload = {
  items: [
    {
      requestId: "req-e2e-pending",
      scope: "artifact",
      status: "pending",
      reason: "Temporary allow for e2e",
      owner: "owner@example.com",
      requestedAt: "2026-06-14T12:00:00+00:00",
      requestedExpiresAt: "2099-01-01T00:00:00+00:00",
    },
  ],
};
export const emptyInventoryPayload = { items: [] };

export const defaultSettingsPayload = {
  guard_home: "~/.hol-guard",
  config_path: "~/.hol-guard/config.toml",
  settings: {
    mode: "prompt",
    security_level: "balanced",
    default_action: "warn",
    unknown_publisher_action: "review",
    changed_hash_action: "require-reapproval",
    new_network_domain_action: "warn",
    subprocess_action: "warn",
    risk_actions: {
      local_secret_read: "require-reapproval",
      credential_exfiltration: "require-reapproval",
      data_flow_exfiltration: "require-reapproval",
      destructive_shell: "require-reapproval",
      encoded_execution: "require-reapproval",
      network_egress: "warn",
    },
    risk_action_overrides: {},
    harness_risk_actions: {},
    approval_wait_timeout_seconds: 120,
    approval_surface_policy: "auto-open-once",
    telemetry: false,
    sync: false,
    billing: false,
  },
};
