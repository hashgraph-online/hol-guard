import type { GuardApprovalGatePublicConfig } from "./guard-types";

export type CloudReviewSettingsStatus = {
  enabled: boolean;
  connected: boolean;
  reason: string | null;
  expires_at: string | null;
  workspace_id: string | null;
  source: string | null;
  pending_uploads: number;
  held_events: number;
  isolated_events: number;
  last_synced_at: string | null;
  delivery_state: string;
  approval_gate: GuardApprovalGatePublicConfig;
  activation_error?: string | null;
};

export type CloudReviewSettingsChange = {
  action: "enable" | "disable";
  workspace_id: string | null;
  source: string | null;
  include_held_requests: boolean;
  renew_consent?: boolean;
};
