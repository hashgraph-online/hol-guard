import type { EffectiveExtensionControls } from "../extension-controls-api";
import type { GuardApprovalGatePublicConfig, GuardRuntimeSnapshot } from "../guard-types";

export function effectiveStatusKey(
  effective: EffectiveExtensionControls,
  options: {
    runtime?: GuardRuntimeSnapshot | null;
    approvalGate?: GuardApprovalGatePublicConfig | null;
  } = {},
): string {
  const managed = effective.managed_controls;
  const approvalGate = options.approvalGate;
  return JSON.stringify({
    schema_version: effective.schema_version,
    health: effective.health,
    revision: effective.revision,
    catalog_digest: effective.catalog_digest,
    global_lockdown: effective.global_lockdown,
    cloud_policy_sync_error: options.runtime?.cloud_policy_sync_error ?? null,
    approval_gate: approvalGate
      ? {
        configured: approvalGate.configured,
        enabled: approvalGate.enabled,
        fail_closed: approvalGate.fail_closed,
        strict_all_decisions: approvalGate.strict_all_decisions,
        totp_enabled: approvalGate.totp_enabled ?? false,
        totp_pending: approvalGate.totp_pending ?? false,
      }
      : null,
    failure_codes: effective.failures
      .map((failure) => `${failure.layer_kind ?? ""}:${failure.code}`)
      .sort(),
    managed_controls: managed
      ? {
        control_set_id: managed.control_set_id,
        control_set_name: managed.control_set_name,
        bundle_version: managed.bundle_version,
        workspace_id: managed.workspace_id,
        authority_mode: managed.authority_mode,
        catalog_digest: managed.catalog_digest,
        acknowledgement: {
          extension_authority_revision: managed.acknowledgement.extension_authority_revision,
          policy_revision: managed.acknowledgement.policy_revision,
          effective_projection_digest: managed.acknowledgement.effective_projection_digest,
          status: managed.acknowledgement.status,
        },
      }
      : null,
  });
}
