"""Guard dependencies reexported by the daemon namespace."""

from __future__ import annotations

from ..adapters import get_adapter
from ..adapters.base import HarnessContext
from ..aibom_cli import _AIBOM_AUTO_SYNC_INTERVAL_SECONDS, sync_aibom_snapshots_if_due
from ..approval_gate import (
    ApprovalGateError,
    begin_totp_enrollment,
    confirm_totp_enrollment,
    disable_totp,
    require_high_risk,
)
from ..approval_gate import input_from_mapping as approval_gate_input_from_mapping
from ..approval_gate import public_config as approval_gate_public_config
from ..approval_gate import (
    revoke_cooldown as revoke_approval_gate_cooldown,
)
from ..approval_gate import (
    update_settings as update_approval_gate_settings,
)
from ..approval_gate import (
    validate_settings_update as validate_approval_gate_settings,
)
from ..approval_scope_support import (
    APPROVAL_SCOPE_CONTRACT_VERSION_PREFIX,
    IneligibleApprovalScopeError,
    StaleApprovalScopeContractError,
    request_scope_contract_payload,
    resolve_request_scope_selection,
)
from ..approvals import (
    ApprovalRequestAlreadyResolvedError,
    ApprovalRequestNotFoundError,
    apply_approval_resolution,
    build_approval_browser_url,
    build_runtime_snapshot,
    bulk_allow_read_only_once,
)
from ..browser_opener import open_browser_url
from ..cli.connect_flow import (
    CONNECT_SYNC_AUTH_CONTEXT_KEY,
    _build_sync_auth_context,
    _persist_oauth_local_credentials,
    exchange_guard_authorization_code,
    resolve_connect_url,
    resolve_guard_oauth_client_config,
    start_guard_browser_session,
)
from ..cli.connect_sync_result import (
    apply_guard_connect_sync_result,
    failed_browser_connect_flow_state,
    headless_sync_retry_summary,
)
from ..cli.install_commands import (
    apply_managed_install,
    build_harness_setup_plan,
    build_harness_verification,
    list_harness_setup_items,
    uninstall_confirmation_token,
)
from ..cli.update_commands import build_guard_update_status_payload
from ..cloud_exception_requests import (
    CloudExceptionRequestError,
    fetch_cloud_exception_requests,
    submit_cloud_exception_request,
)
from ..codex_live_decision import complete_codex_live_decision, resolve_codex_live_allow_authority
from ..codex_live_decision_revalidation import revalidate_codex_live_allow
from ..codex_resume import get_request_resume_status, retry_request_resume
from ..config import (
    VALID_RECEIPT_REDACTION_LEVELS,
    GuardConfig,
    editable_guard_settings,
    load_guard_config,
    reset_guard_settings,
    update_guard_settings,
    update_guard_update_channel,
)
from ..desktop_notifications import (
    desktop_notification_setup_payload,
    ensure_desktop_notification_setup,
    macos_notification_guidance,
)
from ..harness_disconnect_gate import require_harness_disconnect_gate
from ..insights_share import publish_insights_share
from ..json_transport import escape_json_for_html
from ..local_dashboard_session import (
    DEFAULT_LOCAL_DASHBOARD_SESSION_TTL_SECONDS,
    LOCAL_DASHBOARD_SESSION_AUDIENCE,
    LOCAL_DASHBOARD_SESSION_STARTED_AT_CLAIM,
    MAX_LOCAL_DASHBOARD_SESSION_AGE_SECONDS,
    build_local_dashboard_session_token,
)
from ..local_supply_chain import (
    build_workspace_audit_payload,
    managed_install_audit_workspace_dirs,
    resolve_package_firewall_entitlement_with_refresh,
    resolve_supply_chain_audit_workspace_dir,
    sync_supply_chain_cloud_state,
)
from ..managed_controls_policy_fields import ParsedManagedControlsPolicy
from ..models import DECISION_SCOPE_VALUES, DecisionScope, PolicyDecision, format_local_http_origin
from ..native_mode import native_mode_requires_rust as _native_mode_requires_rust
from ..native_mode import python_oracle_surface_enabled
from ..package_firewall_action_rate_limit import PackageFirewallActionRateLimiter
from ..package_firewall_entitlement import (
    package_firewall_action_states,
    package_firewall_available_actions,
    package_firewall_block_details,
    package_firewall_operation_allowed,
    reconcile_connect_state_with_oauth_entitlement,
    resolve_package_firewall_entitlement,
)
from ..package_firewall_receipts import package_firewall_receipt_metadata
from ..package_shim_status import record_package_shim_audit_result
from ..policy_bundle_activation import activate_with_reason
from ..policy_bundle_delivery import policy_bundle_acknowledgement_payload
from ..policy_bundle_parser import policy_bundle_is_enforceable, policy_bundle_rejection_message
from ..policy_bundle_trusted_keys import (
    MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY,
    policy_bundle_keyring_payload,
    validate_synced_policy_bundle,
)
from ..policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT
from ..protection_posture import protection_is_off
from ..receipts.manager import build_receipt
from ..runtime.approval_attention import ApprovalAttentionCoordinator
from ..runtime.cloud_review_sync import CloudReviewSyncWorker, start_cloud_sync_sync_worker, stop_cloud_sync_sync_worker

__all__ = [
    "APPROVAL_SCOPE_CONTRACT_VERSION_PREFIX",
    "CONNECT_SYNC_AUTH_CONTEXT_KEY",
    "DECISION_SCOPE_VALUES",
    "DEFAULT_LOCAL_DASHBOARD_SESSION_TTL_SECONDS",
    "LOCAL_DASHBOARD_SESSION_AUDIENCE",
    "LOCAL_DASHBOARD_SESSION_STARTED_AT_CLAIM",
    "MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY",
    "MAX_LOCAL_DASHBOARD_SESSION_AGE_SECONDS",
    "POLICY_BUNDLE_V2_CONTRACT",
    "VALID_RECEIPT_REDACTION_LEVELS",
    "_AIBOM_AUTO_SYNC_INTERVAL_SECONDS",
    "ApprovalAttentionCoordinator",
    "ApprovalGateError",
    "ApprovalRequestAlreadyResolvedError",
    "ApprovalRequestNotFoundError",
    "CloudExceptionRequestError",
    "CloudReviewSyncWorker",
    "DecisionScope",
    "GuardConfig",
    "HarnessContext",
    "IneligibleApprovalScopeError",
    "PackageFirewallActionRateLimiter",
    "ParsedManagedControlsPolicy",
    "PolicyDecision",
    "StaleApprovalScopeContractError",
    "_build_sync_auth_context",
    "_native_mode_requires_rust",
    "_persist_oauth_local_credentials",
    "activate_with_reason",
    "apply_approval_resolution",
    "apply_guard_connect_sync_result",
    "apply_managed_install",
    "approval_gate_input_from_mapping",
    "approval_gate_public_config",
    "begin_totp_enrollment",
    "build_approval_browser_url",
    "build_guard_update_status_payload",
    "build_harness_setup_plan",
    "build_harness_verification",
    "build_local_dashboard_session_token",
    "build_receipt",
    "build_runtime_snapshot",
    "build_workspace_audit_payload",
    "bulk_allow_read_only_once",
    "complete_codex_live_decision",
    "confirm_totp_enrollment",
    "desktop_notification_setup_payload",
    "disable_totp",
    "editable_guard_settings",
    "ensure_desktop_notification_setup",
    "escape_json_for_html",
    "exchange_guard_authorization_code",
    "failed_browser_connect_flow_state",
    "fetch_cloud_exception_requests",
    "format_local_http_origin",
    "get_adapter",
    "get_request_resume_status",
    "headless_sync_retry_summary",
    "list_harness_setup_items",
    "load_guard_config",
    "macos_notification_guidance",
    "managed_install_audit_workspace_dirs",
    "open_browser_url",
    "package_firewall_action_states",
    "package_firewall_available_actions",
    "package_firewall_block_details",
    "package_firewall_operation_allowed",
    "package_firewall_receipt_metadata",
    "policy_bundle_acknowledgement_payload",
    "policy_bundle_is_enforceable",
    "policy_bundle_keyring_payload",
    "policy_bundle_rejection_message",
    "protection_is_off",
    "publish_insights_share",
    "python_oracle_surface_enabled",
    "reconcile_connect_state_with_oauth_entitlement",
    "record_package_shim_audit_result",
    "request_scope_contract_payload",
    "require_harness_disconnect_gate",
    "require_high_risk",
    "reset_guard_settings",
    "resolve_codex_live_allow_authority",
    "resolve_connect_url",
    "resolve_guard_oauth_client_config",
    "resolve_package_firewall_entitlement",
    "resolve_package_firewall_entitlement_with_refresh",
    "resolve_request_scope_selection",
    "resolve_supply_chain_audit_workspace_dir",
    "retry_request_resume",
    "revalidate_codex_live_allow",
    "revoke_approval_gate_cooldown",
    "start_cloud_sync_sync_worker",
    "start_guard_browser_session",
    "stop_cloud_sync_sync_worker",
    "submit_cloud_exception_request",
    "sync_aibom_snapshots_if_due",
    "sync_supply_chain_cloud_state",
    "uninstall_confirmation_token",
    "update_approval_gate_settings",
    "update_guard_settings",
    "update_guard_update_channel",
    "validate_approval_gate_settings",
    "validate_synced_policy_bundle",
]
