"""_GuardDaemonHandler ownership and method bindings."""

from __future__ import annotations

from . import server as _server
from . import server_handler_approvals as _handler_approvals
from . import server_handler_authorization as _handler_authorization
from . import server_handler_connect as _handler_connect
from . import server_handler_get as _handler_get
from . import server_handler_headless as _handler_headless
from . import server_handler_health as _handler_health
from . import server_handler_hook_admission as _handler_hook_admission
from . import server_handler_hook_execution as _handler_hook_execution
from . import server_handler_mcp_policy as _handler_mcp_policy
from . import server_handler_policy as _handler_policy
from . import server_handler_post as _handler_post
from . import server_handler_reconnect as _handler_reconnect
from . import server_handler_request_state as _handler_request_state
from . import server_handler_requests as _handler_requests
from . import server_handler_responses as _handler_responses
from . import server_handler_sessions as _handler_sessions
from . import server_handler_settings as _handler_settings
from . import server_handler_supply_chain as _handler_supply_chain
from . import server_handler_updates as _handler_updates
from . import server_handler_validation as _handler_validation
from .server_dependencies_base import BaseHTTPRequestHandler


class _GuardDaemonHandler(BaseHTTPRequestHandler):
    _MAX_BODY_BYTES = 1_000_000
    server: _server._GuardDaemonHttpServer  # pyright: ignore[reportIncompatibleVariableOverride]

    def parse_request(self) -> bool:
        parsed = super().parse_request()
        self._daemon_server().classify_connection(self.request)
        if not parsed:
            return False
        if self._daemon_server().claim_request_capacity(self.request, self.path):
            return True
        self.send_error(503, "Guard daemon request capacity reached")
        return False

    do_OPTIONS = _handler_requests.do_OPTIONS  # noqa: N815 - HTTP dispatch contract
    do_GET = _handler_get.do_GET  # noqa: N815 - HTTP dispatch contract
    do_DELETE = _handler_requests.do_DELETE  # noqa: N815 - HTTP dispatch contract
    do_POST = _handler_post.do_POST  # noqa: N815 - HTTP dispatch contract
    log_message = _handler_requests.log_message
    _local_queue_url = _handler_requests._local_queue_url
    _load_request_body = _handler_requests._load_request_body
    _read_request_body = _handler_requests._read_request_body
    _handle_capabilities = _handler_headless._handle_capabilities
    _latest_cloud_sync_snapshot = _handler_headless._latest_cloud_sync_snapshot
    _headless_reconnect_payload = _handler_headless._headless_reconnect_payload
    _headless_app_action_payload = _handler_headless._headless_app_action_payload
    _handle_cloud_app_handoff = _handler_headless._handle_cloud_app_handoff
    _handle_headless_app_action = _handler_headless._handle_headless_app_action
    _run_headless_managed_action = _handler_headless._run_headless_managed_action
    _handle_headless_policy_sync = _handler_headless._handle_headless_policy_sync
    _handle_audit_remediation = _handler_supply_chain._handle_audit_remediation
    _handle_supply_chain_package_firewall_status = _handler_supply_chain._handle_supply_chain_package_firewall_status
    _handle_supply_chain_repair = _handler_supply_chain._handle_supply_chain_repair
    _handle_supply_chain_package_firewall_action = _handler_supply_chain._handle_supply_chain_package_firewall_action
    _run_supply_chain_package_action = _handler_supply_chain._run_supply_chain_package_action
    _resolve_supply_chain_workspace_dir = _handler_supply_chain._resolve_supply_chain_workspace_dir
    _supply_chain_context = _handler_supply_chain._supply_chain_context
    _supply_chain_managers = staticmethod(_handler_supply_chain._supply_chain_managers)
    _supply_chain_entitlement = _handler_supply_chain._supply_chain_entitlement
    _handle_get_supply_chain_bundle = _handler_supply_chain._handle_get_supply_chain_bundle
    _supply_chain_connect_flow = _handler_supply_chain._supply_chain_connect_flow
    _handle_supply_chain_package_firewall_connect = _handler_connect._handle_supply_chain_package_firewall_connect
    _handle_guard_cloud_connect_status = _handler_connect._handle_guard_cloud_connect_status
    _handle_guard_cloud_connect_start = _handler_connect._handle_guard_cloud_connect_start
    _policy_memory_payload = staticmethod(_handler_approvals._policy_memory_payload)
    _record_headless_receipt = _handler_approvals._record_headless_receipt
    _cursor_headless_surface = _handler_approvals._cursor_headless_surface
    _cursor_receipt_context = _handler_approvals._cursor_receipt_context
    _handle_policy_clear = _handler_approvals._handle_policy_clear
    _handle_requests_clear = _handler_approvals._handle_requests_clear
    _handle_bulk_allow_read_once = _handler_approvals._handle_bulk_allow_read_once
    _harness_context = _handler_approvals._harness_context
    _handle_harness_action = _handler_approvals._handle_harness_action
    _handle_notification_setup = _handler_approvals._handle_notification_setup
    _handle_requests_list = _handler_request_state._handle_requests_list
    _optional_bool = staticmethod(_handler_request_state._optional_bool)
    _approval_persist_policy = _handler_request_state._approval_persist_policy
    _write_stale_approval_scope_error = _handler_request_state._write_stale_approval_scope_error
    _write_ineligible_approval_scope_error = _handler_request_state._write_ineligible_approval_scope_error
    _write_approval_gate_error = _handler_request_state._write_approval_gate_error
    _handle_insights_share_publish = _handler_request_state._handle_insights_share_publish
    _handle_cloud_exception_request_list = _handler_request_state._handle_cloud_exception_request_list
    _handle_cloud_exception_request_create = _handler_request_state._handle_cloud_exception_request_create
    _handle_read_state_update = _handler_request_state._handle_read_state_update
    _read_delete_body = _handler_request_state._read_delete_body
    _handle_protection_repair = _handler_settings._handle_protection_repair
    _handle_settings_update = _handler_settings._handle_settings_update
    _apply_settings_payload = _handler_settings._apply_settings_payload
    _handle_update_channel = _handler_settings._handle_update_channel
    _handle_settings_import = _handler_settings._handle_settings_import
    _handle_settings_reset = _handler_settings._handle_settings_reset
    _handle_approval_gate_cooldown_revoke = _handler_settings._handle_approval_gate_cooldown_revoke
    _handle_approval_gate_totp_enroll = _handler_settings._handle_approval_gate_totp_enroll
    _handle_approval_gate_totp_verify = _handler_settings._handle_approval_gate_totp_verify
    _handle_approval_gate_totp_disable = _handler_settings._handle_approval_gate_totp_disable
    _handle_mcp_policy_request_get = _handler_mcp_policy._handle_mcp_policy_request_get
    _handle_mcp_policy_decision = _handler_mcp_policy._handle_mcp_policy_decision
    _handle_initialize = _handler_sessions._handle_initialize
    _handle_client_attach = _handler_sessions._handle_client_attach
    _handle_client_heartbeat = _handler_sessions._handle_client_heartbeat
    _handle_session_start = _handler_sessions._handle_session_start
    _handle_operation_start = _handler_sessions._handle_operation_start
    _handle_operation_block = _handler_sessions._handle_operation_block
    _handle_operation_item = _handler_sessions._handle_operation_item
    _handle_operation_status = _handler_sessions._handle_operation_status
    _handle_session_resume = _handler_sessions._handle_session_resume
    _handle_request_resume_read = _handler_sessions._handle_request_resume_read
    _handle_request_resume_retry = _handler_sessions._handle_request_resume_retry
    _handle_dashboard_update = _handler_updates._handle_dashboard_update
    _handle_codex_live_decision = _handler_updates._handle_codex_live_decision
    _revalidate_codex_live_allow = _handler_updates._revalidate_codex_live_allow
    _handle_cloud_review_settings = _handler_updates._handle_cloud_review_settings
    _handle_command_queue_worker_refresh = _handler_updates._handle_command_queue_worker_refresh
    _write_legacy_pairing_disabled = _handler_updates._write_legacy_pairing_disabled
    _write_legacy_cloud_handoff_disabled = _handler_updates._write_legacy_cloud_handoff_disabled
    _handle_runtime_hook = _handler_hook_admission._handle_runtime_hook
    _runtime_hook_lane = staticmethod(_handler_hook_admission._runtime_hook_lane)
    _runtime_hook_client_key = staticmethod(_handler_hook_admission._runtime_hook_client_key)
    _runtime_hook_payload_size = staticmethod(_handler_hook_admission._runtime_hook_payload_size)
    _record_hook_capacity_rejection = staticmethod(_handler_hook_admission._record_hook_capacity_rejection)
    _runtime_hook_capacity_response = _handler_hook_admission._runtime_hook_capacity_response
    _runtime_hook_fail_safe_response = _handler_hook_admission._runtime_hook_fail_safe_response
    _validated_fail_safe_hook_paths = _handler_hook_admission._validated_fail_safe_hook_paths
    _validated_fail_safe_directory = _handler_hook_admission._validated_fail_safe_directory
    _execute_runtime_hook = _handler_hook_execution._execute_runtime_hook
    _hook_fast_path_enabled = _handler_hook_execution._hook_fast_path_enabled
    _handle_runtime_hook_fast = _handler_hook_execution._handle_runtime_hook_fast
    _handle_runtime_hook_compatibility_cli = _handler_hook_execution._handle_runtime_hook_compatibility_cli
    _query_has_guard_token = _handler_reconnect._query_has_guard_token
    _handle_dashboard_reconnect_prepare = _handler_reconnect._handle_dashboard_reconnect_prepare
    _handle_dashboard_reconnect_challenge = _handler_reconnect._handle_dashboard_reconnect_challenge
    _handle_dashboard_reconnect_verify = _handler_reconnect._handle_dashboard_reconnect_verify
    _write_dashboard_reconnect_candidate_failure = _handler_reconnect._write_dashboard_reconnect_candidate_failure
    _current_authenticated_daemon_state = _handler_reconnect._current_authenticated_daemon_state
    _dashboard_reconnect_daemon_origin = _handler_reconnect._dashboard_reconnect_daemon_origin
    _strict_loopback_origin = classmethod(_handler_reconnect._strict_loopback_origin)
    _handle_daemon_identity_challenge = _handler_reconnect._handle_daemon_identity_challenge
    _consume_codex_daemon_challenge = _handler_reconnect._consume_codex_daemon_challenge
    _write_unauthorized = _handler_reconnect._write_unauthorized
    _daemon_server = _handler_reconnect._daemon_server
    _record_auth_audit_event = _handler_reconnect._record_auth_audit_event
    _record_query_token_rejection = _handler_reconnect._record_query_token_rejection
    _record_hook_path_rejection = _handler_reconnect._record_hook_path_rejection
    _record_bounded_denial_event = _handler_reconnect._record_bounded_denial_event
    _header_token_is_valid = _handler_authorization._header_token_is_valid
    _dashboard_session_token_is_valid = _handler_authorization._dashboard_session_token_is_valid
    _dashboard_session_token_matches = _handler_authorization._dashboard_session_token_matches
    _dashboard_session_token_claims = _handler_authorization._dashboard_session_token_claims
    _refresh_dashboard_session_token = _handler_authorization._refresh_dashboard_session_token
    _refreshable_dashboard_session_claims = _handler_authorization._refreshable_dashboard_session_claims
    _dashboard_session_claims_authorize_request = _handler_authorization._dashboard_session_claims_authorize_request
    _dashboard_session_scoped_read_path_is_allowed = (
        _handler_authorization._dashboard_session_scoped_read_path_is_allowed
    )
    _dashboard_session_scoped_nonce_matches_request = (
        _handler_authorization._dashboard_session_scoped_nonce_matches_request
    )
    _local_surface_session_request_is_allowed = _handler_authorization._local_surface_session_request_is_allowed
    _path_supports_dashboard_session = _handler_authorization._path_supports_dashboard_session
    _claim_string = _handler_authorization._claim_string
    _enforce_package_firewall_rate_limit = _handler_authorization._enforce_package_firewall_rate_limit
    _consume_dashboard_session_nonce = _handler_authorization._consume_dashboard_session_nonce
    _supply_chain_dashboard_claims_authorize = _handler_authorization._supply_chain_dashboard_claims_authorize
    _supply_chain_claim_action_for_request = staticmethod(_handler_authorization._supply_chain_claim_action_for_request)
    _tokens_match = _handler_authorization._tokens_match
    _touch_runtime_heartbeat = _handler_health._touch_runtime_heartbeat
    _increment_active_stream_clients = _handler_health._increment_active_stream_clients
    _try_increment_active_stream_clients = _handler_health._try_increment_active_stream_clients
    _decrement_active_stream_clients = _handler_health._decrement_active_stream_clients
    _optional_int = staticmethod(_handler_health._optional_int)
    _stream_events = _handler_health._stream_events
    _origin_is_allowed_for_request = _handler_health._origin_is_allowed_for_request
    _is_hosted_dashboard_api_path = staticmethod(_handler_health._is_hosted_dashboard_api_path)
    _is_hosted_dashboard_origin = _handler_health._is_hosted_dashboard_origin
    _public_healthz_payload = _handler_health._public_healthz_payload
    _containment_health_payload = _handler_health._containment_health_payload
    _detailed_healthz_payload = _handler_health._detailed_healthz_payload
    _operator_health_payload = _handler_health._operator_health_payload
    _normalize_origin = staticmethod(_handler_health._normalize_origin)
    _cors_headers = staticmethod(_handler_health._cors_headers)
    _cors_headers_for_request = _handler_health._cors_headers_for_request
    _handle_policy_upsert = _handler_policy._handle_policy_upsert
    _handle_policy_resolve = _handler_policy._handle_policy_resolve
    _handle_policy_claim = _handler_policy._handle_policy_claim
    _optional_string = staticmethod(_handler_validation._optional_string)
    _coalesce_string = _handler_validation._coalesce_string
    _query_string = staticmethod(_handler_validation._query_string)
    _query_bool = staticmethod(_handler_validation._query_bool)
    _query_limit = staticmethod(_handler_validation._query_limit)
    _validated_hook_directory_string = _handler_validation._validated_hook_directory_string
    _normalized_hook_workspace_string = staticmethod(_handler_validation._normalized_hook_workspace_string)
    _runtime_hook_exec_command_workdir = staticmethod(_handler_validation._runtime_hook_exec_command_workdir)
    _validate_hook_directory_path = _handler_validation._validate_hook_directory_path
    _is_owned_temporary_hook_workspace = staticmethod(_handler_validation._is_owned_temporary_hook_workspace)
    _validated_hook_guard_home = _handler_validation._validated_hook_guard_home
    _hook_safe_roots = _handler_validation._hook_safe_roots
    _path_is_within_root = staticmethod(_handler_validation._path_is_within_root)
    _scope_target_is_valid = staticmethod(_handler_validation._scope_target_is_valid)
    _resolve_request_action = staticmethod(_handler_validation._resolve_request_action)
    _requires_header_token = staticmethod(_handler_responses._requires_header_token)
    _write_json = _handler_responses._write_json
    _write_empty = _handler_responses._write_empty
    _validated_headers = staticmethod(_handler_responses._validated_headers)
    _write_static_asset = _handler_responses._write_static_asset
    _write_dashboard_shell = _handler_responses._write_dashboard_shell
    _is_dashboard_route = staticmethod(_handler_responses._is_dashboard_route)
