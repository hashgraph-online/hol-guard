"""Runtime dependencies reexported by the daemon namespace."""

from __future__ import annotations

from ..runtime.command_activity_contract import ActivityApprovalReuseStatus, ActivityDecisionReason
from ..runtime.command_activity_lifecycle import CommandActivityDecisionFacts, build_pre_hook_evidence
from ..runtime.command_evaluation import evaluate_command
from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from ..runtime.command_shadow_evaluation import (
    CommandShadowCohort,
    CommandShadowControl,
    baseline_command_shadow_proposal,
    build_command_shadow_observation,
)
from ..runtime.extension_control_authority import ExtensionControlAuthorityError, ExtensionControlAuthorityView
from ..runtime.extension_control_runtime import ExtensionControlRuntime, ExtensionControlRuntimeSnapshot
from ..runtime.isolation_provider import load_managed_provider_registry
from ..runtime.local_temp_paths import trusted_temporary_root_for_path
from ..runtime.network_status import build_network_status, project_network_supervisor_health
from ..runtime.network_supervisor import NetworkSupervisor
from ..runtime.runner import (
    GuardSyncAuthorizationExpiredError,
    GuardSyncNotAvailableError,
    GuardSyncNotConfiguredError,
    _build_policy_bundle_decisions,
    _daemon_version_supported,
    _guard_device_metadata,
    _persist_cloud_receipt_redaction_level,
    _policy_bundle_acceptance_checkpoint,
    _policy_bundle_cloud_exception_items,
    _policy_bundle_downgrade_reference,
    _policy_bundle_is_version_downgrade,
    _requeue_cloud_review_privacy_projection,
    _reset_cloud_receipt_redaction_authority,
    _resolve_guard_sync_auth_context,
    _validate_cached_policy_bundle,
    prepare_guard_cloud_connect_authorization,
    repair_guard_cloud_connect_storage,
    sync_local_guard_cloud_proof,
    sync_supply_chain_bundle,
)
from ..runtime.surface_server import GuardSurfaceRuntime
from ..runtime_artifact_reconciliation import (
    reconcile_runtime_artifacts,
    repair_failing_managed_harness_hooks,
)
from ..shims import (
    activate_package_shims,
    package_shim_dashboard_status,
    package_shim_status,
    package_shim_supported_managers,
    probe_package_shim_intercepts,
    uninstall_package_shims,
)
from ..sqlite_tuning import sqlite_connect_timeout_override
from ..stable_digest import stable_digest_hex
from ..store import GuardStore
from ..store_approvals import InvalidApprovalCursorError
from ..store_evidence import (
    clear_evidence,
    count_evidence,
    evidence_record_to_dict,
    export_evidence_csv,
    export_evidence_json,
    list_evidence,
)
from ..store_storage_maintenance import DEFAULT_GUARD_EVENT_LIMIT, DEFAULT_RECEIPT_DETAIL_LIMIT
from ..supply_chain_repair import coordinate_supply_chain_repair, repair_sync_intelligence
from .bounded_http import BoundedThreadingHTTPServer
from .command_activity_api import (
    handle_command_activity_analytics,
    handle_command_activity_diagnostics,
    handle_command_activity_feedback,
    handle_command_activity_list,
    handle_command_extensions,
    parse_command_activity_event_cursor,
    stream_command_activity_events,
)

__all__ = [
    "BUILT_IN_COMMAND_EXTENSION_REGISTRY",
    "DEFAULT_GUARD_EVENT_LIMIT",
    "DEFAULT_RECEIPT_DETAIL_LIMIT",
    "ActivityApprovalReuseStatus",
    "ActivityDecisionReason",
    "BoundedThreadingHTTPServer",
    "CommandActivityDecisionFacts",
    "CommandShadowCohort",
    "CommandShadowControl",
    "ExtensionControlAuthorityError",
    "ExtensionControlAuthorityView",
    "ExtensionControlRuntime",
    "ExtensionControlRuntimeSnapshot",
    "GuardStore",
    "GuardSurfaceRuntime",
    "GuardSyncAuthorizationExpiredError",
    "GuardSyncNotAvailableError",
    "GuardSyncNotConfiguredError",
    "InvalidApprovalCursorError",
    "NetworkSupervisor",
    "_build_policy_bundle_decisions",
    "_daemon_version_supported",
    "_guard_device_metadata",
    "_persist_cloud_receipt_redaction_level",
    "_policy_bundle_acceptance_checkpoint",
    "_policy_bundle_cloud_exception_items",
    "_policy_bundle_downgrade_reference",
    "_policy_bundle_is_version_downgrade",
    "_requeue_cloud_review_privacy_projection",
    "_reset_cloud_receipt_redaction_authority",
    "_resolve_guard_sync_auth_context",
    "_validate_cached_policy_bundle",
    "activate_package_shims",
    "baseline_command_shadow_proposal",
    "build_command_shadow_observation",
    "build_network_status",
    "build_pre_hook_evidence",
    "clear_evidence",
    "coordinate_supply_chain_repair",
    "count_evidence",
    "evaluate_command",
    "evidence_record_to_dict",
    "export_evidence_csv",
    "export_evidence_json",
    "handle_command_activity_analytics",
    "handle_command_activity_diagnostics",
    "handle_command_activity_feedback",
    "handle_command_activity_list",
    "handle_command_extensions",
    "list_evidence",
    "load_managed_provider_registry",
    "package_shim_dashboard_status",
    "package_shim_status",
    "package_shim_supported_managers",
    "parse_command_activity_event_cursor",
    "prepare_guard_cloud_connect_authorization",
    "probe_package_shim_intercepts",
    "project_network_supervisor_health",
    "reconcile_runtime_artifacts",
    "repair_failing_managed_harness_hooks",
    "repair_guard_cloud_connect_storage",
    "repair_sync_intelligence",
    "sqlite_connect_timeout_override",
    "stable_digest_hex",
    "stream_command_activity_events",
    "sync_local_guard_cloud_proof",
    "sync_supply_chain_bundle",
    "trusted_temporary_root_for_path",
    "uninstall_package_shims",
]
