"""SQLite-backed local Guard persistence facade."""

from __future__ import annotations

# ruff: noqa: F401,F403,I001
from .store_base import *
from .store_base import (
    SystemKeyringSecretStore,
    _runtime_scoped_exact_match_key,
    browser_mcp_exact_match_context,
    runtime_tool_action_exact_match_context,
)
from .store_approval_facade import StoreApprovalsMixin
from .store_cloud_events import StoreCloudEventsMixin
from .store_command_activity import StoreCommandActivityMixin
from .store_command_activity_api import StoreCommandActivityApiMixin
from .store_command_activity_lifecycle import StoreCommandActivityLifecycleMixin
from .store_command_activity_maintenance import StoreCommandActivityMaintenanceMixin
from .store_command_activity_privacy import StoreCommandActivityPrivacyMixin
from .store_command_shadow import StoreCommandShadowMixin
from .store_connection_schema import StoreConnectionSchemaMixin
from .store_event_receipts import StoreEventReceiptsMixin
from .store_evidence_facade import StoreEvidenceMixin
from .store_inventory import StoreInventoryMixin
from .store_live_request_outbox import StoreLiveRequestOutboxMixin
from .store_oauth import StoreOAuthConnectMixin
from .store_policy import StorePolicyMixin
from .store_policy_integrity_runtime import StorePolicyIntegrityAdminMixin
from .store_read_state import StoreReadStateMixin
from .store_receipts import StoreReceiptsRuntimeMixin
from .store_secret_policy_integrity import (
    StoreSecretPolicyIntegrityMixin,
    _POLICY_INTEGRITY_LOOKUP_UNSET,
)
from .store_sessions import StoreSessionsMixin
from .store_workflow_capabilities import StoreWorkflowCapabilitiesMixin
from .store_workflow_capability_lookup import StoreWorkflowCapabilityLookupMixin
from .store_workflow_capability_receipt_lookup import StoreWorkflowCapabilityReceiptLookupMixin
from .store_workflow_capability_revocation import StoreWorkflowCapabilityRevocationMixin
from .store_workflow_capability_secret_control import StoreWorkflowCapabilitySecretControlMixin


class GuardStore(
    StoreSecretPolicyIntegrityMixin,
    StoreWorkflowCapabilitySecretControlMixin,
    StoreConnectionSchemaMixin,
    StoreCommandActivityMixin,
    StoreCommandActivityApiMixin,
    StoreCommandActivityLifecycleMixin,
    StoreCommandActivityMaintenanceMixin,
    StoreCommandActivityPrivacyMixin,
    StoreCommandShadowMixin,
    StoreInventoryMixin,
    StorePolicyMixin,
    StorePolicyIntegrityAdminMixin,
    StoreCloudEventsMixin,
    StoreReceiptsRuntimeMixin,
    StoreApprovalsMixin,
    StoreLiveRequestOutboxMixin,
    StoreEventReceiptsMixin,
    StoreOAuthConnectMixin,
    StoreSessionsMixin,
    StoreEvidenceMixin,
    StoreReadStateMixin,
    StoreWorkflowCapabilitiesMixin,
    StoreWorkflowCapabilityLookupMixin,
    StoreWorkflowCapabilityReceiptLookupMixin,
    StoreWorkflowCapabilityRevocationMixin,
):
    """Local SQLite store for Guard state."""


__all__ = tuple(name for name in globals() if not (name.startswith("__") and name.endswith("__")))
