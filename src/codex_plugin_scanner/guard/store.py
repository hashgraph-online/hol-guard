"""SQLite-backed local Guard persistence facade."""

from __future__ import annotations

# ruff: noqa: F401,F403,I001
from .store_base import *
from .store_base import (
    SystemKeyringSecretStore,
    _runtime_scoped_exact_match_key,
    runtime_tool_action_exact_match_context,
)
from .store_approval_facade import StoreApprovalsMixin
from .store_cloud_events import StoreCloudEventsMixin
from .store_connection_schema import StoreConnectionSchemaMixin
from .store_event_receipts import StoreEventReceiptsMixin
from .store_evidence_facade import StoreEvidenceMixin
from .store_inventory import StoreInventoryMixin
from .store_oauth import StoreOAuthConnectMixin
from .store_policy import StorePolicyMixin
from .store_policy_integrity_runtime import StorePolicyIntegrityAdminMixin
from .store_receipts import StoreReceiptsRuntimeMixin
from .store_secret_policy_integrity import StoreSecretPolicyIntegrityMixin
from .store_sessions import StoreSessionsMixin


class GuardStore(
    StoreSecretPolicyIntegrityMixin,
    StoreConnectionSchemaMixin,
    StoreInventoryMixin,
    StorePolicyMixin,
    StoreReceiptsRuntimeMixin,
    StoreApprovalsMixin,
    StorePolicyIntegrityAdminMixin,
    StoreCloudEventsMixin,
    StoreEventReceiptsMixin,
    StoreOAuthConnectMixin,
    StoreSessionsMixin,
    StoreEvidenceMixin,
):
    """Local SQLite store for Guard state."""


__all__ = tuple(name for name in globals() if not (name.startswith("__") and name.endswith("__")))
