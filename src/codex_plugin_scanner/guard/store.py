"""SQLite-backed local Guard persistence facade."""

from __future__ import annotations

from . import store_base as _store_base
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

for _name in dir(_store_base):
    if not (_name.startswith("__") and _name.endswith("__")):
        globals()[_name] = getattr(_store_base, _name)


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
