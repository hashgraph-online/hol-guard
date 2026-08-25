from lab_store_base import StoreBase
from lab_store_policy import StorePolicyMixin
from lab_store_remediation import StoreRemediationMixin


class Store(StoreRemediationMixin, StorePolicyMixin, StoreBase):
    """Complete reference MDM Cloud store assembled from bounded mixins."""

    pass
