"""Enterprise MDM contracts for machine-owned HOL Guard installations."""

from .contracts import (
    MDM_POLICY_SCHEMA_VERSION,
    MDM_STATUS_SCHEMA_VERSION,
    RELEASE_MANIFEST_SCHEMA_VERSION,
    MachinePaths,
    ManagedPolicy,
    ManagedPolicyState,
    default_machine_paths,
)
from .manifest import verify_release_manifest
from .policy import apply_managed_policy, load_managed_policy

__all__ = [
    "MDM_POLICY_SCHEMA_VERSION",
    "MDM_STATUS_SCHEMA_VERSION",
    "RELEASE_MANIFEST_SCHEMA_VERSION",
    "MachinePaths",
    "ManagedPolicy",
    "ManagedPolicyState",
    "apply_managed_policy",
    "default_machine_paths",
    "load_managed_policy",
    "verify_release_manifest",
]
