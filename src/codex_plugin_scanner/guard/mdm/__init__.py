"""Enterprise MDM contracts for machine-owned HOL Guard installations."""

from .contracts import (
    LOCAL_INTEGRITY_SNAPSHOT_SCHEMA_VERSION,
    MDM_POLICY_SCHEMA_VERSION,
    MDM_STATUS_SCHEMA_VERSION,
    RELEASE_MANIFEST_SCHEMA_VERSION,
    MachinePaths,
    ManagedPolicy,
    ManagedPolicyState,
    default_machine_paths,
)
from .integrity import machine_integrity_snapshot
from .manifest import verify_release_manifest
from .observer_conformance import (
    observer_conformance_cases,
    observer_conformance_public_key_base64,
    run_observer_adapter_conformance,
    sign_observer_assertion,
)
from .policy import apply_managed_policy, load_managed_policy
from .supervisor import install_machine_supervisor, remove_machine_supervisor, verify_machine_supervisor

__all__ = [
    "LOCAL_INTEGRITY_SNAPSHOT_SCHEMA_VERSION",
    "MDM_POLICY_SCHEMA_VERSION",
    "MDM_STATUS_SCHEMA_VERSION",
    "RELEASE_MANIFEST_SCHEMA_VERSION",
    "MachinePaths",
    "ManagedPolicy",
    "ManagedPolicyState",
    "apply_managed_policy",
    "default_machine_paths",
    "install_machine_supervisor",
    "load_managed_policy",
    "machine_integrity_snapshot",
    "observer_conformance_cases",
    "observer_conformance_public_key_base64",
    "remove_machine_supervisor",
    "run_observer_adapter_conformance",
    "sign_observer_assertion",
    "verify_machine_supervisor",
    "verify_release_manifest",
]
