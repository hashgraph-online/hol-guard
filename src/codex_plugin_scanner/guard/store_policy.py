"""GuardStore domain mixin extracted from store.py."""

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Literal, cast

from .config_mutation import notify_native_policy_mutation
from .managed_controls_policy_bundle import (
    MANAGED_CONTROLS_ACTIVE_STATE_KEY,
    MANAGED_CONTROLS_LAST_GOOD_STATE_KEY,
    MANAGED_CONTROLS_NEGOTIATED_CAPABILITIES_STATE_KEY,
    MANAGED_CONTROLS_REVISION_STATE_KEY,
    build_managed_controls_activation_state,
    build_managed_controls_revision_state,
    managed_controls_layers_from_activation_state,
    managed_controls_revision_from_state,
)
from .memory_pattern_fingerprint import _memory_artifact_is_shell_command
from .policy_bundle_activation import (
    PolicyBundleActivationRejectionError,
    composed_managed_authority,
    encoded_delivery_acknowledgement,
    managed_delivery_matches_base,
    published_managed_authority,
)
from .policy_document_types import PolicyCompilationError
from .policy_precedence import generic_policy_row_precedence
from .runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityError,
    ExtensionControlAuthorityView,
)
from .runtime.extension_control_contract import ControlLayerKind
from .store_custom_extension_continuity import CustomExtensionContinuityMutation
from .store_policy_activation_preflight import (
    apply_continuity_rejection,
    continuity_activation_rejection,
    encoded_policy_activation_payloads,
    policy_checkpoint_rejection,
)
from .store_policy_rows import (
    materialized_policy_row_identity,
    normalized_policy_keys,
    replace_remote_policy_rows_locked,
    runtime_policy_row_is_eligible,
)

if TYPE_CHECKING:
    from .managed_controls_policy_fields import ParsedManagedControlsPolicy
    from .policy_rule_identity import PolicyRuleIdentity

# These imports remain the live dependency namespace and compatibility exports.
# ruff: noqa: F401,F403
from . import store_policy_bundle_authority as _bundle_authority
from . import store_policy_lookup as _lookup
from . import store_policy_mutations as _mutations
from . import store_policy_resolution as _resolution
from . import store_policy_reuse_claims as _reuse_claims
from .action_lattice import guard_action_severity
from .memory_pattern_fingerprint import (
    build_exact_command_memory_artifact_id,
    build_exact_shell_command_memory_artifact_id,
    build_memory_pattern_fingerprint,
)
from .models import GUARD_ACTION_VALUES
from .runtime.approval_context import approval_context_tokens_validation_reason
from .store_base import *
from .store_event_receipts import _local_once_approval_is_reusable, _verify_local_once_approval
from .store_policy_probe_queries import (
    _POLICY_LOOKUP_CONSUMING_SQL as _POLICY_LOOKUP_CONSUMING_SQL,
)
from .store_policy_probe_queries import (
    _bounded_non_consuming_policy_rows as _bounded_non_consuming_policy_rows,
)
from .store_policy_probe_queries import (
    _distinct_non_null as _distinct_non_null,
)
from .store_policy_probe_queries import (
    _execute_ordered_probe_groups as _execute_ordered_probe_groups,
)
from .store_policy_probe_queries import (
    _execute_unordered_bounded_probes as _execute_unordered_bounded_probes,
)
from .store_policy_probe_queries import (
    _hash_partition_probes as _hash_partition_probes,
)
from .store_policy_reuse_queries import (
    _append_exclusions as _append_exclusions,
)
from .store_policy_reuse_queries import (
    _approval_authority_revision as _approval_authority_revision,
)
from .store_policy_reuse_queries import (
    _bounded_local_approval_reuse_diagnostic_rows as _bounded_local_approval_reuse_diagnostic_rows,
)
from .store_policy_reuse_queries import (
    _bounded_policy_approval_reuse_diagnostic_rows as _bounded_policy_approval_reuse_diagnostic_rows,
)
from .store_policy_reuse_queries import (
    _most_restrictive_policy_lookup as _most_restrictive_policy_lookup,
)

_NON_CONSUMING_POLICY_MATCH_LIMIT = 256
_APPROVAL_REUSE_DIAGNOSTIC_LIMIT = 32
_APPROVAL_CONTEXT_SQL_PATTERN = "guard-approval-context:v1:%"
_POLICY_LOOKUP_COLUMNS = """
    decision_id, harness, scope, artifact_id, action, artifact_hash, workspace, publisher,
                   exact_command_sha256,
                       source,
    reason, owner, expires_at, updated_at, integrity_version, integrity_generation,
    payload_hash, payload_mac, integrity_key_id, signed_at
"""
_LOCAL_REUSE_DIAGNOSTIC_COLUMNS = """
    approval_id, request_id, harness, artifact_id, artifact_hash, workspace, publisher,
    action, created_at, expires_at, claimed_at, integrity_version, payload_hash, payload_mac,
    integrity_key_id, signed_at
"""
_POLICY_REUSE_DIAGNOSTIC_COLUMNS = _POLICY_LOOKUP_COLUMNS

_SqlProbe = tuple[str, tuple[object, ...], str]


class StorePolicyMixin:
    reconcile_managed_policy_bundle_keyring_state = (
        _mutations.StorePolicyMixin.reconcile_managed_policy_bundle_keyring_state
    )

    _materialized_policy_bundle_row_identity = staticmethod(materialized_policy_row_identity)

    _runtime_policy_row_is_eligible = staticmethod(runtime_policy_row_is_eligible)

    _cached_policy_bundle_decision_identities = _mutations.StorePolicyMixin._cached_policy_bundle_decision_identities

    _cached_policy_bundle_row_authorities = _mutations.StorePolicyMixin._cached_policy_bundle_row_authorities

    upsert_policy = _mutations.StorePolicyMixin.upsert_policy

    _upsert_policy_locked = _mutations.StorePolicyMixin._upsert_policy_locked

    replace_remote_policies = _mutations.StorePolicyMixin.replace_remote_policies

    apply_policy_bundle_authority = _bundle_authority.StorePolicyMixin.apply_policy_bundle_authority

    clear_policy_bundle_authority = _bundle_authority.StorePolicyMixin.clear_policy_bundle_authority

    _prepared_remote_policy_rows = _mutations.StorePolicyMixin._prepared_remote_policy_rows

    _replace_remote_policy_rows_locked = staticmethod(replace_remote_policy_rows_locked)

    resolve_policy = _resolution.StorePolicyMixin.resolve_policy

    resolve_policy_decision_lookup_with_memory_pattern = (
        _resolution.StorePolicyMixin.resolve_policy_decision_lookup_with_memory_pattern
    )

    resolve_policy_decision_lookup = _lookup.StorePolicyMixin.resolve_policy_decision_lookup

    resolve_policy_decision = _resolution.StorePolicyMixin.resolve_policy_decision

    claim_approval_reuse_decision = _reuse_claims.StorePolicyMixin.claim_approval_reuse_decision

    approval_reuse_claim_disposition = staticmethod(_reuse_claims.StorePolicyMixin.approval_reuse_claim_disposition)

    claim_approval_reuse_decisions = _reuse_claims.StorePolicyMixin.claim_approval_reuse_decisions

    _claim_approval_reuse_decision_locked = _reuse_claims.StorePolicyMixin._claim_approval_reuse_decision_locked

    approval_reuse_validation_reason = _reuse_claims.StorePolicyMixin.approval_reuse_validation_reason

    _normalized_policy_keys = staticmethod(normalized_policy_keys)

    policy_fingerprint = _mutations.StorePolicyMixin.policy_fingerprint
