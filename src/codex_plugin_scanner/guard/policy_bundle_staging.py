"""Validate complete canonical sources before staging ordinary policy rows.

This adapter does not verify signatures or claim native application. Its caller
must authenticate the full bundle, and the transaction retains its original
signed bytes separately from the strictly generic row cache.
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from .models import PolicyDecision
from .native_command_expression import materialize_native_command_projection
from .native_policy_authority_command_source import has_canonical_command_expressions
from .policy_bundle_materialization import (
    POLICY_BUNDLE_MATERIALIZATION_KEY,
    PolicyBundleMaterializationError,
    PolicyMaterializationStore,
    bind_policy_bundle_materialization,
)
from .policy_command_projection import project_canonical_command_policy
from .policy_document import GuardPolicyDocument
from .policy_document_types import PolicyCompilationError
from .policy_publication_binding import PolicyPublicationBinding
from .runtime.canonical_policy_decisions import build_canonical_policy_bundle_decisions


@dataclass(frozen=True, slots=True)
class CanonicalPolicyBundleStaging:
    decisions: tuple[PolicyDecision, ...]
    require_source_binding: bool


def prepare_canonical_policy_bundle_staging(
    policy_bundle: dict[str, object], *, device_id: str, device_name: str
) -> CanonicalPolicyBundleStaging:
    """Validate all active expressions before target selection or expiry filtering."""
    if not has_canonical_command_expressions(policy_bundle):
        return CanonicalPolicyBundleStaging(
            tuple(
                build_canonical_policy_bundle_decisions(
                    policy_bundle,
                    device_id=device_id,
                    device_name=device_name,
                )
            ),
            False,
        )
    payload = policy_bundle.get("payload")
    workspace = policy_bundle.get("workspaceId")
    publication = PolicyPublicationBinding.from_mapping(
        {
            "bundleVersion": policy_bundle.get("bundleVersion"),
            "bundleHash": policy_bundle.get("bundleHash"),
            "installationId": device_id,
        }
    )
    if not isinstance(payload, dict) or not isinstance(workspace, str) or publication is None:
        raise PolicyCompilationError("command_source_identity_invalid", "policy-bundle")
    projection = project_canonical_command_policy(
        GuardPolicyDocument.from_mapping(payload),
        publication=publication,
        workspace_id=workspace,
        target_device_id=device_id,
    )
    # Materialize the entire projection before removing expression or off-target
    # rows. An unsupported active rule cannot disappear through target/expiry filters.
    materialize_native_command_projection(projection)
    return CanonicalPolicyBundleStaging(
        tuple(row.selector for row in projection.rows if row.expression is None and row.applicable_to_target),
        True,
    )


def bind_staged_policy_rows(
    store: PolicyMaterializationStore,
    connection: sqlite3.Connection,
    *,
    decisions: Sequence[PolicyDecision],
    rows: Sequence[tuple[object, ...]],
    now: str,
    encoded_payloads: dict[str, str],
    require_source_binding: bool = False,
) -> list[tuple[object, ...]]:
    """Bind source and cache rows inside the existing atomic write transaction."""
    bundle = json.loads(encoded_payloads["policy_bundle"])
    if not isinstance(bundle, dict):
        raise PolicyBundleMaterializationError
    if type(require_source_binding) is not bool:
        raise PolicyBundleMaterializationError
    if require_source_binding or has_canonical_command_expressions(dict(bundle)):
        device = connection.execute(
            "select installation_id, device_label from guard_devices where device_key = 'local-device'"
        ).fetchone()
        if device is None:
            raise PolicyBundleMaterializationError
        staged = prepare_canonical_policy_bundle_staging(
            dict(bundle),
            device_id=str(device["installation_id"]),
            device_name=str(device["device_label"]),
        )
        decision_counts: dict[PolicyDecision, int] = dict(Counter(decisions))
        staged_counts: dict[PolicyDecision, int] = dict(Counter(staged.decisions))
        if decision_counts != staged_counts:
            raise PolicyCompilationError("command_source_generic_rows_mismatch", "policy-bundle")
        require_source_binding = True
    rebound, materialization = bind_policy_bundle_materialization(
        store,
        connection,
        bundle=bundle,
        rows=rows,
        now=now,
        require_source_binding=require_source_binding,
    )
    if materialization is not None:
        encoded_payloads[POLICY_BUNDLE_MATERIALIZATION_KEY] = json.dumps(materialization, allow_nan=False)
    return rebound
