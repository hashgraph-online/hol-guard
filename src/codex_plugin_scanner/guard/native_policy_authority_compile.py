"""Compile verified persistent authority without changing its selectors.

The caller must authenticate rows and their source within a consistent
authority read. In particular, dashboard listings and persisted source labels
are not verified inputs. This compiler creates no acknowledgement, selects no
winner and never reads request facts. The V3 publisher cannot use its output.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from itertools import islice
from typing import cast

from .native_policy_authority_contract import (
    NATIVE_AUTHORITY_MAX_ROWS,
    NativeManagedControl,
    NativeManagedPolicyAuthority,
    NativePolicyAction,
    NativePolicyAuthorityDraft,
    NativePolicyScope,
    NativePolicySourceKind,
    NativeScopedPolicyRow,
    authority_integer,
    bounded_authority_text,
)
from .native_policy_authority_expressions import NativeScopedCommandExpression
from .native_policy_snapshot_constants import NativePolicySnapshotError
from .policy_integrity import is_remote_policy_source
from .runtime.command_extensions import CommandSafetyExtensionRegistry
from .runtime.extension_control_authority import AuthorityHealth, ExtensionControlAuthorityView
from .runtime.extension_control_contract import ControlSurface
from .runtime.extension_control_resolver import resolve_extension_controls

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _timestamp_us(value: object) -> int:
    text = bounded_authority_text(value)
    assert text is not None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
        delta = parsed.astimezone(timezone.utc) - _EPOCH
        return authority_integer((delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds)
    except (ValueError, OverflowError) as error:
        raise NativePolicySnapshotError("native_policy_authority_timestamp_invalid") from error


def _source_kind(value: object) -> NativePolicySourceKind:
    source = bounded_authority_text(value)
    assert source is not None
    if source in {"policy-bundle", "policy-bundle-canonical"}:
        return NativePolicySourceKind.SIGNED_BUNDLE
    if source == "cloud-signed-memory":
        return NativePolicySourceKind.SIGNED_MEMORY
    if is_remote_policy_source(source):
        raise NativePolicySnapshotError("native_policy_authority_source_unsupported")
    return NativePolicySourceKind.LOCAL


def compile_native_policy_row(row: Mapping[str, object]) -> NativeScopedPolicyRow:
    """Preserve a verified persistent row's exact selectors and recency."""

    expires = row.get("expires_at")
    if row.get("approval_id") is not None or (row.get("source") == "approval-gate" and expires is not None):
        # One-shot grants belong to the atomic approval protocol. Copying one
        # into a reusable snapshot would turn a consumed grant into authority.
        raise NativePolicySnapshotError("native_policy_authority_one_shot_unsupported")
    try:
        result = NativeScopedPolicyRow(
            decision_id=authority_integer(row.get("decision_id"), positive=True),
            harness=cast(str, bounded_authority_text(row.get("harness"))),
            scope=NativePolicyScope(row.get("scope")),
            action=NativePolicyAction(row.get("action")),
            source_kind=_source_kind(row.get("source")),
            updated_at_us=_timestamp_us(row.get("updated_at")),
            artifact_id=bounded_authority_text(row.get("artifact_id"), optional=True),
            artifact_hash=bounded_authority_text(row.get("artifact_hash"), optional=True),
            workspace=bounded_authority_text(row.get("workspace"), optional=True),
            publisher=bounded_authority_text(row.get("publisher"), optional=True),
            expires_at_ms=_timestamp_us(expires) // 1_000 if expires is not None else None,
            exact_command_sha256=bounded_authority_text(row.get("exact_command_sha256"), optional=True),
        )
    except (ValueError, TypeError) as error:
        raise NativePolicySnapshotError("native_policy_authority_row_invalid") from error
    return result


def compile_native_managed_authority(
    view: ExtensionControlAuthorityView, registry: CommandSafetyExtensionRegistry
) -> NativeManagedPolicyAuthority:
    """Compose authenticated controls with the existing disable dominance."""

    if view.health is not AuthorityHealth.PROTECTED or view.catalog_digest != registry.catalog_digest:
        raise NativePolicySnapshotError("native_policy_authority_managed_unavailable")
    resolution = resolve_extension_controls(
        view.layers, registry, extension_ids=(), permission_ids=(), surface=ControlSurface.COMMAND_EVALUATION
    )
    if resolution.failures:
        raise NativePolicySnapshotError("native_policy_authority_managed_unavailable")
    return NativeManagedPolicyAuthority(
        revision=view.revision,
        managed_revision=view.managed_revision,
        catalog_digest=view.catalog_digest,
        global_lockdown=resolution.composed.global_lockdown,
        controls=tuple(
            NativeManagedControl(control.target.kind.value, control.target.target_id, control.state.value)
            for control in resolution.composed.controls
        ),
    )


def compile_native_policy_authority(
    verified_rows: Iterable[Mapping[str, object]], *, managed: NativeManagedPolicyAuthority | None = None
) -> NativePolicyAuthorityDraft:
    """Produce a bounded draft; source validation and resident proof stay separate."""

    rows = tuple(islice(verified_rows, NATIVE_AUTHORITY_MAX_ROWS + 1))
    if len(rows) > NATIVE_AUTHORITY_MAX_ROWS:
        raise NativePolicySnapshotError("native_policy_authority_row_limit")
    compiled = tuple(compile_native_policy_row(row) for row in rows)
    expressions = tuple(
        NativeScopedCommandExpression(candidate.decision_id, cast(str, source["_command_expression_json"]))
        for source, candidate in zip(rows, compiled, strict=True)
        if "_command_expression_json" in source
    )
    return NativePolicyAuthorityDraft(compiled, managed, expressions)


__all__ = ["compile_native_managed_authority", "compile_native_policy_authority", "compile_native_policy_row"]
