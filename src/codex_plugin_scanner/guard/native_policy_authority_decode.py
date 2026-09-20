"""Strict reconstruction of bounded native authority values from snapshot JSON."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import fields
from typing import cast

from .native_managed_configuration import NativeManagedConfiguration
from .native_policy_authority_contract import (
    NATIVE_AUTHORITY_MAX_CONTROLS,
    NATIVE_AUTHORITY_MAX_ROWS,
    NATIVE_POLICY_AUTHORITY_SCHEMA,
    NativeManagedControl,
    NativeManagedPolicyAuthority,
    NativePolicyAction,
    NativePolicyAuthorityDraft,
    NativePolicyScope,
    NativePolicySourceKind,
    NativeScopedPolicyRow,
)
from .native_policy_authority_expressions import NativeScopedCommandExpression
from .native_policy_snapshot_constants import NativePolicySnapshotError


def _mapping(value: object, expected: set[str]) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise NativePolicySnapshotError("native_policy_authority_encoding_invalid")
    return dict(value)


def _items(value: object) -> list[object]:
    if type(value) is not list:
        raise NativePolicySnapshotError("native_policy_authority_encoding_invalid")
    return cast(list[object], value)


def native_policy_authority_from_mapping(value: object) -> NativePolicyAuthorityDraft:
    root_fields = {"schema", "generic_precedence", "rows", "managed"}
    if isinstance(value, Mapping) and "command_expressions" in value:
        root_fields.add("command_expressions")
    if isinstance(value, Mapping) and "managed_config" in value:
        root_fields.add("managed_config")
    root = _mapping(value, root_fields)
    if root["schema"] != NATIVE_POLICY_AUTHORITY_SCHEMA or root["generic_precedence"] != "specificity-recency.v1":
        raise NativePolicySnapshotError("native_policy_authority_schema_invalid")
    rows: list[NativeScopedPolicyRow] = []
    row_fields = {field.name for field in fields(NativeScopedPolicyRow)} | {"requires_exact_context"}
    try:
        raw_rows = _items(root["rows"])
        if len(raw_rows) > NATIVE_AUTHORITY_MAX_ROWS:
            raise NativePolicySnapshotError("native_policy_authority_row_limit")
        for value in raw_rows:
            row = _mapping(value, row_fields)
            exact = row.pop("requires_exact_context")
            row["scope"] = NativePolicyScope(row["scope"])
            row["action"] = NativePolicyAction(row["action"])
            row["source_kind"] = NativePolicySourceKind(row["source_kind"])
            candidate = NativeScopedPolicyRow(**row)  # pyright: ignore[reportArgumentType]
            if type(exact) is not bool or exact is not candidate.requires_exact_context:
                raise NativePolicySnapshotError("native_policy_authority_exact_context_invalid")
            rows.append(candidate)
        managed = None
        if root["managed"] is not None:
            raw_managed = _mapping(root["managed"], {field.name for field in fields(NativeManagedPolicyAuthority)})
            control_fields = {field.name for field in fields(NativeManagedControl)}
            raw_controls = _items(raw_managed["controls"])
            if len(raw_controls) > NATIVE_AUTHORITY_MAX_CONTROLS:
                raise NativePolicySnapshotError("native_policy_authority_control_invalid")
            raw_managed["controls"] = tuple(
                NativeManagedControl(**_mapping(item, control_fields))  # pyright: ignore[reportArgumentType]
                for item in raw_controls
            )
            managed = NativeManagedPolicyAuthority(**raw_managed)  # pyright: ignore[reportArgumentType]
        expressions = (
            tuple(NativeScopedCommandExpression.from_mapping(item) for item in _items(root["command_expressions"]))
            if "command_expressions" in root
            else ()
        )
        managed_config = (
            NativeManagedConfiguration.from_mapping(root["managed_config"]) if "managed_config" in root else None
        )
        return NativePolicyAuthorityDraft(tuple(rows), managed, expressions, managed_config)
    except (TypeError, ValueError) as error:
        raise NativePolicySnapshotError("native_policy_authority_encoding_invalid") from error
