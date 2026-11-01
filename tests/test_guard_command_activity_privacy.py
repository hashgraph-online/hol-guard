# pyright: reportUnusedCallResult=false
from __future__ import annotations

from dataclasses import is_dataclass
from typing import cast

import pytest

from codex_plugin_scanner.guard.runtime.command_activity_contract import (
    COMMAND_ACTIVITY_FIELDS,
    COMMAND_ACTIVITY_MATCH_FIELDS,
    CorrelationKind,
)
from codex_plugin_scanner.guard.runtime.command_activity_privacy import (
    InstallationCorrelationKey,
    StrongHarnessIdentifier,
    derive_correlation_handle,
)
from tests.command_activity_privacy_support import FORBIDDEN_ACTIVITY_FIELD_NAMES


def _identifier(
    *,
    harness: str = "codex",
    kind: CorrelationKind = CorrelationKind.REQUEST,
    value: str = "01J3ABCD9XYZ7NATIVEID",
) -> StrongHarnessIdentifier:
    return StrongHarnessIdentifier(harness=harness, kind=kind, value=value)


def _key(*, key_id: str = "correlation.v1", byte: int = 7) -> InstallationCorrelationKey:
    return InstallationCorrelationKey(key_id=key_id, material=bytes([byte]) * 32)


def test_correlation_hmac_is_deterministic_and_domain_separated() -> None:
    key = _key()
    request = _identifier()
    same = derive_correlation_handle(request, key)

    assert same == derive_correlation_handle(request, key)
    assert same != derive_correlation_handle(_identifier(value="01J3ABCD9XYZ7OTHERID"), key)
    assert same.digest != derive_correlation_handle(_identifier(harness="cursor"), key).digest
    assert same.digest != derive_correlation_handle(_identifier(kind=CorrelationKind.SESSION), key).digest
    assert same.digest != derive_correlation_handle(request, _key(byte=8)).digest
    assert same.digest != derive_correlation_handle(request, _key(key_id="correlation.v2")).digest
    assert same.key_id == "correlation.v1"


def test_key_rotation_cannot_reinterpret_old_handles() -> None:
    identifier = _identifier()
    first = derive_correlation_handle(identifier, _key(key_id="correlation.v1", byte=1))
    rotated = derive_correlation_handle(identifier, _key(key_id="correlation.v2", byte=2))

    assert first.key_id != rotated.key_id
    assert first.digest != rotated.digest


def test_raw_identifier_and_key_material_are_hidden_from_repr_and_contract_output() -> None:
    raw_identifier = "01J3SECRET9XYZ7NATIVEID"
    key_material = b"secret-key-material-that-is-32-bytes"
    identifier = _identifier(value=raw_identifier)
    key = InstallationCorrelationKey(key_id="correlation.v1", material=key_material)
    handle = derive_correlation_handle(identifier, key)

    assert raw_identifier not in repr(identifier)
    assert key_material.decode("ascii") not in repr(key)
    assert raw_identifier not in repr(handle)
    assert handle.digest not in repr(handle)
    assert not is_dataclass(identifier)
    assert not is_dataclass(key)
    assert raw_identifier not in handle.digest


@pytest.mark.parametrize(
    "value",
    [
        "1",
        "123456789012345",
        "request-1234567890123",
        "request-123456789012345678901",
        "session:1234567890",
        "2026-07-18T20:00:00Z",
        "aaaaaaaaaaaaaaaa",
        "abababababababab",
    ],
)
def test_predictable_identifiers_are_rejected(value: str) -> None:
    with pytest.raises(ValueError):
        _identifier(value=value)


def test_short_keys_and_untyped_correlation_inputs_are_rejected() -> None:
    with pytest.raises(ValueError, match="at least 32"):
        InstallationCorrelationKey(key_id="correlation.v1", material=b"short")
    with pytest.raises(ValueError, match="StrongHarnessIdentifier"):
        derive_correlation_handle(cast(StrongHarnessIdentifier, cast(object, "raw-request-id")), _key())
    with pytest.raises(ValueError, match="InstallationCorrelationKey"):
        derive_correlation_handle(
            _identifier(),
            cast(InstallationCorrelationKey, cast(object, b"not-a-key")),
        )
    with pytest.raises(ValueError, match="supported Guard harness"):
        _identifier(harness="repository.secret")


def test_frozen_activity_schema_contains_no_forbidden_fields() -> None:
    names = frozenset((*COMMAND_ACTIVITY_FIELDS, *COMMAND_ACTIVITY_MATCH_FIELDS))

    assert names.isdisjoint(FORBIDDEN_ACTIVITY_FIELD_NAMES)
    assert names.isdisjoint({"raw_request_id", "raw_session_id", "installation_id"})
