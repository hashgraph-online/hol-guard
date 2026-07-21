# pyright: reportUnusedCallResult=false
from __future__ import annotations

from dataclasses import is_dataclass
from datetime import date, datetime, timezone
from typing import cast

import pytest

from codex_plugin_scanner.guard.runtime.command_activity_contract import CorrelationKind
from codex_plugin_scanner.guard.runtime.command_activity_privacy import (
    COMMAND_ACTIVITY_CLOUD_SCHEMA_VERSION,
    DEFAULT_COMMAND_ACTIVITY_PRIVACY_POLICY,
    MIN_CLOUD_AGGREGATE_COUNT,
    ActivityEgressMode,
    CloudAggregateDimension,
    CloudCommandActivityAggregate,
    CommandActivityPrivacyPolicy,
    InstallationCorrelationKey,
    StrongHarnessIdentifier,
    derive_correlation_handle,
    validate_activity_schema_privacy,
    validate_cloud_payload,
)


def _identifier(
    *,
    harness: str = "codex",
    kind: CorrelationKind = CorrelationKind.REQUEST,
    value: str = "01J3ABCD9XYZ7NATIVEID",
) -> StrongHarnessIdentifier:
    return StrongHarnessIdentifier(harness=harness, kind=kind, value=value)


def _key(*, key_id: str = "correlation.v1", byte: int = 7) -> InstallationCorrelationKey:
    return InstallationCorrelationKey(key_id=key_id, material=bytes([byte]) * 32)


def _aggregate(count: int = MIN_CLOUD_AGGREGATE_COUNT) -> CloudCommandActivityAggregate:
    return CloudCommandActivityAggregate(
        day=date(2026, 7, 18),
        dimension=CloudAggregateDimension.TOTAL,
        dimension_value="all",
        count=count,
    )


def test_activity_detail_is_local_only_by_default() -> None:
    assert DEFAULT_COMMAND_ACTIVITY_PRIVACY_POLICY.egress_mode is ActivityEgressMode.LOCAL_ONLY
    with pytest.raises(ValueError, match="local-only"):
        _aggregate().to_cloud_payload(DEFAULT_COMMAND_ACTIVITY_PRIVACY_POLICY)


def test_cloud_aggregate_requires_explicit_opt_in_and_exact_allowlist() -> None:
    policy = CommandActivityPrivacyPolicy(ActivityEgressMode.AGGREGATE_ONLY)
    payload = _aggregate().to_cloud_payload(policy)

    assert payload == {
        "day": "2026-07-18",
        "dimension": "total",
        "dimension_value": "all",
        "count": 10,
        "schema_version": COMMAND_ACTIVITY_CLOUD_SCHEMA_VERSION,
    }
    validate_cloud_payload(payload)
    with pytest.raises(ValueError, match="exact flat aggregate allowlist"):
        validate_cloud_payload({**payload, "activity_id": "activity:01"})
    with pytest.raises(ValueError, match="exact flat aggregate allowlist"):
        validate_cloud_payload({**payload, "dimension_value": {"nested": "value"}})
    with pytest.raises(ValueError, match="invalid scalar types"):
        validate_cloud_payload(
            {
                "day": "raw-secret",
                "dimension": "anything",
                "dimension_value": "secret",
                "count": 0,
                "schema_version": "x",
            }
        )
    with pytest.raises(ValueError, match="rare cloud aggregate"):
        validate_cloud_payload({**payload, "count": MIN_CLOUD_AGGREGATE_COUNT - 1})


def test_cloud_aggregate_suppresses_rare_cells_and_arbitrary_dimension_tuples() -> None:
    with pytest.raises(ValueError, match="rare cloud aggregate"):
        _aggregate(MIN_CLOUD_AGGREGATE_COUNT - 1)
    with pytest.raises(ValueError, match="bounded aggregate dimension"):
        CloudCommandActivityAggregate(
            day=date(2026, 7, 18),
            dimension=CloudAggregateDimension.TOTAL,
            dimension_value="codex",
            count=MIN_CLOUD_AGGREGATE_COUNT,
        )
    with pytest.raises(ValueError, match="UTC calendar date"):
        CloudCommandActivityAggregate(
            day=cast(date, datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)),
            dimension=CloudAggregateDimension.TOTAL,
            dimension_value="all",
            count=MIN_CLOUD_AGGREGATE_COUNT,
        )
    with pytest.raises(ValueError, match="bounded aggregate dimension"):
        CloudCommandActivityAggregate(
            day=date(2026, 7, 18),
            dimension=CloudAggregateDimension.EXECUTION_STATUS,
            dimension_value="repository.secret",
            count=MIN_CLOUD_AGGREGATE_COUNT,
        )
    with pytest.raises(ValueError, match="schema version"):
        CloudCommandActivityAggregate(
            day=date(2026, 7, 18),
            dimension=CloudAggregateDimension.HARNESS,
            dimension_value="codex",
            count=MIN_CLOUD_AGGREGATE_COUNT,
            schema_version="guard.command-activity-aggregate.v2",
        )


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
    validate_activity_schema_privacy()
