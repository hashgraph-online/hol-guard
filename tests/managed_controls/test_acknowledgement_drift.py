from __future__ import annotations

import pytest

from tests.managed_controls.acknowledgement import (
    AcknowledgementError,
    ManagedControlsAcknowledgement,
    accept_acknowledgement,
)
from tests.managed_controls.drift import (
    DriftState,
    ExpectedManagedControlsState,
    classify_drift,
)


def _ack(revision: int, catalog: str = "catalog") -> ManagedControlsAcknowledgement:
    return ManagedControlsAcknowledgement(
        revision,
        f"bundle-{revision}",
        catalog,
        "effective",
        revision,
    )


def test_acknowledgement_is_idempotent_and_monotonic() -> None:
    first = _ack(1)
    assert accept_acknowledgement(first, first) is first
    assert accept_acknowledgement(first, _ack(2)).revision == 2
    with pytest.raises(AcknowledgementError):
        accept_acknowledgement(_ack(2), _ack(1))
    with pytest.raises(AcknowledgementError):
        accept_acknowledgement(
            _ack(2),
            ManagedControlsAcknowledgement(3, "bundle-3", "catalog", "effective", 1),
        )


def test_drift_distinguishes_catalog_and_effective_mismatch() -> None:
    expected = ExpectedManagedControlsState(1, "bundle-1", "catalog", "effective", 1)
    assert classify_drift(expected, _ack(1)) is DriftState.CURRENT
    assert classify_drift(expected, _ack(1, "other")) is DriftState.CATALOG_MISMATCH
    assert classify_drift(expected, None) is DriftState.PENDING
    assert classify_drift(expected, _ack(2)) is DriftState.PENDING
    assert (
        classify_drift(
            expected,
            ManagedControlsAcknowledgement(1, "bundle-1", "catalog", "effective", 2),
        )
        is DriftState.PENDING
    )
