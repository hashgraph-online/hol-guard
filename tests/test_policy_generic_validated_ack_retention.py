"""Accepted generic ACK progress must survive later unverified observations."""

from __future__ import annotations

import copy

import pytest

from codex_plugin_scanner.guard.policy_bundle_delivery import policy_bundle_acknowledgement_payload
from codex_plugin_scanner.guard.policy_bundle_generic_ack import generic_policy_bundle_acknowledgement
from codex_plugin_scanner.guard.policy_bundle_v2 import validated_policy_bundle_v2_acknowledgement
from tests.test_policy_bundle_generic_acknowledgement import _generic_v2_bundle

_TIME = "2026-09-18T00:00:00Z"


def _emit(
    bundle: dict[str, object], *, applied: bool, previous: dict[str, object] | None = None,
    entrypoint: str = "generic",
) -> dict[str, object]:
    if entrypoint == "delivery":
        return policy_bundle_acknowledgement_payload(
            device_id="installation-current", device_name="Guard", policy_bundle=bundle,
            synced_at=_TIME, status="applied" if applied else "validated", previous=previous,
        )
    return generic_policy_bundle_acknowledgement(
        device_id="installation-current", policy_bundle=bundle, synced_at=_TIME,
        applied=applied, previous=previous,
    )


def _previous(bundle: dict[str, object], status: str) -> dict[str, object]:
    acknowledgement = _emit(bundle, applied=status == "applied")
    acknowledgement["status"] = status
    assert validated_policy_bundle_v2_acknowledgement(acknowledgement) == (acknowledgement, None)
    return acknowledgement


@pytest.mark.parametrize("entrypoint", ["generic", "delivery"])
@pytest.mark.parametrize("status", ["received", "validated", "applied"])
def test_unverified_refresh_retains_valid_generic_progress(entrypoint: str, status: str) -> None:
    bundle = _generic_v2_bundle()
    previous = _previous(bundle, status)
    unchanged = copy.deepcopy(previous)

    refreshed = _emit(bundle, applied=False, previous=previous, entrypoint=entrypoint)

    assert refreshed
    assert refreshed["status"] == status
    assert validated_policy_bundle_v2_acknowledgement(refreshed, previous=previous) == (refreshed, None)
    for field in ("deviceId", "workspaceId", "bundleVersion", "bundleHash", "contractVersion"):
        assert refreshed[field] == previous[field]
    assert "deliveryId" not in refreshed
    assert "deviceName" not in refreshed
    assert previous == unchanged


def test_validated_generic_ack_can_advance_to_applied() -> None:
    bundle = _generic_v2_bundle()
    previous = _previous(bundle, "validated")

    applied = _emit(bundle, applied=True, previous=previous)

    assert applied["status"] == "applied"
    assert applied["sequence"] == 2
    assert validated_policy_bundle_v2_acknowledgement(applied, previous=previous) == (applied, None)


@pytest.mark.parametrize(
    ("field", "foreign_value"),
    [("deviceId", "installation-other"), ("bundleHash", "sha256:" + "f" * 64)],
)
def test_foreign_validated_ack_cannot_supply_current_progress(field: str, foreign_value: str) -> None:
    bundle = _generic_v2_bundle()
    previous = _previous(bundle, "validated")
    previous[field] = foreign_value
    assert validated_policy_bundle_v2_acknowledgement(previous) == (previous, None)

    current = _emit(bundle, applied=False, previous=previous)

    assert current["status"] == "received"
    assert current["sequence"] == 1
    assert current[field] != previous[field]
    assert validated_policy_bundle_v2_acknowledgement(current) == (current, None)


def test_malformed_validated_ack_cannot_supply_current_progress() -> None:
    bundle = _generic_v2_bundle()
    previous = _previous(bundle, "validated")
    previous["sequence"] = True
    assert validated_policy_bundle_v2_acknowledgement(previous)[0] is None

    current = _emit(bundle, applied=False, previous=previous)

    assert current["status"] == "received"
    assert current["sequence"] == 1
    assert validated_policy_bundle_v2_acknowledgement(current) == (current, None)
