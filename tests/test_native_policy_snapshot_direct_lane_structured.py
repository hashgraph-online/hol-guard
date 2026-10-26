from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot_direct_lane_structured import (
    DIRECT_HOOK_STRUCTURED_OUTPUT_FEATURE,
    STRUCTURED_OUTPUT_BINDING_KEY,
    bound_structured_output_view,
    structured_output_view,
    uniform_structured_output_view,
    with_structured_output_view,
)
from codex_plugin_scanner.guard.native_policy_snapshot_publication import NativePolicySnapshotPublicationMixin

FEATURES = (DIRECT_HOOK_STRUCTURED_OUTPUT_FEATURE,)
HASH = "a" * 64
SETTING = "data_control.structured_output"
ABSENT = {
    "managed_policy_status": None,
    "managed_policy_hash": None,
    "managed_locked_settings": [],
    "managed_policy": None,
}


def _config(settings: object = None, *, locked: object = (SETTING,), status: object = "active") -> SimpleNamespace:
    policy = None if settings is None else SimpleNamespace(content_hash=HASH, settings=settings)
    return SimpleNamespace(
        managed_policy_status=status,
        managed_policy_hash=HASH,
        managed_locked_settings=locked,
        managed_policy=policy,
    )


def _structured(value: object) -> dict[str, object]:
    return {"data_control": {"structured_output": value, "other": True}, "unrelated": 1}


def test_the_view_is_the_wire_the_daemon_resolves() -> None:
    assert structured_output_view(SimpleNamespace()) == ABSENT
    assert structured_output_view(_config(_structured({"harnesses": ["omp"]}))) == {
        "managed_policy_status": "active",
        "managed_policy_hash": HASH,
        "managed_locked_settings": [SETTING],
        "managed_policy": {
            "content_hash": HASH,
            "settings": {"data_control": {"structured_output": {"harnesses": ["omp"]}}},
        },
    }


@pytest.mark.parametrize(
    "config",
    [
        _config(_structured({"harnesses": ("omp",)})),
        _config(_structured({"version": 1.5})),
        _config(_structured({1: "omp"})),
        _config(_structured({"event": "\ud800"})),
        _config(_structured({"limit": 2**53})),
        _config(_structured({"text": "x" * 70_000})),
        _config(status=object()),
    ],
)
def test_a_view_the_resident_could_read_differently_binds_nothing(config: object) -> None:
    assert structured_output_view(config) is None


def test_the_view_binds_only_when_every_compiled_config_agrees() -> None:
    locked = _config(_structured({"harnesses": ["omp"]}))
    assert uniform_structured_output_view([SimpleNamespace(), SimpleNamespace()]) == ABSENT
    assert uniform_structured_output_view([SimpleNamespace(), locked]) is None
    assert uniform_structured_output_view([_config(_structured({"version": 1.5}))]) is None
    assert uniform_structured_output_view([]) is None


def test_the_view_binds_only_for_a_resident_that_accepts_it() -> None:
    assert with_structured_output_view(None, features=FEATURES, view=ABSENT) is None
    assert with_structured_output_view({"generation": 1}, features=(), view=ABSENT) == {"generation": 1}
    assert with_structured_output_view({"generation": 1}, features=FEATURES, view=None) == {"generation": 1}
    bound = with_structured_output_view({"generation": 1}, features=FEATURES, view=ABSENT)
    assert bound == {"generation": 1, STRUCTURED_OUTPUT_BINDING_KEY: ABSENT}
    assert bound_structured_output_view(bound, FEATURES) == ABSENT
    assert bound_structured_output_view(bound, ()) is None
    assert bound_structured_output_view({"generation": 1}, FEATURES) is None
    assert bound_structured_output_view(None, FEATURES) is None


class _Publisher(NativePolicySnapshotPublicationMixin):
    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._publish_event = threading.Event()
        self._closed = False
        self._acked = True
        self._snapshot = {"generation": 7}
        self._direct_lane_ack_target: tuple[int, str] | None = (7, "digest")
        self._direct_lane_review_facts: object = ("origin", "cwd")
        self._direct_lane_structured_output: dict[str, object] | None = dict(ABSENT)
        self._compiled_structured_output_view: dict[str, object] | None = dict(ABSENT)
        self._renewal_after_generation: int | None = None
        self._retry_not_before_monotonic: float | None = None
        self._failure_count = 3
        self.closed_lane = 0

    def _monotonic_clock(self) -> float:
        return 42.0

    def _close_direct_lane_ack(self) -> None:
        self.closed_lane += 1
        self._direct_lane_ack_target = None


@pytest.mark.parametrize("compiled", [None, structured_output_view(_config(_structured({"harnesses": ["omp"]})))])
def test_a_moved_view_closes_the_lane_and_republishes_under_the_ack(compiled: dict[str, object] | None) -> None:
    publisher = _Publisher()
    publisher._recheck_direct_lane_structured_output()
    assert publisher.closed_lane == 0
    assert not publisher._publish_event.is_set()

    publisher._compiled_structured_output_view = compiled
    publisher._recheck_direct_lane_structured_output()
    assert publisher.closed_lane == 1
    assert publisher._direct_lane_structured_output is None
    assert publisher._direct_lane_review_facts is None
    assert publisher._renewal_after_generation == 7
    assert publisher._retry_not_before_monotonic == 42.0
    assert publisher._failure_count == 0
    assert publisher._publish_event.is_set()


def test_an_unbound_or_closed_lane_is_not_rechecked() -> None:
    publisher = _Publisher()
    publisher._direct_lane_structured_output = None
    publisher._compiled_structured_output_view = None
    publisher._recheck_direct_lane_structured_output()
    publisher = _Publisher()
    publisher._direct_lane_ack_target = None
    publisher._compiled_structured_output_view = None
    publisher._recheck_direct_lane_structured_output()
    assert publisher.closed_lane == 0
    assert not publisher._publish_event.is_set()
