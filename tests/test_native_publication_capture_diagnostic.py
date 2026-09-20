"""Pure observation preserves metadata fences, exceptions and hook ownership."""

from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_publisher_scoped as scoped
from scripts.native_publication_capture_diagnostic import CaptureMetadataObservation

_DATABASE = "/private-fixture/sensitive-account/guard.db"


def _publisher() -> SimpleNamespace:
    return SimpleNamespace(_thread=threading.current_thread())


def test_observation_preserves_database_ctime_normalization_and_every_other_field() -> None:
    original = scoped._capture_metadata_equal
    before = ((_DATABASE, (1, 2, 3, 4)), (_DATABASE + "-wal", (4, 5, 6, 7)))
    observation = CaptureMetadataObservation()
    with observation.attach(_publisher()):
        assert scoped._capture_metadata_equal(before, ((_DATABASE, (1, 2, 3, 8)), before[1]), _DATABASE)
        for index in range(3):
            metadata = list(before[1][1])
            metadata[index] += 1
            after = (before[0], (before[1][0], (metadata[0], metadata[1], metadata[2], metadata[3])))
            assert not scoped._capture_metadata_equal(before, after, _DATABASE)
    assert scoped._capture_metadata_equal is original
    assert observation.describe() == (
        "; reservation_metadata_attached=True; reservation_metadata_checks=4"
        "; reservation_metadata_changed=3; reservation_metadata_kinds=wal:3"
    )


def test_non_database_ctime_and_creation_remain_refusals_without_disclosing_paths() -> None:
    observation = CaptureMetadataObservation()
    path = "/private-fixture/person-at-example/policy-verifier.key"
    with observation.attach(_publisher()):
        assert not scoped._capture_metadata_equal(((path, (1, 2, 3, 4)),), ((path, (1, 2, 3, 5)),), _DATABASE)
        assert not scoped._capture_metadata_equal((), (("/private-fixture/secret-source", (1, 2, 3, 4)),), _DATABASE)
    description = observation.describe()
    assert "reservation_metadata_checks=2" in description
    assert "reservation_metadata_changed=2" in description
    assert "reservation_metadata_kinds=verifier:1,other_policy:1" in description
    assert all(value not in description for value in ("private-fixture", "person-at-example", "secret-source"))


def test_only_the_existing_publisher_thread_is_observed() -> None:
    observation = CaptureMetadataObservation()
    results: list[bool] = []
    with observation.attach(_publisher()):
        worker = threading.Thread(target=lambda: results.append(scoped._capture_metadata_equal((), (), _DATABASE)))
        worker.start()
        worker.join(timeout=1)
        assert not worker.is_alive()
        assert scoped._capture_metadata_equal((), (), _DATABASE)
    assert results == [True]
    assert "reservation_metadata_checks=1" in observation.describe()


def test_nested_observers_restore_once_and_captured_wrappers_remain_pass_through() -> None:
    original = scoped._capture_metadata_equal
    first, second = CaptureMetadataObservation(), CaptureMetadataObservation()
    with first.attach(_publisher()):
        wrapped = scoped._capture_metadata_equal
        with second.attach(_publisher()):
            assert scoped._capture_metadata_equal is wrapped
            assert wrapped((), (), _DATABASE)
        assert scoped._capture_metadata_equal is wrapped
        assert wrapped((), (), _DATABASE)
    assert scoped._capture_metadata_equal is original
    assert wrapped((), (), _DATABASE)
    assert "reservation_metadata_checks=2" in first.describe()
    assert "reservation_metadata_checks=1" in second.describe()


def test_original_exceptions_survive_and_concurrent_replacement_is_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    failure = RuntimeError("synthetic-original-comparison-failure")
    calls: list[tuple[object, ...]] = []

    def raising(*args: object) -> bool:
        calls.append(args)
        raise failure

    monkeypatch.setattr(scoped, "_capture_metadata_equal", raising)
    observation = CaptureMetadataObservation()

    def replacement(*_args: object) -> bool:
        return False

    with observation.attach(_publisher()):
        with pytest.raises(RuntimeError) as caught:
            _ = scoped._capture_metadata_equal((), (), _DATABASE)
        assert caught.value is failure
        scoped._capture_metadata_equal = replacement
    assert scoped._capture_metadata_equal is replacement
    assert len(calls) == 1
    assert "reservation_metadata_checks=0" in observation.describe()


def test_unknown_worker_is_unobserved_and_counters_are_bounded() -> None:
    original = scoped._capture_metadata_equal
    observation = CaptureMetadataObservation()
    with observation.attach(SimpleNamespace()):
        assert scoped._capture_metadata_equal is original
    assert "reservation_metadata_attached=False" in observation.describe()
    for _ in range(1_100):
        observation.record((), ((_DATABASE, (1, 2, 3, 4)),), _DATABASE, False)
    assert "reservation_metadata_checks=999" in observation.describe()
    assert "reservation_metadata_changed=999" in observation.describe()
    assert "reservation_metadata_kinds=database:999" in observation.describe()
