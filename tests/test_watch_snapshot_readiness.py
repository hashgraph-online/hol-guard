"""Watch keeps its acknowledged snapshot while hook traffic republishes it."""

from __future__ import annotations

from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_policy_snapshot_publisher as publisher_module
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_codec import _digest_v3
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _DeterministicClock


def _publisher(tmp_path: Path, clock: _DeterministicClock) -> NativePolicySnapshotPublisher:
    return NativePolicySnapshotPublisher(
        store=GuardStore(tmp_path / "guard-home"),
        client_request=lambda **_kwargs: b"unused",
        poll_interval_seconds=0.05,
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )


def _ready_snapshot(clock: _DeterministicClock, mode: str) -> dict[str, object]:
    return {
        "mode": mode,
        "generation": 7,
        "config_digest": "a" * 64,
        "policy_digest": "b" * 64,
        "expires_at_ms": int(clock.wall * 1_000) + 60_000,
    }


def test_watch_command_control_churn_keeps_the_acknowledged_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _DeterministicClock()
    publisher = _publisher(tmp_path, clock)
    policy = {"mode": "observe", "blocked_capabilities": ["network"]}
    policy_digest = _digest_v3({"blocked_capabilities": ["network"]})
    previous_extensions = _digest_v3({"revision": 1})
    publisher._published_policy_fingerprint = (policy_digest, "observe", previous_extensions)
    publisher._observed_policy_fingerprint = publisher._published_policy_fingerprint
    publisher._snapshot = _ready_snapshot(clock, "observe")
    publisher._acked = True
    monkeypatch.setattr(publisher, "_compiled_effective_policy", lambda **_: policy)
    monkeypatch.setattr(publisher, "_compiled_command_extensions", lambda: {"revision": 2})
    try:
        assert publisher.is_ready()
        epoch = publisher._epoch
        assert publisher._policy_input_changed({str(publisher.guard_home / "guard.db-wal")})
        assert publisher._observe_extension_refresh is True
        assert publisher.is_ready()
        assert publisher.current_snapshot_binding() is not None
        publisher._republish_preserving_watch()
        assert publisher.is_ready()
        assert publisher._epoch == epoch
        assert publisher._renewal_after_generation == 7
    finally:
        publisher.close()


def test_protected_command_control_churn_still_withdraws_readiness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _DeterministicClock()
    publisher = _publisher(tmp_path, clock)
    policy = {"mode": "enforce", "blocked_capabilities": ["network"]}
    policy_digest = _digest_v3({"blocked_capabilities": ["network"]})
    publisher._published_policy_fingerprint = (policy_digest, "enforce", _digest_v3({"revision": 1}))
    publisher._observed_policy_fingerprint = publisher._published_policy_fingerprint
    publisher._snapshot = _ready_snapshot(clock, "enforce")
    publisher._acked = True
    monkeypatch.setattr(publisher, "_compiled_effective_policy", lambda **_: policy)
    monkeypatch.setattr(publisher, "_compiled_command_extensions", lambda: {"revision": 2})
    try:
        assert publisher._policy_input_changed({str(publisher.guard_home / "guard.db-wal")})
        assert publisher._observe_extension_refresh is False
        assert not publisher.is_ready()
        assert publisher.current_snapshot_binding() is None
    finally:
        publisher.close()


@pytest.mark.parametrize("mode", ["observe", "enforce"])
def test_publish_command_control_race_follows_posture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    clock = _DeterministicClock()
    publisher = _publisher(tmp_path, clock)
    publisher._retry_not_before_monotonic = clock.monotonic - 1.0
    monkeypatch.setattr(
        publisher,
        "_publication_context",
        lambda **_: (None, None, b"key", {}, {"revision": 1}, lambda **_kwargs: b"unused"),
    )
    monkeypatch.setattr(publisher, "_compiled_command_extensions", lambda: {"revision": 2})
    monkeypatch.setattr(
        publisher_module,
        "_publish_snapshot_v3",
        lambda **_kwargs: (_ready_snapshot(clock, mode), 7),
    )
    try:
        publisher._publish_once()
        if mode == "observe":
            assert publisher.is_ready(), publisher.last_error
            binding = publisher.current_snapshot_binding()
            assert binding is not None
            assert binding["mode"] == "observe"
            return
        assert publisher.last_error == "native_command_control_binding_changed"
        assert not publisher.is_ready()
    finally:
        publisher.close()


def test_watch_publish_survives_resident_file_churn_for_the_acknowledged_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _DeterministicClock()
    publisher = _publisher(tmp_path, clock)
    publisher._retry_not_before_monotonic = clock.monotonic - 1.0
    before = (("resident-v3-a/generation-00000000000000000007.json", 1, 1),)
    after = (("resident-v3-a/generation-00000000000000000007.json", 2, 1),)
    samples = iter((before, after))
    monkeypatch.setattr(publisher, "_current_input_fingerprint", lambda: ((), next(samples)))
    monkeypatch.setattr(
        publisher,
        "_publication_context",
        lambda **_: (None, None, b"key", {}, {}, lambda **_kwargs: b"unused"),
    )
    monkeypatch.setattr(publisher, "_compiled_command_extensions", lambda: {})
    monkeypatch.setattr(
        publisher_module,
        "_publish_snapshot_v3",
        lambda **_kwargs: (_ready_snapshot(clock, "observe"), 7),
    )
    try:
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        binding = publisher.current_snapshot_binding()
        assert binding is not None
        assert binding["mode"] == "observe"
    finally:
        publisher.close()


def test_protected_publish_still_rejects_resident_file_churn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _DeterministicClock()
    publisher = _publisher(tmp_path, clock)
    publisher._snapshot = _ready_snapshot(clock, "enforce")
    publisher._acked = True
    publisher._retry_not_before_monotonic = clock.monotonic - 1.0
    before = (("resident-v3-a/generation-00000000000000000007.json", 1, 1),)
    after = (("resident-v3-a/generation-00000000000000000007.json", 2, 1),)
    samples = iter((before, after))
    monkeypatch.setattr(publisher, "_current_input_fingerprint", lambda: ((), next(samples)))
    monkeypatch.setattr(
        publisher,
        "_publication_context",
        lambda **_: (None, None, b"key", {}, {}, lambda **_kwargs: b"unused"),
    )
    monkeypatch.setattr(publisher, "_compiled_command_extensions", lambda: {})
    monkeypatch.setattr(
        publisher_module,
        "_publish_snapshot_v3",
        lambda **_kwargs: (_ready_snapshot(clock, "enforce"), 7),
    )
    try:
        publisher._publish_once()
        assert publisher.last_error == "native_policy_snapshot_resident_changed"
        assert not publisher.is_ready()
    finally:
        publisher.close()


def test_resident_mtime_churn_keeps_watch_when_policy_inputs_are_unchanged(tmp_path: Path) -> None:
    clock = _DeterministicClock()
    publisher = _publisher(tmp_path, clock)
    publisher._snapshot = _ready_snapshot(clock, "observe")
    publisher._acked = True
    generation = "resident-v3-a/generation-00000000000000000007.json"
    publisher._input_fingerprint = ((), ((generation, 1, 1),))
    try:
        epoch = publisher._epoch
        publisher._accept_resident_fingerprint(((), ((generation, 2, 1),)))
        assert publisher.is_ready()
        assert publisher._epoch == epoch
        assert publisher._renewal_after_generation == 7
    finally:
        publisher.close()


def test_resident_heartbeat_does_not_revoke_unchanged_protected_policy(tmp_path: Path) -> None:
    clock = _DeterministicClock()
    publisher = _publisher(tmp_path, clock)
    publisher._snapshot = _ready_snapshot(clock, "enforce")
    publisher._acked = True
    generation = "resident-v3-a/generation-00000000000000000007.json"
    publisher._input_fingerprint = ((), ((generation, 1, 1),))
    try:
        epoch = publisher._epoch
        publisher._accept_resident_fingerprint(((), ((generation, 2, 1),)))
        assert publisher.is_ready()
        assert publisher.current_snapshot_binding()["generation"] == 7
        assert publisher._epoch == epoch
    finally:
        publisher.close()


def test_new_resident_revokes_protected_policy_binding(tmp_path: Path) -> None:
    clock = _DeterministicClock()
    publisher = _publisher(tmp_path, clock)
    publisher._snapshot = _ready_snapshot(clock, "enforce")
    publisher._acked = True
    publisher._input_fingerprint = ((), (("resident-v3-a/generation-00000000000000000007.json", 1, 1),))
    try:
        publisher._accept_resident_fingerprint(((), (("resident-v3-a/generation-00000000000000000008.json", 2, 1),)))
        assert not publisher.is_ready()
        assert publisher.current_snapshot_binding() is None
    finally:
        publisher.close()


def test_resident_mtime_churn_withdraws_watch_when_policy_moves_to_enforce(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _DeterministicClock()
    publisher = _publisher(tmp_path, clock)
    publisher._snapshot = _ready_snapshot(clock, "observe")
    publisher._acked = True
    config_path = str(publisher.guard_home / "config.toml")
    generation = "resident-v3-a/generation-00000000000000000007.json"
    publisher._input_fingerprint = (((config_path, (1, 1, 1, 1)),), ((generation, 1, 1),))
    monkeypatch.setattr(
        publisher,
        "_compiled_effective_policy",
        lambda **_: {"mode": "enforce", "blocked_capabilities": ["network"]},
    )
    monkeypatch.setattr(publisher, "_compiled_command_extensions", lambda: {"revision": 1})
    try:
        publisher._accept_resident_fingerprint(
            (((config_path, (2, 1, 1, 1)),), ((generation, 2, 1),)),
        )
        assert not publisher.is_ready()
        assert publisher.current_snapshot_binding() is None
    finally:
        publisher.close()
