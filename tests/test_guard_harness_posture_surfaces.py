"""Per-harness posture across the CLI, the daemon settings API, and the publisher binding."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.native_policy_snapshot_publication as publication_module
from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.config import load_guard_config, update_guard_settings
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_harness_postures import read_harness_postures_sidecar
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _ack, _DeterministicClock, _status
from .test_guard_settings_api import _json_request, _with_daemon


def test_cli_sets_and_clears_harness_posture(tmp_path: Path, capsys: object) -> None:
    guard_home = tmp_path / "guard-home"
    rc = main(["guard", "settings", "set", "protection", "watch", "--harness", "codex", "--home", str(guard_home)])
    assert rc == 0
    config = load_guard_config(guard_home)
    assert config.harness_postures == {"codex": "watch"}
    assert config.protection_posture == "protected"

    rc = main(["guard", "settings", "set", "protection", "--harness", "codex", "--inherit", "--home", str(guard_home)])
    assert rc == 0
    assert not load_guard_config(guard_home).harness_postures


def test_status_json_lists_per_harness_postures(tmp_path: Path, capsys: object) -> None:
    guard_home = tmp_path / "guard-home"
    main(["guard", "settings", "set", "protection", "watch", "--harness", "codex", "--home", str(guard_home)])
    capsys.readouterr()  # type: ignore[attr-defined]
    rc = main(["guard", "settings", "doctor", "--home", str(guard_home), "--json"])
    payload = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert rc == 0
    assert payload["harness_postures"] == {"codex": "watch"}
    assert payload["harnesses_in_watch"] == ["codex"]


def test_daemon_settings_exposes_and_patches_harness_postures(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(parents=True)
    _store, daemon = _with_daemon(guard_home)
    try:
        token = daemon._server.auth_token
        status, payload = _json_request(
            daemon.port,
            token,
            "/v1/settings",
            method="POST",
            payload={"settings": {"harness_postures": {"codex": "watch"}}},
        )
        assert status == 200
        assert payload["settings"]["harness_postures"] == {"codex": "watch"}
        assert payload["settings"]["harness_postures_effective"]["codex"] == "watch"
        assert payload["settings"]["harness_postures_locked"] is False

        status, payload = _json_request(daemon.port, token, "/v1/settings")
        assert status == 200
        assert payload["settings"]["harness_postures"] == {"codex": "watch"}

        status, payload = _json_request(
            daemon.port,
            token,
            "/v1/settings",
            method="POST",
            payload={"settings": {"harness_postures": {"codex": None}}},
        )
        assert status == 200
        assert payload["settings"]["harness_postures"] == {}
    finally:
        daemon.stop()


def test_publisher_binding_carries_postures_captured_at_ack(tmp_path: Path) -> None:
    clock = _DeterministicClock()
    publisher = NativePolicySnapshotPublisher(
        store=GuardStore(tmp_path / "guard-home"),
        client_request=lambda **_kwargs: b"unused",
        poll_interval_seconds=0.05,
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )
    publisher._snapshot = {
        "mode": "enforce",
        "generation": 7,
        "config_digest": "a" * 64,
        "policy_digest": "b" * 64,
        "expires_at_ms": int(clock.wall * 1_000) + 60_000,
    }
    publisher._acked = True
    try:
        binding = publisher.current_snapshot_binding()
        assert binding is not None and "harness_postures" not in binding
        publisher._harness_postures = {"codex": "watch"}
        binding = publisher.current_snapshot_binding()
        assert binding is not None
        assert binding["harness_postures"] == {"codex": "watch"}
        assert binding["mode"] == "enforce"
    finally:
        publisher.close()


def test_a_posture_only_change_publishes_a_new_generation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A publish that stops before the sidecar is written leaves no stale Watch.

    Postures ride beside the snapshot, so the materializer would keep the
    generation for a posture-only change, and the old sidecar would still
    match the ACKed snapshot for a hook bridge whose daemon is down.
    """

    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    master = b"p" * 32
    # update_guard_settings opens its own store, so every store shares the key.
    monkeypatch.setattr(GuardStore, "_policy_integrity_secret_material", lambda _self, *, create: (master, "master-id"))
    clock = _DeterministicClock()

    def client_request(**kwargs: object) -> bytes:
        payload = kwargs["payload"]
        assert isinstance(payload, bytes)
        return _ack(payload, guard_home=kwargs.get("guard_home"))

    publisher = NativePolicySnapshotPublisher(
        store=store,
        status_provider=_status,
        client_request=client_request,
        poll_interval_seconds=0.05,
        wall_clock=clock.wall_time,
        monotonic_clock=clock.monotonic_time,
    )
    try:
        update_guard_settings(guard_home, {"harness_postures": {"codex": "watch"}})
        publisher._publish_once()
        first = publisher.current_snapshot()
        assert first is not None, publisher._last_error
        bound = {"generation": first["generation"], "policy_digest": first["policy_digest"]}
        assert read_harness_postures_sidecar(store, **bound) == {"codex": "watch"}
        sidecar = json.loads((guard_home / "native-runtime" / "harness-postures-v1.json").read_text(encoding="utf-8"))
        assert type(sidecar["harness_watch_ends_at_us"]["codex"]) is int

        update_guard_settings(guard_home, {"harness_postures": {"codex": None}})
        # The publish stops after the snapshot is saved, before the sidecar.
        monkeypatch.setattr(publication_module, "write_harness_postures_sidecar", lambda *_args, **_kwargs: {})
        publisher._publish_once()
        second = publisher.current_snapshot()
        assert second is not None
        assert second["generation"] > first["generation"]
        assert (
            read_harness_postures_sidecar(store, generation=second["generation"], policy_digest=second["policy_digest"])
            == {}
        )
    finally:
        publisher.close()
