"""Per-harness posture across the CLI, the daemon settings API, and the publisher binding."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _DeterministicClock
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
