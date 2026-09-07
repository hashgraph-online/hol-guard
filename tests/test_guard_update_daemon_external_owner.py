"""Refresh behavior when another installation owns the live daemon.

A CLI self-update must not fight a Desktop-owned daemon that a supervisor
keeps respawning: retirement can never complete, and the update used to
report failure even though a healthy authenticated daemon kept serving the
whole time.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.daemon import live_identity, manager, runtime_peer

# Relative on purpose: availability checks keep relative fixture paths
# matching by shape, so this stays a Desktop-owned source on every runner.
_DESKTOP_SOURCE_ROOT = "Applications/HOL Guard.app/Contents/MacOS/hol-guard"


@pytest.fixture(autouse=True)
def _stub_locator_publish(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(manager, "publish_approval_center_locator", lambda _home, _url: None)


def _desktop_identity(guard_home: Path, *, port: int) -> dict[str, object]:
    return {
        "guard_home": str(guard_home),
        "host": "127.0.0.1",
        "port": port,
        "compatibility_version": 2,
        "package_version": "3.0.70",
        "runtime_fingerprint": "d" * 64,
        "pid": 4242,
        "source_root": _DESKTOP_SOURCE_ROOT,
        "daemon_url": f"http://127.0.0.1:{port}",
    }


def test_retained_newer_runtime_payload_keeps_only_newer_verified_daemon(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    identity = {**_desktop_identity(guard_home, port=8240), "package_version": "3.0.99"}
    monkeypatch.setattr(
        live_identity,
        "verified_live_guard_daemon_identity",
        lambda _home: identity,
    )

    payload = runtime_peer.retained_newer_runtime_payload(guard_home, minimum_version="3.0.73")

    assert payload == {
        "status": "retained_newer_runtime",
        "daemon_url": "http://127.0.0.1:8240",
        "daemon_version": "3.0.99",
        "cli_version": "3.0.73",
        "runtime_verified": True,
    }
    same_version = {**identity, "package_version": "3.0.73"}
    monkeypatch.setattr(
        live_identity,
        "verified_live_guard_daemon_identity",
        lambda _home: same_version,
    )
    assert runtime_peer.retained_newer_runtime_payload(guard_home, minimum_version="3.0.73") is None


def test_retained_desktop_owner_payload_gates_on_minimum_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    monkeypatch.setattr(
        runtime_peer,
        "live_desktop_owned_daemon",
        lambda _home: _desktop_identity(guard_home, port=8241),
    )

    assert runtime_peer.retained_desktop_owner_payload(guard_home) is not None
    assert runtime_peer.retained_desktop_owner_payload(guard_home, minimum_version="3.0.70") is not None
    assert runtime_peer.retained_desktop_owner_payload(guard_home, minimum_version="3.0.73") is None
    assert runtime_peer.retained_desktop_owner_payload(guard_home, minimum_version="not.a.version") is None


@pytest.mark.parametrize(
    ("payload", "allow_not_running", "expected"),
    [
        ({"status": "restarted", "runtime_verified": True}, False, True),
        ({"status": "restarted"}, False, False),
        ({"status": "retained_newer_runtime", "runtime_verified": True}, False, True),
        ({"status": "retained_desktop_owner", "runtime_verified": True}, False, True),
        ({"status": "retained_desktop_owner"}, False, False),
        ({"status": "not_running"}, False, False),
        ({"status": "not_running"}, True, True),
        ({"status": "retirement_failed"}, True, False),
        ("not-a-dict", True, False),
        (None, True, False),
    ],
)
def test_daemon_refresh_outcome_succeeded_classifies_every_status(
    payload: object, allow_not_running: bool, expected: bool
) -> None:
    assert runtime_peer.daemon_refresh_outcome_succeeded(payload, allow_not_running=allow_not_running) is expected


def _exec_refresh_script(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    *,
    retirement_completes: bool,
) -> tuple[object, str]:
    home_dir = tmp_path / "home"
    guard_home = home_dir / ".hol-guard"
    guard_home.mkdir(parents=True)
    (guard_home / "daemon-state.json").write_text(json.dumps({"port": 8231}), encoding="utf-8")
    retirement_calls = 0

    def retire(_guard_home: Path) -> list[int]:
        nonlocal retirement_calls
        retirement_calls += 1
        # Every retirement is instantly replaced, the way Guard Desktop's
        # supervisor respawns its daemon during the refresh window.
        return [9000 + retirement_calls]

    monkeypatch.setattr(manager, "retire_all_guard_daemons_for_home", retire)
    monkeypatch.setattr(
        manager,
        "guard_daemon_retirement_is_complete",
        lambda _guard_home: retirement_completes,
    )
    monkeypatch.setattr(
        live_identity,
        "verified_live_guard_daemon_identity",
        lambda home: _desktop_identity(home, port=8231),
    )
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({"guard_home": str(guard_home), "home_dir": str(home_dir)})),
    )

    refresh_script = cast(str, update_commands.__dict__["_DAEMON_REFRESH_SCRIPT"])
    try:
        exec(refresh_script, {})
    except SystemExit as exit_info:
        return exit_info.code, capsys.readouterr().out
    return None, capsys.readouterr().out


def test_refresh_script_keeps_desktop_daemon_when_retirement_never_completes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code, out = _exec_refresh_script(
        tmp_path,
        monkeypatch,
        capsys,
        retirement_completes=False,
    )

    assert exit_code == 0
    payload = json.loads(out)
    assert payload["status"] == "retained_desktop_owner"
    assert payload["runtime_verified"] is True
    assert payload["daemon_url"] == "http://127.0.0.1:8231"
    assert payload["daemon_version"] == "3.0.70"


def test_refresh_script_falls_back_to_desktop_daemon_mid_fight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # The daemon only becomes Desktop-owned after the refresh has already
    # started fighting it: the pre-flight keeps nothing, and the first
    # retirement attempt must surrender to the respawned Desktop daemon.
    home_dir = tmp_path / "home"
    guard_home = home_dir / ".hol-guard"
    guard_home.mkdir(parents=True)
    (guard_home / "daemon-state.json").write_text(json.dumps({"port": 8233}), encoding="utf-8")
    owner_calls = 0

    def owner_after_first_check(home: Path) -> dict[str, object] | None:
        nonlocal owner_calls
        owner_calls += 1
        if owner_calls == 1:
            return None
        return _desktop_identity(home, port=8233)

    monkeypatch.setattr(runtime_peer, "live_desktop_owned_daemon", owner_after_first_check)
    monkeypatch.setattr(manager, "retire_all_guard_daemons_for_home", lambda _home: [9100])
    monkeypatch.setattr(manager, "guard_daemon_retirement_is_complete", lambda _home: False)
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(json.dumps({"guard_home": str(guard_home), "home_dir": str(home_dir)})),
    )

    refresh_script = cast(str, update_commands.__dict__["_DAEMON_REFRESH_SCRIPT"])
    with pytest.raises(SystemExit) as exit_info:
        exec(refresh_script, {})

    assert exit_info.value.code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "retained_desktop_owner"
    assert payload["retired"] == [9100]
    assert payload["attempts"] == 1
    assert payload["daemon_url"] == "http://127.0.0.1:8233"


def test_refresh_prefers_live_desktop_daemon_without_running_the_refresh_script(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.cli.update_commands import refresh_guard_daemon_after_update

    home_dir = tmp_path / "home"
    guard_home = home_dir / ".hol-guard"
    guard_home.mkdir(parents=True)
    (guard_home / "daemon-state.json").write_text(json.dumps({"port": 8232}), encoding="utf-8")
    context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=guard_home)

    def fail_if_refresh_runs(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("the refresh script must not run while a Desktop daemon owns the home")

    monkeypatch.setattr(update_commands, "_standalone_update_context", fail_if_refresh_runs)
    monkeypatch.setattr(
        live_identity,
        "verified_live_guard_daemon_identity",
        lambda home: _desktop_identity(home, port=8232),
    )

    payload, note = refresh_guard_daemon_after_update(
        context,
        update_context=None,
        minimum_version="3.0.73",
    )

    assert payload is not None and payload["status"] == "retained_desktop_owner"
    assert payload["runtime_verified"] is True
    assert note is not None and "Guard Desktop" in note


@pytest.mark.parametrize(
    ("source_root", "expected"),
    [
        (_DESKTOP_SOURCE_ROOT, True),
        (
            "Library/Application Support/org.hol.guard.desktop/core/versions/3.0.68/hol-guard",
            True,
        ),
        ("C:/Program Files/HOL Guard/hol-guard/hol-n.exe", True),
        ("opt/hol-desktop/core/bundled/3.0.63/bin/hol-guard", True),
        ("opt/hol-desktop/core/bundled/3.0.63/lib/hol-guard-core/hol-guard", True),
        ("opt/hol-desktop/core/bundled/3.0.63/lib/hol-guard-core/hol-guard.exe", True),
        ("home/u/.local/share/hol-desktop/versions/3.0.70/hol-guard", True),
        ("opt/hol-desktop/core/current-hol-guard", True),
        ("opt/hol-desktop/core/current-hol-guard.cmd", True),
        ("Users/dev/.local/share/uv/python/versions/cpython-3.12/bin/python", False),
        ("/opt/tool/versions/1.2/bin/run", False),
        ("/Users/dev/src/hol-guard", False),
        ("/Users/dev/.local/pipx/venvs/hol-guard/lib/python3.12/site-packages", False),
        ("/opt/hol-guard/lib/python", False),
        ("opt/hol-desktop/core/bundled/3.0.63/lib/other-core/hol-guard", False),
        ("opt/hol-desktop/core/bundled/3.0.63/lib/hol-guard-core/python", False),
        ("Applications/Other Tools.app/Contents/MacOS/hol-guard", False),
        ("D:/tools/hol guard/daemon.exe", False),
        ("", False),
        (None, False),
    ],
)
def test_daemon_source_is_desktop_core_recognizes_every_desktop_shape(source_root: object, expected: bool) -> None:
    assert runtime_peer.daemon_source_is_desktop_core(source_root) is expected


def test_bundled_linux_core_source_is_available_when_executable_exists(tmp_path: Path) -> None:
    source_root = (
        tmp_path
        / "home"
        / ".local"
        / "share"
        / "org.hol.guard.desktop"
        / "core"
        / "bundled"
        / "3.0.86"
        / "lib"
        / "hol-guard-core"
        / "hol-guard"
    )
    source_root.parent.mkdir(parents=True)
    source_root.write_text("synthetic Desktop Core", encoding="utf-8")

    assert runtime_peer.daemon_desktop_core_source_available(str(source_root)) is True
    assert runtime_peer.daemon_desktop_core_source_available(
        str(source_root.parent.parent / "other-core" / "hol-guard")
    ) is False
